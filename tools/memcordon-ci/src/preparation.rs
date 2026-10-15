//! Pinned tool preparation for selected CI work.
use crate::performance_plan::{Layout, PerformancePlan};
use crate::{
    CiError, Result,
    bootstrap_profile::BootstrapProfile,
    command::{CommandSpec, rustup_cargo},
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Debug)]
pub struct GroupStop {
    pub requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    mode: crate::failure_mode::FailureMode,
}

thread_local! {
    static ACTIVE_GROUP: std::cell::RefCell<Option<GroupStop>> = const { std::cell::RefCell::new(None) };
}

pub fn active_group() -> Option<GroupStop> {
    ACTIVE_GROUP.with(|group| group.borrow().clone())
}

impl GroupStop {
    pub fn may_start(&self) -> bool {
        !self.requested.load(std::sync::atomic::Ordering::Acquire)
    }
    pub fn request_after_failure(&self) {
        if self.mode == crate::failure_mode::FailureMode::StopAfterFailure {
            self.requested
                .store(true, std::sync::atomic::Ordering::Release);
        }
    }
}

/// Two scoped owners, completion-order failures and no abandoned active lane.
/// Native command supervision supplies cleanup; joining alone is not a deadline.
pub fn complete_lanes(
    layout: Layout,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    complete_lanes_with_failure(
        layout,
        crate::failure_mode::FailureMode::StopAfterFailure,
        first,
        second,
    )
}

pub fn complete_lanes_with_failure(
    layout: Layout,
    mode: crate::failure_mode::FailureMode,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    let stop = GroupStop {
        requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        mode,
    };
    let run = |operation: Box<dyn FnOnce() -> Result<()> + Send + '_>, stop: GroupStop| {
        if !stop.may_start() {
            return Err(CiError::NotStartedAfterFailure);
        }
        let previous = ACTIVE_GROUP.with(|group| group.replace(Some(stop.clone())));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .unwrap_or_else(|_| Err(CiError::Message("scoped lane panicked".into())));
        if result.is_err() {
            stop.request_after_failure();
        }
        ACTIVE_GROUP.with(|group| *group.borrow_mut() = previous);
        result
    };
    let (first, second) = match layout {
        Layout::Serial => {
            let first = run(Box::new(first), stop.clone());
            if first.is_err() && mode == crate::failure_mode::FailureMode::StopAfterFailure {
                return first;
            }
            (first, run(Box::new(second), stop.clone()))
        }
        Layout::Parallel => std::thread::scope(|scope| {
            let (sender, receiver) = std::sync::mpsc::sync_channel(2);
            let first_sender = sender.clone();
            let first_stop = stop.clone();
            let second_stop = stop.clone();
            let first = std::thread::Builder::new()
                .name("ci-source-lane".into())
                .spawn_scoped(scope, move || {
                    let result = run(Box::new(first), first_stop);
                    let _ = first_sender.send((0, result));
                });
            if first.is_err() {
                stop.request_after_failure();
            }
            let second = std::thread::Builder::new()
                .name("ci-auxiliary-lane".into())
                .spawn_scoped(scope, move || {
                    let result = run(Box::new(second), second_stop);
                    let _ = sender.send((1, result));
                });
            let mut results = [None, None];
            let mut primary = if first.is_err() {
                Some(0)
            } else if second.is_err() {
                stop.request_after_failure();
                Some(1)
            } else {
                None
            };
            for (ordinal, result) in receiver {
                if let Err(error) = &result {
                    for line in error.to_string().lines() {
                        let safe: String = line.chars().flat_map(char::escape_default).collect();
                        eprintln!("[ci lane {ordinal}] failed: {safe}");
                    }
                    if primary.is_none()
                        && !matches!(
                            error,
                            CiError::Cancelled(_)
                                | CiError::SettledCancellation(_)
                                | CiError::NotStartedAfterFailure
                        )
                    {
                        primary = Some(ordinal);
                    }
                }
                results[ordinal] = Some(result);
            }
            for (ordinal, owner) in [first, second].into_iter().enumerate() {
                if let Err(error) = owner.map_err(CiError::Io).and_then(|owner| {
                    owner
                        .join()
                        .map_err(|_| CiError::Message("scoped owner panicked".into()))
                }) {
                    results[ordinal] = Some(Err(error));
                }
            }
            let primary = primary.unwrap_or(0);
            (
                results[primary].take().expect("primary owner settled"),
                results[1 - primary].take().expect("peer owner settled"),
            )
        }),
    };
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(first), Ok(())) => Err(first),
        (Ok(()), Err(second)) => Err(second),
        (Err(first), Err(second)) => Err(CiError::LaneFailures {
            primary: Box::new(first),
            secondary: Box::new(second),
        }),
    }
}

pub fn remaining(deadline: Instant, limit: Duration) -> Result<Duration> {
    let budget = deadline.saturating_duration_since(Instant::now());
    if budget.is_zero() {
        return Err(CiError::Message(
            "original operation group deadline expired".into(),
        ));
    }
    Ok(budget.min(limit))
}

pub fn observed(command: CommandSpec, directory: &Path, name: &str) -> Result<()> {
    let result = command.output_quiet()?;
    let stdout = fs::write(
        directory.join(name).with_extension("stdout.bin"),
        &result.stdout,
    );
    let stderr = fs::write(
        directory.join(name).with_extension("stderr.bin"),
        &result.stderr,
    );
    if !result.status.success() {
        return Err(CiError::SettledCommandFailure(format!(
            "operation {name} failed with {:?}; stdout collection={stdout:?}; stderr collection={stderr:?}\nstdout:\n{}\nstderr:\n{}",
            result.status,
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr),
        )));
    }
    stdout?;
    stderr?;
    Ok(())
}

pub fn auxiliary_tool(root: &Path, name: &str) -> Result<PathBuf> {
    let filename = match (name, cfg!(windows)) {
        ("cargo-fuzz", false) => "cargo-fuzz",
        ("cargo-fuzz", true) => "cargo-fuzz.exe",
        ("cargo-audit", false) => "cargo-audit",
        ("cargo-audit", true) => "cargo-audit.exe",
        ("cargo-deny", false) => "cargo-deny",
        ("cargo-deny", true) => "cargo-deny.exe",
        _ => return Err(CiError::Message("unsupported auxiliary tool".into())),
    };
    Ok(root.join("target/ci-tools/bin").join(filename))
}

pub fn ensure_auxiliary_tool(
    root: &Path,
    profile: BootstrapProfile,
    name: &str,
    version: &str,
) -> Result<PathBuf> {
    ensure_auxiliary_tool_until(
        root,
        profile,
        name,
        version,
        Instant::now() + Duration::from_secs(45 * 60),
    )
}

pub fn ensure_auxiliary_tool_until(
    root: &Path,
    profile: BootstrapProfile,
    name: &str,
    version: &str,
    deadline: Instant,
) -> Result<PathBuf> {
    let path = auxiliary_tool(root, name)?;
    if !valid_auxiliary_version(root, &path, version, deadline)? {
        prepare_until(root, profile, deadline)?;
    }
    if !valid_auxiliary_version(root, &path, version, deadline)? {
        return Err(CiError::Message(
            "promoted auxiliary version differs from selected pin".into(),
        ));
    }
    Ok(path)
}

fn valid_auxiliary_version(
    root: &Path,
    path: &Path,
    version: &str,
    deadline: Instant,
) -> Result<bool> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Ok(false);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Ok(false);
        }
    }
    let output = match CommandSpec::new(path, root, Duration::from_secs(30))
        .arg("--version")
        .bounded_until(deadline)
        .defer_group_failure()
        .output_quiet()
    {
        Ok(output) => output,
        Err(CiError::CommandSpawnFailure(_)) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(output.status.success()
        && std::str::from_utf8(&output.stdout)
            .ok()
            .is_some_and(|text| text.split_whitespace().any(|token| token == version)))
}

pub fn prepare(root: &Path, profile: BootstrapProfile) -> Result<()> {
    prepare_until(root, profile, Instant::now() + Duration::from_secs(45 * 60))
}

pub fn prepare_until(
    root: &Path,
    profile: BootstrapProfile,
    parent_deadline: Instant,
) -> Result<()> {
    let deadline = parent_deadline.min(Instant::now() + Duration::from_secs(45 * 60));
    let toolchains = crate::config::toolchains(root)?;
    let tools = crate::config::tools(root)?;
    let layout = PerformancePlan::read(root)?.preparation.selected;
    let report_root = root.join("target/ci/reports/preparation");
    fs::create_dir_all(&report_root)?;
    let reports = tempfile::Builder::new()
        .prefix("operations-")
        .tempdir_in(&report_root)?
        .keep();
    let source_reports = reports.join("source");
    let auxiliary_reports = reports.join("auxiliary");
    fs::create_dir(&source_reports)?;
    fs::create_dir(&auxiliary_reports)?;
    let mut selected = vec![toolchains.stable.as_str()];
    match profile {
        BootstrapProfile::Msrv => selected.push(&toolchains.msrv),
        BootstrapProfile::Miri | BootstrapProfile::Fuzz => selected.push(&toolchains.miri),
        BootstrapProfile::ReleasePreflight => {
            selected.extend([toolchains.msrv.as_str(), toolchains.miri.as_str()])
        }
        _ => {}
    }
    for (index, toolchain) in selected.into_iter().enumerate() {
        observed(
            CommandSpec::new(
                "rustup",
                root,
                remaining(deadline, Duration::from_secs(900))?,
            )
            .args(["toolchain", "install", toolchain, "--profile", "minimal"])
            .bounded_until(deadline),
            &reports,
            &index.to_string(),
        )?;
    }
    let mut installs = Vec::new();
    if matches!(
        profile,
        BootstrapProfile::Fuzz | BootstrapProfile::ReleasePreflight
    ) {
        installs.push(("cargo-fuzz", tools.cargo_fuzz.as_str()));
    }
    if matches!(
        profile,
        BootstrapProfile::SupplyChain | BootstrapProfile::ReleasePreflight
    ) {
        installs.extend([
            ("cargo-audit", tools.cargo_audit.as_str()),
            ("cargo-deny", tools.cargo_deny.as_str()),
        ]);
    }
    let staging_parent = root.join("target/ci-preparation");
    fs::create_dir_all(&staging_parent)?;
    let staging = tempfile::Builder::new()
        .prefix("tools-")
        .tempdir_in(&staging_parent)?;
    complete_lanes(
        layout,
        || {
            crate::download_cache::fetch_until(
                root,
                crate::download_cache::DownloadFamily::Workspace,
                deadline,
                Some(&source_reports),
            )?;
            if matches!(
                profile,
                BootstrapProfile::Fuzz | BootstrapProfile::ReleasePreflight
            ) {
                crate::download_cache::fetch_until(
                    root,
                    crate::download_cache::DownloadFamily::Fuzz,
                    deadline,
                    Some(&source_reports),
                )?;
            }
            observed(
                rustup_cargo(
                    root,
                    &toolchains.stable,
                    ["metadata", "--locked", "--format-version", "1"],
                    remaining(deadline, Duration::from_secs(900))?,
                )
                .bounded_until(deadline),
                &source_reports,
                "metadata",
            )
        },
        || {
            if matches!(
                profile,
                BootstrapProfile::Miri | BootstrapProfile::ReleasePreflight
            ) {
                observed(
                    CommandSpec::new(
                        "rustup",
                        root,
                        remaining(deadline, Duration::from_secs(900))?,
                    )
                    .args([
                        "component",
                        "add",
                        "--toolchain",
                        &toolchains.miri,
                        "miri",
                        "rust-src",
                    ])
                    .bounded_until(deadline),
                    &auxiliary_reports,
                    "miri-component",
                )?;
                observed(
                    rustup_cargo(
                        root,
                        &toolchains.miri,
                        ["miri", "setup"],
                        remaining(deadline, Duration::from_secs(900))?,
                    )
                    .bounded_until(deadline),
                    &auxiliary_reports,
                    "miri-sysroot",
                )?;
            }
            for (package, version) in &installs {
                let restored = auxiliary_tool(root, package)?;
                if valid_auxiliary_version(root, &restored, version, deadline)? {
                    let destination = staging
                        .path()
                        .join("bin")
                        .join(restored.file_name().expect("named auxiliary tool"));
                    fs::create_dir_all(destination.parent().expect("staging bin"))?;
                    let bytes = crate::release::artifacts::read_file(&restored)?;
                    fs::write(&destination, bytes)?;
                    fs::set_permissions(destination, fs::metadata(&restored)?.permissions())?;
                    continue;
                }
                let family = crate::download_cache::DownloadFamily::for_purpose(package);
                let download_before = crate::download_cache::context_until(root, family, deadline);
                observed(
                    rustup_cargo(
                        root,
                        &toolchains.stable,
                        [
                            "install",
                            "--locked",
                            "--version",
                            *version,
                            *package,
                            "--root",
                        ],
                        remaining(deadline, Duration::from_secs(1200))?,
                    )
                    .arg(staging.path())
                    .arg("--target-dir")
                    .arg(root.join("target/ci-tools-build").join(package))
                    .bounded_until(deadline),
                    &auxiliary_reports,
                    package,
                )?;
                let filename = match (*package, cfg!(windows)) {
                    ("cargo-fuzz", true) => "cargo-fuzz.exe",
                    ("cargo-audit", true) => "cargo-audit.exe",
                    ("cargo-deny", true) => "cargo-deny.exe",
                    (package, false) => package,
                    _ => unreachable!("finite selected tool inventory"),
                };
                let output = CommandSpec::new(
                    staging.path().join("bin").join(filename),
                    root,
                    remaining(deadline, Duration::from_secs(30))?,
                )
                .arg("--version")
                .bounded_until(deadline)
                .output_quiet()?;
                if !output.status.success()
                    || !std::str::from_utf8(&output.stdout)
                        .ok()
                        .is_some_and(|text| text.split_whitespace().any(|token| token == *version))
                {
                    return Err(CiError::Message(
                        "staged auxiliary version differs from selected pin".into(),
                    ));
                }
                if crate::download_cache::packaged_lock_present(root, package, version)
                    .unwrap_or_else(|error| {
                        eprintln!("tool download lock inspection unavailable: {error}");
                        false
                    })
                {
                    crate::download_cache::record(
                        family,
                        &download_before,
                        &crate::download_cache::context_until(root, family, deadline),
                    );
                }
            }
            Ok(())
        },
    )?;
    remaining(deadline, Duration::from_secs(1))?;
    if !installs.is_empty() {
        let destination = root.join("target/ci-tools");
        let backup = staging.path().with_extension("previous");
        let had_previous = destination.try_exists()?;
        if had_previous {
            fs::rename(&destination, &backup)?;
        }
        if let Err(error) = fs::rename(staging.path(), &destination) {
            if had_previous {
                fs::rename(&backup, &destination)?;
            }
            return Err(CiError::Io(error));
        }
        if had_previous {
            fs::remove_dir_all(backup)?;
        }
    }
    Ok(())
}
