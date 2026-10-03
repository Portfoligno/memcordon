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

/// Two scoped owners, with fixed result order and no abandoned second lane.
/// Native command supervision supplies cleanup; joining alone is not a deadline.
pub fn complete_lanes(
    layout: Layout,
    first: impl FnOnce() -> Result<()> + Send,
    second: impl FnOnce() -> Result<()> + Send,
) -> Result<()> {
    let run = |operation: Box<dyn FnOnce() -> Result<()> + Send + '_>| {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
            .unwrap_or_else(|_| Err(CiError::Message("scoped lane panicked".into())))
    };
    let (first, second) = match layout {
        Layout::Serial => (run(Box::new(first)), run(Box::new(second))),
        Layout::Parallel => std::thread::scope(|scope| {
            let first = std::thread::Builder::new()
                .name("ci-source-lane".into())
                .spawn_scoped(scope, move || run(Box::new(first)));
            let second = std::thread::Builder::new()
                .name("ci-auxiliary-lane".into())
                .spawn_scoped(scope, move || run(Box::new(second)));
            let finish = |owner: std::io::Result<std::thread::ScopedJoinHandle<'_, Result<()>>>| {
                owner
                    .map_err(CiError::Io)?
                    .join()
                    .unwrap_or_else(|_| Err(CiError::Message("scoped owner panicked".into())))
            };
            let first = finish(first);
            let second = finish(second);
            (first, second)
        }),
    };
    match (first, second) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(first), Ok(())) => Err(first),
        (Ok(()), Err(second)) => Err(second),
        (Err(first), Err(second)) => Err(CiError::Message(format!(
            "first lane: {first}; second lane: {second}"
        ))),
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
        return Err(CiError::Message(format!(
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
    let path = auxiliary_tool(root, name)?;
    let valid = |path: &Path| -> Result<bool> {
        if !path.is_file() {
            return Ok(false);
        }
        let output = CommandSpec::new(path, root, Duration::from_secs(30))
            .arg("--version")
            .output_quiet()?;
        Ok(output.status.success()
            && std::str::from_utf8(&output.stdout)
                .ok()
                .is_some_and(|text| text.split_whitespace().any(|token| token == version)))
    };
    if !valid(&path)? {
        prepare(root, profile)?;
    }
    if !valid(&path)? {
        return Err(CiError::Message(
            "promoted auxiliary version differs from selected pin".into(),
        ));
    }
    Ok(path)
}

pub fn prepare(root: &Path, profile: BootstrapProfile) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45 * 60);
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
            .args(["toolchain", "install", toolchain, "--profile", "minimal"]),
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
            observed(
                rustup_cargo(
                    root,
                    &toolchains.stable,
                    ["fetch", "--locked"],
                    remaining(deadline, Duration::from_secs(900))?,
                ),
                &source_reports,
                "fetch",
            )?;
            observed(
                rustup_cargo(
                    root,
                    &toolchains.stable,
                    ["metadata", "--locked", "--format-version", "1"],
                    remaining(deadline, Duration::from_secs(900))?,
                ),
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
                    ]),
                    &auxiliary_reports,
                    "miri-component",
                )?;
                observed(
                    rustup_cargo(
                        root,
                        &toolchains.miri,
                        ["miri", "setup"],
                        remaining(deadline, Duration::from_secs(900))?,
                    ),
                    &auxiliary_reports,
                    "miri-sysroot",
                )?;
            }
            for (package, version) in &installs {
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
                    .arg(root.join("target/ci-tools-build")),
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
