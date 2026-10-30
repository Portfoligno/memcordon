//! Direct tests of the selected delivered product. No result archive is consumed.
use super::{distribution, installed_consumer, packages::PackageConsumer, target::TargetBundle};
use crate::{CiError, Result};
use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum Delivery {
    CandidateNative,
    CandidateCargo,
    PublicNative,
    PublicCargo,
}

#[derive(clap::Args)]
pub struct InstalledTestArgs {
    #[arg(long, value_enum)]
    pub delivery: Delivery,
    #[arg(long)]
    pub target: Option<PathBuf>,
    #[arg(long)]
    pub packages: Option<PathBuf>,
    #[arg(long)]
    pub prepared: Option<PathBuf>,
    #[arg(long)]
    pub diagnostics: PathBuf,
}

fn resolved_path(path: &Path) -> Result<PathBuf> {
    let mut existing = std::path::absolute(path)?;
    if existing
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Err(CiError::Message(
            "installed input and diagnostic paths must be normalized".into(),
        ));
    }
    let mut missing = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(
                    existing
                        .file_name()
                        .ok_or_else(|| {
                            CiError::Message("installed path has no existing parent".into())
                        })?
                        .to_owned(),
                );
                existing.pop();
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut resolved = existing.canonicalize()?;
    for part in missing.into_iter().rev() {
        resolved.push(part);
    }
    Ok(resolved)
}

fn retain_failure_output(source: &Path, diagnostics: &Path) -> Result<()> {
    const FILE_BOUND: u64 = 16 * 1024 * 1024;
    const TOTAL_BOUND: u64 = 64 * 1024 * 1024;
    let mut selected = Vec::new();
    for (index, entry) in walkdir::WalkDir::new(source)
        .follow_links(false)
        .into_iter()
        .enumerate()
    {
        if index >= 4096 {
            eprintln!("optional installed diagnostics truncated at entry bound");
            break;
        }
        let entry = entry.map_err(|error| CiError::Message(error.to_string()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !path.extension().is_some_and(|extension| {
            extension == "json" || extension == "txt" || extension == "bin"
        }) {
            continue;
        }
        let metadata = entry
            .metadata()
            .map_err(|error| CiError::Message(error.to_string()))?;
        selected.push((metadata.modified()?, path.to_owned()));
    }
    selected.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
    let mut retained = 0;
    for (_, path) in selected.into_iter().take(128) {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            continue;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                continue;
            }
        }
        if metadata.len() > FILE_BOUND || metadata.len() > TOTAL_BOUND - retained {
            eprintln!(
                "optional installed diagnostic omitted at byte bound: {}",
                path.display()
            );
            continue;
        }
        let mut bytes = Vec::new();
        file.take(FILE_BOUND + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != metadata.len() {
            return Err(CiError::Message(
                "optional installed diagnostic changed during retention".into(),
            ));
        }
        let relative = path
            .strip_prefix(source)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let destination = diagnostics.join("raw").join(relative);
        std::fs::create_dir_all(
            destination
                .parent()
                .expect("selected diagnostic has parent"),
        )?;
        std::fs::write(destination, &bytes)?;
        retained += bytes.len() as u64;
    }
    Ok(())
}

impl InstalledTestArgs {
    pub fn validate(&self) -> Result<()> {
        let candidate = matches!(
            self.delivery,
            Delivery::CandidateNative | Delivery::CandidateCargo
        );
        if candidate
            && (self.target.is_none() || self.packages.is_none() || self.prepared.is_some())
            || !candidate
                && (self.prepared.is_none() || self.target.is_some() || self.packages.is_some())
        {
            return Err(CiError::Message(
                "delivery requires either selected target/packages or the tagged prepared input"
                    .into(),
            ));
        }
        let diagnostics = resolved_path(&self.diagnostics)?;
        for input in [&self.target, &self.packages, &self.prepared]
            .into_iter()
            .flatten()
        {
            let input = resolved_path(input)?;
            if diagnostics.starts_with(&input) || input.starts_with(&diagnostics) {
                return Err(CiError::Message(
                    "installed diagnostics must be independent of selected inputs".into(),
                ));
            }
        }
        Ok(())
    }
}

pub fn run(root: &Path, args: &InstalledTestArgs) -> Result<()> {
    args.validate()?;
    let cleanup = Instant::now() + Duration::from_secs(150 * 60);
    let work = cleanup - Duration::from_secs(15 * 60);
    let cancellation = crate::cancellation::Scope::install()?;
    let session = tempfile::Builder::new()
        .prefix("memcordon-installed-")
        .tempdir()?;
    if resolved_path(session.path())?.starts_with(resolved_path(&args.diagnostics)?) {
        return Err(CiError::Message(
            "installed diagnostics must be outside the owned input session".into(),
        ));
    }
    let (selected_target, selected_packages) = if let Some(prepared) = &args.prepared {
        let target = session.path().join("selected-target");
        let packages = session.path().join("selected-packages");
        let host = distribution::native_target()?;
        let fixture = root
            .join("target/ci/native/release")
            .join(super::target::binary_name("memcordon-test-fixture", host));
        installed_consumer::retain_original_public_inputs(
            prepared, host, &fixture, &target, &packages,
        )?;
        (target, packages)
    } else {
        (
            args.target.clone().expect("validated candidate target"),
            args.packages.clone().expect("validated candidate packages"),
        )
    };
    let (bundle, _) = TargetBundle::load(&selected_target)?;
    let (package_bundle, _) = super::packages::PackageBundle::load(&selected_packages)?;
    if package_bundle.source != bundle.source {
        return Err(CiError::Message(
            "installed target and package source selections differ".into(),
        ));
    }
    bundle.source.recheck(root)?;
    if bundle.distribution.target != distribution::native_target()? {
        return Err(CiError::Message(
            "installed test requires the selected native host".into(),
        ));
    }
    let expected = distribution::Distribution::read(root)?
        .with_runtime_components()?
        .native()?
        .clone();
    if bundle.distribution != expected {
        return Err(CiError::Message(
            "installed test requires the complete current runtime distribution".into(),
        ));
    }
    let (target, packages) = if let Some(prepared) = &args.prepared {
        installed_consumer::acquire_public_selected(
            prepared,
            &selected_target,
            &selected_packages,
            &session.path().join("public"),
            work,
        )?
    } else {
        (selected_target, selected_packages)
    };
    let payload = crate::preparation::with_operation(
        crate::failure_mode::FailureMode::StopAfterFailure,
        work,
        || {
            Ok(match args.delivery {
                Delivery::CandidateNative | Delivery::PublicNative => {
                    installed_consumer::materialize_native(&target, session.path())?
                }
                Delivery::CandidateCargo => {
                    let consumer =
                        PackageConsumer::prepare_selected(root, &packages, &bundle.distribution)?;
                    installed_consumer::materialize_cargo(
                        root,
                        &target,
                        &packages,
                        &bundle,
                        &consumer,
                        &root.join("target/ci-consumers"),
                        session.path(),
                    )?
                }
                Delivery::PublicCargo => installed_consumer::materialize_public_cargo(
                    root,
                    &target,
                    &packages,
                    &bundle,
                    &root.join("target/ci-consumers"),
                    session.path(),
                    &session.path().join("public-cargo"),
                    work,
                )?,
            })
        },
    )?;
    installed_consumer::require_current_runtime(&payload)?;
    eprintln!(
        "installed test: target={} delivery={:?} version={}",
        payload.distribution.target,
        args.delivery,
        payload.source.version()
    );
    let output = session.path().join("cases");
    let result = crate::preparation::with_operation(
        crate::failure_mode::FailureMode::StopAfterFailure,
        cleanup,
        || {
            installed_consumer::run_materialized_channel_until(
                root, &payload, &output, work, cleanup,
            )
        },
    );
    if let Err(error) = std::fs::create_dir_all(&args.diagnostics).and_then(|()| {
        std::fs::write(
            args.diagnostics.join("result.txt"),
            match &result {
                Ok(()) => "completed\n".into(),
                Err(error) => crate::command::bounded_excerpt(format!("{error}\n").as_bytes()),
            },
        )
    }) {
        eprintln!("optional installed diagnostics unavailable: {error}");
    }
    if result.is_err()
        && let Err(error) = retain_failure_output(&output, &args.diagnostics)
    {
        eprintln!("optional installed raw diagnostics unavailable: {error}");
    }
    cancellation.finish(result)
}
