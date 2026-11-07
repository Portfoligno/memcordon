//! Actual working-source Windows production payloads and independent installed channels.
use super::{
    distribution::{TargetDistribution, native_target},
    installed_consumer, packages,
    source::BuildSourceIdentity,
    target::{self, TargetBundle},
};
use crate::{CiError, Result, windows_causal_acceptance::InstalledChannel};
use std::{fs, path::Path};

pub fn selected_distribution(native: &str) -> Result<TargetDistribution> {
    if !matches!(native, "x86_64-pc-windows-msvc" | "aarch64-pc-windows-msvc") {
        return Err(CiError::Message(
            "Windows installed suite requires its actual native Windows architecture".into(),
        ));
    }
    let distribution = TargetDistribution {
        target: native.into(),
        features: vec!["windows-sealed-runtime".into()],
        binaries: [
            "memcordon",
            "memcordon-sealed-agent",
            "memcordon-target-desktop-bootstrap",
            "memcordon-session-broker",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
        units: Vec::new(),
    };
    distribution.validate()?;
    Ok(distribution)
}

/// Credential-free producer. The separately staged fixture remains outside the
/// production archive; payloads are built from working source without a release tag.
pub fn prepare_working(root: &Path, destination: &Path) -> Result<()> {
    let distribution = selected_distribution(native_target()?)?;
    let source = BuildSourceIdentity::working(root)?;
    fs::create_dir(destination)?;
    packages::prepare_build(
        root,
        &source,
        &root.join("target/ci-build/windows-packages"),
        &destination.join("cargo-payload"),
    )?;
    target::build_selected(
        root,
        &source,
        &distribution,
        &destination.join("native-payload"),
    )?;
    source.recheck(root)
}

/// A supplied producer output is mandatory. This never builds a missing native
/// archive or substitutes registry predecessors for selected .crate bytes.
pub fn run_working_channel(
    root: &Path,
    prepared: &Path,
    destination: &Path,
    channel: InstalledChannel,
) -> Result<()> {
    let (bundle, _) = TargetBundle::load(&prepared.join("native-payload"))?;
    if !matches!(bundle.source, BuildSourceIdentity::Working { .. })
        || bundle.distribution != selected_distribution(native_target()?)?
    {
        return Err(CiError::Message(
            "working Windows consumer selection differs".into(),
        ));
    }
    installed_consumer::run_channel(
        root,
        &prepared.join("native-payload"),
        &prepared.join("cargo-payload"),
        destination,
        channel,
    )
}

#[cfg(windows)]
pub fn run_provider_input_experiment(
    root: &Path,
    prepared: &Path,
    destination: &Path,
    dot_local_file: bool,
) -> Result<()> {
    use std::{
        path::PathBuf,
        time::{Duration, Instant},
    };
    let started = Instant::now();
    let cleanup = started + Duration::from_secs(150 * 60);
    let work = cleanup - Duration::from_secs(15 * 60);
    let native = prepared.join("native-payload");
    let (bundle, _) = TargetBundle::load(&native)?;
    bundle.source.recheck(root)?;
    if !matches!(bundle.source, BuildSourceIdentity::Working { .. })
        || bundle.distribution != selected_distribution(native_target()?)?
    {
        return Err(CiError::Message(
            "provider experiment requires its exact current native payload".into(),
        ));
    }
    installed_consumer::create_fresh_destination(destination)?;
    let payload = installed_consumer::materialize_native(&native, destination)?;
    installed_consumer::require_current_runtime(&payload)?;
    let installed = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .ok_or_else(|| CiError::Message("native ProgramFiles missing".into()))?
        .join("MemCordon");
    let config = crate::windows_installed_cases::InstalledWindowsPayload::from_materialized(
        payload.channel,
        &payload.source,
        &payload.distribution,
        payload.selected_case_artifacts()?,
        &payload.directory,
        payload.fixture.clone(),
        &installed,
        std::path::absolute(destination.join("cases"))?,
    )?;
    let deadlines = crate::windows_installed_cases::WindowsLeaseDeadlines::new(work, cleanup)?;
    let result = crate::windows_installed_cases::run_provider_input_experiment_from_source_until(
        root,
        &config,
        deadlines,
        dot_local_file,
    );
    if result.is_err() {
        let _retained = payload.retain();
    }
    result
}

#[cfg(not(windows))]
pub fn run_provider_input_experiment(_: &Path, _: &Path, _: &Path, _: bool) -> Result<()> {
    Err(CiError::Message(
        "declared provider input experiment requires native Windows".into(),
    ))
}

/// Sequential local compatibility. Workflow consumers use the separate channel
/// entrypoint on fresh hosts and only their exact producer artifacts.
pub fn run_working(root: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    let prepared = destination.join("prepared");
    prepare_working(root, &prepared)?;
    run_working_channel(
        root,
        &prepared,
        &destination.join("native-installed"),
        InstalledChannel::NativeBundle,
    )?;
    run_working_channel(
        root,
        &prepared,
        &destination.join("cargo-installed"),
        InstalledChannel::CargoPackage,
    )
}
