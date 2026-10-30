//! Execute consumers against the selected, measured distribution in both channels.
#[path = "public_install_io.rs"]
mod public_install_io;
#[path = "public_registry_location.rs"]
mod public_registry_location;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use memcordon_core::{MemcordonReport, runtime_components::RuntimeComponentRole};

use super::{
    artifacts,
    distribution::{TargetDistribution, native_target},
    packages::PackageConsumer,
    source::{self, BuildSourceIdentity},
    target::{self, TargetBundle},
};
use crate::{
    CiError, Result, command::CommandSpec, windows_causal_acceptance::InstalledChannel,
    windows_installed_cases::SelectedArtifact,
};

pub struct MaterializedPayload {
    pub channel: InstalledChannel,
    pub source: BuildSourceIdentity,
    pub distribution: TargetDistribution,
    pub directory: PathBuf,
    pub artifacts: Vec<SelectedArtifact>,
    selected_artifact_count: usize,
    pub fixture: SelectedArtifact,
    pub workload_diagnostic: Option<crate::windows_installed_cases::WorkloadDiagnosticInput>,
    _owner: tempfile::TempDir,
}

impl MaterializedPayload {
    pub fn selected_case_artifacts(&self) -> Result<Vec<SelectedArtifact>> {
        installed_case_artifacts(
            &self.artifacts,
            self.selected_artifact_count,
            self.distribution.binaries.len(),
        )
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SmokePayload {
    channel: InstalledChannel,
    source: BuildSourceIdentity,
    distribution: TargetDistribution,
    directory: PathBuf,
    artifacts: Vec<SelectedArtifact>,
    selected_artifact_count: usize,
    fixture: SelectedArtifact,
}
#[cfg(target_os = "linux")]
impl SmokePayload {
    fn describe(payload: &MaterializedPayload) -> Self {
        Self {
            channel: payload.channel,
            source: payload.source.clone(),
            distribution: payload.distribution.clone(),
            directory: payload.directory.clone(),
            artifacts: payload.artifacts.clone(),
            selected_artifact_count: payload.selected_artifact_count,
            fixture: payload.fixture.clone(),
        }
    }
    fn reopen(self, parent: &Path) -> Result<MaterializedPayload> {
        self.source.validate()?;
        self.distribution.validate()?;
        if !self.distribution.target.ends_with("-unknown-linux-gnu")
            || self.artifacts.len() > 64
            || self.selected_artifact_count > self.artifacts.len()
        {
            return Err(CiError::Message(
                "current Linux smoke descriptive inventory differs".into(),
            ));
        }
        let owner = tempfile::Builder::new()
            .prefix("current-smoke-payload-")
            .tempdir_in(parent)?;
        let directory = owner.path().join("payload");
        fs::create_dir(&directory)?;
        for name in self
            .distribution
            .binaries
            .iter()
            .map(|binary| binary_path(&self.directory, binary, &self.distribution.target))
            .chain(
                self.distribution
                    .units
                    .iter()
                    .map(|unit| self.directory.join(unit)),
            )
            .chain(std::iter::once(
                self.directory.join("runtime-manifest.json"),
            ))
        {
            let bytes = artifacts::read_file(&name)?;
            let destination = directory.join(name.file_name().ok_or_else(|| {
                CiError::Message("current smoke component filename absent".into())
            })?);
            fs::write(&destination, bytes)?;
            if self.distribution.binaries.iter().any(|binary| {
                binary_path(&self.directory, binary, &self.distribution.target) == name
            }) {
                executable(&destination)?;
            }
        }
        let mut copied = Vec::new();
        for (index, artifact) in self.artifacts.into_iter().enumerate() {
            let bytes = artifacts::read_file(&artifact.path)?;
            if artifacts::checksum(&bytes) != artifact.sha256 {
                return Err(CiError::Message(
                    "current smoke retained artifact changed".into(),
                ));
            }
            let destination = owner.path().join(format!("artifact-{index}"));
            fs::create_dir(&destination)?;
            let path = destination.join(artifact.path.file_name().ok_or_else(|| {
                CiError::Message("current smoke artifact filename absent".into())
            })?);
            fs::write(&path, bytes)?;
            copied.push(SelectedArtifact {
                path,
                sha256: artifact.sha256,
            });
        }
        let bytes = artifacts::read_file(&self.fixture.path)?;
        if artifacts::checksum(&bytes) != self.fixture.sha256 {
            return Err(CiError::Message("current smoke fixture changed".into()));
        }
        target::validate_executable(&bytes, &self.distribution.target)?;
        let path = owner.path().join("fixture");
        fs::write(&path, bytes)?;
        executable(&path)?;
        Ok(MaterializedPayload {
            channel: self.channel,
            source: self.source,
            distribution: self.distribution,
            directory,
            artifacts: copied,
            selected_artifact_count: self.selected_artifact_count,
            fixture: SelectedArtifact {
                path,
                sha256: self.fixture.sha256,
            },
            workload_diagnostic: None,
            _owner: owner,
        })
    }
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentSmokeSpec {
    format: String,
    revision: u32,
    payload: SmokePayload,
    output: PathBuf,
    operation_deadline_unix_millis: u64,
    workflow_run: Option<String>,
    diagnostic_output: PathBuf,
}

#[cfg(target_os = "linux")]
pub fn run_current_smoke_spec(root: &Path, path: &Path, cleanup_only: bool) -> Result<()> {
    if !rustix::process::geteuid().is_root() {
        return Err(CiError::Message(
            "current native smoke reentry requires the actual privileged controller".into(),
        ));
    }
    let bytes = artifacts::read_file(path)?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(CiError::Message(
            "current smoke metadata bound exceeded".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let spec: CurrentSmokeSpec = serde_json::from_slice(&bytes)?;
    if spec.format != "memcordon.current-materialized-smoke" || spec.revision != 1 {
        return Err(CiError::Message("current smoke format differs".into()));
    }
    let sampled = std::time::Instant::now();
    let now = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| CiError::Message(e.to_string()))?
            .as_millis(),
    )
    .map_err(|e| CiError::Message(e.to_string()))?;
    let remaining = spec
        .operation_deadline_unix_millis
        .checked_sub(now)
        .filter(|ms| *ms > 0 && *ms <= 150 * 60 * 1000)
        .ok_or_else(|| {
            CiError::Message(
                "current smoke original absolute deadline exhausted/out of bound".into(),
            )
        })?;
    let cleanup = sampled
        .checked_add(Duration::from_millis(remaining))
        .ok_or_else(|| CiError::Message("current smoke deadline overflow".into()))?;
    let operation = if cleanup_only { "cleanup" } else { "execute" };
    let diagnostic_source = spec
        .output
        .parent()
        .ok_or_else(|| CiError::Message("private smoke authority parent absent".into()))?
        .to_path_buf();
    if spec.output.file_name().and_then(|name| name.to_str()) != Some("linux-installed")
        || !diagnostic_source.starts_with(std::path::absolute(root.join("target/ci"))?)
        || spec.diagnostic_output
            != std::path::absolute(root.join("target/ci/private-installed-diagnostics"))?
    {
        return Err(CiError::Message(
            "private smoke diagnostic/authority namespace differs from selected CI output".into(),
        ));
    }
    let diagnostic_output = spec
        .diagnostic_output
        .join(format!("{operation}-{}", std::process::id()));
    let result = run_current_smoke_owned(root, spec, cleanup_only, cleanup);
    let exported = super::linux_smoke_diagnostics::export(
        &diagnostic_source,
        &diagnostic_output,
        cleanup,
        operation,
        &result,
    );
    if let Ok(crate::diagnostic_projection::Projection::Incomplete { limits, .. }) = &exported {
        eprintln!(
            "diagnostic projection incomplete: {limits:?}; original operation result retained"
        );
    }
    crate::work_outcome::join_completed(
        crate::work_outcome::WorkOutcome::from_result(result),
        crate::work_outcome::WorkOutcome::from_result(exported.map(|_| ())),
    )
    .into_result()
}

#[cfg(target_os = "linux")]
fn run_current_smoke_owned(
    root: &Path,
    spec: CurrentSmokeSpec,
    cleanup_only: bool,
    cleanup: std::time::Instant,
) -> Result<()> {
    if cleanup_only {
        spec.payload.source.validate()?;
        spec.payload.distribution.validate()?;
        let key = memcordon_readiness_verifier::ProductKey {
            target: spec.payload.distribution.target.clone(),
            channel: match spec.payload.channel {
                InstalledChannel::NativeBundle => "candidate-native",
                InstalledChannel::CargoPackage => "candidate-cargo",
            }
            .into(),
        };
        let lifetime = spec
            .output
            .join(&key.target)
            .join(&key.channel)
            .join("lifetime");
        let artifacts = super::linux_current_installed::recover_current_smoke(
            root,
            &lifetime,
            &spec.output,
            spec.payload.source.commit(),
            &spec.payload.source.version().to_string(),
            &key,
            cleanup,
        )?;
        let pid = std::process::id();
        let birth =
            crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
        source::write_json(
            &spec.output.join(format!(
                "local-smoke-cleanup-observations-{pid}-{birth}.json"
            )),
            &serde_json::json!({"format":"memcordon.local-current-smoke-cleanup","revision":1,"workflow_qualification":false,"artifacts":artifacts}),
        )?;
        return Ok(());
    }
    let work = cleanup
        .checked_sub(Duration::from_secs(15 * 60))
        .filter(|time| *time > std::time::Instant::now())
        .ok_or_else(|| CiError::Message("original current smoke work budget exhausted".into()))?;
    let payload = spec.payload.reopen(Path::new("/tmp"))?;
    require_current_runtime(&payload)?;
    let head = CommandSpec::new("git", root, Duration::from_secs(30))
        .args(["rev-parse", "--verify", "HEAD"])
        .bounded_until(work)
        .run()?;
    if std::str::from_utf8(&head)
        .map_err(|e| CiError::Message(e.to_string()))?
        .trim()
        != payload.source.commit()
    {
        return Err(CiError::Message(
            "current smoke source HEAD differs from selected bytes".into(),
        ));
    }
    let archive = CommandSpec::new("git", root, Duration::from_secs(60))
        .args(["archive", "--format=tar", payload.source.commit()])
        .output_limit(source::MAX_SOURCE_ARCHIVE_BYTES)
        .bounded_until(work)
        .output_quiet()?;
    if !archive.status.success() {
        return Err(CiError::Message(
            "actual current smoke source archive failed".into(),
        ));
    }
    let pid = std::process::id();
    let birth = crate::linux_consumer_readiness::process_birth(pid).map_err(CiError::Message)?;
    let run_id = match spec.workflow_run {
        Some(run)
            if run.parse::<u64>().ok().is_some_and(|id| id > 0)
                && run.bytes().all(|b| b.is_ascii_digit()) =>
        {
            run
        }
        Some(_) => {
            return Err(CiError::Message(
                "native workflow run identity invalid".into(),
            ));
        }
        None => format!("local-controller-{pid}-{birth}"),
    };
    let identity = crate::readiness_identity::SourceIdentity {
        run_id,
        source_commit: payload.source.commit().into(),
        source_tree_sha256: artifacts::checksum(&archive.stdout),
        version: payload.source.version().to_string(),
    };
    let key = memcordon_readiness_verifier::ProductKey {
        target: payload.distribution.target.clone(),
        channel: match payload.channel {
            InstalledChannel::NativeBundle => "candidate-native",
            InstalledChannel::CargoPackage => "candidate-cargo",
        }
        .into(),
    };
    fs::create_dir(&spec.output)?;
    let namespace = std::path::absolute(&spec.output)?;
    let publication = std::sync::Arc::new(
        super::linux_lifecycle_diagnostics::HeldCellPublication::create(
            &namespace, &identity, &key,
        )?,
    );
    let lifetime = namespace
        .join(&key.target)
        .join(&key.channel)
        .join("lifetime");
    let (records, artifacts) = super::linux_current_installed::run_current_cell(
        root,
        &payload,
        &identity,
        &key,
        &lifetime,
        &namespace,
        work,
        cleanup,
        spec.operation_deadline_unix_millis,
        publication,
    )?;
    source::write_json(
        &namespace.join("local-smoke-observations.json"),
        &serde_json::json!({"format":"memcordon.local-current-smoke","revision":1,"workflow_qualification":false,"identity":identity,"records":records,"artifacts":artifacts}),
    )?;
    Ok(())
}

/// Verify the complete retained acquisition before selecting its original channel
/// inventory for installed cases. Compiler captures remain retained evidence.
pub fn installed_case_artifacts(
    all: &[SelectedArtifact],
    selected_count: usize,
    binary_count: usize,
) -> Result<Vec<SelectedArtifact>> {
    if selected_count == 0
        || selected_count > 16
        || selected_count > all.len()
        || binary_count == 0
        || binary_count > 16
    {
        return Err(CiError::Message(
            "installed channel artifact inventory is invalid".into(),
        ));
    }
    // Four actual compiler capture files per bin, three acquisition records,
    // two install streams and at most the four verified public registry crates.
    let auxiliary_bound = binary_count * 4 + 5 + source::PUBLIC_PACKAGES.len();
    if all.len() - selected_count > auxiliary_bound {
        return Err(CiError::Message(
            "installed auxiliary artifact inventory exceeds its capture contract".into(),
        ));
    }
    let mut paths = std::collections::BTreeSet::new();
    for artifact in all {
        if !paths.insert(&artifact.path)
            || artifacts::checksum(&artifacts::read_file(&artifact.path)?) != artifact.sha256
        {
            return Err(CiError::Message(
                "installed acquisition artifact is duplicated or changed".into(),
            ));
        }
    }
    Ok(all[..selected_count].to_vec())
}

pub fn binary_path(directory: &Path, binary: &str, target: &str) -> PathBuf {
    let mut path = directory.join(binary);
    if target.ends_with("-pc-windows-msvc") {
        path.set_extension("exe");
    }
    path
}

/// Selects the measured executable, independently of the channel archive inventory.
pub fn materialized_windows_agent(
    source: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    directory: &Path,
) -> Result<SelectedArtifact> {
    let (_, components) = materialized_windows_components(source, distribution, directory)?;
    components
        .into_iter()
        .find(|component| {
            component
                .path
                .file_name()
                .is_some_and(|name| name == "memcordon-sealed-agent.exe")
        })
        .ok_or_else(|| CiError::Message("selected Windows agent absent from manifest".into()))
}

/// Binds the original manifest and every measured executable before retention.
pub fn materialized_windows_components(
    source: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    directory: &Path,
) -> Result<(SelectedArtifact, Vec<SelectedArtifact>)> {
    if !distribution.target.ends_with("-pc-windows-msvc") {
        return Err(CiError::Message(
            "selected agent requires Windows distribution".into(),
        ));
    }
    let manifest_path = std::path::absolute(directory.join("runtime-manifest.json"))?;
    let bytes = artifacts::read_file(&manifest_path)?;
    let revision: serde_json::Value = serde_json::from_slice(&bytes)?;
    let measured = match revision["revision"].as_u64() {
        Some(2) => {
            let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&bytes)
                .map_err(CiError::Message)?;
            if manifest != measured_current_manifest(source, distribution, directory)? {
                return Err(CiError::Message(
                    "current selected manifest differs from measured bytes".into(),
                ));
            }
            manifest.components
        }
        _ => {
            return Err(CiError::Message(
                "unsupported selected manifest revision".into(),
            ));
        }
    };
    let components = measured
        .into_iter()
        .map(|component| {
            Ok(SelectedArtifact {
                path: std::path::absolute(directory.join(component.path))?,
                sha256: component.sha256,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((
        SelectedArtifact {
            path: manifest_path,
            sha256: artifacts::checksum(&bytes),
        },
        components,
    ))
}

fn executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

pub fn measured_current_manifest(
    source: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    directory: &Path,
) -> Result<memcordon_core::runtime_manifest_v2::RuntimeManifestV2> {
    use memcordon_core::runtime_manifest_v2::RuntimeManifestV2;
    source.validate()?;
    distribution.validate()?;
    let mut components = Vec::new();
    for binary in &distribution.binaries {
        let path = binary_path(directory, binary, &distribution.target);
        let bytes = artifacts::read_file(&path)?;
        target::validate_executable(&bytes, &distribution.target)?;
        let role = match binary.as_str() {
            "memcordon" => RuntimeComponentRole::PublicCli,
            "memcordon-sealed-agent" => RuntimeComponentRole::SealedAgent,
            "memcordon-target-desktop-bootstrap" => RuntimeComponentRole::DesktopBootstrap,
            "memcordon-session-broker" => RuntimeComponentRole::SessionBroker,
            _ => {
                return Err(CiError::Message(
                    "unknown current selected component".into(),
                ));
            }
        };
        components.push(target::runtime_component(
            role,
            path.file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    CiError::Message("current component filename encoding differs".into())
                })?
                .into(),
            &bytes,
        ));
    }
    let runtime = distribution.runtime_selection()?;
    let result = if runtime == super::distribution::RuntimeSelection::CliOnly {
        RuntimeManifestV2::cli_only(
            source.version().to_string(),
            source.commit().into(),
            distribution.target.clone(),
            components,
        )
    } else if runtime == super::distribution::RuntimeSelection::WindowsSealed {
        RuntimeManifestV2::windows(
            source.version().to_string(),
            source.commit().into(),
            distribution.target.clone(),
            components,
        )
    } else {
        RuntimeManifestV2::linux(
            source.version().to_string(),
            source.commit().into(),
            distribution.target.clone(),
            components,
            runtime == super::distribution::RuntimeSelection::LinuxPrivateTcp,
        )
    };
    result.map_err(CiError::Message)
}

pub fn require_current_runtime(payload: &MaterializedPayload) -> Result<()> {
    let bytes = artifacts::read_file(&payload.directory.join("runtime-manifest.json"))?;
    let actual = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&bytes)
        .map_err(|_| CiError::Message("UnsupportedProductInterface".into()))?;
    let measured =
        measured_current_manifest(&payload.source, &payload.distribution, &payload.directory)?;
    if actual != measured {
        return Err(CiError::Message(
            "current selected runtime differs from measured inventory".into(),
        ));
    }
    Ok(())
}

fn fixture(
    bundle: &TargetBundle,
    target_directory: &Path,
    directory: &Path,
) -> Result<SelectedArtifact> {
    let bytes = artifacts::read_file(&target_directory.join(&bundle.fixture.name))?;
    artifacts::check_bytes(&bundle.fixture, &bytes)?;
    target::validate_executable(&bytes, &bundle.distribution.target)?;
    let path = directory.join(&bundle.fixture.name);
    fs::write(&path, &bytes)?;
    executable(&path)?;
    Ok(SelectedArtifact {
        path,
        sha256: bundle.fixture.sha256.clone(),
    })
}

fn workload_diagnostic(
    bundle: &TargetBundle,
    target_directory: &Path,
    directory: &Path,
) -> Result<Option<crate::windows_installed_cases::WorkloadDiagnosticInput>> {
    bundle
        .workload_diagnostic_input(target_directory)?
        .map(|mut input| {
            let path = directory.join("memcordon-windows-loader-lab.exe");
            fs::write(&path, artifacts::read_file(&input.executable.path)?)?;
            executable(&path)?;
            input.executable.path = path;
            input.validate_for(&bundle.source, &bundle.distribution.target)?;
            Ok(input)
        })
        .transpose()
}

pub fn materialize_native(
    target_directory: &Path,
    temporary_parent: &Path,
) -> Result<MaterializedPayload> {
    let (bundle, archive) = TargetBundle::load(target_directory)?;
    let owner = tempfile::Builder::new()
        .prefix("native-consumer-")
        .tempdir_in(std::path::absolute(temporary_parent)?)?;
    let directory = owner.path().join("payload");
    artifacts::extract_members(
        &target::decode_archive(&archive, &bundle.distribution.target)?,
        &directory,
    )?;
    for binary in &bundle.distribution.binaries {
        executable(&binary_path(
            &directory,
            binary,
            &bundle.distribution.target,
        ))?;
    }
    let fixture = fixture(&bundle, target_directory, owner.path())?;
    let workload_diagnostic = workload_diagnostic(&bundle, target_directory, owner.path())?;
    Ok(MaterializedPayload {
        channel: InstalledChannel::NativeBundle,
        source: bundle.source,
        distribution: bundle.distribution,
        directory,
        artifacts: vec![SelectedArtifact {
            path: target_directory.join(&bundle.archive.name),
            sha256: bundle.archive.sha256,
        }],
        selected_artifact_count: 1,
        fixture,
        workload_diagnostic,
        _owner: owner,
    })
}

pub fn materialize_cargo(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    bundle: &TargetBundle,
    consumer: &PackageConsumer,
    cache: &Path,
    temporary_parent: &Path,
) -> Result<MaterializedPayload> {
    if consumer.bundle.source != bundle.source {
        return Err(CiError::Message(
            "Cargo and native source selections differ".into(),
        ));
    }
    consumer.build(root, cache)?;
    consumer.install_cli(root, cache, &bundle.distribution)?;
    materialize_cargo_install(
        root,
        target_directory,
        package_directory,
        bundle,
        &consumer.bundle,
        &consumer.install_root,
        temporary_parent,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Public Cargo materialization binds original source, package, target, toolchain, roots, and deadline"
)]
pub fn materialize_public_cargo(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    bundle: &TargetBundle,
    cache: &Path,
    temporary_parent: &Path,
    receipts: &Path,
    deadline: std::time::Instant,
) -> Result<MaterializedPayload> {
    let (packages, _) = super::packages::PackageBundle::load(package_directory)?;
    if packages.source != bundle.source {
        return Err(CiError::Message(
            "public registry packages and selected native source differ".into(),
        ));
    }
    fs::create_dir(receipts)?;
    source::write_json(
        &receipts.join("public-cargo-install-intent.json"),
        &serde_json::json!({"format":"memcordon.public-cargo-install-intent","revision":1,"source":bundle.source,"target":bundle.distribution.target,"registry":"crates-io","locked":true}),
    )?;
    let acquisition = tempfile::Builder::new()
        .prefix("public-registry-install-")
        .tempdir()?;
    public_registry_location::require_independent(acquisition.path()).map_err(CiError::Message)?;
    let home = acquisition.path().join("cargo-home");
    fs::create_dir(&home)?;
    crate::cache_inputs::seed_current_downloads(&home, true)?;
    let install = acquisition.path().join("install");
    let stable = crate::config::toolchains(root)?.stable;
    fs::create_dir_all(cache)?;
    let install_target = tempfile::Builder::new()
        .prefix("public-install-target-")
        .tempdir_in(std::path::absolute(cache)?)?;
    let capture = prepare_public_install_capture(
        root,
        acquisition.path(),
        install_target.path(),
        &home,
        receipts,
        &stable,
        &bundle.distribution,
        &bundle.source,
        deadline,
    )?;
    let mut command = crate::command::rustup_cargo(
        acquisition.path(),
        &stable,
        [
            "install",
            "memcordon",
            "--registry",
            "crates-io",
            "--locked",
        ],
        Duration::from_secs(7200),
    )
    .arg("--version")
    .arg(format!("={}", bundle.source.version()))
    .arg("--target")
    .arg(&bundle.distribution.target)
    .arg("--root")
    .arg(&install)
    .arg("--target-dir")
    .arg(install_target.path())
    .arg("--config")
    .arg(format!(
        "build.rustc-wrapper={}",
        serde_json::to_string(&capture.wrapper)?
    ))
    .arg("--config")
    .arg(format!(
        "build.rustc={}",
        serde_json::to_string(&capture.descriptor.compiler)?
    ))
    .arg("--message-format=json")
    .isolated_cargo(&home)
    .bounded_until(deadline);
    for feature in &bundle.distribution.features {
        command = command.arg("--features").arg(feature);
    }
    for binary in &bundle.distribution.binaries {
        command = command.arg("--bin").arg(binary);
    }
    let observed = command.output_quiet()?;
    crate::cache_inputs::export_current_downloads(&home);
    for (name, bytes) in [
        ("public-cargo-install.stdout.jsonl", &observed.stdout),
        ("public-cargo-install.stderr.bin", &observed.stderr),
    ] {
        fs::write(receipts.join(name), bytes)?;
    }
    source::write_json(
        &receipts.join("public-cargo-install.json"),
        &serde_json::json!({"format":"memcordon.public-cargo-install","revision":1,"target":bundle.distribution.target,"version":bundle.source.version(),"features":bundle.distribution.features,"binaries":bundle.distribution.binaries,"registry":"crates-io","patches":false,"locked":true,"status":observed.status.code()}),
    )?;
    if !observed.status.success() {
        return Err(CiError::Message(format!(
            "ordinary public Cargo installation failed with {}",
            observed.status
        )));
    }
    let manifest = verify_public_install_artifacts(
        &observed.stdout,
        &home,
        &install,
        &bundle.distribution,
        &bundle.source,
        &capture.descriptor,
    )?;
    let cached_packages = verify_cached_public_packages(&home, &packages, receipts)?;
    retain_public_registry_graph(
        root,
        &home,
        &manifest,
        &bundle.distribution,
        &packages,
        receipts,
        deadline,
    )?;
    let mut payload = materialize_cargo_install(
        root,
        target_directory,
        package_directory,
        bundle,
        &packages,
        &install,
        temporary_parent,
    )?;
    payload.artifacts.extend(cached_packages);
    retain_public_install_capture(&mut payload, &capture.descriptor, receipts)?;
    for (name, bytes) in [
        ("public-cargo-install.stdout.jsonl", observed.stdout),
        ("public-cargo-install.stderr.bin", observed.stderr),
    ] {
        let path = receipts.join(name);
        payload.artifacts.push(SelectedArtifact {
            path,
            sha256: String::from(memcordon_core::hash_bytes(&bytes)),
        });
    }
    Ok(payload)
}

/// Read-only public acquisition joins exposed bytes to the original selected
/// publication pair. It does not authorize or reconcile publication.
pub fn retain_original_public_inputs(
    prepared: &Path,
    target_name: &str,
    fixture_path: &Path,
    diagnostic_path: Option<&Path>,
    target_directory: &Path,
    package_directory: &Path,
) -> Result<()> {
    let original = super::bundle::PreparedBundle::load(prepared)?;
    let selected: BuildSourceIdentity = original.metadata.source.clone().into();
    let distribution = original
        .metadata
        .distribution
        .targets
        .iter()
        .find(|target| target.target == target_name)
        .ok_or_else(|| {
            CiError::Message("original prepared pair lacks selected native target".into())
        })?
        .clone();
    let archives: Vec<_> = original
        .metadata
        .files
        .iter()
        .enumerate()
        .filter(|(_, file)| file.kind == "archive" && file.target.as_deref() == Some(target_name))
        .collect();
    if archives.len() != 1 {
        return Err(CiError::Message(
            "original prepared pair has ambiguous selected native archive".into(),
        ));
    }
    let (index, archive) = archives[0];
    let members = super::target::decode_archive(&original.payloads[index], target_name)?;
    let executable_names: std::collections::BTreeSet<_> = distribution
        .binaries
        .iter()
        .map(|binary| super::target::binary_name(binary, target_name))
        .collect();
    let records = members
        .iter()
        .map(|(name, bytes)| super::artifacts::FileRecord {
            name: name.clone(),
            kind: if executable_names.contains(name) {
                "executable"
            } else {
                "runtime-data"
            }
            .into(),
            target: Some(target_name.into()),
            package: None,
            byte_len: bytes.len() as u64,
            sha256: super::artifacts::checksum(bytes),
        })
        .collect();
    let fixture_bytes = super::artifacts::read_file(fixture_path)?;
    super::target::validate_executable(&fixture_bytes, target_name)?;
    let fixture = super::artifacts::FileRecord {
        name: super::target::binary_name("memcordon-test-fixture", target_name),
        kind: "fixture".into(),
        target: Some(target_name.into()),
        package: None,
        byte_len: fixture_bytes.len() as u64,
        sha256: super::artifacts::checksum(&fixture_bytes),
    };
    fs::create_dir(target_directory)?;
    fs::create_dir(package_directory)?;
    fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    }
    retain(
        &target_directory.join(&archive.name),
        &original.payloads[index],
    )?;
    retain(&target_directory.join(&fixture.name), &fixture_bytes)?;
    let workload_diagnostic = if target_name.ends_with("-pc-windows-msvc") {
        let path = diagnostic_path.ok_or_else(|| {
            CiError::Message(
                "current public Windows inputs require their qualified diagnostic companion".into(),
            )
        })?;
        let record = super::target::WorkloadDiagnosticBundle::load(path, &selected, target_name)?;
        let bytes = artifacts::read_file(
            &path
                .parent()
                .ok_or_else(|| CiError::Message("diagnostic companion parent absent".into()))?
                .join(&record.executable.name),
        )?;
        artifacts::check_bytes(&record.executable, &bytes)?;
        retain(&target_directory.join(&record.executable.name), &bytes)?;
        Some(record.executable)
    } else {
        None
    };
    super::source::write_json(
        &target_directory.join("target.json"),
        &TargetBundle {
            format: "memcordon.target".into(),
            revision: 1,
            source: selected.clone(),
            distribution,
            archive: archive.clone(),
            members: records,
            fixture,
            workload_diagnostic,
        },
    )?;
    let mut crate_records = Vec::new();
    for (index, file) in original.metadata.files.iter().enumerate() {
        if file.kind == "crate" {
            retain(
                &package_directory.join(&file.name),
                &original.payloads[index],
            )?;
            crate_records.push(file.clone());
        }
    }
    if crate_records.len() != 4 {
        return Err(CiError::Message(
            "original prepared pair lacks exactly four final crates".into(),
        ));
    }
    super::source::write_json(
        &package_directory.join("packages.json"),
        &super::packages::PackageBundle {
            format: "memcordon.packages".into(),
            revision: 1,
            source: selected,
            files: crate_records,
        },
    )?;
    fs::File::open(target_directory)?.sync_all()?;
    fs::File::open(package_directory)?.sync_all()?;
    TargetBundle::load(target_directory)?;
    super::packages::PackageBundle::load(package_directory)?;
    Ok(())
}

pub fn acquire_public_selected(
    prepared: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
    deadline: std::time::Instant,
) -> Result<(PathBuf, PathBuf)> {
    let original = super::bundle::PreparedBundle::load(prepared)?;
    let (target, _) = TargetBundle::load(target_directory)?;
    let (packages, _) = super::packages::PackageBundle::load(package_directory)?;
    let selected: BuildSourceIdentity = original.metadata.source.clone().into();
    if target.source != selected
        || packages.source != selected
        || !original
            .metadata
            .distribution
            .targets
            .contains(&target.distribution)
    {
        return Err(CiError::Message(
            "public acquisition differs from original selected source/profile".into(),
        ));
    }
    fs::create_dir(destination)?;
    let native = destination.join("native");
    let cargo = destination.join("packages");
    fs::create_dir(&native)?;
    fs::create_dir(&cargo)?;
    let budget = super::http::ReadBudget::new(deadline);
    let mut archive_url = url::Url::parse("https://github.com/")
        .map_err(|_| CiError::Message("public native origin URL invalid".into()))?;
    {
        let mut path = archive_url
            .path_segments_mut()
            .map_err(|_| CiError::Message("public native origin cannot hold path".into()))?;
        path.pop_if_empty();
        for part in original.metadata.source.repository.split('/') {
            path.push(part);
        }
        path.push("releases")
            .push("download")
            .push(&original.metadata.source.version.to_string())
            .push(&target.archive.name);
    }
    let archive = super::http::download(
        &super::http::HttpsTransport,
        &budget,
        &archive_url,
        &[],
        artifacts::MAX_FILE_BYTES,
    )?;
    artifacts::check_bytes(&target.archive, &archive)?;
    fs::write(native.join(&target.archive.name), &archive)?;
    // The owned fixture is separately measured source, never represented as a
    // consumer executable downloaded from the release archive.
    let fixture = artifacts::read_file(&target_directory.join(&target.fixture.name))?;
    artifacts::check_bytes(&target.fixture, &fixture)?;
    fs::write(native.join(&target.fixture.name), fixture)?;
    if let Some(diagnostic) = &target.workload_diagnostic {
        let bytes = artifacts::read_file(&target_directory.join(&diagnostic.name))?;
        artifacts::check_bytes(diagnostic, &bytes)?;
        fs::write(native.join(&diagnostic.name), bytes)?;
    }
    source::write_json(&native.join("target.json"), &target)?;
    for record in &packages.files {
        if !original.metadata.files.contains(record) {
            return Err(CiError::Message(
                "public crate not in original publication pair".into(),
            ));
        }
        let mut url = url::Url::parse("https://static.crates.io/crates/")
            .map_err(|_| CiError::Message("public registry origin URL invalid".into()))?;
        url.path_segments_mut()
            .map_err(|_| CiError::Message("public registry origin cannot hold path".into()))?
            .pop_if_empty()
            .push(
                record.package.as_deref().ok_or_else(|| {
                    CiError::Message("public crate package identity absent".into())
                })?,
            )
            .push(&record.name);
        let bytes = super::http::download(
            &super::http::HttpsTransport,
            &budget,
            &url,
            &[],
            artifacts::MAX_FILE_BYTES,
        )?;
        artifacts::check_bytes(record, &bytes)?;
        fs::write(cargo.join(&record.name), bytes)?;
    }
    source::write_json(&cargo.join("packages.json"), &packages)?;
    TargetBundle::load(&native)?;
    super::packages::PackageBundle::load(&cargo)?;
    source::write_json(
        &destination.join("public-acquisition.json"),
        &serde_json::json!({"format":"memcordon.public-selected-acquisition","revision":1,"source":selected,"target":target.distribution.target,"native_url":archive_url.as_str(),"native_sha256":target.archive.sha256,"crate_files":packages.files,"read_only":true}),
    )?;
    Ok((native, cargo))
}

fn verify_cached_public_packages(
    home: &Path,
    packages: &super::packages::PackageBundle,
    receipts: &Path,
) -> Result<Vec<SelectedArtifact>> {
    let cache = home.join("registry").join("cache");
    let registries = fs::read_dir(&cache)?.collect::<std::io::Result<Vec<_>>>()?;
    if registries.is_empty() || registries.len() > 16 {
        return Err(CiError::Message(
            "public Cargo registry cache scope is absent or excessive".into(),
        ));
    }
    let destination = receipts.join("consumed-crates");
    fs::create_dir(&destination)?;
    let mut result = Vec::new();
    for record in &packages.files {
        let matches = registries
            .iter()
            .map(|registry| registry.path().join(&record.name))
            .filter_map(|path| match fs::symlink_metadata(&path) {
                Ok(metadata) => Some(Ok((path, metadata))),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => Some(Err(error)),
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        if matches.len() != 1 || !matches[0].1.is_file() {
            return Err(CiError::Message(
                "exact consumed public crate cache member absent, aliased or ambiguous".into(),
            ));
        }
        let bytes = artifacts::read_file(&matches[0].0)?;
        artifacts::check_bytes(record, &bytes)?;
        let path = destination.join(&record.name);
        fs::write(&path, &bytes)?;
        result.push(SelectedArtifact {
            path,
            sha256: record.sha256.clone(),
        });
    }
    Ok(result)
}

struct PublicInstallCapture {
    wrapper: PathBuf,
    descriptor: crate::public_install_capture::Descriptor,
}

fn retain_public_install_capture(
    payload: &mut MaterializedPayload,
    capture: &crate::public_install_capture::Descriptor,
    receipts: &Path,
) -> Result<()> {
    for binary in &capture.binaries {
        for suffix in ["json", "bin", "stdout.bin", "stderr.bin"] {
            let path = capture.capture_directory.join(format!("{binary}.{suffix}"));
            let bytes = artifacts::read_file(&path)?;
            payload.artifacts.push(SelectedArtifact {
                path,
                sha256: artifacts::checksum(&bytes),
            });
        }
    }
    for name in [
        "public-install-capture-descriptor.json",
        "public-install-compiler-path.stdout",
        "public-install-compiler-path.stderr",
    ] {
        let path = receipts.join(name);
        let bytes = artifacts::read_file(&path)?;
        payload.artifacts.push(SelectedArtifact {
            path,
            sha256: artifacts::checksum(&bytes),
        });
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Original capture binds compiler, source, target, owned scopes and deadline"
)]
fn prepare_public_install_capture(
    root: &Path,
    acquisition: &Path,
    target_directory: &Path,
    cargo_home: &Path,
    receipts: &Path,
    toolchain: &str,
    distribution: &TargetDistribution,
    source: &BuildSourceIdentity,
    deadline: std::time::Instant,
) -> Result<PublicInstallCapture> {
    let located = CommandSpec::new("rustup", root, Duration::from_secs(30))
        .args(["which", "--toolchain", toolchain, "rustc"])
        .bounded_until(deadline)
        .output_quiet()?;
    if !located.status.success() {
        return Err(CiError::Message(
            "public install compiler selection failed".into(),
        ));
    }
    let compiler = fs::canonicalize(Path::new(
        std::str::from_utf8(&located.stdout)
            .map_err(|_| CiError::Message("public install compiler path encoding differs".into()))?
            .trim(),
    ))?;
    let compiler_bytes = artifacts::read_file(&compiler)?;
    let driver_bytes = artifacts::read_file(&std::env::current_exe()?)?;
    let wrapper = binary_path(
        acquisition,
        "memcordon-public-install-capture",
        native_target()?,
    );
    let capture_directory = std::path::absolute(receipts)?.join("public-install-capture");
    fs::create_dir(&capture_directory)?;
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| CiError::Message("public install capture deadline expired".into()))?;
    let deadline_unix_millis = std::time::SystemTime::now()
        .checked_add(remaining)
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| CiError::Message("public install capture deadline overflow".into()))?;
    let descriptor = crate::public_install_capture::Descriptor {
        format: "memcordon.public-install-capture".into(),
        revision: 1,
        compiler,
        compiler_sha256: artifacts::checksum(&compiler_bytes),
        wrapper_sha256: artifacts::checksum(&driver_bytes),
        target: distribution.target.clone(),
        registry_source: std::path::absolute(cargo_home)?
            .join("registry")
            .join("src"),
        target_directory: target_directory.to_owned(),
        capture_directory,
        package: "memcordon".into(),
        version: source.version().to_string(),
        binaries: distribution.binaries.clone(),
        deadline_unix_millis,
    };
    use std::io::Write;
    for (path, bytes) in [
        (wrapper.clone(), driver_bytes),
        (
            acquisition.join("capture-descriptor.json"),
            serde_json::to_vec(&descriptor)?,
        ),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    executable(&wrapper)?;
    for (name, bytes) in [
        (
            "public-install-capture-descriptor.json",
            serde_json::to_vec(&descriptor)?,
        ),
        ("public-install-compiler-path.stdout", located.stdout),
        ("public-install-compiler-path.stderr", located.stderr),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(receipts.join(name))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    Ok(PublicInstallCapture {
        wrapper,
        descriptor,
    })
}

fn verify_public_install_artifacts(
    messages: &[u8],
    cargo_home: &Path,
    install: &Path,
    distribution: &TargetDistribution,
    source: &BuildSourceIdentity,
    capture: &crate::public_install_capture::Descriptor,
) -> Result<PathBuf> {
    let mut binaries = std::collections::BTreeSet::new();
    let mut selected_manifest = None;
    for line in messages
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        memcordon_core::canonical_json::reject_duplicate_json_keys(line)
            .map_err(CiError::Message)?;
        let value: serde_json::Value = serde_json::from_slice(line)?;
        if value.get("reason").and_then(serde_json::Value::as_str) != Some("compiler-artifact") {
            continue;
        }
        let Some(executable) = value.get("executable").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let name = value
            .get("target")
            .and_then(|target| target.get("name"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CiError::Message("public Cargo executable target absent".into()))?;
        if !distribution.binaries.iter().any(|binary| binary == name) {
            continue;
        }
        let package = value
            .get("package_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CiError::Message("public Cargo executable package identity absent".into())
            })?;
        let expected = format!("memcordon@{}", source.version());
        let (registry, identity) = package.split_once('#').ok_or_else(|| {
            CiError::Message("public Cargo package identity has no registry origin".into())
        })?;
        if ![
            "registry+https://github.com/rust-lang/crates.io-index",
            "registry+https://index.crates.io/",
        ]
        .contains(&registry)
            || identity != expected
        {
            return Err(CiError::Message(
                "public Cargo executable is not the exact ordinary registry package".into(),
            ));
        }
        let manifest = value
            .get("manifest_path")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CiError::Message("public Cargo source manifest absent".into()))?;
        let manifest_path = Path::new(manifest);
        let manifest = public_install_io::contextualize(
            "canonicalize emitted source manifest",
            manifest_path,
            fs::canonicalize(manifest_path),
        )?;
        let registry_source = cargo_home.join("registry").join("src");
        let registry_source = public_install_io::contextualize(
            "canonicalize isolated registry source root",
            &registry_source,
            fs::canonicalize(&registry_source),
        )?;
        if !manifest.starts_with(registry_source) {
            return Err(CiError::Message(
                "public Cargo artifact came from outside measured registry source".into(),
            ));
        }
        if selected_manifest
            .as_ref()
            .is_some_and(|selected| selected != &manifest)
        {
            return Err(CiError::Message(
                "public Cargo selected executables came from distinct manifests".into(),
            ));
        }
        selected_manifest = Some(manifest.clone());
        let executable = Path::new(executable);
        let receipt = crate::public_install_capture::load_receipt(capture, name)?;
        let target_source = value
            .get("target")
            .and_then(|target| target.get("src_path"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CiError::Message("public Cargo target source absent".into()))?;
        if receipt.cargo_output != executable
            || receipt.manifest != manifest
            || receipt.source != fs::canonicalize(target_source)?
        {
            return Err(CiError::Message(
                "public Cargo artifact differs from synchronous compiler origin".into(),
            ));
        }
        let built = artifacts::read_file(&receipt.retained_output)?;
        if built.len() as u64 != receipt.length || artifacts::checksum(&built) != receipt.sha256 {
            return Err(CiError::Message(
                "public Cargo retained compiler bytes changed".into(),
            ));
        }
        target::validate_executable(&built, &distribution.target)?;
        let installed_path = binary_path(&install.join("bin"), name, &distribution.target);
        let installed = artifacts::read_file(&installed_path).map_err(|error| match error {
            CiError::Io(error) => CiError::Io(public_install_io::error(
                "read installed executable",
                &installed_path,
                error,
            )),
            error => error,
        })?;
        if installed != built || !binaries.insert(name.to_owned()) {
            return Err(CiError::Message(
                "public Cargo installed executable differs or has duplicate build origins".into(),
            ));
        }
    }
    if binaries != distribution.binaries.iter().cloned().collect() {
        return Err(CiError::Message(
            "public Cargo compile output omitted selected executable origin".into(),
        ));
    }
    selected_manifest
        .ok_or_else(|| CiError::Message("public Cargo selected manifest absent".into()))
}

fn retain_public_registry_graph(
    root: &Path,
    home: &Path,
    manifest: &Path,
    distribution: &TargetDistribution,
    selected_packages: &super::packages::PackageBundle,
    receipts: &Path,
    deadline: std::time::Instant,
) -> Result<()> {
    let parent = manifest
        .parent()
        .ok_or_else(|| CiError::Message("public registry manifest parent absent".into()))?;
    let lock = parent.join("Cargo.lock");
    let before = artifacts::read_file(&lock)?;
    let lock_value: toml::Value = toml::from_str(
        std::str::from_utf8(&before)
            .map_err(|_| CiError::Message("public packaged lock is not UTF-8".into()))?,
    )?;
    let stable = crate::config::toolchains(root)?.stable;
    let mut command = crate::command::rustup_cargo(
        parent,
        &stable,
        ["metadata", "--locked", "--format-version", "1"],
        Duration::from_secs(600),
    )
    .arg("--manifest-path")
    .arg(manifest)
    .arg("--filter-platform")
    .arg(&distribution.target)
    .isolated_cargo(home)
    .bounded_until(deadline);
    for feature in &distribution.features {
        command = command.arg("--features").arg(feature);
    }
    let observed = command.output_quiet()?;
    fs::write(
        receipts.join("public-registry-metadata.json"),
        &observed.stdout,
    )?;
    fs::write(
        receipts.join("public-registry-metadata.stderr.bin"),
        &observed.stderr,
    )?;
    if !observed.status.success() || artifacts::read_file(&lock)? != before {
        return Err(CiError::Message(
            "public locked registry metadata failed or changed packaged lock".into(),
        ));
    }
    fs::write(receipts.join("public-packaged-Cargo.lock"), &before)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&observed.stdout)
        .map_err(CiError::Message)?;
    let metadata: serde_json::Value = serde_json::from_slice(&observed.stdout)?;
    let packages = metadata["packages"]
        .as_array()
        .ok_or_else(|| CiError::Message("public metadata packages absent".into()))?;
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .ok_or_else(|| CiError::Message("public resolved nodes absent".into()))?;
    let text = |value: &serde_json::Value, key: &str| {
        value
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(String::from)
            .ok_or_else(|| CiError::Message(format!("public registry graph {key} absent")))
    };
    let by_id = packages
        .iter()
        .map(|package| Ok((text(package, "id")?, package)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let cache = home.join("registry/cache");
    let registries = fs::read_dir(cache)?.collect::<std::io::Result<Vec<_>>>()?;
    let destination = receipts.join("registry-graph-crates");
    fs::create_dir(&destination)?;
    let mut graph = Vec::new();
    for node in nodes {
        let id = text(node, "id")?;
        let package = by_id
            .get(&id)
            .ok_or_else(|| CiError::Message("public graph node package absent".into()))?;
        let name = text(package, "name")?;
        let version = text(package, "version")?;
        let package_manifest = PathBuf::from(text(package, "manifest_path")?);
        if !fs::canonicalize(package_manifest)?
            .starts_with(fs::canonicalize(home.join("registry/src"))?)
        {
            return Err(CiError::Message(
                "public graph includes nonregistry source".into(),
            ));
        }
        let filename = format!("{name}-{version}.crate");
        let paths = registries
            .iter()
            .map(|registry| registry.path().join(&filename))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(CiError::Message(
                "public graph cached archive absent or ambiguous".into(),
            ));
        }
        let bytes = artifacts::read_file(&paths[0])?;
        let hash = String::from(memcordon_core::hash_bytes(&bytes));
        let locked = lock_value["package"]
            .as_array()
            .ok_or_else(|| CiError::Message("public packaged lock entries absent".into()))?
            .iter()
            .filter(|entry| {
                entry.get("name").and_then(toml::Value::as_str) == Some(name.as_str())
                    && entry.get("version").and_then(toml::Value::as_str) == Some(version.as_str())
            })
            .collect::<Vec<_>>();
        let selected = selected_packages
            .files
            .iter()
            .find(|record| record.name == filename);
        let root_package = package
            .get("source")
            .is_some_and(serde_json::Value::is_null)
            && fs::canonicalize(PathBuf::from(text(package, "manifest_path")?))?
                == fs::canonicalize(manifest)?;
        if locked.len() != 1
            || if root_package {
                selected.is_none_or(|record| record.sha256 != hash)
            } else {
                locked[0].get("checksum").and_then(toml::Value::as_str) != Some(hash.as_str())
            }
        {
            return Err(CiError::Message("public cached graph archive differs from untouched packaged lock or selected root bytes".into()));
        }
        fs::write(destination.join(&filename), &bytes)?;
        let mut dependencies = Vec::new();
        for dependency in node["deps"]
            .as_array()
            .ok_or_else(|| CiError::Message("public graph dependency edges absent".into()))?
        {
            let dependency_id = text(dependency, "pkg")?;
            let package = by_id
                .get(&dependency_id)
                .ok_or_else(|| CiError::Message("public graph edge package absent".into()))?;
            for kind in dependency["dep_kinds"]
                .as_array()
                .ok_or_else(|| CiError::Message("public graph dependency kinds absent".into()))?
            {
                dependencies.push(serde_json::json!({"name":text(package,"name")?,"version":text(package,"version")?,"kind":kind.get("kind").ok_or_else(||CiError::Message("public graph dependency kind absent".into()))?,"target":kind.get("target").ok_or_else(||CiError::Message("public graph dependency target absent".into()))?}));
            }
        }
        dependencies.sort_by_key(|value| value.to_string());
        dependencies.dedup();
        graph.push(serde_json::json!({"name":name,"version":version,"crate_sha256":hash,"crate_artifact":format!("registry-graph-crates/{filename}"),"features":node.get("features").ok_or_else(||CiError::Message("public graph resolved features absent".into()))?,"dependencies":dependencies}));
    }
    source::write_json(
        &receipts.join("registry-graph.json"),
        &serde_json::json!({"format":"memcordon.consumer-readiness.registry-graph","revision":1,"packages":graph,"raw_metadata":"public-registry-metadata.json","raw_lock":"public-packaged-Cargo.lock"}),
    )
}

fn materialize_cargo_install(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    bundle: &TargetBundle,
    packages: &super::packages::PackageBundle,
    install_root: &Path,
    temporary_parent: &Path,
) -> Result<MaterializedPayload> {
    let owner = tempfile::Builder::new()
        .prefix("cargo-consumer-")
        .tempdir_in(std::path::absolute(temporary_parent)?)?;
    let directory = owner.path().join("payload");
    fs::create_dir(&directory)?;
    for binary in &bundle.distribution.binaries {
        let from = binary_path(
            &install_root.join("bin"),
            binary,
            &bundle.distribution.target,
        );
        let to = binary_path(&directory, binary, &bundle.distribution.target);
        let bytes = artifacts::read_file(&from)?;
        target::validate_executable(&bytes, &bundle.distribution.target)?;
        fs::write(&to, bytes)?;
        executable(&to)?;
    }
    source::write_json(
        &directory.join("runtime-manifest.json"),
        &measured_current_manifest(&packages.source, &bundle.distribution, &directory)?,
    )?;
    if !bundle.distribution.units.is_empty() {
        let units = target::unit_export_directory(owner.path())?;
        CommandSpec::new(
            binary_path(
                &directory,
                "memcordon-sealed-agent",
                &bundle.distribution.target,
            ),
            root,
            Duration::from_secs(30),
        )
        .arg("__export-unit-files")
        .arg(units.path())
        .run()?;
        for unit in &bundle.distribution.units {
            fs::write(
                directory.join(unit),
                artifacts::read_file(&units.path().join(unit))?,
            )?;
        }
    }
    let fixture = fixture(bundle, target_directory, owner.path())?;
    let workload_diagnostic = workload_diagnostic(bundle, target_directory, owner.path())?;
    let artifacts: Vec<_> = packages
        .files
        .iter()
        .map(|file| SelectedArtifact {
            path: package_directory.join(&file.name),
            sha256: file.sha256.clone(),
        })
        .collect();
    let selected_artifact_count = artifacts.len();
    Ok(MaterializedPayload {
        channel: InstalledChannel::CargoPackage,
        source: packages.source.clone(),
        distribution: bundle.distribution.clone(),
        directory,
        artifacts,
        selected_artifact_count,
        fixture,
        workload_diagnostic,
        _owner: owner,
    })
}

/// Bind driver-relative paths before changing the selected child's directory.
/// Absolute paths retain symlink spelling and do not replace custody checks.
pub fn cli_case_command(
    directory: &Path,
    target: &str,
    fixture: &Path,
    output_directory: &Path,
    name: &str,
    wrapper_arguments: &[OsString],
    fixture_arguments: &[&str],
) -> Result<(CommandSpec, PathBuf)> {
    artifacts::safe_basename(name)?;
    let directory = std::path::absolute(directory)?;
    let fixture = std::path::absolute(fixture)?;
    let report_path = std::path::absolute(output_directory.join(name).with_extension("json"))?;
    let command = CommandSpec::new(
        binary_path(&directory, "memcordon", target),
        &directory,
        Duration::from_secs(60),
    )
    .args(wrapper_arguments)
    .args([
        OsString::from("--report-format"),
        OsString::from("standard"),
        OsString::from("--report"),
        report_path.as_os_str().to_os_string(),
        OsString::from("--"),
        fixture.as_os_str().to_os_string(),
    ])
    .args(fixture_arguments);
    Ok((command, report_path))
}

/// Ordinary installed smoke success; unknown workload emptiness retains its
/// existing acceptance policy, independently of the public-registry validator.
pub fn public_success_retired(
    outcome: Option<&memcordon_core::RunOutcome>,
    wrapper: Option<i32>,
) -> bool {
    super::consumer_success::exited_zero(outcome)
        && wrapper == Some(0)
        && outcome.is_some_and(|outcome| {
            outcome.cleanup().direct_child_reaped
                && outcome.cleanup().errors.is_empty()
                && outcome.cleanup().workload_empty != Some(false)
        })
}

pub fn run_cli_case(
    payload: &MaterializedPayload,
    output_directory: &Path,
    name: &str,
    wrapper_arguments: &[OsString],
    fixture_arguments: &[&str],
) -> Result<MemcordonReport> {
    let (command, report_path) = cli_case_command(
        &payload.directory,
        &payload.distribution.target,
        &payload.fixture.path,
        output_directory,
        name,
        wrapper_arguments,
        fixture_arguments,
    )?;
    let capture = |output: &memcordon_testkit::ObservedOutput| -> Result<()> {
        fs::write(
            output_directory.join(name).with_extension("stdout.bin"),
            &output.stdout,
        )?;
        fs::write(
            output_directory.join(name).with_extension("stderr.bin"),
            &output.stderr,
        )?;
        Ok(())
    };
    #[cfg(target_os = "linux")]
    let output = crate::standard_runner::run_delegated_case(&command, capture)?;
    #[cfg(not(target_os = "linux"))]
    let mut command = command.materialize()?;
    #[cfg(not(target_os = "linux"))]
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(60),
        1024 * 1024,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    #[cfg(not(target_os = "linux"))]
    capture(&output)?;
    let bytes = artifacts::read_file(&report_path)?;
    if bytes.len() > 8 * 1024 * 1024 {
        return Err(CiError::Message(
            "ordinary execution report exceeds byte bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let result: MemcordonReport = serde_json::from_slice(&bytes)?;
    if result.tool.version != payload.source.version().to_string()
        || output.status.code()
            != result
                .supervision
                .as_ref()
                .map(|summary| summary.wrapper_exit_code)
    {
        return Err(CiError::Message(
            "selected CLI native exit/report association differs".into(),
        ));
    }
    Ok(result)
}

pub fn run_materialized_channel(
    root: &Path,
    payload: &MaterializedPayload,
    output: &Path,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    let original_cleanup_deadline = std::time::SystemTime::now()
        .checked_add(Duration::from_secs(105 * 60))
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or_else(|| CiError::Message("current consumer original deadline overflow".into()))?;
    require_current_runtime(payload)?;
    fs::create_dir(output)?;
    let mut version = CommandSpec::new(
        binary_path(
            &payload.directory,
            "memcordon",
            &payload.distribution.target,
        ),
        &payload.directory,
        Duration::from_secs(30),
    )
    .arg("--version")
    .materialize()?;
    let version = memcordon_testkit::run_with_deadline_output_limit(
        &mut version,
        Duration::from_secs(30),
        16 * 1024,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    if !version.status.success()
        || std::str::from_utf8(&version.stdout)
            .ok()
            .and_then(|text| text.split_whitespace().last())
            != Some(payload.source.version().to_string().as_str())
    {
        return Err(CiError::Message(
            "installed selected CLI version differs".into(),
        ));
    }
    let success = run_cli_case(
        payload,
        output,
        "public-success",
        &[],
        &["exit", "--code", "0"],
    )?;
    let success_outcome = success
        .attempts
        .last()
        .and_then(|attempt| attempt.outcome.as_ref());
    if !public_success_retired(
        success_outcome,
        success
            .supervision
            .as_ref()
            .map(|summary| summary.wrapper_exit_code),
    ) {
        return Err(CiError::Message(
            "actual selected CLI success/retirement failed".into(),
        ));
    }
    let deadline = run_cli_case(
        payload,
        output,
        "public-deadline",
        &["+200ms".into()],
        &["hold", "--duration", "10s"],
    )?;
    let deadline_outcome = deadline
        .attempts
        .last()
        .and_then(|attempt| attempt.outcome.as_ref());
    if !matches!(
        deadline_outcome,
        Some(memcordon_core::RunOutcome::DeadlineExceeded { .. })
    ) || deadline
        .supervision
        .as_ref()
        .is_none_or(|summary| summary.wrapper_exit_code != 123)
        || deadline_outcome.is_none_or(|outcome| {
            !outcome.cleanup().direct_child_reaped
                || !outcome.cleanup().errors.is_empty()
                || outcome.cleanup().workload_empty == Some(false)
        })
    {
        return Err(CiError::Message(
            "actual selected CLI deadline/retirement failed".into(),
        ));
    }
    let runtime = payload.distribution.runtime_selection()?;
    if runtime == super::distribution::RuntimeSelection::WindowsSealed {
        let installed = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("MemCordon");
        let config = crate::windows_installed_cases::InstalledWindowsPayload::from_materialized(
            payload.channel,
            &payload.source,
            &payload.distribution,
            installed_case_artifacts(
                &payload.artifacts,
                payload.selected_artifact_count,
                payload.distribution.binaries.len(),
            )?,
            &payload.directory,
            payload.fixture.clone(),
            payload.workload_diagnostic.clone(),
            &installed,
            output.join("windows-installed"),
        )?;
        fs::create_dir_all(&config.output_directory)?;
        let deadlines = crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default();
        let assessment = crate::windows_installed_cases::run_from_source_with_observer_until(
            root,
            &config,
            &mut |_| Ok(()),
            deadlines,
        )?;
        source::write_json(&output.join("windows-assessment.json"), &assessment)?;
        #[cfg(windows)]
        if let Err(error) =
            super::installed_loader_support::run(root, payload, &config, &assessment, deadlines)
        {
            eprintln!("secondary separate installed loader support unavailable: {error}");
        }
        if !assessment.accepted() {
            return Err(CiError::Message(format!(
                "actual installed Windows case or retirement failed; install/smoke: {:?}; upgrade: {:?}; uninstall: {:?}",
                assessment.public_smoke_before,
                assessment.package_upgrade,
                assessment.package_uninstall,
            )));
        }
    } else if matches!(
        runtime,
        super::distribution::RuntimeSelection::LinuxBaseline
            | super::distribution::RuntimeSelection::LinuxPrivateTcp
    ) {
        #[cfg(target_os = "linux")]
        {
            let preparation = crate::preparation_tools::checked_owner_preparation(
                root,
                crate::preparation_tools::Kind::Private,
            )?;
            let workflow_run = std::env::var("GITHUB_RUN_ID").ok();
            let mut smoke_payload = SmokePayload::describe(payload);
            smoke_payload.artifacts.extend(
                super::original_native_components::retain_current_owner_probe(
                    &preparation,
                    &super::original_native_components::OwnerProbeOrigin {
                        kind: crate::preparation_tools::Kind::Private,
                        commit: payload.source.commit(),
                        version: &payload.source.version().to_string(),
                        target: &payload.distribution.target,
                        run: workflow_run.as_deref().ok_or_else(|| {
                            CiError::Message(
                                "private smoke requires its original prepared workflow run".into(),
                            )
                        })?,
                    },
                    &output.join("owner-probe"),
                )?,
            );
            let spec = CurrentSmokeSpec {
                format: "memcordon.current-materialized-smoke".into(),
                revision: 1,
                payload: smoke_payload,
                output: std::path::absolute(output.join("linux-installed"))?,
                operation_deadline_unix_millis: original_cleanup_deadline,
                workflow_run,
                diagnostic_output: std::path::absolute(
                    root.join("target/ci/private-installed-diagnostics"),
                )?,
            };
            fs::create_dir_all(&spec.diagnostic_output)?;
            let path = std::path::absolute(output.join("current-linux-smoke.json"))?;
            source::write_json(&path, &spec)?;
            if rustix::process::geteuid().is_root() {
                run_current_smoke_spec(root, &path, false)?;
            } else {
                let toolchain = super::consumer_readiness_cell::selected_toolchain_environment()?;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| CiError::Message(e.to_string()))?
                    .as_millis();
                let remaining = u128::from(original_cleanup_deadline)
                    .checked_sub(now)
                    .and_then(|ms| u64::try_from(ms).ok())
                    .filter(|ms| *ms > 0)
                    .ok_or_else(|| {
                        CiError::Message(
                            "current smoke original deadline exhausted before root reentry".into(),
                        )
                    })?;
                let result = CommandSpec::new("sudo", root, Duration::from_millis(remaining))
                    .args(["-n", "--", "/usr/bin/env"])
                    .args(toolchain.clone())
                    .arg(std::env::current_exe()?)
                    .args(["release", "current-materialized-smoke", "--spec"])
                    .arg(&path)
                    .run();
                if let Err(primary) = result {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|e| CiError::Message(e.to_string()))?
                        .as_millis();
                    let cleanup_remaining = u128::from(original_cleanup_deadline)
                        .checked_sub(now)
                        .and_then(|ms| u64::try_from(ms).ok())
                        .filter(|ms| *ms > 0);
                    let retired = if let Some(ms) = cleanup_remaining {
                        CommandSpec::new("sudo", root, Duration::from_millis(ms))
                            .args(["-n", "--", "/usr/bin/env"])
                            .args(toolchain)
                            .arg(std::env::current_exe()?)
                            .args([
                                "release",
                                "current-materialized-smoke",
                                "--cleanup-only",
                                "--spec",
                            ])
                            .arg(&path)
                            .run()
                            .map(|_| ())
                    } else {
                        Err(CiError::Message("original current smoke cleanup cutoff exhausted; original native owner retained".into()))
                    };
                    return crate::work_outcome::join_completed(
                        crate::work_outcome::WorkOutcome::<()>::from_result(Err(primary)),
                        crate::work_outcome::WorkOutcome::from_result(retired),
                    )
                    .into_result();
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        return Err(CiError::Message(
            "Linux installed consumer requires its native host".into(),
        ));
    }
    Ok(())
}

/// Provision container directories while reserving a fresh operation leaf.
/// An existing leaf remains an error; prior diagnostics are never reused.
pub fn create_fresh_destination(destination: &Path) -> Result<()> {
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(destination)?;
    Ok(())
}

pub fn run(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
) -> Result<()> {
    run_with_external(root, target_directory, package_directory, destination, None)
}

/// Both channels, with an optional caller-supplied executable contract. Each
/// invocation binds that contract to its own verified materialized CLI.
pub fn run_with_external(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
    external_input: Option<&Path>,
) -> Result<()> {
    create_fresh_destination(destination)?;
    run_channel_with_external(
        root,
        target_directory,
        package_directory,
        &destination.join("native"),
        InstalledChannel::NativeBundle,
        external_input,
    )?;
    run_channel_with_external(
        root,
        target_directory,
        package_directory,
        &destination.join("cargo"),
        InstalledChannel::CargoPackage,
        external_input,
    )
}

/// One actual selected channel on this native host. Native does not build/read
/// Cargo packages; Cargo requires the exact supplied package bundle.
pub fn run_channel(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
    channel: InstalledChannel,
) -> Result<()> {
    run_channel_with_external(
        root,
        target_directory,
        package_directory,
        destination,
        channel,
        None,
    )
}

pub fn run_channel_with_external(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
    channel: InstalledChannel,
    external_input: Option<&Path>,
) -> Result<()> {
    run_channel_with_cache(
        root,
        target_directory,
        package_directory,
        destination,
        channel,
        external_input,
        super::ordinary_consumer_cache::ConsumerBuildLayout::Ephemeral,
    )
}

pub fn run_channel_with_cache(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    destination: &Path,
    channel: InstalledChannel,
    external_input: Option<&Path>,
    consumer_cache: super::ordinary_consumer_cache::ConsumerBuildLayout,
) -> Result<()> {
    use super::ordinary_consumer_cache::{self, ConsumerBuildLayout};
    ordinary_consumer_cache::validate_selection(
        consumer_cache,
        matches!(channel, InstalledChannel::CargoPackage),
        true,
        external_input.is_some(),
    )?;
    let started = std::time::Instant::now();
    let channel_name = match channel {
        InstalledChannel::NativeBundle => "native",
        InstalledChannel::CargoPackage => "cargo",
    };
    let record = |state: &str, selection: &Option<serde_json::Value>, error: Option<&CiError>| {
        let write = || -> Result<()> {
            let directory = root.join("target/ci/reports/execution");
            std::fs::create_dir_all(&directory)?;
            let value = serde_json::json!({
                "phase": "installed-consumer",
                "expected-operation": "validate and execute selected installed native or Cargo payload",
                "channel": channel_name,
                "selection": selection,
                "state": state,
                "elapsed-ms": started.elapsed().as_millis(),
                "error": error.map(|error| crate::command::bounded_excerpt(error.to_string().as_bytes())),
            });
            let temporary = directory.join("installed-consumer.tmp");
            source::write_json(&temporary, &value)?;
            std::fs::rename(temporary, directory.join("installed-consumer.json"))?;
            Ok(())
        };
        if let Err(error) = write() {
            eprintln!("diagnostic retention incomplete: {error}");
        }
    };
    let mut selection = None;
    record("in-progress", &selection, None);
    let result = (|| -> Result<()> {
        let (bundle, _) = TargetBundle::load(target_directory)?;
        selection = Some(
            serde_json::json!({"source": bundle.source, "target": bundle.distribution.target}),
        );
        record("in-progress", &selection, None);
        bundle.source.recheck(root)?;
        if bundle.distribution.target != native_target()? {
            return Err(CiError::Message(
                "installed consumer requires the actual selected native host".into(),
            ));
        }
        create_fresh_destination(destination)?;
        let mut ordinary_consumer = None;
        let payload = match channel {
            InstalledChannel::NativeBundle => materialize_native(target_directory, destination)?,
            InstalledChannel::CargoPackage => {
                let consumer = if consumer_cache == ConsumerBuildLayout::StableOrdinary {
                    ordinary_consumer_cache::prepare_execution(
                        root,
                        target_directory,
                        package_directory,
                    )?
                } else {
                    PackageConsumer::prepare_selected(
                        root,
                        package_directory,
                        &bundle.distribution,
                    )?
                };
                if consumer.bundle.source != bundle.source {
                    return Err(CiError::Message(
                        "installed channel source selections differ".into(),
                    ));
                }
                let build = consumer
                    .ordinary_slot()
                    .map(|slot| slot.build().to_owned())
                    .unwrap_or_else(|| root.join("target/ci-consumers"));
                let payload = materialize_cargo(
                    root,
                    target_directory,
                    package_directory,
                    &bundle,
                    &consumer,
                    &build,
                    destination,
                )?;
                if consumer_cache == ConsumerBuildLayout::StableOrdinary {
                    ordinary_consumer = Some(consumer);
                }
                payload
            }
        };
        run_materialized_channel(root, &payload, &destination.join("cases"))?;
        if let Some(input) = external_input {
            let spec = crate::external_consumer::ExternalConsumerSpec::parse(
                &super::artifacts::read_file(input)?,
            )?;
            let assessment = crate::external_consumer::run_materialized(
                &payload,
                &spec,
                &destination.join("external"),
            )?;
            if !assessment.passed() {
                return Err(CiError::Message(
                "external installed consumer did not complete execution, collection, and retirement"
                    .into(),
            ));
            }
        }
        let measured = BTreeMap::from([
            ("source", bundle.source.commit().to_owned()),
            ("target", bundle.distribution.target),
            (
                "channel",
                match channel {
                    InstalledChannel::NativeBundle => "native",
                    InstalledChannel::CargoPackage => "cargo",
                }
                .to_owned(),
            ),
        ]);
        source::write_json(&destination.join("consumer.json"), &measured)?;
        if let Some(consumer) = ordinary_consumer {
            ordinary_consumer_cache::complete(&consumer, &payload.distribution)?;
        }
        Ok(())
    })();
    record(
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
        &selection,
        result.as_ref().err(),
    );
    result
}
