//! Execute consumers against the selected, measured distribution in both channels.
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use memcordon_core::{
    result_v1::{CleanupStateV1, OutcomeKindV1, ResultV1},
    runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole, RuntimeManifest},
};

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
    pub fixture: SelectedArtifact,
    _owner: tempfile::TempDir,
}

pub fn binary_path(directory: &Path, binary: &str, target: &str) -> PathBuf {
    let mut path = directory.join(binary);
    if target.ends_with("-pc-windows-msvc") {
        path.set_extension("exe");
    }
    path
}

fn executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Inventory generated from the Cargo channel's own binaries. It never copies
/// the native channel's hashes and cannot grant execution permission.
pub fn measured_manifest(
    source: &BuildSourceIdentity,
    distribution: &TargetDistribution,
    directory: &Path,
) -> Result<RuntimeManifest> {
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
                    "unexpected selected consumer binary".into(),
                ));
            }
        };
        components.push(RuntimeComponentRecord {
            id: if role == RuntimeComponentRole::SealedAgent {
                "sealed-agent".into()
            } else {
                binary.clone()
            },
            path: path
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| CiError::Message("consumer filename is not UTF-8".into()))?
                .into(),
            role,
            size: bytes.len() as u64,
            mode: 0o755,
            sha256: artifacts::checksum(&bytes),
        });
    }
    let args = (
        source.version().to_string(),
        source.commit().to_owned(),
        distribution.target.clone(),
        components,
    );
    let result = if distribution.features.is_empty() {
        RuntimeManifest::cli_only(args.0, args.1, args.2, args.3)
    } else if distribution.target.ends_with("-pc-windows-msvc") {
        RuntimeManifest::windows(args.0, args.1, args.2, args.3)
    } else {
        RuntimeManifest::linux_selected(
            args.0,
            args.1,
            args.2,
            args.3,
            distribution
                .features
                .iter()
                .any(|feature| feature == "private-tcp"),
        )
    };
    result.map_err(CiError::Message)
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

pub fn materialize_native(
    target_directory: &Path,
    temporary_parent: &Path,
) -> Result<MaterializedPayload> {
    let (bundle, archive) = TargetBundle::load(target_directory)?;
    let owner = tempfile::Builder::new()
        .prefix("native-consumer-")
        .tempdir_in(temporary_parent)?;
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
    Ok(MaterializedPayload {
        channel: InstalledChannel::NativeBundle,
        source: bundle.source,
        distribution: bundle.distribution,
        directory,
        artifacts: vec![SelectedArtifact {
            path: target_directory.join(&bundle.archive.name),
            sha256: bundle.archive.sha256,
        }],
        fixture,
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
    let owner = tempfile::Builder::new()
        .prefix("cargo-consumer-")
        .tempdir_in(temporary_parent)?;
    let directory = owner.path().join("payload");
    fs::create_dir(&directory)?;
    for binary in &bundle.distribution.binaries {
        let from = binary_path(
            &consumer.install_root.join("bin"),
            binary,
            &bundle.distribution.target,
        );
        let to = binary_path(&directory, binary, &bundle.distribution.target);
        let bytes = artifacts::read_file(&from)?;
        target::validate_executable(&bytes, &bundle.distribution.target)?;
        fs::write(&to, bytes)?;
        executable(&to)?;
    }
    let manifest = measured_manifest(&bundle.source, &bundle.distribution, &directory)?;
    source::write_json(&directory.join("runtime-manifest.json"), &manifest)?;
    if !bundle.distribution.units.is_empty() {
        let units = owner.path().join("units");
        fs::create_dir(&units)?;
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
        .arg(&units)
        .run()?;
        for unit in &bundle.distribution.units {
            fs::write(
                directory.join(unit),
                artifacts::read_file(&units.join(unit))?,
            )?;
        }
    }
    let fixture = fixture(bundle, target_directory, owner.path())?;
    let artifacts = consumer
        .bundle
        .files
        .iter()
        .map(|file| SelectedArtifact {
            path: package_directory.join(&file.name),
            sha256: file.sha256.clone(),
        })
        .collect();
    Ok(MaterializedPayload {
        channel: InstalledChannel::CargoPackage,
        source: bundle.source.clone(),
        distribution: bundle.distribution.clone(),
        directory,
        artifacts,
        fixture,
        _owner: owner,
    })
}

pub fn run_cli_case(
    payload: &MaterializedPayload,
    output_directory: &Path,
    name: &str,
    wrapper_arguments: &[OsString],
    fixture_arguments: &[&str],
) -> Result<ResultV1> {
    artifacts::safe_basename(name)?;
    let report_path = output_directory.join(name).with_extension("json");
    let mut command = CommandSpec::new(
        binary_path(
            &payload.directory,
            "memcordon",
            &payload.distribution.target,
        ),
        &payload.directory,
        Duration::from_secs(60),
    )
    .args(wrapper_arguments)
    .args([
        OsString::from("--report-format"),
        OsString::from("result-v1"),
        OsString::from("--report"),
        report_path.as_os_str().to_os_string(),
        OsString::from("--"),
        payload.fixture.path.as_os_str().to_os_string(),
    ])
    .args(fixture_arguments)
    .materialize()?;
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(60),
        1024 * 1024,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    fs::write(
        output_directory.join(name).with_extension("stdout.bin"),
        &output.stdout,
    )?;
    fs::write(
        output_directory.join(name).with_extension("stderr.bin"),
        &output.stderr,
    )?;
    let result = ResultV1::parse(&artifacts::read_file(&report_path)?).map_err(CiError::Message)?;
    if result.tool.version != payload.source.version().to_string()
        || output.status.code() != Some(result.outcome.wrapper_status)
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
    if success.outcome.kind != OutcomeKindV1::Completed
        || success.outcome.wrapper_status != 0
        || success.cleanup.state != CleanupStateV1::Complete
    {
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
    if deadline.outcome.kind != OutcomeKindV1::Deadline
        || deadline.cleanup.state != CleanupStateV1::Complete
    {
        return Err(CiError::Message(
            "actual selected CLI deadline/retirement failed".into(),
        ));
    }
    if payload
        .distribution
        .features
        .iter()
        .any(|feature| feature == "windows-sealed-runtime")
    {
        let installed = std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("MemCordon");
        let config = crate::windows_installed_cases::InstalledWindowsPayload::from_materialized(
            payload.channel,
            &payload.source,
            &payload.distribution,
            payload.artifacts.clone(),
            &payload.directory,
            payload.fixture.clone(),
            &installed,
            output.join("windows-installed"),
        )?;
        let assessment = crate::windows_installed_cases::run_cases_for_installed_payload(&config)?;
        source::write_json(&output.join("windows-assessment.json"), &assessment)?;
        if !assessment.accepted() {
            return Err(CiError::Message(
                "actual installed Windows case or retirement failed".into(),
            ));
        }
    } else if payload
        .distribution
        .features
        .iter()
        .any(|feature| feature == "sealed-runtime")
    {
        super::linux_installed_consumer::run(root, payload, &output.join("linux-installed"))?;
    }
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
    fs::create_dir(destination)?;
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
    let (bundle, _) = TargetBundle::load(target_directory)?;
    bundle.source.recheck(root)?;
    if bundle.distribution.target != native_target()? {
        return Err(CiError::Message(
            "installed consumer requires the actual selected native host".into(),
        ));
    }
    fs::create_dir(destination)?;
    let payload = match channel {
        InstalledChannel::NativeBundle => materialize_native(target_directory, destination)?,
        InstalledChannel::CargoPackage => {
            let consumer = PackageConsumer::prepare(root, package_directory)?;
            if consumer.bundle.source != bundle.source {
                return Err(CiError::Message(
                    "installed channel source selections differ".into(),
                ));
            }
            materialize_cargo(
                root,
                target_directory,
                package_directory,
                &bundle,
                &consumer,
                &root.join("target/ci-consumers"),
                destination,
            )?
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
    source::write_json(&destination.join("consumer.json"), &measured)
}
