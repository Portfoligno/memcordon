//! Source-native Windows fault tests use their own current support installation.
use super::{
    artifacts, distribution,
    source::{self, BuildSourceIdentity},
    target,
};
use crate::{CiError, Result, command::CommandSpec};
use memcordon_core::runtime_components::RuntimeComponentRole;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub fn run(root: &Path, work: Instant, cleanup: Instant) -> Result<()> {
    let selected = BuildSourceIdentity::working(root)?;
    let host = distribution::native_target()?;
    let distribution = distribution::Distribution::read(root)?
        .with_runtime_components()?
        .native()?
        .clone();
    let owner = tempfile::Builder::new()
        .prefix("memcordon-source-components-")
        .tempdir()?;
    let destination = std::path::absolute(owner.path())?;
    let build = std::path::absolute(root.join("target/ci/native"))?;
    let names = [
        ("memcordon", RuntimeComponentRole::PublicCli),
        ("memcordon-sealed-agent", RuntimeComponentRole::SealedAgent),
        (
            "memcordon-target-desktop-bootstrap",
            RuntimeComponentRole::DesktopBootstrap,
        ),
        (
            "memcordon-session-broker",
            RuntimeComponentRole::SessionBroker,
        ),
    ];
    let toolchain = crate::config::toolchains(root)?.stable;
    let mut command = CommandSpec::cargo("rustup", root, &toolchain, Duration::from_secs(60 * 60))
        .args([
            "build",
            "--release",
            "--locked",
            "--message-format=json",
            "-p",
            "memcordon",
            "--features",
            "windows-sealed-runtime,test-support,test-fixtures",
            "--target",
        ])
        .arg(host)
        .arg("--target-dir")
        .arg(&build)
        .bounded_until(work);
    for (name, _) in &names {
        command = command.arg("--bin").arg(name);
    }
    command = command.args(["--bin", "memcordon-test-fixture"]);
    let output = command
        .output_limit(64 * 1024 * 1024)
        .run_owned()
        .into_result()?;
    let mut emitted = BTreeMap::new();
    let mut finished = false;
    for message in cargo_metadata::Message::parse_stream(output.as_slice()) {
        match message.map_err(|error| CiError::Message(error.to_string()))? {
            cargo_metadata::Message::CompilerArtifact(artifact)
                if !artifact.profile.test
                    && artifact
                        .target
                        .kind
                        .contains(&cargo_metadata::TargetKind::Bin)
                    && (names.iter().any(|(name, _)| *name == artifact.target.name)
                        || artifact.target.name == "memcordon-test-fixture") =>
            {
                let path = artifact
                    .executable
                    .ok_or_else(|| CiError::Message("source component executable missing".into()))?
                    .into_std_path_buf();
                if !path.starts_with(&build) || emitted.insert(artifact.target.name, path).is_some()
                {
                    return Err(CiError::Message(
                        "source component output is duplicated or outside its build root".into(),
                    ));
                }
            }
            cargo_metadata::Message::BuildFinished(value) => finished = value.success,
            _ => (),
        }
    }
    if !finished || emitted.len() != names.len() + 1 {
        return Err(CiError::Message(
            "source component build did not produce all intended images".into(),
        ));
    }
    let mut held = Vec::new();
    let mut components = Vec::new();
    let mut selected_artifacts = Vec::new();
    for (name, role) in names {
        let image = emitted
            .remove(name)
            .expect("complete source component inventory");
        let bytes = artifacts::read_file(&image)?;
        target::validate_executable(&bytes, host)?;
        let filename = PathBuf::from(name).with_extension("exe");
        let path = destination.join(&filename);
        let checksum = artifacts::checksum(&bytes);
        held.push(crate::windows_native_files::copy_compiler_artifact(
            &image, &build, &path, &checksum,
        )?);
        components.push(target::runtime_component(
            role,
            filename.to_string_lossy().into_owned(),
            &bytes,
        ));
        selected_artifacts.push(crate::windows_installed_cases::SelectedArtifact {
            path,
            sha256: checksum,
        });
    }
    let fixture_source = emitted
        .remove("memcordon-test-fixture")
        .expect("complete source fixture inventory");
    let bytes = artifacts::read_file(&fixture_source)?;
    target::validate_executable(&bytes, host)?;
    let fixture = crate::windows_installed_cases::SelectedArtifact {
        path: destination.join("memcordon-test-fixture.exe"),
        sha256: artifacts::checksum(&bytes),
    };
    held.push(crate::windows_native_files::copy_compiler_artifact(
        &fixture_source,
        &build,
        &fixture.path,
        &fixture.sha256,
    )?);
    selected.recheck(root)?;
    let manifest = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::windows(
        selected.version().to_string(),
        selected.commit().to_owned(),
        host.to_owned(),
        components,
    )
    .map_err(CiError::Message)?;
    let path = destination.join("runtime-manifest.json");
    source::write_json(&path, &manifest)?;
    held.push(crate::windows_native_files::hold_artifact(
        &path,
        None,
        1024 * 1024,
    )?);
    let installed = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .ok_or_else(|| CiError::Message("native Windows ProgramFiles is missing".into()))?
        .join("MemCordon");
    let config = crate::windows_installed_cases::InstalledWindowsPayload::from_materialized(
        crate::windows_causal_acceptance::InstalledChannel::NativeBundle,
        &selected,
        &distribution,
        selected_artifacts,
        &destination,
        fixture,
        &installed,
        destination.join("cases"),
    )?;
    crate::windows_installed_cases::run_components_from_source_until(
        root,
        &config,
        crate::windows_installed_cases::WindowsLeaseDeadlines::new(work, cleanup)?,
    )
}
