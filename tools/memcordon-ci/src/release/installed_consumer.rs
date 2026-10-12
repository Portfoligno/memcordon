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

use memcordon_core::{
    result_v1::{CleanupStateV1, OutcomeKindV1, ResultV1},
    runtime_manifest::{RuntimeComponentRole, RuntimeManifest},
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
    selected_artifact_count: usize,
    pub fixture: SelectedArtifact,
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
        components.push(target::runtime_component(
            role,
            path.file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| CiError::Message("consumer filename is not UTF-8".into()))?
                .into(),
            &bytes,
        ));
    }
    let args = (
        source.version().to_string(),
        source.commit().to_owned(),
        distribution.target.clone(),
        components,
    );
    let runtime = distribution.runtime_selection()?;
    let result = if runtime == super::distribution::RuntimeSelection::CliOnly {
        RuntimeManifest::cli_only(args.0, args.1, args.2, args.3)
    } else if runtime == super::distribution::RuntimeSelection::WindowsSealed {
        RuntimeManifest::windows(args.0, args.1, args.2, args.3)
    } else if runtime == super::distribution::RuntimeSelection::LinuxPrivateTcp {
        RuntimeManifest::linux_combined(args.0, args.1, args.2, args.3)
    } else {
        RuntimeManifest::linux_selected(
            args.0,
            args.1,
            args.2,
            args.3,
            runtime == super::distribution::RuntimeSelection::LinuxPrivateTcp,
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
        false,
    )
}

/// Public delivery uses Cargo's ordinary registry installation. Downloaded
/// archive metadata is measured separately and never patches the install graph.
pub fn acquire_cargo_predecessor(
    root: &Path,
    current_target: &Path,
    current: &TargetBundle,
    temporary_parent: &Path,
    receipts: &Path,
    deadline: std::time::Instant,
) -> Result<MaterializedPayload> {
    let version = semver::Version::parse("0.5.7-rc.19")?;
    if current.source.version() <= &version {
        return Err(CiError::Message(
            "selected runtime has no strictly older rc19 predecessor".into(),
        ));
    }
    fs::create_dir(receipts)?;
    let repository = crate::config::release(root)?.repository;
    source::validate_repository(&repository)?;
    let selected = source::SelectedSource {
        format: "memcordon.selected-source".into(),
        revision: 1,
        repository: repository.clone(),
        tag_ref: format!("refs/tags/{version}"),
        commit: "a02e8f1e845349e27706c11d6d57acb27090223a".into(),
        version: version.clone(),
    };
    selected.validate()?;
    let mut url = url::Url::parse("https://github.com/")
        .map_err(|_| CiError::Message("predecessor origin URL invalid".into()))?;
    {
        let mut path = url
            .path_segments_mut()
            .map_err(|_| CiError::Message("predecessor origin cannot hold path".into()))?;
        path.pop_if_empty();
        for part in repository.split('/') {
            path.push(part);
        }
        path.push("releases")
            .push("download")
            .push(&version.to_string())
            .push("release-manifest.json");
    }
    let budget = super::http::ReadBudget::new(deadline);
    let bytes = super::http::download(
        &super::http::HttpsTransport,
        &budget,
        &url,
        &[],
        artifacts::MAX_FILE_BYTES,
    )?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
        .map_err(CiError::Message)?;
    let manifest: super::bundle::PublicManifest = serde_json::from_slice(&bytes)?;
    if manifest.schema != 1
        || manifest.version != version
        || manifest.tag != version.to_string()
        || manifest.commit != selected.commit
    {
        return Err(CiError::Message(
            "actual predecessor publication source/version differs".into(),
        ));
    }
    fs::write(receipts.join("predecessor-release-manifest.json"), &bytes)?;
    let packages_directory = receipts.join("packages");
    fs::create_dir(&packages_directory)?;
    let mut records = Vec::new();
    let mut payloads = Vec::new();
    for name in source::PUBLIC_PACKAGES {
        let expected = format!("{name}-{version}.crate");
        let matches = manifest
            .files
            .iter()
            .filter(|record| {
                record.kind == "crate"
                    && record.package.as_deref() == Some(name)
                    && record.name == expected
            })
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(CiError::Message(
                "predecessor publication omits or duplicates a required crate".into(),
            ));
        }
        let record = matches[0];
        let mut url = url::Url::parse("https://static.crates.io/crates/")
            .map_err(|_| CiError::Message("predecessor registry URL invalid".into()))?;
        url.path_segments_mut()
            .map_err(|_| CiError::Message("predecessor registry URL cannot hold path".into()))?
            .pop_if_empty()
            .push(name)
            .push(&record.name);
        let bytes = super::http::download(
            &super::http::HttpsTransport,
            &budget,
            &url,
            &[],
            artifacts::MAX_FILE_BYTES,
        )?;
        artifacts::check_bytes(record, &bytes)?;
        let members = artifacts::crate_members(&bytes)?;
        let vcs = members
            .get(".cargo_vcs_info.json")
            .ok_or_else(|| CiError::Message("predecessor crate source identity absent".into()))?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(vcs)
            .map_err(CiError::Message)?;
        let vcs: serde_json::Value = serde_json::from_slice(vcs)?;
        if vcs["git"]["sha1"].as_str() != Some(selected.commit.as_str()) {
            return Err(CiError::Message(
                "predecessor registry crate came from a different source commit".into(),
            ));
        }
        fs::write(packages_directory.join(&record.name), &bytes)?;
        payloads.push(bytes);
        records.push(record.clone());
    }
    let mut packages = super::packages::PackageBundle {
        format: "memcordon.packages".into(),
        revision: 1,
        source: selected.clone().into(),
        files: records,
    };
    let order = super::packages::archive_order(&packages, &payloads)?;
    packages.files.sort_by_key(|record| {
        order
            .iter()
            .position(|name| Some(name) == record.package.as_ref())
            .expect("validated predecessor archive order")
    });
    source::write_json(&packages_directory.join("packages.json"), &packages)?;
    super::packages::PackageBundle::load(&packages_directory)?;
    let acquisition = tempfile::Builder::new()
        .prefix("older-cargo-runtime-")
        .tempdir()?;
    public_registry_location::require_independent(acquisition.path()).map_err(CiError::Message)?;
    let home = acquisition.path().join("cargo-home");
    fs::create_dir(&home)?;
    let install = acquisition.path().join("install");
    let stable = crate::config::toolchains(root)?.stable;
    // A fresh target scope requires every selected executable to originate in
    // this install's synchronous compiler capture, including on cache hits.
    let cache = root.join("target/ci-predecessor");
    fs::create_dir_all(&cache)?;
    let install_target = tempfile::Builder::new()
        .prefix("public-install-target-")
        .tempdir_in(std::path::absolute(&cache)?)?;
    let capture = prepare_public_install_capture(
        root,
        acquisition.path(),
        install_target.path(),
        &home,
        receipts,
        &stable,
        &current.distribution,
        &packages.source,
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
    .arg(format!("={version}"))
    .arg("--target")
    .arg(&current.distribution.target)
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
    for feature in &current.distribution.features {
        command = command.arg("--features").arg(feature);
    }
    for binary in &current.distribution.binaries {
        command = command.arg("--bin").arg(binary);
    }
    source::write_json(
        &receipts.join("predecessor-install-intent.json"),
        &serde_json::json!({"source":selected,"target":current.distribution.target,"features":current.distribution.features,"binaries":current.distribution.binaries,"registry":"crates-io","locked":true,"patches":false}),
    )?;
    let observed = command.output_quiet()?;
    fs::write(
        receipts.join("predecessor-cargo.stdout.jsonl"),
        &observed.stdout,
    )?;
    fs::write(
        receipts.join("predecessor-cargo.stderr.bin"),
        &observed.stderr,
    )?;
    if !observed.status.success() {
        return Err(CiError::Message(
            "actual older Cargo runtime build/install failed".into(),
        ));
    }
    let native_manifest = verify_public_install_artifacts(
        &observed.stdout,
        &home,
        &install,
        &current.distribution,
        &packages.source,
        &capture.descriptor,
    )?;
    verify_cached_public_packages(&home, &packages, receipts)?;
    retain_public_registry_graph(
        root,
        &home,
        &native_manifest,
        &current.distribution,
        &packages,
        receipts,
        deadline,
    )?;
    let mut payload = materialize_cargo_install(
        root,
        current_target,
        &packages_directory,
        current,
        &packages,
        &install,
        temporary_parent,
        true,
    )?;
    retain_public_install_capture(&mut payload, &capture.descriptor, receipts)?;
    Ok(payload)
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
        false,
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
            sha256: String::from(memcordon_core::workload_codec::hash_bytes(&bytes)),
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
        memcordon_core::workload_contract::reject_duplicate_json_keys(line)
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
    memcordon_core::workload_contract::reject_duplicate_json_keys(&observed.stdout)
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
        let hash = String::from(memcordon_core::workload_codec::hash_bytes(&bytes));
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

#[expect(
    clippy::too_many_arguments,
    reason = "Cargo install materialization retains independent source, package, target, toolchain, custody, and deadline"
)]
fn materialize_cargo_install(
    root: &Path,
    target_directory: &Path,
    package_directory: &Path,
    bundle: &TargetBundle,
    packages: &super::packages::PackageBundle,
    install_root: &Path,
    temporary_parent: &Path,
    legacy_predecessor: bool,
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
    let mut manifest = measured_manifest(&packages.source, &bundle.distribution, &directory)?;
    if legacy_predecessor
        && bundle.distribution.runtime_selection()?
            == super::distribution::RuntimeSelection::LinuxPrivateTcp
    {
        manifest = RuntimeManifest::linux_selected(
            manifest.version,
            manifest.source_commit,
            manifest.target,
            manifest.components,
            true,
        )
        .map_err(CiError::Message)?;
    }
    source::write_json(&directory.join("runtime-manifest.json"), &manifest)?;
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
        OsString::from("result-v1"),
        OsString::from("--report"),
        report_path.as_os_str().to_os_string(),
        OsString::from("--"),
        fixture.as_os_str().to_os_string(),
    ])
    .args(fixture_arguments);
    Ok((command, report_path))
}

pub fn run_cli_case(
    payload: &MaterializedPayload,
    output_directory: &Path,
    name: &str,
    wrapper_arguments: &[OsString],
    fixture_arguments: &[&str],
) -> Result<ResultV1> {
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
    predecessor: Option<&MaterializedPayload>,
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
            &installed,
            output.join("windows-installed"),
        )?;
        let predecessor = predecessor.ok_or_else(|| {
            CiError::Message(
                "installed Windows lifecycle requires its acquired rc19 predecessor".into(),
            )
        })?;
        let older = crate::windows_installed_cases::InstalledWindowsPayload::from_materialized(
            predecessor.channel,
            &predecessor.source,
            &predecessor.distribution,
            installed_case_artifacts(
                &predecessor.artifacts,
                predecessor.selected_artifact_count,
                predecessor.distribution.binaries.len(),
            )?,
            &predecessor.directory,
            predecessor.fixture.clone(),
            &installed,
            output.join("windows-predecessor"),
        )?;
        fs::create_dir_all(&config.output_directory)?;
        source::write_json(
            &config
                .output_directory
                .join("windows-upgrade-predecessor.json"),
            &crate::windows_installed_cases::WindowsUpgradePredecessor {
                format: "memcordon.windows-upgrade-predecessor".into(),
                revision: 1,
                payload: older,
            },
        )?;
        let assessment = crate::windows_installed_cases::run_from_source_with_observer_until(
            root,
            &config,
            &mut |_| Ok(()),
            crate::windows_installed_cases::WindowsLeaseDeadlines::finite_default(),
        )?;
        source::write_json(&output.join("windows-assessment.json"), &assessment)?;
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
        super::linux_installed_consumer::run(root, payload, &output.join("linux-installed"))?;
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
        let payload = match channel {
            InstalledChannel::NativeBundle => materialize_native(target_directory, destination)?,
            InstalledChannel::CargoPackage => {
                let consumer = PackageConsumer::prepare_selected(
                    root,
                    package_directory,
                    &bundle.distribution,
                )?;
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
        let predecessor = if payload.distribution.runtime_selection()?
            == super::distribution::RuntimeSelection::WindowsSealed
        {
            Some(acquire_cargo_predecessor(
                root,
                target_directory,
                &bundle,
                destination,
                &destination.join("predecessor"),
                std::time::Instant::now() + Duration::from_secs(7200),
            )?)
        } else {
            None
        };
        run_materialized_channel(
            root,
            &payload,
            predecessor.as_ref(),
            &destination.join("cases"),
        )?;
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
