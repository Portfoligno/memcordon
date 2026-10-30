//! Actual selected-cell acquisition and its explicit outer cleanup boundary.
use crate::{
    CiError, Result,
    consumer_readiness_current::{self, CellEvidenceV2 as CellEvidence},
    readiness_identity::SourceIdentity,
};
use memcordon_readiness_verifier::ProductKey;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug, clap::Args)]
pub struct CellArguments {
    #[arg(long)]
    pub target: String,
    #[arg(long)]
    pub channel: String,
    #[arg(long)]
    pub identity: PathBuf,
    #[arg(long)]
    pub destination: PathBuf,
    #[arg(long)]
    pub operation_deadline_unix_millis: u64,
    #[arg(long)]
    pub owner_preparation_sha256: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CellOwner {
    format: String,
    revision: u32,
    identity: SourceIdentity,
    key: ProductKey,
    deadline_unix_millis: u64,
    finalization_completed: bool,
    cleanup_failures: Vec<String>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy)]
enum CellOperation {
    Execute,
    Cleanup,
}

#[cfg(any(target_os = "linux", test))]
fn toolchain_environment(
    path: std::ffi::OsString,
    rustup_home: PathBuf,
) -> [std::ffi::OsString; 2] {
    let mut native_path = std::ffi::OsString::from("PATH=");
    native_path.push(path);
    let mut rustup_environment = std::ffi::OsString::from("RUSTUP_HOME=");
    rustup_environment.push(rustup_home);
    [native_path, rustup_environment]
}

#[cfg(target_os = "linux")]
pub(super) fn selected_toolchain_environment() -> Result<[std::ffi::OsString; 2]> {
    let path = std::env::var_os("PATH")
        .ok_or_else(|| CiError::Message("native toolchain PATH absent".into()))?;
    let rustup_home = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
        .ok_or_else(|| CiError::Message("native Rust toolchain home absent".into()))?;
    Ok(toolchain_environment(path, rustup_home))
}

#[cfg(any(target_os = "linux", test))]
fn privileged_cell_command(
    root: &Path,
    arguments: &CellArguments,
    operation: CellOperation,
    toolchain: [std::ffi::OsString; 2],
    executable: &Path,
    deadline: Instant,
) -> Result<crate::command::CommandSpec> {
    let (command, minutes) = match operation {
        CellOperation::Execute => ("consumer-readiness-cell", 150),
        CellOperation::Cleanup => ("consumer-readiness-cleanup", 15),
    };
    let [native_path, rustup_environment] = toolchain;
    let mut command =
        crate::command::CommandSpec::new("sudo", root, Duration::from_secs(minutes * 60))
            .arg("-n")
            .arg("--")
            .arg("/usr/bin/env")
            .arg(native_path)
            .arg(rustup_environment)
            .arg(executable)
            .arg(command)
            .arg("--target")
            .arg(&arguments.target)
            .arg("--channel")
            .arg(&arguments.channel)
            .arg("--identity")
            .arg(std::path::absolute(&arguments.identity)?)
            .arg("--destination")
            .arg(std::path::absolute(&arguments.destination)?)
            .arg("--operation-deadline-unix-millis")
            .arg(arguments.operation_deadline_unix_millis.to_string())
            .bounded_until(deadline);
    if let Some(digest) = &arguments.owner_preparation_sha256 {
        command = command.args(["--owner-preparation-sha256", digest]);
    }
    Ok(command)
}

#[cfg(test)]
#[path = "../../tests/private/readiness_cell_privilege.rs"]
mod privilege_tests;

fn remaining(arguments: &CellArguments) -> Result<Instant> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CiError::Message(error.to_string()))?;
    let now = u64::try_from(now.as_millis())
        .map_err(|_| CiError::Message("native wall clock exceeds operation range".into()))?;
    let remaining = arguments
        .operation_deadline_unix_millis
        .checked_sub(now)
        .filter(|remaining| *remaining > 0 && *remaining <= 150 * 60 * 1000)
        .ok_or_else(|| {
            CiError::Message(
                "selected cell original deadline expired or exceeds finite operation budget".into(),
            )
        })?;
    Ok(Instant::now() + Duration::from_millis(remaining))
}
fn select(
    root: &Path,
    arguments: &CellArguments,
) -> Result<(SourceIdentity, ProductKey, super::target::TargetBundle)> {
    let identity: SourceIdentity = super::source::read_json(&arguments.identity)?;
    let key = ProductKey {
        target: arguments.target.clone(),
        channel: arguments.channel.clone(),
    };
    if ![
        "candidate-native",
        "candidate-cargo",
        "public-native",
        "public-cargo",
    ]
    .contains(&key.channel.as_str())
        || key.target != super::distribution::native_target()?
    {
        return Err(CiError::Message(
            "readiness cell must select one frozen native target/channel".into(),
        ));
    }
    if key.channel.starts_with("public-") && !root.join(".release/target").exists() {
        let diagnostic = root.join("target/ci/native/release/workload-diagnostic.json");
        super::installed_consumer::retain_original_public_inputs(
            &root.join(".release/prepared"),
            &key.target,
            &root
                .join("target/ci/native/release")
                .join(super::target::binary_name(
                    "memcordon-test-fixture",
                    &key.target,
                )),
            key.target
                .ends_with("-pc-windows-msvc")
                .then_some(diagnostic.as_path()),
            &root.join(".release/target"),
            &root.join(".release/packages"),
        )?;
    }
    let (bundle, _) = super::target::TargetBundle::load(&root.join(".release/target"))?;
    if bundle.distribution.target != key.target
        || bundle.source.commit() != identity.source_commit
        || bundle.source.version().to_string() != identity.version
    {
        return Err(CiError::Message(
            "selected cell source/version/native payload differs".into(),
        ));
    }
    let expected = super::distribution::Distribution::read(root)?
        .consumer_readiness()?
        .native()?
        .clone();
    if bundle.distribution != expected {
        return Err(CiError::Message(
            "selected cell did not acquire full consumer profile".into(),
        ));
    }
    bundle.source.recheck(root)?;
    Ok((identity, key, bundle))
}

pub fn execute(root: &Path, arguments: &CellArguments) -> Result<()> {
    let cleanup_deadline = remaining(arguments)?;
    let deadline = cleanup_deadline
        .checked_sub(Duration::from_secs(15 * 60))
        .filter(|deadline| *deadline > Instant::now())
        .ok_or_else(|| {
            CiError::Message(
                "original selected-cell work budget exhausted before reserved cleanup".into(),
            )
        })?;
    let (identity, key, bundle) = select(root, arguments)?;
    #[cfg(target_os = "linux")]
    if !rustix::process::geteuid().is_root() {
        let proof = crate::preparation_tools::checked_owner_preparation(
            root,
            crate::preparation_tools::Kind::Readiness,
        )?;
        let mut arguments = arguments.clone();
        arguments.owner_preparation_sha256 = Some(super::artifacts::checksum(&proof));
        return privileged_cell_command(
            root,
            &arguments,
            CellOperation::Execute,
            selected_toolchain_environment()?,
            &std::env::current_exe()?,
            cleanup_deadline,
        )?
        .run()
        .map(|_| ());
    }
    fs::create_dir_all(&arguments.destination)?;
    let artifact_root = std::path::absolute(&arguments.destination)?;
    let prefix = artifact_root.join(&key.target).join(&key.channel);
    #[cfg(target_os = "linux")]
    let publication = {
        if !rustix::process::geteuid().is_root() {
            return Err(CiError::Message(
                "cell publication requires the original privileged controller".into(),
            ));
        }
        std::sync::Arc::new(
            super::linux_lifecycle_diagnostics::HeldCellPublication::create(
                &artifact_root,
                &identity,
                &key,
            )?,
        )
    };
    #[cfg(not(target_os = "linux"))]
    fs::create_dir_all(&prefix)?;
    let owner_path = prefix.join("cell-owner.json");
    if owner_path.exists() {
        return Err(CiError::Message(
            "readiness cell cannot reuse an existing installation owner".into(),
        ));
    }
    let mut owner = CellOwner {
        format: "memcordon.consumer-readiness.cell-owner".into(),
        revision: 1,
        identity: identity.clone(),
        key: key.clone(),
        deadline_unix_millis: arguments.operation_deadline_unix_millis,
        finalization_completed: false,
        cleanup_failures: Vec::new(),
    };
    super::source::write_json(&owner_path, &owner)?;
    let index = consumer_readiness_current::initialize(
        &root.join("ci/consumer-readiness-v2.toml"),
        identity.clone(),
    )
    .map_err(CiError::Message)?;
    let mut cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 2,
        identity: identity.clone(),
        key: key.clone(),
        product: None,
        component_build: None,
        records: index
            .records
            .into_iter()
            .filter(|record| {
                record.key.target == key.target
                    && record.key.channel.as_deref() == Some(&key.channel)
            })
            .collect(),
        artifacts: Vec::new(),
        cleanup_failures: Vec::new(),
        cache_quiescent: false,
    };
    // A killed controller still leaves an explicit not-run inventory for the
    // separate native cleanup reentry; no successful row is reconstructed.
    super::source::write_json(&arguments.destination.join("cell.json"), &cell)?;
    let result = (|| -> Result<()> {
        let candidate_target = root.join(".release/target");
        let candidate_packages = root.join(".release/packages");
        let (target, packages) = if key.channel.starts_with("public-") {
            super::installed_consumer::acquire_public_selected(
                &root.join(".release/prepared"),
                &candidate_target,
                &candidate_packages,
                &prefix.join("public-acquisition"),
                deadline,
            )?
        } else {
            (candidate_target, candidate_packages)
        };
        let mut payload = if key.channel.ends_with("native") {
            super::installed_consumer::materialize_native(&target, &prefix)?
        } else if key.channel.starts_with("public-") {
            super::installed_consumer::materialize_public_cargo(
                root,
                &target,
                &packages,
                &bundle,
                &root.join("target/ci-consumers"),
                &prefix,
                &prefix.join("public-cargo"),
                deadline,
            )?
        } else {
            let consumer = super::packages::PackageConsumer::prepare_selected(
                root,
                &packages,
                &bundle.distribution,
            )?;
            let payload = super::installed_consumer::materialize_cargo(
                root,
                &target,
                &packages,
                &bundle,
                &consumer,
                &root.join("target/ci-consumers"),
                &prefix,
            )?;
            consumer.retain_install_graph(
                root,
                &packages,
                &prefix.join("candidate-cargo-lineage"),
                &artifact_root,
                deadline,
            )?;
            payload
        };
        super::installed_consumer::require_current_runtime(&payload)?;
        #[cfg(target_os = "linux")]
        let owner_preparation = {
            let kind = crate::preparation_tools::Kind::Readiness;
            let proof =
                super::artifacts::read_file(&root.join(crate::preparation_tools::manifest(kind)))?;
            let expected = match &arguments.owner_preparation_sha256 {
                Some(digest) => digest.clone(),
                None => super::artifacts::checksum(
                    &crate::preparation_tools::checked_owner_preparation(root, kind)?,
                ),
            };
            if super::artifacts::checksum(&proof) != expected {
                return Err(CiError::Message(
                    "readiness owner preparation changed after full transport validation".into(),
                ));
            }
            proof
        };
        #[cfg(target_os = "linux")]
        payload.artifacts.extend(
            super::original_native_components::retain_current_owner_probe(
                &owner_preparation,
                &super::original_native_components::OwnerProbeOrigin {
                    kind: crate::preparation_tools::Kind::Readiness,
                    commit: &identity.source_commit,
                    version: &identity.version,
                    target: &key.target,
                    run: &identity.run_id,
                },
                &prefix.join("owner-probe"),
            )?,
        );
        #[cfg(target_os = "linux")]
        {
            let observed = super::linux_current_installed::run_current_cell(
                root,
                &payload,
                &identity,
                &key,
                &prefix.join("lifetime"),
                &artifact_root,
                deadline,
                cleanup_deadline,
                arguments.operation_deadline_unix_millis,
                publication.clone(),
            );
            let (records, captures, primary) = match observed {
                Ok((records, captures)) => (records, captures, None),
                Err(primary) => {
                    match super::linux_current_installed::collect_current_cell_observations(
                        &prefix.join("lifetime"),
                        &artifact_root,
                        &identity,
                        &key,
                    ) {
                        Ok((records, captures)) => (records, captures, Some(primary)),
                        Err(secondary) => {
                            cell.cleanup_failures
                                .push(format!("current original observation frame: {secondary}"));
                            publication.verify().map_err(|error|CiError::Message(format!("{primary}; original frame capture: {secondary}; publication custody: {error}")))?;
                            let captures=capture_current_failure_files(&prefix.join("lifetime"),&artifact_root)
                            .map_err(|error|CiError::Message(format!("{primary}; original frame capture: {secondary}; native diagnostic capture: {error}")))?;
                            (Vec::new(), captures, Some(primary))
                        }
                    }
                }
            };
            for record in records {
                let selected = cell
                    .records
                    .iter_mut()
                    .find(|selected| selected.key == record.key)
                    .ok_or_else(|| {
                        CiError::Message(
                            "current Linux driver emitted an unplanned native case".into(),
                        )
                    })?;
                if selected.state != memcordon_readiness_verifier::CaseState::NotRun {
                    return Err(CiError::Message(
                        "current Linux driver duplicated an observed native case".into(),
                    ));
                }
                *selected = record;
            }
            cell.artifacts.extend(captures);
            if let Some(primary) = primary {
                return Err(primary);
            }
            let (product, artifacts) = super::readiness_product::collect_current(
                &identity,
                &key,
                &payload,
                root,
                &prefix,
                &artifact_root,
                &target,
                &packages,
                deadline,
            )?;
            cell.product = Some(product);
            for artifact in artifacts {
                if let Some(existing) = cell
                    .artifacts
                    .iter()
                    .find(|existing| existing.path == artifact.path)
                {
                    if existing.sha256 != artifact.sha256 || existing.length != artifact.length {
                        return Err(CiError::Message(
                            "normalized row and selected-product artifact bytes differ".into(),
                        ));
                    }
                } else {
                    cell.artifacts.push(artifact);
                }
            }
        }
        #[cfg(windows)]
        {
            let archived = crate::command::CommandSpec::new("git", root, Duration::from_secs(60))
                .args(["archive", "--format=tar", &identity.source_commit])
                .output_limit(super::source::MAX_SOURCE_ARCHIVE_BYTES)
                .bounded_until(deadline)
                .output_quiet()?;
            let fixture_source_sha256 = super::artifacts::checksum(&archived.stdout);
            if !archived.status.success() || fixture_source_sha256 != identity.source_tree_sha256 {
                return Err(CiError::Message("actual complete selected fixture source archive differs from original source identity".into()));
            }
            let fixture_source = prefix.join("windows-fixture-selected-source.tar");
            {
                use std::io::Write;
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&fixture_source)?;
                file.write_all(&archived.stdout)?;
                file.sync_all()?;
            }
            let observed = super::windows_readiness_lease::run(
                root,
                &payload,
                &identity,
                &key,
                &prefix.join("lifetime"),
                &artifact_root,
                cleanup_deadline,
            );
            if let Err(original) = &observed {
                let selected_path = prefix.join("lifetime/selected-current.json");
                let journal_path = prefix.join("lifetime/installed-journal.json");
                if selected_path.is_file() && journal_path.is_file() {
                    let selected_custody = crate::windows_readiness_adapter::hold_artifact(
                        &selected_path,
                        None,
                        16 * 1024 * 1024,
                    )?;
                    let journal_custody = crate::windows_readiness_adapter::hold_artifact(
                        &journal_path,
                        None,
                        16 * 1024 * 1024,
                    )?;
                    memcordon_core::canonical_json::reject_duplicate_json_keys(
                        &selected_custody.bytes,
                    )
                    .map_err(CiError::Message)?;
                    memcordon_core::canonical_json::reject_duplicate_json_keys(
                        &journal_custody.bytes,
                    )
                    .map_err(CiError::Message)?;
                    let current: crate::windows_installed_cases::InstalledWindowsPayload =
                        serde_json::from_slice(&selected_custody.bytes)?;
                    let journal: memcordon_readiness_verifier::InstalledLifecycleJournal =
                        serde_json::from_slice(&journal_custody.bytes)?;
                    let expected_lease = super::artifacts::checksum(&serde_json::to_vec(&(
                        &identity,
                        &key,
                        "windows-installed-lease",
                    ))?);
                    if journal.format != "memcordon.consumer-readiness.installed-journal"
                        || journal.revision != 1
                        || journal.lease_id != expected_lease
                        || journal.run_id != identity.run_id
                        || journal.key != key
                        || journal.source_commit != identity.source_commit
                        || journal.source_tree_sha256 != identity.source_tree_sha256
                    {
                        return Err(CiError::Message(format!(
                            "{original}; retained Windows lifetime association differs"
                        )));
                    }
                    let context = crate::windows_readiness_adapter::WindowsAdapterContext {
                        identity: identity.clone(),
                        product: key.clone(),
                        lease_id: journal.lease_id,
                        destination: artifact_root.clone(),
                        fixture_source: crate::windows_installed_cases::SelectedArtifact {
                            path: fixture_source.clone(),
                            sha256: fixture_source_sha256.clone(),
                        },
                    };
                    let retained =
                        crate::windows_readiness_adapter::normalize_retained(&context, &current)
                            .map_err(|error| {
                                CiError::Message(format!(
                                    "{original}; retained Windows normalization: {error}"
                                ))
                            })?;
                    for record in retained.records {
                        let selected = cell
                            .records
                            .iter_mut()
                            .find(|selected| selected.key == record.key)
                            .ok_or_else(|| {
                                CiError::Message(
                                    "retained Windows adapter emitted an unknown finite row".into(),
                                )
                            })?;
                        if selected.state != memcordon_readiness_verifier::CaseState::NotRun {
                            return Err(CiError::Message(
                                "retained Windows adapter duplicated a finite row".into(),
                            ));
                        }
                        *selected = record;
                    }
                    cell.artifacts.extend(retained.artifacts);
                }
            }
            let lifetime = observed?;
            let context = crate::windows_readiness_adapter::WindowsAdapterContext {
                identity: identity.clone(),
                product: key.clone(),
                lease_id: lifetime.journal.lease_id.clone(),
                destination: artifact_root.clone(),
                fixture_source: crate::windows_installed_cases::SelectedArtifact {
                    path: fixture_source,
                    sha256: fixture_source_sha256,
                },
            };
            let normalized = crate::windows_readiness_adapter::normalize_positive(
                &context,
                &lifetime.current,
                &lifetime
                    .current
                    .output_directory
                    .join("windows-readiness-input.json"),
                &lifetime.assessment.positive_cases,
            )?;
            let losses = crate::windows_readiness_adapter::normalize_loss(
                &context,
                &lifetime.current,
                &lifetime.assessment.loss_cases,
            )?;
            let capacity = crate::windows_readiness_adapter::normalize_capacity(
                &context,
                &lifetime.current,
                &lifetime
                    .current
                    .output_directory
                    .join("windows-readiness-input.json"),
                &lifetime.assessment.capacity_cases,
            )?;
            let refusals = crate::windows_readiness_adapter::normalize_refusals(
                &context,
                &lifetime.current,
                &lifetime.assessment.refusal_cases,
            )?;
            let special = crate::windows_readiness_adapter::normalize_special(
                &context,
                &lifetime.current,
                &lifetime.assessment.cases,
            )?;
            for record in normalized
                .records
                .into_iter()
                .chain(losses.records)
                .chain(capacity.records)
                .chain(refusals.records)
                .chain(special.records)
            {
                let selected = cell
                    .records
                    .iter_mut()
                    .find(|selected| selected.key == record.key)
                    .ok_or_else(|| {
                        CiError::Message(
                            "Windows installed adapter emitted an unknown finite row".into(),
                        )
                    })?;
                if selected.state != memcordon_readiness_verifier::CaseState::NotRun {
                    return Err(CiError::Message(
                        "Windows installed adapters duplicated an observed finite row".into(),
                    ));
                }
                *selected = record;
            }
            cell.artifacts.extend(normalized.artifacts);
            cell.artifacts.extend(losses.artifacts);
            cell.artifacts.extend(capacity.artifacts);
            cell.artifacts.extend(refusals.artifacts);
            cell.artifacts.extend(special.artifacts);
            let (product, artifacts) = super::readiness_product::collect_current(
                &identity,
                &key,
                &payload,
                root,
                &prefix,
                &artifact_root,
                &target,
                &packages,
                deadline,
            )?;
            let package = crate::windows_readiness_adapter::normalize_lifecycle(
                &context,
                &lifetime.current,
                &product,
                &prefix.join("lifetime/installed-journal.json"),
                &prefix.join("lifetime/windows-lease-owner.json"),
            )?;
            for record in package.records {
                let selected = cell
                    .records
                    .iter_mut()
                    .find(|selected| selected.key == record.key)
                    .ok_or_else(|| {
                        CiError::Message(
                            "current Windows package adapter emitted unknown finite row".into(),
                        )
                    })?;
                if selected.state != memcordon_readiness_verifier::CaseState::NotRun {
                    return Err(CiError::Message(
                        "current Windows package row already observed".into(),
                    ));
                }
                *selected = record;
            }
            cell.artifacts.extend(package.artifacts);
            cell.product = Some(product);
            for artifact in artifacts {
                if let Some(existing) = cell
                    .artifacts
                    .iter()
                    .find(|existing| existing.path == artifact.path)
                {
                    if existing.sha256 != artifact.sha256 || existing.length != artifact.length {
                        return Err(CiError::Message(
                            "Windows normalized row and selected-product artifact bytes differ"
                                .into(),
                        ));
                    }
                } else {
                    cell.artifacts.push(artifact);
                }
            }
        }
        Ok(())
    })();
    #[cfg(target_os = "linux")]
    let result = crate::work_outcome::join_completed(
        crate::work_outcome::WorkOutcome::from_result(result),
        crate::work_outcome::WorkOutcome::from_result(public_projection::canonicalize(
            &arguments.destination,
            &mut cell,
            cleanup_deadline,
        )),
    )
    .into_result();
    if let Err(error) = &result {
        owner.cleanup_failures.push(error.to_string());
        cell.cleanup_failures.push(error.to_string());
    }
    // Only a native final retirement receipt may complete the owner; the
    // normalized product adapter joins that receipt separately.
    let retirement = prefix.join("lifetime/installed-retirement.json");
    if retirement.is_file() {
        let receipt: memcordon_readiness_verifier::current::InstalledLifecycleReceiptV2 =
            super::source::read_json(&retirement)?;
        owner.finalization_completed = receipt.package_absent
            && memcordon_readiness_verifier::current::validate_native_inventory(
                &key.target,
                &receipt.native,
            )
            .is_ok()
            && receipt.outstanding.is_empty()
            && receipt.cleanup_failures.is_empty();
        cell.cache_quiescent = owner.finalization_completed;
    }
    super::source::write_json(&owner_path, &owner)?;
    super::source::write_json(&arguments.destination.join("cell.json"), &cell)?;
    #[cfg(target_os = "linux")]
    {
        let projection =
            public_projection::publish(&arguments.destination, &cell, cleanup_deadline);
        crate::work_outcome::join_completed(
            crate::work_outcome::WorkOutcome::from_result(result),
            crate::work_outcome::WorkOutcome::from_result(projection),
        )
        .into_result()
    }
    #[cfg(not(target_os = "linux"))]
    result
}

/// The Linux administrative tree stays private; clients consume its projection.
pub fn cell_record_path(destination: &Path) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        destination.join("producer/cell.json")
    }
    #[cfg(not(target_os = "linux"))]
    {
        destination.join("cell.json")
    }
}

#[cfg(target_os = "linux")]
fn capture_current_failure_files(
    lifetime: &Path,
    artifact_root: &Path,
) -> Result<Vec<memcordon_readiness_verifier::Artifact>> {
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut captured = Vec::new();
    for name in [
        "current-owner.json",
        "installed-journal.json",
        "installed-retirement.json",
        "native-absence.json",
    ] {
        let mut file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(lifetime.join(name))
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let before = file.metadata()?;
        if !before.is_file()
            || before.uid() != 0
            || before.mode() & 0o022 != 0
            || before.nlink() != 1
            || before.len() > 16 * 1024 * 1024
        {
            return Err(CiError::Message(
                "current failure diagnostic file custody/bound differs".into(),
            ));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() as u64 != before.len()
            || (
                before.dev(),
                before.ino(),
                before.len(),
                before.mtime(),
                before.mtime_nsec(),
            ) != (
                after.dev(),
                after.ino(),
                after.len(),
                after.mtime(),
                after.mtime_nsec(),
            )
        {
            return Err(CiError::Message(
                "current failure diagnostic changed during capture".into(),
            ));
        }
        let path = lifetime.join(format!("controller-failure-capture-{name}"));
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        let relative = path.strip_prefix(artifact_root).map_err(|_| {
            CiError::Message("current failure capture escapes original artifact namespace".into())
        })?;
        captured.push(memcordon_readiness_verifier::Artifact {
            path: relative
                .to_str()
                .ok_or_else(|| CiError::Message("current failure capture encoding differs".into()))?
                .into(),
            length: bytes.len() as u64,
            sha256: super::artifacts::checksum(&bytes),
        });
    }
    Ok(captured)
}

#[cfg(unix)]
#[path = "readiness_public_projection.rs"]
pub(crate) mod public_projection;

pub fn cleanup(root: &Path, arguments: &CellArguments) -> Result<()> {
    let deadline = remaining(arguments)?;
    let (identity, key, _) = select(root, arguments)?;
    // The cell owner is created by the privileged execution path and remains
    // root-private. Enter the existing cleanup boundary before reading it.
    #[cfg(target_os = "linux")]
    if !rustix::process::geteuid().is_root() {
        return privileged_cell_command(
            root,
            arguments,
            CellOperation::Cleanup,
            selected_toolchain_environment()?,
            &std::env::current_exe()?,
            deadline,
        )?
        .run()
        .map(|_| ());
    }
    let bound_arguments = CellArguments {
        destination: std::path::absolute(&arguments.destination)?,
        ..arguments.clone()
    };
    let arguments = &bound_arguments;
    let path = arguments
        .destination
        .join(&key.target)
        .join(&key.channel)
        .join("cell-owner.json");
    let mut owner: CellOwner = super::source::read_json(&path)?;
    if owner.format != "memcordon.consumer-readiness.cell-owner"
        || owner.revision != 1
        || owner.identity.run_id != identity.run_id
        || owner.identity.source_commit != identity.source_commit
        || owner.identity.source_tree_sha256 != identity.source_tree_sha256
        || owner.key != key
        || owner.deadline_unix_millis != arguments.operation_deadline_unix_millis
    {
        return Err(CiError::Message(
            "cleanup cannot reassociate a selected installation owner".into(),
        ));
    }
    if owner.finalization_completed {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let recovered = super::linux_current_installed::recover_current_cell(
            root,
            &path.parent().expect("cell owner parent").join("lifetime"),
            &arguments.destination,
            &identity,
            &key,
            deadline,
        );
        if let Err(cause) = &recovered {
            let cell_path = arguments.destination.join("cell.json");
            let retention = (|| -> Result<()> {
                let mut cell: CellEvidence = super::source::read_json(&cell_path)?;
                if serde_json::to_value(&cell.identity)? != serde_json::to_value(&identity)?
                    || cell.key != key
                {
                    return Err(CiError::Message(
                        "failed cleanup cell evidence association differs".into(),
                    ));
                }
                cell.cache_quiescent = false;
                cell.cleanup_failures.push(cause.to_string());
                public_projection::canonicalize(&arguments.destination, &mut cell, deadline)?;
                super::source::write_json(&cell_path, &cell)?;
                public_projection::publish(&arguments.destination, &cell, deadline)
            })();
            return crate::work_outcome::join_completed(
                crate::work_outcome::WorkOutcome::<()>::from_result(Err(CiError::Message(
                    cause.to_string(),
                ))),
                crate::work_outcome::WorkOutcome::from_result(retention),
            )
            .into_result();
        }
        let receipt: memcordon_readiness_verifier::current::InstalledLifecycleReceiptV2 =
            super::source::read_json(
                &path
                    .parent()
                    .expect("cell owner parent")
                    .join("lifetime/installed-retirement.json"),
            )?;
        if receipt.format != "memcordon.installed-lifecycle.receipt"
            || receipt.revision != 2
            || receipt.key != key
            || receipt.run_id != identity.run_id
            || !receipt.package_absent
            || !receipt.cache_quiescent
            || !receipt.cleanup_failures.is_empty()
            || !receipt.outstanding.is_empty()
            || receipt.explicit_finalization_count != 1
        {
            return Err(CiError::Message(
                "current recovered native finalization receipt is incomplete or reassociated"
                    .into(),
            ));
        }
        memcordon_readiness_verifier::current::validate_native_inventory(
            &key.target,
            &receipt.native,
        )
        .map_err(CiError::Message)?;
        owner.finalization_completed = true;
        super::source::write_json(&path, &owner)?;
        let cell_path = arguments.destination.join("cell.json");
        let mut cell: CellEvidence = super::source::read_json(&cell_path)?;
        for artifact in recovered? {
            if let Some(old) = cell.artifacts.iter().find(|old| old.path == artifact.path) {
                if old.length != artifact.length || old.sha256 != artifact.sha256 {
                    return Err(CiError::Message(
                        "recovery capture conflicts with original retained bytes".into(),
                    ));
                }
            } else {
                cell.artifacts.push(artifact);
            }
        }
        if serde_json::to_value(&cell.identity)? != serde_json::to_value(&identity)?
            || cell.key != key
        {
            return Err(CiError::Message(
                "cleanup cell evidence association differs".into(),
            ));
        }
        cell.cache_quiescent = true;
        public_projection::canonicalize(&arguments.destination, &mut cell, deadline)?;
        super::source::write_json(&cell_path, &cell)?;
        public_projection::publish(&arguments.destination, &cell, deadline)
    }
    #[cfg(windows)]
    {
        super::windows_readiness_lease::recover(
            root,
            &path.parent().expect("cell owner parent").join("lifetime"),
            &identity,
            &key,
            deadline,
        )?;
        owner.finalization_completed = true;
        super::source::write_json(&path, &owner)?;
        let cell_path = arguments.destination.join("cell.json");
        let mut cell: CellEvidence = super::source::read_json(&cell_path)?;
        if serde_json::to_value(&cell.identity)? != serde_json::to_value(&identity)?
            || cell.key != key
        {
            return Err(CiError::Message(
                "Windows cleanup cell evidence association differs".into(),
            ));
        }
        cell.cache_quiescent = true;
        super::source::write_json(&cell_path, &cell)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (deadline, &mut owner);
        Err(CiError::Message("consumer readiness cleanup supports only the four declared Linux and Windows native targets".into()))
    }
}
