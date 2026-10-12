//! Actual selected-cell acquisition and its explicit outer cleanup boundary.
use crate::{
    CiError, Result,
    consumer_readiness_ledger::{self, CellEvidence, SourceIdentity},
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
        super::installed_consumer::retain_original_public_inputs(
            &root.join(".release/prepared"),
            &key.target,
            &root
                .join("target/ci/native/release")
                .join(super::target::binary_name(
                    "memcordon-test-fixture",
                    &key.target,
                )),
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
        let mut native_path = std::ffi::OsString::from("PATH=");
        native_path.push(
            std::env::var_os("PATH")
                .ok_or_else(|| CiError::Message("native toolchain PATH absent".into()))?,
        );
        let rustup_home = std::env::var_os("RUSTUP_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".rustup")))
            .ok_or_else(|| CiError::Message("native Rust toolchain home absent".into()))?;
        let mut rustup_environment = std::ffi::OsString::from("RUSTUP_HOME=");
        rustup_environment.push(rustup_home);
        return crate::command::CommandSpec::new("sudo", root, Duration::from_secs(150 * 60))
            .arg("-n")
            .arg("--")
            .arg("/usr/bin/env")
            .arg(native_path)
            .arg(rustup_environment)
            .arg(std::env::current_exe()?)
            .arg("consumer-readiness-cell")
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
            .bounded_until(cleanup_deadline)
            .run()
            .map(|_| ());
    }
    fs::create_dir_all(&arguments.destination)?;
    let artifact_root = std::path::absolute(&arguments.destination)?;
    let prefix = artifact_root.join(&key.target).join(&key.channel);
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
    let index = consumer_readiness_ledger::initialize(
        &root.join("ci/consumer-readiness-v1.toml"),
        identity.clone(),
    )
    .map_err(CiError::Message)?;
    let mut cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
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
        let payload = if key.channel.ends_with("native") {
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
        let predecessor = super::installed_consumer::acquire_cargo_predecessor(
            root,
            &target,
            &bundle,
            &prefix,
            &prefix.join("predecessor"),
            deadline,
        )?;
        #[cfg(target_os = "linux")]
        {
            let mut lease = super::linux_readiness_lease::ReadinessLinuxLease::new(
                identity.clone(),
                key.clone(),
                root,
                &artifact_root,
                &predecessor,
                prefix.join("lifetime"),
                deadline,
                cleanup_deadline,
                arguments.operation_deadline_unix_millis,
            )?;
            let observed = super::linux_installed_consumer::run_with_extension(
                root,
                &payload,
                &prefix.join("installed"),
                &mut lease,
            );
            let (records, artifacts) = lease.driver.collect_case_records(
                &identity,
                &key,
                &artifact_root,
                &prefix.join("installed"),
            )?;
            for record in records {
                let selected = cell
                    .records
                    .iter_mut()
                    .find(|selected| selected.key == record.key)
                    .ok_or_else(|| {
                        CiError::Message("installed driver emitted an unknown finite row".into())
                    })?;
                *selected = record;
            }
            cell.artifacts.extend(artifacts);
            observed?;
            let (product, artifacts) = super::readiness_product::collect(
                &identity,
                &key,
                &payload,
                &predecessor,
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
                &predecessor,
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
            for record in normalized
                .records
                .into_iter()
                .chain(losses.records)
                .chain(capacity.records)
                .chain(refusals.records)
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
            let (product, artifacts) = super::readiness_product::collect(
                &identity,
                &key,
                &payload,
                &predecessor,
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
    if let Err(error) = &result {
        owner.cleanup_failures.push(error.to_string());
        cell.cleanup_failures.push(error.to_string());
    }
    // Only a native final retirement receipt may complete the owner; the
    // normalized product adapter joins that receipt separately.
    let retirement = prefix.join("lifetime/installed-retirement.json");
    if retirement.is_file() {
        let receipt: memcordon_readiness_verifier::InstalledLifecycleReceipt =
            super::source::read_json(&retirement)?;
        owner.finalization_completed = receipt.package_absent
            && receipt.policy_retired
            && receipt.native_resources_retired
            && receipt.outstanding.is_empty()
            && receipt.cleanup_failures.is_empty();
        cell.cache_quiescent = owner.finalization_completed;
    }
    super::source::write_json(&owner_path, &owner)?;
    super::source::write_json(&arguments.destination.join("cell.json"), &cell)?;
    result
}

pub fn cleanup(root: &Path, arguments: &CellArguments) -> Result<()> {
    let deadline = remaining(arguments)?;
    let (identity, key, _) = select(root, arguments)?;
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
        if !rustix::process::geteuid().is_root() {
            return crate::command::CommandSpec::new("sudo", root, Duration::from_secs(15 * 60))
                .arg("-n")
                .arg("--")
                .arg(std::env::current_exe()?)
                .arg("consumer-readiness-cleanup")
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
                .bounded_until(deadline)
                .run()
                .map(|_| ());
        }
        super::linux_readiness_lease::recover_installation(
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
                "cleanup cell evidence association differs".into(),
            ));
        }
        cell.cache_quiescent = true;
        super::source::write_json(&cell_path, &cell)
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
