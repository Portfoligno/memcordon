//! Persist owned native image observations without accepting their semantics.
#![cfg(target_os = "linux")]
use super::linux_readiness_image_cases::ImageCaseReport;
use crate::{CiError, Result, consumer_readiness_ledger::SourceIdentity};
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, LinuxImageExportEvidence,
    LinuxImageImportEvidence, LinuxImageMemberCapture, LinuxImagePreparationEvidence, ProductKey,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

fn read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.nlink() != 1
        || ![0, 65534].contains(&before.uid())
        || before.mode() & 0o022 != 0
        || before.len() > limit
    {
        return Err(CiError::Message(
            "native image normalized artifact custody exceeds bound/type".into(),
        ));
    }
    let mut bytes = Vec::new();
    file.try_clone()?.take(limit + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.ctime(),
        after.ctime_nsec(),
    ) || bytes.len() as u64 != before.len()
    {
        return Err(CiError::Message(
            "native image normalized artifact changed during read".into(),
        ));
    }
    Ok(bytes)
}
fn json(path: &Path) -> Result<serde_json::Value> {
    let bytes = read(path, 16 * 1024 * 1024)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    Ok(serde_json::from_slice(&bytes)?)
}
fn relative(root: &Path, path: &Path) -> Result<String> {
    let value = path
        .strip_prefix(root)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if value
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err(CiError::Message(
            "image artifact has noncanonical custody path".into(),
        ));
    }
    value
        .to_str()
        .map(str::to_owned)
        .ok_or_else(|| CiError::Message("image artifact path not UTF8".into()))
}
fn capture(root: &Path, path: &Path, artifacts: &mut BTreeMap<String, Artifact>) -> Result<String> {
    let path_string = relative(root, path)?;
    let bytes = read(path, 128 * 1024 * 1024)?;
    let artifact = Artifact {
        path: path_string.clone(),
        length: bytes.len() as u64,
        sha256: hex::encode(Sha256::digest(&bytes)),
    };
    if artifacts
        .get(&path_string)
        .is_some_and(|old| old.sha256 != artifact.sha256 || old.length != artifact.length)
    {
        return Err(CiError::Message(
            "image artifact path has conflicting owned bytes".into(),
        ));
    }
    artifacts.insert(path_string.clone(), artifact);
    Ok(path_string)
}
fn value_path(value: &serde_json::Value, field: &str) -> Result<PathBuf> {
    value[field]
        .as_str()
        .map(PathBuf::from)
        .ok_or_else(|| CiError::Message(format!("native image receipt path {field} absent")))
}
fn required(path: &Option<PathBuf>) -> Result<&Path> {
    path.as_deref().ok_or_else(|| {
        CiError::Message("export original native acquisition/capture remains unsettled".into())
    })
}
fn persist(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub fn collect_import_records(
    report: &ImageCaseReport,
    identity: &SourceIdentity,
    cell: &ProductKey,
    root: &Path,
    artifacts: &mut BTreeMap<String, Artifact>,
) -> Result<Vec<CaseRecord>> {
    let mut records = Vec::new();
    let neighbor = report
        .observations
        .iter()
        .find(|row| row.scenario == "neighbor-import")
        .ok_or_else(|| {
            CiError::Message("image negatives lack actual neighboring import observation".into())
        })?;
    for (index, row) in report.observations.iter().enumerate() {
        if row.scenario == "neighbor-import" {
            continue;
        }
        let key = CaseKey {
            target: cell.target.clone(),
            channel: Some(cell.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: row.family.clone(),
            scenario: row.scenario.clone(),
        };
        let normalized = (|| -> Result<String> {
            if let Some(error) = &row.error {
                return Err(CiError::Message(error.clone()));
            }
            let inventory = json(&row.source_inventory)?;
            let mut source_members = Vec::new();
            for member in inventory["members"]
                .as_array()
                .ok_or_else(|| CiError::Message("native image source member array absent".into()))?
            {
                if member["bytes"].is_null() {
                    continue;
                }
                source_members.push(LinuxImageMemberCapture {
                    path: member["path"]
                        .as_str()
                        .ok_or_else(|| CiError::Message("native image member path absent".into()))?
                        .into(),
                    bytes: capture(root, &value_path(member, "bytes")?, artifacts)?,
                    baseline_bytes: if member["baseline_bytes"].is_null() {
                        None
                    } else {
                        Some(capture(
                            root,
                            &value_path(member, "baseline_bytes")?,
                            artifacts,
                        )?)
                    },
                });
            }
            let preparation = if let Some(path) = &row.preparation_probe {
                let receipt = json(path)?;
                let result_path = value_path(&receipt, "result")?;
                let directory = result_path.parent().ok_or_else(|| {
                    CiError::Message("native loader frontend directory absent".into())
                })?;
                Some(LinuxImagePreparationEvidence {
                    receipt: capture(root, path, artifacts)?,
                    activation: capture(root, &value_path(&receipt, "activation")?, artifacts)?,
                    policy: capture(
                        root,
                        &path
                            .parent()
                            .ok_or_else(|| CiError::Message("loader probe parent absent".into()))?
                            .join("mixed.policy.json"),
                        artifacts,
                    )?,
                    contract: capture(root, &value_path(&receipt, "contract")?, artifacts)?,
                    provider_request: capture(
                        root,
                        &value_path(&receipt, "provider_request")?,
                        artifacts,
                    )?,
                    result: capture(root, &result_path, artifacts)?,
                    native_census: capture(
                        root,
                        &value_path(&receipt, "native_census")?,
                        artifacts,
                    )?,
                    stdout: capture(root, &directory.join("stdout.bin"), artifacts)?,
                    stderr: capture(root, &directory.join("stderr.bin"), artifacts)?,
                })
            } else {
                None
            };
            let owned = report
                .retained_images
                .get(index)
                .ok_or_else(|| CiError::Message("image cleanup definition owner absent".into()))?;
            let retirement = owned.retirement.as_deref().ok_or_else(|| {
                CiError::Message("native image owner has no retirement capture".into())
            })?;
            let retirement_prefix = retirement
                .to_str()
                .and_then(|path| path.strip_suffix(".stdout.json"))
                .ok_or_else(|| {
                    CiError::Message("image retirement native receipt basename differs".into())
                })?;
            let evidence = LinuxImageImportEvidence {
                format: "memcordon.consumer-readiness.linux-image-import".into(),
                revision: 1,
                key: key.clone(),
                run_id: identity.run_id.clone(),
                source_commit: identity.source_commit.clone(),
                source_tree_sha256: identity.source_tree_sha256.clone(),
                lease_id: inventory["lease_id"]
                    .as_str()
                    .ok_or_else(|| CiError::Message("image original lease absent".into()))?
                    .into(),
                owner: capture(root, &report.output.join("owner.json"), artifacts)?,
                original_lease_owner: capture(
                    root,
                    &report
                        .output
                        .parent()
                        .and_then(Path::parent)
                        .ok_or_else(|| {
                            CiError::Message("image original acquisition directory absent".into())
                        })?
                        .join("lease-owner.json"),
                    artifacts,
                )?,
                observation: relative(root, &row.invocation.with_file_name("observation.json"))?,
                definition: capture(root, &row.definition_capture, artifacts)?,
                cleanup_definition: capture(root, &row.cleanup_definition_capture, artifacts)?,
                import_intent: capture(
                    root,
                    &row.invocation.with_file_name("import-intent.json"),
                    artifacts,
                )?,
                invocation: capture(root, &row.invocation, artifacts)?,
                native_process: capture(root, &row.native_process, artifacts)?,
                native_creation: capture(root, &row.native_creation, artifacts)?,
                stdout: capture(root, &row.stdout, artifacts)?,
                stderr: capture(root, &row.stderr, artifacts)?,
                exit: capture(root, &row.exit, artifacts)?,
                source_inventory: capture(root, &row.source_inventory, artifacts)?,
                baseline_entrypoint: capture(root, &row.baseline_entrypoint, artifacts)?,
                neighbor_definition: capture(root, &neighbor.definition_capture, artifacts)?,
                neighbor_stdout: capture(root, &neighbor.stdout, artifacts)?,
                neighbor_invocation: capture(root, &neighbor.invocation, artifacts)?,
                neighbor_native_process: capture(root, &neighbor.native_process, artifacts)?,
                neighbor_native_creation: capture(root, &neighbor.native_creation, artifacts)?,
                neighbor_stderr: capture(root, &neighbor.stderr, artifacts)?,
                neighbor_exit: capture(root, &neighbor.exit, artifacts)?,
                source_members,
                retirement: capture(root, retirement, artifacts)?,
                retirement_exit: capture(
                    root,
                    Path::new(&format!("{retirement_prefix}.exit.json")),
                    artifacts,
                )?,
                retirement_stderr: capture(
                    root,
                    Path::new(&format!("{retirement_prefix}.stderr.bin")),
                    artifacts,
                )?,
                preparation,
            };
            let observation = row.invocation.with_file_name("observation.json");
            persist(&observation, &serde_json::to_vec(row)?)?;
            capture(root, &observation, artifacts)?;
            let destination = row.invocation.with_file_name("case-evidence.json");
            persist(&destination, &serde_json::to_vec(&evidence)?)?;
            capture(root, &destination, artifacts)
        })();
        match normalized {
            Ok(path) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Passed,
                reason: None,
                evidence: Some(path),
            }),
            Err(error) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(error.to_string()),
                evidence: None,
            }),
        }
    }
    Ok(records)
}

pub fn collect_export_records(
    report: &ImageCaseReport,
    identity: &SourceIdentity,
    cell: &ProductKey,
    root: &Path,
    artifacts: &mut BTreeMap<String, Artifact>,
) -> Result<Vec<CaseRecord>> {
    let mut records = Vec::new();
    for row in &report.export_observations {
        let key = CaseKey {
            target: cell.target.clone(),
            channel: Some(cell.channel.clone()),
            evidence_class: EvidenceClass::InstalledProduct,
            family: row.family.clone(),
            scenario: row.scenario.clone(),
        };
        let normalized = (|| -> Result<String> {
            if let Some(error) = &row.error {
                return Err(CiError::Message(error.clone()));
            }
            let directory = row.challenge.parent().ok_or_else(|| {
                CiError::Message("export original observation directory absent".into())
            })?;
            let mut external = BTreeMap::new();
            let names = if row.fixture_mode == "concurrent-writer" {
                vec![
                    "writer-held.json",
                    "writer-native-held.json",
                    "writer-retired.json",
                    "external-helper-setup.json",
                    "external-helper-invocation.json",
                    "external-helper-held.json",
                    "external-helper-armed.json",
                    "external-helper-event.json",
                    "external-family-retirement.json",
                    "external-cgroup-retirement.json",
                    "external-helper-ack.json",
                    "external-administrative-closure.json",
                    "external-helper-settled.json",
                    "external-helper-retirement.json",
                    "external-helper-stdout.bin",
                    "external-helper-stderr.bin",
                ]
            } else if row.fixture_mode == "device" {
                vec!["device-admin-handles-retired.json"]
            } else {
                Vec::new()
            };
            for name in names {
                external.insert(
                    name.into(),
                    capture(root, &directory.join(name), artifacts)?,
                );
            }
            let observation = directory.join("observation.json");
            persist(&observation, &serde_json::to_vec(row)?)?;
            let owner = json(&report.output.join("owner.json"))?;
            let recovery_path = required(&row.recovery)?;
            let recovery = json(recovery_path)?;
            let mut recovery_artifacts = BTreeMap::new();
            for field in ["invocation", "process", "stdout", "stderr", "census"] {
                let name = recovery[field].as_str().ok_or_else(|| {
                    CiError::Message("export measured recovery capture leaf absent".into())
                })?;
                if Path::new(name).components().count() != 1
                    || !matches!(
                        Path::new(name).components().next(),
                        Some(std::path::Component::Normal(_))
                    )
                {
                    return Err(CiError::Message(
                        "export original recovery leaf crosses selected native scenario".into(),
                    ));
                }
                recovery_artifacts.insert(
                    field.into(),
                    capture(root, &directory.join(name), artifacts)?,
                );
            }
            if recovery["original_journal_present"] == true {
                recovery_artifacts.insert(
                    "original_journal".into(),
                    capture(
                        root,
                        &directory.join("recovery-original-journal.bin"),
                        artifacts,
                    )?,
                );
            }
            let evidence = LinuxImageExportEvidence {
                format: "memcordon.consumer-readiness.linux-image-export".into(),
                revision: 1,
                key: key.clone(),
                run_id: identity.run_id.clone(),
                source_commit: identity.source_commit.clone(),
                source_tree_sha256: identity.source_tree_sha256.clone(),
                lease_id: owner["lease_id"]
                    .as_str()
                    .ok_or_else(|| CiError::Message("export original lease absent".into()))?
                    .into(),
                owner: capture(root, &report.output.join("owner.json"), artifacts)?,
                original_lease_owner: capture(
                    root,
                    &report
                        .output
                        .parent()
                        .and_then(Path::parent)
                        .ok_or_else(|| {
                            CiError::Message("export original acquisition directory absent".into())
                        })?
                        .join("lease-owner.json"),
                    artifacts,
                )?,
                observation: capture(root, &observation, artifacts)?,
                challenge: capture(root, &row.challenge, artifacts)?,
                activation: capture(root, required(&row.activation)?, artifacts)?,
                policy: capture(root, &directory.join("mixed.policy.json"), artifacts)?,
                contract: capture(root, &row.contract, artifacts)?,
                provider_request: capture(root, required(&row.provider_request)?, artifacts)?,
                result: capture(root, required(&row.result)?, artifacts)?,
                prepared: capture(root, required(&row.prepared)?, artifacts)?,
                prepared_native: capture(root, required(&row.prepared_native)?, artifacts)?,
                ready: capture(root, required(&row.ready)?, artifacts)?,
                native_source: capture(root, required(&row.native_source)?, artifacts)?,
                native_worker: capture(root, &directory.join("export-worker.json"), artifacts)?,
                invocation: capture(root, required(&row.native_invocation)?, artifacts)?,
                native_wait: capture(root, required(&row.native_wait)?, artifacts)?,
                native_family: capture(root, required(&row.native_family)?, artifacts)?,
                stdout: capture(root, required(&row.stdout)?, artifacts)?,
                stderr: capture(root, required(&row.stderr)?, artifacts)?,
                controller_setup: row
                    .controller_setup
                    .as_deref()
                    .map(|path| capture(root, path, artifacts))
                    .transpose()?,
                external,
                recovery: capture(root, recovery_path, artifacts)?,
                recovery_artifacts,
            };
            let destination = directory.join("case-evidence.json");
            persist(&destination, &serde_json::to_vec(&evidence)?)?;
            capture(root, &destination, artifacts)
        })();
        match normalized {
            Ok(path) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Passed,
                reason: None,
                evidence: Some(path),
            }),
            Err(error) => records.push(CaseRecord {
                key,
                run_id: identity.run_id.clone(),
                state: CaseState::Failed,
                reason: Some(error.to_string()),
                evidence: None,
            }),
        }
    }
    Ok(records)
}
