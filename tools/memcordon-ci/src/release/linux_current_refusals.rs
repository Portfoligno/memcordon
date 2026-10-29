//! Actual current request preparation failures under the ordinary caller.
use super::{
    artifacts,
    linux_current_installed::CurrentLinuxInput,
    linux_current_package::{retain, retain_raw},
    linux_request_fixture::{CallerRequestFixture, CallerSnapshot},
};
use crate::{CiError, Result, readiness_identity::SourceIdentity};
use memcordon_core::{BoundedVec, identifiers::LogicalId, workload_request::PrivateRootLayoutV1};
use memcordon_readiness_verifier::{
    Artifact, CaseKey, CaseRecord, CaseState, EvidenceClass, ProductKey, current::CaseEvidenceV2,
};
use std::{
    fs,
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        process::ExitStatusExt,
    },
    path::Path,
};

pub(super) fn allocations() -> Result<serde_json::Value> {
    let mut observations = Vec::new();
    for path in [
        "/var/lib/memcordon/workload-attempts",
        "/var/lib/memcordon/workload-inputs",
        "/var/lib/memcordon/workload-resources",
        "/sys/fs/cgroup/memcordon-sealed",
    ] {
        let observed = match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                serde_json::json!({"path":path,"absent":true})
            }
            Err(error) => return Err(error.into()),
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
                    return Err(CiError::Message(
                        "request refusal allocation root custody differs".into(),
                    ));
                }
                let held = fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(path)?;
                let pinned = held.metadata()?;
                let mut children = fs::read_dir(path)?
                    .map(|entry| entry.map(|entry| entry.file_name()))
                    .collect::<std::io::Result<Vec<_>>>()?;
                if children.len() > 1024 {
                    return Err(CiError::Message(
                        "refusal native inventory exceeds bound".into(),
                    ));
                }
                children.sort();
                let after = fs::symlink_metadata(path)?;
                if (pinned.dev(), pinned.ino()) != (after.dev(), after.ino()) {
                    return Err(CiError::Message("native inventory root changed".into()));
                }
                serde_json::json!({"path":path,"device":pinned.dev(),"inode":pinned.ino(),"children":children})
            }
        };
        observations.push(observed);
    }
    Ok(serde_json::Value::Array(observations))
}

#[expect(
    clippy::too_many_arguments,
    reason = "Real request refusals retain selected source, native caller, lease and original cutoffs"
)]
pub fn run(
    mut input: CurrentLinuxInput<'_>,
    identity: &SourceIdentity,
    key: &ProductKey,
    lease_id: &str,
    artifact_root: &Path,
    fixture_source: &str,
    owner: &mut serde_json::Value,
    lifetime: &Path,
    inventory: &mut Vec<Artifact>,
) -> Result<Vec<CaseRecord>> {
    input.images = input.images.minimal();
    fs::create_dir(input.directory)?;
    fs::set_permissions(input.directory, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        input.directory,
        Some(rustix::process::Uid::from_raw(input.caller.uid)),
        Some(rustix::process::Gid::from_raw(input.caller.gid)),
    )
    .map_err(std::io::Error::from)?;
    let fixture = CallerRequestFixture::pack(
        input.caller,
        input.directory,
        CallerSnapshot {
            manifest: &input.images.runtime,
            manifest_path: &input.images.runtime_manifest,
            source_root: &input.images.runtime_source,
        },
        CallerSnapshot {
            manifest: &input.images.input,
            manifest_path: &input.images.input_manifest,
            source_root: &input.images.input_source,
        },
        LogicalId::new("owned-readiness".into()).map_err(CiError::Message)?,
        PrivateRootLayoutV1 {
            writable_roots: BoundedVec::default(),
            output_files: BoundedVec::default(),
        },
        BoundedVec::default(),
        input.work_cutoff,
    )?;
    let original = fs::read(&fixture.request)?;
    let cli = artifacts::read_file(&input.caller.installed_cli)?;
    let cli_hash = artifacts::checksum(&cli);
    let cli_path = retain_raw(
        artifact_root,
        &input.controller_directory.join("request-parser-cli.bin"),
        &cli,
        inventory,
    )?;
    let mut records = Vec::new();
    for (family, scenario) in [
        ("C-ADMISSION", "unsupported-profile"),
        ("C-ADMISSION", "malformed-request"),
        ("C-ADMISSION", "unsupported-format"),
        ("C-ADMISSION", "identity-override-rejected"),
        ("L-VER-01", "unknown-request-variant"),
        ("L-VER-01", "duplicate-request"),
        ("L-VER-01", "result-format-mismatch"),
        ("L-VER-01", "unsupported-provider-version"),
        ("L-VER-01", "corrupted-binding"),
    ] {
        let mut request: serde_json::Value = serde_json::from_slice(&original)?;
        let request = match scenario {
            "unsupported-profile" => {
                request["runtime"]["profile"] = "unsupported-profile".into();
                serde_json::to_vec(&request)?
            }
            "malformed-request" | "duplicate-request" => {
                br#"{"format":"memcordon.workload-request","revision":1,"revision":1}"#.to_vec()
            }
            "unsupported-format" => br#"{"format":"unsupported-request","revision":255}"#.to_vec(),
            "identity-override-rejected" => {
                request["runtime"]["uid"] = 0.into();
                serde_json::to_vec(&request)?
            }
            "unknown-request-variant" => {
                request["runtime"]["kind"] = "unsupported-runtime".into();
                serde_json::to_vec(&request)?
            }
            "result-format-mismatch" | "unsupported-provider-version" | "corrupted-binding" => {
                original.clone()
            }
            _ => unreachable!(),
        };
        let request_path = input.directory.join(format!("{scenario}.request.json"));
        let mut request_file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&request_path)?;
        use std::io::Write;
        request_file.write_all(&request)?;
        request_file.sync_all()?;
        let report = input.directory.join(format!("{scenario}.result.json"));
        let before = allocations()?;
        let mut process = None;
        let report_format = if scenario == "result-format-mismatch" {
            "standard"
        } else {
            "result-v3"
        };
        let command = input
            .caller
            .command(input.directory, input.work_cutoff)?
            .args([
                "+128MiB",
                "+10s",
                "--sealed",
                "--report-format",
                report_format,
                "--workload-request",
            ])
            .arg(&request_path)
            .arg("--workload-input")
            .arg(&fixture.bundle)
            .arg("--report")
            .arg(&report)
            .args(["--image-entrypoint", "owned-readiness"])
            .args(["--", "bytes-argv-status", "refusal-no-target", "0"]);
        let mut provider_fixture = if matches!(
            scenario,
            "unsupported-provider-version" | "corrupted-binding"
        ) {
            Some(super::linux_current_provider_state::begin(
                owner, lifetime, scenario,
            )?)
        } else {
            None
        };
        let observed=command.output_quiet_with_exec_observation(|child|{process=Some(serde_json::json!({"pid":child.id(),"birth":crate::linux_consumer_readiness::process_birth(child.id()).map_err(CiError::Message)?}));Ok(())});
        if provider_fixture.is_some() {
            super::linux_current_provider_state::restore(owner, lifetime)?;
            if let Some(fixture) = &mut provider_fixture {
                fixture["restored"] = owner["provider_fixture"]["restored"].clone();
                fixture["provider"] = serde_json::to_value(input.provider)?;
            }
        }
        let observed = observed?;
        let after = allocations()?;
        let report_absent = matches!(fs::symlink_metadata(&report),Err(error)if error.kind()==std::io::ErrorKind::NotFound);
        let case_key = CaseKey {
            target: key.target.clone(),
            channel: Some(key.channel.clone()),
            family: family.into(),
            scenario: scenario.into(),
            evidence_class: EvidenceClass::InstalledProduct,
        };
        let prefix = input.controller_directory.join(scenario);
        fs::create_dir(&prefix)?;
        let request_artifact = retain_raw(
            artifact_root,
            &prefix.join("request.json"),
            &request,
            inventory,
        )?;
        let stdout = retain_raw(
            artifact_root,
            &prefix.join("stdout.bin"),
            &observed.stdout,
            inventory,
        )?;
        let stderr = retain_raw(
            artifact_root,
            &prefix.join("stderr.bin"),
            &observed.stderr,
            inventory,
        )?;
        let mut receipt = serde_json::json!({"format":"memcordon.linux-current-request-refusal","revision":1,"run_id":identity.run_id,"lease_id":lease_id,"scenario":scenario,"process":process,"cli_sha256":cli_hash,"caller_uid":input.caller.uid,"caller_gid":input.caller.gid,"native_status":observed.status.code(),"raw_wait_status":observed.status.into_raw(),"report_absent":report_absent,"before":before,"after":after,"request":request_artifact});
        let raw_result = if provider_fixture.is_some() && !report_absent {
            Some(retain_raw(
                artifact_root,
                &prefix.join("result.json"),
                &artifacts::read_file(&report)?,
                inventory,
            )?)
        } else {
            None
        };
        if let Some(fixture) = provider_fixture {
            receipt["provider_fixture"] = fixture;
        }
        let receipt = retain(
            artifact_root,
            &prefix.join("native.json"),
            &serde_json::to_vec(&receipt)?,
            inventory,
        )?;
        let invocation = serde_json::json!({"format":"memcordon.linux-current-refusal-invocation","revision":1,"program":input.caller.installed_cli,"request":request_artifact,"bundle_sha256":artifacts::checksum(&artifacts::read_file(&fixture.bundle)?),"report":report,"memory":"+128MiB","deadline":"+10s","sealed":true,"report_format":report_format});
        let invocation = retain(
            artifact_root,
            &prefix.join("invocation.json"),
            &serde_json::to_vec(&invocation)?,
            inventory,
        )?;
        let case_input = serde_json::json!({"format":"memcordon.linux-current-refusal-input","revision":1,"run_id":identity.run_id,"key":case_key,"request":request_artifact,"caller_uid":input.caller.uid,"caller_gid":input.caller.gid});
        let case_input_path = retain(
            artifact_root,
            &prefix.join("input.json"),
            &serde_json::to_vec(&case_input)?,
            inventory,
        )?;
        let actual_input = fs::read(artifact_root.join(&case_input_path))?;
        let evidence = CaseEvidenceV2 {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 2,
            key: case_key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: Some(lease_id.into()),
            fixture: cli_path.clone(),
            fixture_source: fixture_source.into(),
            fixture_sha256: cli_hash.clone(),
            fixture_source_sha256: identity.source_tree_sha256.clone(),
            input: case_input_path,
            input_sha256: artifacts::checksum(&actual_input),
            invocation,
            request: Some(request_artifact),
            raw_result,
            attempt_observation: None,
            authenticated_terminal: None,
            recovery: None,
            stdout,
            stderr,
            outputs: Vec::new(),
            native_observation: receipt.clone(),
            retirement: receipt.clone(),
            semantic_observation: receipt,
            component_recipe_id: None,
        };
        memcordon_readiness_verifier::current::linux_refusals::verify_observed(
            &evidence,
            &case_input,
            &|path| fs::read(artifact_root.join(path)).map_err(|error| error.to_string()),
        )
        .map_err(CiError::Message)?;
        let case = retain(
            artifact_root,
            &prefix.join("case.json"),
            &serde_json::to_vec(&evidence)?,
            inventory,
        )?;
        records.push(CaseRecord {
            key: case_key,
            run_id: identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(case),
        });
    }
    Ok(records)
}
