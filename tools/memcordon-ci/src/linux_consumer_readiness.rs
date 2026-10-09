//! Collection of actual installed Linux driver products. This module supplies
//! persisted inputs to the independent verifier, never a readiness verdict.
#![cfg(target_os = "linux")]
use crate::consumer_readiness_ledger::SourceIdentity;
use memcordon_readiness_verifier::{Artifact, CaseKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

/// Preserve the two actual recovery recipes without assigning a successful
/// Rust-test count or exit code to the deliberately killed harness.
#[expect(
    clippy::type_complexity,
    reason = "Recovery normalization returns associated case records and their original artifact bytes together"
)]
pub fn normalize_native_recovery_harness(
    identity: &SourceIdentity,
    build: &memcordon_readiness_verifier::ComponentBuild,
    source_artifact: &Artifact,
    output: &Path,
    prefix: &str,
    bundle: &Path,
    fixture_acquisition: memcordon_readiness_verifier::ComponentFixtureAcquisition,
) -> Result<
    (
        Vec<memcordon_readiness_verifier::CaseRecord>,
        Vec<(Artifact, Vec<u8>)>,
    ),
    String,
> {
    use memcordon_readiness_verifier::*;
    let mut frozen = std::collections::BTreeMap::new();
    let mut total = 0usize;
    let entries = std::fs::read_dir(output).map_err(|error| error.to_string())?;
    for (ordinal, entry) in entries.enumerate() {
        if ordinal >= 128 {
            return Err("native recovery raw artifact count exceeds bound".into());
        }
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "native recovery artifact name is not UTF-8")?;
        if name.starts_with('.')
            || !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_file()
        {
            return Err("native recovery retains unresolved/nonregular artifact".into());
        }
        let remaining = (128 * 1024 * 1024usize)
            .checked_sub(total)
            .ok_or("native recovery aggregate capture overflow")?;
        let limit = remaining.min(16 * 1024 * 1024);
        if entry.metadata().map_err(|error| error.to_string())?.len() > limit as u64 {
            return Err("native recovery raw artifact exceeds remaining capture bound".into());
        }
        let bytes = measured(&entry.path(), limit as u64)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("native recovery raw size overflow")?;
        if total > 128 * 1024 * 1024 {
            return Err("native recovery aggregate raw capture exceeds bound".into());
        }
        frozen.insert(name, bytes);
    }
    let json = |name: &str| -> Result<serde_json::Value, String> {
        let bytes = frozen
            .get(name)
            .ok_or_else(|| format!("native recovery original artifact missing: {name}"))?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)
            .map_err(|error| error.to_string())?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    };
    let input = json("native-input.json")?;
    let spawn = json("native-spawn-intent.json")?;
    let boundary = json("account-boundary.json")?;
    let before = json("native-pre-input.json")?;
    let retired = json("native-retirement.json")?;
    let exit = json("native-exit.json")?;
    let test = spawn["test_name"]
        .as_str()
        .ok_or("native recovery actual test absent")?;
    let (scenario, recipe, crash) = match test {
        "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt" => (
            "crash-before-account-retirement",
            "account-retirement",
            true,
        ),
        "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt" => {
            ("lost-terminal-response", "lost-terminal", false)
        }
        _ => return Err("native recovery test is outside exact two-recipe scope".into()),
    };
    let base = format!("{}/candidate-native/components", build.target);
    if prefix != format!("{base}/{recipe}")
        || input["artifact_prefix"] != prefix
        || input["run_id"] != identity.run_id
        || input["recipe_id"] != build.recipe_id
        || input["native_target"] != build.target
        || boundary["run_id"] != identity.run_id
        || boundary["recipe_id"] != build.recipe_id
        || boundary["native_target"] != build.target
        || boundary["test_name"] != test
        || boundary["worker"]["pid"] != before["process_id"]
        || boundary["worker"]["start_time"] != before["birth"]
        || before["held_before_input_delivery"] != true
        || retired["held_before_input_delivery"] != true
        || retired["retirement_observed"] != true
        || retired["same_image_helpers_absent"] != true
        || before["process_id"] != retired["process_id"]
        || before["birth"] != retired["birth"]
        || exit["input_delivered"] != true
        || exit["capture_complete"] != true
        || build.source_commit != identity.source_commit
        || build.source_tree_sha256 != identity.source_tree_sha256
        || fixture_acquisition.checkpoint
            != format!("{base}/native-fixture/owned-resources-acquired.json")
        || fixture_acquisition.account_intent
            != format!("{base}/native-fixture/exclusive-account-intent.json")
        || fixture_acquisition.account_readback
            != format!("{base}/native-fixture/exclusive-account-getent.bin")
        || fixture_acquisition.group_readback
            != format!("{base}/native-fixture/exclusive-group-getent.bin")
    {
        return Err("native recovery original source/input/held role association differs".into());
    }
    let executable_bytes = measured(&bundle.join(&build.executable), 512 * 1024 * 1024)?;
    let executable_sha256 = hex::encode(Sha256::digest(executable_bytes));
    if source_artifact.length > 16 * 1024 * 1024 {
        return Err("native recovery selected source archive exceeds measured bound".into());
    }
    let source = measured(&bundle.join(&source_artifact.path), 16 * 1024 * 1024)?;
    if source.len() as u64 != source_artifact.length
        || hex::encode(Sha256::digest(&source)) != source_artifact.sha256
        || source_artifact.sha256 != identity.source_tree_sha256
        || before["image_sha256"] != executable_sha256
        || retired["image_sha256"] != executable_sha256
        || spawn["image_sha256"] != executable_sha256
        || spawn["environment_cleared"] != true
        || spawn["argv_bytes"]
            != serde_json::json!([
                b"--exact".to_vec(),
                test.as_bytes().to_vec(),
                b"--ignored".to_vec(),
                b"--test-threads=1".to_vec()
            ])
    {
        return Err("native recovery actual role/source/native argv differs".into());
    }
    let challenge: Vec<u8> =
        serde_json::from_value(input["challenge"].clone()).map_err(|error| error.to_string())?;
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || boundary["challenge_sha256"] != hex::encode(Sha256::digest(&challenge))
    {
        return Err("native recovery actual delivered challenge differs".into());
    }
    if crash {
        let crash_exit = json("native-crash-exit.json")?;
        let intent = json("native-crash-controller.json")?;
        if crash_exit["raw_wait_status"] != 9
            || crash_exit["native_signal"] != 9
            || !crash_exit["native_exit_code"].is_null()
            || crash_exit["worker_pid"] != before["process_id"]
            || crash_exit["worker_birth"] != before["birth"]
            || crash_exit["worker_pidfd_retirement_observed"] != true
            || intent["requested_signal"] != "SIGKILL"
            || intent["boundary_sha256"]
                != hex::encode(Sha256::digest(
                    frozen
                        .get("account-boundary.json")
                        .expect("parsed original boundary"),
                ))
        {
            return Err("native recovery crash does not preserve actual controller wait".into());
        }
    } else if exit["native_status"] != 0 {
        return Err("native lost-terminal harness did not complete".into());
    }
    let required = [
        "native-recovery-invocation.json",
        "native-recovery-capture.json",
        "native-recovery-process.json",
        "recovered-ownership.json",
        "account-ownership.json",
        "native-prepared.json",
        "boundary-journal.bin",
        "boundary-reference.json",
        "export-receipt.json",
        "stdout.bin",
        "stderr.bin",
    ];
    if required.iter().any(|name| !frozen.contains_key(*name)) {
        return Err("native recovery missing actual command/absence/capture".into());
    }
    for field in [
        "fixture",
        "current_contract",
        "actual_activation",
        "journal",
        "reference",
    ] {
        let original = boundary[field]
            .as_str()
            .ok_or_else(|| format!("native recovery boundary lacks original {field} path"))?;
        let name = original
            .strip_prefix(&format!("{prefix}/"))
            .ok_or("native recovery boundary artifact escapes recipe namespace")?;
        if name.is_empty() || name.contains('/') || !frozen.contains_key(name) {
            return Err(format!(
                "native recovery boundary original {field} artifact is absent"
            ));
        }
    }
    if !crash
        && [
            "lost-terminal-native-receipt.json",
            "completed-terminal-carrier.json",
            "terminal-request.json",
            "lost-terminal-helper-retirements.json",
        ]
        .iter()
        .any(|name| !frozen.contains_key(*name))
    {
        return Err(
            "native lost-terminal recovery omits original delivery/carrier/helper evidence".into(),
        );
    }
    let package_owner = format!("{base}/native-fixture/native-package-owner.json");
    measured(&bundle.join(&package_owner), 16 * 1024 * 1024)?;
    let path = |name: &str| format!("{prefix}/{name}");
    let recovery = if crash {
        LinuxRecoveryComponentEvidence::AccountRetirementCrash {
            input: path("native-input.json"),
            boundary: path("account-boundary.json"),
            ownership: path("account-ownership.json"),
            controller_intent: path("native-crash-controller.json"),
            crash_exit: path("native-crash-exit.json"),
            recovery_invocation: path("native-recovery-invocation.json"),
            recovery_capture: path("native-recovery-capture.json"),
            recovery_process: path("native-recovery-process.json"),
            package_owner,
            recovered_ownership: path("recovered-ownership.json"),
            fixture_acquisition,
        }
    } else {
        LinuxRecoveryComponentEvidence::LostTerminalResponse {
            input: path("native-input.json"),
            boundary: path("account-boundary.json"),
            ownership: path("account-ownership.json"),
            delivery_receipt: path("lost-terminal-native-receipt.json"),
            completed_carrier: path("completed-terminal-carrier.json"),
            terminal_request: path("terminal-request.json"),
            helper_retirements: path("lost-terminal-helper-retirements.json"),
            recovery_invocation: path("native-recovery-invocation.json"),
            recovery_capture: path("native-recovery-capture.json"),
            recovery_process: path("native-recovery-process.json"),
            package_owner,
            recovered_ownership: path("recovered-ownership.json"),
            fixture_acquisition,
        }
    };
    let key = CaseKey {
        target: build.target.clone(),
        channel: None,
        family: "L-LIFE-04".into(),
        scenario: scenario.into(),
        evidence_class: EvidenceClass::NativeComponentRegression,
    };
    let evidence = LinuxNativeRecoveryCaseEvidence {
        format: "memcordon.consumer-readiness.linux-native-recovery".into(),
        revision: 1,
        key: key.clone(),
        run_id: identity.run_id.clone(),
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        component_recipe_id: build.recipe_id.clone(),
        executable: build.executable.clone(),
        executable_sha256,
        source_artifact: source_artifact.path.clone(),
        source_artifact_sha256: source_artifact.sha256.clone(),
        invocation: path("native-spawn-intent.json"),
        native_preinput: path("native-pre-input.json"),
        native_retirement: path("native-retirement.json"),
        stdout: path("stdout.bin"),
        stderr: path("stderr.bin"),
        recovery,
    };
    // The original adapter publishes these exact bytes through its retained
    // confined directory owner. This projection performs no destination writes.
    let mut artifacts = Vec::new();
    for (name, bytes) in frozen {
        let relative = path(&name);
        artifacts.push((
            Artifact {
                path: relative,
                length: bytes.len() as u64,
                sha256: hex::encode(Sha256::digest(&bytes)),
            },
            bytes,
        ));
    }
    let relative = path("case-evidence.json");
    let bytes = serde_json::to_vec(&evidence).map_err(|error| error.to_string())?;
    artifacts.push((
        Artifact {
            path: relative.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        },
        bytes,
    ));
    Ok((
        vec![CaseRecord {
            key,
            run_id: identity.run_id.clone(),
            state: CaseState::Passed,
            reason: None,
            evidence: Some(relative),
        }],
        artifacts,
    ))
}

/// Converts a completed measured parser harness execution. Native ownership
/// remains with the caller; this function supplies data to the standalone gate.
pub fn normalize_native_harness(
    identity: &SourceIdentity,
    build: &memcordon_readiness_verifier::ComponentBuild,
    source_artifact: &Artifact,
    output: &Path,
    prefix: &str,
    bundle: &Path,
) -> Result<(Vec<memcordon_readiness_verifier::CaseRecord>, Vec<Artifact>), String> {
    normalize_native_harness_with_fixture(
        identity,
        build,
        source_artifact,
        output,
        prefix,
        bundle,
        None,
    )
}

pub fn normalize_native_harness_with_fixture(
    identity: &SourceIdentity,
    build: &memcordon_readiness_verifier::ComponentBuild,
    source_artifact: &Artifact,
    output: &Path,
    prefix: &str,
    bundle: &Path,
    fixture_acquisition: Option<memcordon_readiness_verifier::ComponentFixtureAcquisition>,
) -> Result<(Vec<memcordon_readiness_verifier::CaseRecord>, Vec<Artifact>), String> {
    use memcordon_readiness_verifier::*;
    use std::os::unix::ffi::OsStrExt;
    if prefix.is_empty()
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || prefix.contains(['\\', ':'])
    {
        return Err("native harness artifact prefix is not confined".into());
    }
    let json = |name: &str| -> Result<serde_json::Value, String> {
        let bytes = measured(&output.join(name), 16 * 1024 * 1024)?;
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
            .map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    };
    let spawn = json("native-spawn-intent.json")?;
    let receipt_name = if spawn["test_name"]
        == "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts"
    {
        "filter-native-receipt.json"
    } else if spawn["test_name"]
        == "private_attempt::durable_journal_barriers_emit_actual_component_receipts"
    {
        "journal-native-receipt.json"
    } else if spawn["test_name"]
        == "native_mixed_release::native_leased_release_emit_actual_component_receipt"
    {
        "release-native-receipt.json"
    } else {
        "native-receipt.json"
    };
    let receipt = json(receipt_name)?;
    let request = json("native-input.json")?;
    let before = json("native-pre-input.json")?;
    let retired = json("native-retirement.json")?;
    let exit = json("native-exit.json")?;
    let test = receipt["test_name"]
        .as_str()
        .ok_or("native parser actual test name absent")?;
    let release =
        test == "native_mixed_release::native_leased_release_emit_actual_component_receipt";
    if release != fixture_acquisition.is_some() {
        return Err(
            "native fixture acquisition applicability differs from actual release recipe".into(),
        );
    }
    let scenarios: &[&str] = match test {
        "native_index_mutations_emit_actual_parser_receipts" => {
            &["omitted-case", "duplicate-case", "wrong-product"]
        }
        "operational_parser_receipts::native_operational_parser_mutations_emit_actual_receipts" => {
            &[
                "duplicate-key",
                "wrong-format",
                "wrong-revision",
                "unknown-authority-variant",
                "oversized-record",
                "stale-attempt",
                "forged-cleanup",
            ]
        }
        "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts" => {
            &["filter-x64", "filter-arm64"]
        }
        "private_attempt::durable_journal_barriers_emit_actual_component_receipts" => {
            &["journal-barrier"]
        }
        "native_versions::native_version_vectors_emit_actual_component_receipts" => &[
            "v1-vectors",
            "v2-vectors",
            "v3-vectors",
            "projection-mutation",
        ],
        "native_mixed_release::native_leased_release_emit_actual_component_receipt" => {
            &["release-barrier"]
        }
        _ => return Err("native harness has no declared producer parser crosswalk".into()),
    };
    let operational = test
        == "native_private_tcp::mixed_filter_vectors_emit_actual_component_receipts"
        || test == "private_attempt::durable_journal_barriers_emit_actual_component_receipts"
        || test == "native_versions::native_version_vectors_emit_actual_component_receipts"
        || test == "native_mixed_release::native_leased_release_emit_actual_component_receipt";
    let executable = if operational {
        &build.executable
    } else {
        build
            .parser_executable
            .as_ref()
            .ok_or("measured parser role absent")?
    };
    let executable_bytes = measured(&bundle.join(executable), 512 * 1024 * 1024)?;
    let executable_sha = hex::encode(Sha256::digest(executable_bytes));
    let source = measured(&bundle.join(&source_artifact.path), 16 * 1024 * 1024)?;
    if source.len() as u64 != source_artifact.length
        || hex::encode(Sha256::digest(&source)) != source_artifact.sha256
        || source_artifact.sha256 != identity.source_tree_sha256
        || build.source_commit != identity.source_commit
        || build.source_tree_sha256 != identity.source_tree_sha256
        || receipt["run_id"] != identity.run_id
        || receipt["native_target"] != build.target
        || receipt["recipe_id"] != build.recipe_id
        || receipt["executable_sha256"] != executable_sha
        || before["image_sha256"] != executable_sha
        || retired["image_sha256"] != executable_sha
        || before["held_before_input_delivery"] != true
        || retired["held_before_input_delivery"] != true
        || retired["retirement_observed"] != true
        || retired["same_image_helpers_absent"] != true
        || before["process_id"] != retired["process_id"]
        || before["birth"] != retired["birth"]
        || exit["native_status"] != 0
        || exit["input_delivered"] != true
        || exit["capture_complete"] != true
        || request["artifact_prefix"] != prefix
        || request["run_id"] != identity.run_id
        || request["recipe_id"] != build.recipe_id
        || request["native_target"] != build.target
    {
        return Err(
            "completed native parser source/input/held execution association differs".into(),
        );
    }
    let challenge: Vec<u8> =
        serde_json::from_value(request["challenge"].clone()).map_err(|error| error.to_string())?;
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || receipt["challenge_sha256"] != hex::encode(Sha256::digest(&challenge))
    {
        return Err("native parser challenge association differs".into());
    }
    let stdout = measured(&output.join("stdout.bin"), 16 * 1024 * 1024)?;
    let text = std::str::from_utf8(&stdout).map_err(|_| "native parser output not UTF-8")?;
    let successful = format!("test {test} ... ok");
    if text
        .lines()
        .filter(|line| *line == "running 1 test")
        .count()
        != 1
        || text.lines().filter(|line| *line == successful).count() != 1
        || text
            .lines()
            .filter(|line| {
                line.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
            })
            .count()
            != 1
        || text
            .lines()
            .filter(|line| line.starts_with("running "))
            .count()
            != 1
        || text
            .lines()
            .filter(|line| line.starts_with("test result:"))
            .count()
            != 1
        || text
            .lines()
            .filter(|line| line.starts_with("test ") && !line.starts_with("test result:"))
            .count()
            != 1
    {
        return Err("native parser actual selected harness execution differs".into());
    }
    let mut artifacts = Vec::new();
    std::fs::create_dir_all(bundle.join(prefix)).map_err(|error| error.to_string())?;
    let mut entries = std::fs::read_dir(output)
        .map_err(|error| error.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| error.to_string())?;
    entries.sort_by_key(|entry| entry.file_name());
    if entries.len() > 128 {
        return Err("native parser artifact table exceeds bound".into());
    }
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "native parser artifact name not UTF-8")?;
        if name.starts_with('.')
            || !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_file()
        {
            return Err("native parser retained output has unresolved/nonregular member".into());
        }
        let bytes = measured(&entry.path(), 16 * 1024 * 1024)?;
        let path = format!("{prefix}/{name}");
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(bundle.join(&path))
            .map_err(|error| error.to_string())?;
        destination
            .write_all(&bytes)
            .map_err(|error| error.to_string())?;
        destination.sync_all().map_err(|error| error.to_string())?;
        if measured(&bundle.join(&path), 16 * 1024 * 1024)? != bytes {
            return Err("native parser copied raw artifact readback differs".into());
        }
        artifacts.push(Artifact {
            path,
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
    }
    let mut persist = |name: &str, bytes: &[u8]| -> Result<String, String> {
        let path = format!("{prefix}/{name}");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(bundle.join(&path))
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        artifacts.push(Artifact {
            path: path.clone(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
        Ok(path)
    };
    let challenge_path = persist("controller-challenge.bin", &challenge)?;
    let environment = serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new()))
        .map_err(|error| error.to_string())?;
    let environment_path = persist("controller-environment.json", &environment)?;
    let argv: Vec<Vec<u8>> =
        serde_json::from_value(spawn["argv_bytes"].clone()).map_err(|error| error.to_string())?;
    if spawn["environment_cleared"] != true
        || spawn["image_sha256"] != executable_sha
        || spawn["test_name"] != test
        || argv
            != vec![
                b"--exact".to_vec(),
                test.as_bytes().to_vec(),
                b"--ignored".to_vec(),
                b"--test-threads=1".to_vec(),
            ]
    {
        return Err("native parser actual invocation differs".into());
    }
    let public = memcordon_core::InvocationReport {
        syntax: "plus-budgets-v1".into(),
        budget_tokens: Vec::new(),
        memory_token: None,
        deadline_token: None,
        argv: argv
            .iter()
            .map(|bytes| {
                memcordon_core::NativeArgument::from_os(std::ffi::OsStr::from_bytes(bytes))
            })
            .collect(),
    };
    let association = hex::encode(Sha256::digest(
        serde_json::to_vec(&public).map_err(|error| error.to_string())?,
    ));
    let invocation = NativeInvocation {
        format: "memcordon.consumer-readiness.invocation".into(),
        revision: 1,
        arguments: NativeArguments::UnixBytes(argv.clone()),
        executable_sha256: executable_sha.clone(),
        environment: environment_path,
        environment_sha256: hex::encode(Sha256::digest(environment)),
        association_sha256: association.clone(),
        budget_tokens: Vec::new(),
        memory_token: None,
        deadline_token: None,
    };
    let invocation_path = persist(
        "controller-invocation.json",
        &serde_json::to_vec(&invocation).map_err(|error| error.to_string())?,
    )?;
    let pid = u32::try_from(
        before["process_id"]
            .as_u64()
            .ok_or("held parser PID absent")?,
    )
    .map_err(|error| error.to_string())?;
    if pid == 0 {
        return Err("held native harness PID is zero".into());
    }
    let birth = before["birth"]
        .as_u64()
        .filter(|birth| *birth > 0)
        .ok_or("held parser birth absent")?;
    let native = NativeObservation {
        format: "memcordon.consumer-readiness.native".into(),
        revision: 1,
        run_id: identity.run_id.clone(),
        lease_id: None,
        target: build.target.clone(),
        executable_sha256: executable_sha.clone(),
        invocation_sha256: association,
        execution_invocation_sha256: None,
        request_sha256: None,
        provider_sha256: None,
        provider_generation: None,
        runtime_manifest_sha256: None,
        attempt_id: None,
        root_pid: Some(pid),
        root_birth: Some(birth),
        attempt_nonce: None,
        held_processes: Vec::new(),
        frontend_status: 0,
        origin: OutcomeOrigin::ComponentRegression,
        target_status: None,
        authenticated_provider_exchange: false,
        relay_complete: true,
        result_named_identity_verified: true,
        result_readback_verified: true,
        application_stage: None,
    };
    let native_path = persist(
        "controller-native.json",
        &serde_json::to_vec(&native).map_err(|error| error.to_string())?,
    )?;
    let retirement = RetirementObservation {
        format: "memcordon.consumer-readiness.retirement".into(),
        revision: 1,
        run_id: identity.run_id.clone(),
        attempt_id: None,
        root_pid: Some(pid),
        root_birth: Some(birth),
        target_reaped_or_absent: true,
        aggregate_empty: true,
        relays_retired: true,
        guardian_retired: false,
        native_handles_closed: false,
        independently_observed: true,
        namespace_init_reaped: None,
        private_root_closed: None,
        exports_finalized: None,
        account_reservation_retired: None,
        final_job_handles_closed: None,
        active_processes_zero: None,
        outstanding: Vec::new(),
        failed_operations: Vec::new(),
    };
    let retirement_path = persist(
        "controller-retirement.json",
        &serde_json::to_vec(&retirement).map_err(|error| error.to_string())?,
    )?;
    let mut records = Vec::new();
    for scenario in scenarios {
        let key = CaseKey {
            target: build.target.clone(),
            channel: None,
            evidence_class: EvidenceClass::NativeComponentRegression,
            family: if operational { "L-VER-01" } else { "C-PARSER" }.into(),
            scenario: (*scenario).into(),
        };
        let input = FixtureInput {
            format: "memcordon.consumer-readiness.input".into(),
            revision: 1,
            run_id: identity.run_id.clone(),
            key: key.clone(),
            challenge_sha256: hex::encode(Sha256::digest(&challenge)),
            binary: Vec::new(),
            target_argv: NativeArguments::UnixBytes(argv.clone()),
            deadline_millis: None,
            memory_bytes: None,
            toolchain_identity: None,
        };
        let input_bytes = serde_json::to_vec(&input).map_err(|error| error.to_string())?;
        let input_path = persist(&format!("{scenario}-input.json"), &input_bytes)?;
        let semantic = SemanticObservation {
            format: "memcordon.consumer-readiness.semantic".into(),
            revision: 1,
            run_id: identity.run_id.clone(),
            key: key.clone(),
            challenge: challenge_path.clone(),
            operations: Vec::new(),
            comparisons: Vec::new(),
            counters: Default::default(),
            negative_probe: None,
            component_test: Some(ComponentTest {
                recipe_id: build.recipe_id.clone(),
                test_name: test.into(),
                native_exit: 0,
                tests_executed: 1,
                tests_failed: 0,
                tests_ignored: 0,
                raw_test_output: format!("{prefix}/stdout.bin"),
                native_receipt: format!("{prefix}/{receipt_name}"),
                native_retirement: Some(format!("{prefix}/native-retirement.json")),
                fixture_acquisition: fixture_acquisition.clone(),
            }),
            component_actors: None,
            windows_capacity: None,
            windows_refusal: None,
            fixture_behavior: None,
        };
        let semantic_path = persist(
            &format!("{scenario}-semantic.json"),
            &serde_json::to_vec(&semantic).map_err(|error| error.to_string())?,
        )?;
        let evidence = CaseEvidence {
            format: "memcordon.consumer-readiness.case".into(),
            revision: 1,
            key: key.clone(),
            run_id: identity.run_id.clone(),
            source_commit: identity.source_commit.clone(),
            source_tree_sha256: identity.source_tree_sha256.clone(),
            lease_id: None,
            fixture: executable.clone(),
            fixture_source: source_artifact.path.clone(),
            fixture_sha256: executable_sha.clone(),
            fixture_source_sha256: source_artifact.sha256.clone(),
            input: input_path,
            input_sha256: hex::encode(Sha256::digest(input_bytes)),
            invocation: invocation_path.clone(),
            request: None,
            raw_result: None,
            provider_request: None,
            authenticated_terminal: None,
            windows_loss: None,
            execution_invocation: None,
            execution_environment: None,
            transcript: None,
            inventory: None,
            qualification: None,
            export_receipt: None,
            prepared_observation: None,
            prepared_native_receipt: None,
            native_observation: native_path.clone(),
            retirement: retirement_path.clone(),
            semantic_observation: semantic_path,
            component_recipe_id: Some(build.recipe_id.clone()),
        };
        let evidence_path = persist(
            &format!("{scenario}-case.json"),
            &serde_json::to_vec(&evidence).map_err(|error| error.to_string())?,
        )?;
        records.push(CaseRecord {
            key,
            state: CaseState::Passed,
            run_id: identity.run_id.clone(),
            evidence: Some(evidence_path),
            reason: None,
        });
    }
    File::open(bundle.join(prefix))
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())?;
    Ok((records, artifacts))
}

/// Native observation owner. Only acquisition before fixture release can
/// establish a hold; parsing a terminal report never constructs this value.
pub struct HeldLinuxProcess {
    pub process_id: u32,
    pub birth: u64,
    pidfd: std::os::fd::OwnedFd,
    observed_parent: Option<(u32, u64)>,
    pub namespace_pid: Option<u32>,
    observed_images: Vec<File>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxNativeNamespace {
    pub device: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxHeldSnapshot {
    pub process_id: u32,
    pub birth: u64,
    pub namespace_pids: Vec<u32>,
    pub user: LinuxNativeNamespace,
    pub mount: LinuxNativeNamespace,
    pub pid: LinuxNativeNamespace,
    pub network: LinuxNativeNamespace,
    pub ipc: LinuxNativeNamespace,
}

pub struct PreparedLinuxObserver {
    pub observation: memcordon_core::mixed_observation::MixedPreparedObservationV2,
    pub target: HeldLinuxProcess,
    pub namespace_init: HeldLinuxProcess,
    pub guardian: HeldLinuxProcess,
    pub caller: HeldLinuxProcess,
    pub persisted_observation: Artifact,
    captured_target: LinuxHeldSnapshot,
    captured_init: LinuxHeldSnapshot,
    captured_guardian: LinuxHeldSnapshot,
    captured_caller: LinuxHeldSnapshot,
    cgroup: File,
}

impl PreparedLinuxObserver {
    /// Duplicates the native cgroup owner while the authenticated prepared
    /// family remains held. This grants no release authority.
    pub fn retain_cgroup_descriptor(&self) -> Result<File, String> {
        use std::os::unix::fs::MetadataExt;
        if self.target.exited()? || self.namespace_init.exited()? || self.guardian.exited()? {
            return Err("prepared native family exited before cgroup descriptor retention".into());
        }
        let before = self.cgroup.metadata().map_err(|e| e.to_string())?;
        if !before.is_dir() || before.nlink() == 0 {
            return Err("prepared native cgroup already removed".into());
        }
        let retained = self.cgroup.try_clone().map_err(|e| e.to_string())?;
        let after = retained.metadata().map_err(|e| e.to_string())?;
        if (before.dev(), before.ino(), before.nlink()) != (after.dev(), after.ino(), after.nlink())
            || self.target.exited()?
            || self.namespace_init.exited()?
            || self.guardian.exited()?
        {
            return Err("prepared native cgroup changed during descriptor retention".into());
        }
        Ok(retained)
    }
    pub fn acquire_named(
        directory: &Path,
        provider: &memcordon_core::PublicProviderBindingV1,
        request: &memcordon_core::workload_contract_v3::WorkloadContractV3,
        attempt: &str,
        destination: &Path,
        relative: &str,
    ) -> Result<Self, String> {
        if attempt.len() != 32 || !attempt.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("mixed observer attempt path malformed".into());
        }
        let path = directory.join(attempt).with_extension("prepared.json");
        let bytes = measured(&path, 1024 * 1024)?;
        Self::acquire(&bytes, provider, request, attempt, destination, relative)
    }

    /// Publishes only an observation barrier after real native acquisition.
    /// The provider's retained policy lease remains the release authority.
    pub fn acknowledge(&self, directory: &Path) -> Result<(), String> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if self.target.exited()? || self.namespace_init.exited()? || self.guardian.exited()? {
            return Err("prepared native family exited before observer acknowledgment".into());
        }
        let observer_pid = std::process::id();
        let acknowledgment = memcordon_core::mixed_observation::MixedObserverAcknowledgmentV2 {
            format: "memcordon.mixed-observer-acknowledgment".into(),
            revision: 2,
            attempt_id: self.observation.admission.attempt_id.clone(),
            admission_nonce: self.observation.admission.admission_nonce,
            target: self.observation.target.clone(),
            observer: memcordon_core::result_v2::NativeProcessV2 {
                pid: observer_pid,
                birth: process_birth(observer_pid)?,
            },
        };
        let output = directory
            .join(acknowledgment.attempt_id.as_str())
            .with_extension("observer-ack.json");
        let mut bytes = serde_json::to_vec(&acknowledgment).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&output)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        let owner = std::fs::symlink_metadata(directory).map_err(|e| e.to_string())?;
        if !owner.is_dir()
            || owner.uid() != self.observation.admission.caller_uid
            || owner.mode() & 0o022 != 0
        {
            return Err(
                "observer directory does not belong to authenticated frontend caller".into(),
            );
        }
        rustix::fs::fchown(
            &file,
            Some(rustix::process::Uid::from_raw(owner.uid())),
            None,
        )
        .map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        if measured(&output, 64 * 1024)? != bytes {
            return Err("observer ACK named custody differs".into());
        }
        File::open(directory)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Caller supplies bytes received through the authenticated mixed frame,
    /// before sending its observation barrier acknowledgment.
    pub fn acquire(
        bytes: &[u8],
        provider: &memcordon_core::PublicProviderBindingV1,
        request: &memcordon_core::workload_contract_v3::WorkloadContractV3,
        attempt: &str,
        destination: &Path,
        relative: &str,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        if bytes.len() > 1024 * 1024
            || relative.is_empty()
            || relative.contains(['\\', ':', '\0'])
            || relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("prepared observation exceeds owned custody".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let observation: memcordon_core::mixed_observation::MixedPreparedObservationV2 =
            serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        observation.validate()?;
        if &observation.provider != provider
            || &observation.admission.request != request
            || observation.admission.attempt_id.as_str() != attempt
        {
            return Err(
                "prepared observation differs from selected provider/request/attempt".into(),
            );
        }
        let identities: std::collections::BTreeSet<_> = [
            &observation.caller,
            &observation.target,
            &observation.namespace_init,
            &observation.guardian,
        ]
        .iter()
        .map(|process| (process.pid, process.birth))
        .collect();
        if identities.len() != 4 {
            return Err("prepared process owners alias native identities".into());
        }
        let target = HeldLinuxProcess::acquire(observation.target.pid, observation.target.birth)?;
        let membership = std::fs::read_to_string(
            Path::new("/proc")
                .join(target.process_id.to_string())
                .join("cgroup"),
        )
        .map_err(|e| e.to_string())?;
        let rows = membership.lines().collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("prepared native target is not in one unified cgroup membership".into());
        }
        let member = rows[0]
            .strip_prefix("0::/")
            .ok_or("prepared native target has no unified cgroup path")?;
        if member.is_empty()
            || member
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("prepared native cgroup path malformed/root".into());
        }
        let mut cgroup = File::open("/sys/fs/cgroup").map_err(|e| e.to_string())?;
        for component in member.split('/') {
            let next = rustix::fs::openat(
                &cgroup,
                component,
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::DIRECTORY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            cgroup = File::from(next);
        }
        let namespace_init = HeldLinuxProcess::acquire(
            observation.namespace_init.pid,
            observation.namespace_init.birth,
        )?;
        let guardian =
            HeldLinuxProcess::acquire(observation.guardian.pid, observation.guardian.birth)?;
        let caller = HeldLinuxProcess::acquire(observation.caller.pid, observation.caller.birth)?;
        let actual = target.live_snapshot()?;
        for (native, reported) in [
            (&actual.user, &observation.user_namespace),
            (&actual.mount, &observation.mount_namespace),
            (&actual.pid, &observation.pid_namespace),
            (&actual.network, &observation.network_namespace),
            (&actual.ipc, &observation.ipc_namespace),
        ] {
            if (native.device, native.inode) != (reported.device, reported.inode) {
                return Err(
                    "prepared target native namespace differs from authenticated observation"
                        .into(),
                );
            }
        }
        let init = namespace_init.live_snapshot()?;
        let caller_snapshot = caller.live_snapshot()?;
        let guardian_snapshot = guardian.live_snapshot()?;
        for (target, init) in [
            (&actual.user, &init.user),
            (&actual.mount, &init.mount),
            (&actual.pid, &init.pid),
            (&actual.network, &init.network),
            (&actual.ipc, &init.ipc),
        ] {
            if (target.device, target.inode) != (init.device, init.inode) {
                return Err(
                    "target and held namespace init occupy different native namespaces".into(),
                );
            }
        }
        for (target, caller, shared) in [
            (&actual.user, &caller_snapshot.user, true),
            (&actual.mount, &caller_snapshot.mount, false),
            (&actual.pid, &caller_snapshot.pid, false),
            (&actual.network, &caller_snapshot.network, false),
            (&actual.ipc, &caller_snapshot.ipc, false),
        ] {
            if ((target.device, target.inode) == (caller.device, caller.inode)) != shared {
                return Err("prepared actual namespace separation differs".into());
            }
        }
        let root = std::fs::metadata(
            Path::new("/proc")
                .join(target.process_id.to_string())
                .join("root"),
        )
        .map_err(|e| e.to_string())?;
        if (root.dev(), root.ino()) != (observation.root_device, observation.root_inode)
            || target.exited()?
            || namespace_init.exited()?
            || guardian.exited()?
            || caller.exited()?
        {
            return Err("prepared held native root changed/exited during capture".into());
        }
        let output = destination.join(relative);
        std::fs::create_dir_all(output.parent().ok_or("observation parent absent")?)
            .map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|e| e.to_string())?;
        file.write_all(bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        File::open(output.parent().ok_or("observation parent absent")?)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        let persisted_observation = Artifact {
            path: relative.into(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        Ok(Self {
            observation,
            target,
            namespace_init,
            guardian,
            caller,
            persisted_observation,
            captured_target: actual,
            captured_init: init,
            captured_guardian: guardian_snapshot,
            captured_caller: caller_snapshot,
            cgroup,
        })
    }

    pub fn persist_native_receipt(
        &self,
        run_id: &str,
        destination: &Path,
        relative: &str,
    ) -> Result<Artifact, String> {
        if relative.is_empty()
            || relative.contains(['\\', ':', '\0'])
            || relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("unsafe native observer receipt path".into());
        }
        let observer_pid = std::process::id();
        let receipt = serde_json::json!({"format":"memcordon.linux-prepared-native-observation","revision":1,"run_id":run_id,
            "attempt_id":self.observation.admission.attempt_id,"prepared_sha256":self.persisted_observation.sha256,
            "observer":{"pid":observer_pid,"birth":process_birth(observer_pid)?},"held_before_authorization":true,
            "target":self.captured_target,"namespace_init":self.captured_init,"guardian":self.captured_guardian,"caller":self.captured_caller,
            "root_device":self.observation.root_device,"root_inode":self.observation.root_inode});
        let mut bytes = serde_json::to_vec(&receipt).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        let output = destination.join(relative);
        std::fs::create_dir_all(output.parent().ok_or("receipt parent absent")?)
            .map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        File::open(output.parent().ok_or("receipt parent absent")?)
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
        Ok(Artifact {
            path: relative.into(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        })
    }

    pub fn native_family_retired(&self, descendants: &[HeldLinuxProcess]) -> Result<bool, String> {
        use std::os::unix::fs::MetadataExt;
        if !self.target.exited()? || !self.namespace_init.exited()? || !self.guardian.exited()? {
            return Ok(false);
        }
        for child in descendants {
            if !child.exited()? {
                return Ok(false);
            }
        }
        // Kernel removal of this held cgroup inode requires it to be empty;
        // otherwise read current populated state through that exact owner.
        if self.cgroup.metadata().map_err(|e| e.to_string())?.nlink() != 0 {
            let events = rustix::fs::openat(
                &self.cgroup,
                "cgroup.events",
                rustix::fs::OFlags::RDONLY
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            )
            .map_err(|e| e.to_string())?;
            let mut text = String::new();
            File::from(events)
                .take(4097)
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            if text.len() > 4096
                || text
                    .lines()
                    .filter(|line| line.starts_with("populated "))
                    .collect::<Vec<_>>()
                    != ["populated 0"]
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

pub(crate) fn process_birth(pid: u32) -> Result<u64, String> {
    let bytes = std::fs::read_to_string(Path::new("/proc").join(pid.to_string()).join("stat"))
        .map_err(|e| e.to_string())?;
    bytes
        .rsplit_once(')')
        .ok_or("native process stat malformed")?
        .1
        .split_whitespace()
        .nth(19)
        .ok_or("native birth missing")?
        .parse()
        .map_err(|e: std::num::ParseIntError| e.to_string())
}

impl HeldLinuxProcess {
    /// The outer result describes ownership/liveness checks; the inner result
    /// preserves the actual PIDFD syscall outcome and native errno.
    pub fn signal_interrupt(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::INT)
    }
    pub fn signal_stop(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::STOP)
    }
    pub fn signal_continue(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::CONT)
    }
    pub fn signal_kill(&self) -> Result<Result<(), i32>, String> {
        self.signal_held(rustix::process::Signal::KILL)
    }
    fn signal_held(&self, signal: rustix::process::Signal) -> Result<Result<(), i32>, String> {
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("held process is no longer live at native signal boundary".into());
        }
        Ok(rustix::process::pidfd_send_signal(&self.pidfd, signal)
            .map_err(|error| error.raw_os_error()))
    }
    /// Reads the native kernel TCP table and actual root descriptor ownership
    /// while the same PIDFD and birth remain live on both sides of observation.
    pub fn observe_loopback_listeners(
        &self,
        endpoints: [std::net::SocketAddrV4; 2],
    ) -> Result<serde_json::Value, String> {
        use std::collections::BTreeSet;
        let before = self.live_snapshot()?;
        if endpoints[0] == endpoints[1]
            || endpoints
                .iter()
                .any(|endpoint| !endpoint.ip().is_loopback() || endpoint.port() == 0)
        {
            return Err(
                "native endpoint observation requires two distinct owned loopback listeners".into(),
            );
        }
        let base = Path::new("/proc").join(self.process_id.to_string());
        let observe = || -> Result<[u64; 2], String> {
            let mut descriptors = BTreeSet::new();
            let mut count = 0usize;
            for entry in std::fs::read_dir(base.join("fd")).map_err(|error| error.to_string())? {
                count += 1;
                if count > 4096 {
                    return Err("native endpoint root descriptor table exceeds bound".into());
                }
                let path = entry.map_err(|error| error.to_string())?.path();
                let link = std::fs::read_link(path).map_err(|error| error.to_string())?;
                if let Some(text) = link
                    .to_str()
                    .and_then(|text| text.strip_prefix("socket:["))
                    .and_then(|text| text.strip_suffix(']'))
                {
                    descriptors.insert(text.parse::<u64>().map_err(|error| error.to_string())?);
                }
            }
            let mut bytes = Vec::new();
            File::open(base.join("net/tcp"))
                .map_err(|error| error.to_string())?
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| error.to_string())?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err("native TCP table exceeds bound".into());
            }
            let table = std::str::from_utf8(&bytes).map_err(|_| "native TCP table is not ASCII")?;
            let mut observed = [0u64; 2];
            for line in table.lines().skip(1) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() < 10 {
                    return Err("native TCP row is malformed".into());
                }
                if fields[3] != "0A" {
                    continue;
                }
                for (ordinal, endpoint) in endpoints.iter().enumerate() {
                    let local = format!(
                        "{:08X}:{:04X}",
                        u32::from_le_bytes(endpoint.ip().octets()),
                        endpoint.port()
                    );
                    if fields[1] != local {
                        continue;
                    }
                    let inode = fields[9]
                        .parse::<u64>()
                        .map_err(|error| error.to_string())?;
                    if inode == 0 || !descriptors.contains(&inode) || observed[ordinal] != 0 {
                        return Err(
                            "native listener is absent from exact held root or duplicated".into(),
                        );
                    }
                    observed[ordinal] = inode;
                }
            }
            if observed.contains(&0) || observed[0] == observed[1] {
                return Err("two native retained listener identities absent or aliased".into());
            }
            Ok(observed)
        };
        let first = observe()?;
        let second = observe()?;
        let after = self.live_snapshot()?;
        if first != second
            || before.network.device != after.network.device
            || before.network.inode != after.network.inode
        {
            return Err("native listener or held root namespace changed during observation".into());
        }
        Ok(
            serde_json::json!({"format":"memcordon.linux-native-endpoint-mismatch","revision":1,
            "process_id":self.process_id,"birth":self.birth,"network":before.network,
            "listeners":endpoints.iter().zip(first).map(|(endpoint,inode)|serde_json::json!({"endpoint":endpoint.to_string(),"socket_inode":inode})).collect::<Vec<_>>(),
            "root_held_live_before_and_after":true,"kernel_listen_and_root_descriptor_observed_twice":true}),
        )
    }
    /// Reads the native parent while this exact child and expected parent are
    /// both held live. Namespace-local transcript ancestry never substitutes
    /// for this host identity join.
    pub fn verify_parent(&mut self, parent: &Self) -> Result<(), String> {
        if self.exited()?
            || parent.exited()?
            || process_birth(self.process_id)? != self.birth
            || process_birth(parent.process_id)? != parent.birth
        {
            return Err("native ancestry owner no longer held live".into());
        }
        let stat = std::fs::read_to_string(
            Path::new("/proc")
                .join(self.process_id.to_string())
                .join("stat"),
        )
        .map_err(|e| e.to_string())?;
        let fields = stat
            .rsplit_once(')')
            .ok_or("native child stat malformed")?
            .1
            .split_whitespace()
            .collect::<Vec<_>>();
        let parent_pid = fields
            .get(1)
            .ok_or("native parent PID absent")?
            .parse::<u32>()
            .map_err(|e| e.to_string())?;
        if parent_pid != parent.process_id
            || parent.birth > self.birth
            || self.exited()?
            || parent.exited()?
            || process_birth(self.process_id)? != self.birth
            || process_birth(parent.process_id)? != parent.birth
        {
            return Err("native held parent/creation-time association differs".into());
        }
        self.observed_parent = Some((parent.process_id, parent.birth));
        Ok(())
    }

    pub fn retirement_identity(
        &self,
    ) -> Result<memcordon_readiness_verifier::HeldProcessIdentity, String> {
        Ok(memcordon_readiness_verifier::HeldProcessIdentity {
            pid: self.process_id,
            birth: self.birth,
            parent_pid: self.observed_parent.map(|parent| parent.0),
            parent_birth: self.observed_parent.map(|parent| parent.1),
            retirement_observed: self.exited()?,
        })
    }
    pub fn acquire(process_id: u32, expected_birth: u64) -> Result<Self, String> {
        if process_id == 0 || expected_birth == 0 || process_birth(process_id)? != expected_birth {
            return Err("live native process birth differs".into());
        }
        let pid =
            rustix::process::Pid::from_raw(i32::try_from(process_id).map_err(|e| e.to_string())?)
                .ok_or("native PID absent")?;
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())
            .map_err(|e| e.to_string())?;
        let value = Self {
            process_id,
            birth: expected_birth,
            pidfd,
            observed_parent: None,
            namespace_pid: None,
            observed_images: Vec::new(),
        };
        if value.exited()? || process_birth(process_id)? != expected_birth {
            return Err("native process changed/exited during hold acquisition".into());
        }
        Ok(value)
    }

    pub fn exited(&self) -> Result<bool, String> {
        use rustix::event::{PollFd, PollFlags};
        let mut descriptors = [PollFd::new(&self.pidfd, PollFlags::IN)];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let status =
            rustix::event::poll(&mut descriptors, Some(&timeout)).map_err(|e| e.to_string())?;
        let events = descriptors[0].revents();
        if events.intersects(PollFlags::NVAL | PollFlags::ERR) {
            return Err("native process descriptor poll failed".into());
        }
        Ok(status != 0 && events.intersects(PollFlags::IN | PollFlags::HUP))
    }

    pub fn hold_executable_image(
        &mut self,
        deadline: std::time::Instant,
    ) -> Result<serde_json::Value, String> {
        use std::os::unix::fs::MetadataExt;
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("held process exited before native executable acquisition".into());
        }
        // This is the kernel procfs executable link of an already PIDFD-held
        // process, not a fixture-supplied pathname or imported descriptor.
        let mut image = File::open(format!("/proc/{}/exe", self.process_id))
            .map_err(|error| error.to_string())?;
        let before = image.metadata().map_err(|error| error.to_string())?;
        if !before.is_file() || before.len() > 512 * 1024 * 1024 {
            return Err("native held executable type/length exceeds bound".into());
        }
        let mut hash = Sha256::new();
        let mut length = 0u64;
        let mut chunk = [0; 65536];
        loop {
            if std::time::Instant::now() >= deadline {
                return Err("native held executable observation deadline exhausted".into());
            }
            let count = image.read(&mut chunk).map_err(|error| error.to_string())?;
            if count == 0 {
                break;
            }
            length += count as u64;
            if length > before.len() {
                return Err("native held executable changed size while measured".into());
            }
            hash.update(&chunk[..count]);
        }
        let after = image.metadata().map_err(|error| error.to_string())?;
        let named = File::open(format!("/proc/{}/exe", self.process_id))
            .map_err(|error| error.to_string())?
            .metadata()
            .map_err(|error| error.to_string())?;
        if self.exited()?
            || process_birth(self.process_id)? != self.birth
            || length != before.len()
            || (
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
            )
            || (named.dev(), named.ino()) != (after.dev(), after.ino())
        {
            return Err("held executable/birth changed through native readback".into());
        }
        let receipt = serde_json::json!({"device":before.dev(),"inode":before.ino(),"length":length,"sha256":hex::encode(hash.finalize())});
        self.observed_images.push(image);
        Ok(receipt)
    }

    pub fn live_snapshot(&self) -> Result<LinuxHeldSnapshot, String> {
        use std::os::unix::fs::MetadataExt;
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("snapshot process is no longer held live".into());
        }
        let root = Path::new("/proc").join(self.process_id.to_string());
        let namespace = |name: &str| -> Result<LinuxNativeNamespace, String> {
            let metadata =
                std::fs::metadata(root.join("ns").join(name)).map_err(|e| e.to_string())?;
            if metadata.ino() == 0 {
                return Err("native namespace inode absent".into());
            }
            Ok(LinuxNativeNamespace {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        };
        let status = std::fs::read_to_string(root.join("status")).map_err(|e| e.to_string())?;
        let namespace_pids = status
            .lines()
            .find_map(|line| line.strip_prefix("NSpid:"))
            .ok_or("native namespace PID tuple absent")?
            .split_whitespace()
            .map(|value| value.parse::<u32>().map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        if namespace_pids.first() != Some(&self.process_id) || namespace_pids.contains(&0) {
            return Err("native namespace PID tuple differs".into());
        }
        let snapshot = LinuxHeldSnapshot {
            process_id: self.process_id,
            birth: self.birth,
            namespace_pids,
            user: namespace("user")?,
            mount: namespace("mnt")?,
            pid: namespace("pid")?,
            network: namespace("net")?,
            ipc: namespace("ipc")?,
        };
        if self.exited()? || process_birth(self.process_id)? != self.birth {
            return Err("native process changed while namespaces were observed".into());
        }
        Ok(snapshot)
    }

    /// Resolves a fixture-local identity only inside this already held native
    /// PID namespace. A PID string or transcript alone cannot select a host
    /// process from another attempt.
    pub fn hold_namespace_member(
        &self,
        local_pid: u32,
        expected_birth: u64,
    ) -> Result<Self, String> {
        use std::os::unix::fs::MetadataExt;
        let root = self.live_snapshot()?;
        let mut selected = None;
        for entry in std::fs::read_dir("/proc").map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let namespace = match std::fs::metadata(entry.path().join("ns/pid")) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if (namespace.dev(), namespace.ino()) != (root.pid.device, root.pid.inode) {
                continue;
            }
            let status = match std::fs::read_to_string(entry.path().join("status")) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let observed_local = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .and_then(|values| values.split_whitespace().last())
                .and_then(|value| value.parse::<u32>().ok());
            if observed_local != Some(local_pid) {
                continue;
            }
            let mut held = Self::acquire(pid, expected_birth)?;
            let snapshot = held.live_snapshot()?;
            if (snapshot.pid.device, snapshot.pid.inode) != (root.pid.device, root.pid.inode)
                || snapshot.namespace_pids.last() != Some(&local_pid)
            {
                return Err("native member changed PID namespace during hold".into());
            }
            held.namespace_pid = Some(local_pid);
            if selected.replace(held).is_some() {
                return Err("fixture identity maps to multiple native host processes".into());
            }
        }
        if self.exited()? {
            return Err("held root exited before cohort observation completed".into());
        }
        selected.ok_or("fixture-local process is not live in the held attempt PID namespace".into())
    }
}

#[derive(Clone, Debug)]
pub struct LinuxCollectionInput {
    pub identity: SourceIdentity,
    pub key: CaseKey,
    pub challenge: String,
    pub artifact_prefix: String,
    pub result: PathBuf,
    pub stdout: PathBuf,
    pub stderr: PathBuf,
    pub transcript: Option<PathBuf>,
    pub provider_request: PathBuf,
    pub contract: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxTranscriptRow {
    pub format: String,
    pub revision: u32,
    pub sequence: u64,
    pub challenge: String,
    pub root_pid: u32,
    pub root_birth: u64,
    pub operation: String,
    pub observation: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxCollectedEvidence {
    pub format: String,
    pub revision: u32,
    pub identity: SourceIdentity,
    pub key: CaseKey,
    pub artifacts: Vec<Artifact>,
    pub transcript: Vec<LinuxTranscriptRow>,
}

pub(crate) fn measured(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute()
        || path.components().any(|part| {
            matches!(
                part,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Linux artifact custody requires an absolute normalized path".into());
    }
    let mut ancestors = Vec::new();
    let mut current_path = std::path::PathBuf::from("/");
    for component in path.parent().ok_or("artifact parent absent")?.components() {
        if let std::path::Component::Normal(name) = component {
            current_path.push(name);
        } else if !matches!(component, std::path::Component::RootDir) {
            return Err("artifact ancestor invalid".into());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&current_path)
            .map_err(|error| error.to_string())?;
        let metadata = held.metadata().map_err(|error| error.to_string())?;
        ancestors.push((current_path.clone(), held, metadata.dev(), metadata.ino()));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.nlink() != 1 || before.len() > maximum {
        return Err("Linux driver artifact is not bounded exclusive regular custody".into());
    }
    let mut bytes = Vec::new();
    file.try_clone()
        .map_err(|e| e.to_string())?
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    let named = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| e.to_string())?;
    let current = named.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
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
        )
        || (before.dev(), before.ino()) != (current.dev(), current.ino())
    {
        return Err("Linux driver artifact changed during collection".into());
    }
    let mut readback = Vec::new();
    named
        .take(maximum + 1)
        .read_to_end(&mut readback)
        .map_err(|e| e.to_string())?;
    if readback != bytes {
        return Err("Linux driver named readback differs".into());
    }
    for (path, held, device, inode) in ancestors {
        let named = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(path)
            .map_err(|error| error.to_string())?;
        let original = held.metadata().map_err(|error| error.to_string())?;
        let named = named.metadata().map_err(|error| error.to_string())?;
        if (original.dev(), original.ino()) != (device, inode)
            || (named.dev(), named.ino()) != (device, inode)
        {
            return Err("Linux driver named ancestor changed during artifact readback".into());
        }
    }
    Ok(bytes)
}

pub fn collect(
    input: LinuxCollectionInput,
    destination: &Path,
) -> Result<LinuxCollectedEvidence, String> {
    if !input.key.target.ends_with("linux-gnu") || input.key.channel.is_none() {
        return Err("Linux installed collection requires an exact product cell".into());
    }
    if input.artifact_prefix.is_empty()
        || input.artifact_prefix.contains(['\\', ':', '\0'])
        || input
            .artifact_prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("unsafe Linux artifact prefix".into());
    }
    let mut artifacts = Vec::new();
    let mut transcript = Vec::new();
    for (name, path, maximum) in [
        ("result.json", &input.result, 4 * 1024 * 1024),
        ("stdout.bin", &input.stdout, 64 * 1024 * 1024),
        ("stderr.bin", &input.stderr, 64 * 1024 * 1024),
        (
            "provider-request.json",
            &input.provider_request,
            4 * 1024 * 1024,
        ),
        ("contract.json", &input.contract, 1024 * 1024),
    ] {
        let bytes = measured(path, maximum)?;
        if name == "stdout.bin" && input.transcript.is_none() && bytes.starts_with(b"{") {
            for (ordinal, line) in bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .enumerate()
            {
                let row: LinuxTranscriptRow =
                    serde_json::from_slice(line).map_err(|e| e.to_string())?;
                if row.format != "memcordon.linux-readiness-transcript"
                    || row.revision != 1
                    || row.sequence != ordinal as u64 + 1
                    || row.challenge != input.challenge
                    || row.root_pid == 0
                    || row.root_birth == 0
                    || row.operation.is_empty()
                {
                    return Err("Linux fixture transcript association/sequence invalid".into());
                }
                if transcript
                    .first()
                    .is_some_and(|first: &LinuxTranscriptRow| {
                        (first.root_pid, first.root_birth) != (row.root_pid, row.root_birth)
                    })
                {
                    return Err("Linux transcript changed root identity".into());
                }
                transcript.push(row);
            }
            if transcript.is_empty() || !bytes.ends_with(b"\n") {
                return Err("Linux fixture transcript missing or truncated".into());
            }
        }
        let relative = Path::new(&input.artifact_prefix).join(name);
        let output = destination.join(&relative);
        std::fs::create_dir_all(output.parent().ok_or("artifact parent absent")?)
            .map_err(|e| e.to_string())?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&output)
            .map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        artifacts.push(Artifact {
            path: relative.to_str().ok_or("artifact path not UTF-8")?.into(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    if let Some(path) = &input.transcript {
        let bytes = measured(path, 64 * 1024 * 1024)?;
        for (ordinal, line) in bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .enumerate()
        {
            let row: LinuxTranscriptRow =
                serde_json::from_slice(line).map_err(|e| e.to_string())?;
            if row.format != "memcordon.linux-readiness-transcript"
                || row.revision != 1
                || row.sequence != ordinal as u64 + 1
                || row.challenge != input.challenge
                || row.root_pid == 0
                || row.root_birth == 0
                || row.operation.is_empty()
            {
                return Err("persisted Linux transcript association invalid".into());
            }
            transcript.push(row);
        }
        if transcript.is_empty() || !bytes.ends_with(b"\n") {
            return Err("persisted Linux transcript missing/truncated".into());
        }
        let relative = Path::new(&input.artifact_prefix).join("transcript.jsonl");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination.join(&relative))
            .map_err(|e| e.to_string())?;
        output.write_all(&bytes).map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        artifacts.push(Artifact {
            path: relative.to_str().ok_or("transcript path not UTF-8")?.into(),
            length: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(&bytes)),
        });
    }
    File::open(destination.join(&input.artifact_prefix))
        .map_err(|e| e.to_string())?
        .sync_all()
        .map_err(|e| e.to_string())?;
    Ok(LinuxCollectedEvidence {
        format: "memcordon.linux-collected-evidence".into(),
        revision: 1,
        identity: input.identity,
        key: input.key,
        artifacts,
        transcript,
    })
}
