use memcordon_ci::private_protected_readback::{
    ProtectedCandidateAttemptV1, ProtectedCandidateCheckpointV1, StructuralProtectedNativeCaseV1,
    expected_protected_candidate_leaves_for_selector, parse_protected_candidate_attempt,
    parse_protected_candidate_request, parse_protected_checkpoint_gate_witness,
    validate_candidate_checkpoint_gate_raw_attachments,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseCaseResultV1, PrivateReleaseExecV1, PrivateReleaseInstalledBindingV1,
    PrivateReleaseKnowledgeV1, PrivateReleaseObservationV1, PrivateReleaseStageV1,
    private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const SELECTOR: &str = "private_tcp::checkpoint_persisted_before_release";

#[derive(Serialize)]
struct GateWitness<'a> {
    schema_version: u8,
    selector: &'a str,
    result_key: &'a DiagnosticSha256,
    attempt_id: &'a str,
    checkpoint_sha256: &'a DiagnosticSha256,
    release_intent_record_digest: &'a DiagnosticSha256,
    release_intent_bytes: &'a [u8],
    target: serde_json::Value,
    target_pidfd_live: bool,
    control_event_absent: bool,
}

#[test]
fn checkpoint_gate_joins_prior_release_intent_target_and_all_raw_hashes() {
    let challenge = [0xab; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        SELECTOR,
        &challenge,
    )
    .unwrap();
    let epoch = DiagnosticSha256::from_bytes([1; 32]);
    let manifest = DiagnosticSha256::from_bytes([2; 32]);
    let service = DiagnosticSha256::from_bytes([3; 32]);
    let request_bytes = serde_json::to_vec(&json!({
        "schema_version": 1,
        "stage": "candidate-capability",
        "selector": SELECTOR,
        "challenge": hex::encode(challenge),
        "result_key": key,
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "coordinator": {"pid": 123, "start_time": 456}
    }))
    .unwrap();
    let request =
        parse_protected_candidate_request(&request_bytes, SELECTOR, challenge, &key).unwrap();
    let mut id_hash = Sha256::new();
    id_hash.update(b"memcordon-private-release-candidate-attempt-v1\0");
    id_hash.update(key.bytes());
    let attempt_id = hex::encode(&id_hash.finalize()[..16]);
    let checkpoint_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": SELECTOR,
        "challenge_sha256": hash_bytes(&challenge),
        "attempt_id": attempt_id,
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "fixture_sha256": DiagnosticSha256::from_bytes([8; 32]),
        "filter_sha256": DiagnosticSha256::from_bytes([9; 32]),
        "target_uid": 1000,
        "target_gid": 1000,
        "guardian": {"pid": 124, "start_time": 457},
        "namespace_init": {"pid": 125, "start_time": 458},
        "target": {"pid": 126, "start_time": 459},
        "network_namespace_inode": 42,
        "topology_sha256": DiagnosticSha256::from_bytes([10; 32]),
        "native_readback_sha256": DiagnosticSha256::from_bytes([11; 32])
    });
    let checkpoint: ProtectedCandidateCheckpointV1 =
        serde_json::from_value(checkpoint_json.clone()).unwrap();
    let checkpoint_digest = checkpoint.canonical_digest().unwrap();
    let mut intent_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": SELECTOR,
        "challenge_sha256": hash_bytes(&challenge),
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "attempt_id": attempt_id,
        "coordinator": {"pid": 123, "start_time": 456},
        "phase": "release-intent",
        "guardian": {"pid": 124, "start_time": 457},
        "namespace_init": {"pid": 125, "start_time": 458},
        "target": {"pid": 126, "start_time": 459},
        "network_namespace_inode": 42,
        "checkpoint_digest": checkpoint_digest,
        "checkpoint_binding": checkpoint_json,
        "release_knowledge": "possibly-released",
        "cleanup_error": null,
        "candidate_exit_code": null,
        "record_digest": DiagnosticSha256::from_bytes([0; 32])
    });
    let typed_intent: ProtectedCandidateAttemptV1 =
        serde_json::from_value(intent_json.clone()).unwrap();
    intent_json["record_digest"] = json!(typed_intent.canonical_digest().unwrap());
    let typed_intent: ProtectedCandidateAttemptV1 =
        serde_json::from_value(intent_json.clone()).unwrap();
    let intent_bytes = serde_json::to_vec(&typed_intent).unwrap();
    let intent_digest: DiagnosticSha256 =
        serde_json::from_value(intent_json["record_digest"].clone()).unwrap();
    let mut final_json = intent_json;
    final_json["phase"] = json!("retired");
    final_json["release_knowledge"] = json!("exec-observed");
    final_json["candidate_exit_code"] = json!(0);
    final_json["record_digest"] = json!(DiagnosticSha256::from_bytes([0; 32]));
    let final_typed: ProtectedCandidateAttemptV1 =
        serde_json::from_value(final_json.clone()).unwrap();
    final_json["record_digest"] = json!(final_typed.canonical_digest().unwrap());
    let final_typed: ProtectedCandidateAttemptV1 =
        serde_json::from_value(final_json.clone()).unwrap();
    let final_bytes = serde_json::to_vec(&final_typed).unwrap();
    let final_digest: DiagnosticSha256 =
        serde_json::from_value(final_json["record_digest"].clone()).unwrap();
    let gate_bytes = serde_json::to_vec(&GateWitness {
        schema_version: 1,
        selector: SELECTOR,
        result_key: &key,
        attempt_id: &attempt_id,
        checkpoint_sha256: &checkpoint_digest,
        release_intent_record_digest: &intent_digest,
        release_intent_bytes: &intent_bytes,
        target: json!({"pid": 126, "start_time": 459}),
        target_pidfd_live: true,
        control_event_absent: true,
    })
    .unwrap();
    let gate_digest = hash_bytes(&gate_bytes);
    let mut response_hash = Sha256::new();
    response_hash.update(b"memcordon-private-release-candidate-fixture-v1\0");
    response_hash.update(SELECTOR.as_bytes());
    response_hash.update([0]);
    response_hash.update(challenge);
    let response: [u8; 32] = response_hash.finalize().into();
    let report = serde_json::to_vec(&json!({
        "schema_version": 1,
        "selector": SELECTOR,
        "result_key": key,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": final_digest,
        "challenge_sha256": hash_bytes(&challenge),
        "response_sha256": hash_bytes(&response),
        "checkpoint_gate_sha256": gate_digest,
        "candidate_exit_code": 0,
        "installed_inspection_json": "{}"
    }))
    .unwrap();
    let mut guardian_terminal = [0_u8; 20];
    guardian_terminal[0] = 4;
    guardian_terminal[1..17].copy_from_slice(&hex::decode(&attempt_id).unwrap());
    guardian_terminal[17] = 1;
    let observer = serde_json::to_vec(&json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": final_digest,
        "checkpoint_gate_sha256": gate_digest,
        "settlement": {
            "schema_version": 1,
            "monitor_outcome": "Completed",
            "cgroup_empty_before_cleanup": true,
            "containment_removed": true,
            "target_pidfd_exited": true,
            "namespace_init_reaped": true,
            "guardian_terminal": guardian_terminal,
            "candidate_exit_code": 0
        }
    }))
    .unwrap();
    let cleanup = serde_json::to_vec(&json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": final_digest,
        "checkpoint_gate_sha256": gate_digest,
        "kernel_trace_sha256": hash_bytes(&observer),
        "coordinator": {"pid": 123, "start_time": 456},
        "worker": {"pid": 789, "start_time": 987},
        "worker_pidfd_exited": true,
        "service_generation_sha256": service,
        "settlement_source": "control-coordinator-pidfd"
    }))
    .unwrap();
    let mut stdio = challenge.to_vec();
    stdio.extend_from_slice(&response);
    let attachments = vec![request_bytes.clone(), report, stdio, observer, cleanup];
    let inventory = PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .zip(&attachments)
        .map(|(role, bytes)| PrivateReleaseAttachmentV1 {
            role,
            size: bytes.len() as u64,
            sha256: hash_bytes(bytes),
        })
        .collect();
    let observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: attempt_id.clone(),
        checkpoint_sha256: checkpoint_digest,
        terminal_sha256: hash_bytes(&final_bytes),
        retirement_sha256: hash_bytes(&attachments[4]),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: hash_bytes(&attachments[3]),
    };
    let attempt =
        parse_protected_candidate_attempt(&final_bytes, &request, &observation, challenge).unwrap();
    let inspection_digest = hash_bytes(b"{}");
    let result = PrivateReleaseCaseResultV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        challenge: hex::encode(challenge),
        target: "x86_64-unknown-linux-gnu".into(),
        native_machine: "x86_64".into(),
        installed: PrivateReleaseInstalledBindingV1::CandidateCapability {
            installation_epoch: epoch,
            candidate_manifest_sha256: manifest,
            installed_inspection_sha256: inspection_digest.clone(),
        },
        observation,
        attachments: inventory,
    };
    result.validate().unwrap();
    let mut case = StructuralProtectedNativeCaseV1 {
        result,
        candidate_request: request,
        candidate_request_bytes: request_bytes,
        attempt_record: Some(attempt),
        attempt_record_bytes: Some(final_bytes),
        fault_marker_bytes: None,
        checkpoint_gate_bytes: Some(gate_bytes.clone()),
        attachments,
    };
    let leaves =
        expected_protected_candidate_leaves_for_selector(SELECTOR, &case.result.observation)
            .unwrap();
    let expected = [
        "request.json",
        "attempt.json",
        "request.bin",
        "report.bin",
        "stdio.bin",
        "observer.bin",
        "cleanup.bin",
        "checkpoint-gate.json",
        "checkpoint-committed-v1.json",
        "release-intent-v1.json",
        "execution-observed-v1.json",
        "candidate-live-pre-v1.json",
        "candidate-live-pre-v1.ack",
        "candidate-live-release-intent-v1.json",
        "candidate-live-release-intent-v1.ack",
        "candidate-live-baseline-v1.json",
        "candidate-live-baseline-v1.ack",
        "candidate-live-post-v1.json",
        "candidate-live-post-v1.ack",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(leaves, expected);
    parse_protected_checkpoint_gate_witness(
        &gate_bytes,
        &case.candidate_request,
        case.attempt_record.as_ref(),
    )
    .unwrap();
    validate_candidate_checkpoint_gate_raw_attachments(&case, challenge, &inspection_digest)
        .unwrap();

    let mut changed: serde_json::Value = serde_json::from_slice(&gate_bytes).unwrap();
    changed["control_event_absent"] = json!(false);
    case.checkpoint_gate_bytes = Some(serde_json::to_vec(&changed).unwrap());
    assert!(
        validate_candidate_checkpoint_gate_raw_attachments(&case, challenge, &inspection_digest)
            .is_err()
    );
    changed["control_event_absent"] = json!(true);
    changed["release_intent_bytes"][0] = json!(0);
    case.checkpoint_gate_bytes = Some(serde_json::to_vec(&changed).unwrap());
    assert!(
        validate_candidate_checkpoint_gate_raw_attachments(&case, challenge, &inspection_digest)
            .is_err()
    );
    case.checkpoint_gate_bytes = Some(gate_bytes);

    let report = case.attachments[1].clone();
    let mut changed: serde_json::Value = serde_json::from_slice(&report).unwrap();
    changed["checkpoint_gate_sha256"] = json!(DiagnosticSha256::from_bytes([7; 32]));
    case.attachments[1] = serde_json::to_vec(&changed).unwrap();
    assert!(
        validate_candidate_checkpoint_gate_raw_attachments(&case, challenge, &inspection_digest)
            .is_err()
    );
    case.attachments[1] = report;
    let cleanup = case.attachments[4].clone();
    let mut changed: serde_json::Value = serde_json::from_slice(&cleanup).unwrap();
    changed["worker_pidfd_exited"] = json!(false);
    case.attachments[4] = serde_json::to_vec(&changed).unwrap();
    assert!(
        validate_candidate_checkpoint_gate_raw_attachments(&case, challenge, &inspection_digest)
            .is_err()
    );
}
