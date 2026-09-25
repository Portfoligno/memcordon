use memcordon_ci::private_protected_readback::{
    ProtectedCandidateAttemptV1, ProtectedCandidateCheckpointV1, StructuralProtectedNativeCaseV1,
    parse_protected_candidate_attempt, parse_protected_candidate_request,
    validate_candidate_frontend_loss_raw_attachments,
    validate_candidate_guardian_loss_raw_attachments,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseCaseResultV1, PrivateReleaseExecV1, PrivateReleaseInstalledBindingV1,
    PrivateReleaseKnowledgeV1, PrivateReleaseObservationV1, PrivateReleaseStageV1,
    private_release_case_key_v1,
};
use memcordon_core::workload_codec::hash_bytes;
use serde_json::json;
use sha2::{Digest, Sha256};

const SELECTOR: &str = "private_tcp::guardian_loss_retired";
const FRONTEND_SELECTOR: &str = "private_tcp::frontend_loss_retired";

fn fixture(selector: &str) -> (StructuralProtectedNativeCaseV1, [u8; 32], DiagnosticSha256) {
    let frontend_loss = selector == FRONTEND_SELECTOR;
    assert!(selector == SELECTOR || frontend_loss);
    let challenge = [0xab; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        selector,
        &challenge,
    )
    .unwrap();
    let epoch = DiagnosticSha256::from_bytes([1; 32]);
    let manifest = DiagnosticSha256::from_bytes([2; 32]);
    let service = DiagnosticSha256::from_bytes([3; 32]);
    let request_bytes = serde_json::to_vec(&json!({
        "schema_version": 1,
        "stage": "candidate-capability",
        "selector": selector,
        "challenge": hex::encode(challenge),
        "result_key": key,
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "coordinator": {"pid": 123, "start_time": 456}
    }))
    .unwrap();
    let request =
        parse_protected_candidate_request(&request_bytes, selector, challenge, &key).unwrap();
    let mut id_hash = Sha256::new();
    id_hash.update(b"memcordon-private-release-candidate-attempt-v1\0");
    id_hash.update(key.bytes());
    let attempt_id = hex::encode(&id_hash.finalize()[..16]);
    let checkpoint_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": selector,
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
    let mut attempt_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": selector,
        "challenge_sha256": hash_bytes(&challenge),
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "attempt_id": attempt_id,
        "coordinator": {"pid": 123, "start_time": 456},
        "phase": "retired",
        "guardian": {"pid": 124, "start_time": 457},
        "namespace_init": {"pid": 125, "start_time": 458},
        "target": {"pid": 126, "start_time": 459},
        "network_namespace_inode": 42,
        "checkpoint_digest": checkpoint_digest,
        "checkpoint_binding": checkpoint_json,
        "release_knowledge": "exec-observed",
        "cleanup_error": null,
        "candidate_exit_code": null,
        "record_digest": DiagnosticSha256::from_bytes([0; 32])
    });
    if frontend_loss {
        attempt_json["frontend_proxy"] = json!({"pid": 127, "start_time": 460});
    }
    let typed: ProtectedCandidateAttemptV1 = serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(typed.canonical_digest().unwrap());
    let attempt_bytes = serde_json::to_vec(&attempt_json).unwrap();
    let terminal_record_digest: DiagnosticSha256 =
        serde_json::from_value(attempt_json["record_digest"].clone()).unwrap();
    let mut response_hash = Sha256::new();
    response_hash.update(b"memcordon-private-release-candidate-fixture-v1\0");
    response_hash.update(selector.as_bytes());
    response_hash.update([0]);
    response_hash.update(challenge);
    let response: [u8; 32] = response_hash.finalize().into();
    let mut report_json = json!({
        "schema_version": 1,
        "selector": selector,
        "result_key": key,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_record_digest,
        "challenge_sha256": hash_bytes(&challenge),
        "armed_response_sha256": hash_bytes(&response),
        "network_namespace_inode": 42,
        "candidate_exit_code": null,
        "installed_inspection_json": "{}"
    });
    if frontend_loss {
        report_json["frontend_proxy"] = json!({"pid": 127, "start_time": 460});
    }
    let report = serde_json::to_vec(&report_json).unwrap();
    let mut observer_json = json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_record_digest,
        "settlement": {
            "schema_version": 1,
            "guardian": {"pid": 124, "start_time": 457},
            "guardian_signal": 9,
            "containment_removed": true,
            "target_pidfd_exited": true,
            "namespace_init_reaped": true,
            "candidate_exit_code": null
        }
    });
    if frontend_loss {
        let mut guardian_terminal = [0_u8; 20];
        guardian_terminal[0] = 4;
        guardian_terminal[1..17].copy_from_slice(&hex::decode(&attempt_id).unwrap());
        guardian_terminal[17] = 2;
        guardian_terminal[18] = 1;
        observer_json["settlement"] = json!({
            "schema_version": 1,
            "frontend": {"pid": 127, "start_time": 460},
            "frontend_signal": 9,
            "guardian_terminal": guardian_terminal,
            "containment_removed": true,
            "target_pidfd_exited": true,
            "namespace_init_reaped": true,
            "candidate_exit_code": null
        });
    }
    let observer = serde_json::to_vec(&observer_json).unwrap();
    let mut cleanup_json = json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_record_digest,
        "guardian_signal": 9,
        "kernel_trace_sha256": hash_bytes(&observer),
        "coordinator": {"pid": 123, "start_time": 456},
        "worker": {"pid": 789, "start_time": 987},
        "worker_pidfd_exited": true,
        "service_generation_sha256": service,
        "settlement_source": "control-coordinator-pidfd"
    });
    if frontend_loss {
        cleanup_json["frontend_proxy"] = json!({"pid": 127, "start_time": 460});
        cleanup_json["frontend_signal"] = json!(9);
        cleanup_json["guardian_terminal"] =
            observer_json["settlement"]["guardian_terminal"].clone();
        cleanup_json
            .as_object_mut()
            .unwrap()
            .remove("guardian_signal");
    }
    let cleanup = serde_json::to_vec(&cleanup_json).unwrap();
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
    let inspection_digest = hash_bytes(b"{}");
    let observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: if frontend_loss {
            PrivateReleaseAllocatedOutcomeV1::FrontendLost
        } else {
            PrivateReleaseAllocatedOutcomeV1::GuardianLost
        },
        attempt_id: attempt_id.clone(),
        checkpoint_sha256: checkpoint_digest,
        terminal_sha256: hash_bytes(&attempt_bytes),
        retirement_sha256: hash_bytes(&attachments[4]),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: hash_bytes(&attachments[3]),
    };
    let attempt =
        parse_protected_candidate_attempt(&attempt_bytes, &request, &observation, challenge)
            .unwrap();
    let result = PrivateReleaseCaseResultV1 {
        schema_version: 1,
        selector: selector.into(),
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
    (
        StructuralProtectedNativeCaseV1 {
            result,
            candidate_request: request,
            candidate_request_bytes: request_bytes,
            attempt_record: Some(attempt),
            attempt_record_bytes: Some(attempt_bytes),
            fault_marker_bytes: None,
            checkpoint_gate_bytes: None,
            attachments,
        },
        challenge,
        inspection_digest,
    )
}

#[test]
fn guardian_loss_requires_exact_signal_native_identity_stdio_and_coordinator_cleanup() {
    let (mut case, challenge, inspection) = fixture(SELECTOR);
    validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).unwrap();

    let observer = case.attachments[3].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&observer).unwrap();
    altered["settlement"]["guardian_signal"] = json!(15);
    case.attachments[3] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    altered["settlement"]["guardian_signal"] = json!(9);
    altered["settlement"]["guardian"]["start_time"] = json!(999);
    case.attachments[3] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[3] = observer;

    let cleanup = case.attachments[4].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&cleanup).unwrap();
    altered["worker_pidfd_exited"] = json!(false);
    case.attachments[4] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[4] = cleanup;

    let report = case.attachments[1].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&report).unwrap();
    altered["network_namespace_inode"] = json!(43);
    case.attachments[1] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[1] = report;
    case.attachments[2][0] ^= 1;
    assert!(
        validate_candidate_guardian_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
}

#[test]
fn frontend_loss_requires_distinct_proxy_guardian_frame_and_worker_cleanup() {
    let (mut case, challenge, inspection) = fixture(FRONTEND_SELECTOR);
    validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).unwrap();

    let observer = case.attachments[3].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&observer).unwrap();
    altered["settlement"]["frontend_signal"] = json!(15);
    case.attachments[3] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    altered["settlement"]["frontend_signal"] = json!(9);
    altered["settlement"]["frontend"]["start_time"] = json!(999);
    case.attachments[3] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    altered["settlement"]["frontend"]["start_time"] = json!(460);
    altered["settlement"]["guardian_terminal"][17] = json!(1);
    case.attachments[3] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[3] = observer;

    let cleanup = case.attachments[4].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&cleanup).unwrap();
    altered["worker_pidfd_exited"] = json!(false);
    case.attachments[4] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    altered["worker_pidfd_exited"] = json!(true);
    altered["worker"] = json!({"pid": 127, "start_time": 460});
    case.attachments[4] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[4] = cleanup;

    let report = case.attachments[1].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&report).unwrap();
    altered["frontend_proxy"] = json!({"pid": 123, "start_time": 456});
    case.attachments[1] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );
    case.attachments[1] = report;
    case.attachments[2][0] ^= 1;
    assert!(
        validate_candidate_frontend_loss_raw_attachments(&case, challenge, &inspection).is_err()
    );

    let mut attempt_json: serde_json::Value =
        serde_json::from_slice(case.attempt_record_bytes.as_ref().unwrap()).unwrap();
    attempt_json["frontend_proxy"] = json!({"pid": 123, "start_time": 456});
    let mutated: ProtectedCandidateAttemptV1 =
        serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(mutated.canonical_digest().unwrap());
    let attempt_bytes = serde_json::to_vec(&attempt_json).unwrap();
    assert!(
        parse_protected_candidate_attempt(
            &attempt_bytes,
            &case.candidate_request,
            &case.result.observation,
            challenge,
        )
        .is_err()
    );
}
