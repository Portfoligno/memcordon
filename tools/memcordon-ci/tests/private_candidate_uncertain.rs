use memcordon_ci::private_protected_readback::{
    ProtectedCandidateAttemptV1, ProtectedCandidateCheckpointV1, StructuralProtectedNativeCaseV1,
    parse_protected_candidate_attempt, parse_protected_candidate_request,
    validate_candidate_uncertain_raw_attachments,
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

const SELECTOR: &str = "private_tcp::authorization_uncertainty_retired";

fn fixture() -> (StructuralProtectedNativeCaseV1, [u8; 32], DiagnosticSha256) {
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
    let mut attempt_hash = Sha256::new();
    attempt_hash.update(b"memcordon-private-release-candidate-attempt-v1\0");
    attempt_hash.update(key.bytes());
    let attempt_id = hex::encode(&attempt_hash.finalize()[..16]);
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
    let mut attempt_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": SELECTOR,
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
        "release_knowledge": "possibly-released",
        "cleanup_error": null,
        "candidate_exit_code": null,
        "record_digest": DiagnosticSha256::from_bytes([0; 32])
    });
    let typed: ProtectedCandidateAttemptV1 = serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(typed.canonical_digest().unwrap());
    let attempt_bytes = serde_json::to_vec(&attempt_json).unwrap();
    let terminal_digest: DiagnosticSha256 =
        serde_json::from_value(attempt_json["record_digest"].clone()).unwrap();
    let observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
        attempt_id: attempt_id.clone(),
        checkpoint_sha256: checkpoint_digest.clone(),
        terminal_sha256: hash_bytes(&attempt_bytes),
        retirement_sha256: DiagnosticSha256::from_bytes([0; 32]),
        release_knowledge: PrivateReleaseKnowledgeV1::PossiblyReleased,
        exec: PrivateReleaseExecV1::NotObserved,
        native_observer_sha256: DiagnosticSha256::from_bytes([0; 32]),
    };
    let attempt =
        parse_protected_candidate_attempt(&attempt_bytes, &request, &observation, challenge)
            .unwrap();
    let inspection = "{}";
    let inspection_digest = hash_bytes(inspection.as_bytes());
    let report = serde_json::to_vec(&json!({
        "schema_version": 1,
        "selector": SELECTOR,
        "result_key": key,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_digest,
        "challenge_sha256": hash_bytes(&challenge),
        "release_knowledge": "possibly-released",
        "transport_errno": 32,
        "authorization_failure_phase": 4,
        "authorization_failure_detail": "authorization packet invalid",
        "candidate_exit_code": null,
        "installed_inspection_json": inspection
    }))
    .unwrap();
    let mut guardian = [0_u8; 20];
    guardian[0] = 4;
    guardian[1..17].copy_from_slice(&hex::decode(&attempt_id).unwrap());
    guardian[17] = 1;
    let observer = serde_json::to_vec(&json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_digest,
        "authorization_failure_phase": 4,
        "authorization_failure_detail": "authorization packet invalid",
        "settlement": {
            "schema_version": 1,
            "transport_errno": 32,
            "containment_removed": true,
            "target_pidfd_exited": true,
            "namespace_init_reaped": true,
            "guardian_terminal": guardian,
            "candidate_exit_code": null
        }
    }))
    .unwrap();
    let cleanup = serde_json::to_vec(&json!({
        "schema_version": 1,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_digest,
        "release_knowledge": "possibly-released",
        "transport_errno": 32,
        "kernel_trace_sha256": hash_bytes(&observer),
        "coordinator": {"pid": 123, "start_time": 456},
        "worker": {"pid": 789, "start_time": 987},
        "worker_pidfd_exited": true,
        "service_generation_sha256": service,
        "settlement_source": "control-coordinator-pidfd"
    }))
    .unwrap();
    let attachments = vec![
        request_bytes.clone(),
        report,
        challenge.to_vec(),
        observer,
        cleanup,
    ];
    let inventory = PrivateReleaseAttachmentRoleV1::ALL
        .into_iter()
        .zip(&attachments)
        .map(|(role, raw)| PrivateReleaseAttachmentV1 {
            role,
            size: raw.len() as u64,
            sha256: hash_bytes(raw),
        })
        .collect();
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
        observation: PrivateReleaseObservationV1::AllocatedRetired {
            outcome: PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
            attempt_id,
            checkpoint_sha256: checkpoint_digest,
            terminal_sha256: hash_bytes(&attempt_bytes),
            retirement_sha256: hash_bytes(&attachments[4]),
            release_knowledge: PrivateReleaseKnowledgeV1::PossiblyReleased,
            exec: PrivateReleaseExecV1::NotObserved,
            native_observer_sha256: hash_bytes(&attachments[3]),
        },
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

fn refresh_observer_and_cleanup_hashes(case: &mut StructuralProtectedNativeCaseV1) {
    if let PrivateReleaseObservationV1::AllocatedRetired {
        native_observer_sha256,
        retirement_sha256,
        ..
    } = &mut case.result.observation
    {
        *native_observer_sha256 = hash_bytes(&case.attachments[3]);
        *retirement_sha256 = hash_bytes(&case.attachments[4]);
    }
    case.result.attachments[3].sha256 = hash_bytes(&case.attachments[3]);
    case.result.attachments[3].size = case.attachments[3].len() as u64;
    case.result.attachments[4].sha256 = hash_bytes(&case.attachments[4]);
    case.result.attachments[4].size = case.attachments[4].len() as u64;
}

#[test]
fn uncertain_candidate_requires_exact_phase_epipe_nonexec_and_coordinator_cleanup() {
    let (case, challenge, inspection) = fixture();
    validate_candidate_uncertain_raw_attachments(&case, challenge, &inspection).unwrap();
    let mut wrong_phase = fixture().0;
    let mut report: serde_json::Value =
        serde_json::from_slice(&wrong_phase.attachments[1]).unwrap();
    report["authorization_failure_phase"] = json!(5);
    wrong_phase.attachments[1] = serde_json::to_vec(&report).unwrap();
    wrong_phase.result.attachments[1].sha256 = hash_bytes(&wrong_phase.attachments[1]);
    wrong_phase.result.attachments[1].size = wrong_phase.attachments[1].len() as u64;
    assert!(
        validate_candidate_uncertain_raw_attachments(&wrong_phase, challenge, &inspection).is_err()
    );
    let mut wrong_errno = fixture().0;
    let mut report: serde_json::Value =
        serde_json::from_slice(&wrong_errno.attachments[1]).unwrap();
    report["transport_errno"] = json!(1);
    wrong_errno.attachments[1] = serde_json::to_vec(&report).unwrap();
    wrong_errno.result.attachments[1].sha256 = hash_bytes(&wrong_errno.attachments[1]);
    wrong_errno.result.attachments[1].size = wrong_errno.attachments[1].len() as u64;
    assert!(
        validate_candidate_uncertain_raw_attachments(&wrong_errno, challenge, &inspection).is_err()
    );
    let mut wrong_worker = fixture().0;
    let mut cleanup: serde_json::Value =
        serde_json::from_slice(&wrong_worker.attachments[4]).unwrap();
    cleanup["worker_pidfd_exited"] = json!(false);
    wrong_worker.attachments[4] = serde_json::to_vec(&cleanup).unwrap();
    refresh_observer_and_cleanup_hashes(&mut wrong_worker);
    assert!(
        validate_candidate_uncertain_raw_attachments(&wrong_worker, challenge, &inspection)
            .is_err()
    );
    let mut wrong_guardian = fixture().0;
    let mut observer: serde_json::Value =
        serde_json::from_slice(&wrong_guardian.attachments[3]).unwrap();
    observer["settlement"]["guardian_terminal"][17] = json!(2);
    wrong_guardian.attachments[3] = serde_json::to_vec(&observer).unwrap();
    let mut cleanup: serde_json::Value =
        serde_json::from_slice(&wrong_guardian.attachments[4]).unwrap();
    cleanup["kernel_trace_sha256"] = json!(hash_bytes(&wrong_guardian.attachments[3]));
    wrong_guardian.attachments[4] = serde_json::to_vec(&cleanup).unwrap();
    refresh_observer_and_cleanup_hashes(&mut wrong_guardian);
    assert!(
        validate_candidate_uncertain_raw_attachments(&wrong_guardian, challenge, &inspection)
            .is_err()
    );
}
