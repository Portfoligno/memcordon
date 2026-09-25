use std::path::Path;

use memcordon_ci::private_native::NativeRunStageV2;
use memcordon_ci::private_protected_readback::{
    ProtectedCandidateAttemptV1, ProtectedCandidateCheckpointV1, StructuralProtectedNativeCaseV1,
    expected_protected_candidate_leaves, expected_protected_candidate_leaves_for_selector,
    parse_protected_candidate_attempt, parse_protected_candidate_request,
    read_protected_raw_case_file, validate_candidate_blocked_retirement_raw_attachments,
    validate_candidate_tcp_raw_attachments, validate_fixed_case_observation,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseCaseResultV1, PrivateReleaseDualRetiredBranchV1, PrivateReleaseExecV1,
    PrivateReleaseInstalledBindingV1, PrivateReleaseKnowledgeV1, PrivateReleaseObservationV1,
    PrivateReleaseStageV1, private_release_case_key_v1,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn candidate_admission_request_requires_exact_protected_identity() {
    let selector = "private_tcp::abi_alternate_entry_denied";
    let challenge = [0xab; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        selector,
        &challenge,
    )
    .unwrap();
    let record = json!({
        "schema_version": 1,
        "stage": "candidate-capability",
        "selector": selector,
        "challenge": hex::encode(challenge),
        "result_key": key,
        "installation_epoch": "a".repeat(64),
        "candidate_manifest_sha256": "b".repeat(64),
        "service_generation_sha256": "c".repeat(64),
        "coordinator": {"pid": 123, "start_time": 456}
    });
    let bytes = serde_json::to_vec(&record).unwrap();
    let parsed = parse_protected_candidate_request(&bytes, selector, challenge, &key).unwrap();
    assert_eq!(parsed.coordinator.pid, 123);
    assert_eq!(
        String::from(parsed.candidate_manifest_sha256),
        "b".repeat(64)
    );

    let mut wrong_stage = record.clone();
    wrong_stage["stage"] = json!("final-public");
    assert!(
        parse_protected_candidate_request(
            &serde_json::to_vec(&wrong_stage).unwrap(),
            selector,
            challenge,
            &key
        )
        .is_err()
    );
    let mut wrong_coordinator = record;
    wrong_coordinator["coordinator"]["start_time"] = json!(0);
    assert!(
        parse_protected_candidate_request(
            &serde_json::to_vec(&wrong_coordinator).unwrap(),
            selector,
            challenge,
            &key
        )
        .is_err()
    );
    assert!(
        parse_protected_candidate_request(
            b"{\"stage\":\"candidate-capability\",\"stage\":\"candidate-capability\"}",
            selector,
            challenge,
            &key
        )
        .is_err()
    );
}

#[test]
fn protected_inventory_distinguishes_preallocation_from_allocated_attempts() {
    let digest = DiagnosticSha256::from_bytes([1; 32]);
    let rejected = PrivateReleaseObservationV1::PreallocationRejected {
        rejection_code: "fixed-denial".into(),
        observer_sha256: digest.clone(),
    };
    let rejected_leaves = expected_protected_candidate_leaves(&rejected);
    assert_eq!(rejected_leaves.len(), 6);
    assert!(rejected_leaves.contains("request.json"));
    assert!(!rejected_leaves.contains("attempt.json"));

    let allocated = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: "a".repeat(32),
        checkpoint_sha256: digest.clone(),
        terminal_sha256: digest.clone(),
        retirement_sha256: digest.clone(),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: digest,
    };
    let allocated_leaves = expected_protected_candidate_leaves(&allocated);
    assert_eq!(allocated_leaves.len(), 7);
    assert!(allocated_leaves.contains("attempt.json"));
    assert!(allocated_leaves.contains("request.bin"));
    let child_leaves = expected_protected_candidate_leaves_for_selector(
        "private_tcp::child_runtime_and_threads_retired",
        &allocated,
    )
    .unwrap();
    assert_eq!(child_leaves.len(), 9);
    assert!(child_leaves.contains("live-gate.json"));
    assert!(child_leaves.contains("live-ack.json"));
    assert!(!child_leaves.contains("live-gate.pending"));
    assert!(!child_leaves.contains("live-ack.pending"));
    assert!(
        expected_protected_candidate_leaves_for_selector(
            "private_tcp::child_runtime_and_threads_retired",
            &rejected,
        )
        .is_err()
    );
    let socket_leaves = expected_protected_candidate_leaves_for_selector(
        "private_tcp::scm_rights_and_precreated_socket_denied",
        &allocated,
    )
    .unwrap();
    assert_eq!(socket_leaves.len(), 9);
    assert!(socket_leaves.contains("socket-gate.json"));
    assert!(socket_leaves.contains("socket-ack.json"));
    assert!(!socket_leaves.contains("socket-ack.pending"));
    assert!(
        expected_protected_candidate_leaves_for_selector(
            "private_tcp::scm_rights_and_precreated_socket_denied",
            &rejected,
        )
        .is_err()
    );
    let terminal_leaves = expected_protected_candidate_leaves_for_selector(
        "private_tcp::release_checkpoint_terminal_joined",
        &allocated,
    )
    .unwrap();
    assert_eq!(terminal_leaves.len(), 10);
    assert!(terminal_leaves.contains("terminal-join-midflight.json"));
    assert!(terminal_leaves.contains("terminal-join-gate.json"));
    assert!(terminal_leaves.contains("terminal-join-ack.json"));
    assert!(!terminal_leaves.contains("terminal-join-ack.pending"));
    assert!(
        expected_protected_candidate_leaves_for_selector(
            "private_tcp::release_checkpoint_terminal_joined",
            &rejected,
        )
        .is_err()
    );

    let dual_branch = PrivateReleaseDualRetiredBranchV1 {
        attempt_id: "1".repeat(32),
        checkpoint_sha256: DiagnosticSha256::from_bytes([1; 32]),
        terminal_sha256: DiagnosticSha256::from_bytes([2; 32]),
        retirement_sha256: DiagnosticSha256::from_bytes([3; 32]),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
    };
    let mut second_branch = dual_branch.clone();
    second_branch.attempt_id = "2".repeat(32);
    second_branch.checkpoint_sha256 = DiagnosticSha256::from_bytes([4; 32]);
    let dual = PrivateReleaseObservationV1::DualAttemptsRetired {
        first: dual_branch,
        second: second_branch,
        native_observer_sha256: DiagnosticSha256::from_bytes([5; 32]),
    };
    let dual_leaves = expected_protected_candidate_leaves_for_selector(
        "private_tcp::dual_attempt_namespace_isolation",
        &dual,
    )
    .unwrap();
    assert_eq!(dual_leaves.len(), 12);
    assert!(dual_leaves.contains("dual-first"));
    assert!(dual_leaves.contains("dual-second"));
    assert!(dual_leaves.contains("dual-live-ack.json"));
    assert!(!dual_leaves.contains("attempt.json"));
    assert!(!dual_leaves.contains("dual-live-ack.pending"));
    assert!(
        expected_protected_candidate_leaves_for_selector(
            "private_tcp::dual_attempt_namespace_isolation",
            &allocated,
        )
        .is_err()
    );
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::dual_attempt_namespace_isolation",
            &dual,
        )
        .is_ok()
    );
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::native_tcp_bind_listen_connect",
            &dual,
        )
        .is_err()
    );

    let blocked = PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
        attempt_id: "a".repeat(32),
        checkpoint_sha256: DiagnosticSha256::from_bytes([1; 32]),
        terminal_sha256: DiagnosticSha256::from_bytes([2; 32]),
        cleanup_failure_sha256: DiagnosticSha256::from_bytes([3; 32]),
        reuse_rejection_sha256: DiagnosticSha256::from_bytes([4; 32]),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: DiagnosticSha256::from_bytes([5; 32]),
    };
    let blocked_leaves = expected_protected_candidate_leaves_for_selector(
        "private_tcp::retirement_failure_blocks_reuse",
        &blocked,
    )
    .unwrap();
    assert_eq!(blocked_leaves.len(), 8);
    assert!(blocked_leaves.contains("attempt.json.new"));
    assert!(
        expected_protected_candidate_leaves_for_selector(
            "private_tcp::native_tcp_bind_listen_connect",
            &blocked,
        )
        .is_err()
    );
}

#[test]
fn fixed_catalogue_rejects_result_selected_wrong_phase_or_outcome() {
    let digest = DiagnosticSha256::from_bytes([1; 32]);
    let denied = PrivateReleaseObservationV1::PreallocationRejected {
        rejection_code: "untrusted-code".into(),
        observer_sha256: digest.clone(),
    };
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::wrong_grant_profile_and_port_rejected",
            &denied,
        )
        .is_ok()
    );
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::native_tcp_bind_listen_connect",
            &denied,
        )
        .is_err()
    );

    let completed = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: "a".repeat(32),
        checkpoint_sha256: digest.clone(),
        terminal_sha256: digest.clone(),
        retirement_sha256: digest.clone(),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: digest.clone(),
    };
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::native_tcp_bind_listen_connect",
            &completed,
        )
        .is_ok()
    );
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::authorization_uncertainty_retired",
            &completed,
        )
        .is_err()
    );
    let uncertain = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain,
        attempt_id: "a".repeat(32),
        checkpoint_sha256: digest.clone(),
        terminal_sha256: digest.clone(),
        retirement_sha256: digest.clone(),
        release_knowledge: PrivateReleaseKnowledgeV1::PossiblyReleased,
        exec: PrivateReleaseExecV1::NotObserved,
        native_observer_sha256: digest.clone(),
    };
    validate_fixed_case_observation(
        NativeRunStageV2::CandidateCapability,
        "private_tcp::authorization_uncertainty_retired",
        &uncertain,
    )
    .unwrap();
    let mut falsely_executed = uncertain;
    if let PrivateReleaseObservationV1::AllocatedRetired { exec, .. } = &mut falsely_executed {
        *exec = PrivateReleaseExecV1::Succeeded;
    }
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::authorization_uncertainty_retired",
            &falsely_executed,
        )
        .is_err()
    );
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::FinalPublic,
            "private_tcp::wrong_grant_profile_and_port_rejected",
            &completed,
        )
        .is_err()
    );
    let mut no_exec = completed;
    if let PrivateReleaseObservationV1::AllocatedRetired { exec, .. } = &mut no_exec {
        *exec = PrivateReleaseExecV1::NotObserved;
    }
    assert!(
        validate_fixed_case_observation(
            NativeRunStageV2::CandidateCapability,
            "private_tcp::native_tcp_bind_listen_connect",
            &no_exec,
        )
        .is_err()
    );
}

#[test]
fn candidate_attempt_readback_binds_digest_admission_and_terminal_branch() {
    let selector = "private_tcp::native_tcp_bind_listen_connect";
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
    let request_json = json!({
        "schema_version": 1,
        "stage": "candidate-capability",
        "selector": selector,
        "challenge": hex::encode(challenge),
        "result_key": key,
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "coordinator": {"pid": 123, "start_time": 456}
    });
    let request_bytes = serde_json::to_vec(&request_json).unwrap();
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
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
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
    let observation = PrivateReleaseObservationV1::AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
        attempt_id: attempt_id.clone(),
        checkpoint_sha256: checkpoint_digest.clone(),
        terminal_sha256: DiagnosticSha256::from_bytes([5; 32]),
        retirement_sha256: DiagnosticSha256::from_bytes([6; 32]),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: DiagnosticSha256::from_bytes([7; 32]),
    };
    let mut attempt_json = json!({
        "schema_version": 1,
        "result_key": key,
        "selector": selector,
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
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
        "candidate_exit_code": 0,
        "record_digest": DiagnosticSha256::from_bytes([0; 32])
    });
    let typed: ProtectedCandidateAttemptV1 = serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(typed.canonical_digest().unwrap());
    let bytes = serde_json::to_vec(&attempt_json).unwrap();
    let attempt =
        parse_protected_candidate_attempt(&bytes, &request, &observation, challenge).unwrap();
    assert_eq!(
        attempt.checkpoint_filter_sha256(),
        Some(&DiagnosticSha256::from_bytes([9; 32]))
    );
    assert_ne!(
        attempt.checkpoint_filter_sha256(),
        Some(&DiagnosticSha256::from_bytes([12; 32]))
    );

    let mut response_digest = Sha256::new();
    response_digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    response_digest.update(selector.as_bytes());
    response_digest.update([0]);
    response_digest.update(challenge);
    let response: [u8; 32] = response_digest.finalize().into();
    let terminal_record_digest: DiagnosticSha256 =
        serde_json::from_value(attempt_json["record_digest"].clone()).unwrap();
    let inspection = "{}";
    let inspection_digest = memcordon_core::workload_codec::hash_bytes(inspection.as_bytes());
    let report = serde_json::to_vec(&json!({
        "schema_version": 1,
        "selector": selector,
        "result_key": key,
        "attempt_id": attempt_id,
        "checkpoint_sha256": checkpoint_digest,
        "terminal_record_digest": terminal_record_digest,
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
        "response_sha256": memcordon_core::workload_codec::hash_bytes(&response),
        "candidate_exit_code": 0,
        "installed_inspection_json": inspection
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
        "terminal_record_digest": terminal_record_digest,
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
        "terminal_record_digest": terminal_record_digest,
        "candidate_exit_code": 0,
        "kernel_trace_sha256": memcordon_core::workload_codec::hash_bytes(&observer),
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
        .map(|(role, raw)| PrivateReleaseAttachmentV1 {
            role,
            size: raw.len() as u64,
            sha256: memcordon_core::workload_codec::hash_bytes(raw),
        })
        .collect();
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
        observation: PrivateReleaseObservationV1::AllocatedRetired {
            outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
            attempt_id: attempt_id.clone(),
            checkpoint_sha256: checkpoint_digest,
            terminal_sha256: memcordon_core::workload_codec::hash_bytes(&bytes),
            retirement_sha256: memcordon_core::workload_codec::hash_bytes(&attachments[4]),
            release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
            exec: PrivateReleaseExecV1::Succeeded,
            native_observer_sha256: memcordon_core::workload_codec::hash_bytes(&attachments[3]),
        },
        attachments: inventory,
    };
    result.validate().unwrap();
    let mut structural = StructuralProtectedNativeCaseV1 {
        result,
        candidate_request: request.clone(),
        candidate_request_bytes: request_bytes,
        attempt_record: Some(attempt),
        attempt_record_bytes: Some(bytes.clone()),
        fault_marker_bytes: None,
        checkpoint_gate_bytes: None,
        attachments,
    };
    validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).unwrap();
    let original_observer = structural.attachments[3].clone();
    let mut changed_observer: serde_json::Value =
        serde_json::from_slice(&original_observer).unwrap();
    changed_observer["settlement"]["target_pidfd_exited"] = json!(false);
    structural.attachments[3] = serde_json::to_vec(&changed_observer).unwrap();
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );
    changed_observer["settlement"]["target_pidfd_exited"] = json!(true);
    changed_observer["settlement"]["guardian_terminal"][17] = json!(2);
    structural.attachments[3] = serde_json::to_vec(&changed_observer).unwrap();
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );
    structural.attachments[3] = original_observer;
    let original_cleanup = structural.attachments[4].clone();
    let mut changed_cleanup: serde_json::Value = serde_json::from_slice(&original_cleanup).unwrap();
    changed_cleanup["kernel_trace_sha256"] = json!(DiagnosticSha256::from_bytes([8; 32]));
    structural.attachments[4] = serde_json::to_vec(&changed_cleanup).unwrap();
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );
    changed_cleanup["kernel_trace_sha256"] = json!(memcordon_core::workload_codec::hash_bytes(
        &structural.attachments[3]
    ));
    changed_cleanup["worker_pidfd_exited"] = json!(false);
    structural.attachments[4] = serde_json::to_vec(&changed_cleanup).unwrap();
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );
    changed_cleanup["worker_pidfd_exited"] = json!(true);
    changed_cleanup["coordinator"]["start_time"] = json!(999);
    structural.attachments[4] = serde_json::to_vec(&changed_cleanup).unwrap();
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );
    structural.attachments[4] = original_cleanup;
    assert!(
        validate_candidate_tcp_raw_attachments(
            &structural,
            challenge,
            &DiagnosticSha256::from_bytes([12; 32]),
        )
        .is_err()
    );
    structural.attachments[2][0] ^= 1;
    assert!(
        validate_candidate_tcp_raw_attachments(&structural, challenge, &inspection_digest).is_err()
    );

    attempt_json["installation_epoch"] = json!(DiagnosticSha256::from_bytes([9; 32]));
    let changed: ProtectedCandidateAttemptV1 =
        serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(changed.canonical_digest().unwrap());
    let altered = serde_json::to_vec(&attempt_json).unwrap();
    assert!(
        parse_protected_candidate_attempt(&altered, &request, &observation, challenge).is_err()
    );
    assert!(parse_protected_candidate_attempt(&bytes, &request, &observation, [0xcd; 32]).is_err());
}

#[test]
fn blocked_retirement_requires_retiring_journal_marker_and_exact_raw_joins() {
    const SELECTOR: &str = "private_tcp::retirement_failure_blocks_reuse";
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
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
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
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
        "installation_epoch": epoch,
        "candidate_manifest_sha256": manifest,
        "service_generation_sha256": service,
        "attempt_id": attempt_id,
        "coordinator": {"pid": 123, "start_time": 456},
        "phase": "retiring",
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
    let typed: ProtectedCandidateAttemptV1 = serde_json::from_value(attempt_json.clone()).unwrap();
    attempt_json["record_digest"] = json!(typed.canonical_digest().unwrap());
    let attempt_bytes = serde_json::to_vec(&attempt_json).unwrap();
    let terminal_record_digest: DiagnosticSha256 =
        serde_json::from_value(attempt_json["record_digest"].clone()).unwrap();
    #[derive(Serialize)]
    struct Marker<'a> {
        schema_version: u8,
        result_key: &'a DiagnosticSha256,
        attempt_id: &'a str,
        checkpoint_digest: &'a DiagnosticSha256,
        transition: &'static str,
    }
    let marker_bytes = serde_json::to_vec(&Marker {
        schema_version: 1,
        result_key: &key,
        attempt_id: &attempt_id,
        checkpoint_digest: &checkpoint_digest,
        transition: "retired-transition-blocked",
    })
    .unwrap();
    let marker_digest = memcordon_core::workload_codec::hash_bytes(&marker_bytes);
    let reuse_error =
        "MCSEALED-PRIVATE-RELEASE: attempt transition blocked: File exists (os error 17)";
    let transition_error = reuse_error;
    let observation = PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
        attempt_id: attempt_id.clone(),
        checkpoint_sha256: checkpoint_digest.clone(),
        terminal_sha256: memcordon_core::workload_codec::hash_bytes(&attempt_bytes),
        cleanup_failure_sha256: marker_digest.clone(),
        reuse_rejection_sha256: memcordon_core::workload_codec::hash_bytes(reuse_error.as_bytes()),
        release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
        exec: PrivateReleaseExecV1::Succeeded,
        native_observer_sha256: DiagnosticSha256::from_bytes([0; 32]),
    };
    let attempt =
        parse_protected_candidate_attempt(&attempt_bytes, &request, &observation, challenge)
            .unwrap();
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
        "terminal_record_digest": terminal_record_digest,
        "challenge_sha256": memcordon_core::workload_codec::hash_bytes(&challenge),
        "response_sha256": memcordon_core::workload_codec::hash_bytes(&response),
        "fault_marker_sha256": marker_digest,
        "transition_error": transition_error,
        "reuse_error": reuse_error,
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
        "terminal_record_digest": terminal_record_digest,
        "fault_marker_sha256": marker_digest,
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
        "terminal_record_digest": terminal_record_digest,
        "fault_marker_sha256": marker_digest,
        "reuse_rejection_sha256": memcordon_core::workload_codec::hash_bytes(reuse_error.as_bytes()),
        "kernel_trace_sha256": memcordon_core::workload_codec::hash_bytes(&observer),
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
        .map(|(role, raw)| PrivateReleaseAttachmentV1 {
            role,
            size: raw.len() as u64,
            sha256: memcordon_core::workload_codec::hash_bytes(raw),
        })
        .collect();
    let inspection_digest = memcordon_core::workload_codec::hash_bytes(b"{}");
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
        observation: PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
            attempt_id: attempt_id.clone(),
            checkpoint_sha256: checkpoint_digest,
            terminal_sha256: memcordon_core::workload_codec::hash_bytes(&attempt_bytes),
            cleanup_failure_sha256: marker_digest,
            reuse_rejection_sha256: memcordon_core::workload_codec::hash_bytes(
                reuse_error.as_bytes(),
            ),
            release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
            exec: PrivateReleaseExecV1::Succeeded,
            native_observer_sha256: memcordon_core::workload_codec::hash_bytes(&attachments[3]),
        },
        attachments: inventory,
    };
    result.validate().unwrap();
    let mut structural = StructuralProtectedNativeCaseV1 {
        result,
        candidate_request: request,
        candidate_request_bytes: request_bytes,
        attempt_record: Some(attempt),
        attempt_record_bytes: Some(attempt_bytes),
        fault_marker_bytes: Some(marker_bytes),
        checkpoint_gate_bytes: None,
        attachments,
    };
    validate_candidate_blocked_retirement_raw_attachments(
        &structural,
        challenge,
        &inspection_digest,
    )
    .unwrap();
    assert!(
        parse_protected_candidate_attempt(
            structural.attempt_record_bytes.as_ref().unwrap(),
            &structural.candidate_request,
            &PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                attempt_id: attempt_id.clone(),
                checkpoint_sha256: DiagnosticSha256::from_bytes([0; 32]),
                terminal_sha256: DiagnosticSha256::from_bytes([0; 32]),
                retirement_sha256: DiagnosticSha256::from_bytes([0; 32]),
                release_knowledge: PrivateReleaseKnowledgeV1::ExecObserved,
                exec: PrivateReleaseExecV1::Succeeded,
                native_observer_sha256: DiagnosticSha256::from_bytes([0; 32]),
            },
            challenge,
        )
        .is_err()
    );
    let original_marker = structural.fault_marker_bytes.clone();
    structural.fault_marker_bytes.as_mut().unwrap()[0] ^= 1;
    assert!(
        validate_candidate_blocked_retirement_raw_attachments(
            &structural,
            challenge,
            &inspection_digest,
        )
        .is_err()
    );
    structural.fault_marker_bytes = original_marker;
    let original_cleanup = structural.attachments[4].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&original_cleanup).unwrap();
    altered["worker_pidfd_exited"] = json!(false);
    structural.attachments[4] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_blocked_retirement_raw_attachments(
            &structural,
            challenge,
            &inspection_digest,
        )
        .is_err()
    );
    structural.attachments[4] = original_cleanup;
    let original_report = structural.attachments[1].clone();
    let mut altered: serde_json::Value = serde_json::from_slice(&original_report).unwrap();
    altered["reuse_error"] = json!("unrelated error");
    structural.attachments[1] = serde_json::to_vec(&altered).unwrap();
    assert!(
        validate_candidate_blocked_retirement_raw_attachments(
            &structural,
            challenge,
            &inspection_digest,
        )
        .is_err()
    );
}

#[test]
fn protected_readback_rejects_nonabsolute_or_noncanonical_paths() {
    assert!(read_protected_raw_case_file(Path::new("relative.json")).is_err());
    assert!(read_protected_raw_case_file(Path::new("/tmp/../tmp/result.json")).is_err());
}

#[test]
#[cfg(unix)]
fn protected_readback_rejects_unprotected_or_symlinked_test_files() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("result.json");
    std::fs::write(&source, b"{}").unwrap();
    assert!(read_protected_raw_case_file(&source).is_err());
    let link = directory.path().join("alias.json");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(read_protected_raw_case_file(&link).is_err());
}
