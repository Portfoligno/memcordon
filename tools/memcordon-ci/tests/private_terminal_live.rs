use memcordon_ci::private_protected_readback::{
    ProtectedCoordinatorIdentityV1, StructuralTerminalMidflightV1,
};
use memcordon_ci::private_terminal_live::{TERMINAL_JOIN_SELECTOR, validate_terminal_gate_bytes};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;

#[derive(Clone, Serialize)]
struct Gate<'a> {
    schema_version: u8,
    selector: &'a str,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    target: ProtectedCoordinatorIdentityV1,
    checkpoint_sha256: DiagnosticSha256,
    execution_record_digest: DiagnosticSha256,
    midflight_bytes_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
}

#[test]
fn terminal_midpoint_gate_rejects_substituted_checkpoint_and_target() {
    let challenge = [0x5a; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        TERMINAL_JOIN_SELECTOR,
        &challenge,
    )
    .unwrap();
    let filter = DiagnosticSha256::from_bytes([1; 32]);
    let midflight_bytes = b"fixed-protected-midflight-vector";
    let midpoint = StructuralTerminalMidflightV1 {
        attempt_id: "ab".repeat(16),
        target: ProtectedCoordinatorIdentityV1 {
            pid: 1234,
            start_time: 5678,
        },
        checkpoint_sha256: DiagnosticSha256::from_bytes([2; 32]),
        execution_record_digest: DiagnosticSha256::from_bytes([3; 32]),
        filter_sha256: filter.clone(),
        network_namespace_inode: 99,
    };
    let gate = Gate {
        schema_version: 1,
        selector: TERMINAL_JOIN_SELECTOR,
        result_key: key.clone(),
        challenge_sha256: hash_bytes(&challenge),
        attempt_id: midpoint.attempt_id.clone(),
        target: midpoint.target.clone(),
        checkpoint_sha256: midpoint.checkpoint_sha256.clone(),
        execution_record_digest: midpoint.execution_record_digest.clone(),
        midflight_bytes_sha256: hash_bytes(midflight_bytes),
        filter_sha256: filter.clone(),
    };
    let bytes = serde_json::to_vec(&gate).unwrap();
    assert_eq!(
        validate_terminal_gate_bytes(&bytes, &key, challenge, &midpoint, midflight_bytes, &filter,)
            .unwrap(),
        hash_bytes(&bytes)
    );
    assert!(
        validate_terminal_gate_bytes(
            &bytes,
            &key,
            [0x7b; 32],
            &midpoint,
            midflight_bytes,
            &filter,
        )
        .is_err()
    );
    let mut wrong = gate.clone();
    wrong.target.start_time = 0;
    assert!(
        validate_terminal_gate_bytes(
            &serde_json::to_vec(&wrong).unwrap(),
            &key,
            challenge,
            &midpoint,
            midflight_bytes,
            &filter,
        )
        .is_err()
    );
    let mut wrong = gate.clone();
    wrong.checkpoint_sha256 = DiagnosticSha256::from_bytes([4; 32]);
    assert!(
        validate_terminal_gate_bytes(
            &serde_json::to_vec(&wrong).unwrap(),
            &key,
            challenge,
            &midpoint,
            midflight_bytes,
            &filter,
        )
        .is_err()
    );
    let mut wrong = gate;
    wrong.midflight_bytes_sha256 = DiagnosticSha256::from_bytes([5; 32]);
    assert!(
        validate_terminal_gate_bytes(
            &serde_json::to_vec(&wrong).unwrap(),
            &key,
            challenge,
            &midpoint,
            midflight_bytes,
            &filter,
        )
        .is_err()
    );
}
