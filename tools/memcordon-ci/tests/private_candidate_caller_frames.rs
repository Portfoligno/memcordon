pub use memcordon_ci::{CiError, Result, private_observer_session};
#[path = "../src/private_candidate_caller_frames.rs"]
mod private_candidate_caller_frames;

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::provider_rejection_wire::{
    RejectionCleanupV1, RejectionPhaseV1, RejectionWireV1,
};
use memcordon_core::workload_codec::hash_bytes;
use private_candidate_caller_frames::{
    CallerIdentityV1, CandidateCallerFrameReadbackV1, parse_candidate_caller_frames_v1,
};
use serde::Serialize;

#[derive(Serialize)]
struct Request {
    schema_version: u8,
    stage: String,
    selector: String,
    challenge: [u8; 32],
    result_key: DiagnosticSha256,
}
fn frame(kind: u16, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&4u16.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    let total = 2 + 2 + 4 + 16 + 16 + hash_bytes(payload).bytes().len() + payload.len();
    bytes.extend_from_slice(&(total as u32).to_be_bytes());
    bytes.extend_from_slice(&[1; 16]);
    bytes.extend_from_slice(&[2; 16]);
    bytes.extend_from_slice(hash_bytes(payload).bytes());
    bytes.extend_from_slice(payload);
    bytes
}
fn fixture() -> CandidateCallerFrameReadbackV1 {
    let mut challenge = b"memcordon-private-caller-spoof-v1\0".to_vec();
    challenge.extend_from_slice(&[3; 32]);
    let challenge = *hash_bytes(&challenge).bytes();
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        "private_tcp::caller_identity_and_epoch_bound",
        &challenge,
    )
    .unwrap();
    let request = serde_json::to_vec(&Request {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: "private_tcp::caller_identity_and_epoch_bound".into(),
        challenge,
        result_key: key.clone(),
    })
    .unwrap();
    let response = serde_json::to_vec(&RejectionWireV1 {
        workload_admission: None,
        schema_version: 1,
        code: "MCSEALED-PRIVATE-RELEASE-AUTHORIZATION".into(),
        phase: RejectionPhaseV1::RequestValidation,
        detail: "unprivileged caller is not authorized for the private release route".into(),
        os_code: None,
        target_created: false,
        target_released: false,
        cleanup: RejectionCleanupV1 {
            attempted: false,
            direct_child_reaped: false,
            workload_empty: None,
            helpers_reaped: false,
            containment_removed: false,
            sealed_boundary_retired: false,
            errors: Vec::new(),
        },
    })
    .unwrap();
    CandidateCallerFrameReadbackV1 {
        caller: CallerIdentityV1 {
            pid: 42,
            start_time: 100,
        },
        caller_uid: 1001,
        caller_gid: 1002,
        control_group_gid: 1003,
        spoof_result_key: key,
        rejection_sha256: hash_bytes(&response),
        request_frame_bytes: frame(15, &request),
        response_frame_bytes: frame(106, &response),
    }
}

#[test]
fn parses_original_exchange_without_creating_authority() {
    let source = fixture();
    let bytes = serde_json::to_vec(&source).unwrap();
    assert_eq!(
        parse_candidate_caller_frames_v1(&bytes, &[3; 32], 1001, 1002).unwrap(),
        source
    );
    assert!(parse_candidate_caller_frames_v1(&bytes, &[4; 32], 1001, 1002).is_err());
    assert!(parse_candidate_caller_frames_v1(&bytes, &[3; 32], 1004, 1002).is_err());
}

#[test]
fn exact_frame_digest_context_length_and_message_kind_are_required() {
    for (offset, value) in [(0, 1), (3, 105), (7, 0), (8, 3), (40, 9)] {
        let mut source = fixture();
        source.response_frame_bytes[offset] = value;
        assert!(
            parse_candidate_caller_frames_v1(
                &serde_json::to_vec(&source).unwrap(),
                &[3; 32],
                1001,
                1002
            )
            .is_err()
        );
    }
    let mut source = fixture();
    source.request_frame_bytes.push(0);
    assert!(
        parse_candidate_caller_frames_v1(
            &serde_json::to_vec(&source).unwrap(),
            &[3; 32],
            1001,
            1002
        )
        .is_err()
    );
    let mut source = fixture();
    source.response_frame_bytes.truncate(32);
    assert!(
        parse_candidate_caller_frames_v1(
            &serde_json::to_vec(&source).unwrap(),
            &[3; 32],
            1001,
            1002
        )
        .is_err()
    );
}
