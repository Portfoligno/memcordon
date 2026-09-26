use memcordon_ci::private_public_epoch_join::{
    ExpectedPublicSpoofV1, ExpectedSameArchiveEpochV1, validate_protected_public_spoof_v1,
    validate_same_archive_epoch_transition_v1,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn same_archive_epoch_transition_rejects_unchanged_generation_or_new_archive() {
    let e0 = DiagnosticSha256::from_bytes([1; 32]);
    let e1 = DiagnosticSha256::from_bytes([2; 32]);
    let h0 = DiagnosticSha256::from_bytes([3; 32]);
    let h1 = DiagnosticSha256::from_bytes([4; 32]);
    let archive = DiagnosticSha256::from_bytes([5; 32]);
    let different = DiagnosticSha256::from_bytes([6; 32]);
    let mut expected = ExpectedSameArchiveEpochV1 {
        e0_installation_epoch: &e0,
        e1_installation_epoch: &e1,
        e0_h1_receipt_sha256: &h0,
        e1_h1_receipt_sha256: &h1,
        e0_challenge: "11",
        e1_challenge: "22",
        protected_archive_sha256: &archive,
        upgrade_archive_sha256: &archive,
    };
    expected.e0_challenge = "1111111111111111111111111111111111111111111111111111111111111111";
    expected.e1_challenge = "2222222222222222222222222222222222222222222222222222222222222222";
    validate_same_archive_epoch_transition_v1(&expected).unwrap();
    expected.e1_installation_epoch = &e0;
    assert!(validate_same_archive_epoch_transition_v1(&expected).is_err());
    expected.e1_installation_epoch = &e1;
    expected.e1_h1_receipt_sha256 = &h0;
    assert!(validate_same_archive_epoch_transition_v1(&expected).is_err());
    expected.e1_h1_receipt_sha256 = &h1;
    expected.upgrade_archive_sha256 = &different;
    assert!(validate_same_archive_epoch_transition_v1(&expected).is_err());
    expected.upgrade_archive_sha256 = &archive;
    expected.e1_challenge = expected.e0_challenge;
    assert!(validate_same_archive_epoch_transition_v1(&expected).is_err());
}

fn rejection(code: &str, created: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version":1, "code":code, "phase":"request-validation",
        "detail":"authenticated peer differs", "os_code":null,
        "target_created":created, "target_released":false,
        "cleanup":{"attempted":false,"direct_child_reaped":false,"workload_empty":null,
            "helpers_reaped":false,"containment_removed":false,"sealed_boundary_retired":false,"errors":[]}
    })).unwrap()
}

#[test]
fn protected_spoof_requires_real_distinct_peer_and_exact_e1_subjects() {
    let selector = "private_tcp::caller_identity_and_epoch_bound";
    let challenge = "11".repeat(32);
    let result_key =
        private_release_case_key_v1(PrivateReleaseStageV1::FinalPublic, selector, &[0x11; 32])
            .unwrap();
    let epoch = DiagnosticSha256::from_bytes([2; 32]);
    let h1 = DiagnosticSha256::from_bytes([3; 32]);
    let request = b"exact protected spoof request";
    let grant_decision =
        b"{\"schema_version\":1,\"evidence_scope\":\"lease-bound-v2-grant-decision\"}";
    let code = "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED";
    let rejected = rejection(code, false);
    let expected = ExpectedPublicSpoofV1 {
        selector,
        challenge: &challenge,
        result_key: &result_key,
        authorized_uid: 1000,
        unauthorized_uid: 1001,
        unauthorized_gid: 1001,
        registered_peer_pid: 99,
        registered_peer_start_ticks: 500,
        installation_epoch: &epoch,
        active_h1_receipt_sha256: &h1,
        request_bytes: request,
        grant_decision_bytes: grant_decision,
        rejection_code: code,
    };
    let record = serde_json::json!({
        "schema_version":1,"selector":selector,"challenge":challenge,"result_key":result_key,
        "authenticated_peer_uid":1001,"authenticated_peer_gid":1001,
        "authenticated_peer_pid":99,"authenticated_peer_start_ticks":500,
        "authorized_uid":1000,
        "installation_epoch":epoch,"active_h1_receipt_sha256":h1,
        "contract_file_sha256":hash_bytes(request),
        "grant_decision_sha256":hash_bytes(grant_decision),
        "request_sha256":hash_bytes(request),"rejection_sha256":hash_bytes(&rejected),
        "rejection_code":code,"durable_attempt_record_absent":true
    });
    let bytes = serde_json::to_vec(&record).unwrap();
    validate_protected_public_spoof_v1(&bytes, &rejected, &expected).unwrap();
    for (field, value) in [
        ("authenticated_peer_uid", serde_json::json!(1000)),
        ("authenticated_peer_gid", serde_json::json!(1002)),
        ("authenticated_peer_pid", serde_json::json!(100)),
        ("authenticated_peer_start_ticks", serde_json::json!(501)),
        (
            "installation_epoch",
            serde_json::json!(DiagnosticSha256::from_bytes([4; 32])),
        ),
        ("durable_attempt_record_absent", serde_json::json!(false)),
        (
            "rejection_sha256",
            serde_json::json!(DiagnosticSha256::from_bytes([5; 32])),
        ),
        (
            "grant_decision_sha256",
            serde_json::json!(DiagnosticSha256::from_bytes([6; 32])),
        ),
    ] {
        let mut tampered = record.clone();
        tampered[field] = value;
        assert!(
            validate_protected_public_spoof_v1(
                &serde_json::to_vec(&tampered).unwrap(),
                &rejected,
                &expected
            )
            .is_err(),
            "{field}"
        );
    }
    assert!(validate_protected_public_spoof_v1(&bytes, &rejection(code, true), &expected).is_err());
    assert!(validate_protected_public_spoof_v1(b"{}", &rejected, &expected).is_err());
}
