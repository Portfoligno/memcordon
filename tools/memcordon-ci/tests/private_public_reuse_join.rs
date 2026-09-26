use memcordon_ci::private_public_reuse_join::{
    ExpectedPublicReuseV1, validate_protected_public_reuse_v1,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

fn rejection(code: &str, created: bool, failure: bool) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version":1,"code":code,"phase":if failure {"retirement"} else {"request-validation"},
        "detail":"protected reuse predicate","os_code":null,
        "target_created":created,"target_released":failure,
        "cleanup":{"attempted":failure,"direct_child_reaped":false,"workload_empty":null,
            "helpers_reaped":false,"containment_removed":false,"sealed_boundary_retired":false,
            "errors":if failure {vec!["namespace fd held"]} else {Vec::<&str>::new()}}
    })).unwrap()
}

#[test]
fn reuse_transcript_requires_failure_before_block_and_fd_close_before_recovery() {
    let key = DiagnosticSha256::from_bytes([1; 32]);
    let epoch = DiagnosticSha256::from_bytes([2; 32]);
    let h1 = DiagnosticSha256::from_bytes([3; 32]);
    let failure_code = "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE";
    let blocked_code = "MCSEALED-PRIVATE-REUSE-BLOCKED";
    let failure = rejection(failure_code, true, true);
    let blocked = rejection(blocked_code, false, false);
    let request = b"second distinct launch request";
    let recovery = b"protected later cleanup success";
    let expected = ExpectedPublicReuseV1 {
        result_key: &key,
        boot_id: "boot-a",
        installation_epoch: &epoch,
        active_h1_receipt_sha256: &h1,
        first_attempt_id: "attempt-one",
        second_attempt_id: "attempt-two",
        cleanup_failure_bytes: &failure,
        blocked_request_bytes: request,
        blocked_rejection_bytes: &blocked,
        recovered_cleanup_bytes: recovery,
        expected_failure_code: failure_code,
        expected_blocked_code: blocked_code,
    };
    let record = serde_json::json!({
        "schema_version":1,"selector":"private_tcp::retirement_failure_blocks_reuse",
        "result_key":key,"boot_id":"boot-a","installation_epoch":epoch,"active_h1_receipt_sha256":h1,
        "first_attempt_id":"attempt-one","second_attempt_id":"attempt-two",
        "cleanup_failure_sha256":hash_bytes(&failure),
        "durable_incomplete_state_sha256":DiagnosticSha256::from_bytes([4;32]),
        "namespace_inode":71,"holder_pid":44,"holder_start_time":500,"held_fd":7,
        "failure_boot_nanos":100,"blocked_request_sha256":hash_bytes(request),
        "blocked_rejection_sha256":hash_bytes(&blocked),"blocked_boot_nanos":200,
        "namespace_fd_closed_boot_nanos":300,"recovered_cleanup_sha256":hash_bytes(recovery),
        "recovery_boot_nanos":400,"durable_attempt_record_absent_after_recovery":true
    });
    let bytes = serde_json::to_vec(&record).unwrap();
    validate_protected_public_reuse_v1(&bytes, &expected).unwrap();
    for (field, value) in [
        ("second_attempt_id", serde_json::json!("attempt-one")),
        ("blocked_boot_nanos", serde_json::json!(50)),
        ("namespace_fd_closed_boot_nanos", serde_json::json!(150)),
        ("recovery_boot_nanos", serde_json::json!(250)),
        (
            "durable_incomplete_state_sha256",
            serde_json::json!(DiagnosticSha256::from_bytes([0; 32])),
        ),
        (
            "durable_attempt_record_absent_after_recovery",
            serde_json::json!(false),
        ),
        (
            "blocked_rejection_sha256",
            serde_json::json!(DiagnosticSha256::from_bytes([9; 32])),
        ),
    ] {
        let mut tampered = record.clone();
        tampered[field] = value;
        assert!(
            validate_protected_public_reuse_v1(&serde_json::to_vec(&tampered).unwrap(), &expected)
                .is_err(),
            "{field}"
        );
    }
    assert!(validate_protected_public_reuse_v1(b"{}", &expected).is_err());
    let fake_failure = rejection(failure_code, false, false);
    let fake_expected = ExpectedPublicReuseV1 {
        cleanup_failure_bytes: &fake_failure,
        ..expected
    };
    assert!(validate_protected_public_reuse_v1(&bytes, &fake_expected).is_err());
    let mut unreleased: serde_json::Value = serde_json::from_slice(&failure).unwrap();
    unreleased["target_released"] = serde_json::json!(false);
    let unreleased = serde_json::to_vec(&unreleased).unwrap();
    let fake_expected = ExpectedPublicReuseV1 {
        cleanup_failure_bytes: &unreleased,
        ..expected
    };
    let mut unreleased_record = record.clone();
    unreleased_record["cleanup_failure_sha256"] = serde_json::json!(hash_bytes(&unreleased));
    assert!(
        validate_protected_public_reuse_v1(
            &serde_json::to_vec(&unreleased_record).unwrap(),
            &fake_expected,
        )
        .is_err()
    );
}
