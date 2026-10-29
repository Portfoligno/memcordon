use memcordon_core::{WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION, WindowsProviderResponseV4};

#[test]
fn unavailable_recovery_preserves_context_without_terminal_authority() {
    let attempt = "ab".repeat(32);
    let challenge = "fresh-recovery-challenge";
    let native = "launcher response read failed: native pipe error 233";
    let response =
        WindowsProviderResponseV4::recovery_attempt_unavailable(&attempt, challenge, native, true)
            .unwrap();
    let bytes = serde_json::to_vec(&response).unwrap();
    let decoded: WindowsProviderResponseV4 = serde_json::from_slice(&bytes).unwrap();
    let WindowsProviderResponseV4::RecoveryAttemptUnavailable {
        schema_version,
        attempt_id,
        challenge: returned_challenge,
        detail,
    } = decoded
    else {
        panic!("preparation failure must remain unavailable");
    };
    assert_eq!(schema_version, WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION);
    assert_eq!(attempt_id, attempt);
    assert_eq!(returned_challenge, challenge);
    assert_eq!(detail, native);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for authority in [
        "receipt",
        "cleanup_complete",
        "terminal_response_sha256",
        "acknowledged",
        "terminal_disposition",
    ] {
        assert!(value.get(authority).is_none(), "{authority}");
    }
}

#[test]
fn unelevated_recovery_never_discloses_native_preparation_detail() {
    let response = WindowsProviderResponseV4::recovery_attempt_unavailable(
        &"cd".repeat(32),
        "original-challenge",
        "private-other-attempt-owner-path: native error 5",
        false,
    )
    .unwrap();
    let WindowsProviderResponseV4::RecoveryAttemptUnavailable { detail, .. } = response else {
        panic!("unavailable must not become terminal authority");
    };
    assert_eq!(detail, "recovery preparation unavailable");
    assert!(!detail.contains("private-other-attempt"));
}

#[test]
fn unavailable_recovery_bounds_utf8_detail_and_rejects_invalid_context() {
    let attempt = "ef".repeat(32);
    let challenge = "bound-challenge";
    let long = "λ".repeat(900);
    let response =
        WindowsProviderResponseV4::recovery_attempt_unavailable(&attempt, challenge, &long, true)
            .unwrap();
    let WindowsProviderResponseV4::RecoveryAttemptUnavailable { detail, .. } = &response else {
        panic!("bounded detail must remain unavailable");
    };
    assert!(detail.len() <= 1024);
    assert!(detail.starts_with('λ'));
    assert!(detail.contains("truncated"));
    let roundtrip: WindowsProviderResponseV4 =
        serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
    assert!(matches!(
        roundtrip,
        WindowsProviderResponseV4::RecoveryAttemptUnavailable { .. }
    ));
    for (invalid_attempt, invalid_challenge) in [
        (String::new(), challenge.into()),
        ("a".repeat(129), challenge.into()),
        (attempt.clone(), String::new()),
        (attempt.clone(), "c".repeat(129)),
    ] {
        assert!(
            WindowsProviderResponseV4::recovery_attempt_unavailable(
                &invalid_attempt,
                &invalid_challenge,
                "native failure",
                true,
            )
            .is_err()
        );
    }
    assert!(
        WindowsProviderResponseV4::recovery_attempt_unavailable(&attempt, challenge, "", true,)
            .is_err()
    );
}
