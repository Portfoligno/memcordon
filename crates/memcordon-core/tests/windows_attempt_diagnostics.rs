use memcordon_core::*;

fn provider() -> PublicProviderBindingV1 {
    PublicProviderBindingV1 {
        generation: BoundedText::new("provider").unwrap(),
        source_commit: BoundedText::new(&"ab".repeat(20)).unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    }
}
fn request() -> WindowsProviderRequestV4 {
    WindowsProviderRequestV4::ObserveAttemptDiagnostics {
        schema_version: 4,
        attempt_id: "ab".repeat(32),
        nonce: "nonce".into(),
        request_sha256: "cd".repeat(32),
        challenge: "challenge".into(),
    }
}
fn reply() -> WindowsAttemptDiagnosticsV1 {
    WindowsAttemptDiagnosticsV1 {
        schema_version: 4,
        challenge: "challenge".into(),
        attempt_id: "ab".repeat(32),
        request_sha256: "cd".repeat(32),
        provider_binding: provider(),
        status: WindowsAttemptDiagnosticsStatusV1::Denied,
        diagnostic_availability: None,
        provider_failure: None,
    }
}
fn valid(value: &WindowsAttemptDiagnosticsV1) -> Result<(), String> {
    value.validate_bound(
        4,
        "challenge",
        &"ab".repeat(32),
        &"cd".repeat(32),
        &provider(),
    )
}

#[test]
fn request_is_closed_bounded_and_contains_no_client_claimed_owner() {
    let source = request();
    let wire = serde_json::to_vec(&source).unwrap();
    let decoded: WindowsProviderRequestV4 = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded, source);
    validate_windows_attempt_diagnostics_request(
        4,
        &"ab".repeat(32),
        "nonce",
        &"cd".repeat(32),
        "challenge",
    )
    .unwrap();
    for (schema, attempt, nonce, request, challenge) in [
        (
            3,
            "ab".repeat(32),
            "nonce".into(),
            "cd".repeat(32),
            "challenge".into(),
        ),
        (
            4,
            "ab".repeat(31),
            "nonce".into(),
            "cd".repeat(32),
            "challenge".into(),
        ),
        (
            4,
            "ab".repeat(32),
            String::new(),
            "cd".repeat(32),
            "challenge".into(),
        ),
        (
            4,
            "ab".repeat(32),
            "nonce".into(),
            "ZZ".repeat(32),
            "challenge".into(),
        ),
        (
            4,
            "ab".repeat(32),
            "nonce".into(),
            "cd".repeat(32),
            "x".repeat(129),
        ),
    ] {
        assert!(
            validate_windows_attempt_diagnostics_request(
                schema, &attempt, &nonce, &request, &challenge
            )
            .is_err()
        );
    }
    let value = serde_json::to_value(&source).unwrap();
    for field in ["caller", "token", "path", "handle"] {
        let mut unsafe_claim = value.clone();
        unsafe_claim[field] = true.into();
        assert!(
            serde_json::from_value::<WindowsProviderRequestV4>(unsafe_claim).is_err(),
            "{field}"
        );
    }
    let mut oversized = value;
    oversized["nonce"] = "x".repeat(129).into();
    assert!(serde_json::from_value::<WindowsProviderRequestV4>(oversized).is_err());
    let duplicate = String::from_utf8(wire).unwrap().replacen(
        "\"nonce\":",
        "\"nonce\":\"duplicate\",\"nonce\":",
        1,
    );
    assert!(serde_json::from_slice::<WindowsProviderRequestV4>(duplicate.as_bytes()).is_err());
}

#[test]
fn reply_requires_exact_binding_and_denied_or_unavailable_never_carries_projection() {
    let denied = reply();
    valid(&denied).unwrap();
    let mut unavailable = denied.clone();
    unavailable.status = WindowsAttemptDiagnosticsStatusV1::Unavailable;
    unavailable.diagnostic_availability =
        Some(DiagnosticProjectionAvailabilityV1::RetentionExpired);
    valid(&unavailable).unwrap();
    let projection = ProviderFailureDiagnosticV1::from_journal(
        provider(),
        &denied.attempt_id,
        &denied.request_sha256,
        &WindowsCausalDiagnosticsV1::default(),
    )
    .unwrap();
    let mut observed = denied.clone();
    observed.status = WindowsAttemptDiagnosticsStatusV1::Observed;
    observed.provider_failure = Some(Box::new(projection));
    observed.diagnostic_availability = Some(DiagnosticProjectionAvailabilityV1::Available);
    valid(&observed).unwrap();
    for status in [
        WindowsAttemptDiagnosticsStatusV1::Denied,
        WindowsAttemptDiagnosticsStatusV1::Unavailable,
    ] {
        let mut invalid = observed.clone();
        invalid.status = status;
        assert!(valid(&invalid).is_err());
    }
    for field in [
        "schema",
        "challenge",
        "attempt",
        "request",
        "provider",
        "digest",
        "missing",
    ] {
        let mut changed = observed.clone();
        match field {
            "schema" => changed.schema_version += 1,
            "challenge" => changed.challenge.push('x'),
            "attempt" => changed.attempt_id = "ef".repeat(32),
            "request" => changed.request_sha256 = "ef".repeat(32),
            "provider" => changed.provider_binding.generation = BoundedText::new("other").unwrap(),
            "digest" => {
                changed.provider_failure.as_mut().unwrap().projection_sha256 =
                    DiagnosticSha256::from_bytes([0; 32])
            }
            "missing" => changed.provider_failure = None,
            _ => unreachable!(),
        }
        assert!(valid(&changed).is_err(), "{field}");
    }
    let mut hidden = serde_json::to_value(denied).unwrap();
    hidden["detail"] = "record existence".into();
    assert!(serde_json::from_value::<WindowsAttemptDiagnosticsV1>(hidden).is_err());
}

#[test]
fn diagnostic_responses_are_bounded_nonterminal_and_have_no_authority_encoding() {
    let public = WindowsProviderResponseV4::AttemptDiagnostics(reply());
    let private = WindowsLauncherResponseV4::AttemptDiagnostics(reply());
    let bytes = serde_json::to_vec(&public).unwrap();
    assert_eq!(
        windows_response_frame_limit(&bytes).unwrap(),
        MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
    );
    assert!(public.terminal_authority_json().is_err());
    assert!(private.terminal_authority_json().is_err());
    let decoded: WindowsProviderResponseV4 = serde_json::from_slice(&bytes).unwrap();
    assert!(matches!(
        decoded,
        WindowsProviderResponseV4::AttemptDiagnostics(_)
    ));
    let wire = serde_json::to_value(public).unwrap();
    for field in [
        "terminal",
        "receipt",
        "delivery",
        "acknowledgement",
        "guardian",
        "handle",
        "nonce",
    ] {
        assert!(wire.get(field).is_none(), "{field}");
    }
    let old = WindowsProviderResponseV4::recovery_attempt_unavailable(
        &"ab".repeat(32),
        "challenge",
        "pending",
        true,
    )
    .unwrap();
    let oldwire = serde_json::to_value(old).unwrap();
    assert!(oldwire.get("provider_failure").is_none());
    assert!(oldwire.get("diagnostic_availability").is_none());
}
