use memcordon_core::*;

fn request() -> WindowsLaunchRequestV2 {
    serde_json::from_value(serde_json::json!({"schema_version":4,"restart_attempt":0,
        "expected_provider_binding":{"generation":"provider","source_commit":"ab".repeat(20),"runtime_manifest_sha256":"cd".repeat(32)},
        "nonce":"original","command":{"program":[120],"arguments":[]},"environment":[],"current_directory":[67,58,92],
        "policy":{"memory_limit_bytes":null,"absolute_deadline_millis":null,"lifetime":"command","poll_interval_millis":10,"signal_grace_millis":10,"command_exit_grace_millis":10,"limit_grace_millis":10}})).unwrap()
}

#[test]
fn accepted_custody_requires_exact_request_provider_nonce_and_held_frontend() {
    let request = request();
    let bytes = serde_json::to_vec(&request).unwrap();
    let frontend = WindowsProcessIdentityV1 {
        process_id: 4,
        creation_time_100ns: 5,
    };
    let accepted = WindowsWorkloadAcceptedV1 {
        format: "memcordon.windows-workload-accepted".into(),
        revision: 1,
        provider: request.expected_provider_binding.clone(),
        frontend: frontend.clone(),
        attempt_id: "ef".repeat(32),
        nonce: request.nonce.clone(),
        request_sha256: hash_bytes(&bytes).into(),
        setup_deadline_millis: 10,
    };
    validate_windows_accepted_observation(&accepted, &bytes, &accepted.provider, &frontend)
        .unwrap();
    for field in ["provider", "pid", "birth", "nonce", "digest"] {
        let mut changed = accepted.clone();
        match field {
            "provider" => changed.provider.generation = BoundedText::new("other").unwrap(),
            "pid" => changed.frontend.process_id += 1,
            "birth" => changed.frontend.creation_time_100ns += 1,
            "nonce" => changed.nonce.push('x'),
            "digest" => changed.request_sha256 = "ab".repeat(32),
            _ => unreachable!(),
        }
        assert!(
            validate_windows_accepted_observation(&changed, &bytes, &accepted.provider, &frontend)
                .is_err(),
            "{field}"
        );
    }
    let mut changed = bytes.clone();
    changed.push(b' ');
    assert!(
        validate_windows_accepted_observation(&accepted, &changed, &accepted.provider, &frontend)
            .is_err()
    );
    let mut wrong_request = request;
    wrong_request.nonce.push('x');
    let bytes = serde_json::to_vec(&wrong_request).unwrap();
    let mut changed = accepted.clone();
    changed.request_sha256 = hash_bytes(&bytes).into();
    assert!(
        validate_windows_accepted_observation(&changed, &bytes, &accepted.provider, &frontend)
            .is_err()
    );
    assert!(
        validate_windows_accepted_observation(
            &accepted,
            &vec![0; WINDOWS_MAX_FRAME_BYTES + 1],
            &accepted.provider,
            &frontend
        )
        .is_err()
    );
}

#[test]
fn diagnostic_projection_is_bound_but_never_terminal_or_ack_authority() {
    let provider = request().expected_provider_binding;
    let journal = WindowsCausalDiagnosticsV1::default();
    let projection = ProviderFailureDiagnosticV1::from_journal(
        provider.clone(),
        &"ef".repeat(32),
        &"ab".repeat(32),
        &journal,
    )
    .unwrap();
    let validate = |value: Option<&ProviderFailureDiagnosticV1>,
                    availability: Option<DiagnosticProjectionAvailabilityV1>| {
        WindowsAttemptDiagnosticsV1 {
            schema_version: 4,
            challenge: "challenge".into(),
            attempt_id: "ef".repeat(32),
            request_sha256: "ab".repeat(32),
            provider_binding: provider.clone(),
            status: if value.is_some()
                || availability == Some(DiagnosticProjectionAvailabilityV1::Available)
            {
                WindowsAttemptDiagnosticsStatusV1::Observed
            } else if availability.is_some() {
                WindowsAttemptDiagnosticsStatusV1::Unavailable
            } else {
                WindowsAttemptDiagnosticsStatusV1::Denied
            },
            diagnostic_availability: availability,
            provider_failure: value.cloned().map(Box::new),
        }
        .validate_bound(
            4,
            "challenge",
            &"ef".repeat(32),
            &"ab".repeat(32),
            &provider,
        )
    };
    validate(None, None).unwrap();
    validate(
        None,
        Some(DiagnosticProjectionAvailabilityV1::RetentionExpired),
    )
    .unwrap();
    validate(
        Some(&projection),
        Some(DiagnosticProjectionAvailabilityV1::Available),
    )
    .unwrap();
    assert!(validate(None, Some(DiagnosticProjectionAvailabilityV1::Available)).is_err());
    assert!(validate(Some(&projection), None).is_err());
    let mut stale = projection.clone();
    stale.provider_binding.generation = BoundedText::new("stale").unwrap();
    stale.projection_sha256 = stale.canonical_digest();
    assert!(
        validate(
            Some(&stale),
            Some(DiagnosticProjectionAvailabilityV1::Available)
        )
        .is_err()
    );
    let mut tampered = projection.clone();
    tampered.request_sha256 = DiagnosticSha256::from_bytes([9; 32]);
    assert!(
        validate(
            Some(&tampered),
            Some(DiagnosticProjectionAvailabilityV1::Available)
        )
        .is_err()
    );
    let ordinary = WindowsProviderResponseV4::recovery_attempt_unavailable(
        &"ef".repeat(32),
        "challenge",
        "pending",
        true,
    )
    .unwrap();
    let old = serde_json::to_value(&ordinary).unwrap();
    assert!(old.get("provider_failure").is_none());
    assert!(old.get("diagnostic_availability").is_none());
    let reply = WindowsAttemptDiagnosticsV1 {
        schema_version: 4,
        challenge: "challenge".into(),
        attempt_id: "ef".repeat(32),
        request_sha256: "ab".repeat(32),
        provider_binding: provider,
        status: WindowsAttemptDiagnosticsStatusV1::Observed,
        diagnostic_availability: Some(DiagnosticProjectionAvailabilityV1::Available),
        provider_failure: Some(Box::new(projection)),
    };
    let response = WindowsProviderResponseV4::AttemptDiagnostics(reply.clone());
    let wire = serde_json::to_vec(&response).unwrap();
    assert!(wire.len() < MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES);
    assert_eq!(
        windows_response_frame_limit(&wire).unwrap(),
        MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
    );
    let decoded: WindowsProviderResponseV4 = serde_json::from_slice(&wire).unwrap();
    assert!(matches!(
        decoded,
        WindowsProviderResponseV4::AttemptDiagnostics(_)
    ));
    for key in [
        "receipt",
        "terminal_authority_json",
        "acknowledged",
        "terminal_response_sha256",
    ] {
        assert!(serde_json::to_value(&response).unwrap().get(key).is_none());
    }
    assert!(response.terminal_authority_json().is_err());
    assert!(
        WindowsLauncherResponseV4::AttemptDiagnostics(reply)
            .terminal_authority_json()
            .is_err()
    );
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&ordinary.terminal_authority_json().unwrap())
            .unwrap(),
        old
    );
}
