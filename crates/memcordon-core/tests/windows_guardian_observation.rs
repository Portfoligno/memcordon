use memcordon_core::{
    BoundedText, DiagnosticSha256, PublicProviderBindingV1, WindowsGuardianAttemptObservation,
    WindowsProcessIdentityV1, result_v1::ProviderAttemptAssociationV1,
};

fn observation() -> WindowsGuardianAttemptObservation {
    WindowsGuardianAttemptObservation {
        format: "memcordon.windows-live-guardian-observation".into(),
        revision: 1,
        challenge: BoundedText::new("independent-query-challenge").unwrap(),
        guardian_identity: WindowsProcessIdentityV1 {
            process_id: 42,
            creation_time_100ns: 1234,
        },
        association: ProviderAttemptAssociationV1 {
            provider: PublicProviderBindingV1 {
                generation: BoundedText::new("installed-generation").unwrap(),
                source_commit: BoundedText::new("c21430372b4c7b37982259f93aac757f605b7f35")
                    .unwrap(),
                runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
            },
            attempt_id: DiagnosticSha256::from_bytes([2; 32]),
            request_sha256: DiagnosticSha256::from_bytes([3; 32]),
        },
    }
}

fn failure() -> memcordon_core::WindowsReadOnlyQueryFailure {
    memcordon_core::WindowsReadOnlyQueryFailure::new(
        memcordon_core::WindowsReadOnlyQueryOperation::GuardianObservation,
        observation().challenge,
        observation().association.provider,
        memcordon_core::WindowsReadOnlyQueryPhase::QueryHandler,
        "guardian-record-read: Access is denied. (os error 5)",
    )
    .unwrap()
}

#[test]
fn authenticated_owner_query_roundtrip_keeps_public_facts_and_private_frame_bounds() {
    use memcordon_core::{WindowsLauncherRequestV3, WindowsLauncherResponseV3};

    let expected = observation();
    let request = WindowsLauncherRequestV3::ObserveGuardianAttempt {
        schema_version: memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION,
        challenge: expected.challenge.clone(),
        guardian_identity: expected.guardian_identity.clone(),
    };
    let bytes = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        serde_json::from_slice::<WindowsLauncherRequestV3>(&bytes).unwrap(),
        request
    );
    assert!(serde_json::from_slice::<memcordon_core::WindowsLauncherRequestV1>(&bytes).is_err());
    let mut oversized = serde_json::to_value(&request).unwrap();
    fn above_bound<const N: usize>(_: &BoundedText<N>) -> String {
        "x".repeat(N + 1)
    }
    oversized["challenge"] = serde_json::json!(above_bound(&expected.challenge));
    assert!(
        serde_json::from_slice::<WindowsLauncherRequestV3>(
            &serde_json::to_vec(&oversized).unwrap()
        )
        .is_err()
    );
    let response = WindowsLauncherResponseV3::GuardianAttemptObservation(expected.clone());
    let bytes = serde_json::to_vec(&response).unwrap();
    assert_eq!(
        memcordon_core::windows_launcher_response_frame_limit(&bytes).unwrap(),
        WindowsGuardianAttemptObservation::MAX_FRAME_BYTES
    );
    let bound = WindowsGuardianAttemptObservation::from_launcher_query_response(
        serde_json::from_slice(&bytes).unwrap(),
        expected.challenge.as_str(),
        &expected.association.provider,
        &expected.guardian_identity,
    )
    .unwrap();
    // The public hop preserves its existing dedicated shape and native facts.
    assert_eq!(bound, expected);
    assert_eq!(
        WindowsGuardianAttemptObservation::from_query_wire_json(
            &serde_json::to_vec(&bound).unwrap(),
            expected.challenge.as_str(),
            &expected.association.provider,
        )
        .unwrap(),
        expected
    );
}

#[test]
fn owner_reply_rejects_substituted_challenge_provider_and_both_guardian_identity_fields() {
    use memcordon_core::WindowsLauncherResponseV3;

    let expected = observation();
    let validate = |value| {
        let bytes = serde_json::to_vec(&WindowsLauncherResponseV3::GuardianAttemptObservation(
            value,
        ))
        .unwrap();
        WindowsGuardianAttemptObservation::from_launcher_query_response(
            serde_json::from_slice(&bytes).unwrap(),
            expected.challenge.as_str(),
            &expected.association.provider,
            &expected.guardian_identity,
        )
    };
    assert_eq!(validate(expected.clone()).unwrap(), expected);
    for field in ["challenge", "provider", "pid", "birth", "namespace"] {
        let mut altered = expected.clone();
        match field {
            "challenge" => altered.challenge = BoundedText::new("other-query").unwrap(),
            "provider" => {
                altered.association.provider.runtime_manifest_sha256 =
                    DiagnosticSha256::from_bytes([9; 32])
            }
            "pid" => altered.guardian_identity.process_id += 1,
            "birth" => altered.guardian_identity.creation_time_100ns += 1,
            "namespace" => altered.format = "unbound-observation".into(),
            _ => unreachable!(),
        }
        assert!(validate(altered).is_err(), "{field}");
    }
}

#[test]
fn private_owner_failure_never_becomes_observation_or_exposes_unbound_native_detail() {
    use memcordon_core::{WindowsLauncherResponseV3, WindowsReadOnlyQueryFailure};

    let expected = observation();
    let value = failure();
    let bytes = serde_json::to_vec(&WindowsLauncherResponseV3::ReadOnlyQueryFailure(
        value.clone(),
    ))
    .unwrap();
    assert_eq!(
        memcordon_core::windows_launcher_response_frame_limit(&bytes).unwrap(),
        WindowsReadOnlyQueryFailure::MAX_FRAME_BYTES
    );
    let validate = |response| {
        WindowsGuardianAttemptObservation::from_launcher_query_response(
            response,
            expected.challenge.as_str(),
            &expected.association.provider,
            &expected.guardian_identity,
        )
    };
    let error = validate(serde_json::from_slice(&bytes).unwrap()).unwrap_err();
    assert!(error.contains(value.detail.as_str()));
    for field in ["operation", "challenge", "provider"] {
        let mut altered = value.clone();
        match field {
            "operation" => {
                altered.operation =
                    memcordon_core::WindowsReadOnlyQueryOperation::RecoveryConvergence
            }
            "challenge" => altered.challenge = BoundedText::new("other-query").unwrap(),
            "provider" => {
                altered.provider.runtime_manifest_sha256 = DiagnosticSha256::from_bytes([9; 32])
            }
            _ => unreachable!(),
        }
        let error = validate(WindowsLauncherResponseV3::ReadOnlyQueryFailure(altered)).unwrap_err();
        assert!(!error.contains(value.detail.as_str()), "{field}");
    }
    assert!(
        validate(WindowsLauncherResponseV3::Membership {
            schema_version: memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION,
            attempt_id: "unrelated".into(),
            nonce: "unrelated".into(),
            request_sha256: "unrelated".into(),
            inside_active_job: false,
        })
        .is_err()
    );
}

#[test]
fn bound_native_query_failure_is_preserved_as_error_and_never_an_observation() {
    let expected = observation();
    let value = failure();
    let bytes = serde_json::to_vec(&value).unwrap();
    let error = WindowsGuardianAttemptObservation::from_query_wire_json(
        &bytes,
        expected.challenge.as_str(),
        &expected.association.provider,
    )
    .unwrap_err();
    assert!(error.contains(value.detail.as_str()));
    assert!(error.contains("QueryHandler"));
    assert!(WindowsGuardianAttemptObservation::from_wire_json(&bytes).is_err());
    assert!(memcordon_core::windows_response_frame_limit(&bytes).is_err());
    let positive = serde_json::to_vec(&expected).unwrap();
    assert_eq!(
        WindowsGuardianAttemptObservation::from_query_wire_json(
            &positive,
            expected.challenge.as_str(),
            &expected.association.provider,
        )
        .unwrap(),
        expected
    );
}

#[test]
fn failed_query_wire_requires_exact_operation_challenge_provider_and_finite_shape() {
    let expected = observation();
    let value = failure();
    let parse = |bytes: &[u8]| {
        WindowsGuardianAttemptObservation::from_query_wire_json(
            bytes,
            expected.challenge.as_str(),
            &expected.association.provider,
        )
    };
    for field in [
        "format",
        "revision",
        "operation",
        "challenge",
        "provider",
        "unknown",
        "phase",
    ] {
        let mut altered = serde_json::to_value(&value).unwrap();
        match field {
            "format" => altered[field] = serde_json::json!("old-query-failure"),
            "revision" => altered[field] = serde_json::json!(2),
            "operation" => altered[field] = serde_json::json!("recovery-convergence"),
            "challenge" => altered[field] = serde_json::json!("another-query"),
            "provider" => {
                altered[field]["runtime_manifest_sha256"] =
                    serde_json::to_value(DiagnosticSha256::from_bytes([9; 32])).unwrap()
            }
            "phase" => altered[field] = serde_json::json!("grant-authorized"),
            "unknown" => altered[field] = serde_json::json!(true),
            _ => unreachable!(),
        }
        let error = parse(&serde_json::to_vec(&altered).unwrap()).unwrap_err();
        assert!(!error.contains(value.detail.as_str()), "{field}");
    }
    let bytes = serde_json::to_vec(&value).unwrap();
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"revision\":1",
        "\"revision\":1,\"revision\":1",
        1,
    );
    assert!(
        parse(duplicate.as_bytes())
            .unwrap_err()
            .contains("duplicate")
    );
    assert!(parse(b"{").is_err());
    assert!(
        parse(&vec![
            b' ';
            WindowsGuardianAttemptObservation::MAX_FRAME_BYTES + 1
        ])
        .is_err()
    );
}

#[test]
fn recovery_failure_has_ordinary_kind_framing_and_bounded_explicit_truncation() {
    use memcordon_core::{
        WindowsProviderResponseV3, WindowsReadOnlyQueryFailure,
        WindowsReadOnlyQueryOperation as Operation, WindowsReadOnlyQueryPhase as Phase,
    };
    let expected = observation();
    let detail = "native error 🦀\n".repeat(512);
    let value = WindowsReadOnlyQueryFailure::new(
        Operation::RecoveryConvergence,
        expected.challenge.clone(),
        expected.association.provider.clone(),
        Phase::StateHardening,
        &detail,
    )
    .unwrap();
    assert!(value.detail_truncated);
    assert!(detail.starts_with(value.detail.as_str()));
    let payload =
        serde_json::to_vec(&WindowsProviderResponseV3::ReadOnlyQueryFailure(value)).unwrap();
    assert!(payload.len() < WindowsReadOnlyQueryFailure::MAX_FRAME_BYTES);
    assert_eq!(
        memcordon_core::windows_response_frame_limit(&payload).unwrap(),
        WindowsReadOnlyQueryFailure::MAX_FRAME_BYTES
    );
    let decoded: WindowsProviderResponseV3 = serde_json::from_slice(&payload).unwrap();
    let WindowsProviderResponseV3::ReadOnlyQueryFailure(value) = decoded else {
        panic!("failure changed kind")
    };
    let error = value
        .error_for(
            Operation::RecoveryConvergence,
            expected.challenge.as_str(),
            &expected.association.provider,
        )
        .unwrap();
    assert!(error.contains(value.detail.as_str()));
    assert!(error.ends_with("[detail truncated]"));
    assert!(
        value
            .error_for(
                Operation::GuardianObservation,
                expected.challenge.as_str(),
                &expected.association.provider
            )
            .is_err()
    );
}

#[test]
fn actual_server_observation_uses_dedicated_wire_shape_without_provider_kind() {
    let expected = observation();
    // The server uses pipe::write_frame, which serializes this concrete type.
    let payload = serde_json::to_vec(&expected).unwrap();
    assert!(payload.starts_with(b"{\"format\":"));
    assert!(memcordon_core::windows_response_frame_limit(&payload).is_err());
    assert_eq!(
        WindowsGuardianAttemptObservation::from_wire_json(&payload).unwrap(),
        expected
    );
    assert!(memcordon_core::windows_response_frame_limit(b"{\"kind\":\"completed\"}").is_ok());
}

#[test]
fn observation_decoder_rejects_other_protocols_and_malformed_or_inconsistent_frames() {
    let original = serde_json::to_value(observation()).unwrap();
    for (path, value) in [
        (
            "/format",
            serde_json::json!("memcordon.windows-live-guardian-observation-neighbour"),
        ),
        ("/revision", serde_json::json!(2)),
        ("/challenge", serde_json::json!("")),
        ("/guardian_identity/process_id", serde_json::json!(0)),
        (
            "/guardian_identity/creation_time_100ns",
            serde_json::json!(0),
        ),
        ("/association/provider/generation", serde_json::json!("")),
    ] {
        let mut malformed = original.clone();
        *malformed.pointer_mut(path).unwrap() = value;
        assert!(
            WindowsGuardianAttemptObservation::from_wire_json(
                &serde_json::to_vec(&malformed).unwrap()
            )
            .is_err(),
            "{path}"
        );
    }
    let mut unknown = original;
    unknown["kind"] = serde_json::json!("completed");
    assert!(
        WindowsGuardianAttemptObservation::from_wire_json(&serde_json::to_vec(&unknown).unwrap())
            .is_err()
    );
    let payload = serde_json::to_vec(&observation()).unwrap();
    let mut duplicate = b"{\"revision\":1,".to_vec();
    duplicate.extend_from_slice(payload.strip_prefix(b"{").unwrap());
    assert!(WindowsGuardianAttemptObservation::from_wire_json(&duplicate).is_err());
    for malformed in [b"{\"kind\":\"completed\"}".as_slice(), b"{", &[0xff]] {
        assert!(WindowsGuardianAttemptObservation::from_wire_json(malformed).is_err());
    }
    let mut oversized = payload.clone();
    oversized.resize(WindowsGuardianAttemptObservation::MAX_FRAME_BYTES + 1, b' ');
    assert!(WindowsGuardianAttemptObservation::from_wire_json(&oversized).is_err());
    let mut exactly_bounded = payload;
    exactly_bounded.resize(WindowsGuardianAttemptObservation::MAX_FRAME_BYTES, b' ');
    assert!(WindowsGuardianAttemptObservation::from_wire_json(&exactly_bounded).is_ok());
}
