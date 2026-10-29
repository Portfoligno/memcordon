use memcordon_core::{WindowsProcessIdentityV1, WindowsWorkloadPreparedV1};
use memcordon_readiness_verifier::current::windows::prepared_commitment;

#[test]
fn actual_current_caller_controls_use_message_tag_and_exact_native_association() {
    use memcordon_core::WindowsProviderRequestV4;
    use memcordon_readiness_verifier::current::windows::validate_control_message;
    let binding = serde_json::json!({"attempt_id":"ab".repeat(32),"nonce":"actual native nonce","request_sha256":"cd".repeat(32)});
    let messages = [
        (
            "cancel",
            None,
            WindowsProviderRequestV4::Cancel {
                schema_version: 4,
                attempt_id: "ab".repeat(32),
                nonce: "actual native nonce".into(),
                request_sha256: "cd".repeat(32),
                signal: 2,
            },
        ),
        (
            "preparation-acknowledged",
            Some("ef".repeat(32)),
            WindowsProviderRequestV4::PreparationAcknowledged {
                schema_version: 4,
                attempt_id: "ab".repeat(32),
                nonce: "actual native nonce".into(),
                request_sha256: "cd".repeat(32),
                accepted_sha256: "ef".repeat(32),
            },
        ),
        (
            "prepared-acknowledged",
            Some("12".repeat(32)),
            WindowsProviderRequestV4::PreparedAcknowledged {
                schema_version: 4,
                attempt_id: "ab".repeat(32),
                nonce: "actual native nonce".into(),
                request_sha256: "cd".repeat(32),
                prepared_sha256: "12".repeat(32),
            },
        ),
    ];
    for (variant, commitment, message) in messages {
        let value = serde_json::to_value(message).unwrap();
        validate_control_message(&value, variant, &binding, commitment.as_deref()).unwrap();
        let mut wrong_tag = value.clone();
        let tag = wrong_tag
            .as_object_mut()
            .unwrap()
            .remove("message")
            .unwrap();
        wrong_tag["kind"] = tag;
        assert!(
            validate_control_message(&wrong_tag, variant, &binding, commitment.as_deref()).is_err()
        );
        let mut wrong_binding = value;
        wrong_binding["nonce"] = serde_json::json!("foreign nonce");
        assert!(
            validate_control_message(&wrong_binding, variant, &binding, commitment.as_deref())
                .is_err()
        );
    }
}

#[test]
fn independent_acceptance_encoder_binds_original_provider_caller_and_cutoff() {
    use memcordon_core::{PublicProviderBindingV1, WindowsWorkloadAcceptedV1};
    use memcordon_readiness_verifier::current::windows::accepted_commitment;
    let accepted = WindowsWorkloadAcceptedV1 {
        format: "memcordon.windows-workload-accepted".into(), revision: 1,
        provider: serde_json::from_value::<PublicProviderBindingV1>(serde_json::json!({"generation":"current-native-generation", "source_commit":"ab".repeat(20), "runtime_manifest_sha256":"cd".repeat(32)})).unwrap(),
        frontend: WindowsProcessIdentityV1 { process_id: 2314, creation_time_100ns: 0 },
        attempt_id: "12".repeat(32), nonce: "actual native nonce".into(), request_sha256: "34".repeat(32), setup_deadline_millis: 44100,
    };
    let expected = accepted.canonical_sha256().unwrap();
    let value = serde_json::to_value(accepted).unwrap();
    assert_eq!(accepted_commitment(&value).unwrap(), expected);
    for (pointer, replacement) in [
        (
            "/provider/generation",
            serde_json::json!("another-native-generation"),
        ),
        (
            "/provider/source_commit",
            serde_json::json!("ef".repeat(20)),
        ),
        (
            "/provider/runtime_manifest_sha256",
            serde_json::json!("56".repeat(32)),
        ),
        ("/frontend/process_id", serde_json::json!(2315)),
        ("/frontend/creation_time_100ns", serde_json::json!(1)),
        ("/setup_deadline_millis", serde_json::json!(44101)),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(accepted_commitment(&changed).unwrap(), expected);
    }
    let mut invalid = value.clone();
    invalid["frontend"]["process_id"] = serde_json::json!(0);
    assert!(accepted_commitment(&invalid).is_err());
    let mut invalid = value;
    invalid["unexpected_field"] = serde_json::json!(true);
    assert!(accepted_commitment(&invalid).is_err());
}

#[test]
fn independent_prepared_encoder_matches_native_field_order_and_rejects_rebinding() {
    let prepared = WindowsWorkloadPreparedV1 {
        format: "memcordon.windows-workload-prepared".into(),
        revision: 1,
        attempt_id: "ab".repeat(32),
        nonce: "original native nonce".into(),
        request_sha256: "cd".repeat(32),
        target: WindowsProcessIdentityV1 {
            process_id: 2314,
            creation_time_100ns: 0,
        },
        owner_manifest_sha256: "ef".repeat(32),
    };
    let actual = prepared.canonical_sha256().unwrap();
    let value = serde_json::to_value(&prepared).unwrap();
    assert_eq!(prepared_commitment(&value).unwrap(), actual);
    for (pointer, replacement) in [
        ("/attempt_id", serde_json::json!("12".repeat(32))),
        ("/nonce", serde_json::json!("another native nonce")),
        ("/request_sha256", serde_json::json!("34".repeat(32))),
        ("/target/process_id", serde_json::json!(2315)),
        ("/target/creation_time_100ns", serde_json::json!(1)),
        ("/owner_manifest_sha256", serde_json::json!("56".repeat(32))),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert_ne!(prepared_commitment(&changed).unwrap(), actual);
    }
    let mut zero = value.clone();
    zero["target"]["process_id"] = serde_json::json!(0);
    assert!(prepared_commitment(&zero).is_err());
    let mut unknown = value;
    unknown["unexpected_field"] = serde_json::json!(true);
    assert!(prepared_commitment(&unknown).is_err());
}
