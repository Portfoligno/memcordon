use memcordon_core::diagnostics::*;

fn event() -> CausalEventV1 {
    CausalEventV1 {
        sequence: 0,
        origin: DiagnosticOriginV1::Launcher,
        category: FailureCategoryV1::Monitor,
        operation: FailureOperationV1::ObserveProcessIdentity,
        code: FailureCodeV1::ProcessInventoryObservation,
        native_code: Some(NativeFailureCodeV1::Win32(1234)),
        observed_phase: AttemptObservationPhaseV1::Monitoring,
        safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    }
}

#[test]
fn original_is_immutable_and_secondary_overflow_is_explicit() {
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    let original = journal.original.clone();
    for _ in 0..MAX_DIAGNOSTIC_SECONDARY_EVENTS + 3 {
        journal.observe(event()).unwrap();
    }
    assert_eq!(journal.original, original);
    assert_eq!(
        journal.secondary.as_slice().len(),
        MAX_DIAGNOSTIC_SECONDARY_EVENTS
    );
    assert_eq!(journal.loss.secondary_events_omitted, 3);
    assert!(journal.is_consistent());
    assert_eq!(
        WindowsCausalDiagnosticsV1::parse(&serde_json::to_vec(&journal).unwrap()).unwrap(),
        journal
    );
}

#[test]
fn duplicate_sequences_and_future_durability_reject() {
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    journal.durable_through_sequence = Some(journal.sequence + 1);
    assert!(!journal.is_consistent());
    journal.durable_through_sequence = None;
    let mut duplicate = event();
    duplicate.sequence = 1;
    journal.secondary.try_push(duplicate).unwrap();
    assert!(!journal.is_consistent());
}

#[test]
fn reserved_journal_copies_keep_cleanup_storage_and_original_cause() {
    let mut source = WindowsCausalDiagnosticsV1::default();
    source.observe(event()).unwrap();
    let original = source.original.clone();
    for mut target in [
        WindowsCausalDiagnosticsV1::default(),
        WindowsCausalDiagnosticsV1::default().clone(),
        WindowsCausalDiagnosticsV1::parse(
            &serde_json::to_vec(&WindowsCausalDiagnosticsV1::default()).unwrap(),
        )
        .unwrap(),
    ] {
        let storage = target.secondary.as_slice().as_ptr();
        source.copy_into_reserved(&mut target);
        for _ in 0..MAX_DIAGNOSTIC_SECONDARY_EVENTS {
            target.observe_secondary(event()).unwrap();
        }
        assert_eq!(target.secondary.as_slice().as_ptr(), storage);
        assert_eq!(target.original, original);
        assert!(target.is_consistent());
        source.copy_into_reserved(&mut target);
        assert_eq!(target.secondary.as_slice().as_ptr(), storage);
        assert_eq!(target, source);
    }
}

#[test]
fn retention_never_renews_after_expiry_rollback_or_uncertain_boot() {
    let mut retention = DiagnosticRetentionV1::admitted_at(100).unwrap();
    assert!(retention.export_eligible(true, 100));
    assert!(!retention.export_eligible(true, 99));
    assert!(!retention.export_eligible(false, 100));
    assert!(!retention.export_eligible(true, retention.expires_monotonic_millis));
    retention.tombstone = Some(OriginalUnavailableReasonV1::RetentionExpired);
    assert!(!retention.export_eligible(true, 100));
    retention.expires_monotonic_millis += 1;
    assert!(!retention.is_consistent());
    assert!(DiagnosticRetentionV1::admitted_at(u64::MAX).is_err());
}

#[test]
fn exact_serialized_record_budget_includes_escaping_pretty_layout_and_newline() {
    let value = serde_json::json!({"events": ["\n\"\\", "second"]});
    for pretty in [false, true] {
        let mut expected = if pretty {
            serde_json::to_vec_pretty(&value).unwrap()
        } else {
            serde_json::to_vec(&value).unwrap()
        };
        expected.push(b'\n');
        assert_eq!(
            bounded_json_bytes(&value, expected.len(), pretty).unwrap(),
            expected
        );
        assert!(bounded_json_bytes(&value, expected.len() - 1, pretty).is_err());
        assert!(bounded_json_bytes(&value, 0, pretty).is_err());
    }
}

#[test]
fn diagnostic_expiry_does_not_change_terminal_authority_or_ack_bytes() {
    let binding = PublicProviderBindingV1 {
        generation: BoundedText::new("test-provider").unwrap(),
        source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    };
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    let projection = ProviderFailureDiagnosticV1::from_journal(
        binding,
        &"02".repeat(32),
        &"03".repeat(32),
        &journal,
    )
    .unwrap();
    let mut response = memcordon_core::WindowsProviderResponseV1::Reject {
        schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        attempt_id: "02".repeat(32),
        nonce: "nonce".to_owned(),
        request_sha256: "03".repeat(32),
        rejection: memcordon_core::ProviderRejectionEvidence {
            provider_failure: Some(projection),
            workload_admission: None,
            schema_version: 1,
            code: "MCSPAWN-FAILED".to_owned(),
            phase: memcordon_core::BoundarySetupPhase::TargetCreation,
            detail: "target creation failed".to_owned(),
            os_code: None,
            loader_qualification: None,
            target_created: false,
            target_released: false,
            cleanup_attempted: false,
            restart_safety: memcordon_core::RestartSafetyProof::default(),
            terminal_ack_required: false,
            terminal_receipt: None,
        },
    };
    let authority = response.terminal_authority_json().unwrap();
    assert!(serde_json::to_value(&response).unwrap()["rejection"]["provider_failure"].is_object());
    if let memcordon_core::WindowsProviderResponseV1::Reject { rejection, .. } = &mut response {
        rejection.provider_failure = None;
    }
    assert_eq!(authority, response.terminal_authority_json().unwrap());
    assert_eq!(authority, serde_json::to_string(&response).unwrap());
}

#[test]
fn response_prefix_selects_diagnostic_budget_before_payload_allocation() {
    for prefix in [
        b"{\"message\":\"attempt-retained\",\"schema_version\":".as_slice(),
        b"{\"message\":\"replay-pending\",\"schema_version\":".as_slice(),
    ] {
        assert_eq!(
            windows_response_frame_limit(prefix).unwrap(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
        );
    }
    assert_eq!(
        windows_response_frame_limit(b"{\"message\":\"terminal\",\"schema_version\":").unwrap(),
        WINDOWS_MAX_TERMINAL_FRAME_BYTES
    );
    for invalid in [
        b"{\"schema_version\":2,\"message\":\"attempt-retained\"}".as_slice(),
        b"{\"message\":\"attempt\\u002dretained\"}".as_slice(),
        b"{\"message\":\"unterminated".as_slice(),
    ] {
        assert!(windows_response_frame_limit(invalid).is_err());
    }
}

#[test]
fn native_domains_preserve_bits_and_reject_unknown_fields() {
    for native in [
        NativeFailureCodeV1::Win32(u32::MAX),
        NativeFailureCodeV1::NtStatus(0xc0000005),
        NativeFailureCodeV1::HResult(0x80070005),
        NativeFailureCodeV1::Winsock(-1),
        NativeFailureCodeV1::LegacyUntyped(-1),
    ] {
        assert_eq!(
            serde_json::from_slice::<NativeFailureCodeV1>(&serde_json::to_vec(&native).unwrap())
                .unwrap(),
            native
        );
    }
    assert!(
        serde_json::from_str::<SafeDiagnosticDetailV1>(
            r#"{"provider-message":{"id":"original-failure-captured","secret":"password"}}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<BoundedVec<u8, 2>>("[1,2,3]").is_err());
    assert!(serde_json::from_str::<BoundedText<2>>(r#""abc""#).is_err());
    assert!(
        serde_json::from_str::<DiagnosticSha256>(
            &serde_json::to_string(&"A".repeat(32 * 2)).unwrap()
        )
        .is_err()
    );
}

#[test]
fn projection_requires_exact_provider_attempt_request_and_digest() {
    let binding = PublicProviderBindingV1 {
        generation: BoundedText::new("test-provider").unwrap(),
        source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    };
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    let mut projection = ProviderFailureDiagnosticV1 {
        schema_version: CAUSAL_DIAGNOSTIC_SCHEMA,
        provider_binding: binding.clone(),
        attempt_id: DiagnosticSha256::from_bytes([2; 32]),
        request_sha256: DiagnosticSha256::from_bytes([3; 32]),
        diagnostic_sequence: journal.sequence,
        durable_through_sequence: None,
        original: journal.original,
        secondary: journal.secondary,
        loss: journal.loss,
        projection_sha256: DiagnosticSha256::from_bytes([0; 32]),
    };
    projection.projection_sha256 = projection.canonical_digest();
    // Independently encoded from the published big-endian V1 grammar and
    // hashed with Python hashlib, without invoking the Rust producer.
    assert_eq!(
        String::from(projection.projection_sha256.clone()),
        "ef433f64117baa1db88649ce38386ea3af3c491b3c2645d8415c9f855c97a3e5"
    );
    let bytes = serde_json::to_vec(&projection).unwrap();
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &bytes,
            &binding,
            &projection.attempt_id,
            &projection.request_sha256
        )
        .is_ok()
    );
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &bytes,
            &binding,
            &projection.request_sha256,
            &projection.request_sha256
        )
        .is_err()
    );
    projection.loss.persistence_failure_observed = true;
    let corrupt = serde_json::to_vec(&projection).unwrap();
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &corrupt,
            &binding,
            &projection.attempt_id,
            &projection.request_sha256
        )
        .is_err()
    );
}

#[test]
fn journal_rejects_unexplained_gaps_and_impossible_omission_counts() {
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    journal.sequence = 20;
    assert!(!journal.is_consistent());
    journal.sequence = 2;
    journal.loss.secondary_events_omitted = 1;
    assert!(!journal.is_consistent());
    let mut value = serde_json::to_string(&WindowsCausalDiagnosticsV1::default()).unwrap();
    value.insert_str(1, "\"schema_version\":1,");
    assert!(WindowsCausalDiagnosticsV1::parse(value.as_bytes()).is_err());
}

#[test]
fn record_preflight_bounds_decoded_container_and_metadata_expansion() {
    assert!(validate_record_json_structure(br#"{"state":"empty","inventory":[1,2,3]}"#).is_ok());
    let nodes = serde_json::to_vec(&vec![0_u8; MAX_RECORD_JSON_NODES]).unwrap();
    assert!(validate_record_json_structure(&nodes).is_err());
    let text = serde_json::to_vec(
        &serde_json::json!({"detail": "a".repeat(MAX_RECORD_METADATA_TEXT_BYTES + 1)}),
    )
    .unwrap();
    assert!(validate_record_json_structure(&text).is_err());
    let outbox = serde_json::to_vec(
        &serde_json::json!({"terminal_response_json": "a".repeat(MAX_RECORD_METADATA_TEXT_BYTES + 1)}),
    )
    .unwrap();
    assert!(validate_record_json_structure(&outbox).is_ok());
    let nested = serde_json::to_vec(
        &serde_json::json!({"nested": {"terminal_response_json": "a".repeat(MAX_RECORD_METADATA_TEXT_BYTES + 1)}}),
    )
    .unwrap();
    assert!(validate_record_json_structure(&nested).is_err());
    assert!(serde_json::from_str::<memcordon_core::WindowsTerminalizationErrorV1>(&serde_json::json!({
        "stage": "atomic-store", "error_code": "X", "detail": "a".repeat(2049), "native_code": null, "observed_unix_millis": null
    }).to_string()).is_err());
}

#[test]
fn maximal_terminal_structure_and_escape_expansion_fit_reserved_transport() {
    let mut fields = serde_json::Map::new();
    for index in 0..MAX_RECORD_JSON_NODES - 1 {
        let key = format!("{index:064}");
        fields.insert(key, serde_json::Value::String("\u{1}".repeat(16)));
    }
    let encoded = serde_json::to_vec(&fields).unwrap();
    validate_record_json_structure(&encoded).unwrap();
    assert!(encoded.len() < WINDOWS_MAX_TERMINAL_FRAME_BYTES);
    assert_eq!(
        windows_response_frame_limit(br#"{"message":"terminal"}"#).unwrap(),
        WINDOWS_MAX_TERMINAL_FRAME_BYTES
    );
    assert_eq!(
        windows_response_frame_limit(br#"{"message":"reject"}"#).unwrap(),
        WINDOWS_MAX_TERMINAL_FRAME_BYTES
    );
}

#[test]
fn allocation_failure_precedes_serialization_and_post_reservation_failure_returns_no_image() {
    struct Refuse<'a>(&'a std::cell::Cell<usize>);
    impl serde::Serialize for Refuse<'_> {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            self.0.set(self.0.get() + 1);
            Err(serde::ser::Error::custom(
                "injected serialization failure after reservation",
            ))
        }
    }
    let calls = std::cell::Cell::new(0);
    assert!(bounded_json_bytes(&Refuse(&calls), usize::MAX, false).is_err());
    assert_eq!(calls.get(), 0);
    assert!(bounded_json_bytes(&Refuse(&calls), 4096, false).is_err());
    assert_eq!(calls.get(), 1);
}
