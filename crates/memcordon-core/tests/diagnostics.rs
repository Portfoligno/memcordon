use memcordon_core::diagnostics::*;

fn assert_serialized_response_limit<T: WindowsResponseFrame + serde::Serialize>(
    response: &T,
    expected: usize,
) {
    let bytes = serde_json::to_vec(response).unwrap();
    let prefix = &bytes[..bytes.len().min(WINDOWS_RESPONSE_PREFIX_BYTES)];
    assert_eq!(T::frame_limit(prefix).unwrap(), expected);
    let decoded: T = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);
}

#[test]
fn response_framing_is_bound_to_the_serialized_protocol() {
    use memcordon_core::{WindowsLauncherResponseV1, WindowsProviderResponseV1};

    let response = WindowsLauncherResponseV1::Probe {
        schema_version: memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attestation: memcordon_core::WindowsServiceSelfAttestationV1 {
            schema_version: 1,
            challenge: "01".repeat(32),
            service_name: "MemCordonSealedLauncher".to_owned(),
            process_identity: memcordon_core::WindowsProcessIdentityV1 {
                process_id: 41,
                creation_time_100ns: 73,
            },
            service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
            service_sid_enabled: true,
            service_sid_restricted: true,
            token_session_id: 0,
            required_privileges: vec!["SeAssignPrimaryTokenPrivilege".to_owned()],
        },
        provider_binding: PublicProviderBindingV1 {
            generation: BoundedText::new("test-provider").unwrap(),
            source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
        },
    };
    let bytes = serde_json::to_vec(&response).unwrap();
    assert!(bytes.len() > WINDOWS_RESPONSE_PREFIX_BYTES);
    let prefix = &bytes[..WINDOWS_RESPONSE_PREFIX_BYTES];
    assert_eq!(
        WindowsLauncherResponseV1::frame_limit(prefix).unwrap(),
        memcordon_core::WINDOWS_MAX_FRAME_BYTES
    );
    // Both response protocols use kind; their concrete payload schemas still differ.
    assert!(serde_json::from_slice::<WindowsProviderResponseV1>(&bytes).is_err());
    let decoded: WindowsLauncherResponseV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&decoded).unwrap(), bytes);

    let cleanup = WindowsProviderResponseV1::PackageCleanupResult {
        schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        challenge: "04".repeat(32),
        status: memcordon_core::WindowsControlRequestStatusV1::Failed,
        attempts_empty: None,
        terminal_outboxes: None,
        detail: "cleanup did not converge".to_owned(),
    };
    assert_serialized_response_limit(&cleanup, memcordon_core::WINDOWS_MAX_FRAME_BYTES);
    assert_serialized_response_limit(
        &WindowsProviderResponseV1::QualificationReady {
            schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
        memcordon_core::WINDOWS_MAX_FRAME_BYTES,
    );
    let discovery = memcordon_core::workload_discovery::WorkloadDiscoveryV1::authenticated(
        None,
        &memcordon_core::workload_registry::CallerSelector::Linux { uid: 1000 },
        memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate,
        DiagnosticSha256::from_bytes([1; 32]),
        match &response {
            WindowsLauncherResponseV1::Probe {
                provider_binding, ..
            } => provider_binding.clone(),
            _ => unreachable!(),
        },
        BoundedText::new("boot-a").unwrap(),
    )
    .unwrap();
    assert_serialized_response_limit(
        &WindowsProviderResponseV1::WorkloadDiscovery {
            schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
            challenge: memcordon_core::workload_contract::Nonce128([3; 16]),
            discovery,
        },
        memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES,
    );

    for (response, request, limit) in [
        (
            br#"{"kind":"attempt-retained"}"#.as_slice(),
            br#"{"message":"attempt-retained"}"#.as_slice(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES,
        ),
        (
            br#"{"kind":"replay-pending"}"#.as_slice(),
            br#"{"message":"replay-pending"}"#.as_slice(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES,
        ),
        (
            br#"{"kind":"terminal"}"#.as_slice(),
            br#"{"message":"terminal"}"#.as_slice(),
            WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        ),
        (
            br#"{"kind":"reject"}"#.as_slice(),
            br#"{"message":"reject"}"#.as_slice(),
            WINDOWS_MAX_TERMINAL_FRAME_BYTES,
        ),
    ] {
        assert_eq!(
            WindowsLauncherResponseV1::frame_limit(response).unwrap(),
            limit
        );
        assert_eq!(
            WindowsProviderResponseV1::frame_limit(response).unwrap(),
            limit
        );
        assert!(WindowsLauncherResponseV1::frame_limit(request).is_err());
        assert!(WindowsProviderResponseV1::frame_limit(request).is_err());
    }
    for invalid in [
        br#"{"schema_version":2,"kind":"probe"}"#.as_slice(),
        br#"{"kind":"Probe"}"#.as_slice(),
        br#"{"kind":"pro\u0062e"}"#.as_slice(),
        br#"{"kind":"probe"#.as_slice(),
    ] {
        assert!(WindowsLauncherResponseV1::frame_limit(invalid).is_err());
        assert!(WindowsProviderResponseV1::frame_limit(invalid).is_err());
    }
}

#[test]
fn specification_prefix_fixtures_match_both_response_classifiers() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Fixture {
        name: String,
        prefix: String,
        public_limit: Option<usize>,
        launcher_limit: Option<usize>,
    }

    let fixtures: Vec<Fixture> = serde_json::from_str(include_str!(
        "fixtures/windows-response-frame-prefixes.json"
    ))
    .unwrap();
    assert!(!fixtures.is_empty());
    for fixture in fixtures {
        assert!(fixture.prefix.len() <= WINDOWS_RESPONSE_PREFIX_BYTES);
        assert_eq!(
            windows_response_frame_limit(fixture.prefix.as_bytes()).ok(),
            fixture.public_limit,
            "public: {}",
            fixture.name
        );
        assert_eq!(
            windows_launcher_response_frame_limit(fixture.prefix.as_bytes()).ok(),
            fixture.launcher_limit,
            "launcher: {}",
            fixture.name
        );
    }
}

#[test]
fn discriminator_terminator_must_fit_the_exact_prefix_window() {
    let opening = b"{\"kind\":\"";
    let quote = b"\"";
    let closing = b"\"}";
    for kind_end in [
        WINDOWS_RESPONSE_PREFIX_BYTES - quote.len(),
        WINDOWS_RESPONSE_PREFIX_BYTES,
    ] {
        let mut frame = opening.to_vec();
        frame.resize(kind_end, b'x');
        frame.extend_from_slice(closing);
        let prefix = &frame[..WINDOWS_RESPONSE_PREFIX_BYTES];
        for classify in [
            windows_response_frame_limit,
            windows_launcher_response_frame_limit,
        ] {
            if kind_end < prefix.len() {
                // An unknown canonical kind receives only a size classification.
                assert_eq!(
                    classify(prefix).unwrap(),
                    memcordon_core::WINDOWS_MAX_FRAME_BYTES
                );
            } else {
                // The closing quote beyond the window cannot authorize allocation.
                assert!(classify(prefix).is_err());
            }
        }
        assert!(
            serde_json::from_slice::<memcordon_core::WindowsProviderResponseV1>(&frame).is_err()
        );
        assert!(
            serde_json::from_slice::<memcordon_core::WindowsLauncherResponseV1>(&frame).is_err()
        );
    }
}

#[test]
fn fragmented_response_prefixes_keep_the_same_bounded_classification() {
    use std::io::Read;

    struct Fragmented<'a> {
        remaining: &'a [u8],
        fragment_bytes: usize,
    }
    impl Read for Fragmented<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let bytes = buffer
                .len()
                .min(self.fragment_bytes)
                .min(self.remaining.len());
            buffer[..bytes].copy_from_slice(&self.remaining[..bytes]);
            self.remaining = &self.remaining[bytes..];
            Ok(bytes)
        }
    }

    let discriminator = b"{\"kind\":\"attempt-retained\"";
    let mut frame = discriminator.to_vec();
    frame.resize(WINDOWS_RESPONSE_PREFIX_BYTES, b' ');
    let unread_body = b",\"kind\":\"terminal\"}";
    frame.extend_from_slice(unread_body);
    for fragment_bytes in 1..=WINDOWS_RESPONSE_PREFIX_BYTES {
        let mut reader = Fragmented {
            remaining: &frame,
            fragment_bytes,
        };
        let mut prefix = [0; WINDOWS_RESPONSE_PREFIX_BYTES];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(reader.remaining, unread_body);
        assert_eq!(
            windows_response_frame_limit(&prefix).unwrap(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
        );
        assert_eq!(
            windows_launcher_response_frame_limit(&prefix).unwrap(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
        );
    }
    for end in 0..discriminator.len() {
        let mut reader = Fragmented {
            remaining: &frame[..end],
            fragment_bytes: 1,
        };
        let mut prefix = [0; WINDOWS_RESPONSE_PREFIX_BYTES];
        assert_eq!(
            reader.read_exact(&mut prefix).unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(windows_response_frame_limit(&frame[..end]).is_err());
        assert!(windows_launcher_response_frame_limit(&frame[..end]).is_err());
    }
}

#[test]
fn classified_duplicate_and_unknown_kinds_still_fail_full_decoding() {
    use memcordon_core::{WindowsLauncherResponseV1, WindowsProviderResponseV1};

    let public = br#"{"kind":"qualification-ready","schema_version":2}"#;
    let private =
        br#"{"kind":"certification-machine-restart","schema_version":2,"recovered":true}"#;
    assert!(serde_json::from_slice::<WindowsProviderResponseV1>(public).is_ok());
    assert!(serde_json::from_slice::<WindowsLauncherResponseV1>(private).is_ok());
    for invalid in [
        br#"{"kind":"qualification-ready","kind":"qualification-ready","schema_version":2}"#.as_slice(),
        br#"{"kind":"certification-machine-restart","kind":"certification-machine-restart","schema_version":2,"recovered":true}"#.as_slice(),
        br#"{"kind":"attempt-retained","kind":"terminal"}"#.as_slice(),
        br#"{"kind":"not-a-response","schema_version":2}"#.as_slice(),
    ] {
        assert!(windows_response_frame_limit(invalid).is_ok());
        assert!(windows_launcher_response_frame_limit(invalid).is_ok());
        assert!(memcordon_core::workload_contract::reject_duplicate_json_keys(invalid).is_err()
            || invalid == br#"{"kind":"not-a-response","schema_version":2}"#);
        assert!(serde_json::from_slice::<WindowsProviderResponseV1>(invalid).is_err());
        assert!(serde_json::from_slice::<WindowsLauncherResponseV1>(invalid).is_err());
    }
}

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
    assert_serialized_response_limit(&response, WINDOWS_MAX_TERMINAL_FRAME_BYTES);
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
        b"{\"kind\":\"attempt-retained\",\"schema_version\":".as_slice(),
        b"{\"kind\":\"replay-pending\",\"schema_version\":".as_slice(),
    ] {
        assert_eq!(
            windows_response_frame_limit(prefix).unwrap(),
            MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES
        );
    }
    assert_eq!(
        windows_response_frame_limit(b"{\"kind\":\"terminal\",\"schema_version\":").unwrap(),
        WINDOWS_MAX_TERMINAL_FRAME_BYTES
    );
    for invalid in [
        b"{\"schema_version\":2,\"kind\":\"attempt-retained\"}".as_slice(),
        b"{\"kind\":\"attempt\\u002dretained\"}".as_slice(),
        b"{\"kind\":\"unterminated".as_slice(),
    ] {
        assert!(windows_response_frame_limit(invalid).is_err());
    }
}

#[test]
fn eligible_diagnostic_changes_preserve_authority_and_receiptless_posttarget_refusal() {
    use memcordon_core::{
        WindowsAttemptTerminalDispositionV1, WindowsLauncherResponseV1, WindowsProviderResponseV1,
        windows_terminal_outbox_is_bound,
    };

    let provider = PublicProviderBindingV1 {
        generation: BoundedText::new("test-provider").unwrap(),
        source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    };
    let attempt = "02".repeat(32);
    let request = "03".repeat(32);
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event()).unwrap();
    let original = journal.original.clone();
    let mut projections = vec![None]; // Expired or omitted public diagnostics.
    for variant in 0..4 {
        match variant {
            0 => {}
            1 => journal.observe_secondary(event()).unwrap(),
            2 => journal.loss.persistence_failure_observed = true,
            3 => journal.loss.writer_unavailable = true,
            _ => unreachable!(),
        }
        let projection = ProviderFailureDiagnosticV1::from_journal(
            provider.clone(),
            &attempt,
            &request,
            &journal,
        )
        .unwrap();
        assert_eq!(projection.original, original);
        ProviderFailureDiagnosticV1::parse_bound(
            &serde_json::to_vec(&projection).unwrap(),
            &provider,
            &DiagnosticSha256::from_bytes([2; 32]),
            &DiagnosticSha256::from_bytes([3; 32]),
        )
        .unwrap();
        projections.push(Some(projection));
    }

    let mut authority = None;
    for projection in projections {
        let public = WindowsProviderResponseV1::Reject {
            schema_version: memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt.clone(),
            nonce: "nonce".to_owned(),
            request_sha256: request.clone(),
            rejection: memcordon_core::ProviderRejectionEvidence {
                provider_failure: projection,
                workload_admission: None,
                schema_version: 1,
                code: "MCSPAWN-FAILED".to_owned(),
                phase: memcordon_core::BoundarySetupPhase::TargetCreation,
                detail: "posttarget monitor failure without terminal authority".to_owned(),
                os_code: None,
                loader_qualification: None,
                target_created: true,
                target_released: true,
                cleanup_attempted: false,
                restart_safety: memcordon_core::RestartSafetyProof::default(),
                terminal_ack_required: false,
                terminal_receipt: None,
            },
        };
        let private: WindowsLauncherResponseV1 =
            serde_json::from_value(serde_json::to_value(&public).unwrap()).unwrap();
        let WindowsLauncherResponseV1::Reject { rejection, .. } = &private else {
            panic!("fixture must remain a rejection");
        };
        assert!(rejection.is_consistent());
        assert!(!windows_terminal_outbox_is_bound(
            &attempt,
            &request,
            Some(WindowsAttemptTerminalDispositionV1::Posttarget),
            &private,
        ));
        let bytes = public.terminal_authority_json().unwrap();
        assert_eq!(private.terminal_authority_json().unwrap(), bytes);
        assert_eq!(authority.get_or_insert_with(|| bytes.clone()), &bytes);
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
    let maximal_entries = MAX_RECORD_JSON_NODES - 1;
    // Miri exercises the first and repeated map-entry paths, including escaping
    // and deserialization. Native runs materialize the entire capacity stress
    // case; the exact full-capacity transport bound is checked in both modes.
    let entries = if cfg!(miri) { 2 } else { maximal_entries };
    let mut fields = serde_json::Map::new();
    fields.insert(
        format!("{:064}", 0),
        serde_json::Value::String("\u{1}".repeat(16)),
    );
    let entry_bytes = serde_json::to_vec(&fields).unwrap().len() - b"{}".len();
    let encoded_size = |entries: usize| {
        b"{}".len() + entries * entry_bytes + entries.saturating_sub(1) * b",".len()
    };
    assert!(encoded_size(maximal_entries) < WINDOWS_MAX_TERMINAL_FRAME_BYTES);
    for index in 1..entries {
        let key = format!("{index:064}");
        fields.insert(key, serde_json::Value::String("\u{1}".repeat(16)));
    }
    let encoded = serde_json::to_vec(&fields).unwrap();
    assert_eq!(encoded.len(), encoded_size(entries));
    validate_record_json_structure(&encoded).unwrap();
    assert!(encoded.len() < WINDOWS_MAX_TERMINAL_FRAME_BYTES);
    assert_eq!(
        windows_response_frame_limit(br#"{"kind":"terminal"}"#).unwrap(),
        WINDOWS_MAX_TERMINAL_FRAME_BYTES
    );
    assert_eq!(
        windows_response_frame_limit(br#"{"kind":"reject"}"#).unwrap(),
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
