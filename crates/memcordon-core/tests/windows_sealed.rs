use memcordon_core::*;
use sha2::{Digest, Sha256};

fn sha256(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

fn probe() -> WindowsProviderProbeV1 {
    WindowsProviderProbeV1 {
        format: "memcordon.windows-provider-probe".into(),
        revision: 1,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        provider_binding: memcordon_core::PublicProviderBindingV1 {
            generation: memcordon_core::BoundedText::new("native-fixture-generation").unwrap(),
            source_commit: memcordon_core::BoundedText::new(&sha256(b"source identity")).unwrap(),
            runtime_manifest_sha256: memcordon_core::DiagnosticSha256::from_bytes([7; 32]),
        },
        launcher_authenticated: true,
        recovery_clear: true,
        attempts_empty: true,
    }
}

fn utf16_arguments(arguments: &[&str]) -> Vec<Vec<u16>> {
    arguments
        .iter()
        .map(|argument| argument.encode_utf16().collect())
        .collect()
}

fn launcher_self_attestation() -> WindowsServiceSelfAttestationV1 {
    WindowsServiceSelfAttestationV1 {
        schema_version: 1,
        challenge: sha256(b"launcher-self-attestation-challenge"),
        service_name: "MemCordonSealedLauncher".to_owned(),
        process_identity: WindowsProcessIdentityV1 {
            process_id: 41,
            creation_time_100ns: 73,
        },
        service_sid: "S-1-5-80-1-2-3-4-5".to_owned(),
        service_sid_enabled: true,
        service_sid_restricted: true,
        token_session_id: 0,
        required_privileges: vec![
            "SeAssignPrimaryTokenPrivilege".to_owned(),
            "SeIncreaseQuotaPrivilege".to_owned(),
            "SeTcbPrivilege".to_owned(),
        ],
    }
}

#[test]
fn provider_replacement_requires_live_and_durable_provider_quiescence() {
    use WindowsProviderReplacementQuiescenceV1::{
        DurableRecoveryStillActive, ProviderJobStillActive, ProviderJobsNotTerminated,
        ReadyForReplacement,
    };

    assert_eq!(
        windows_provider_replacement_quiescence(false, false, false),
        ProviderJobsNotTerminated
    );
    assert_eq!(
        windows_provider_replacement_quiescence(true, false, false),
        ProviderJobStillActive
    );
    assert_eq!(
        windows_provider_replacement_quiescence(true, true, false),
        DurableRecoveryStillActive
    );
    assert_eq!(
        windows_provider_replacement_quiescence(true, true, true),
        ReadyForReplacement
    );
    assert_eq!(ReadyForReplacement.phase(), "ready-for-replacement");
    assert_eq!(ProviderJobStillActive.phase(), "provider-job-still-active");
}

#[test]
fn windows_service_self_attestation_is_fresh_identity_bound_and_fail_closed() {
    let expected = launcher_self_attestation();
    let expected_privileges = [
        "SeAssignPrimaryTokenPrivilege",
        "SeIncreaseQuotaPrivilege",
        "SeTcbPrivilege",
    ];
    assert_eq!(
        expected.validate_for(
            &expected.challenge,
            &expected.service_name,
            &expected.process_identity,
            &expected.service_sid,
            &expected_privileges,
        ),
        Ok(())
    );

    let mutations = [
        {
            let mut value = expected.clone();
            value.challenge = sha256(b"replayed-challenge");
            value
        },
        {
            let mut value = expected.clone();
            value.process_identity.process_id += 1;
            value
        },
        {
            let mut value = expected.clone();
            value.process_identity.creation_time_100ns += 1;
            value
        },
        {
            let mut value = expected.clone();
            value.service_sid = "S-1-5-80-9-9-9-9-9".to_owned();
            value
        },
        {
            let mut value = expected.clone();
            value.service_sid_enabled = false;
            value
        },
        {
            let mut value = expected.clone();
            value.service_sid_restricted = false;
            value
        },
        {
            let mut value = expected.clone();
            value.required_privileges.remove(0);
            value
        },
        {
            let mut value = expected.clone();
            value.required_privileges.remove(1);
            value
        },
        {
            let mut value = expected.clone();
            value.required_privileges.swap(0, 1);
            value
        },
    ];
    for mutation in mutations {
        assert!(
            mutation
                .validate_for(
                    &expected.challenge,
                    &expected.service_name,
                    &expected.process_identity,
                    &expected.service_sid,
                    &expected_privileges,
                )
                .is_err(),
            "mutated service self-attestation must fail closed: {mutation:?}"
        );
    }
}

#[test]
fn windows_certification_frontend_handle_layouts_are_mode_derived_and_exact() {
    let cases = [
        (
            "windows-certification-target",
            vec!["target.result", "cleanup.marker"],
            3,
        ),
        (
            "windows-certification-nested-target",
            vec!["target.result", "nested-child.json", "cleanup.marker"],
            4,
        ),
    ];
    for (mode, retained, expected_prelude_len) in cases {
        let mut arguments = vec![mode];
        arguments.extend(retained);
        arguments.extend(["101", "102", "103", "104", "105", "106"]);
        let arguments = utf16_arguments(&arguments);

        assert_eq!(
            windows_certification_argument_prelude_len(&arguments[0]),
            Some(expected_prelude_len),
        );
        assert_eq!(
            parse_windows_certification_frontend_handle_values(&arguments)
                .expect("current certification layout must parse"),
            Some([101, 102, 103, 104, 105, 106]),
        );
    }
}

#[test]
fn windows_certification_frontend_handle_inventory_fails_closed() {
    for retained in [
        vec!["target.result", "cleanup.marker"],
        vec!["target.result", "nested-child.json", "cleanup.marker"],
    ] {
        let mode = if retained.len() == 2 {
            "windows-certification-target"
        } else {
            "windows-certification-nested-target"
        };
        let mut valid = vec![mode];
        valid.extend(retained);
        valid.extend(["101", "102", "103", "104", "105", "106"]);

        for mutation in [
            {
                let mut values = valid.clone();
                values.pop();
                values
            },
            {
                let mut values = valid.clone();
                values.push("107");
                values
            },
            {
                let mut values = valid.clone();
                values.remove(1);
                values
            },
        ] {
            assert_eq!(
                parse_windows_certification_frontend_handle_values(&utf16_arguments(&mutation))
                    .expect_err("malformed certification inventory must fail closed"),
                "frontend handle-canary inventory is not exact",
            );
        }

        let mut nonnumeric = valid;
        let last = nonnumeric.len() - 1;
        nonnumeric[last] = "not-a-handle";
        assert!(
            parse_windows_certification_frontend_handle_values(&utf16_arguments(&nonnumeric))
                .expect_err("nonnumeric certification canary must fail closed")
                .starts_with("frontend handle-canary value is invalid:"),
        );
    }

    assert_eq!(
        parse_windows_certification_frontend_handle_values(&utf16_arguments(&[
            "ordinary-command",
            "101",
            "102",
            "103",
            "104",
            "105",
            "106",
        ]))
        .expect("ordinary arguments are outside the certification protocol"),
        None,
    );
}

#[test]
fn windows_command_line_quotes_embedded_quotes_and_trailing_backslashes() {
    let encoded = |value: &str| {
        String::from_utf16(&encode_windows_command_line(&[value
            .encode_utf16()
            .collect()]))
        .expect("test arguments are valid UTF-16")
    };
    assert_eq!(encoded("plain"), "plain");
    assert_eq!(encoded(""), r#""""#);
    assert_eq!(encoded("a\"b"), r#""a\"b""#);
    assert_eq!(encoded(r#"a\"b"#), r#""a\\\"b""#);
    assert_eq!(
        encoded(r#"C:\path with space\"#),
        r#""C:\path with space\\""#
    );
}

#[test]
fn windows_command_line_round_trips_adversarial_vectors() {
    let arguments = [
        "",
        "plain",
        "two words",
        "tab\tseparated",
        "embedded\"quote",
        r#"slashes\\\"quote"#,
        r#"C:\path with space\"#,
        "日本語 🦀",
    ]
    .map(|value| value.encode_utf16().collect::<Vec<_>>())
    .to_vec();
    let encoded = encode_windows_command_line(&arguments);
    assert_eq!(decode_windows_command_line(&encoded), Ok(arguments));
    assert!(decode_windows_command_line(&[0]).is_err());
}

#[test]
fn windows_command_line_preserves_separator_after_unquoted_backslash() {
    let arguments = vec![vec![], vec![b'\\' as u16], vec![1282]];
    let encoded = encode_windows_command_line(&arguments);
    assert_eq!(decode_windows_command_line(&encoded), Ok(arguments));
}

#[test]
fn windows_environment_uses_one_case_key_and_native_size_limit() {
    let canonical = [
        WindowsEnvironmentEntryV1 {
            name: "windir".encode_utf16().collect(),
            value: r"C:\Windows".encode_utf16().collect(),
        },
        WindowsEnvironmentEntryV1 {
            name: "SystemDrive".encode_utf16().collect(),
            value: "C:".encode_utf16().collect(),
        },
        WindowsEnvironmentEntryV1 {
            name: "SystemRoot".encode_utf16().collect(),
            value: r"C:\Windows".encode_utf16().collect(),
        },
    ];
    let block = encode_windows_environment_block(&canonical).unwrap();
    let expected = "SystemDrive=C:\0SystemRoot=C:\\Windows\0windir=C:\\Windows\0\0"
        .encode_utf16()
        .collect::<Vec<_>>();
    assert_eq!(block, expected);
    assert_eq!(&block[block.len() - 2..], &[0, 0]);

    let duplicate = vec![
        WindowsEnvironmentEntryV1 {
            name: "straße".encode_utf16().collect(),
            value: vec![b'a' as u16],
        },
        WindowsEnvironmentEntryV1 {
            name: "STRASSE".encode_utf16().collect(),
            value: vec![b'b' as u16],
        },
    ];
    assert!(encode_windows_environment_block(&duplicate).is_err());

    for invalid in [
        WindowsEnvironmentEntryV1 {
            name: Vec::new(),
            value: Vec::new(),
        },
        WindowsEnvironmentEntryV1 {
            name: vec![b'A' as u16, 0],
            value: Vec::new(),
        },
        WindowsEnvironmentEntryV1 {
            name: vec![b'A' as u16, b'=' as u16],
            value: Vec::new(),
        },
        WindowsEnvironmentEntryV1 {
            name: vec![b'A' as u16],
            value: vec![0],
        },
    ] {
        assert!(encode_windows_environment_block(&[invalid]).is_err());
    }

    let oversized = [WindowsEnvironmentEntryV1 {
        name: vec![b'A' as u16],
        value: vec![b'x' as u16; 32_766],
    }];
    assert!(encode_windows_environment_block(&oversized).is_err());
}

#[test]
fn windows_environment_preserves_native_drive_directories_and_utf16() {
    let entries = [
        ("Path", "C:\\Windows"),
        ("=z:", "Z:\\資料😀=archive"),
        ("=C:", "C:\\work"),
    ]
    .map(|(name, value)| WindowsEnvironmentEntryV1 {
        name: name.encode_utf16().collect(),
        value: value.encode_utf16().collect(),
    });
    assert_eq!(
        encode_windows_environment_block(&entries).unwrap(),
        "=C:=C:\\work\0=z:=Z:\\資料😀=archive\0Path=C:\\Windows\0\0"
            .encode_utf16()
            .collect::<Vec<_>>()
    );

    let native_value = WindowsEnvironmentEntryV1 {
        name: "=D:".encode_utf16().collect(),
        value: vec![0xd800],
    };
    let mut expected: Vec<_> = "=D:=".encode_utf16().collect();
    expected.extend([0xd800, 0, 0]);
    assert_eq!(
        encode_windows_environment_block(&[native_value]).unwrap(),
        expected
    );
}

#[test]
fn windows_environment_rejects_malformed_and_duplicate_drive_entries() {
    for name in [
        "=", "=C", "=C::", "=CC:", "=1:", "=é:", "A=B", "==C:", "=C:\0",
    ] {
        let entry = WindowsEnvironmentEntryV1 {
            name: name.encode_utf16().collect(),
            value: "C:\\work".encode_utf16().collect(),
        };
        assert_eq!(
            encode_windows_environment_block(&[entry]),
            Err("invalid Windows environment entry"),
            "{name:?}"
        );
    }
    let duplicate = ["=C:", "=c:"].map(|name| WindowsEnvironmentEntryV1 {
        name: name.encode_utf16().collect(),
        value: "C:\\work".encode_utf16().collect(),
    });
    assert_eq!(
        encode_windows_environment_block(&duplicate),
        Err("duplicate case-insensitive Windows environment name")
    );
    let nul_value = WindowsEnvironmentEntryV1 {
        name: "=C:".encode_utf16().collect(),
        value: vec![0],
    };
    assert_eq!(
        encode_windows_environment_block(&[nul_value]),
        Err("invalid Windows environment entry")
    );
}

#[test]
fn windows_probe_requires_named_identity_and_actual_live_service_facts() {
    let canonical = probe();
    canonical.validate().unwrap();
    let mut no_launcher = canonical.clone();
    no_launcher.launcher_authenticated = false;
    assert!(no_launcher.validate().is_err());
    let mut pending_recovery = canonical.clone();
    pending_recovery.recovery_clear = false;
    assert!(pending_recovery.validate().is_err());
    let mut wrong_namespace = canonical.clone();
    wrong_namespace.format = "memcordon.saved-qualification".into();
    assert!(wrong_namespace.validate().is_err());
    let mut stale_revision = canonical.clone();
    stale_revision.revision += 1;
    assert!(stale_revision.validate().is_err());
    let mut absent_source = canonical.clone();
    absent_source.provider_binding.source_commit =
        memcordon_core::BoundedText::new(&"0".repeat(std::mem::size_of::<[u8; 32]>() * 2)).unwrap();
    assert!(absent_source.validate().is_err());
    let mut absent_manifest = canonical.clone();
    absent_manifest.provider_binding.runtime_manifest_sha256 =
        memcordon_core::DiagnosticSha256::from_bytes([0; 32]);
    assert!(absent_manifest.validate().is_err());
    let mut busy = canonical;
    busy.attempts_empty = false;
    busy.validate()
        .expect("busy is a real live observation, not a permission failure");
}

#[test]
fn windows_retained_and_retired_outcomes_require_exact_typed_bindings() {
    let attempt_id = "a".repeat(64);
    let request_sha256 = "b".repeat(64);
    let terminal_response_sha256 = "c".repeat(64);
    let retained = WindowsRetainedMetadata {
        causal_diagnostics: memcordon_core::WindowsCausalDiagnosticsV1::default(),
        provider_failure: None,
        diagnostic_availability:
            memcordon_core::DiagnosticProjectionAvailabilityV1::RecordUnavailable,
        attempt_id: attempt_id.clone(),
        nonce: "nonce".to_owned(),
        request_sha256: request_sha256.clone(),
        relay_phase: WindowsRelayPhaseV1::AwaitAbortRejection,
        durable_state: Some(WindowsAttemptStateV1::Empty),
        terminal_disposition: Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort),
        cleanup_complete: true,
        terminal_replay_available: true,
        authority_retained: true,
        primary_detail: "terminal delivery failed".to_owned(),
        secondary_failures: vec!["replay pipe unavailable".to_owned()],
    };
    assert!(retained.is_consistent_for(
        &attempt_id,
        "nonce",
        &request_sha256,
        WindowsRelayPhaseV1::AwaitAbortRejection,
    ));
    let mut contradictory = retained.clone();
    contradictory.cleanup_complete = false;
    assert!(!contradictory.is_consistent_for(
        &attempt_id,
        "nonce",
        &request_sha256,
        WindowsRelayPhaseV1::AwaitAbortRejection,
    ));

    let retired = WindowsRetirementMetadata {
        attempt_id: attempt_id.clone(),
        nonce: "nonce".to_owned(),
        request_sha256: request_sha256.clone(),
        terminal_response_sha256: terminal_response_sha256.clone(),
        disposition: WindowsAttemptTerminalDispositionV1::PreauthorizationAbort,
    };
    assert!(retired.is_consistent_for(
        &attempt_id,
        "nonce",
        &request_sha256,
        &terminal_response_sha256,
    ));
    assert!(!retired.is_consistent_for(&attempt_id, "nonce", &request_sha256, &"d".repeat(64),));
}

#[test]
fn windows_stream_manifest_requires_exact_unique_owned_roles() {
    let canonical = vec![
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stdin,
            remote_handle: 11,
        },
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stdout,
            remote_handle: 12,
        },
        WindowsRemoteStreamV1 {
            role: WindowsStreamRoleV1::Stderr,
            remote_handle: 13,
        },
    ];
    assert!(validate_windows_stream_manifest(&canonical).is_ok());

    let mut omitted = canonical.clone();
    omitted.pop();
    assert!(validate_windows_stream_manifest(&omitted).is_err());

    let mut duplicate_role = canonical.clone();
    duplicate_role[2].role = WindowsStreamRoleV1::Stdout;
    assert!(validate_windows_stream_manifest(&duplicate_role).is_err());

    let mut duplicate_handle = canonical.clone();
    duplicate_handle[2].remote_handle = duplicate_handle[1].remote_handle;
    assert!(validate_windows_stream_manifest(&duplicate_handle).is_err());

    let mut null_handle = canonical;
    null_handle[0].remote_handle = 0;
    assert!(validate_windows_stream_manifest(&null_handle).is_err());
}

#[test]
fn windows_attempt_state_machine_rejects_authorization_shortcuts() {
    assert!(windows_attempt_transition_allowed(
        WindowsAttemptStateV1::BoundaryCreated,
        WindowsAttemptStateV1::GuardianReady,
    ));
    assert!(!windows_attempt_transition_allowed(
        WindowsAttemptStateV1::BoundaryCreated,
        WindowsAttemptStateV1::Authorized,
    ));
    assert!(!windows_attempt_transition_allowed(
        WindowsAttemptStateV1::GuardianReady,
        WindowsAttemptStateV1::Authorized,
    ));
    assert!(windows_attempt_transition_allowed(
        WindowsAttemptStateV1::TargetCreatedSuspended,
        WindowsAttemptStateV1::Authorized,
    ));
    assert!(!windows_attempt_transition_allowed(
        WindowsAttemptStateV1::Empty,
        WindowsAttemptStateV1::BoundaryCreated,
    ));
}

#[test]
fn windows_security_descriptor_text_rejects_malformed_ace_shapes() {
    assert!(validate_windows_security_descriptor_text("D:P(A;;GA;;;SY)(A;;GR;;;AU)").is_ok());
    assert!(validate_windows_security_descriptor_text("O:SYD:P(A;;GA;;;SY)").is_ok());
    assert!(validate_windows_security_descriptor_text("O:SYG:SYD:P(A;;GA;;;SY)").is_ok());
    assert!(
        validate_windows_security_descriptor_text("O:S-1-5-18G:S-1-5-18D:P(A;;GA;;;S-1-5-18)")
            .is_ok()
    );
    assert!(validate_windows_security_descriptor_text("G:SYD:P(A;;GA;;;SY)").is_ok());
    assert!(validate_windows_security_descriptor_text("S:(ML;;NW;;;LW)").is_err());
    assert!(validate_windows_security_descriptor_text("D:P").is_err());
    assert!(validate_windows_security_descriptor_text("D:PS:(ML;;NW;;;LW)").is_err());
    assert!(validate_windows_security_descriptor_text("D:P(A;;GA;;;SY").is_err());
    assert!(validate_windows_security_descriptor_text("D:P((A;;GA;;;SY))").is_err());
    for malformed in [
        "O:G:SYD:P(A;;GA;;;SY)",
        "O:SYG:D:P(A;;GA;;;SY)",
        "O:SYG:SY",
        "O:SYG:SYG:SYD:P(A;;GA;;;SY)",
        "G:SYO:SYD:P(A;;GA;;;SY)",
        "D:P(A;;GA;;;SY)G:SY",
        "D:P(A;;GA;;;SY)S:(ML;;NW;;;LW)G:SY",
        "D:P(A;;GA;;;SY)S:(ML;;NW;;;LW)S:(ML;;NW;;;LW)",
        "O:SY:D:P(A;;GA;;;SY)",
    ] {
        assert!(
            validate_windows_security_descriptor_text(malformed).is_err(),
            "unexpectedly accepted {malformed}"
        );
    }
}

#[test]
fn windows_nonspawn_provider_rejection_has_consistent_public_provenance() {
    let rejection = ProviderRejectionEvidence {
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-WINDOWS-JOB".to_owned(),
        phase: BoundarySetupPhase::BoundaryCreation,
        detail: "certification rejection".to_owned(),
        os_code: Some(5),
        loader_qualification: None,
        target_created: false,
        target_released: false,
        cleanup_attempted: false,
        restart_safety: RestartSafetyProof::default(),
    };
    let record = SupervisionErrorRecord {
        native_startup: None,
        category: "setup".to_owned(),
        code: "MCSEALED-PROVIDER-REJECTION".to_owned(),
        message: "provider rejected launch".to_owned(),
        os_code: Some(5),
        attempt_number: Some(1),
        supervision_phase: SupervisionPhase::AttemptSetup,
        launch_phase: Some("boundary-creation".to_owned()),
        target_released: false,
        workload_may_be_alive: false,
        initial_spawn_failure: None,
        provider_rejection: Some(rejection),
        backend_selection_drift: None,
    };
    assert!(record.is_consistent());

    let mut windows_specific_wrapper = record;
    windows_specific_wrapper.code = "MCSEALED-WINDOWS-REJECTION".to_owned();
    assert!(!windows_specific_wrapper.is_consistent());
}

#[test]
fn windows_relay_phase_rejects_skipped_duplicate_reversed_and_late_abort_events() {
    use WindowsRelayEventV1 as Event;
    use WindowsRelayPhaseV1 as Phase;

    let valid = [
        Event::StreamsPrepared,
        Event::RelaysReady,
        Event::TargetAuthorized,
        Event::TargetRetired,
        Event::RelaysRetired,
        Event::Terminal,
    ];
    let mut phase = Phase::AwaitStreams;
    for event in valid {
        phase.advance(event).expect("valid relay transition");
    }
    assert_eq!(phase, Phase::Terminal);

    for sequence in [
        vec![Event::TargetAuthorized],
        vec![Event::StreamsPrepared, Event::StreamsPrepared],
        vec![Event::StreamsPrepared, Event::TargetAuthorized],
        vec![
            Event::StreamsPrepared,
            Event::RelaysReady,
            Event::TargetRetired,
        ],
        vec![
            Event::StreamsPrepared,
            Event::RelaysReady,
            Event::TargetAuthorized,
            Event::RelaysAbort,
        ],
        vec![
            Event::StreamsPrepared,
            Event::RelaysReady,
            Event::TargetAuthorized,
            Event::Terminal,
        ],
    ] {
        let mut phase = Phase::AwaitStreams;
        assert!(
            sequence
                .into_iter()
                .try_for_each(|event| phase.advance(event))
                .is_err()
        );
    }

    let mut abort = Phase::AwaitStreams;
    for event in [
        Event::StreamsPrepared,
        Event::RelaysReady,
        Event::RelaysAbort,
        Event::RelaysRetired,
        Event::Reject,
    ] {
        abort.advance(event).expect("valid preauthorization abort");
    }
    assert_eq!(abort, Phase::Terminal);
}

#[test]
fn windows_cleanup_identity_schema_rejects_unknown_and_omitted_fields() {
    let cleanup = WindowsCleanupProcessCreationEvidenceV1 {
        schema_version: 1,
        attempt_binding: format!("attempt-{}", sha256(b"cleanup-attempt")),
        attempted_after_terminating_transition: true,
        child_created: true,
        child_job_membership_verified: true,
        child_identity: WindowsProcessIdentityV1 {
            process_id: 41,
            creation_time_100ns: 73,
        },
        total_processes_before: 1,
        total_processes_after: 2,
        final_active_processes_zero: true,
    };
    let mut unknown = serde_json::to_value(&cleanup).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WindowsCleanupProcessCreationEvidenceV1>(unknown).is_err());

    let mut omitted = serde_json::to_value(cleanup).unwrap();
    omitted.as_object_mut().unwrap().remove("child_identity");
    assert!(serde_json::from_value::<WindowsCleanupProcessCreationEvidenceV1>(omitted).is_err());
}

#[test]
fn windows_public_terminal_recovery_is_bound_peer_close_only_and_one_shot() {
    let mut recovery = WindowsPublicTerminalRecoveryV1::default();
    assert_eq!(
        recovery.observe_failure(WindowsPublicFrameFailureV1::PeerClosed(
            WindowsPublicFramePhaseV1::Length,
        )),
        WindowsTerminalReplayDecisionV1::FailClosed,
    );
    recovery.bind_attempt().unwrap();
    assert_eq!(
        recovery.observe_failure(WindowsPublicFrameFailureV1::Protocol(
            WindowsPublicFramePhaseV1::Decode,
        )),
        WindowsTerminalReplayDecisionV1::FailClosed,
    );
    assert_eq!(
        recovery.observe_failure(WindowsPublicFrameFailureV1::PeerClosed(
            WindowsPublicFramePhaseV1::Payload,
        )),
        WindowsTerminalReplayDecisionV1::ReplayOnce,
    );
    assert!(recovery.retire_local_relays_once());
    assert!(!recovery.retire_local_relays_once());
    assert_eq!(
        recovery.observe_failure(WindowsPublicFrameFailureV1::PeerClosed(
            WindowsPublicFramePhaseV1::Availability,
        )),
        WindowsTerminalReplayDecisionV1::FailClosed,
    );
}

#[test]
fn windows_public_terminal_pending_is_exactly_bound() {
    let digest = sha256(b"request");
    let attempt = sha256(b"attempt");
    let pending = WindowsReplayMetadata {
        causal_diagnostics: memcordon_core::WindowsCausalDiagnosticsV1::default(),
        provider_failure: None,
        diagnostic_availability:
            memcordon_core::DiagnosticProjectionAvailabilityV1::RecordUnavailable,
        attempt_id: attempt.clone(),
        nonce: "nonce".to_owned(),
        request_sha256: digest.clone(),
        relay_phase: WindowsRelayPhaseV1::AwaitAbortRejection,
        durable_state: WindowsAttemptStateV1::Terminating,
        terminal_disposition: None,
        authorization_present: false,
        resume_attempted: false,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1::default(),
        cleanup_complete: false,
        outbox_stage: WindowsReplayOutboxStageV1::NotAttempted,
        terminalization: WindowsTerminalizationStatusV1 {
            schema_version: 1,
            owner: WindowsTerminalizationOwnerV1::LauncherWorker,
            sequence: 1,
            checkpoint: WindowsTerminalizationCheckpointV1::Executing,
            last_error: None,
            secondary_errors: Vec::new(),
        },
        detail: "durable terminal is not staged".to_owned(),
    };
    assert!(pending.is_consistent_for(
        &attempt,
        "nonce",
        &digest,
        WindowsRelayPhaseV1::AwaitAbortRejection,
    ));
    assert!(!pending.is_consistent_for(
        &attempt,
        "nonce",
        &sha256(b"other"),
        WindowsRelayPhaseV1::AwaitAbortRejection,
    ));
    let mut recovery = WindowsPublicTerminalRecoveryV1::default();
    recovery.bind_attempt().unwrap();
    assert_eq!(
        recovery.begin_replay_after_bound_pending(),
        WindowsTerminalReplayDecisionV1::ReplayOnce,
    );
    assert_eq!(
        recovery.begin_replay_after_bound_pending(),
        WindowsTerminalReplayDecisionV1::FailClosed,
    );
}
