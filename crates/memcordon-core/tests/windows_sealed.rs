use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    CredentialTransitionDisposition, ProviderRejectionEvidence, RestartSafetyProof, RunOutcome,
    SupervisionErrorRecord, SupervisionPhase, WINDOWS_MAX_JOB_PROCESS_IDENTITIES,
    WINDOWS_QUALIFICATION_SCHEMA_VERSION, WindowsAttemptRetainedV1, WindowsAttemptStateV1,
    WindowsAttemptTerminalDispositionV1, WindowsCleanupProcessCreationEvidenceV1,
    WindowsDurableAttemptRecordV1, WindowsDurableCleanupStateV1, WindowsEnvironmentEntryV1,
    WindowsLaunchBrokerRequestV1, WindowsLauncherResponseV1, WindowsProcessIdentityV1,
    WindowsProviderRequestV1, WindowsPublicFrameFailureV1, WindowsPublicFramePhaseV1,
    WindowsPublicTerminalRecoveryV1, WindowsQualificationReceiptV1, WindowsRelayEventV1,
    WindowsRelayPhaseV1, WindowsRemoteStreamV1, WindowsReplayOutboxStageV1, WindowsReplayPendingV1,
    WindowsSealedEvidenceV2, WindowsServiceSelfAttestationV1, WindowsStreamRoleV1,
    WindowsTerminalReceiptV1, WindowsTerminalReplayDecisionV1, WindowsTerminalRetiredV1,
    WindowsTerminalizationCheckpointV1, WindowsTerminalizationOwnerV1,
    WindowsTerminalizationStatusV1, decode_windows_command_line, encode_windows_command_line,
    encode_windows_environment_block, parse_and_authenticate_windows_attempt_record,
    parse_windows_certification_frontend_handle_values, validate_windows_security_descriptor_text,
    validate_windows_stream_manifest, windows_attempt_transition_allowed,
    windows_certification_argument_prelude_len,
};
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

fn authenticate_signed_attempt_record(
    record: &mut WindowsDurableAttemptRecordV1,
) -> Result<WindowsDurableAttemptRecordV1, &'static str> {
    record.integrity_sha256.clear();
    record.integrity_sha256 = sha256(&serde_json::to_vec(record).unwrap());
    parse_and_authenticate_windows_attempt_record(
        &serde_json::to_vec(record).unwrap(),
        &record.attempt_id,
        &record.provider_generation,
    )
}

fn qualification() -> WindowsQualificationReceiptV1 {
    WindowsQualificationReceiptV1 {
        schema_version: WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        guardian_pool_identity: "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            .to_owned(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
        guardian_slot_tokens_verified: true,
        guardian_slot_loader_verified: true,
        guardian_capacity_verified: true,
        caller_token_authentication_verified: true,
        restricted_caller_token_verified: true,
        primary_token_duplication_verified: true,
        create_process_as_user_verified: true,
        job_list_supported: true,
        handle_list_supported: true,
        nested_host_job_supported: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_verified: true,
        guardian_verified: true,
        frontend_loss_cleanup_verified: true,
        alternate_token_child_contained: true,
        nested_child_job_contained: true,
        recursive_provider_request_denied: true,
        exact_handle_inheritance_verified: true,
        active_processes_zero_verified: true,
        relays_retired_verified: true,
        recovery_complete: true,
        loader_qualification: memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
            memcordon_core::WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256: sha256(b"production-plan"),
                elapsed_millis: 1,
            },
        ),
        qualified: true,
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
fn windows_qualification_requires_every_native_predicate() {
    let canonical = qualification();
    assert!(canonical.is_consistent());

    let mut missing_guardian = canonical.clone();
    missing_guardian.guardian_verified = false;
    assert!(!missing_guardian.is_consistent());

    let mut stale_schema = canonical;
    stale_schema.schema_version = WINDOWS_QUALIFICATION_SCHEMA_VERSION + 1;
    assert!(!stale_schema.is_consistent());
}

#[test]
fn windows_protocol_rejects_unknown_fields() {
    let value = serde_json::json!({
        "message": "probe",
        "schema_version": 1,
        "unexpected": true
    });
    assert!(serde_json::from_value::<WindowsProviderRequestV1>(value).is_err());
}

#[test]
fn windows_launch_broker_protocol_rejects_restricted_diagnostic_token_relay() {
    let error = serde_json::from_value::<WindowsLaunchBrokerRequestV1>(serde_json::json!({
        "loader_restriction_canary": null
    }))
    .unwrap_err();
    assert!(error.to_string().contains("loader_restriction_canary"));
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn windows_retained_and_retired_outcomes_require_exact_typed_bindings() {
    let attempt_id = "a".repeat(64);
    let request_sha256 = "b".repeat(64);
    let terminal_response_sha256 = "c".repeat(64);
    let retained = WindowsAttemptRetainedV1 {
        schema_version: 1,
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

    let retired = WindowsTerminalRetiredV1 {
        schema_version: 1,
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
fn windows_durable_attempt_parser_authenticates_and_bounds_real_records() {
    let digest = sha256(&[]);
    let mut record = WindowsDurableAttemptRecordV1 {
        schema_version: 2,
        attempt_id: digest.clone(),
        provider_generation: "windows-provider-generation".to_owned(),
        boot_identity: "boot-identity".to_owned(),
        request_sha256: digest.clone(),
        caller_process_identity: WindowsProcessIdentityV1 {
            process_id: 17,
            creation_time_100ns: 23,
        },
        caller_token_sha256: digest.clone(),
        job_identity_sha256: digest.clone(),
        guardian_identity: None,
        target_identity: None,
        state: WindowsAttemptStateV1::BoundaryCreated,
        authorization_unix_millis: None,
        resume_attempted: false,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1::default(),
        terminal_response_json: None,
        terminal_disposition: None,
        terminalization: WindowsTerminalizationStatusV1 {
            schema_version: 1,
            owner: WindowsTerminalizationOwnerV1::LauncherWorker,
            sequence: 1,
            checkpoint: WindowsTerminalizationCheckpointV1::Executing,
            last_error: None,
            secondary_errors: Vec::new(),
        },
        integrity_sha256: String::new(),
    };
    record.integrity_sha256 = sha256(&serde_json::to_vec(&record).unwrap());
    let bytes = serde_json::to_vec(&record).unwrap();
    assert!(
        parse_and_authenticate_windows_attempt_record(
            &bytes,
            &record.attempt_id,
            &record.provider_generation,
        )
        .is_ok()
    );

    let mut tampered = record.clone();
    tampered.target_released = true;
    assert!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&tampered).unwrap(),
            &record.attempt_id,
            &record.provider_generation,
        )
        .is_err()
    );

    let mut pending = record.clone();
    pending.state = WindowsAttemptStateV1::Empty;
    pending.authorization_unix_millis = Some(1);
    pending.resume_attempted = true;
    pending.target_released = true;
    pending.target_identity = Some(WindowsProcessIdentityV1 {
        process_id: 29,
        creation_time_100ns: 31,
    });
    pending.cleanup_state = WindowsDurableCleanupStateV1 {
        termination_requested: true,
        active_processes_zero: true,
        guardian_reaped: true,
        final_handles_closed: true,
    };
    let mut terminal = complete_windows_certification_terminal();
    terminal.attempt_id = digest.clone();
    terminal.request_sha256 = digest.clone();
    pending.terminal_response_json =
        Some(serde_json::to_string(&WindowsLauncherResponseV1::Terminal(terminal)).unwrap());
    pending.terminal_disposition =
        Some(memcordon_core::WindowsAttemptTerminalDispositionV1::Posttarget);
    pending.terminalization.sequence += 1;
    pending.terminalization.checkpoint = WindowsTerminalizationCheckpointV1::OutboxStaged;
    pending.integrity_sha256.clear();
    pending.integrity_sha256 = sha256(&serde_json::to_vec(&pending).unwrap());
    assert!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&pending).unwrap(),
            &pending.attempt_id,
            &pending.provider_generation,
        )
        .is_ok()
    );

    let mut mismatched_outbox = pending.clone();
    let mut terminal = complete_windows_certification_terminal();
    terminal.attempt_id = "d".repeat(64);
    terminal.request_sha256 = digest.clone();
    mismatched_outbox.terminal_response_json =
        Some(serde_json::to_string(&WindowsLauncherResponseV1::Terminal(terminal)).unwrap());
    mismatched_outbox.integrity_sha256.clear();
    mismatched_outbox.integrity_sha256 = sha256(&serde_json::to_vec(&mismatched_outbox).unwrap());
    assert!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&mismatched_outbox).unwrap(),
            &mismatched_outbox.attempt_id,
            &mismatched_outbox.provider_generation,
        )
        .is_err()
    );

    let mut unknown = serde_json::to_value(record).unwrap();
    unknown["unknown"] = serde_json::json!(true);
    assert!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&unknown).unwrap(),
            &digest,
            "windows-provider-generation",
        )
        .is_err()
    );
}

#[test]
fn windows_attempt_record_authenticates_only_typed_preauthorization_abort_release() {
    let digest = sha256(&[]);
    let process_identity = WindowsProcessIdentityV1 {
        process_id: 17,
        creation_time_100ns: 23,
    };
    let mut record = WindowsDurableAttemptRecordV1 {
        schema_version: 2,
        attempt_id: digest.clone(),
        provider_generation: "windows-provider-generation".to_owned(),
        boot_identity: "boot-identity".to_owned(),
        request_sha256: digest.clone(),
        caller_process_identity: process_identity.clone(),
        caller_token_sha256: digest.clone(),
        job_identity_sha256: digest,
        guardian_identity: Some(process_identity.clone()),
        target_identity: Some(process_identity),
        state: WindowsAttemptStateV1::TargetCreatedSuspended,
        authorization_unix_millis: None,
        resume_attempted: true,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1::default(),
        terminal_response_json: None,
        terminal_disposition: None,
        terminalization: WindowsTerminalizationStatusV1 {
            schema_version: 1,
            owner: WindowsTerminalizationOwnerV1::LauncherWorker,
            sequence: 1,
            checkpoint: WindowsTerminalizationCheckpointV1::Executing,
            last_error: None,
            secondary_errors: Vec::new(),
        },
        integrity_sha256: String::new(),
    };

    assert_eq!(
        authenticate_signed_attempt_record(&mut record),
        Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-resume-without-authorization")
    );

    record.resume_attempted = false;
    record.state = WindowsAttemptStateV1::Terminating;
    record.cleanup_state.termination_requested = true;
    record.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    assert!(authenticate_signed_attempt_record(&mut record).is_ok());

    record.target_released = true;
    assert!(authenticate_signed_attempt_record(&mut record).is_ok());

    let mut untyped_release = record.clone();
    untyped_release.terminal_disposition = None;
    assert_eq!(
        authenticate_signed_attempt_record(&mut untyped_release),
        Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-release-without-intent")
    );

    let mut before_target_creation = record.clone();
    before_target_creation.target_identity = None;
    before_target_creation.target_released = false;
    assert!(authenticate_signed_attempt_record(&mut before_target_creation).is_ok());

    authenticate_signed_attempt_record(&mut record).unwrap();
    record.boot_identity = "tampered-boot-identity".to_owned();
    assert_eq!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&record).unwrap(),
            &record.attempt_id,
            &record.provider_generation,
        ),
        Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=integrity-digest")
    );
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
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let record = SupervisionErrorRecord {
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
    };
    assert!(record.is_consistent());

    let mut windows_specific_wrapper = record;
    windows_specific_wrapper.code = "MCSEALED-WINDOWS-REJECTION".to_owned();
    assert!(!windows_specific_wrapper.is_consistent());
}

#[test]
fn windows_posttarget_rejection_retains_truthful_terminal_receipt() {
    let terminal = complete_windows_certification_terminal();
    let rejection = ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-WINDOWS-CLEANUP-PRODUCER-IO".to_owned(),
        phase: BoundarySetupPhase::Retirement,
        detail: "producer_phase=StartObserved attempted_phase=SpawnEntered operation=state-publish-rename"
            .to_owned(),
        os_code: Some(5),
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: terminal.restart_safety.clone(),
        terminal_ack_required: true,
        terminal_receipt: Some(Box::new(terminal.clone())),
    };
    assert!(rejection.is_consistent());
    let round_trip: ProviderRejectionEvidence =
        serde_json::from_slice(&serde_json::to_vec(&rejection).unwrap()).unwrap();
    assert_eq!(round_trip.terminal_receipt.as_deref(), Some(&terminal));

    let mut malformed_loader_evidence = rejection.clone();
    malformed_loader_evidence.loader_qualification =
        Some(memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
            memcordon_core::WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256: String::from("not-a-sha256"),
                elapsed_millis: 1,
            },
        ));
    assert!(!malformed_loader_evidence.is_consistent());

    let mut contradictory = rejection;
    contradictory.target_released = false;
    assert!(!contradictory.is_consistent());
}

#[test]
fn windows_preauthorization_abort_can_require_ack_without_target_receipt() {
    let rejection = ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-WINDOWS-LAUNCH".to_owned(),
        phase: BoundarySetupPhase::TargetCreation,
        detail: "target creation failed after stream publication".to_owned(),
        os_code: Some(5),
        loader_qualification: None,
        target_created: false,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
        terminal_ack_required: true,
        terminal_receipt: None,
    };
    assert!(rejection.is_consistent());
    let encoded = serde_json::to_value(&rejection).unwrap();
    assert_eq!(encoded["terminal_ack_required"], true);

    let mut unsafe_ack = rejection;
    unsafe_ack.cleanup_attempted = false;
    assert!(!unsafe_ack.is_consistent());
}

#[test]
fn windows_terminal_process_identity_inventory_is_bounded_and_unique() {
    let mut receipt = WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: "a".repeat(64),
        nonce: "nonce".to_owned(),
        request_sha256: "b".repeat(64),
        child_pid: 1,
        duration_millis: 1,
        authorization_offset_millis: 0,
        job_total_processes: 1,
        job_process_identities: (0..WINDOWS_MAX_JOB_PROCESS_IDENTITIES)
            .map(|index| memcordon_core::WindowsProcessIdentityV1 {
                process_id: u32::try_from(index + 1).unwrap(),
                creation_time_100ns: u64::try_from(index).unwrap(),
            })
            .collect(),
        cleanup_process_creation: None,
        outcome: RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 },
            peak: None,
            cleanup: CleanupSummary::default(),
        },
        restart_safety: RestartSafetyProof::default(),
        boundary_detail: BoundaryMechanismEvidence::WindowsJobObjectV2(
            WindowsSealedEvidenceV2::default(),
        ),
    };
    assert!(receipt.process_identity_inventory_is_bounded());
    receipt
        .job_process_identities
        .push(memcordon_core::WindowsProcessIdentityV1 {
            process_id: u32::try_from(WINDOWS_MAX_JOB_PROCESS_IDENTITIES + 1).unwrap(),
            creation_time_100ns: 0,
        });
    assert!(!receipt.process_identity_inventory_is_bounded());
    receipt.job_process_identities.pop();
    receipt.job_process_identities[1] = receipt.job_process_identities[0].clone();
    assert!(!receipt.process_identity_inventory_is_bounded());
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

fn complete_windows_certification_terminal() -> WindowsTerminalReceiptV1 {
    let attempt_binding = format!("attempt-{}", "a".repeat(64));
    WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: "b".repeat(64),
        nonce: "nonce".to_owned(),
        request_sha256: "c".repeat(64),
        child_pid: 10,
        duration_millis: 1,
        authorization_offset_millis: 1,
        job_total_processes: 18,
        job_process_identities: vec![WindowsProcessIdentityV1 {
            process_id: 10,
            creation_time_100ns: 10,
        }],
        cleanup_process_creation: Some(WindowsCleanupProcessCreationEvidenceV1 {
            schema_version: 1,
            attempt_binding,
            attempted_after_terminating_transition: true,
            child_created: true,
            child_job_membership_verified: true,
            child_identity: WindowsProcessIdentityV1 {
                process_id: 11,
                creation_time_100ns: 11,
            },
            total_processes_before: 17,
            total_processes_after: 18,
            final_active_processes_zero: true,
        }),
        outcome: RunOutcome::Exited {
            child: ChildTermination::ExitCode { code: 0 },
            peak: None,
            cleanup: CleanupSummary::default(),
        },
        restart_safety: RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            containment_incapable_of_live_members: true,
            sealed_boundary_retired: true,
            errors: Vec::new(),
        },
        boundary_detail: BoundaryMechanismEvidence::WindowsJobObjectV2(WindowsSealedEvidenceV2 {
            schema_version: 2,
            service_identity: "MemCordonSealedControl+MemCordonSealedLauncher:v1".to_owned(),
            caller_token_authenticated: true,
            initial_target_token_matches_caller: true,
            credential_transition_disposition:
                CredentialTransitionDisposition::PreserveCallerEnvelope,
            job_membership_independent_of_token: true,
            job_created: true,
            job_limits_verified: true,
            kill_on_close_verified: true,
            breakaway_denied: true,
            completion_port_associated: true,
            guardian_ready: true,
            target_created_suspended: true,
            job_list_applied_at_creation: true,
            handle_list_applied_at_creation: true,
            target_job_membership_verified: true,
            target_still_suspended_during_verification: true,
            inherited_handles_verified: true,
            target_released: true,
            terminate_job_invoked: true,
            active_processes_zero: true,
            direct_target_reaped: true,
            relays_retired: true,
            guardian_reaped: true,
            final_job_handles_closed: true,
            loader_qualification: None,
        }),
    }
}

#[test]
fn windows_certification_terminal_validator_names_cross_field_failures() {
    let complete = complete_windows_certification_terminal();
    let binding = complete
        .cleanup_process_creation
        .as_ref()
        .unwrap()
        .attempt_binding
        .clone();
    assert!(complete.validate_for_certification(&binding, 18).is_ok());

    let mut wrong_binding = complete.clone();
    wrong_binding
        .cleanup_process_creation
        .as_mut()
        .unwrap()
        .attempt_binding = "attempt-wrong".to_owned();
    assert_eq!(
        wrong_binding
            .validate_for_certification(&binding, 18)
            .unwrap_err(),
        "cleanup_process_creation.attempt_binding"
    );

    let mut zero_identity = complete.clone();
    zero_identity
        .cleanup_process_creation
        .as_mut()
        .unwrap()
        .child_identity
        .process_id = 0;
    assert_eq!(
        zero_identity
            .validate_for_certification(&binding, 18)
            .unwrap_err(),
        "cleanup_process_creation.child_identity.process_id"
    );

    let mut below_cleanup = complete.clone();
    below_cleanup.job_total_processes = 17;
    assert_eq!(
        below_cleanup
            .validate_for_certification(&binding, 17)
            .unwrap_err(),
        "job_total_processes.cleanup_floor"
    );

    let mut nonzero = complete;
    if let RunOutcome::Exited { child, .. } = &mut nonzero.outcome {
        *child = ChildTermination::ExitCode { code: 125 };
    }
    assert_eq!(
        nonzero
            .validate_for_certification(&binding, 18)
            .unwrap_err(),
        "outcome.child"
    );
}

#[test]
fn windows_cleanup_identity_schema_rejects_unknown_and_omitted_fields() {
    let cleanup = complete_windows_certification_terminal()
        .cleanup_process_creation
        .unwrap();
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
    let pending = WindowsReplayPendingV1 {
        schema_version: 2,
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
