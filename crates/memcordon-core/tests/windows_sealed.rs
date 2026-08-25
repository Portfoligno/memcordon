use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    ProviderRejectionEvidence, RestartSafetyProof, RunOutcome, SupervisionErrorRecord,
    SupervisionPhase, WINDOWS_MAX_JOB_PROCESS_IDENTITIES, WINDOWS_QUALIFICATION_SCHEMA_VERSION,
    WindowsAttemptStateV1, WindowsDurableAttemptRecordV1, WindowsDurableCleanupStateV1,
    WindowsEnvironmentEntryV1, WindowsProcessIdentityV1, WindowsProviderRequestV1,
    WindowsQualificationReceiptV1, WindowsRemoteStreamV1, WindowsSealedEvidenceV2,
    WindowsStreamRoleV1, WindowsTerminalReceiptV1, decode_windows_command_line,
    encode_windows_command_line, encode_windows_environment_block,
    parse_and_authenticate_windows_attempt_record, validate_windows_security_descriptor_text,
    validate_windows_stream_manifest, windows_attempt_transition_allowed,
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

fn qualification() -> WindowsQualificationReceiptV1 {
    WindowsQualificationReceiptV1 {
        schema_version: WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
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
        qualified: true,
    }
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
fn windows_environment_uses_one_case_key_and_native_size_limit() {
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
        schema_version: 1,
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
fn windows_security_descriptor_text_rejects_malformed_ace_shapes() {
    assert!(validate_windows_security_descriptor_text("D:P(A;;GA;;;SY)(A;;GR;;;AU)").is_ok());
    assert!(validate_windows_security_descriptor_text("O:SYD:P(A;;GA;;;SY)").is_ok());
    assert!(validate_windows_security_descriptor_text("S:(ML;;NW;;;LW)").is_err());
    assert!(validate_windows_security_descriptor_text("D:P").is_err());
    assert!(validate_windows_security_descriptor_text("D:P(A;;GA;;;SY").is_err());
    assert!(validate_windows_security_descriptor_text("D:P((A;;GA;;;SY))").is_err());
}

#[test]
fn windows_nonspawn_provider_rejection_has_consistent_public_provenance() {
    let rejection = ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-WINDOWS-JOB".to_owned(),
        phase: BoundarySetupPhase::BoundaryCreation,
        detail: "certification rejection".to_owned(),
        os_code: Some(5),
        target_created: false,
        target_released: false,
        cleanup_attempted: false,
        restart_safety: RestartSafetyProof::default(),
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
