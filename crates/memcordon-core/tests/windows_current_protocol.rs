use memcordon_core::*;

#[path = "support/windows_current_postauthorization.rs"]
mod fixture;

#[test]
fn current_prepared_commitment_binds_native_target_and_frozen_owner_set() {
    let prepared = WindowsWorkloadPreparedV1 {
        format: "memcordon.windows-workload-prepared".into(),
        revision: 1,
        attempt_id: "ab".repeat(32),
        nonce: "native-random-nonce".into(),
        request_sha256: "cd".repeat(32),
        target: WindowsProcessIdentityV1 {
            process_id: 4321,
            creation_time_100ns: 0,
        },
        owner_manifest_sha256: "ef".repeat(32),
    };
    prepared.validate().unwrap();
    let commitment = prepared.canonical_sha256().unwrap();
    for dimension in 0..6 {
        let mut substituted = prepared.clone();
        match dimension {
            0 => substituted.attempt_id = "12".repeat(32),
            1 => substituted.nonce.push('x'),
            2 => substituted.request_sha256 = "34".repeat(32),
            3 => substituted.target.process_id += 1,
            4 => substituted.target.creation_time_100ns += 1,
            _ => substituted.owner_manifest_sha256 = "56".repeat(32),
        }
        assert_ne!(substituted.canonical_sha256().unwrap(), commitment);
    }
    let mut invalid = prepared.clone();
    invalid.target.process_id = 0;
    assert!(invalid.validate().is_err());
    let mut unknown = serde_json::to_value(&prepared).unwrap();
    unknown["authority"] = serde_json::json!(true);
    assert!(serde_json::from_value::<WindowsWorkloadPreparedV1>(unknown).is_err());
    let response = WindowsProviderResponseV4::WorkloadPrepared(prepared);
    let roundtrip: WindowsProviderResponseV4 =
        serde_json::from_slice(&serde_json::to_vec(&response).unwrap()).unwrap();
    let WindowsProviderResponseV4::WorkloadPrepared(actual) = roundtrip else {
        panic!("current prepared frame changed kind")
    };
    assert_eq!(actual.canonical_sha256().unwrap(), commitment);
}

#[test]
fn current_suspended_cancellation_retains_cleanup_wait_without_claiming_resume() {
    let rejection = fixture::rejection();
    let mut terminal = rejection.terminal_receipt().unwrap().clone();
    let WindowsTerminalPayloadV3::Execution {
        outcome,
        boundary_detail,
        ..
    } = &mut terminal.payload
    else {
        panic!("native execution carrier required")
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_mut() else {
        panic!("current native Windows facts required")
    };
    native.target_released = false;
    *outcome = RunOutcome::Interrupted {
        signal: Interruption { signal: 2 },
        child_after_termination: Some(ChildTermination::WindowsStatus { status: 0xc000013a }),
        cleanup: CleanupSummary {
            force_attempted: true,
            direct_child_reaped: true,
            workload_empty: Some(true),
            ..CleanupSummary::default()
        },
    };
    terminal.validate_for_attempt().unwrap();
    assert!(
        terminal
            .restart_safety
            .is_safe_for(BoundaryRequirement::Sealed)
    );
}

#[test]
fn current_terminal_retirement_cannot_cross_attempt_or_manufacture_wait() {
    let rejection = fixture::rejection();
    assert!(rejection.is_consistent());
    let terminal = rejection.terminal_receipt().unwrap();
    terminal.validate_for_attempt().unwrap();

    let mut crossed = terminal.clone();
    crossed.retirement_proof.nonce.push('x');
    assert!(crossed.validate_for_attempt().is_err());

    let mut missing_retirement = terminal.clone();
    missing_retirement
        .retirement_proof
        .owner_capabilities_closed = false;
    assert!(missing_retirement.validate_for_attempt().is_err());

    let mut false_wait = terminal.clone();
    false_wait.payload = WindowsTerminalPayloadV3::RecoveredClosure {
        primary_failure: rejection
            .provider_failure
            .as_ref()
            .unwrap()
            .original
            .clone(),
        target_creation_observed: true,
        resume_attempted: true,
    };
    assert!(false_wait.validate_for_attempt().is_err());
}

#[test]
fn current_rejection_joins_actual_frozen_native_terminal() {
    let mut rejection = fixture::rejection();
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        panic!("fixture requires a real postauthorization terminal")
    };
    receipt.request_sha256 = "34".repeat(32);
    assert!(!rejection.is_consistent());
}

#[test]
fn current_wire_rejects_unknown_fields_and_unsupported_versions() {
    let request = WindowsProviderRequestV4::Probe {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
    };
    let mut unknown = serde_json::to_value(request).unwrap();
    unknown["approval"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<WindowsProviderRequestV4>(unknown).is_err());

    let rejection = fixture::rejection();
    let launch = WindowsLaunchRequestV2 {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION + 1,
        expected_provider_binding: rejection.provider_failure.unwrap().provider_binding,
        workload_request: None,
        loader_diagnostic: None,
        restart_attempt: 0,
        nonce: "native-current-launch".into(),
        command: NativeWindowsCommandV1 {
            program: "fixture.exe".encode_utf16().collect(),
            arguments: Vec::new(),
        },
        environment: Vec::new(),
        current_directory: "C:\\fixture".encode_utf16().collect(),
        policy: WindowsLaunchPolicyV1 {
            memory_limit_bytes: None,
            absolute_deadline_millis: None,
            lifetime: WindowsLifetimeV1::Command,
            poll_interval_millis: 10,
            signal_grace_millis: 1000,
            command_exit_grace_millis: 0,
            limit_grace_millis: 0,
        },
    };
    assert!(launch.validate_workload().is_err());
}

#[test]
fn current_frontend_delivery_requires_both_native_validation_and_acknowledgment() {
    let mut delivery = WindowsFrontendDeliveryV3 {
        attempt_id: "ab".repeat(32),
        nonce: "native-nonce".into(),
        request_sha256: "cd".repeat(32),
        terminal_sha256: "ef".repeat(32),
        retired_sha256: "12".repeat(32),
        terminal_validated: true,
        acknowledgement_observed: true,
    };
    assert!(delivery.is_consistent());
    delivery.acknowledgement_observed = false;
    assert!(!delivery.is_consistent());
    delivery.acknowledgement_observed = true;
    delivery.terminal_validated = false;
    assert!(!delivery.is_consistent());
}
