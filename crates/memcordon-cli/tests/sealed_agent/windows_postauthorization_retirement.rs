use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    ProviderRejectionEvidence, RestartSafetyProof, RunOutcome, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WindowsLauncherResponseV1, WindowsProcessIdentityV1, WindowsSealedEvidenceV2,
    WindowsTerminalReceiptV1,
};

#[test]
fn revocation_remains_the_original_diagnostic_after_cleanup_failure() {
    use memcordon_core::{
        AttemptObservationPhaseV1, FailureCategoryV1, FailureCodeV1, FailureOperationV1,
        OriginalFailureV1, WindowsCausalDiagnosticsV1,
    };
    let event = crate::windows::launcher_service::policy_revocation_observation_for_test();
    assert_eq!(event.code, FailureCodeV1::PolicyRevoked);
    assert_eq!(event.code.display_code(), "MCSEALED-POLICY-DRIFT");
    assert_eq!(event.category, FailureCategoryV1::Monitor);
    assert_eq!(event.operation, FailureOperationV1::VerifyPolicy);
    assert_eq!(event.observed_phase, AttemptObservationPhaseV1::Monitoring);
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.observe(event.clone()).unwrap();
    let mut secondary = event;
    secondary.code = FailureCodeV1::JobQuery;
    secondary.operation = FailureOperationV1::WaitJobEmpty;
    secondary.observed_phase = AttemptObservationPhaseV1::Terminalizing;
    journal.observe(secondary).unwrap();
    let OriginalFailureV1::Observed { event: original } = &journal.original else {
        panic!("revocation original lost");
    };
    assert_eq!(original.code, FailureCodeV1::PolicyRevoked);
    let encoded = serde_json::to_vec(&journal).unwrap();
    assert_eq!(
        serde_json::from_slice::<WindowsCausalDiagnosticsV1>(&encoded).unwrap(),
        journal
    );
}

#[test]
fn policy_revocation_keeps_observed_status_in_a_bound_terminal_outbox() {
    let cleanup = CleanupSummary {
        force_attempted: true,
        direct_child_reaped: true,
        workload_empty: Some(true),
        ..CleanupSummary::default()
    };
    for observed_status in [37, 0xc000_013a] {
        let outcome = crate::windows::launcher_service::policy_revocation_outcome_for_test(
            observed_status,
            cleanup.clone(),
        );
        let RunOutcome::MonitorFailed {
            error,
            child_after_termination,
            cleanup: observed_cleanup,
        } = &outcome
        else {
            panic!("revocation must remain an explicit monitor failure");
        };
        assert_eq!(error, "MCSEALED-POLICY-DRIFT: active policy revoked");
        let expected_child = if observed_status == 37 {
            ChildTermination::ExitCode { code: 37 }
        } else {
            ChildTermination::WindowsStatus {
                status: observed_status,
            }
        };
        assert_eq!(child_after_termination, &Some(expected_child));
        assert_eq!(observed_cleanup, &cleanup);
        let terminal = WindowsTerminalReceiptV1 {
            policy_enforcement: Default::default(),
            schema_version: 1,
            attempt_id: "attempt-revoked".to_owned(),
            nonce: "nonce-revoked".to_owned(),
            request_sha256: "ab".repeat(32),
            child_pid: 412,
            duration_millis: 20,
            authorization_offset_millis: 7,
            job_total_processes: 1,
            job_process_identities: vec![WindowsProcessIdentityV1 {
                process_id: 412,
                creation_time_100ns: 991_337,
            }],
            cleanup_process_creation: None,
            outcome,
            restart_safety: RestartSafetyProof {
                direct_child_reaped: true,
                workload_empty: Some(true),
                helpers_reaped: true,
                containment_removed: true,
                containment_incapable_of_live_members: true,
                sealed_boundary_retired: true,
                errors: Vec::new(),
            },
            boundary_detail: BoundaryMechanismEvidence::WindowsJobObjectV2(
                WindowsSealedEvidenceV2 {
                    target_released: true,
                    terminate_job_invoked: true,
                    active_processes_zero: true,
                    direct_target_reaped: true,
                    relays_retired: true,
                    guardian_reaped: true,
                    final_job_handles_closed: true,
                    ..WindowsSealedEvidenceV2::default()
                },
            ),
        };
        let response = WindowsLauncherResponseV1::Terminal(terminal.clone());
        let disposition = Some(memcordon_core::WindowsAttemptTerminalDispositionV1::Posttarget);
        assert!(memcordon_core::windows_terminal_outbox_is_bound(
            &terminal.attempt_id,
            &terminal.request_sha256,
            disposition,
            &response
        ));
        assert!(!memcordon_core::windows_terminal_outbox_is_bound(
            "different-attempt",
            &terminal.request_sha256,
            disposition,
            &response
        ));
        let decoded: WindowsLauncherResponseV1 =
            serde_json::from_str(&response.terminal_authority_json().unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap(),
            serde_json::to_value(response).unwrap()
        );
    }
}

#[test]
fn suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox() {
    let digest = "9a".repeat(32);
    let nonce = "postauthorization-suspended-cancellation";
    let identity = WindowsProcessIdentityV1 {
        process_id: 412,
        creation_time_100ns: 991_337,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.guardian_identity = Some(identity.clone());
    record.target_identity = Some(identity.clone());
    record.state = crate::windows::record::WindowsAttemptStateV1::Authorized;
    record.authorization_unix_millis = Some(1);
    record.validate_for_store_for_test().unwrap();

    record
        .begin_postauthorization_retirement_for_test()
        .unwrap();
    assert_eq!(
        record.state,
        crate::windows::record::WindowsAttemptStateV1::Terminating
    );
    assert_eq!(
        record.terminal_disposition,
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::Posttarget)
    );
    assert!(!record.resume_attempted);
    assert!(!record.target_released);
    assert!(record.cleanup_state.termination_requested);

    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.complete_rejection_cleanup_for_test().unwrap();
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    };
    let terminal = WindowsTerminalReceiptV1 {
        policy_enforcement: Default::default(),
        schema_version: 1,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        child_pid: identity.process_id,
        duration_millis: 2,
        authorization_offset_millis: 1,
        job_total_processes: 1,
        job_process_identities: vec![identity],
        cleanup_process_creation: None,
        outcome: RunOutcome::MonitorFailed {
            error: "Resume certification fault cancelled the suspended target".to_owned(),
            child_after_termination: Some(ChildTermination::ExitCode { code: 1 }),
            cleanup: CleanupSummary {
                force_attempted: true,
                direct_child_reaped: true,
                workload_empty: Some(true),
                ..CleanupSummary::default()
            },
        },
        restart_safety: restart_safety.clone(),
        boundary_detail: BoundaryMechanismEvidence::WindowsJobObjectV2(WindowsSealedEvidenceV2 {
            target_released: false,
            terminate_job_invoked: true,
            active_processes_zero: true,
            direct_target_reaped: true,
            relays_retired: true,
            guardian_reaped: true,
            final_job_handles_closed: true,
            ..WindowsSealedEvidenceV2::default()
        }),
    };
    let rejection = ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-WINDOWS-CERTIFICATION-FAULT".to_owned(),
        phase: BoundarySetupPhase::Authorization,
        detail: "Resume certification fault".to_owned(),
        os_code: None,
        loader_qualification: None,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety,
        terminal_ack_required: true,
        terminal_receipt: Some(Box::new(terminal)),
    };
    assert!(rejection.is_consistent());
    let mut release_mismatch = rejection.clone();
    release_mismatch.target_released = true;
    assert!(!release_mismatch.is_consistent());

    let response = WindowsLauncherResponseV1::Reject {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };
    record.stage_terminal_response_for_test(&response).unwrap();
    let replayed: WindowsLauncherResponseV1 =
        serde_json::from_str(record.terminal_response_json.as_deref().unwrap()).unwrap();
    assert_eq!(
        serde_json::to_value(replayed).unwrap(),
        serde_json::to_value(response).unwrap()
    );
    let retired = record.terminal_retired_receipt(nonce).unwrap();
    assert_eq!(retired.attempt_id, record.attempt_id);
    assert_eq!(retired.request_sha256, record.request_sha256);
    assert_eq!(
        retired.disposition,
        memcordon_core::WindowsAttemptTerminalDispositionV1::Posttarget
    );
}

#[test]
fn receiptless_posttarget_rejection_cannot_bypass_terminal_binding() {
    let digest = "8b".repeat(32);
    let nonce = "receiptless-posttarget-rejection";
    let identity = WindowsProcessIdentityV1 {
        process_id: 413,
        creation_time_100ns: 991_338,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    let original = memcordon_core::CausalEventV1 {
        sequence: 0,
        origin: memcordon_core::DiagnosticOriginV1::Launcher,
        category: memcordon_core::FailureCategoryV1::Monitor,
        operation: memcordon_core::FailureOperationV1::ObserveProcessIdentity,
        code: memcordon_core::FailureCodeV1::ProcessInventoryObservation,
        native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(1234)),
        observed_phase: memcordon_core::AttemptObservationPhaseV1::Monitoring,
        safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
        detail_redacted: true,
        detail_truncated: false,
        terminalization_reference: None,
    };
    record.causal_diagnostics.observe(original).unwrap();
    let retained_original = record.causal_diagnostics.original.clone();
    record.guardian_identity = Some(identity.clone());
    record.target_identity = Some(identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::Authorized;
    record.authorization_unix_millis = Some(1);
    record.validate_for_store_for_test().unwrap();
    record
        .begin_postauthorization_retirement_for_test()
        .unwrap();
    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.complete_rejection_cleanup_for_test().unwrap();

    let rejection = ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-WINDOWS-CERTIFICATION-FAULT".to_owned(),
        phase: BoundarySetupPhase::Retirement,
        detail: "receipt-less posttarget certification fault".to_owned(),
        os_code: None,
        loader_qualification: None,
        target_created: true,
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
    let response = WindowsLauncherResponseV1::Reject {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };

    assert_eq!(
        record
            .stage_terminal_response_for_test(&response)
            .unwrap_err(),
        "terminal outbox response is not bound and consistent for the attempt"
    );
    assert!(record.terminal_response_json.is_none());
    assert_eq!(record.causal_diagnostics.original, retained_original);
    assert!(
        record
            .stage_terminal_response_with_store_for_test(&response, |record| record
                .validate_for_store_for_test())
            .is_err()
    );
    assert_eq!(record.causal_diagnostics.original, retained_original);
    let secondary = record.causal_diagnostics.secondary.as_slice();
    assert_eq!(secondary.len(), 1);
    assert_eq!(
        secondary[0].operation,
        memcordon_core::FailureOperationV1::ValidateTerminalResponse
    );
    assert_eq!(
        secondary[0].terminalization_reference,
        Some(memcordon_core::TerminalizationReferenceV1::FirstError)
    );
    assert!(record.terminal_response_json.is_none());
}
