use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    ProviderRejectionEvidence, RestartSafetyProof, RunOutcome, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WindowsLauncherResponseV1, WindowsProcessIdentityV1, WindowsSealedEvidenceV2,
    WindowsTerminalReceiptV1,
};

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
}
