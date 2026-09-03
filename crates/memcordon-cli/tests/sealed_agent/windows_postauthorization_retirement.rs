use memcordon_core::{
    BoundaryMechanismEvidence, BoundarySetupPhase, ChildTermination, CleanupSummary,
    ProviderRejectionEvidence, RestartSafetyProof, RunOutcome, WINDOWS_PRIVATE_PROTOCOL_VERSION,
    WindowsLauncherResponseV1, WindowsProcessIdentityV1, WindowsSealedEvidenceV2,
    WindowsTerminalReceiptV1,
};

fn normalized_source_variants(source: &str) -> [String; 2] {
    let lf = source.lines().collect::<Vec<_>>().join("\n");
    let crlf = lf.replace('\n', "\r\n");
    [lf, crlf]
}

fn normalized_line_position(lines: &[&str], expected: &str) -> usize {
    lines
        .iter()
        .position(|line| *line == expected)
        .unwrap_or_else(|| panic!("missing normalized source line: {expected}"))
}

fn normalized_line_containing(lines: &[&str], token: &str) -> usize {
    lines
        .iter()
        .position(|line| line.contains(token))
        .unwrap_or_else(|| panic!("missing normalized source token: {token}"))
}

#[test]
fn resume_fault_uses_postauthorization_retirement_and_attaches_terminal_candidate() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/launcher_service.rs");
    let authorize = source
        .find("cleanup_guard.record.authorize()")
        .expect("launcher must durably authorize the attempt");
    let resume_fault = source
        .find("if request.certification_fault == Some(WindowsSealedFault::Resume)")
        .expect("launcher must inject the Resume certification fault");
    let resume_attempt = source
        .find("cleanup_guard.record.mark_resume_attempted()")
        .expect("launcher must persist native resume intent");
    assert!(authorize < resume_fault);
    assert!(resume_fault < resume_attempt);

    let resume_branch = &source[resume_fault..resume_attempt];
    assert!(resume_branch.contains("retire_postauthorization_before_resume!"));
    assert!(!resume_branch.contains("retire_preauthorization_with_target!"));

    let retirement_start = source
        .find("macro_rules! retire_postauthorization_before_resume")
        .expect("postauthorization retirement macro must exist");
    let retirement = &source[retirement_start..resume_fault];
    let begin = retirement
        .find("begin_postauthorization_retirement")
        .expect("retirement must durably select Posttarget before cleanup");
    let terminate = retirement
        .find("job.terminate(CANCEL_STATUS)")
        .expect("retirement must terminate the suspended Job");
    let complete = retirement
        .find("record.complete_retirement()")
        .expect("retirement must persist complete cleanup");
    let attach = retirement
        .find("failure.terminal_candidate")
        .expect("retirement must attach the bound receipt to the rejection");
    assert!(begin < terminate && terminate < complete && complete < attach);
    assert!(retirement.contains("TargetReleaseDisposition::CancelledWhileSuspended"));
    assert!(retirement.contains("build_terminal_receipt"));
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
fn completed_terminal_is_staged_before_disconnected_delivery_gate() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/launcher_service.rs");

    for source in normalized_source_variants(source) {
        let helper_start = source
            .find("fn stage_completed_terminal_response(")
            .expect("completed terminal staging helper must exist");
        let helper_end = source[helper_start..]
            .find("struct DirectTargetReaped;")
            .map(|offset| helper_start + offset)
            .expect("completed terminal staging helper must have a stable end boundary");
        let helper_lines = source[helper_start..helper_end]
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>();
        let response = normalized_line_position(
            &helper_lines,
            "let response = WindowsLauncherResponseV1::Terminal(receipt.clone());",
        );
        let stage =
            normalized_line_containing(&helper_lines, "record.stage_terminal_response(&response)");
        let digest = normalized_line_position(
            &helper_lines,
            "let terminal_response_sha256 = super::record::digest(",
        );
        assert!(response < stage && stage < digest);

        let completed_start = source
            .find("let (response, terminal_response_sha256) =")
            .expect("completed response must be durably staged");
        let completed_end = source[completed_start..]
            .find("struct DirectTargetReaped;")
            .map(|offset| completed_start + offset)
            .expect("completed terminal path must have a stable end boundary");
        let completed_lines = source[completed_start..completed_end]
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>();
        let stage_call = normalized_line_position(
            &completed_lines,
            "stage_completed_terminal_response(&mut record, receipt)?;",
        );
        let delivery_gate = normalized_line_position(&completed_lines, "if control_connected {");
        let live_delivery = normalized_line_containing(
            &completed_lines,
            "pipe::write_frame(connection, &response)",
        );
        let acknowledgment =
            normalized_line_position(&completed_lines, "wait_for_terminal_acknowledgment(");
        let retirement =
            normalized_line_containing(&completed_lines, "record.acknowledge_terminal_response()");
        assert!(
            stage_call < delivery_gate
                && delivery_gate < live_delivery
                && live_delivery < acknowledgment
                && acknowledgment < retirement
        );
    }
}

#[test]
fn retirement_faults_attach_bound_terminal_before_rejection() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/launcher_service.rs");

    for source in normalized_source_variants(source) {
        let receipt_start = source
            .find("let receipt = build_terminal_receipt(&request, started, authorization_offset, completed);")
            .expect("completed retirement must produce a terminal receipt");
        let fault_end = source[receipt_start..]
            .find("if let Some(mut cleanup_failure) = cleanup_probe_failure {")
            .map(|offset| receipt_start + offset)
            .expect("retirement fault path must have a stable end boundary");
        let fault_lines = source[receipt_start..fault_end]
            .lines()
            .map(str::trim)
            .collect::<Vec<_>>();
        let receipt = normalized_line_position(
            &fault_lines,
            "let receipt = build_terminal_receipt(&request, started, authorization_offset, completed);",
        );
        let record_retire =
            normalized_line_position(&fault_lines, "fault @ (WindowsSealedFault::RecordRetire");
        let guardian = normalized_line_position(
            &fault_lines,
            "| WindowsSealedFault::GuardianKilledAfterAuthorization),",
        );
        let bind = normalized_line_position(&fault_lines, ".with_terminal_candidate(receipt));");
        assert!(receipt < record_retire && record_retire < guardian && guardian < bind);
    }
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
