use memcordon_core::{
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1,
    WindowsDurableCleanupStateV1, WindowsProcessIdentityV1, WindowsRelayPhaseV1,
    WindowsReplayOutboxStageV1, WindowsReplayPendingV1, WindowsTerminalizationCheckpointV1,
    WindowsTerminalizationErrorStageV1, WindowsTerminalizationErrorV1,
    WindowsTerminalizationOwnerV1, WindowsTerminalizationStatusV1,
};
use std::cell::Cell;

#[test]
fn attempt_record_store_validates_typed_preauthorization_abort_before_publication() {
    let digest = "ab".repeat(32);
    let process_identity = WindowsProcessIdentityV1 {
        process_id: 42,
        creation_time_100ns: 123_456_789,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        process_identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.guardian_identity = Some(process_identity.clone());
    record.target_identity = Some(process_identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::TargetCreatedSuspended;
    record.resume_attempted = true;

    let error = record.validate_for_store_for_test().unwrap_err();
    assert!(
        error.starts_with("MCSEALED-WINDOWS-ATTEMPT-RECORD-STORE: phase=validate-before-publish")
    );
    assert!(error.ends_with("reason=lifecycle-resume-without-authorization"));

    record.resume_attempted = false;
    record.state = crate::windows::record::WindowsAttemptStateV1::Terminating;
    record.cleanup_state.termination_requested = true;
    record.terminal_disposition =
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    record.validate_for_store_for_test().unwrap();

    record.target_released = true;
    record.validate_for_store_for_test().unwrap();
}

#[test]
fn fallback_rejection_finalizes_before_staging_bound_terminal_outbox() {
    let digest = "cd".repeat(32);
    let nonce = "fallback-rejection-finalization";
    let process_identity = WindowsProcessIdentityV1 {
        process_id: 73,
        creation_time_100ns: 987_654_321,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        process_identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.guardian_identity = Some(process_identity.clone());
    record.target_identity = Some(process_identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::Terminating;
    record.target_released = true;
    record.cleanup_state.termination_requested = true;
    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.terminal_disposition =
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    record.validate_for_store_for_test().unwrap();

    let mut invalid_direct_finalization = record.clone();
    invalid_direct_finalization
        .cleanup_state
        .final_handles_closed = true;
    assert!(
        invalid_direct_finalization
            .validate_for_store_for_test()
            .unwrap_err()
            .ends_with("reason=lifecycle-final-handles-before-empty")
    );

    record.complete_rejection_cleanup_for_test().unwrap();
    assert_eq!(
        record.state,
        crate::windows::record::WindowsAttemptStateV1::Empty
    );
    assert!(record.cleanup_state.final_handles_closed);
    assert_eq!(
        record.terminal_disposition,
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
    );

    let rejection = memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-WINDOWS-LAUNCH".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::Retirement,
        detail: "certification rejection after fallback cleanup".to_owned(),
        os_code: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: memcordon_core::RestartSafetyProof {
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
    let response = memcordon_core::WindowsLauncherResponseV1::Reject {
        schema_version: memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };
    record.stage_terminal_response_for_test(&response).unwrap();
    let replayed: memcordon_core::WindowsLauncherResponseV1 =
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
        memcordon_core::WindowsAttemptTerminalDispositionV1::PreauthorizationAbort
    );
}

#[test]
fn completed_posttarget_rejection_skips_duplicate_finalization_and_stages_bound_outbox() {
    let digest = "ef".repeat(32);
    let nonce = "completed-posttarget-rejection";
    let process_identity = WindowsProcessIdentityV1 {
        process_id: 91,
        creation_time_100ns: 123_987_456,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        process_identity.clone(),
        digest.clone(),
        digest,
    )
    .unwrap();
    record.guardian_identity = Some(process_identity.clone());
    record.target_identity = Some(process_identity);
    record.state = crate::windows::record::WindowsAttemptStateV1::Terminating;
    record.authorization_unix_millis = Some(1);
    record.resume_attempted = true;
    record.target_released = true;
    record.cleanup_state.termination_requested = true;
    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.validate_for_store_for_test().unwrap();

    record.complete_rejection_cleanup_for_test().unwrap();
    assert_eq!(
        record.state,
        crate::windows::record::WindowsAttemptStateV1::Empty
    );
    assert_eq!(
        record.terminal_disposition,
        Some(crate::windows::record::WindowsAttemptTerminalDispositionV1::Posttarget)
    );
    assert!(record.cleanup_state.final_handles_closed);
    record.validate_for_store_for_test().unwrap();
    let rejection_cleanup_is_guarded = |source: &str| {
        let rejection_source = source
            .split_once("pub fn rejection_evidence(")
            .expect("rejection evidence function must exist")
            .1
            .split_once("fn posttarget_rejection(")
            .expect("posttarget rejection boundary must exist")
            .0;
        let lines = rejection_source.lines().map(str::trim).collect::<Vec<_>>();
        let expected = [
            "if cleanup_attempted",
            "&& record.cleanup_state.active_processes_zero",
            "&& record.cleanup_state.guardian_reaped",
            "&& !record.cleanup_state.final_handles_closed",
            "&& !live",
            "{",
            "record.complete_rejection_cleanup()?;",
            "}",
        ];
        lines
            .windows(expected.len())
            .any(|window| window == expected.as_slice())
    };
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/record.rs");
    assert!(
        rejection_cleanup_is_guarded(source),
        "completed rejection cleanup must be skipped while unfinished cleanup is finalized"
    );
    let canonical = source.lines().collect::<Vec<_>>().join("\n");
    assert!(rejection_cleanup_is_guarded(&canonical));
    let crlf = canonical.replace('\n', "\r\n");
    assert!(rejection_cleanup_is_guarded(&crlf));

    let restart_safety = memcordon_core::RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    };
    let terminal = memcordon_core::WindowsTerminalReceiptV1 {
        schema_version: 1,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        child_pid: 91,
        duration_millis: 1,
        authorization_offset_millis: 1,
        job_total_processes: 1,
        job_process_identities: vec![WindowsProcessIdentityV1 {
            process_id: 91,
            creation_time_100ns: 123_987_456,
        }],
        cleanup_process_creation: None,
        outcome: memcordon_core::RunOutcome::Exited {
            child: memcordon_core::ChildTermination::ExitCode { code: 1 },
            peak: None,
            cleanup: memcordon_core::CleanupSummary::default(),
        },
        restart_safety: restart_safety.clone(),
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::WindowsJobObjectV2(
            memcordon_core::WindowsSealedEvidenceV2 {
                target_released: true,
                ..Default::default()
            },
        ),
    };
    let rejection = memcordon_core::ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-WINDOWS-LAUNCH".to_owned(),
        phase: memcordon_core::BoundarySetupPhase::Retirement,
        detail: "certification rejection after completed posttarget cleanup".to_owned(),
        os_code: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety,
        terminal_ack_required: true,
        terminal_receipt: Some(Box::new(terminal)),
    };
    let response = memcordon_core::WindowsLauncherResponseV1::Reject {
        schema_version: memcordon_core::WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce: nonce.to_owned(),
        request_sha256: record.request_sha256.clone(),
        rejection,
    };
    record.stage_terminal_response_for_test(&response).unwrap();
    let replayed: memcordon_core::WindowsLauncherResponseV1 =
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
fn qualification_accepts_only_locally_derived_pre_stream_reject_attempts() {
    let nonce = "qualification-reject-binding";
    let request_sha256 = "ab".repeat(32);
    let caller = WindowsProcessIdentityV1 {
        process_id: 42,
        creation_time_100ns: 123_456_789,
    };
    let process_attempt = crate::windows::qualification::qualification_process_attempt_id(
        nonce,
        &request_sha256,
        &caller,
    );
    let pretarget_attempt =
        crate::windows::qualification::qualification_pretarget_attempt_id(nonce, &request_sha256);
    assert_ne!(process_attempt, pretarget_attempt);
    let rejection = crate::windows::record::pretarget_rejection(
        "MCSEALED-WINDOWS-TEST",
        "bound pre-stream rejection".to_owned(),
    );

    for returned_attempt in [&process_attempt, &pretarget_attempt] {
        crate::windows::qualification::validate_native_reject(
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            returned_attempt,
            nonce,
            &request_sha256,
            &rejection,
            None,
            &process_attempt,
            &pretarget_attempt,
            nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitStreams,
        )
        .unwrap();
    }

    let error = crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &"cd".repeat(32),
        nonce,
        &request_sha256,
        &rejection,
        None,
        &process_attempt,
        &pretarget_attempt,
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitStreams,
    )
    .unwrap_err();
    assert!(error.contains("variant=reject"));
    assert!(error.contains("predicate=attempt-id"));

    for (schema, returned_nonce, returned_digest, observed_rejection, predicate) in [
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION + 1,
            nonce,
            request_sha256.as_str(),
            rejection.clone(),
            "schema",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            "wrong-nonce",
            request_sha256.as_str(),
            rejection.clone(),
            "nonce",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce,
            "wrong-digest",
            rejection.clone(),
            "request-digest",
        ),
        (
            WINDOWS_PUBLIC_PROTOCOL_VERSION,
            nonce,
            request_sha256.as_str(),
            {
                let mut inconsistent = rejection.clone();
                inconsistent.code = "not-stable".to_owned();
                inconsistent
            },
            "rejection-consistency",
        ),
    ] {
        let error = crate::windows::qualification::validate_native_reject(
            schema,
            &process_attempt,
            returned_nonce,
            returned_digest,
            &observed_rejection,
            None,
            &process_attempt,
            &pretarget_attempt,
            nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitStreams,
        )
        .unwrap_err();
        assert!(error.contains(&format!("predicate={predicate}")));
    }
}

#[test]
fn qualification_post_stream_reject_is_pinned_to_the_active_attempt() {
    let nonce = "qualification-active-reject";
    let request_sha256 = "ef".repeat(32);
    let active_attempt = "12".repeat(32);
    let rejection = crate::windows::record::pretarget_rejection(
        "MCSEALED-WINDOWS-TEST",
        "bound post-stream rejection".to_owned(),
    );
    crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &active_attempt,
        nonce,
        &request_sha256,
        &rejection,
        Some(&active_attempt),
        &"34".repeat(32),
        &"56".repeat(32),
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::Authorized,
    )
    .unwrap();

    let error = crate::windows::qualification::validate_native_reject(
        WINDOWS_PUBLIC_PROTOCOL_VERSION,
        &"78".repeat(32),
        nonce,
        &request_sha256,
        &rejection,
        Some(&active_attempt),
        &"34".repeat(32),
        &"56".repeat(32),
        nonce,
        &request_sha256,
        WindowsRelayPhaseV1::Authorized,
    )
    .unwrap_err();
    assert!(error.contains("predicate=attempt-id"));
}

#[test]
fn failed_qualification_terminal_is_acknowledged_before_semantics_propagate() {
    let semantic_latched = Cell::new(false);
    let acknowledgment_attempted = Cell::new(false);
    let pending_terminal_outbox = Cell::new(true);
    let semantic_result = {
        semantic_latched.set(true);
        Err::<(), _>("primary semantic failure".to_owned())
    };

    let error = crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
        semantic_result,
        "attempt-bound-terminal",
        "nonce-bound-terminal",
        &"ab".repeat(32),
        || {
            assert!(
                semantic_latched.get(),
                "semantics must be latched before ACK"
            );
            acknowledgment_attempted.set(true);
            pending_terminal_outbox.set(false);
            Ok(())
        },
    )
    .unwrap_err();

    assert!(acknowledgment_attempted.get());
    assert!(
        !pending_terminal_outbox.get(),
        "a successfully forwarded bound ACK must permit launcher outbox retirement"
    );
    assert_eq!(error, "primary semantic failure");
}

#[test]
fn failed_terminal_ack_preserves_primary_and_secondary_evidence() {
    let acknowledgment_attempted = Cell::new(false);
    let pending_terminal_outbox = Cell::new(true);
    let error = crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
        Err::<(), _>("primary semantic failure".to_owned()),
        "attempt-bound-terminal",
        "nonce-bound-terminal",
        &"cd".repeat(32),
        || {
            acknowledgment_attempted.set(true);
            Err("native pipe write failed".to_owned())
        },
    )
    .unwrap_err();

    assert!(acknowledgment_attempted.get());
    assert!(
        pending_terminal_outbox.get(),
        "a failed ACK must leave the durable terminal outbox pending"
    );
    assert!(error.starts_with("primary semantic failure;"));
    assert!(error.contains("terminal acknowledgment failed after bound receipt was latched"));
    assert!(error.contains("MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT"));
    assert!(error.contains("stage=bound-receipt-write"));
    assert!(error.contains("api=WriteFile(named-pipe-frame)"));
    assert!(error.contains("attempt_id=attempt-bound-terminal"));
    assert!(error.contains("request_sha256=cdcd"));
    assert!(error.ends_with("detail=native pipe write failed"));

    let acknowledgment_only =
        crate::windows::qualification::acknowledge_latched_qualification_terminal_for_test(
            Ok("semantic evidence"),
            "attempt-bound-terminal",
            "nonce-bound-terminal",
            &"ef".repeat(32),
            || Err("native pipe write failed".to_owned()),
        )
        .unwrap_err();
    assert!(acknowledgment_only.starts_with("MCSEALED-WINDOWS-TERMINAL-ACKNOWLEDGMENT"));
    assert!(!acknowledgment_only.contains("primary semantic failure"));
}

#[test]
fn qualification_pending_diagnostic_preserves_authenticated_terminalization_snapshot() {
    let attempt_id = "a7".repeat(32);
    let request_sha256 = "b7".repeat(32);
    let pending = WindowsReplayPendingV1 {
        schema_version: 2,
        attempt_id: attempt_id.clone(),
        nonce: "cycle-7-qualification-pending".to_owned(),
        request_sha256,
        relay_phase: WindowsRelayPhaseV1::AwaitTerminal,
        durable_state: WindowsAttemptStateV1::Terminating,
        terminal_disposition: Some(WindowsAttemptTerminalDispositionV1::Posttarget),
        authorization_present: true,
        resume_attempted: true,
        target_released: false,
        cleanup_state: WindowsDurableCleanupStateV1 {
            termination_requested: true,
            active_processes_zero: true,
            guardian_reaped: false,
            final_handles_closed: false,
        },
        cleanup_complete: false,
        outbox_stage: WindowsReplayOutboxStageV1::Failed,
        terminalization: WindowsTerminalizationStatusV1 {
            schema_version: 1,
            owner: WindowsTerminalizationOwnerV1::StartupRecovery,
            sequence: 11,
            checkpoint: WindowsTerminalizationCheckpointV1::RetainedFailure,
            last_error: Some(WindowsTerminalizationErrorV1 {
                stage: WindowsTerminalizationErrorStageV1::LaunchRelay,
                error_code: "MCSEALED-WINDOWS-RELAY-WRITE".to_owned(),
                detail: "TargetAuthorized delivery failed".to_owned(),
                native_code: Some(109),
                observed_unix_millis: Some(1_725_000_000_456),
            }),
            secondary_errors: Vec::new(),
        },
        detail: "authenticated terminalization remains pending".to_owned(),
    };
    assert!(pending.is_consistent_for(
        &attempt_id,
        "cycle-7-qualification-pending",
        &"b7".repeat(32),
        WindowsRelayPhaseV1::AwaitTerminal,
    ));

    let rendered = crate::windows::qualification::render_replay_pending(&pending);
    let ordered_labels = [
        "attempt_id=",
        "relay_phase=",
        "durable_state=",
        "terminal_disposition=",
        "authorization_present=",
        "resume_attempted=",
        "target_released=",
        "termination_requested=",
        "active_processes_zero=",
        "guardian_reaped=",
        "final_handles_closed=",
        "outbox_stage=",
        "terminalization_owner=",
        "terminalization_sequence=",
        "terminalization_checkpoint=",
        "last_error_stage=",
        "last_error_code=",
        "last_error_detail=",
        "last_error_native_code=",
        "last_error_observed_unix_millis=",
    ];
    let mut remainder = rendered.as_str();
    for label in ordered_labels {
        remainder = remainder
            .split_once(label)
            .unwrap_or_else(|| panic!("missing qualification diagnostic label: {label}"))
            .1;
    }
    for value in [
        attempt_id.as_str(),
        "AwaitTerminal",
        "Terminating",
        "Posttarget",
        "Failed",
        "StartupRecovery",
        "RetainedFailure",
        "LaunchRelay",
        "MCSEALED-WINDOWS-RELAY-WRITE",
        "TargetAuthorized delivery failed",
        "109",
        "1725000000456",
    ] {
        assert!(
            rendered.contains(value),
            "missing diagnostic value: {value}"
        );
    }

    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/qualification.rs");
    let canary_start = source
        .find("fn native_public_canary(")
        .expect("native public canary must exist");
    let canary_end = source[canary_start..]
        .find("fn prepare_frontend_canaries(")
        .map(|offset| canary_start + offset)
        .expect("native public canary must have a stable end boundary");
    assert!(source[canary_start..canary_end].contains("render_replay_pending(&pending)"));
}
