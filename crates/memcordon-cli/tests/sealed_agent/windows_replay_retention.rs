use memcordon_core::{
    BoundarySetupPhase, PROVIDER_REJECTION_MAX_DETAIL_BYTES, ProviderRejectionEvidence,
    RestartSafetyProof, WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS,
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1,
    WindowsDurableAttemptRecordV1, WindowsDurableCleanupStateV1, WindowsLauncherResponseV1,
    WindowsProcessIdentityV1, WindowsProviderResponseV1, WindowsRelayPhaseV1,
    WindowsReplayOutboxStageV1, WindowsReplayPendingV1, WindowsTerminalizationCheckpointV1,
    WindowsTerminalizationErrorStageV1, WindowsTerminalizationErrorV1,
    WindowsTerminalizationOwnerV1, WindowsTerminalizationStatusV1,
    parse_and_authenticate_windows_attempt_record,
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

fn binding() -> (String, String, String) {
    (
        "ab".repeat(32),
        "replay-retention-nonce".to_owned(),
        "cd".repeat(32),
    )
}

fn retained_terminalization() -> WindowsTerminalizationStatusV1 {
    WindowsTerminalizationStatusV1 {
        schema_version: 1,
        owner: WindowsTerminalizationOwnerV1::StartupRecovery,
        sequence: 7,
        checkpoint: WindowsTerminalizationCheckpointV1::RetainedFailure,
        last_error: Some(WindowsTerminalizationErrorV1 {
            stage: WindowsTerminalizationErrorStageV1::AtomicStore,
            error_code: "MCSEALED-WINDOWS-TERMINAL-STORE".to_owned(),
            detail: "authenticated terminal outbox publication failed".to_owned(),
            native_code: Some(5),
            observed_unix_millis: Some(1_725_000_000_123),
        }),
        secondary_errors: Vec::new(),
    }
}

fn completed_cleanup() -> WindowsDurableCleanupStateV1 {
    WindowsDurableCleanupStateV1 {
        termination_requested: true,
        active_processes_zero: true,
        guardian_reaped: true,
        final_handles_closed: true,
    }
}

fn completed_preauthorization_record() -> crate::windows::record::WindowsAttemptRecordV1 {
    let (attempt_id, _, request_sha256) = binding();
    let identity = WindowsProcessIdentityV1 {
        process_id: 818,
        creation_time_100ns: 8_181,
    };
    let mut record = crate::windows::record::WindowsAttemptRecordV1::new(
        attempt_id,
        request_sha256,
        identity.clone(),
        "e8".repeat(32),
        "f8".repeat(32),
    )
    .unwrap();
    record.guardian_identity = Some(identity.clone());
    record.target_identity = Some(identity);
    record.state = WindowsAttemptStateV1::Empty;
    record.cleanup_state.termination_requested = true;
    record.cleanup_state.active_processes_zero = true;
    record.cleanup_state.guardian_reaped = true;
    record.cleanup_state.final_handles_closed = true;
    record.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    record.terminalization = WindowsTerminalizationStatusV1 {
        schema_version: 1,
        owner: WindowsTerminalizationOwnerV1::LauncherWorker,
        sequence: 3,
        checkpoint: WindowsTerminalizationCheckpointV1::CleanupProofReady,
        last_error: None,
        secondary_errors: Vec::new(),
    };
    record.validate_for_store_for_test().unwrap();
    record
}

fn bound_preauthorization_rejection(
    record: &crate::windows::record::WindowsAttemptRecordV1,
) -> WindowsLauncherResponseV1 {
    let (_, nonce, _) = binding();
    WindowsLauncherResponseV1::Reject {
        schema_version: WINDOWS_PRIVATE_PROTOCOL_VERSION,
        attempt_id: record.attempt_id.clone(),
        nonce,
        request_sha256: record.request_sha256.clone(),
        rejection: ProviderRejectionEvidence {
            schema_version: 1,
            code: "MCSEALED-WINDOWS-PREAUTHORIZATION-ABORT".to_owned(),
            phase: BoundarySetupPhase::TargetCreation,
            detail: "preauthorization target creation failed".to_owned(),
            os_code: Some(5),
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
        },
    }
}

#[test]
fn pretarget_rejection_bounds_and_sanitizes_provider_detail() {
    let cases = [
        ("empty", String::new()),
        ("embedded-nul", "relay\0detail".to_owned()),
        (
            "exact-limit",
            "x".repeat(PROVIDER_REJECTION_MAX_DETAIL_BYTES),
        ),
        (
            "over-limit",
            "y".repeat(PROVIDER_REJECTION_MAX_DETAIL_BYTES + 1),
        ),
    ];

    for (case, detail) in cases {
        let rejection =
            crate::windows::record::pretarget_rejection("MCSEALED-WINDOWS-PRETARGET-TEST", detail);
        assert!(!rejection.detail.is_empty(), "case={case}");
        assert!(!rejection.detail.contains('\0'), "case={case}");
        assert!(
            rejection.detail.len() <= PROVIDER_REJECTION_MAX_DETAIL_BYTES,
            "case={case} bytes={}",
            rejection.detail.len()
        );
        assert!(rejection.is_consistent(), "case={case}");
    }
}

#[test]
fn launcher_record_inspection_failure_returns_bound_retained_evidence() {
    let (attempt_id, nonce, request_sha256) = binding();
    let response =
        crate::windows::launcher_service::bound_launcher_replay_failure_response_for_test(
            &attempt_id,
            &nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitRelaysReady,
            "record authentication failed".to_owned(),
        );

    let WindowsLauncherResponseV1::AttemptRetained(retained) = response else {
        panic!("launcher replay failure did not return AttemptRetained");
    };
    assert!(retained.is_consistent_for(
        &attempt_id,
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitRelaysReady,
    ));
    assert!(!retained.cleanup_complete);
    assert!(!retained.terminal_replay_available);
    assert_eq!(
        retained.secondary_failures,
        ["launcher replay record inspection failed: record authentication failed"]
    );
}

#[test]
fn control_private_replay_failure_returns_public_retained_evidence() {
    let (attempt_id, nonce, request_sha256) = binding();
    let response = crate::windows::control_service::bound_public_replay_failure_response_for_test(
        &attempt_id,
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitTerminal,
        "private launcher pipe peer disconnected".to_owned(),
    );

    let WindowsProviderResponseV1::AttemptRetained(retained) = response else {
        panic!("control replay failure did not return AttemptRetained");
    };
    assert!(retained.is_consistent_for(
        &attempt_id,
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitTerminal,
    ));
    assert_eq!(
        retained.secondary_failures,
        ["control replay failure: private launcher pipe peer disconnected"]
    );
}

#[test]
fn bound_launch_retention_survives_record_reread_failure() {
    let (attempt_id, nonce, request_sha256) = binding();
    let retained =
        crate::windows::record::retained_attempt_evidence_after_inspection_failure_for_test(
            &attempt_id,
            &nonce,
            &request_sha256,
            WindowsRelayPhaseV1::AwaitRelaysReady,
            "relay failed after StreamsPrepared".to_owned(),
            vec!["terminal replay failed".to_owned()],
            "record JSON is invalid".to_owned(),
        );

    assert!(retained.is_consistent_for(
        &attempt_id,
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitRelaysReady,
    ));
    assert_eq!(
        retained.primary_detail,
        "relay failed after StreamsPrepared"
    );
    assert_eq!(
        retained.secondary_failures,
        [
            "terminal replay failed",
            "retained attempt record inspection failed: record JSON is invalid",
        ]
    );
}

#[test]
fn terminal_inventory_distinguishes_canonical_and_staged_publications() {
    let (attempt_id, _, _) = binding();
    assert_eq!(
        crate::windows::record::terminal_inventory_attempt_id_for_test(&format!(
            "{attempt_id}.json"
        ))
        .unwrap(),
        attempt_id
    );

    let error = crate::windows::record::terminal_inventory_attempt_id_for_test(&format!(
        "{attempt_id}.json.new"
    ))
    .unwrap_err();
    assert_eq!(
        error,
        format!(
            "MCSEALED-WINDOWS-TERMINAL-INVENTORY-STAGED: attempt_id={attempt_id} requires durable recovery before inventory"
        )
    );
}

#[test]
fn final_outbox_store_failure_preserves_primary_and_bounds_secondary_diagnostics() {
    let mut record = completed_preauthorization_record();
    let response = bound_preauthorization_rejection(&record);
    let injected_store_failure = "injected final populated-outbox store failure";
    let mut store_calls = 0;

    let error = record
        .stage_terminal_response_with_store_for_test(&response, |candidate| {
            store_calls += 1;
            if store_calls == 2 {
                Err(injected_store_failure.to_owned())
            } else {
                candidate.validate_for_store_for_test()
            }
        })
        .unwrap_err();

    assert_eq!(error, injected_store_failure);
    assert_eq!(store_calls, 3);
    assert_eq!(record.state, WindowsAttemptStateV1::Empty);
    assert!(record.cleanup_state.termination_requested);
    assert!(record.cleanup_state.active_processes_zero);
    assert!(record.cleanup_state.guardian_reaped);
    assert!(record.cleanup_state.final_handles_closed);
    assert!(record.terminal_response_json.is_none());
    assert_eq!(
        record.terminalization.owner,
        WindowsTerminalizationOwnerV1::LauncherWorker
    );
    assert_eq!(record.terminalization.sequence, 6);
    assert_eq!(
        record.terminalization.checkpoint,
        WindowsTerminalizationCheckpointV1::RetainedFailure
    );
    let primary = record.terminalization.last_error.clone().unwrap();
    assert_eq!(
        primary.stage,
        WindowsTerminalizationErrorStageV1::AtomicStore
    );
    assert_eq!(primary.error_code, "MCSEALED-WINDOWS-TERMINAL-OUTBOX-STORE");
    assert!(primary.detail.contains(injected_store_failure));

    for observer in 0..WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS {
        record
            .record_terminalization_diagnostic_for_test(WindowsTerminalizationErrorV1 {
                stage: WindowsTerminalizationErrorStageV1::LaunchRelay,
                error_code: "MCSEALED-WINDOWS-CONTROL-RELAY".to_owned(),
                detail: format!("named-pipe relay observer={observer} disconnected"),
                native_code: None,
                observed_unix_millis: Some(1_725_000_001_000 + observer as u64),
            })
            .unwrap();
    }

    assert_eq!(record.terminalization.last_error, Some(primary.clone()));
    assert_eq!(
        record.terminalization.secondary_errors.len(),
        WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
    );
    assert!(
        record
            .terminalization
            .secondary_errors
            .iter()
            .all(|error| error.stage == WindowsTerminalizationErrorStageV1::LaunchRelay)
    );
    let bounded_sequence = record.terminalization.sequence;
    record
        .record_terminalization_diagnostic_for_test(WindowsTerminalizationErrorV1 {
            stage: WindowsTerminalizationErrorStageV1::LaunchRelay,
            error_code: "MCSEALED-WINDOWS-CONTROL-RELAY".to_owned(),
            detail: "diagnostic beyond the authenticated bound".to_owned(),
            native_code: None,
            observed_unix_millis: Some(1_725_000_002_000),
        })
        .unwrap();
    assert_eq!(record.terminalization.sequence, bounded_sequence);
    assert_eq!(record.terminalization.last_error, Some(primary.clone()));
    assert_eq!(
        record.terminalization.secondary_errors.len(),
        WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
    );

    let authenticated = parse_and_authenticate_windows_attempt_record(
        &serde_json::to_vec(&record).unwrap(),
        &record.attempt_id,
        &record.provider_generation,
    )
    .unwrap();
    assert_eq!(authenticated.terminalization.last_error, Some(primary));
    assert_eq!(
        authenticated.terminalization.secondary_errors,
        record.terminalization.secondary_errors
    );
}

#[test]
fn cleanup_complete_retained_failure_classifies_terminal_attempt_retained() {
    let (_, nonce, _) = binding();
    let mut record = completed_preauthorization_record();
    record.terminalization = WindowsTerminalizationStatusV1 {
        schema_version: 1,
        owner: WindowsTerminalizationOwnerV1::LauncherWorker,
        sequence: 7,
        checkpoint: WindowsTerminalizationCheckpointV1::RetainedFailure,
        last_error: Some(WindowsTerminalizationErrorV1 {
            stage: WindowsTerminalizationErrorStageV1::AtomicStore,
            error_code: "MCSEALED-WINDOWS-TERMINAL-OUTBOX-STORE".to_owned(),
            detail: "final populated-outbox store failed".to_owned(),
            native_code: Some(5),
            observed_unix_millis: Some(1_725_000_003_000),
        }),
        secondary_errors: vec![WindowsTerminalizationErrorV1 {
            stage: WindowsTerminalizationErrorStageV1::LaunchRelay,
            error_code: "MCSEALED-WINDOWS-CONTROL-RELAY".to_owned(),
            detail: "public replay relay failed".to_owned(),
            native_code: None,
            observed_unix_millis: Some(1_725_000_003_001),
        }],
    };
    record.validate_for_store_for_test().unwrap();

    let evidence = crate::windows::record::replay_unstaged_evidence_for_test(
        &record,
        &nonce,
        WindowsRelayPhaseV1::AwaitTerminal,
    );
    let crate::windows::record::ReplayUnstagedEvidence::Retained(retained) = evidence else {
        panic!("cleanup-complete RetainedFailure was misclassified as ReplayPending");
    };
    assert!(retained.is_consistent_for(
        &record.attempt_id,
        &nonce,
        &record.request_sha256,
        WindowsRelayPhaseV1::AwaitTerminal,
    ));
    assert_eq!(retained.durable_state, Some(WindowsAttemptStateV1::Empty));
    assert_eq!(
        retained.terminal_disposition,
        Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
    );
    assert!(retained.cleanup_complete);
    assert!(!retained.terminal_replay_available);
    assert!(retained.authority_retained);
    assert!(
        retained
            .primary_detail
            .contains("MCSEALED-WINDOWS-TERMINAL-OUTBOX-STORE")
    );
    assert!(
        retained
            .primary_detail
            .contains("final populated-outbox store failed")
    );
    assert_eq!(retained.secondary_failures.len(), 1);
    assert!(retained.secondary_failures[0].contains("MCSEALED-WINDOWS-CONTROL-RELAY"));
    assert!(retained.secondary_failures[0].contains("public replay relay failed"));
}

#[test]
fn bound_launch_pending_replay_emits_one_public_response_and_returns() {
    let source = include_str!("../../src/bin/memcordon-sealed-agent/windows/control_service.rs");

    for source in normalized_source_variants(source) {
        let replay_start = source
            .find("fn replay_terminal(")
            .expect("terminal replay must have a stable start boundary");
        let replay_end = source[replay_start..]
            .find("#[derive(Clone, Copy, Debug, Eq, PartialEq)]")
            .map(|offset| replay_start + offset)
            .expect("terminal replay must have a stable end boundary");
        let replay = &source[replay_start..replay_end];
        let replay_lines = replay.lines().map(str::trim).collect::<Vec<_>>();
        let pending_write = normalized_line_position(
            &replay_lines,
            "pipe::write_frame(public, &WindowsProviderResponseV1::ReplayPending(pending))?;",
        );
        let pending_return =
            normalized_line_position(&replay_lines, "return Ok(ReplayTerminalProgress::Pending);");
        assert!(pending_write < pending_return);
        assert_eq!(
            replay_lines
                .iter()
                .filter(|line| line.contains("WindowsProviderResponseV1::ReplayPending"))
                .count(),
            1
        );

        let branch_start = source
            .find("let primary = failure.detail.clone();")
            .expect("bound launch failure must preserve its primary diagnostic");
        let branch_end = source[branch_start..]
            .find("_ => Err(failure.diagnostic()),")
            .map(|offset| branch_start + offset)
            .expect("bound launch failure branch must have a stable end boundary");
        let branch = &source[branch_start..branch_end];
        let lines = branch.lines().map(str::trim).collect::<Vec<_>>();

        let primary = normalized_line_position(&lines, "let primary = failure.detail.clone();");
        let complete = normalized_line_position(
            &lines,
            "Ok(ReplayTerminalProgress::Complete) => return Ok(()),",
        );
        let pending = normalized_line_position(
            &lines,
            "Ok(ReplayTerminalProgress::Pending) => return Ok(()),",
        );
        let retained = normalized_line_position(
            &lines,
            "let retained = super::record::retained_attempt_evidence(",
        );
        let retained_primary = normalized_line_position(&lines, "primary,");

        assert!(primary < complete && complete < pending);
        assert!(pending < retained && retained < retained_primary);
        assert!(!branch.contains("Ok(_) => return Ok(()),"));
        assert!(!branch.contains("Ok(ReplayTerminalProgress::Pending) => {"));
    }
}

#[test]
fn authenticated_record_roundtrip_preserves_terminalization_and_cleanup_facts() {
    let (attempt_id, _, request_sha256) = binding();
    let provider_generation = "cycle-7-terminalization-generation".to_owned();
    let identity = WindowsProcessIdentityV1 {
        process_id: 717,
        creation_time_100ns: 7_171,
    };
    let mut record = WindowsDurableAttemptRecordV1 {
        schema_version: 2,
        attempt_id: attempt_id.clone(),
        provider_generation: provider_generation.clone(),
        boot_identity: "cycle-7-boot".to_owned(),
        request_sha256,
        caller_process_identity: identity.clone(),
        caller_token_sha256: "de".repeat(32),
        job_identity_sha256: "ef".repeat(32),
        guardian_identity: Some(identity.clone()),
        target_identity: Some(identity),
        state: WindowsAttemptStateV1::Empty,
        authorization_unix_millis: Some(1_725_000_000_000),
        resume_attempted: true,
        target_released: true,
        cleanup_state: completed_cleanup(),
        terminal_response_json: None,
        terminal_disposition: Some(WindowsAttemptTerminalDispositionV1::Posttarget),
        terminalization: retained_terminalization(),
        integrity_sha256: String::new(),
    };
    record.integrity_sha256 = crate::windows::record::digest(
        &serde_json::to_vec(&record).expect("record must serialize canonically"),
    );

    let authenticated = parse_and_authenticate_windows_attempt_record(
        &serde_json::to_vec(&record).unwrap(),
        &attempt_id,
        &provider_generation,
    )
    .unwrap();
    assert_eq!(authenticated.terminalization, retained_terminalization());
    assert_eq!(authenticated.cleanup_state, completed_cleanup());
    assert_eq!(
        authenticated.terminal_disposition,
        Some(WindowsAttemptTerminalDispositionV1::Posttarget)
    );

    let mut tampered = authenticated;
    tampered.terminalization.sequence += 1;
    assert_eq!(
        parse_and_authenticate_windows_attempt_record(
            &serde_json::to_vec(&tampered).unwrap(),
            &attempt_id,
            &provider_generation,
        )
        .unwrap_err(),
        "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=integrity-digest"
    );
}

#[test]
fn replay_pending_roundtrip_preserves_terminalization_disposition_and_binding() {
    let (attempt_id, nonce, request_sha256) = binding();
    let pending = WindowsReplayPendingV1 {
        schema_version: 2,
        attempt_id: attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: request_sha256.clone(),
        relay_phase: WindowsRelayPhaseV1::AwaitTerminal,
        durable_state: WindowsAttemptStateV1::Empty,
        terminal_disposition: Some(WindowsAttemptTerminalDispositionV1::Posttarget),
        authorization_present: true,
        resume_attempted: true,
        target_released: true,
        cleanup_state: completed_cleanup(),
        cleanup_complete: true,
        outbox_stage: WindowsReplayOutboxStageV1::Failed,
        terminalization: retained_terminalization(),
        detail: "durable terminal staging failed and awaits recovery".to_owned(),
    };
    let roundtrip: WindowsReplayPendingV1 =
        serde_json::from_slice(&serde_json::to_vec(&pending).unwrap()).unwrap();

    assert_eq!(roundtrip, pending);
    assert!(roundtrip.is_consistent_for(
        &attempt_id,
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitTerminal,
    ));
    assert_eq!(
        roundtrip.terminal_disposition,
        Some(WindowsAttemptTerminalDispositionV1::Posttarget)
    );
    assert_eq!(roundtrip.cleanup_state, completed_cleanup());
    assert_eq!(roundtrip.terminalization, retained_terminalization());
    assert!(!roundtrip.is_consistent_for(
        &"01".repeat(32),
        &nonce,
        &request_sha256,
        WindowsRelayPhaseV1::AwaitTerminal,
    ));
}
