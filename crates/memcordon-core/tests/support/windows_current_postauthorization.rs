use memcordon_core::*;

pub fn rejection() -> WindowsProviderRejectionV3 {
    let attempt_id = "ab".repeat(32);
    let request_sha256 = "cd".repeat(32);
    let nonce = "ef".repeat(16);
    let provider = PublicProviderBindingV1 {
        generation: BoundedText::new("fixture-generation").unwrap(),
        source_commit: BoundedText::new(&"12".repeat(20)).unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([3; 32]),
    };
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Monitor,
            operation: FailureOperationV1::CheckGuardian,
            code: FailureCodeV1::GuardianLoss,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::Monitoring,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    journal.durable_through_sequence = Some(journal.sequence);
    let diagnostic =
        ProviderFailureDiagnosticV1::from_journal(provider, &attempt_id, &request_sha256, &journal)
            .unwrap();
    let mut observation = WindowsProcessObservationV2::unavailable(
        ProcessObservationUnavailableReasonV1::WorkerLostBeforeFreeze,
    );
    observation.root_identity = Some(WindowsProcessIdentityV1 {
        process_id: 1234,
        creation_time_100ns: 5678,
    });
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    };
    let receipt = WindowsTerminalReceiptV3 {
        schema_version: 3,
        attempt_id: attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: request_sha256.clone(),
        payload: WindowsTerminalPayloadV3::Execution {
            child_pid: 1234,
            duration_millis: 29,
            authorization_offset_millis: 7,
            outcome: RunOutcome::MonitorFailed {
                error: "MCSEALED-WINDOWS-GUARDIAN-LOSS".into(),
                child_after_termination: Some(ChildTermination::ExitCode { code: 0 }),
                cleanup: CleanupSummary {
                    force_attempted: true,
                    direct_child_reaped: true,
                    workload_empty: Some(true),
                    ..CleanupSummary::default()
                },
            },
            boundary_detail: Box::new(BoundaryMechanismEvidence::WindowsJobObjectV3(Box::new(
                WindowsSealedEvidenceV3 {
                    schema_version: 3,
                    target_identity: observation.root_identity.clone(),
                    process_observation: Some(Box::new(observation.clone())),
                    service_identity: "MemCordonSealedControl+MemCordonSealedLauncher:v1".into(),
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
                    ..WindowsSealedEvidenceV3::default()
                },
            ))),
        },
        process_observation: observation,
        cleanup_process_creation: None,
        restart_safety: restart_safety.clone(),
        retirement_proof: WindowsRetirementProofV3 {
            capability_extinction: None,
            schema_version: 3,
            source: WindowsRetirementProofSourceV2::LiveNative,
            attempt_id,
            nonce,
            request_sha256,
            provider_generation: "fixture-generation".into(),
            launch_incarnation: "fixture-incarnation".into(),
            original_boot_id: "fixture-boot".into(),
            job_identity: "34".repeat(32),
            owner_manifest_sha256: "56".repeat(32),
            guardian_receipt_sha256: None,
            current_boot_id: None,
            target_completion_observed: true,
            native_job_empty_observed: true,
            relay_closure_observed: true,
            guardian_completion_observed: true,
            owner_capabilities_closed: true,
            launch_gate_closed: true,
        },
    };
    receipt.validate_for_attempt().unwrap();
    let rejection = WindowsProviderRejectionV3 {
        schema_version: 3,
        provider_failure: Some(diagnostic),
        guardian_causal_receipt: None,
        code: "MCSEALED-WINDOWS-GUARDIAN-LOSS".into(),
        phase: BoundarySetupPhase::Monitoring,
        detail: "guardian exited while the target was released".into(),
        os_code: None,
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety,
        disposition: WindowsProviderRejectionDispositionV3::PostauthorizationFailure {
            receipt: Box::new(receipt),
        },
    };
    assert!(rejection.is_consistent());
    rejection
}
