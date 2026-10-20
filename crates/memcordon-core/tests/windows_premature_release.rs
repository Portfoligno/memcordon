#[path = "support/windows_postauthorization.rs"]
mod physical_fixture;

use memcordon_core::*;

fn witness(mutant: WindowsSealedMutant) -> WindowsPrematureReleaseWitnessV1 {
    WindowsPrematureReleaseWitnessV1 {
        schema_version: 1,
        mutant,
        observation: WindowsMutantNativeObservationV1::PrematureAuthorization {
            guardian_ready: mutant != WindowsSealedMutant::ResumeBeforeGuardian,
            relays_ready: mutant != WindowsSealedMutant::ResumeBeforeRelays,
            target_marker_observed: true,
        },
    }
}

fn rejection() -> WindowsProviderRejectionV2 {
    let mut rejected = physical_fixture::rejection();
    let mut receipt = rejected.terminal_receipt().unwrap().clone();
    receipt.payload = WindowsTerminalPayloadV2::PrematureReleaseFailure {
        witness: witness(WindowsSealedMutant::ResumeBeforeGuardian),
        child_pid: 1234,
        duration_millis: 29,
        outcome: RunOutcome::MonitorFailed {
            error: "an executable mutant produced a native invariant violation".into(),
            child_after_termination: Some(ChildTermination::ExitCode { code: 125 }),
            cleanup: CleanupSummary {
                force_attempted: true,
                direct_child_reaped: true,
                workload_empty: Some(true),
                ..CleanupSummary::default()
            },
        },
    };
    let provider = rejected
        .provider_failure
        .as_ref()
        .unwrap()
        .provider_binding
        .clone();
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Launch,
            operation: FailureOperationV1::UnclassifiedProviderOperation,
            code: FailureCodeV1::UnexpectedProviderFailure,
            native_code: None,
            observed_phase: AttemptObservationPhaseV1::BeforeAuthorization,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    journal.durable_through_sequence = Some(journal.sequence);
    rejected.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(
            provider,
            &receipt.attempt_id,
            &receipt.request_sha256,
            &journal,
        )
        .unwrap(),
    );
    rejected.code = "MCSEALED-WINDOWS-MUTANT-OBSERVED".into();
    rejected.phase = BoundarySetupPhase::Authorization;
    rejected.detail = "actual premature release observed, then native cleanup completed".into();
    rejected.disposition = WindowsProviderRejectionDispositionV2::PrematureReleaseFailure {
        receipt: Box::new(receipt),
    };
    assert!(rejected.is_consistent());
    rejected
}

#[test]
fn premature_witness_requires_selected_native_violation_and_marker() {
    for selected in [
        WindowsSealedMutant::ResumeBeforeGuardian,
        WindowsSealedMutant::ResumeBeforeRelays,
    ] {
        let valid = witness(selected);
        assert!(valid.is_consistent());
        assert_eq!(
            serde_json::from_slice::<WindowsPrematureReleaseWitnessV1>(
                &serde_json::to_vec(&valid).unwrap()
            )
            .unwrap(),
            valid
        );
        for dimension in 0..4 {
            let mut changed = valid.clone();
            match dimension {
                0 => changed.schema_version = 2,
                1 => changed.mutant = WindowsSealedMutant::OmitJobList,
                2 => {
                    changed.observation = WindowsMutantNativeObservationV1::PrematureAuthorization {
                        guardian_ready: true,
                        relays_ready: true,
                        target_marker_observed: true,
                    }
                }
                _ => {
                    changed.observation = WindowsMutantNativeObservationV1::PrematureAuthorization {
                        guardian_ready: false,
                        relays_ready: false,
                        target_marker_observed: false,
                    }
                }
            }
            assert!(!changed.is_consistent(), "dimension {dimension}");
        }
    }
}

#[test]
fn premature_receipt_requires_complete_native_retirement_and_never_certifies() {
    let rejected = rejection();
    let receipt = rejected.terminal_receipt().unwrap();
    receipt.validate_for_attempt().unwrap();
    assert!(
        receipt
            .validate_for_certification(&receipt.attempt_id, 1)
            .is_err()
    );
    let payload = serde_json::to_value(&receipt.payload).unwrap();
    assert!(payload.get("authorization_offset_millis").is_none());
    assert!(payload.get("boundary_detail").is_none());
    for dimension in 0..10 {
        let mut changed = receipt.clone();
        match dimension {
            0 => changed.retirement_proof.target_completion_observed = false,
            1 => changed.retirement_proof.native_job_empty_observed = false,
            2 => changed.retirement_proof.relay_closure_observed = false,
            3 => changed.retirement_proof.guardian_completion_observed = false,
            4 => changed.retirement_proof.owner_capabilities_closed = false,
            5 => changed.retirement_proof.launch_gate_closed = false,
            6 => changed.retirement_proof.policy_reference_bound = false,
            7 => changed.retirement_proof.request_sha256 = "foreign".into(),
            8 => {
                changed
                    .process_observation
                    .root_identity
                    .as_mut()
                    .unwrap()
                    .process_id += 1
            }
            _ => changed.restart_safety.direct_child_reaped = false,
        }
        assert!(
            changed.validate_for_attempt().is_err(),
            "dimension {dimension}"
        );
    }
    let mut natural = receipt.clone();
    let WindowsTerminalPayloadV2::PrematureReleaseFailure { outcome, .. } = &mut natural.payload
    else {
        unreachable!()
    };
    *outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: CleanupSummary::default(),
    };
    assert!(natural.validate_for_attempt().is_err());
}

#[test]
fn premature_rejection_rejects_ordinary_dispositions_and_foreign_cause_binding() {
    let rejected = rejection();
    let receipt = rejected.terminal_receipt().unwrap().clone();
    let mut ordinary = rejected.clone();
    ordinary.disposition = WindowsProviderRejectionDispositionV2::PostauthorizationFailure {
        receipt: Box::new(receipt),
    };
    assert!(!ordinary.is_consistent());
    let mut wrong_payload = rejected.clone();
    wrong_payload.disposition = WindowsProviderRejectionDispositionV2::PrematureReleaseFailure {
        receipt: Box::new(
            physical_fixture::rejection()
                .terminal_receipt()
                .unwrap()
                .clone(),
        ),
    };
    assert!(!wrong_payload.is_consistent());
    for dimension in 0..3 {
        let mut changed = rejected.clone();
        let mut diagnostic = changed.provider_failure.take().unwrap();
        match dimension {
            0 => {
                diagnostic.provider_binding.generation =
                    BoundedText::new("foreign-provider").unwrap()
            }
            1 => diagnostic.attempt_id = memcordon_core::DiagnosticSha256::from_bytes([0x98; 32]),
            _ => {
                diagnostic.request_sha256 = memcordon_core::DiagnosticSha256::from_bytes([0x76; 32])
            }
        }
        diagnostic.projection_sha256 = diagnostic.canonical_digest();
        changed.provider_failure = Some(diagnostic);
        assert!(!changed.is_consistent(), "dimension {dimension}");
    }
}

#[test]
fn premature_outbox_joins_selected_witness_seed_and_exact_receipt() {
    let rejected = rejection();
    let receipt = rejected.terminal_receipt().unwrap().clone();
    let selected = witness(WindowsSealedMutant::ResumeBeforeGuardian);
    let mut record = WindowsDurableAttemptRecordV4 {
        schema_version: 4,
        attempt_id: receipt.attempt_id.clone(),
        provider_generation: receipt.retirement_proof.provider_generation.clone(),
        boot_identity: receipt.retirement_proof.original_boot_id.clone(),
        launch_incarnation: receipt.retirement_proof.launch_incarnation.clone(),
        nonce: receipt.nonce.clone(),
        request_sha256: receipt.request_sha256.clone(),
        caller_process_identity: WindowsProcessIdentityV1 {
            process_id: 55,
            creation_time_100ns: 66,
        },
        caller_token_sha256: "12".repeat(32),
        job_identity_sha256: receipt.retirement_proof.job_identity.clone(),
        guardian_identity: None,
        worker_identity: None,
        worker_thread_identity: None,
        target_identity: receipt.process_observation.root_identity.clone(),
        state: WindowsAttemptStateV1::Empty,
        lifecycle: WindowsTerminalLifecycleV1::OutboxStaged,
        authorization_unix_millis: None,
        resume_attempted: false,
        target_released: true,
        cleanup_state: WindowsDurableCleanupStateV1 {
            termination_requested: true,
            active_processes_zero: true,
            guardian_reaped: true,
            final_handles_closed: true,
        },
        owner_manifest: None,
        job_closure_contract: None,
        recovery_authorization: None,
        terminal_publication_reserved: true,
        terminal_seed: Some(WindowsTerminalSeedV2 {
            schema_version: 2,
            attempt_id: receipt.attempt_id.clone(),
            nonce: receipt.nonce.clone(),
            request_sha256: receipt.request_sha256.clone(),
            process_observation: receipt.process_observation.clone(),
            primary_failure: rejected.provider_failure.clone(),
            premature_release: Some(selected),
        }),
        retirement_proof: Some(receipt.retirement_proof.clone()),
        terminal_response_json: None,
        terminal_disposition: Some(
            WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure {
                mutant: WindowsSealedMutant::ResumeBeforeGuardian,
            },
        ),
        terminalization: WindowsTerminalizationStatusV1 {
            schema_version: 1,
            owner: WindowsTerminalizationOwnerV1::LauncherWorker,
            sequence: 1,
            checkpoint: WindowsTerminalizationCheckpointV1::OutboxStaged,
            last_error: None,
            secondary_errors: Vec::new(),
        },
        causal_diagnostics: WindowsCausalDiagnosticsV1::default(),
        diagnostic_retention: DiagnosticRetentionV1::admitted_at(0).unwrap(),
        workload_admission: None,
        workload_checkpoint: None,
        record_revision: 1,
        provider_incarnation: "34".repeat(32),
        integrity_sha256: String::new(),
    };
    let response = WindowsLauncherResponseV3::Reject {
        schema_version: 3,
        attempt_id: receipt.attempt_id,
        nonce: receipt.nonce,
        request_sha256: receipt.request_sha256,
        rejection: rejected,
    };
    // This exercises the actual outbox-binding predicate, not record authentication.
    assert!(windows_terminal_outbox_is_bound_v3(&record, &response));
    for dimension in 0..10 {
        let mut changed = record.clone();
        match dimension {
            0 => {
                changed.terminal_disposition = Some(WindowsAttemptTerminalDispositionV1::Posttarget)
            }
            1 => {
                changed.terminal_disposition = Some(
                    WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure {
                        mutant: WindowsSealedMutant::ResumeBeforeRelays,
                    },
                )
            }
            2 => changed.terminal_seed.as_mut().unwrap().premature_release = None,
            3 => changed.request_sha256 = "98".repeat(32),
            4 => {
                changed
                    .retirement_proof
                    .as_mut()
                    .unwrap()
                    .native_job_empty_observed = false
            }
            5 => changed.authorization_unix_millis = Some(1),
            6 => changed.resume_attempted = true,
            7 => changed.target_released = false,
            8 => {
                changed
                    .terminal_seed
                    .as_mut()
                    .unwrap()
                    .process_observation
                    .root_identity
                    .as_mut()
                    .unwrap()
                    .creation_time_100ns += 1
            }
            _ => {
                changed
                    .target_identity
                    .as_mut()
                    .unwrap()
                    .creation_time_100ns += 1
            }
        }
        assert!(
            !windows_terminal_outbox_is_bound_v3(&changed, &response),
            "dimension {dimension}"
        );
    }
    record.terminal_seed.as_mut().unwrap().premature_release =
        Some(witness(WindowsSealedMutant::ResumeBeforeRelays));
    assert!(!windows_terminal_outbox_is_bound_v3(&record, &response));
}
