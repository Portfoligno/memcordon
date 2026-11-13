use memcordon_core::*;

#[path = "support/windows_current_postauthorization.rs"]
mod fixture;

fn cancellation() -> WindowsProviderRejectionV3 {
    let mut rejection = fixture::rejection();
    rejection.target_released = false;
    rejection.phase = BoundarySetupPhase::Authorization;
    let receipt = receipt_mut(&mut rejection);
    let WindowsTerminalPayloadV3::Execution {
        outcome,
        boundary_detail,
        ..
    } = &mut receipt.payload
    else {
        panic!("execution fixture")
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_mut() else {
        panic!("native fixture")
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
    rejection
}

fn receipt_mut(rejection: &mut WindowsProviderRejectionV3) -> &mut WindowsTerminalReceiptV3 {
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        panic!("postauthorization fixture")
    };
    receipt
}

fn outbox(
    rejection: WindowsProviderRejectionV3,
) -> (WindowsDurableAttemptRecordV5, WindowsLauncherResponseV4) {
    let receipt = rejection.terminal_receipt().unwrap();
    let record = WindowsDurableAttemptRecordV5 {
        schema_version: 5,
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
        authorization_unix_millis: Some(1),
        resume_attempted: false,
        target_released: false,
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
            primary_failure: rejection.provider_failure.clone(),
            premature_release: None,
        }),
        retirement_proof: Some(receipt.retirement_proof.clone()),
        terminal_response_json: None,
        terminal_disposition: Some(WindowsAttemptTerminalDispositionV1::Posttarget),
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
        record_revision: 1,
        provider_incarnation: "34".repeat(32),
        integrity_sha256: String::new(),
    };
    let response = WindowsLauncherResponseV4::Reject {
        schema_version: 4,
        attempt_id: receipt.attempt_id.clone(),
        nonce: receipt.nonce.clone(),
        request_sha256: receipt.request_sha256.clone(),
        rejection,
    };
    (record, response)
}

#[test]
fn suspended_cancellation_is_a_bound_reject_with_present_or_expired_diagnostics() {
    for omit_diagnostic in [false, true] {
        let mut rejected = cancellation();
        if omit_diagnostic {
            rejected.provider_failure = None;
        }
        rejected
            .terminal_receipt()
            .unwrap()
            .validate_for_attempt()
            .unwrap();
        assert!(rejected.is_consistent());
        let (record, response) = outbox(rejected);
        // Exercise the existing binding predicate, not record authentication.
        assert!(windows_terminal_outbox_is_bound_v4(&record, &response));
        let mut crossed = record.clone();
        crossed.nonce.push('x');
        assert!(!windows_terminal_outbox_is_bound_v4(&crossed, &response));
    }
}

#[test]
fn suspended_cancellation_rejects_release_binding_retirement_and_cleanup_contradictions() {
    for dimension in 0..11 {
        let mut rejected = cancellation();
        match dimension {
            0 => rejected.target_created = false,
            1 => rejected.target_released = true,
            2 => rejected.cleanup_attempted = false,
            3 => receipt_mut(&mut rejected).nonce.push('x'),
            4 => {
                receipt_mut(&mut rejected)
                    .retirement_proof
                    .owner_capabilities_closed = false
            }
            5 => rejected.restart_safety.helpers_reaped = false,
            6 => {
                rejected.target_released = true;
                let WindowsTerminalPayloadV3::Execution {
                    boundary_detail, ..
                } = &mut receipt_mut(&mut rejected).payload
                else {
                    unreachable!()
                };
                let BoundaryMechanismEvidence::WindowsJobObjectV3(native) =
                    boundary_detail.as_mut()
                else {
                    unreachable!()
                };
                native.target_released = true;
            }
            _ => {
                let failure = rejected.provider_failure.as_mut().unwrap();
                match dimension {
                    7 => failure.attempt_id = DiagnosticSha256::from_bytes([0x98; 32]),
                    8 => failure.request_sha256 = DiagnosticSha256::from_bytes([0x76; 32]),
                    9 => {
                        failure.provider_binding.generation =
                            BoundedText::new("other-provider").unwrap()
                    }
                    _ => {
                        if let OriginalFailureV1::Observed { event } = &mut failure.original {
                            event.sequence = 0;
                        }
                    }
                }
                failure.projection_sha256 = failure.canonical_digest();
            }
        }
        assert!(!rejected.is_consistent(), "dimension {dimension}");
        let (record, response) = outbox(rejected);
        assert!(
            !windows_terminal_outbox_is_bound_v4(&record, &response),
            "dimension {dimension}"
        );
    }
}

#[test]
fn suspended_reject_does_not_admit_exit_deadline_or_memory_outcomes() {
    for dimension in 0..3 {
        let mut rejected = cancellation();
        let WindowsTerminalPayloadV3::Execution { outcome, .. } =
            &mut receipt_mut(&mut rejected).payload
        else {
            unreachable!()
        };
        let cleanup = outcome.cleanup().clone();
        *outcome = match dimension {
            0 => RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 0 },
                peak: None,
                cleanup,
            },
            1 => RunOutcome::DeadlineExceeded {
                deadline: DeadlineEvidence::new(
                    1,
                    DeadlineScope::Attempt,
                    "fixture".into(),
                    1,
                    2,
                    0,
                    0,
                    None,
                    None,
                )
                .unwrap(),
                child_after_termination: Some(ChildTermination::WindowsStatus { status: 1 }),
                peak: None,
                cleanup,
            },
            _ => RunOutcome::LimitExceeded {
                limit: ByteSize::from_bytes(1),
                observed: Some(ByteSize::from_bytes(2)),
                peak: None,
                evidence: LimitEvidence {
                    backend: "windows-job".into(),
                    metric: "memory".into(),
                    detail: "fixture".into(),
                },
                child_after_termination: Some(ChildTermination::WindowsStatus { status: 1 }),
                cleanup,
            },
        };
        rejected
            .terminal_receipt()
            .unwrap()
            .validate_for_attempt()
            .unwrap();
        assert!(!rejected.is_consistent());
    }
}
