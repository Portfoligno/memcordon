#[path = "../../../crates/memcordon-core/tests/support/windows_current_postauthorization.rs"]
mod support;
use memcordon_ci::windows_readiness_components::authenticated_transport_injection_authority;
use memcordon_core::*;

#[test]
fn only_original_service_process_loss_selects_its_exact_recovery_endpoint() {
    use memcordon_ci::windows_readiness_components::ServiceRecoveryRole;

    assert_eq!(ServiceRecoveryRole::for_fault(None), None);
    for (fault, role, service, pipe) in [
        (
            WindowsSealedFault::ControlServiceKilledAfterAuthorization,
            ServiceRecoveryRole::Control,
            WINDOWS_CONTROL_SERVICE_NAME,
            WINDOWS_CONTROL_PIPE,
        ),
        (
            WindowsSealedFault::LauncherServiceKilledAfterAuthorization,
            ServiceRecoveryRole::Launcher,
            WINDOWS_LAUNCHER_SERVICE_NAME,
            WINDOWS_LAUNCHER_PIPE,
        ),
        (
            WindowsSealedFault::AllJobOwnersClosedAfterAuthorization,
            ServiceRecoveryRole::Launcher,
            WINDOWS_LAUNCHER_SERVICE_NAME,
            WINDOWS_LAUNCHER_PIPE,
        ),
    ] {
        let selected = ServiceRecoveryRole::for_fault(Some(fault)).unwrap();
        assert_eq!(selected, role);
        assert_eq!(selected.service_name(), service);
        assert_eq!(selected.pipe_name(), pipe);
    }
    for fault in memcordon_ci::windows_readiness_components::fault_selectors() {
        if !matches!(
            fault,
            WindowsSealedFault::ControlServiceKilledAfterAuthorization
                | WindowsSealedFault::LauncherServiceKilledAfterAuthorization
                | WindowsSealedFault::AllJobOwnersClosedAfterAuthorization
        ) {
            assert_eq!(ServiceRecoveryRole::for_fault(Some(fault)), None);
        }
    }
}

#[test]
fn service_recovery_executor_never_substitutes_for_original_held_owner() {
    use memcordon_ci::windows_readiness_components::control_service_recovery_process_matches;
    let original = WindowsProcessIdentityV1 {
        process_id: 100,
        creation_time_100ns: 200,
    };
    for replacement in [
        WindowsProcessIdentityV1 {
            process_id: 101,
            creation_time_100ns: 201,
        },
        WindowsProcessIdentityV1 {
            process_id: 100,
            creation_time_100ns: 201,
        },
    ] {
        assert!(control_service_recovery_process_matches(
            &original,
            &replacement,
            replacement.process_id
        ));
        assert!(!control_service_recovery_process_matches(
            &original,
            &replacement,
            999
        ));
        assert!(!control_service_recovery_process_matches(
            &original,
            &replacement,
            0
        ));
        for invalid in [
            WindowsProcessIdentityV1 {
                process_id: 0,
                creation_time_100ns: replacement.creation_time_100ns,
            },
            WindowsProcessIdentityV1 {
                process_id: replacement.process_id,
                creation_time_100ns: 0,
            },
        ] {
            assert!(!control_service_recovery_process_matches(
                &original,
                &invalid,
                replacement.process_id
            ));
            assert!(!control_service_recovery_process_matches(
                &invalid,
                &replacement,
                replacement.process_id
            ));
        }
    }
    assert!(!control_service_recovery_process_matches(
        &original,
        &original,
        original.process_id
    ));
}

fn fixture() -> (
    WindowsProviderResponseV4,
    PublicProviderBindingV1,
    String,
    String,
    String,
) {
    let mut rejection = support::rejection();
    let previous = rejection.provider_failure.as_ref().unwrap();
    let provider = previous.provider_binding.clone();
    let attempt = String::from(previous.attempt_id.clone());
    let request = String::from(previous.request_sha256.clone());
    let nonce = rejection.terminal_receipt().unwrap().nonce.clone();
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal
        .observe(CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::Launcher,
            category: FailureCategoryV1::Transport,
            operation: FailureOperationV1::DeliverResponse,
            code: FailureCodeV1::ControlTransport,
            native_code: Some(NativeFailureCodeV1::Win32(232)),
            observed_phase: AttemptObservationPhaseV1::Cleaning,
            safe_detail: SafeDiagnosticDetailV1::InjectedWindowsFault {
                fault: WindowsSealedFault::ControlWorkerKilledAfterAuthorization,
            },
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    journal.durable_through_sequence = Some(journal.sequence);
    rejection.provider_failure = Some(
        ProviderFailureDiagnosticV1::from_journal(provider.clone(), &attempt, &request, &journal)
            .unwrap(),
    );
    rejection.code = "MCSEALED-WINDOWS-AUTHORITY-LOSS".into();
    rejection.phase = BoundarySetupPhase::Retirement;
    assert!(rejection.is_consistent());
    (
        WindowsProviderResponseV4::Reject {
            schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt.clone(),
            nonce: nonce.clone(),
            request_sha256: request.clone(),
            rejection,
        },
        provider,
        attempt,
        nonce,
        request,
    )
}

#[test]
fn original_authenticated_transport_receipt_survives_later_ack_retirement() {
    let (response, provider, attempt, nonce, request) = fixture();
    let selected = WindowsSealedFault::ControlWorkerKilledAfterAuthorization;
    let accepts = |response: &WindowsProviderResponseV4,
                   selected,
                   provider: &PublicProviderBindingV1,
                   attempt: &str,
                   nonce: &str,
                   request: &str| {
        authenticated_transport_injection_authority(
            response, selected, provider, attempt, nonce, request,
        )
    };
    assert!(accepts(
        &response, selected, &provider, &attempt, &nonce, &request
    ));
    let WindowsProviderResponseV4::Reject { rejection, .. } = &response else {
        unreachable!()
    };
    let receipt = rejection.terminal_receipt().unwrap();
    let proof = &receipt.retirement_proof;
    let retired = WindowsTerminalRetiredV2 {
        schema_version: 2,
        attempt_id: attempt.clone(),
        nonce: nonce.clone(),
        request_sha256: request.clone(),
        terminal_response_sha256: "11".repeat(32),
        disposition: WindowsAttemptTerminalDispositionV1::Posttarget,
        provider_generation: provider.generation.as_str().into(),
        original_boot_id: proof.original_boot_id.clone(),
        launch_incarnation: proof.launch_incarnation.clone(),
        job_identity: proof.job_identity.clone(),
        owner_manifest_sha256: proof.owner_manifest_sha256.clone(),
        retirement_proof_sha256: "22".repeat(32),
        preauthorization_retirement_proof: None,
        ledger_generation: "33".repeat(32),
        completion: WindowsRetirementLedgerCompletionV1::RetirementComplete,
    };
    assert!(retired.is_consistent_for(&attempt, &nonce, &request, &"11".repeat(32)));
    assert!(!accepts(
        &WindowsProviderResponseV4::TerminalRetiredV2(retired),
        selected,
        &provider,
        &attempt,
        &nonce,
        &request
    ));
    assert!(!accepts(
        &WindowsProviderResponseV4::Terminal(receipt.clone()),
        selected,
        &provider,
        &attempt,
        &nonce,
        &request
    ));
    assert!(!accepts(
        &response,
        WindowsSealedFault::ControlServiceKilledAfterAuthorization,
        &provider,
        &attempt,
        &nonce,
        &request
    ));
    for (actual_attempt, actual_nonce, actual_request) in [
        ("99".repeat(32), nonce.clone(), request.clone()),
        (attempt.clone(), "99".repeat(16), request.clone()),
        (attempt.clone(), nonce.clone(), "99".repeat(32)),
    ] {
        assert!(!accepts(
            &response,
            selected,
            &provider,
            &actual_attempt,
            &actual_nonce,
            &actual_request
        ));
    }
    let mut wrong_provider = provider.clone();
    wrong_provider.generation = BoundedText::new("other-generation").unwrap();
    assert!(!accepts(
        &response,
        selected,
        &wrong_provider,
        &attempt,
        &nonce,
        &request
    ));
    for field in [
        "failure",
        "receipt-nonce",
        "receipt-generation",
        "natural-outcome",
        "phase",
        "native-code",
        "schema",
    ] {
        let mut changed = response.clone();
        let WindowsProviderResponseV4::Reject {
            schema_version,
            rejection,
            ..
        } = &mut changed
        else {
            unreachable!()
        };
        match field {
            "failure" => rejection.provider_failure = None,
            "schema" => *schema_version = 0,
            "phase" | "native-code" => {
                let failure = rejection.provider_failure.as_mut().unwrap();
                let OriginalFailureV1::Observed { event } = &mut failure.original else {
                    unreachable!()
                };
                if field == "phase" {
                    event.observed_phase = AttemptObservationPhaseV1::BeforeAuthorization;
                } else {
                    event.native_code = Some(NativeFailureCodeV1::Win32(5));
                }
            }
            _ => {
                let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
                    &mut rejection.disposition
                else {
                    unreachable!()
                };
                match field {
                    "receipt-nonce" => receipt.nonce = "99".repeat(16),
                    "receipt-generation" => {
                        receipt.retirement_proof.provider_generation = "other-generation".into()
                    }
                    "natural-outcome" => {
                        let WindowsTerminalPayloadV3::Execution { outcome, .. } =
                            &mut receipt.payload
                        else {
                            unreachable!()
                        };
                        *outcome = RunOutcome::Exited {
                            child: ChildTermination::ExitCode { code: 0 },
                            peak: None,
                            cleanup: CleanupSummary::default(),
                        };
                    }
                    _ => unreachable!(),
                }
            }
        }
        assert!(
            !accepts(&changed, selected, &provider, &attempt, &nonce, &request),
            "accepted {field}"
        );
    }
}
