#![cfg(feature = "test-support")]

#[path = "../../memcordon-core/tests/support/windows_postauthorization.rs"]
mod terminal_fixture;

use memcordon_core::*;
use memcordon_platform::{SupervisorRequest, test_support::supervise_failed_attempt};
use std::{ffi::OsStr, time::Duration};

fn rejection() -> WindowsProviderRejectionV2 {
    let mut rejection = terminal_fixture::rejection();
    let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        panic!("full execution fixture")
    };
    let WindowsTerminalPayloadV2::Execution {
        boundary_detail, ..
    } = &mut receipt.payload
    else {
        panic!("execution fixture")
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = boundary_detail.as_mut() else {
        panic!("Windows native fixture")
    };
    native.schema_version = 2;
    native.service_identity = "MemCordonSealedControl+MemCordonSealedLauncher:v1".into();
    native.caller_token_authenticated = true;
    native.initial_target_token_matches_caller = true;
    native.credential_transition_disposition =
        CredentialTransitionDisposition::PreserveCallerEnvelope;
    native.job_membership_independent_of_token = true;
    native.job_created = true;
    native.job_limits_verified = true;
    native.kill_on_close_verified = true;
    native.breakaway_denied = true;
    native.completion_port_associated = true;
    native.guardian_ready = true;
    native.target_created_suspended = true;
    native.job_list_applied_at_creation = true;
    native.handle_list_applied_at_creation = true;
    native.target_job_membership_verified = true;
    native.target_still_suspended_during_verification = true;
    native.inherited_handles_verified = true;
    assert!(rejection.is_consistent());
    rejection
}

fn failure(rejection: WindowsProviderRejectionV2) -> Error {
    let projection = rejection.provider_failure.clone().unwrap();
    let mut error = Error::new(
        ErrorCategory::Setup,
        "MCSEALED-PROVIDER-REJECTION",
        rejection.detail.clone(),
    )
    .with_boundary_setup_failure(BoundarySetupFailure {
        requested: BoundaryRequirement::Sealed,
        mechanism: Some("windows-job-object-v2".into()),
        phase: rejection.phase,
        target_created: rejection.target_created,
        target_released: rejection.target_released,
        cleanup_attempted: rejection.cleanup_attempted,
        restart_safety: rejection.restart_safety.clone(),
    })
    .with_windows_provider_rejection_v2(rejection.clone());
    error.provider_association = Some(Box::new(result_v1::ProviderAttemptAssociationV1 {
        provider: projection.provider_binding.clone(),
        attempt_id: projection.attempt_id.clone(),
        request_sha256: projection.request_sha256.clone(),
    }));
    error.provider_failure = Some(projection);
    error.launch_phase = Some("monitoring");
    if let Some(WindowsTerminalReceiptV2 {
        payload:
            WindowsTerminalPayloadV2::Execution {
                child_pid,
                authorization_offset_millis,
                outcome,
                ..
            },
        ..
    }) = rejection.terminal_receipt()
    {
        error.target_pid = Some(*child_pid);
        error.authorization_offset = Some(Duration::from_millis(*authorization_offset_millis));
        error.cleanup = outcome.cleanup().clone();
    }
    error
}

fn request() -> SupervisorRequest {
    SupervisorRequest {
        policy: Policy::default().with_boundary(BoundaryRequirement::Sealed),
        restart: RestartPolicy::Never,
        command: CommandSpec::new("receipt-fixture-target"),
        memcordon_executable: None,
        resolved_backend: Some(BackendCapabilityReport {
            name: "windows-job-object".into(),
            boundary: BoundaryCapability {
                class: BoundaryClass::Sealed,
                mechanism: "windows-job-object-v2".into(),
                target_gated: true,
                boundary_verified_before_authorization: true,
                target_can_reconfigure_boundary: false,
                frontend_loss_cleanup_authority: true,
                workload_empty_proof: true,
                limitations: Vec::new(),
            },
            ..BackendCapabilityReport::default()
        }),
    }
}

fn report(execution: SupervisionExecution) -> MemcordonReport {
    let policy = PolicyEnvelopeReport {
        requested: RequestedPolicyReport {
            workload: Default::default(),
            boundary: BoundaryRequirement::Sealed,
            memory: None,
            deadline: None,
            wait_for: "command".into(),
            signal_grace_ms: 2_000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: RequestedRestartPolicyReport {
                enabled: false,
                enablement_source: None,
                configured_conditions: RestartConditions::NONE,
                limit: RestartLimit::Unlimited,
                backoff: None,
                circuit_breaker: None,
            },
        },
        effective: EffectivePolicyReport {
            workload: workload_evidence::RuntimeWorkloadResolution::unresolved(
                None,
                workload_evidence::BaselineRestrictionObservationV1::UnmanagedStandardBackend,
            ),
            boundary: BoundaryClass::Sealed,
            memory: None,
            deadline: None,
            wait_for: "command".into(),
            signal_grace_ms: 2_000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: EffectiveRestartPolicyReport {
                enabled: false,
                conditions: RestartConditions::NONE,
                dormant_conditions: Vec::new(),
                cleanup_proof_required: false,
            },
        },
        effects: Vec::new(),
    };
    let backend = execution.backend().clone();
    MemcordonReport::schema10(
        ToolReport {
            name: "memcordon".into(),
            version: "fixture".into(),
        },
        InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: Vec::new(),
            memory_token: None,
            deadline_token: None,
            argv: vec![NativeArgument::from_os(OsStr::new(
                "receipt-fixture-target",
            ))],
        },
        policy,
        Some(backend),
        Some(execution),
        None,
    )
    .unwrap()
}

#[test]
fn actual_supervisor_failure_retains_windows_execution_proofs_and_public_association() {
    use result_v1::{AuthorizationV1, CleanupStateV1, OutcomeKindV1, ResultV1};
    let rejection = rejection();
    let diagnostic = rejection.provider_failure.clone().unwrap();
    let error = failure(rejection);
    assert!(!error.cgroup_verified_before_release);
    assert!(!error.guardian_ready_before_release);
    let execution = supervise_failed_attempt(request(), error).unwrap();
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert_eq!(execution.targets_authorized(), 1);
    let attempt = execution.attempts().records().next().unwrap();
    assert_eq!(attempt.phase, AttemptPhase::Failed);
    assert!(attempt.outcome.is_none());
    assert_eq!(attempt.target_pid, Some(1234));
    assert_eq!(
        attempt.authorized_offset_ms.unwrap() - attempt.started_offset_ms.unwrap(),
        7
    );
    assert!(attempt.runtime.is_none());
    assert!(matches!(
        attempt.boundary_detail,
        BoundaryMechanismEvidence::WindowsJobObjectV2(_)
    ));
    assert!(boundary_evidence_is_consistent(
        &attempt.launch,
        &attempt.restart_safety,
        &attempt.boundary_detail
    ));
    let source = report(execution);
    assert!(source.error.is_none());
    let result = ResultV1::from_legacy(&source, vec!["windows-sealed-runtime".into()]).unwrap();
    assert_eq!(result.outcome.kind, OutcomeKindV1::ProviderFailure);
    assert_eq!(result.outcome.wrapper_status, 125);
    assert_eq!(
        result.outcome.native_termination,
        Some(ChildTermination::ExitCode { code: 0 })
    );
    assert_eq!(result.authorization, AuthorizationV1::Granted);
    assert_eq!(result.cleanup.state, CleanupStateV1::Complete);
    assert_eq!(result.diagnostics, Some(diagnostic.clone()));
    assert_eq!(
        result.provider_association.unwrap().attempt_id,
        diagnostic.attempt_id
    );
}

#[test]
fn failed_supervisor_does_not_invent_missing_windows_native_proofs() {
    for missing in ["guardian", "handles", "breakaway", "caller-token"] {
        let mut rejection = rejection();
        let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
            &mut rejection.disposition
        else {
            panic!("fixture receipt")
        };
        let WindowsTerminalPayloadV2::Execution {
            boundary_detail, ..
        } = &mut receipt.payload
        else {
            panic!("fixture execution")
        };
        let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = boundary_detail.as_mut() else {
            panic!("fixture Windows boundary")
        };
        match missing {
            "guardian" => native.guardian_ready = false,
            "handles" => native.inherited_handles_verified = false,
            "breakaway" => native.breakaway_denied = false,
            _ => native.initial_target_token_matches_caller = false,
        }
        assert!(
            rejection.is_consistent(),
            "bounded receipt still requires native boundary validation"
        );
        assert_eq!(
            supervise_failed_attempt(request(), failure(rejection))
                .unwrap_err()
                .code,
            "MCRESTART-MODEL",
            "{missing}"
        );
    }
}

#[test]
fn failed_supervisor_does_not_promote_missing_recovered_or_mismatched_receipts() {
    let mut missing = failure(rejection());
    missing.windows_provider_rejection_v2 = None;
    assert_eq!(
        supervise_failed_attempt(request(), missing)
            .unwrap_err()
            .code,
        "MCRESTART-MODEL"
    );
    let mut mismatched = failure(rejection());
    mismatched.authorization_offset = Some(Duration::from_millis(8));
    assert_eq!(
        supervise_failed_attempt(request(), mismatched)
            .unwrap_err()
            .code,
        "MCRESTART-MODEL"
    );
    let mut recovered = rejection();
    let original = recovered
        .provider_failure
        .as_ref()
        .unwrap()
        .original
        .clone();
    let WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } =
        &mut recovered.disposition
    else {
        panic!("fixture receipt")
    };
    receipt.payload = WindowsTerminalPayloadV2::RecoveredClosure {
        primary_failure: original,
        target_creation_observed: true,
        resume_attempted: true,
    };
    receipt.retirement_proof.source = WindowsRetirementProofSourceV2::GuardianRecovery;
    receipt.retirement_proof.target_completion_observed = false;
    receipt.retirement_proof.guardian_receipt_sha256 = Some("78".repeat(32));
    assert!(recovered.is_consistent());
    assert_eq!(
        supervise_failed_attempt(request(), failure(recovered))
            .unwrap_err()
            .code,
        "MCRESTART-MODEL"
    );
}
