#![cfg(feature = "test-support")]

#[path = "../../memcordon-core/tests/support/windows_current_postauthorization.rs"]
mod terminal_fixture;

use memcordon_core::*;
use memcordon_platform::{SupervisorRequest, test_support::supervise_failed_attempt};
use std::time::Duration;

fn rejection() -> WindowsProviderRejectionV3 {
    let mut rejection = terminal_fixture::rejection();
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut rejection.disposition
    else {
        panic!("full execution fixture")
    };
    let WindowsTerminalPayloadV3::Execution {
        boundary_detail, ..
    } = &mut receipt.payload
    else {
        panic!("execution fixture")
    };
    let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_mut() else {
        panic!("Windows native fixture")
    };
    native.schema_version = 3;
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

fn failure(rejection: WindowsProviderRejectionV3) -> Error {
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
    .with_windows_provider_rejection_v3(rejection.clone());
    error.provider_association = Some(Box::new(execution_facts::ProviderAttemptAssociationV1 {
        provider: projection.provider_binding.clone(),
        attempt_id: projection.attempt_id.clone(),
        request_sha256: projection.request_sha256.clone(),
    }));
    error.provider_failure = Some(projection);
    error.launch_phase = Some("monitoring");
    if let Some(WindowsTerminalReceiptV3 {
        payload:
            WindowsTerminalPayloadV3::Execution {
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
        #[cfg(target_os = "linux")]
        workload_frontend: None,
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

#[test]
fn actual_supervisor_failure_retains_windows_execution_proofs_and_public_association() {
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
        BoundaryMechanismEvidence::WindowsJobObjectV3(_)
    ));
    assert!(boundary_evidence_is_consistent(
        &attempt.launch,
        &attempt.restart_safety,
        &attempt.boundary_detail
    ));
    let failure = attempt.operational_failure.as_ref().unwrap();
    assert_eq!(failure.provider_failure.as_ref(), Some(&diagnostic));
    assert_eq!(
        failure.provider_association.as_ref().unwrap().attempt_id,
        diagnostic.attempt_id
    );
    assert!(
        failure
            .windows_current_rejection
            .as_ref()
            .unwrap()
            .is_consistent()
    );
}

#[test]
fn failed_supervisor_does_not_invent_missing_windows_native_proofs() {
    for missing in ["guardian", "handles", "breakaway", "caller-token"] {
        let mut rejection = rejection();
        let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
            &mut rejection.disposition
        else {
            panic!("fixture receipt")
        };
        let WindowsTerminalPayloadV3::Execution {
            boundary_detail, ..
        } = &mut receipt.payload
        else {
            panic!("fixture execution")
        };
        let BoundaryMechanismEvidence::WindowsJobObjectV3(native) = boundary_detail.as_mut() else {
            panic!("fixture Windows boundary")
        };
        match missing {
            "guardian" => native.guardian_ready = false,
            "handles" => native.inherited_handles_verified = false,
            "breakaway" => native.breakaway_denied = false,
            _ => native.initial_target_token_matches_caller = false,
        }
        assert!(
            !rejection.is_consistent(),
            "current receipt rejects the missing native release proof"
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
    missing.windows_provider_rejection_v3 = None;
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
    let WindowsProviderRejectionDispositionV3::PostauthorizationFailure { receipt } =
        &mut recovered.disposition
    else {
        panic!("fixture receipt")
    };
    receipt.payload = WindowsTerminalPayloadV3::RecoveredClosure {
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
