#![cfg(feature = "test-support")]

use memcordon_core::*;
use memcordon_platform::{SupervisorRequest, test_support::supervise_counted_failed_attempt};
use std::{ffi::OsStr, time::Duration};

fn request(scope: DeadlineScope) -> SupervisorRequest {
    let mut policy = Policy::default().with_boundary(BoundaryRequirement::Sealed);
    policy.deadline = Some(DeadlinePolicy::new(Duration::ZERO, scope).unwrap());
    SupervisorRequest {
        policy,
        restart: RestartPolicy::Never,
        command: CommandSpec::new("must-not-launch-for-zero-supervision"),
        memcordon_executable: None,
        resolved_backend: Some(BackendCapabilityReport {
            name: "selected-private-provider".into(),
            boundary: BoundaryCapability {
                class: BoundaryClass::Sealed,
                mechanism: "selected-private-provider".into(),
                target_gated: true,
                boundary_verified_before_authorization: true,
                target_can_reconfigure_boundary: false,
                frontend_loss_cleanup_authority: true,
                workload_empty_proof: true,
                ..BoundaryCapability::default()
            },
            ..BackendCapabilityReport::default()
        }),
    }
}

fn transport_failure() -> Error {
    let mut error = Error::new(
        ErrorCategory::Monitor,
        "MCSEALED-PRIVATE-TRANSACTION",
        "private request transfer deadline elapsed",
    );
    error.workload_may_be_alive = true;
    error
}

fn report(execution: SupervisionExecution, scope: DeadlineScope) -> MemcordonReport {
    let deadline = Some(DeadlinePolicyReport {
        duration_ms: 0,
        scope,
        origin: None,
        clock: "rust-instant".into(),
    });
    let policy = PolicyEnvelopeReport {
        requested: RequestedPolicyReport {
            workload: Default::default(),
            boundary: BoundaryRequirement::Sealed,
            memory: None,
            deadline: deadline.clone(),
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
            deadline,
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
            budget_tokens: vec![BudgetTokenReport {
                kind: BudgetKindReport::Time,
                token: "+0ms".into(),
            }],
            memory_token: None,
            deadline_token: Some("+0ms".into()),
            argv: vec![NativeArgument::from_os(OsStr::new("deadline-fixture"))],
        },
        policy,
        Some(backend),
        Some(execution),
        None,
    )
    .unwrap()
}

#[test]
fn declared_zero_supervision_expires_before_any_attempt_dispatch() {
    use result_v1::{AuthorizationV1, LaunchStateV1, OutcomeKindV1, ResultV1};
    let (execution, calls) =
        supervise_counted_failed_attempt(request(DeadlineScope::Supervision), transport_failure())
            .unwrap();
    assert_eq!(calls, 0);
    assert_eq!(execution.attempts().total, 0);
    assert_eq!(execution.targets_authorized(), 0);
    assert_eq!(execution.wrapper_exit_code(), 123);
    let deadline = execution.deadline().unwrap();
    assert_eq!(deadline.terminal_phase, SupervisionPhase::AttemptSetup);
    assert_eq!(deadline.evidence.origin(), "supervision-pre-attempt");
    assert_eq!(deadline.evidence.expires_offset_ms(), 0);
    assert_eq!(
        deadline.evidence.observed_offset_ms(),
        execution.duration_ms()
    );
    assert_eq!(deadline.evidence.grace_elapsed_ms(), 0);
    assert!(deadline.evidence.graceful_action().is_none());
    assert!(deadline.evidence.force_action().is_none());
    let source = report(execution, DeadlineScope::Supervision);
    let encoded = serde_json::to_vec(&source).unwrap();
    let source: MemcordonReport = serde_json::from_slice(&encoded).unwrap();
    let SupervisionTerminal::DeadlineOutsideAttempt { evidence } =
        &source.supervision.as_ref().unwrap().terminal
    else {
        panic!("pre-attempt deadline must survive report roundtrip")
    };
    assert_eq!(evidence.evidence.origin(), "supervision-pre-attempt");
    let result = ResultV1::from_legacy(&source, Vec::new()).unwrap();
    assert_eq!(result.outcome.wrapper_status, 123);
    assert_eq!(result.outcome.kind, OutcomeKindV1::Deadline);
    assert_eq!(result.launch.state, LaunchStateV1::NotCreated);
    assert_eq!(result.authorization, AuthorizationV1::RejectedBeforeRelease);
    assert!(result.launch.target_pid.is_none());
    assert!(result.outcome.native_termination.is_none());
    assert!(result.private_execution.is_none());
    assert!(!result.cleanup.direct_child_reaped);
    assert!(result.provider_association.is_none());
    ResultV1::parse(&serde_json::to_vec(&result).unwrap()).unwrap();
}

#[test]
fn zero_attempt_still_dispatches_and_unobserved_transport_failure_stays_uncertain() {
    use result_v1::{AuthorizationV1, CleanupStateV1, LaunchStateV1, OutcomeKindV1, ResultV1};
    let (execution, calls) =
        supervise_counted_failed_attempt(request(DeadlineScope::Attempt), transport_failure())
            .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(execution.attempts().total, 1);
    assert_eq!(execution.targets_authorized(), 0);
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert!(execution.deadline().is_none());
    let result =
        ResultV1::from_legacy(&report(execution, DeadlineScope::Attempt), Vec::new()).unwrap();
    assert_eq!(result.outcome.wrapper_status, 125);
    assert_eq!(result.outcome.kind, OutcomeKindV1::Unknown);
    assert_eq!(result.launch.state, LaunchStateV1::Unknown);
    assert_eq!(result.authorization, AuthorizationV1::Uncertain);
    assert_ne!(result.cleanup.state, CleanupStateV1::Complete);
    assert!(result.outcome.native_termination.is_none());
    assert!(!result.cleanup.direct_child_reaped);
}
