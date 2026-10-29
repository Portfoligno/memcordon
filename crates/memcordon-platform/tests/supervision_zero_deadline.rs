#![cfg(feature = "test-support")]

use memcordon_core::*;
use memcordon_platform::{SupervisorRequest, test_support::supervise_counted_failed_attempt};
use std::time::Duration;

fn request(scope: DeadlineScope) -> SupervisorRequest {
    let mut policy = Policy::default().with_boundary(BoundaryRequirement::Sealed);
    policy.deadline = Some(DeadlinePolicy::new(Duration::ZERO, scope).unwrap());
    SupervisorRequest {
        policy,
        restart: RestartPolicy::Never,
        command: CommandSpec::new("must-not-launch-for-zero-supervision"),
        memcordon_executable: None,
        #[cfg(target_os = "linux")]
        workload_frontend: None,
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

#[test]
fn declared_zero_supervision_expires_before_any_attempt_dispatch() {
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
    assert!(matches!(
        execution.terminal(),
        SupervisionTerminal::DeadlineOutsideAttempt { .. }
    ));
}

#[test]
fn zero_attempt_still_dispatches_and_unobserved_transport_failure_stays_uncertain() {
    let (execution, calls) =
        supervise_counted_failed_attempt(request(DeadlineScope::Attempt), transport_failure())
            .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(execution.attempts().total, 1);
    assert_eq!(execution.targets_authorized(), 0);
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert!(execution.deadline().is_none());
    let attempt = execution.attempts().records().next().unwrap();
    assert!(attempt.outcome.is_none());
    assert!(!attempt.launch.target_released);
    assert!(
        !attempt
            .restart_safety
            .is_safe_for(BoundaryRequirement::Sealed)
    );
    assert!(attempt.error.as_ref().unwrap().workload_may_be_alive);
}
