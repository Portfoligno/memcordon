use memcordon_core::{DeadlineScope, Error, ErrorCategory, RestartCondition, RestartSafetyProof};
use memcordon_platform::{BackendInfo, capabilities};
use std::time::Duration;

#[test]
fn capability_conversion_separates_lifecycle_and_memory_contracts() {
    let report = capabilities(&BackendInfo {
        name: "fixture",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "fixture-memory",
        hard_limit: true,
        startup_containment: "contained before authorization",
        limitations: vec!["fixture limitation"],
    });
    assert!(report.containment.supported);
    assert!(
        report
            .memory
            .as_ref()
            .is_some_and(|memory| memory.supported)
    );
    assert!(report.deadline.supported);
    assert!(report.restart.supported);
    assert_eq!(
        report.deadline_scopes,
        vec![DeadlineScope::Attempt, DeadlineScope::Supervision]
    );
    assert!(
        report
            .restart_conditions
            .contains(RestartCondition::MemoryLimit)
    );
    assert!(
        report
            .restart_conditions
            .contains(RestartCondition::Deadline)
    );
    assert!(!report.persistent_restart_state);
}

#[test]
fn categorized_errors_preserve_backend_restart_safety_evidence() {
    let proof = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        errors: Vec::new(),
    };
    let error = Error::new(ErrorCategory::Setup, "MCSETUP-FIXTURE", "fixture failure")
        .with_restart_safety(proof.clone());

    assert_eq!(error.restart_safety, Some(proof));
}

#[test]
fn authorization_evidence_preserves_the_exact_attempt_offset() {
    let offset = Duration::from_micros(12_345);
    let error = Error::new(ErrorCategory::Spawn, "MCSPAWN-FIXTURE", "fixture")
        .with_authorization_offset(offset);

    assert!(error.target_released);
    assert_eq!(error.authorization_offset, Some(offset));
}
