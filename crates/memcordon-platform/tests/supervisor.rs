use memcordon_core::{
    BoundaryCapability, BoundaryClass, BoundaryRequirement, DeadlineScope, Error, ErrorCategory,
    RestartCondition, RestartSafetyProof,
};
use memcordon_platform::{BackendInfo, BoundarySupport, SealedAvailability, capabilities};
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
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Standard,
                mechanism: "fixture-standard".to_owned(),
                target_gated: true,
                boundary_verified_before_authorization: true,
                target_can_reconfigure_boundary: true,
                frontend_loss_cleanup_authority: false,
                workload_empty_proof: true,
                limitations: vec!["not sealed".to_owned()],
            },
            sealed: SealedAvailability::Unavailable {
                reason: "fixture has no provider".to_owned(),
                prerequisites: vec!["qualified provider".to_owned()],
            },
        },
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
        sealed_boundary_retired: false,
        errors: Vec::new(),
    };
    let error = Error::new(ErrorCategory::Setup, "MCSETUP-FIXTURE", "fixture failure")
        .with_restart_safety(proof.clone());

    assert_eq!(error.restart_safety, Some(proof));
}

#[test]
fn sealed_capability_requires_every_normative_predicate() {
    let valid = BoundaryCapability {
        class: BoundaryClass::Sealed,
        mechanism: "fixture".to_owned(),
        target_gated: true,
        boundary_verified_before_authorization: true,
        target_can_reconfigure_boundary: false,
        frontend_loss_cleanup_authority: true,
        workload_empty_proof: true,
        limitations: Vec::new(),
    };
    assert!(valid.is_consistent());
    for invalid in [
        BoundaryCapability {
            target_gated: false,
            ..valid.clone()
        },
        BoundaryCapability {
            boundary_verified_before_authorization: false,
            ..valid.clone()
        },
        BoundaryCapability {
            target_can_reconfigure_boundary: true,
            ..valid.clone()
        },
        BoundaryCapability {
            frontend_loss_cleanup_authority: false,
            ..valid.clone()
        },
        BoundaryCapability {
            workload_empty_proof: false,
            ..valid
        },
    ] {
        assert!(!invalid.is_consistent());
    }
}

#[test]
fn sealed_restart_safety_requires_retirement() {
    let mut proof = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: false,
        sealed_boundary_retired: false,
        errors: Vec::new(),
    };
    assert!(proof.is_safe());
    assert!(!proof.is_safe_for(BoundaryRequirement::Sealed));
    proof.sealed_boundary_retired = true;
    assert!(proof.is_safe_for(BoundaryRequirement::Sealed));
}

#[test]
fn authorization_evidence_preserves_the_exact_attempt_offset() {
    let offset = Duration::from_micros(12_345);
    let error = Error::new(ErrorCategory::Spawn, "MCSPAWN-FIXTURE", "fixture")
        .with_authorization_offset(offset);

    assert!(error.target_released);
    assert_eq!(error.authorization_offset, Some(offset));
}
