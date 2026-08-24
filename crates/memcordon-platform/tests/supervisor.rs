use memcordon_core::{
    BoundaryCapability, BoundaryClass, BoundaryRequirement, DeadlineScope, Error, ErrorCategory,
    RestartCondition, RestartSafetyProof,
};
use memcordon_platform::{
    BackendInfo, BoundaryQualification, BoundarySupport, ProbeReport, SealedAvailability,
    capabilities,
};
use std::time::Duration;

#[cfg(feature = "test-support")]
use memcordon_core::{
    BoundarySetupFailure, BoundarySetupPhase, DeadlinePolicy, Metric, Policy,
    ProviderRejectionEvidence,
};

#[cfg(feature = "test-support")]
use memcordon_platform::AttemptContext;

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

#[cfg(feature = "test-support")]
#[test]
fn backend_selection_allows_only_the_requested_watchdog_metric_difference() {
    let selected = capabilities(&BackendInfo {
        name: "macos-watchdog",
        containment_supported: true,
        memory_supported: true,
        class: "watchdog",
        metric: "physical-footprint-sum",
        hard_limit: false,
        startup_containment: "new process group established before target exec",
        limitations: vec!["sampled accounting"],
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Standard,
                mechanism: "process-group-pre-spawn".to_owned(),
                ..BoundaryCapability::default()
            },
            sealed: SealedAvailability::Unavailable {
                reason: "provider unavailable".to_owned(),
                prerequisites: Vec::new(),
            },
        },
    });

    for (metric, effective) in [
        (Metric::PhysicalFootprint, "physical-footprint-sum"),
        (Metric::Rss, "rss-sum"),
        (Metric::Virtual, "virtual-size-sum"),
    ] {
        let mut observed = selected.clone();
        observed.memory.as_mut().unwrap().metric = effective.to_owned();
        assert!(
            memcordon_platform::test_support::backend_selection_matches(
                &selected, &observed, metric,
            ),
            "requested metric {metric:?} should be an allowed effective difference"
        );

        observed.boundary.mechanism = "changed-boundary".to_owned();
        assert!(
            !memcordon_platform::test_support::backend_selection_matches(
                &selected, &observed, metric,
            ),
            "boundary drift must remain fail-closed"
        );

        let mut wrong_metric = selected.clone();
        wrong_metric.memory.as_mut().unwrap().metric = "wrong-metric".to_owned();
        assert!(
            !memcordon_platform::test_support::backend_selection_matches(
                &selected,
                &wrong_metric,
                metric,
            )
        );
    }

    let mut unrequested = selected.clone();
    unrequested.memory.as_mut().unwrap().metric = "virtual-size-sum".to_owned();
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &unrequested,
            Metric::Native,
        )
    );

    let mut renamed = selected.clone();
    renamed.name = "different-backend".to_owned();
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &renamed,
            Metric::Native,
        )
    );
}

#[cfg(feature = "test-support")]
#[test]
fn only_exact_retired_sealed_retry_deadline_rejection_is_outside_attempt() {
    let restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    };
    let rejection = ProviderRejectionEvidence {
        schema_version: 1,
        code: "MCSEALED-AUTHORIZATION".to_owned(),
        phase: BoundarySetupPhase::Authorization,
        detail: "authorization deadline elapsed before gate release".to_owned(),
        os_code: None,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: restart_safety.clone(),
    };
    let mut error = Error::new(
        ErrorCategory::Setup,
        "MCSEALED-PROVIDER-REJECTION",
        "provider rejected launch",
    )
    .with_boundary_setup_failure(BoundarySetupFailure {
        requested: BoundaryRequirement::Sealed,
        mechanism: Some("linux-pid-namespace-cgroup-v2".to_owned()),
        phase: BoundarySetupPhase::Authorization,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety,
    })
    .with_provider_rejection(rejection);
    error.launch_phase = Some("authorization");

    let mut supervision_policy = Policy::unbounded();
    supervision_policy.deadline =
        Some(DeadlinePolicy::new(Duration::from_secs(30), DeadlineScope::Supervision).unwrap());
    let retry = AttemptContext {
        supervision_offset: Duration::from_secs(25),
        supervision_deadline_remaining: Some(Duration::from_secs(5)),
    };
    assert!(
        memcordon_platform::test_support::sealed_deadline_rejection_is_outside_attempt(
            &supervision_policy,
            retry,
            &error,
        )
    );

    let initial = AttemptContext {
        supervision_offset: Duration::ZERO,
        supervision_deadline_remaining: None,
    };
    assert!(
        !memcordon_platform::test_support::sealed_deadline_rejection_is_outside_attempt(
            &supervision_policy,
            initial,
            &error,
        )
    );

    let mut unsafe_error = error.clone();
    unsafe_error
        .provider_rejection
        .as_mut()
        .unwrap()
        .restart_safety
        .sealed_boundary_retired = false;
    assert!(
        !memcordon_platform::test_support::sealed_deadline_rejection_is_outside_attempt(
            &supervision_policy,
            retry,
            &unsafe_error,
        )
    );

    let mut wrong_code = error;
    wrong_code.provider_rejection.as_mut().unwrap().code = "MCSEALED-TARGET".to_owned();
    assert!(
        !memcordon_platform::test_support::sealed_deadline_rejection_is_outside_attempt(
            &supervision_policy,
            retry,
            &wrong_code,
        )
    );
}

#[test]
fn boundary_selection_does_not_conflate_default_and_sealed_backends() {
    let standard = BackendInfo {
        name: "standard-fixture",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "fixture",
        hard_limit: true,
        startup_containment: "fixture",
        limitations: Vec::new(),
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Standard,
                mechanism: "fixture-standard".to_owned(),
                ..BoundaryCapability::default()
            },
            sealed: SealedAvailability::Unavailable {
                reason: "independent provider required".to_owned(),
                prerequisites: Vec::new(),
            },
        },
    };
    let sealed = BackendInfo {
        name: "sealed-fixture",
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Unavailable,
                ..BoundaryCapability::default()
            },
            sealed: SealedAvailability::Available {
                capability: BoundaryCapability {
                    class: BoundaryClass::Sealed,
                    mechanism: "fixture-sealed".to_owned(),
                    target_gated: true,
                    boundary_verified_before_authorization: true,
                    frontend_loss_cleanup_authority: true,
                    workload_empty_proof: true,
                    ..BoundaryCapability::default()
                },
                qualification: BoundaryQualification {
                    provider_identity: "fixture-provider".to_owned(),
                    receipt_digest: "ab".repeat(32),
                    mechanism: "fixture-sealed".to_owned(),
                },
            },
        },
        ..standard.clone()
    };
    let report = ProbeReport {
        selected: Some(standard.clone()),
        available: vec![standard, sealed],
        unavailable: Vec::new(),
    };
    assert_eq!(
        report
            .selected_for(BoundaryRequirement::Standard)
            .unwrap()
            .name,
        "standard-fixture"
    );
    assert_eq!(
        report
            .selected_for(BoundaryRequirement::Sealed)
            .unwrap()
            .name,
        "sealed-fixture"
    );
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
