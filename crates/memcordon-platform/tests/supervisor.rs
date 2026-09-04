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
fn post_attempt_backend_drift_retains_typed_runtime_evidence() {
    let selected = capabilities(&BackendInfo {
        name: "fixture",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "fixture-memory",
        hard_limit: true,
        startup_containment: "selected containment",
        limitations: vec!["selected limitation"],
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Standard,
                mechanism: "fixture-standard".to_owned(),
                ..BoundaryCapability::default()
            },
            sealed: SealedAvailability::Unavailable {
                reason: "provider unavailable".to_owned(),
                prerequisites: Vec::new(),
            },
        },
    });
    let mut observed = selected.clone();
    observed.startup_containment = "observed containment".to_owned();
    observed.boundary.mechanism = "observed-standard".to_owned();

    let execution = memcordon_platform::test_support::backend_selection_drift_execution(
        selected.clone(),
        observed.clone(),
        memcordon_core::Metric::Native,
    )
    .expect("post-attempt drift must remain a valid typed supervision execution");
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert_eq!(execution.targets_authorized(), 1);
    assert_eq!(execution.attempts().total, 1);
    assert_eq!(execution.aggregates().monitor_failures, 1);
    assert_eq!(execution.aggregates().setup_failures, 0);
    let attempt = execution
        .attempts()
        .records()
        .next()
        .expect("completed launch must retain one failed monitoring attempt");
    assert_eq!(attempt.target_pid, Some(42));
    assert!(attempt.authorized_offset_ms.is_some());
    assert!(attempt.terminal_offset_ms.is_some());
    assert!(attempt.restart_safety.is_safe());
    let error = attempt.error.as_ref().expect("drift must be typed");
    assert_eq!(error.code, "MCBACKEND-SELECTION-DRIFT");
    assert_eq!(error.attempt_number, Some(1));
    assert_eq!(
        error.supervision_phase,
        memcordon_core::SupervisionPhase::ActiveAttempt
    );
    assert!(error.target_released);
    assert!(!error.workload_may_be_alive);
    let drift = error
        .backend_selection_drift
        .as_ref()
        .expect("drift must retain selected and observed reports");
    assert_eq!(drift.selected.as_ref(), &selected);
    assert_eq!(drift.observed.as_ref(), &observed);
    assert_eq!(
        drift.mismatched_fields,
        vec!["boundary".to_owned(), "startup_containment".to_owned()]
    );
    assert!(drift.is_consistent());
    let encoded = serde_json::to_value(&execution).expect("drift execution must serialize");
    assert_eq!(
        encoded["terminal"]["error"]["backend_selection_drift"]["mismatched_fields"],
        serde_json::json!(["boundary", "startup_containment"])
    );
    assert_eq!(
        encoded["terminal"]["error"]["supervision_phase"],
        "active-attempt"
    );
    let _: memcordon_core::SupervisionExecution =
        serde_json::from_value(encoded.clone()).expect("typed drift execution must round trip");
    let mut inaccurate = encoded;
    inaccurate["terminal"]["error"]["backend_selection_drift"]["mismatched_fields"] =
        serde_json::json!(["startup_containment"]);
    inaccurate["attempts"]["first"]["error"]["backend_selection_drift"]["mismatched_fields"] =
        serde_json::json!(["startup_containment"]);
    assert!(
        serde_json::from_value::<memcordon_core::SupervisionExecution>(inaccurate).is_err(),
        "schema validation must reject incomplete drift field evidence"
    );
}

#[cfg(all(windows, feature = "test-support"))]
fn windows_qualification() -> memcordon_core::WindowsQualificationReceiptV1 {
    memcordon_core::WindowsQualificationReceiptV1 {
        schema_version: memcordon_core::WINDOWS_QUALIFICATION_SCHEMA_VERSION,
        provider_identity: format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        ),
        control_service_identity: "MemCordonSealedControl:LocalService:restricted".to_owned(),
        launcher_service_identity: "MemCordonSealedLauncher:LocalSystem:restricted".to_owned(),
        guardian_pool_identity: "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            .to_owned(),
        package_verified: true,
        public_pipe_security_verified: true,
        private_pipe_security_verified: true,
        control_service_privileges_verified: true,
        launcher_service_privileges_verified: true,
        guardian_slot_tokens_verified: true,
        guardian_slot_loader_verified: true,
        guardian_capacity_verified: true,
        caller_token_authentication_verified: true,
        restricted_caller_token_verified: true,
        primary_token_duplication_verified: true,
        create_process_as_user_verified: true,
        job_list_supported: true,
        handle_list_supported: true,
        nested_host_job_supported: true,
        kill_on_close_verified: true,
        breakaway_denied: true,
        completion_port_verified: true,
        guardian_verified: true,
        frontend_loss_cleanup_verified: true,
        alternate_token_child_contained: true,
        nested_child_job_contained: true,
        recursive_provider_request_denied: true,
        exact_handle_inheritance_verified: true,
        active_processes_zero_verified: true,
        relays_retired_verified: true,
        recovery_complete: true,
        loader_qualification: memcordon_core::WindowsLoaderQualificationOutcomeV2::Ready(
            memcordon_core::WindowsLoaderReadyEvidenceV1 {
                schema_version: 1,
                launch_plan_sha256:
                    "b0d52f6c6974566b7077fc0ff7c14f68aa640e5dff36d4cef3d916a616047995".to_owned(),
                launch_plan_json: None,
                elapsed_millis: 1,
            },
        ),
        qualified: true,
    }
}

#[cfg(all(windows, feature = "test-support"))]
#[test]
fn windows_sealed_preflight_and_runtime_capabilities_are_canonical_and_strict() {
    let qualification = windows_qualification();
    assert!(qualification.is_consistent());

    let selected = memcordon_platform::test_support::windows_preflight_backend_capabilities(
        qualification.clone(),
    );
    let observed =
        memcordon_platform::test_support::windows_runtime_backend_capabilities(qualification);
    assert_eq!(selected, observed);
    assert!(memcordon_platform::test_support::backend_selection_matches(
        &selected,
        &observed,
        Metric::Native,
    ));

    let boundary_qualification = selected
        .boundary_qualification
        .as_ref()
        .expect("qualified sealed capability must retain qualification data");
    assert_eq!(
        boundary_qualification.provider_identity,
        format!(
            "memcordon-sealed-agent-windows-v1:{}",
            env!("CARGO_PKG_VERSION")
        )
    );
    assert!(!boundary_qualification.receipt_digest.is_empty());
    assert_eq!(boundary_qualification.mechanism, "windows-job-object-v2");
    assert_eq!(selected.boundary.mechanism, "windows-job-object-v2");
    assert_eq!(
        selected.startup_containment,
        "target created suspended, assigned to Job Object, then resumed"
    );
    assert!(
        selected
            .boundary
            .limitations
            .iter()
            .any(|value| value.contains("provider-owned pipes"))
    );

    let mut startup_drift = observed.clone();
    startup_drift.startup_containment.push_str(" changed");
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &startup_drift,
            Metric::Native,
        )
    );

    let mut limitation_drift = observed.clone();
    limitation_drift
        .limitations
        .push("unobserved limitation".to_owned());
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &limitation_drift,
            Metric::Native,
        )
    );

    let mut boundary_drift = observed.clone();
    boundary_drift.boundary.mechanism = "changed-boundary".to_owned();
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &boundary_drift,
            Metric::Native,
        )
    );

    let mut qualification_drift = observed;
    qualification_drift
        .boundary_qualification
        .as_mut()
        .expect("observed sealed capability must retain qualification data")
        .receipt_digest
        .push('0');
    assert!(
        !memcordon_platform::test_support::backend_selection_matches(
            &selected,
            &qualification_drift,
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
        loader_qualification: None,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: restart_safety.clone(),
        terminal_ack_required: false,
        terminal_receipt: None,
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
