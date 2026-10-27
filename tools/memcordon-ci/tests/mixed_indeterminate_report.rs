use memcordon_core::result_v2::*;
use memcordon_core::workload_contract::{AuthorizationRef, LogicalId, Nonce128, PolicyEpoch};
use memcordon_core::workload_contract_v3::*;
use memcordon_core::*;
use memcordon_platform::{
    BackendInfo, BoundaryReadiness, BoundarySupport, SealedAvailability, SupervisorRequest,
    test_support,
};
use std::{ffi::OsStr, num::NonZeroU64, time::Duration};

const ORIGINAL_EXPORT_CAUSE: &str = concat!(
    "retire mixed native execution: ",
    "export mixed private root: ",
    "export selected private root outputs: ",
    "openat2 selected output work/exported.bin from writable mount work: Too many levels of symbolic links (os error 40)"
);

fn id(text: &str) -> LogicalId {
    LogicalId::new(text.into()).unwrap()
}
fn object(text: &str, marker: u8) -> BoundObjectRef {
    BoundObjectRef {
        id: id(text),
        digest: DiagnosticSha256::from_bytes([marker; 32]),
    }
}
fn contract() -> WorkloadContractV3 {
    WorkloadContractV3 {
        schema_version: ContractVersionThree::default(),
        workload_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        authorized_profile: memcordon_core::workload_registry_v3::profile_reference(),
        authorization: AuthorizationRef {
            grant_id: id("mixed-report-regression"),
            grant_revision: NonZeroU64::new(1).unwrap(),
            approved_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        },
        ceiling: MixedPrivateCeiling::FreshRootIpv4TcpUnixStreamsIntraAttemptNoGain,
        requirements: BoundedVec::default(),
        execution_identity: ExclusiveAdministratorIdentityRef {
            identity: object("account", 3),
            exclusive_use_policy: object("exclusive", 4),
        },
        runtime_image: object("runtime", 5),
        input_image: object("input", 6),
        root_layout: object("root", 7),
        launch: ImageLaunchV1 {
            entrypoint: id("entry"),
            working_directory: RootRelativePath::new("work".into()).unwrap(),
        },
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([8; 16]),
            revision: NonZeroU64::new(1).unwrap(),
        },
    }
}
fn native(
    contract: &WorkloadContractV3,
    knowledge: MixedAuthorizationKnowledgeV2,
) -> MixedRuntimeExecutionV2 {
    let mut obligations = BoundedVec::default();
    obligations
        .try_push(BoundedText::new(ORIGINAL_EXPORT_CAUSE).unwrap())
        .unwrap();
    MixedRuntimeExecutionV2 {
        runtime: MixedRuntimeCarrierV2 {
            kind: "linux-mixed-private".into(),
            carrier_revision: 2,
            provider_contract: 4,
            launch_wire: 4,
            outcome: MixedRuntimeOutcomeV2::Indeterminate {
                attempt_id: BoundedText::new("0123456789abcdef0123456789abcdef").unwrap(),
                request_sha256: contract.digest().unwrap(),
                retained_obligations: OutstandingMixedRetirementV2 {
                    authorization: knowledge,
                    obligations,
                },
            },
        },
        frontend: MixedFrontendEvidenceV2 {
            relay_drained: true,
            interruption: None,
            relay_error: None,
            observation_error: None,
        },
    }
}
fn capability() -> BoundaryCapability {
    BoundaryCapability {
        class: BoundaryClass::Sealed,
        mechanism: PROFILE.into(),
        target_gated: true,
        boundary_verified_before_authorization: true,
        target_can_reconfigure_boundary: false,
        frontend_loss_cleanup_authority: true,
        workload_empty_proof: true,
        limitations: vec![],
    }
}
fn backend() -> BackendInfo {
    BackendInfo {
        name: "mixed-regression",
        containment_supported: true,
        memory_supported: false,
        class: "sealed",
        metric: "fixture",
        hard_limit: false,
        startup_containment: "fixture",
        limitations: vec![],
        boundary_support: BoundarySupport {
            standard: BoundaryCapability::default(),
            sealed: SealedAvailability::Available {
                capability: capability(),
                observation: BoundaryReadiness {
                    provider_identity: "fixture".into(),
                    mechanism: PROFILE.into(),
                },
            },
        },
    }
}
fn policy(contract: &WorkloadContractV3) -> Policy {
    Policy::default()
        .with_boundary(BoundaryRequirement::Sealed)
        .with_deadline(Duration::from_secs(1))
        .unwrap()
        .with_mixed_workload_contract(contract.clone())
        .unwrap()
}
fn request(contract: &WorkloadContractV3) -> SupervisorRequest {
    SupervisorRequest {
        policy: policy(contract),
        restart: RestartPolicy::OnLimits(
            RestartSettings::new(
                RestartConditions::DEADLINE,
                RestartConditions::DEADLINE,
                vec![],
                RestartLimit::Unlimited,
                HalfLifeLogisticBackoffPolicy::default(),
                None,
            )
            .unwrap(),
        ),
        command: CommandSpec::new("mixed-report-fixture"),
        memcordon_executable: None,
        resolved_backend: Some(memcordon_platform::capabilities_for(
            &backend(),
            BoundaryRequirement::Sealed,
        )),
    }
}

fn report(execution: SupervisionExecution) -> MemcordonReport {
    let deadline = DeadlinePolicyReport {
        duration_ms: 1000,
        scope: DeadlineScope::Attempt,
        origin: None,
        clock: "rust-instant".into(),
    };
    let envelope = PolicyEnvelopeReport {
        requested: RequestedPolicyReport {
            workload: Default::default(),
            boundary: BoundaryRequirement::Sealed,
            memory: None,
            deadline: Some(deadline.clone()),
            wait_for: "command".into(),
            signal_grace_ms: 2000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: RequestedRestartPolicyReport {
                enabled: true,
                enablement_source: Some("regression".into()),
                configured_conditions: RestartConditions::DEADLINE,
                limit: RestartLimit::Unlimited,
                backoff: Some(BackoffPolicyReport {
                    model: "half-life-logistic-v1".into(),
                    base_interval_ms: 250,
                    multiplier_numerator: 4,
                    multiplier_denominator: 1,
                    asymptote_interval_ms: 900000,
                    recovery_half_life_ms: 900000,
                    quantization: "ceil-whole-milliseconds".into(),
                }),
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
            deadline: Some(DeadlinePolicyReport {
                origin: Some("regression".into()),
                ..deadline
            }),
            wait_for: "command".into(),
            signal_grace_ms: 2000,
            command_exit_grace_ms: 0,
            limit_grace_ms: 0,
            restart: EffectiveRestartPolicyReport {
                enabled: true,
                conditions: RestartConditions::DEADLINE,
                dormant_conditions: vec![],
                cleanup_proof_required: true,
            },
        },
        effects: vec![],
    };
    let backend = execution.backend().clone();
    MemcordonReport::schema10(
        ToolReport {
            name: "memcordon".into(),
            version: "regression".into(),
        },
        InvocationReport {
            syntax: "plus-budgets-v1".into(),
            budget_tokens: vec![BudgetTokenReport {
                kind: BudgetKindReport::Time,
                token: "+1s".into(),
            }],
            memory_token: None,
            deadline_token: Some("+1s".into()),
            argv: vec![NativeArgument::from_os(OsStr::new("mixed-report-fixture"))],
        },
        envelope,
        Some(backend),
        Some(execution),
        None,
    )
    .unwrap()
}
fn tool() -> memcordon_core::result_v1::OperationalToolV1 {
    memcordon_core::result_v1::OperationalToolV1 {
        name: "memcordon".into(),
        version: "regression".into(),
        os: std::env::consts::OS.into(),
        architecture: std::env::consts::ARCH.into(),
        runtime_features: vec!["sealed-runtime".into()],
    }
}

#[test]
fn authenticated_authorized_indeterminate_survives_actual_supervision_factory_parser_and_export_validator()
 {
    let contract = contract();
    contract.validate().unwrap();
    let native = native(&contract, MixedAuthorizationKnowledgeV2::Authorized);
    let projected =
        test_support::project_mixed_indeterminate(&contract, native.clone(), backend()).unwrap();
    assert!(
        projected.child_pid.is_none()
            && projected.authorization_offset.is_none()
            && projected.runtime.is_none()
    );
    let configured = request(&contract);
    assert!(matches!(configured.restart, RestartPolicy::OnLimits(_)));
    let (execution, calls) =
        test_support::supervise_backend_execution(configured, projected).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert_eq!(execution.targets_authorized(), 1);
    assert_eq!(execution.restart().restarts_launched(), 0);
    assert_eq!(execution.attempts().records().count(), 1);
    let attempt = execution.attempts().records().next().unwrap();
    assert!(
        attempt.target_pid.is_none()
            && attempt.authorized_offset_ms.is_none()
            && attempt.runtime.is_none()
    );
    assert!(!attempt.restart_safety.is_safe());
    let report = report(execution);
    let result = ResultV2::from_legacy(&report, tool(), 125).unwrap();
    assert_eq!(result.runtime, native.runtime);
    assert_eq!(result.frontend, native.frontend);
    let encoded = serde_json::to_vec(&result).unwrap();
    let parsed = ResultV2::parse(&encoded).unwrap();
    assert_eq!(parsed.runtime, native.runtime);
    assert!(
        memcordon_readiness_verifier::validate_linux_export_outcome(
            "symlink",
            &serde_json::to_value(&parsed).unwrap(),
            "0123456789abcdef0123456789abcdef",
            &String::from(contract.digest().unwrap()),
            125
        )
        .is_ok()
    );
}

#[test]
fn never_and_unknown_authorization_remain_distinct_without_pid_clock_or_restart() {
    let contract = contract();
    for knowledge in [
        MixedAuthorizationKnowledgeV2::NeverAuthorized,
        MixedAuthorizationKnowledgeV2::Unknown,
    ] {
        let is_unknown = matches!(knowledge, MixedAuthorizationKnowledgeV2::Unknown);
        let native = native(&contract, knowledge);
        let projected =
            test_support::project_mixed_indeterminate(&contract, native.clone(), backend())
                .unwrap();
        assert!(!projected.launch.target_released);
        let (execution, calls) =
            test_support::supervise_backend_execution(request(&contract), projected).unwrap();
        assert_eq!(calls, 1);
        assert_eq!(execution.targets_authorized(), 0);
        assert_eq!(execution.wrapper_exit_code(), 125);
        assert_eq!(execution.restart().restarts_launched(), 0);
        assert_eq!(
            execution.aggregates().unknown_authorization_attempts,
            u64::from(is_unknown)
        );
        let result = ResultV2::from_legacy(&report(execution), tool(), 125).unwrap();
        assert_eq!(result.runtime, native.runtime);
        assert!(
            memcordon_readiness_verifier::validate_linux_export_outcome(
                "symlink",
                &serde_json::to_value(result).unwrap(),
                "0123456789abcdef0123456789abcdef",
                &String::from(contract.digest().unwrap()),
                125
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_or_inconsistent_projections_never_enter_history_or_forge_a_result() {
    let contract = contract();
    let native = native(&contract, MixedAuthorizationKnowledgeV2::Authorized);
    let original =
        test_support::project_mixed_indeterminate(&contract, native.clone(), backend()).unwrap();
    let mut malformed = native.clone();
    malformed.runtime.carrier_revision = 1;
    assert!(test_support::project_mixed_indeterminate(&contract, malformed, backend()).is_err());
    let mut mismatch = contract.clone();
    mismatch.runtime_image = object("different-runtime", 99);
    assert!(
        test_support::project_mixed_indeterminate(&mismatch, native.clone(), backend()).is_err()
    );
    assert!(test_support::validate_backend_execution(&original, &policy(&mismatch)).is_err());
    let mut wrong_backend = backend();
    if let SealedAvailability::Available { capability, .. } =
        &mut wrong_backend.boundary_support.sealed
    {
        capability.mechanism = "different-qualified-profile".into();
    }
    assert!(
        test_support::project_mixed_indeterminate(&contract, native.clone(), wrong_backend)
            .is_err()
    );
    let mut candidates = Vec::new();
    let mut changed = original.clone();
    changed.launch.target_released = false;
    candidates.push(changed);
    let mut changed = original.clone();
    changed.child_pid = std::num::NonZeroU32::new(42);
    candidates.push(changed);
    let mut changed = original.clone();
    changed.authorization_offset = Some(Duration::ZERO);
    candidates.push(changed);
    let mut changed = original.clone();
    changed.runtime = Some(RuntimeEvidenceV1 {
        schema_version: 1,
        clock: ClockDomain::DarwinContinuousTicksV1 {
            boot_identity: "unrelated-runtime".into(),
            ticks_per_second: 1,
        },
        run_origin: 0,
        attempt_origin: 0,
        work_expires: None,
        startup_expires: 1,
        release: ReleaseEvidence::Unknown,
        target_pid: None,
        terminal_observed: None,
        force_requested: None,
        force_expires: None,
        retirement_expires: None,
        delivery_expires: None,
        retirement: RetirementEvidence::Unconfirmed { last_owner: None },
        delivery: DeliveryEvidence::Unknown,
    });
    candidates.push(changed);
    let mut changed = original.clone();
    if let RunOutcome::MonitorFailed { cleanup, .. } = &mut changed.outcome {
        cleanup.direct_child_reaped = true;
        cleanup.workload_empty = Some(true);
    }
    candidates.push(changed);
    let mut changed = original.clone();
    if let BoundaryMechanismEvidence::LinuxMixedPrivate(native) = &mut changed.boundary_detail {
        native.runtime.provider_contract = 0;
    }
    candidates.push(changed);
    let mut changed = original.clone();
    changed.restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: vec![],
    };
    candidates.push(changed);
    let mut changed = original.clone();
    changed.outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: CleanupSummary::default(),
    };
    candidates.push(changed);
    for changed in candidates {
        assert!(test_support::validate_backend_execution(&changed, &policy(&contract)).is_err());
    }
    let mut generic = original.clone();
    generic.launch = LaunchEvidence {
        mechanism: "fixture-standard".into(),
        target_released: true,
        containment_verified_before_authorization: true,
        boundary_requested: BoundaryRequirement::Standard,
        boundary_effective: BoundaryClass::Standard,
        ..LaunchEvidence::default()
    };
    generic.boundary_detail = BoundaryMechanismEvidence::Standard {
        backend: "fixture-standard".into(),
    };
    generic.child_pid = std::num::NonZeroU32::new(42);
    generic.authorization_offset = Some(Duration::ZERO);
    generic.outcome = RunOutcome::Exited {
        child: ChildTermination::ExitCode { code: 0 },
        peak: None,
        cleanup: CleanupSummary {
            direct_child_reaped: true,
            workload_empty: Some(true),
            ..CleanupSummary::default()
        },
    };
    generic.restart_safety = RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        ..RestartSafetyProof::default()
    };
    let ordinary_policy = Policy::default();
    test_support::validate_backend_execution(&generic, &ordinary_policy).unwrap();
    let mut missing_clock = generic.clone();
    missing_clock.authorization_offset = None;
    assert_eq!(
        test_support::validate_backend_execution(&missing_clock, &ordinary_policy)
            .unwrap_err()
            .code,
        "MCRESTART-AUTHORIZATION-EVIDENCE"
    );
    let mut missing_pid = generic;
    missing_pid.child_pid = None;
    assert_eq!(
        test_support::validate_backend_execution(&missing_pid, &ordinary_policy)
            .unwrap_err()
            .code,
        "MCRESTART-AUTHORIZATION-EVIDENCE"
    );
}

#[test]
fn bare_obligation_is_retained_but_never_substituted_for_the_original_export_context() {
    let contract = contract();
    let mut native = native(&contract, MixedAuthorizationKnowledgeV2::Authorized);
    let detail = "Too many levels of symbolic links (os error 40)";
    if let MixedRuntimeOutcomeV2::Indeterminate {
        retained_obligations,
        ..
    } = &mut native.runtime.outcome
    {
        retained_obligations.obligations = BoundedVec::default();
        retained_obligations
            .obligations
            .try_push(BoundedText::new(detail).unwrap())
            .unwrap();
    }
    let projected =
        test_support::project_mixed_indeterminate(&contract, native.clone(), backend()).unwrap();
    let (execution, calls) =
        test_support::supervise_backend_execution(request(&contract), projected).unwrap();
    assert_eq!(calls, 1);
    let report = report(execution);
    let result = ResultV2::from_legacy(&report, tool(), 125).unwrap();
    let parsed = ResultV2::parse(&serde_json::to_vec(&result).unwrap()).unwrap();
    assert_eq!(parsed.runtime, native.runtime);
    assert!(
        memcordon_readiness_verifier::validate_linux_export_outcome(
            "symlink",
            &serde_json::to_value(&parsed).unwrap(),
            "0123456789abcdef0123456789abcdef",
            &String::from(contract.digest().unwrap()),
            125
        )
        .is_err()
    );
    let mut missing = report.clone();
    missing.attempts.clear();
    assert!(ResultV2::from_legacy(&missing, tool(), 125).is_err());
    let mut malformed = report;
    if let BoundaryMechanismEvidence::LinuxMixedPrivate(native) =
        &mut malformed.attempts.last_mut().unwrap().boundary_detail
    {
        native.runtime.launch_wire = 0;
    }
    assert!(ResultV2::from_legacy(&malformed, tool(), 125).is_err());
}

#[test]
fn original_frontend_errors_and_uncertainty_survive_without_cleanup_or_restart_promotion() {
    let contract = contract();
    let mut native = native(&contract, MixedAuthorizationKnowledgeV2::Authorized);
    native.frontend.relay_drained = false;
    native.frontend.relay_error = Some(BoundedText::new("original relay failure").unwrap());
    native.frontend.observation_error =
        Some(BoundedText::new("original observation unavailable").unwrap());
    native.frontend.interruption = Some(2);
    let projected =
        test_support::project_mixed_indeterminate(&contract, native.clone(), backend()).unwrap();
    assert_eq!(
        projected.outcome.cleanup().errors[0].message,
        "original relay failure"
    );
    assert_eq!(
        projected.outcome.cleanup().errors[1].message,
        "original observation unavailable"
    );
    let (execution, calls) =
        test_support::supervise_backend_execution(request(&contract), projected).unwrap();
    assert_eq!(calls, 1);
    assert_eq!(execution.wrapper_exit_code(), 125);
    assert_eq!(execution.restart().restarts_launched(), 0);
    let result = ResultV2::from_legacy(&report(execution), tool(), 125).unwrap();
    let parsed = ResultV2::parse(&serde_json::to_vec(&result).unwrap()).unwrap();
    assert_eq!(parsed.runtime, native.runtime);
    assert_eq!(parsed.frontend, native.frontend);
    assert!(
        memcordon_readiness_verifier::validate_linux_export_outcome(
            "symlink",
            &serde_json::to_value(parsed).unwrap(),
            "0123456789abcdef0123456789abcdef",
            &String::from(contract.digest().unwrap()),
            125
        )
        .is_err()
    );
}
