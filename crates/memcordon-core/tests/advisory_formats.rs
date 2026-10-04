use memcordon_core::{
    BoundaryClass, BoundaryRequirement, CapabilityStatusReport, DoctorReport, HostReport,
    RequestedPolicyReport, RequestedRestartPolicyReport, RequirementReport, RestartConditions,
    RestartLimit, ToolReport,
    result_v1::{CapabilitiesV1, OperationalBackendV1, PlanV1},
    workload_discovery::DiscoveryReportV1,
    workload_evidence::{BaselineRestrictionObservationV1, RuntimeWorkloadResolution},
};

fn plan() -> PlanV1 {
    PlanV1 {
        format: "memcordon.plan".into(),
        revision: 1,
        tool: ToolReport {
            name: "memcordon".into(),
            version: "0.5.7-dev".into(),
        },
        requested: RequestedPolicyReport {
            workload: Default::default(),
            boundary: BoundaryRequirement::Standard,
            memory: None,
            deadline: None,
            wait_for: "command".into(),
            signal_grace_ms: 2000,
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
        workload: RuntimeWorkloadResolution::LegacyUnspecified {
            restrictions: BaselineRestrictionObservationV1::UnmanagedStandardBackend,
        },
        private_plan: None,
        backend: OperationalBackendV1 {
            name: "ordinary".into(),
            containment: CapabilityStatusReport {
                supported: true,
                reason: None,
            },
            boundary: BoundaryClass::Standard,
            memory: None,
            deadline: CapabilityStatusReport {
                supported: true,
                reason: None,
            },
            limitations: vec![],
        },
        applied_memory: None,
        applied_deadline: None,
        limitations: vec![],
        pending_steps: vec!["create-owned-target".into()],
        authorizes_launch: false,
    }
}

fn capabilities() -> CapabilitiesV1 {
    CapabilitiesV1::from(&DoctorReport {
        schema_version: 6,
        tool: plan().tool,
        host: HostReport {
            os: "linux".into(),
            architecture: "x86_64".into(),
        },
        selected: None,
        available: vec![],
        unavailable: vec![],
        requirement: RequirementReport {
            kind: None,
            met: true,
            reason: None,
            workload: None,
        },
        workload_discovery: DiscoveryReportV1::Unsupported,
    })
}

fn private_plan() -> memcordon_core::private_runtime::PrivateRuntimePlan {
    use memcordon_core::{
        BoundedText, DiagnosticSha256, PublicProviderBindingV1,
        workload_contract::WorkloadContractV2, workload_registry_v2::ProfileKindV2,
    };
    let mut request = WorkloadContractV2::parse(include_bytes!(
        "../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))
    .unwrap();
    request.authorized_profile = ProfileKindV2::LinuxTcp4PrivateV1.reference();
    request.ceiling = ProfileKindV2::LinuxTcp4PrivateV1.ceiling();
    request.requirements = Default::default();
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    memcordon_core::private_runtime::PrivateRuntimePlan {
        format: "memcordon.private-runtime-plan".into(),
        revision: 1,
        provider: PublicProviderBindingV1 {
            generation: BoundedText::new(&format!("0.5.7-dev:{source}")).unwrap(),
            source_commit: BoundedText::new(source).unwrap(),
            runtime_manifest_sha256: DiagnosticSha256::from_bytes([7; 32]),
        },
        request_sha256: memcordon_core::workload_codec::contract_digest_v2(&request).unwrap(),
        request,
        available_for_preparation: true,
        conflicts: None,
        pending: vec!["authenticate-live-caller".into()],
        authorizes_launch: false,
    }
}

#[test]
fn named_advisory_formats_require_exact_namespace_revision_and_false_authority() {
    let original = plan();
    let bytes = serde_json::to_vec(&original).unwrap();
    PlanV1::parse(&bytes).unwrap();
    for (field, replacement) in [
        ("format", serde_json::json!("memcordon.result")),
        ("revision", serde_json::json!(2)),
        ("authorizes_launch", serde_json::json!(true)),
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = replacement;
        assert!(PlanV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let original = capabilities();
    CapabilitiesV1::parse(&serde_json::to_vec(&original).unwrap()).unwrap();
    for (field, replacement) in [
        ("format", serde_json::json!("memcordon.plan")),
        ("revision", serde_json::json!(2)),
        ("authorizes_launch", serde_json::json!(true)),
        ("request_versions", serde_json::json!([1, 1])),
        ("request_versions", serde_json::json!([1, 2])),
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[field] = replacement;
        assert!(CapabilitiesV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn advisory_parsers_reject_duplicates_nested_unknown_fields_and_oversize() {
    let mut bytes = serde_json::to_vec(&plan()).unwrap();
    bytes.pop();
    bytes.extend(b",\"revision\":1}");
    assert!(PlanV1::parse(&bytes).is_err());
    let mut value = serde_json::to_value(plan()).unwrap();
    value["requested"]["qualification_digest"] = serde_json::json!("saved approval");
    assert!(PlanV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(capabilities()).unwrap();
    value["requirement"]["permission"] = serde_json::json!(true);
    assert!(CapabilitiesV1::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let oversized = vec![b' '; memcordon_core::result_v1::RESULT_MAX_BYTES + 1];
    assert!(PlanV1::parse(&oversized).is_err());
    assert!(CapabilitiesV1::parse(&oversized).is_err());
}

#[test]
fn private_advisory_plan_keeps_full_request_and_rejects_false_correlations() {
    let mut plan = plan();
    plan.requested.boundary = BoundaryRequirement::Sealed;
    plan.backend.boundary = BoundaryClass::Sealed;
    plan.private_plan = Some(private_plan());
    let decoded = PlanV1::parse(&serde_json::to_vec(&plan).unwrap()).unwrap();
    assert_eq!(
        decoded.private_plan.unwrap().request,
        plan.private_plan.as_ref().unwrap().request
    );
    let mut wrong = plan.clone();
    wrong
        .private_plan
        .as_mut()
        .unwrap()
        .request
        .expected_epoch
        .revision = std::num::NonZeroU64::new(2).unwrap();
    assert!(wrong.validate().is_err());
    let mut wrong = plan.clone();
    wrong.private_plan.as_mut().unwrap().authorizes_launch = true;
    assert!(wrong.validate().is_err());
    let mut wrong = plan.clone();
    wrong
        .private_plan
        .as_mut()
        .unwrap()
        .available_for_preparation = false;
    assert!(wrong.validate().is_err());
    let mut wrong = plan;
    wrong.requested.boundary = BoundaryRequirement::Standard;
    assert!(wrong.validate().is_err());
    let mut capabilities = capabilities();
    capabilities.private_plan = Some(private_plan());
    capabilities.requirement.kind = Some("sealed".into());
    capabilities.request_versions = vec![1, 2];
    CapabilitiesV1::parse(&serde_json::to_vec(&capabilities).unwrap()).unwrap();
    capabilities.request_versions = vec![1];
    assert!(capabilities.validate().is_err());
}
