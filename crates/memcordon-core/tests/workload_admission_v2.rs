use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use memcordon_core::workload_admission_v2::AttemptBindingV2;
use memcordon_core::workload_contract::*;
use memcordon_core::workload_registry::{CallerSelector, GrantChangeDisposition};
use memcordon_core::workload_registry_v2::*;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}
fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn authority() -> (RuntimePrivatePolicyRegistry, WorkloadContractV2) {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let mut entrypoints = BoundedVec::default();
    entrypoints
        .try_push(ApprovedEntrypointV2 {
            id: id("approved"),
            absolute_path: BoundedText::new("/opt/approved").unwrap(),
            sha256: digest(2),
            size: NonZeroU64::new(1024).unwrap(),
        })
        .unwrap();
    let mut identity = LinuxExecutionIdentityV2 {
        reference: ExecutionIdentityRefV2 {
            id: id("candidate"),
            semantic_digest: digest(1),
        },
        enabled: true,
        uid: NonZeroU32::new(2000).unwrap(),
        gid: NonZeroU32::new(2000).unwrap(),
        supplementary_groups: BoundedVec::default(),
        entrypoints,
    };
    identity.reference.semantic_digest = identity.semantic_digest().unwrap();
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(RuntimePrivateProfileDefinition {
            profile,
            reference: profile.reference(),
            enabled: true,
        })
        .unwrap();
    let mut identities = BoundedVec::default();
    identities.try_push(identity.clone()).unwrap();
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut plans = BoundedVec::default();
    plans.try_push(digest(4)).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV2 {
            id: id("grant"),
            revision: NonZeroU64::MIN,
            profile: profile.reference(),
            ceiling: profile.ceiling(),
            enabled: true,
            callers,
            approved_plans: plans,
            execution_identity: ExecutionIdentityRequestV2::AdministratorProfile {
                reference: identity.reference.clone(),
            },
        })
        .unwrap();
    let registry = RuntimePrivatePolicyRegistry {
        format: "memcordon.local-private-policy".into(),
        revision: 1,
        profiles,
        execution_identities: identities,
        grants,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    let request = WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: digest(4),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: id("grant"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(4),
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([5; 16]),
            revision: NonZeroU64::MIN,
        },
        execution_identity: ExecutionIdentityRequestV2::AdministratorProfile {
            reference: identity.reference,
        },
    };
    (registry, request)
}

#[test]
fn candidate_decision_uses_production_predicate_without_freezing_authority() {
    let (registry, request) = authority();
    let caller = CallerSelector::Linux { uid: 1000 };
    let decide = |request: &WorkloadContractV2, caller: &CallerSelector| {
        evaluate_candidate_policy_v2(
            &registry,
            &request.expected_epoch,
            request,
            caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
        )
    };
    assert_eq!(
        decide(&request, &caller),
        CandidatePolicyDecisionV2::Accepted
    );

    let mut wrong_grant = request.clone();
    wrong_grant.authorization.grant_id = id("other-grant");
    assert_eq!(
        decide(&wrong_grant, &caller),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::ProfileNotAuthorized
        ))
    );

    let mut unapproved_plan = request.clone();
    unapproved_plan.workload_plan_digest = digest(44);
    unapproved_plan.authorization.approved_plan_digest = digest(44);
    assert!(unapproved_plan.validate().is_ok());
    assert_eq!(
        decide(&unapproved_plan, &caller),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::PlanNotApproved
        ))
    );

    let mut wrong_profile = request.clone();
    wrong_profile.authorized_profile = ProfileKindV2::LinuxUnixCreateV1.reference();
    assert_eq!(
        decide(&wrong_profile, &caller),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::ProfileDigestMismatch
        ))
    );

    assert_eq!(
        evaluate_candidate_policy_v2(
            &registry,
            &request.expected_epoch,
            &request,
            &caller,
            ProfileKindV2::LinuxUnixCreateV1,
        ),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::HostPrerequisiteUnavailable
        ))
    );
}

#[test]
fn port_only_change_with_unchanged_approved_labels_is_not_a_static_port_allowlist() {
    let (registry, mut request) = authority();
    let mut operations = BoundedVec::default();
    operations.try_push(TcpOperation::Create).unwrap();
    operations.try_push(TcpOperation::Connect).unwrap();
    request
        .requirements
        .try_push(RequirementV1::Tcp {
            id: RequirementId::new("client".into()).unwrap(),
            family: IpFamily::V4,
            operations: TcpOperations::new(operations).unwrap(),
            scope: TcpScope::AttemptPrivateStack,
            local_ports: LocalPortRequirement::KernelAssigned,
            peer: TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 {
                    address: [127, 0, 0, 1],
                    port: NonZeroU16::new(8080).unwrap(),
                },
            },
        })
        .unwrap();
    let caller = CallerSelector::Linux { uid: 1000 };
    let decide = |contract: &WorkloadContractV2| {
        evaluate_candidate_policy_v2(
            &registry,
            &contract.expected_epoch,
            contract,
            &caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
        )
    };
    assert_eq!(decide(&request), CandidatePolicyDecisionV2::Accepted);

    let mut changed = request.clone();
    let mut changed_requirement = changed.requirements.as_slice()[0].clone();
    let RequirementV1::Tcp {
        peer:
            TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 { port, .. },
            },
        ..
    } = &mut changed_requirement
    else {
        panic!("fixed test contract must retain its IPv4 endpoint");
    };
    *port = NonZeroU16::new(8081).unwrap();
    changed.requirements = BoundedVec::default();
    changed.requirements.try_push(changed_requirement).unwrap();
    assert_eq!(decide(&changed), CandidatePolicyDecisionV2::Accepted);
    assert_ne!(
        serde_json::to_vec(&request).unwrap(),
        serde_json::to_vec(&changed).unwrap()
    );
    // A reviewed changed-port plan must change both the plan identity and
    // its matching authorization label. The unchanged-label port probe above
    // remains accepted; this distinct plan is not approved by the grant.
    let mut unapproved_changed_plan = changed.clone();
    unapproved_changed_plan.workload_plan_digest = digest(44);
    unapproved_changed_plan.authorization.approved_plan_digest = digest(44);
    assert!(unapproved_changed_plan.validate().is_ok());
    assert!(memcordon_core::product_fixture::one_workload_port_changed(
        &request,
        &unapproved_changed_plan
    ));
    assert_eq!(
        decide(&unapproved_changed_plan),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::PlanNotApproved
        ))
    );
}

#[test]
fn raw_attempt_binding_preserves_independent_native_correlation_facts() {
    let binding = AttemptBindingV2 {
        attempt_id: BoundedText::new("attempt-1").unwrap(),
        admission_digest: digest(1),
        caller_envelope_digest: digest(2),
        native_invocation_digest: digest(3),
    };
    let original = binding.canonical_digest().unwrap();
    let mut changed = binding.clone();
    changed.attempt_id = BoundedText::new("attempt-2").unwrap();
    assert_ne!(changed.canonical_digest().unwrap(), original);
    for field in [0, 1, 2] {
        let mut changed = binding.clone();
        match field {
            0 => changed.admission_digest = digest(9),
            1 => changed.caller_envelope_digest = digest(9),
            2 => changed.native_invocation_digest = digest(9),
            _ => unreachable!(),
        }
        assert_ne!(changed.canonical_digest().unwrap(), original);
    }
}
