use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};

use memcordon_core::workload_admission_v2::{AttemptBindingV2, ProviderAdmissionSnapshotV2};
use memcordon_core::workload_contract::*;
use memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2;
use memcordon_core::workload_registry::{CallerSelector, GrantChangeDisposition};
use memcordon_core::workload_registry_v2::*;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}
fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn authority() -> (PolicyRegistryV2, WorkloadContractV2) {
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
        .try_push(ProfileDefinitionV2 {
            profile,
            reference: profile.reference(),
            enabled: true,
            qualification_digest: digest(3),
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
    let registry = PolicyRegistryV2 {
        schema_version: ContractVersionTwo::default(),
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

fn frozen() -> (PolicyRegistryV2, ProviderAdmissionSnapshotV2) {
    let (registry, request) = authority();
    let snapshot = ProviderAdmissionSnapshotV2::freeze(
        &registry,
        &request.expected_epoch,
        &request,
        &CallerSelector::Linux { uid: 1000 },
        digest(3),
        digest(6),
        QualifiedNativeAbiV2::X86_64LinuxGnu,
        Nonce128([7; 16]),
        Nonce128([8; 16]),
        digest(9),
        digest(10),
    )
    .unwrap();
    (registry, snapshot)
}

#[test]
fn frozen_v2_authority_binds_exact_registry_identity_and_attempt() {
    let (registry, snapshot) = frozen();
    snapshot.validate_against(&registry).unwrap();
    let parsed =
        ProviderAdmissionSnapshotV2::parse(&serde_json::to_vec(&snapshot).unwrap()).unwrap();
    assert_eq!(
        parsed.canonical_digest().unwrap(),
        snapshot.canonical_digest().unwrap()
    );
    let binding =
        AttemptBindingV2::from_admission(BoundedText::new("attempt-1").unwrap(), &snapshot)
            .unwrap();
    assert!(binding.matches_admission(&snapshot));
    let mut changed = snapshot.clone();
    changed.native_invocation_digest = digest(11);
    assert!(!binding.matches_admission(&changed));
    let mut changed = snapshot.clone();
    changed.identity.uid = NonZeroU32::new(2001).unwrap();
    assert!(changed.validate().is_err());
    let mut changed = snapshot.clone();
    changed.package_generation_digest = digest(12);
    assert_ne!(
        changed.canonical_digest().unwrap(),
        snapshot.canonical_digest().unwrap()
    );
    let mut changed_registry = registry.clone();
    let mut disabled = changed_registry.grants.as_slice()[0].clone();
    disabled.enabled = false;
    changed_registry.grants = BoundedVec::default();
    changed_registry.grants.try_push(disabled).unwrap();
    assert!(snapshot.validate_against(&changed_registry).is_err());
}

#[test]
fn frozen_v2_decoder_rejects_duplicate_unknown_and_oversized_bytes() {
    let (_, snapshot) = frozen();
    let bytes = serde_json::to_vec(&snapshot).unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen("{", "{\"request_digest\":\"bad\",", 1);
    assert!(ProviderAdmissionSnapshotV2::parse(duplicate.as_bytes()).is_err());
    let unknown = text.replacen("{", "{\"surprise\":true,", 1);
    assert!(ProviderAdmissionSnapshotV2::parse(unknown.as_bytes()).is_err());
    assert!(
        ProviderAdmissionSnapshotV2::parse(&vec![
            b' ';
            memcordon_core::workload_limits::REGISTRY_BYTES
                + 1
        ])
        .is_err()
    );
}

#[test]
fn frozen_v2_rejects_authority_substitution() {
    let (registry, snapshot) = frozen();
    let mut changed = snapshot.clone();
    changed.epoch.revision = NonZeroU64::new(2).unwrap();
    assert!(changed.validate().is_err());

    let mut changed = snapshot.clone();
    changed.caller = CallerSelector::Linux { uid: 1001 };
    assert!(changed.validate().is_err());

    let mut changed = snapshot.clone();
    changed.profile.qualification_digest = digest(99);
    assert!(changed.validate().is_err());

    let mut changed = snapshot.clone();
    changed.grant.enabled = false;
    assert!(changed.validate().is_err());

    let mut changed = snapshot.clone();
    changed.request.workload_plan_digest = digest(99);
    assert!(changed.validate().is_err());

    let mut changed = snapshot.clone();
    changed.registry_digest = digest(99);
    assert!(changed.validate_against(&registry).is_err());

    let mut changed = snapshot.clone();
    changed.native_abi = QualifiedNativeAbiV2::Aarch64LinuxGnu;
    assert_ne!(
        changed.canonical_digest().unwrap(),
        snapshot.canonical_digest().unwrap()
    );

    let mut changed = snapshot.clone();
    changed.admission_nonce = Nonce128([99; 16]);
    assert_ne!(
        changed.canonical_digest().unwrap(),
        snapshot.canonical_digest().unwrap()
    );

    let mut changed = snapshot.clone();
    changed.caller_envelope_digest = digest(99);
    assert_ne!(
        changed.canonical_digest().unwrap(),
        snapshot.canonical_digest().unwrap()
    );
}

#[test]
fn candidate_decision_uses_production_predicate_without_freezing_authority() {
    let (registry, request) = authority();
    let caller = CallerSelector::Linux { uid: 1000 };
    let decide =
        |request: &WorkloadContractV2, caller: &CallerSelector, digest: &DiagnosticSha256| {
            evaluate_candidate_policy_v2(
                &registry,
                &request.expected_epoch,
                request,
                caller,
                ProfileKindV2::LinuxTcp4PrivateV1,
                digest,
            )
        };
    assert_eq!(
        decide(&request, &caller, &digest(3)),
        CandidatePolicyDecisionV2::Accepted
    );

    let mut wrong_grant = request.clone();
    wrong_grant.authorization.grant_id = id("other-grant");
    assert_eq!(
        decide(&wrong_grant, &caller, &digest(3)),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::ProfileNotAuthorized
        ))
    );

    let mut unapproved_plan = request.clone();
    unapproved_plan.workload_plan_digest = digest(44);
    unapproved_plan.authorization.approved_plan_digest = digest(44);
    assert!(unapproved_plan.validate().is_ok());
    assert_eq!(
        decide(&unapproved_plan, &caller, &digest(3)),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::PlanNotApproved
        ))
    );

    let mut wrong_profile = request.clone();
    wrong_profile.authorized_profile = ProfileKindV2::LinuxUnixCreateV1.reference();
    assert_eq!(
        decide(&wrong_profile, &caller, &digest(3)),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::ProfileDigestMismatch
        ))
    );

    assert_eq!(
        decide(&request, &caller, &digest(99)),
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
            &digest(3),
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
    assert!(
        memcordon_core::private_release_branch_v1::one_policy_port_changed(
            &request,
            &unapproved_changed_plan
        )
    );
    assert_eq!(
        decide(&unapproved_changed_plan),
        CandidatePolicyDecisionV2::Rejected(AdmissionRejectionV2::single(
            AdmissionCodeV2::PlanNotApproved
        ))
    );
    let mut frozen = ProviderAdmissionSnapshotV2::freeze(
        &registry,
        &request.expected_epoch,
        &request,
        &caller,
        digest(3),
        digest(6),
        QualifiedNativeAbiV2::X86_64LinuxGnu,
        Nonce128([7; 16]),
        Nonce128([8; 16]),
        digest(9),
        digest(10),
    )
    .unwrap();
    frozen.request = changed;
    assert!(frozen.validate_against(&registry).is_err());
}
