use memcordon_core::workload_codec::{contract_digest_v2, decode_contract_v2, encode_contract_v2};
use memcordon_core::workload_contract::*;
use memcordon_core::workload_discovery_v2::*;
use memcordon_core::workload_registry::{BaselineProfile, CallerSelector, GrantChangeDisposition};
use memcordon_core::workload_registry_v2::*;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256, PublicProviderBindingV1};
use std::num::{NonZeroU32, NonZeroU64};

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}

fn digest() -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([7; 32])
}

fn request() -> WorkloadContractV2 {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: digest(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: id("private-grant"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(),
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
        execution_identity: ExecutionIdentityRequestV2::PreserveCaller,
    }
}

fn identity() -> LinuxExecutionIdentityV2 {
    let mut entrypoints = BoundedVec::default();
    entrypoints
        .try_push(ApprovedEntrypointV2 {
            id: id("http-adapter"),
            absolute_path: BoundedText::new("/opt/memcordon/approved/http-adapter").unwrap(),
            sha256: digest(),
            size: NonZeroU64::new(4096).unwrap(),
        })
        .unwrap();
    let mut identity = LinuxExecutionIdentityV2 {
        reference: ExecutionIdentityRefV2 {
            id: id("candidate"),
            semantic_digest: digest(),
        },
        enabled: true,
        uid: NonZeroU32::new(2000).unwrap(),
        gid: NonZeroU32::new(2000).unwrap(),
        supplementary_groups: BoundedVec::default(),
        entrypoints,
    };
    identity.reference.semantic_digest = identity.semantic_digest().unwrap();
    identity
}

fn registry(identity: LinuxExecutionIdentityV2) -> PolicyRegistryV2 {
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(ProfileDefinitionV2 {
            profile,
            reference: profile.reference(),
            enabled: true,
            qualification_digest: digest(),
        })
        .unwrap();
    let mut identities = BoundedVec::default();
    identities.try_push(identity.clone()).unwrap();
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut plans = BoundedVec::default();
    plans.try_push(digest()).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV2 {
            id: id("private-grant"),
            revision: NonZeroU64::MIN,
            profile: profile.reference(),
            ceiling: profile.ceiling(),
            enabled: true,
            callers,
            approved_plans: plans,
            execution_identity: ExecutionIdentityRequestV2::AdministratorProfile {
                reference: identity.reference,
            },
        })
        .unwrap();
    PolicyRegistryV2 {
        schema_version: ContractVersionTwo::default(),
        profiles,
        execution_identities: identities,
        grants,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    }
}

fn provider() -> PublicProviderBindingV1 {
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    PublicProviderBindingV1 {
        generation: BoundedText::new(&format!("0.5.7-dev:{source}")).unwrap(),
        source_commit: BoundedText::new(source).unwrap(),
        runtime_manifest_sha256: digest(),
    }
}

fn unavailable_profile_states() -> [ProviderProfileStateV2; 2] {
    [
        ProviderProfileStateV2 {
            profile: ProfileKindV2::LinuxUnixCreateV1,
            supported: true,
            package_state: ProfilePackageStateV2::EnabledUnqualified,
        },
        ProviderProfileStateV2 {
            profile: ProfileKindV2::LinuxTcp4PrivateV1,
            supported: false,
            package_state: ProfilePackageStateV2::InstalledDisabled,
        },
    ]
}

#[test]
fn v2_registry_preserves_only_explicit_v1_baseline_authority() {
    let mut policy = registry(identity());
    let baseline = BaselineProfile::LinuxUnixCreate;
    policy
        .profiles
        .try_push(ProfileDefinitionV2 {
            profile: ProfileKindV2::LinuxUnixCreateV1,
            reference: baseline.reference(),
            enabled: true,
            qualification_digest: digest(),
        })
        .unwrap();
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut plans = BoundedVec::default();
    plans.try_push(digest()).unwrap();
    policy
        .grants
        .try_push(PolicyGrantV2 {
            id: id("baseline-grant"),
            revision: NonZeroU64::MIN,
            profile: baseline.reference(),
            ceiling: baseline.ceiling(),
            enabled: true,
            callers,
            approved_plans: plans,
            execution_identity: ExecutionIdentityRequestV2::PreserveCaller,
        })
        .unwrap();
    let projected = policy.baseline_v1_projection().unwrap();
    assert_eq!(projected.profiles.as_slice().len(), 1);
    assert_eq!(
        projected.profiles.as_slice()[0].reference,
        baseline.reference()
    );
    assert_eq!(projected.grants.as_slice().len(), 1);
    assert_eq!(projected.grants.as_slice()[0].id, id("baseline-grant"));
    assert_ne!(
        projected.canonical_digest().unwrap(),
        policy.canonical_digest().unwrap()
    );
    let epoch = PolicyEpoch {
        service_instance: Nonce128([3; 16]),
        revision: NonZeroU64::MIN,
    };
    let request = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest(),
        authorized_profile: baseline.reference(),
        authorization: AuthorizationRef {
            grant_id: id("baseline-grant"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(),
        },
        ceiling: baseline.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: epoch.clone(),
    };
    assert!(
        memcordon_core::workload_registry::resolve(
            &projected,
            &epoch,
            &request,
            &CallerSelector::Linux { uid: 1000 },
            baseline,
            &digest(),
        )
        .is_ok()
    );
}

#[test]
fn v2_dispatch_is_closed_and_never_drops_execution_identity() {
    let request = request();
    let json = serde_json::to_vec(&request).unwrap();
    assert_eq!(
        WorkloadContract::parse(&json).unwrap(),
        WorkloadContract::V2(request)
    );
    let mut value: serde_json::Value = serde_json::from_slice(&json).unwrap();
    value["schema_version"] = serde_json::json!(3);
    assert!(WorkloadContract::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value["schema_version"] = serde_json::json!(1);
    assert!(WorkloadContract::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value["schema_version"] = serde_json::json!(2);
    value["execution_identity"] = serde_json::json!({"kind":"administrator-profile"});
    assert!(WorkloadContract::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let duplicate = String::from_utf8(json).unwrap().replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert!(WorkloadContract::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn v2_canonical_bytes_have_separate_domain_and_identity_tag() {
    let mut request = request();
    let preserved = encode_contract_v2(&request).unwrap();
    let mut expected = b"memcordon-workload-contract-v2\0\0\x01".to_vec();
    expected.extend_from_slice(&[7; 32]);
    let profile_id = request.authorized_profile.id.as_str().as_bytes();
    expected.extend_from_slice(&u16::try_from(profile_id.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(profile_id);
    expected.extend_from_slice(request.authorized_profile.semantic_digest.bytes());
    let grant_id = request.authorization.grant_id.as_str().as_bytes();
    expected.extend_from_slice(&u16::try_from(grant_id.len()).unwrap().to_be_bytes());
    expected.extend_from_slice(grant_id);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.extend_from_slice(&[7; 32]);
    expected.extend_from_slice(&[3, 1, 1, 1, 1]);
    expected.extend_from_slice(&0_u16.to_be_bytes());
    expected.extend_from_slice(&0_u16.to_be_bytes());
    expected.extend_from_slice(&[3; 16]);
    expected.extend_from_slice(&1_u64.to_be_bytes());
    expected.push(1);
    assert_eq!(preserved, expected);
    assert_eq!(decode_contract_v2(&preserved).unwrap(), request);
    let preserved_digest = contract_digest_v2(&request).unwrap();
    assert_eq!(
        String::from(preserved_digest.clone()),
        "736967c1da4c77c4e1e724087e96fcb8d7e718148bc82cb092303c4c035a31dd"
    );
    request.execution_identity = ExecutionIdentityRequestV2::AdministratorProfile {
        reference: identity().reference,
    };
    let delegated = encode_contract_v2(&request).unwrap();
    assert_eq!(decode_contract_v2(&delegated).unwrap(), request);
    assert_ne!(delegated, preserved);
    assert_ne!(contract_digest_v2(&request).unwrap(), preserved_digest);
    let mut wrong_tag = delegated;
    let tag_index = preserved.len() - 1;
    wrong_tag[tag_index] = 3;
    assert!(decode_contract_v2(&wrong_tag).is_err());
}

#[test]
fn identity_digest_and_exact_grant_reject_substitution() {
    let identity = identity();
    identity.validate().unwrap();
    assert_eq!(
        String::from(identity.reference.semantic_digest.clone()),
        "d6212d424562cd76f133f331838f811331c42900767d25316632bdd8183a5ef6"
    );
    assert_eq!(
        String::from(
            ProfileKindV2::LinuxTcp4PrivateV1
                .reference()
                .semantic_digest
        ),
        "fefad78a6eb35d49a99ca8a2f4771d575331c72a5cabc130fdd64d84d699d1e5"
    );
    let policy = registry(identity.clone());
    policy.validate().unwrap();
    let bytes = serde_json::to_vec(&policy).unwrap();
    assert_eq!(PolicyRegistryV2::parse(&bytes).unwrap(), policy);
    let baseline_digest = policy.canonical_digest().unwrap();
    assert_eq!(
        String::from(baseline_digest.clone()),
        "b297bb32459e516fbcd004d5c06d0afe9ba87194b07df2f320c759190e76f2f0"
    );

    let mut request = request();
    request.execution_identity = ExecutionIdentityRequestV2::AdministratorProfile {
        reference: identity.reference.clone(),
    };
    let caller = CallerSelector::Linux { uid: 1000 };
    assert!(
        resolve_v2(
            &policy,
            &request.expected_epoch,
            &request,
            &caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
            &digest(),
        )
        .is_ok()
    );
    let mut wrong_request = request.clone();
    wrong_request.execution_identity = ExecutionIdentityRequestV2::PreserveCaller;
    assert_eq!(
        resolve_v2(
            &policy,
            &request.expected_epoch,
            &wrong_request,
            &caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
            &digest(),
        )
        .unwrap_err()
        .code,
        AdmissionCodeV2::ExecutionIdentityNotAuthorized
    );
    let mut disabled_identity = identity;
    disabled_identity.enabled = false;
    let changed = registry(disabled_identity);
    assert!(changed.validate().is_err());
    assert_ne!(changed.canonical_digest().ok(), Some(baseline_digest));
}

#[test]
fn identity_paths_and_groups_reject_ambiguous_authority() {
    for path in ["relative/path", "/", "/opt/../candidate", "/opt//candidate"] {
        let mut identity = identity();
        let mut entrypoint = identity.entrypoints.as_slice()[0].clone();
        entrypoint.absolute_path = BoundedText::new(path).unwrap();
        let mut entrypoints = BoundedVec::default();
        entrypoints.try_push(entrypoint).unwrap();
        identity.entrypoints = entrypoints;
        assert!(identity.semantic_digest().is_err(), "{path}");
    }
    let mut identity = identity();
    identity
        .supplementary_groups
        .try_push(NonZeroU32::new(3000).unwrap())
        .unwrap();
    identity
        .supplementary_groups
        .try_push(NonZeroU32::new(3000).unwrap())
        .unwrap();
    assert!(identity.semantic_digest().is_err());
}

#[test]
fn identity_semantic_digest_sorts_groups_and_entrypoints() {
    let original = identity().entrypoints.as_slice()[0].clone();
    let second = ApprovedEntrypointV2 {
        id: id("worker-adapter"),
        absolute_path: BoundedText::new("/opt/memcordon/approved/worker-adapter").unwrap(),
        sha256: DiagnosticSha256::from_bytes([8; 32]),
        size: NonZeroU64::new(8192).unwrap(),
    };
    let mut forward = identity();
    forward
        .supplementary_groups
        .try_push(NonZeroU32::new(3000).unwrap())
        .unwrap();
    forward
        .supplementary_groups
        .try_push(NonZeroU32::new(4000).unwrap())
        .unwrap();
    forward.entrypoints.try_push(second.clone()).unwrap();
    let mut reverse = identity();
    reverse
        .supplementary_groups
        .try_push(NonZeroU32::new(4000).unwrap())
        .unwrap();
    reverse
        .supplementary_groups
        .try_push(NonZeroU32::new(3000).unwrap())
        .unwrap();
    let mut entrypoints = BoundedVec::default();
    entrypoints.try_push(second).unwrap();
    entrypoints.try_push(original).unwrap();
    reverse.entrypoints = entrypoints;
    assert_eq!(
        forward.semantic_digest().unwrap(),
        reverse.semantic_digest().unwrap()
    );
}

#[test]
fn v2_requirement_conflicts_are_sorted_and_bounded() {
    let identity = identity();
    let policy = registry(identity.clone());
    let mut request = request();
    request.execution_identity = ExecutionIdentityRequestV2::AdministratorProfile {
        reference: identity.reference,
    };
    for index in (0..17).rev() {
        request
            .requirements
            .try_push(RequirementV1::UnixSocketPair {
                id: id(&format!("pair-{index:02}")),
                socket_kind: UnixSocketKind::Stream,
            })
            .unwrap();
    }
    let rejection = resolve_v2(
        &policy,
        &request.expected_epoch,
        &request,
        &CallerSelector::Linux { uid: 1000 },
        ProfileKindV2::LinuxTcp4PrivateV1,
        &digest(),
    )
    .unwrap_err();
    assert_eq!(rejection.code, AdmissionCodeV2::FeatureNotEnforceable);
    assert_eq!(rejection.conflicts.as_slice().len(), 16);
    assert_eq!(rejection.remaining_conflicts, 1);
    assert_eq!(
        rejection.conflicts.as_slice()[0].requirement,
        Some(id("pair-00"))
    );
}

#[test]
fn v2_discovery_filters_caller_and_never_advertises_private_profile() {
    assert_eq!(
        String::from(profile_catalog_digest_v2()),
        "c87c704237b1d74f70271e64dadcb617421943a1b77f53f11b7b247983fb165d"
    );
    let policy = registry(identity());
    let epoch = request().expected_epoch;
    let states = unavailable_profile_states();
    let discovery = WorkloadDiscoveryV2::authenticated(
        Some((&policy, &epoch)),
        &CallerSelector::Linux { uid: 1000 },
        &states,
        provider(),
        BoundedText::new("boot-a").unwrap(),
    )
    .unwrap();
    assert!(discovery.validate());
    assert_eq!(discovery.profiles.as_slice().len(), 2);
    let private = discovery
        .profiles
        .as_slice()
        .iter()
        .find(|profile| profile.profile == ProfileKindV2::LinuxTcp4PrivateV1.reference())
        .unwrap();
    assert!(!private.supported);
    assert!(!private.available);
    assert_eq!(private.required_qualification_digest, Some(digest()));
    assert_eq!(private.grants.as_slice().len(), 1);
    assert_eq!(private.permitted_execution_identities.as_slice().len(), 1);
    let unauthorized = WorkloadDiscoveryV2::authenticated(
        Some((&policy, &epoch)),
        &CallerSelector::Linux { uid: 1001 },
        &states,
        provider(),
        BoundedText::new("boot-a").unwrap(),
    )
    .unwrap();
    assert!(
        unauthorized
            .profiles
            .as_slice()
            .iter()
            .all(|profile| profile.grants.as_slice().is_empty()
                && profile.permitted_execution_identities.as_slice().is_empty())
    );
    let mut forged: serde_json::Value = serde_json::to_value(&discovery).unwrap();
    let profiles = forged["profiles"].as_array_mut().unwrap();
    let private = profiles
        .iter_mut()
        .find(|profile| profile["profile"]["id"] == "linux-tcp4-private-v1")
        .unwrap();
    private["available"] = serde_json::json!(true);
    assert!(
        !serde_json::from_value::<WorkloadDiscoveryV2>(forged)
            .unwrap()
            .validate()
    );
    let mut unsupported = unavailable_profile_states();
    unsupported[1].supported = true;
    assert!(
        WorkloadDiscoveryV2::authenticated(
            Some((&policy, &epoch)),
            &CallerSelector::Linux { uid: 1000 },
            &unsupported,
            provider(),
            BoundedText::new("boot-a").unwrap(),
        )
        .is_err()
    );
    let mut enabled = unavailable_profile_states();
    enabled[1].package_state = ProfilePackageStateV2::EnabledUnqualified;
    assert!(
        WorkloadDiscoveryV2::authenticated(
            Some((&policy, &epoch)),
            &CallerSelector::Linux { uid: 1000 },
            &enabled,
            provider(),
            BoundedText::new("boot-a").unwrap(),
        )
        .is_err()
    );
}

#[test]
fn private_profile_requires_loopback_tcp_and_no_gain() {
    let identity = identity();
    let policy = registry(identity.clone());
    let mut request = request();
    request.execution_identity = ExecutionIdentityRequestV2::AdministratorProfile {
        reference: identity.reference,
    };
    let mut operations = BoundedVec::default();
    operations.try_push(TcpOperation::Create).unwrap();
    operations.try_push(TcpOperation::Connect).unwrap();
    request
        .requirements
        .try_push(RequirementV1::Tcp {
            id: id("tcp"),
            family: IpFamily::V4,
            operations: TcpOperations::new(operations).unwrap(),
            scope: TcpScope::AttemptPrivateStack,
            local_ports: LocalPortRequirement::KernelAssigned,
            peer: TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 {
                    address: [127, 0, 0, 1],
                    port: 80.try_into().unwrap(),
                },
            },
        })
        .unwrap();
    let caller = CallerSelector::Linux { uid: 1000 };
    let admit = |request: &WorkloadContractV2| {
        resolve_v2(
            &policy,
            &request.expected_epoch,
            request,
            &caller,
            ProfileKindV2::LinuxTcp4PrivateV1,
            &digest(),
        )
    };
    assert!(admit(&request).is_ok());
    let mut nonlocal: serde_json::Value = serde_json::to_value(&request).unwrap();
    nonlocal["requirements"][0]["peer"]["endpoint"]["address"] = serde_json::json!([192, 0, 2, 1]);
    let nonlocal: WorkloadContractV2 = serde_json::from_value(nonlocal).unwrap();
    assert_eq!(
        admit(&nonlocal).unwrap_err().code,
        AdmissionCodeV2::PolicyIncompatible
    );
    let mut wrong_ceiling = request;
    wrong_ceiling.ceiling.credential_gains = CredentialGainCeiling::ExistingCallerEnvelopeAccepted;
    assert!(wrong_ceiling.validate().is_err());
}
