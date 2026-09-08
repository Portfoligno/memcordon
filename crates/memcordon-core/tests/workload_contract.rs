use memcordon_core::workload_contract::*;
use memcordon_core::workload_evidence::*;
use memcordon_core::workload_registry::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}
fn digest() -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([7; 32])
}
fn request() -> WorkloadContractV1 {
    WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest(),
        authorized_profile: BaselineProfile::LinuxUnixCreate.reference(),
        authorization: AuthorizationRef {
            grant_id: id("approved-plan"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest(),
        },
        ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
    }
}
fn registry() -> PolicyRegistryV1 {
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(ProfileDefinitionV1 {
            profile: BaselineProfile::LinuxUnixCreate,
            reference: BaselineProfile::LinuxUnixCreate.reference(),
            enabled: true,
            qualification_digest: digest(),
        })
        .unwrap();
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut approved_plans = BoundedVec::default();
    approved_plans.try_push(digest()).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV1 {
            id: id("approved-plan"),
            revision: NonZeroU64::MIN,
            profile: BaselineProfile::LinuxUnixCreate.reference(),
            ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
            enabled: true,
            callers,
            approved_plans,
        })
        .unwrap();
    PolicyRegistryV1 {
        schema_version: ContractVersionOne::default(),
        profiles,
        grants,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    }
}
fn admit(value: &WorkloadContractV1, caller: u32) -> Result<(), AdmissionRejectionV1> {
    resolve(
        &registry(),
        &request().expected_epoch,
        value,
        &CallerSelector::Linux { uid: caller },
        BaselineProfile::LinuxUnixCreate,
        &digest(),
    )
    .map(|_| ())
}

fn frozen() -> ProviderAdmissionSnapshotV1 {
    let request = request();
    ProviderAdmissionSnapshotV1 {
        request_digest: memcordon_core::workload_codec::contract_digest(&request).unwrap(),
        request,
        registry_digest: registry().canonical_digest().unwrap(),
        qualification_digest: digest(),
        admission_nonce: Nonce128([4; 16]),
        caller_invocation_reference: Nonce128([5; 16]),
        private_invocation_digest: digest(),
        caller: CallerSelector::Linux { uid: 1000 },
        native_profile: BaselineProfile::LinuxUnixCreate,
    }
}

fn attempt_binding() -> AttemptBindingV1 {
    let source = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    AttemptBindingV1::from_snapshot(
        &frozen(),
        memcordon_core::PublicProviderBindingV1 {
            generation: memcordon_core::BoundedText::new(&format!("0.5.3-dev:{source}")).unwrap(),
            source_commit: memcordon_core::BoundedText::new(source).unwrap(),
            runtime_manifest_sha256: digest(),
        },
        memcordon_core::BoundedText::new("boot-a").unwrap(),
        memcordon_core::BoundedText::new("attempt-a").unwrap(),
        2,
    )
    .unwrap()
}

#[test]
fn planned_response_rejects_effective_policy_and_pending_check_substitution() {
    let mut pending = BoundedVec::default();
    for check in PENDING_PRELAUNCH_CHECKS {
        pending.try_push(check).unwrap();
    }
    let planned = WorkloadResolutionReportV1::Planned {
        binding: attempt_binding().plan,
        effective: EffectiveWorkloadPolicyV1 {
            profile: BaselineProfile::LinuxUnixCreate,
            ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
            restriction: baseline_observation(BaselineProfile::LinuxUnixCreate),
        },
        pending,
    };
    assert!(planned.valid_plan_response(&request(), BaselineProfile::LinuxUnixCreate));
    for field in [
        "effective-digest",
        "profile",
        "ceiling",
        "restriction",
        "pending",
    ] {
        let mut changed = planned.clone();
        let WorkloadResolutionReportV1::Planned {
            binding,
            effective,
            pending,
        } = &mut changed
        else {
            unreachable!()
        };
        match field {
            "effective-digest" => binding.effective_policy_digest = digest(),
            "profile" => effective.profile = BaselineProfile::WindowsHostNetworkExternal,
            "ceiling" => effective.ceiling = BaselineProfile::WindowsHostNetworkExternal.ceiling(),
            "restriction" => {
                effective.restriction =
                    BaselineRestrictionObservationV1::WindowsNetworkExternallyGoverned
            }
            "pending" => *pending = BoundedVec::default(),
            _ => unreachable!(),
        }
        assert!(
            !changed.valid_plan_response(&request(), BaselineProfile::LinuxUnixCreate),
            "{field}"
        );
    }
}

#[test]
fn terminal_requires_exact_attempt_restart_boot_and_frozen_caller_invocation_reference() {
    let binding = attempt_binding();
    let checkpoint = VerifiedCheckpointV1::observed(
        &binding,
        baseline_observation(BaselineProfile::LinuxUnixCreate),
        true,
        true,
        true,
        true,
        true,
        true,
    )
    .unwrap();
    let terminal =
        AttemptPolicyEnforcementV1::retired(binding.clone(), checkpoint.clone(), true, true)
            .unwrap();
    assert!(terminal.valid_native_terminal(
        Some(&request()),
        BaselineProfile::LinuxUnixCreate,
        "attempt-a",
        2,
        "boot-a"
    ));
    assert!(!terminal.valid_native_terminal(
        Some(&request()),
        BaselineProfile::LinuxUnixCreate,
        "attempt-b",
        2,
        "boot-a"
    ));
    assert!(!terminal.valid_native_terminal(
        Some(&request()),
        BaselineProfile::LinuxUnixCreate,
        "attempt-a",
        3,
        "boot-a"
    ));
    assert!(!terminal.valid_native_terminal(
        Some(&request()),
        BaselineProfile::LinuxUnixCreate,
        "attempt-a",
        2,
        "boot-b"
    ));
    let mut changed = binding.clone();
    changed.caller_invocation_reference = Nonce128([6; 16]);
    assert!(!changed.matches_snapshot(&frozen()));
    assert!(!checkpoint.matches_binding(&changed));
    assert!(AttemptPolicyEnforcementV1::retired(changed, checkpoint, true, true).is_err());
    let serialized = serde_json::to_value(&terminal).unwrap();
    assert!(!serialized.to_string().contains("private_invocation_digest"));
    assert!(!serialized.to_string().contains("1000"));
    let mut changed = serialized;
    changed["before_authorization"]["target_gated"] = false.into();
    assert!(serde_json::from_value::<AttemptPolicyEnforcementV1>(changed).is_err());
}

#[test]
fn independent_baseline_profile_known_answer() {
    // Independently encoded from the published field/tag table and hashed with hashlib.
    let expected =
        b"profile-definition-v1\0\0\x01\0\x14linux-unix-create-v1\x01\x02\x02\x02\x01\x01\x01";
    assert_eq!(BaselineProfile::LinuxUnixCreate.semantic_bytes(), expected);
    let hash: String = BaselineProfile::LinuxUnixCreate
        .reference()
        .semantic_digest
        .into();
    assert_eq!(
        hash,
        "6a8a4c2a8003371ea0c7cd8e3a2c340fb86a33c5980538d806783848578099bb"
    );
}

#[test]
fn caller_grant_plan_and_epoch_are_independent_authority_checks() {
    let mut value = request();
    assert!(admit(&value, 1000).is_ok());
    assert_eq!(
        admit(&value, 1001).unwrap_err().code,
        AdmissionCode::ProfileNotAuthorized
    );
    value.expected_epoch.revision = NonZeroU64::new(2).unwrap();
    assert_eq!(
        admit(&value, 1000).unwrap_err().code,
        AdmissionCode::PolicyEpochStale
    );
    value.authorization.grant_revision = NonZeroU64::new(2).unwrap();
    assert_eq!(
        admit(&value, 1000).unwrap_err().code,
        AdmissionCode::ProfileNotAuthorized
    );
}

#[test]
fn successful_tcp_rejects_but_qualified_denial_is_admitted() {
    let mut value = request();
    value
        .requirements
        .try_push(RequirementV1::DenialExercise {
            id: id("denial"),
            operation: DeniedOperation::InetSocketCreation,
        })
        .unwrap();
    assert!(admit(&value, 1000).is_ok());
    let mut operations = BoundedVec::default();
    operations.try_push(TcpOperation::Create).unwrap();
    operations.try_push(TcpOperation::Connect).unwrap();
    value
        .requirements
        .try_push(RequirementV1::Tcp {
            id: id("tcp"),
            family: IpFamily::V4,
            operations: TcpOperations::new(operations).unwrap(),
            scope: TcpScope::HostSharedLoopback,
            local_ports: LocalPortRequirement::KernelAssigned,
            peer: TcpPeerRequirement::ExactAddress {
                endpoint: TcpEndpoint::V4 {
                    address: [127, 0, 0, 1],
                    port: 80.try_into().unwrap(),
                },
            },
        })
        .unwrap();
    let rejection = admit(&value, 1000).unwrap_err();
    assert_eq!(rejection.code, AdmissionCode::PolicyIncompatible);
    assert_eq!(
        rejection.conflicts.as_slice()[0].requirement,
        Some(id("tcp"))
    );
}

#[test]
fn strict_parser_rejects_duplicate_keys_versions_and_oversized_input() {
    let bytes = serde_json::to_vec(&request()).unwrap();
    assert!(WorkloadContractV1::parse(&bytes).is_ok());
    let text = String::from_utf8(bytes).unwrap();
    let duplicate = text.replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(WorkloadContractV1::parse(duplicate.as_bytes()).is_err());
    let unknown = text.replacen("\"schema_version\":1", "\"schema_version\":2", 1);
    assert!(WorkloadContractV1::parse(unknown.as_bytes()).is_err());
    assert!(
        WorkloadContractV1::parse(&vec![
            b' ';
            memcordon_core::workload_limits::CONTRACT_BYTES + 1
        ])
        .is_err()
    );
}

#[test]
fn identifiers_and_operation_sets_reject_ambiguous_forms() {
    for invalid in ["", "-start", "end-", "two--hyphens", "UPPER", "a/b", "a b"] {
        assert!(LogicalId::new(invalid.into()).is_err());
    }
    let mut operations = BoundedVec::default();
    operations.try_push(TcpOperation::Listen).unwrap();
    assert!(TcpOperations::new(operations).is_err());
    let mut operations = BoundedVec::default();
    operations.try_push(TcpOperation::Create).unwrap();
    operations.try_push(TcpOperation::Create).unwrap();
    assert!(TcpOperations::new(operations).is_err());
}
