use memcordon_core::workload_contract::{
    AuthorizationRef, LogicalId, Nonce128, PolicyEpoch, ProfileRef, WorkloadContract,
};
use memcordon_core::workload_contract_v3::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.into()).unwrap()
}
fn object(value: &str, marker: u8) -> BoundObjectRef {
    BoundObjectRef {
        id: id(value),
        digest: DiagnosticSha256::from_bytes([marker; 32]),
    }
}
fn bounded<T, const N: usize>(values: Vec<T>) -> BoundedVec<T, N> {
    let mut output = BoundedVec::default();
    for value in values {
        assert!(output.try_push(value).is_ok());
    }
    output
}
fn contract() -> WorkloadContractV3 {
    WorkloadContractV3 {
        schema_version: ContractVersionThree::default(),
        workload_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        authorized_profile: ProfileRef {
            id: id(PROFILE),
            semantic_digest: DiagnosticSha256::from_bytes([2; 32]),
        },
        authorization: AuthorizationRef {
            grant_id: id("combined-grant"),
            grant_revision: NonZeroU64::new(1).unwrap(),
            approved_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        },
        ceiling: MixedPrivateCeiling::FreshRootIpv4TcpUnixStreamsIntraAttemptNoGain,
        requirements: bounded(vec![
            RequirementV3::TcpListener {
                id: id("tcp"),
                local_port: LocalPortV3::KernelAssigned,
                peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
            },
            RequirementV3::UnixStreamPair { id: id("unix") },
        ]),
        execution_identity: ExclusiveAdministratorIdentityRef {
            identity: object("account", 3),
            exclusive_use_policy: object("exclusive", 4),
        },
        runtime_image: object("toolchain", 5),
        input_image: object("fixture", 6),
        root_layout: object("build-root", 7),
        launch: ImageLaunchV1 {
            entrypoint: id("build-driver"),
            working_directory: RootRelativePath::new("work".into()).unwrap(),
        },
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([8; 16]),
            revision: NonZeroU64::new(1).unwrap(),
        },
    }
}

#[test]
fn combined_canonical_bytes_match_independently_encoded_known_answer() {
    // Fixed wire vector assembled from the documented domain, big-endian
    // lengths/tags and explicit object markers; no producer codec computes it.
    const HEX: &str = "6d656d636f72646f6e2e776f726b6c6f61642d636f6e74726163742f76657273696f6e3300000100030101010101010101010101010101010101010101010101010101010101010101001a6c696e75782d746370342d756e69782d707269766174652d76310202020202020202020202020202020202020202020202020202020202020202000e636f6d62696e65642d6772616e74000000000000000101010101010101010101010101010101010101010101010101010101010101010100076163636f756e74030303030303030303030303030303030303030303030303030303030303030300096578636c757369766504040404040404040404040404040404040404040404040404040404040404040009746f6f6c636861696e05050505050505050505050505050505050505050505050505050505050505050007666978747572650606060606060606060606060606060606060606060606060606060606060606000a6275696c642d726f6f740707070707070707070707070707070707070707070707070707070707070707000c6275696c642d6472697665720004776f726b080808080808080808080808080808080000000000000001000200037463700101010004756e697802";
    let expected = HEX
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(expected.len(), 463);
    assert_eq!(contract().canonical_bytes().unwrap(), expected);
    let mut reordered = contract();
    reordered.requirements = bounded(vec![
        RequirementV3::UnixStreamPair { id: id("unix") },
        RequirementV3::TcpListener {
            id: id("tcp"),
            local_port: LocalPortV3::KernelAssigned,
            peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
        },
    ]);
    assert_eq!(reordered.canonical_bytes().unwrap(), expected);
}

#[test]
fn combined_contract_dispatch_never_drops_authority_fields_into_old_versions() {
    let original = contract();
    let bytes = serde_json::to_vec(&original).unwrap();
    assert_eq!(
        WorkloadContract::parse(&bytes).unwrap(),
        WorkloadContract::V3(original)
    );
    assert!(memcordon_core::workload_contract::WorkloadContractV2::parse(&bytes).is_err());
    let mut downgrade = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap();
    downgrade["schema_version"] = 2.into();
    assert!(WorkloadContract::parse(&serde_json::to_vec(&downgrade).unwrap()).is_err());
}

#[test]
fn combined_plan_identity_image_epoch_and_requirement_bindings_change_canonical_identity() {
    let original = contract();
    let digest = original.digest().unwrap();
    let mut invalid_plan = original.clone();
    invalid_plan.workload_plan_digest = DiagnosticSha256::from_bytes([9; 32]);
    assert!(invalid_plan.validate().is_err());
    for mutate in [
        |value: &mut WorkloadContractV3| {
            value.runtime_image.digest = DiagnosticSha256::from_bytes([9; 32])
        },
        |value: &mut WorkloadContractV3| {
            value.input_image.digest = DiagnosticSha256::from_bytes([9; 32])
        },
        |value: &mut WorkloadContractV3| {
            value.execution_identity.identity.digest = DiagnosticSha256::from_bytes([9; 32])
        },
        |value: &mut WorkloadContractV3| {
            value.execution_identity.exclusive_use_policy.digest =
                DiagnosticSha256::from_bytes([9; 32])
        },
        |value: &mut WorkloadContractV3| {
            value.root_layout.digest = DiagnosticSha256::from_bytes([9; 32])
        },
        |value: &mut WorkloadContractV3| {
            value.expected_epoch.revision = NonZeroU64::new(2).unwrap()
        },
    ] {
        let mut changed = original.clone();
        mutate(&mut changed);
        assert_ne!(changed.digest().unwrap(), digest);
    }
    let mut reordered = original.clone();
    reordered.requirements = bounded(
        original
            .requirements
            .as_slice()
            .iter()
            .rev()
            .cloned()
            .collect(),
    );
    assert_eq!(reordered.digest().unwrap(), digest);
    reordered.requirements = bounded(vec![original.requirements.as_slice()[0].clone(); 2]);
    assert!(reordered.validate().is_err());
}

#[test]
fn root_paths_and_closed_authority_variants_reject_host_escapes() {
    for path in ["", "/host", "a/../b", "a//b", "a/./b", "../x", "x\0y"] {
        assert!(RootRelativePath::new(path.into()).is_err());
    }
    let mut value = serde_json::to_value(contract()).unwrap();
    value["execution_identity"] = serde_json::json!({"kind":"preserve_caller"});
    assert!(WorkloadContractV3::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value = serde_json::to_value(contract()).unwrap();
    value["requirements"][0]["peer"] = serde_json::json!({"kind":"host_endpoint","port":80});
    assert!(WorkloadContractV3::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
