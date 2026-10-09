//! Native protocol vectors remain descriptive test evidence, never launch authority.
use memcordon_core::workload_contract::*;
use memcordon_core::workload_contract_v3::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    num::NonZeroU64,
    path::PathBuf,
};

fn id(value: &str) -> LogicalId {
    LogicalId::new(value.to_owned()).unwrap()
}
fn sha(bytes: impl AsRef<[u8]>) -> String {
    Sha256::digest(bytes.as_ref())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn object(value: &str, marker: u8) -> BoundObjectRef {
    BoundObjectRef {
        id: id(value),
        digest: DiagnosticSha256::from_bytes([marker; 32]),
    }
}
fn mixed() -> WorkloadContractV3 {
    let mut requirements = BoundedVec::default();
    requirements
        .try_push(RequirementV3::TcpListener {
            id: id("tcp"),
            local_port: LocalPortV3::KernelAssigned,
            peer: PrivatePeerV3::DynamicLoopbackWithinThisAttempt,
        })
        .unwrap();
    requirements
        .try_push(RequirementV3::UnixStreamPair { id: id("unix") })
        .unwrap();
    WorkloadContractV3 {
        schema_version: ContractVersionThree::default(),
        workload_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        authorized_profile: ProfileRef {
            id: id(PROFILE),
            semantic_digest: DiagnosticSha256::from_bytes([2; 32]),
        },
        authorization: AuthorizationRef {
            grant_id: id("combined-grant"),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: DiagnosticSha256::from_bytes([1; 32]),
        },
        ceiling: MixedPrivateCeiling::FreshRootIpv4TcpUnixStreamsIntraAttemptNoGain,
        requirements,
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
            revision: NonZeroU64::MIN,
        },
    }
}

#[test]
#[ignore = "requires an explicitly owned native component receipt directory"]
fn native_version_vectors_emit_actual_component_receipts() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Input {
        run_id: String,
        recipe_id: String,
        native_target: String,
        artifact_root: PathBuf,
        artifact_prefix: String,
        challenge: [u8; 32],
    }
    let mut input = Vec::new();
    std::io::stdin()
        .take(65537)
        .read_to_end(&mut input)
        .unwrap();
    assert!(input.len() <= 65536);
    memcordon_core::canonical_json::reject_duplicate_json_keys(&input).unwrap();
    let input: Input = serde_json::from_slice(&input).unwrap();
    assert!(!input.run_id.is_empty() && !input.recipe_id.is_empty() && input.challenge != [0; 32]);
    let target = if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "x86_64-unknown-linux-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "aarch64-unknown-linux-gnu"
    } else {
        panic!("native Linux vector host required")
    };
    assert_eq!(input.native_target, target);
    assert!(input.artifact_root.is_absolute());
    assert!(
        !input.artifact_prefix.is_empty()
            && !input.artifact_prefix.contains(['\\', ':'])
            && input
                .artifact_prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != "..")
    );
    let retain = |name: &str, bytes: &[u8]| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(input.artifact_root.join(name))
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        format!("{}/{name}", input.artifact_prefix)
    };
    let fixed =
        include_str!("../../../memcordon-core/tests/fixtures/workload_independent/contract.hex");
    let v1 = fixed
        .split_whitespace()
        .flat_map(|value| {
            value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let decoded = memcordon_core::workload_codec::decode_contract(&v1).unwrap();
    assert_eq!(
        memcordon_core::workload_codec::encode_contract(&decoded).unwrap(),
        v1
    );
    let v2_json = include_bytes!("../../../../fuzz/corpus/workload-request/baseline-v2.json");
    let private = WorkloadContractV2::parse(v2_json).unwrap();
    let v2 = memcordon_core::workload_codec::encode_contract_v2(&private).unwrap();
    assert_eq!(
        memcordon_core::workload_codec::decode_contract_v2(&v2).unwrap(),
        private
    );
    let mixed = mixed();
    let v3 = mixed.canonical_bytes().unwrap();
    assert_eq!(v3.len(), 463);
    let json = serde_json::to_vec(&mixed).unwrap();
    assert_eq!(
        WorkloadContract::parse(&json).unwrap(),
        WorkloadContract::V3(mixed.clone())
    );
    let mut projection: serde_json::Value = serde_json::from_slice(&json).unwrap();
    projection["schema_version"] = 2.into();
    let changed = serde_json::to_vec(&projection).unwrap();
    let refusal = WorkloadContract::parse(&changed).unwrap_err();
    assert!(!refusal.is_empty());
    let old_refusal = WorkloadContractV2::parse(&json).unwrap_err();
    assert!(!old_refusal.is_empty());
    let executable = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let receipt = serde_json::json!({"format":"memcordon.linux-version-component","revision":1,
        "run_id":input.run_id,"recipe_id":input.recipe_id,"native_target":input.native_target,
        "test_name":"native_versions::native_version_vectors_emit_actual_component_receipts",
        "executable_sha256":sha(executable),"challenge_sha256":sha(input.challenge),
        "operation":"actual-version-codec-and-projection-vectors","fixture_resource_claims":true,
        "v1_canonical":retain("v1-canonical.bin",&v1),"v2_request":retain("v2-request.json",v2_json),"v2_canonical":retain("v2-canonical.bin",&v2),
        "v3_request":retain("v3-request.json",&json),"v3_canonical":retain("v3-canonical.bin",&v3),
        "projection":retain("projection.json",&changed),"projection_refusal":refusal,"old_parser_refusal":old_refusal});
    retain(
        "native-receipt.json",
        &serde_json::to_vec(&receipt).unwrap(),
    );
    std::fs::File::open(&input.artifact_root)
        .unwrap()
        .sync_all()
        .unwrap();
}
