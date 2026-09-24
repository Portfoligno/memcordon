use std::ffi::OsString;
use std::num::NonZeroU64;

use memcordon::invocation::{Invocation, route};
use memcordon_core::workload_contract::{
    AuthorizationRef, ContractVersionOne, ContractVersionTwo, ExecutionIdentityRequestV2,
    LogicalId, Nonce128, PolicyEpoch, WorkloadContractV1, WorkloadContractV2,
};
use memcordon_core::workload_registry::BaselineProfile;
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedVec, DiagnosticSha256};

#[test]
fn valid_v2_workload_contract_is_explicitly_unavailable_before_invocation() {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let contract = WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("private-grant".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest,
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
        execution_identity: ExecutionIdentityRequestV2::PreserveCaller,
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("private-v2.json");
    std::fs::write(&path, serde_json::to_vec(&contract).unwrap()).unwrap();
    let arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--workload-contract"),
        path.into_os_string(),
        OsString::from("/bin/true"),
    ];
    let error = route(&arguments).unwrap_err();
    assert_eq!(error.code, "MCWORKLOAD-V2-UNAVAILABLE");
}

#[test]
fn malformed_v2_contract_is_not_reclassified_as_unavailable() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed-v2.json");
    std::fs::write(&path, b"{\"schema_version\":2}\n").unwrap();
    let arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--workload-contract"),
        path.into_os_string(),
        OsString::from("/bin/true"),
    ];
    let error = route(&arguments).unwrap_err();
    assert_eq!(error.code, "MCUSAGE-WORKLOAD-CONTRACT");
}

#[test]
fn valid_v1_workload_contract_still_reaches_legacy_invocation() {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = BaselineProfile::LinuxUnixCreate;
    let contract = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("baseline-grant".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest,
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("baseline-v1.json");
    std::fs::write(&path, serde_json::to_vec(&contract).unwrap()).unwrap();
    let arguments = vec![
        OsString::from("--sealed"),
        OsString::from("--workload-contract"),
        path.into_os_string(),
        OsString::from("/bin/true"),
    ];
    match route(&arguments).unwrap() {
        Invocation::Execute(request) => {
            assert_eq!(request.policy.workload_contract, Some(contract))
        }
        other => panic!("expected legacy execution, got {other:?}"),
    }
}
