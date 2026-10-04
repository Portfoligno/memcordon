#![cfg(unix)]

use std::{num::NonZeroU64, os::unix::fs::MetadataExt};

use memcordon_ci::release::{linux_installed_consumer::write_caller_contract, source};
use memcordon_core::{
    BoundedVec,
    workload_contract::{
        AuthorizationRef, ContractVersionTwo, Nonce128, PolicyEpoch, WorkloadContract,
        WorkloadContractV2,
    },
    workload_registry_v2::RuntimePrivatePolicyRegistry,
};

#[test]
fn caller_contract_is_readable_without_writable_custody_or_private_record_changes() {
    let owner = tempfile::tempdir_in("/tmp").unwrap();
    let registry: RuntimePrivatePolicyRegistry = serde_json::from_slice(include_bytes!(
        "../../../crates/memcordon-core/tests/fixtures/workload-v2/local-private-policy.json"
    ))
    .unwrap();
    let grant = &registry.grants.as_slice()[0];
    let contract = WorkloadContractV2 {
        schema_version: ContractVersionTwo::default(),
        workload_plan_digest: grant.approved_plans.as_slice()[0].clone(),
        authorized_profile: grant.profile.clone(),
        authorization: AuthorizationRef {
            grant_id: grant.id.clone(),
            grant_revision: grant.revision,
            approved_plan_digest: grant.approved_plans.as_slice()[0].clone(),
        },
        ceiling: grant.ceiling.clone(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([7; 16]),
            revision: NonZeroU64::new(1).unwrap(),
        },
        execution_identity: grant.execution_identity.clone(),
    };
    let private = owner.path().join("administrator-policy.json");
    source::write_json(&private, &registry).unwrap();
    let prior_private = std::fs::read(&private).unwrap();
    let private_metadata = std::fs::metadata(&private).unwrap();
    assert_eq!(private_metadata.mode() & 0o777, 0o600);

    let request = owner.path().join("caller.request.json");
    write_caller_contract(&request, &contract).unwrap();
    let held = std::fs::File::open(&request).unwrap();
    let metadata = held.metadata().unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), private_metadata.uid());
    assert_eq!(metadata.mode() & 0o777, 0o644);
    assert_eq!(metadata.mode() & 0o022, 0);
    let bytes = std::fs::read(&request).unwrap();
    let mut expected = serde_json::to_vec_pretty(&contract).unwrap();
    expected.push(b'\n');
    assert_eq!(bytes, expected);
    assert_eq!(
        WorkloadContract::parse(&bytes).unwrap(),
        WorkloadContract::V2(contract.clone())
    );

    // Atomic publication replaces a prior link; it never chmods or overwrites
    // the link's target while making caller input readable.
    let linked = owner.path().join("linked.request.json");
    std::os::unix::fs::symlink(&private, &linked).unwrap();
    write_caller_contract(&linked, &contract).unwrap();
    assert!(std::fs::symlink_metadata(&linked).unwrap().is_file());
    assert_eq!(std::fs::read(&linked).unwrap(), bytes);
    assert_eq!(std::fs::read(&private).unwrap(), prior_private);
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o600);
}
