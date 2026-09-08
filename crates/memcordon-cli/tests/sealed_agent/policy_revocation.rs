use crate::policy_registry::Activation;
use memcordon_core::workload_contract::*;
use memcordon_core::workload_registry::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

#[test]
fn revoke_then_drain_keeps_each_live_admission_revoked() {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let profile = BaselineProfile::LinuxUnixCreate;
    let epoch = PolicyEpoch {
        service_instance: Nonce128([1; 16]),
        revision: NonZeroU64::MIN,
    };
    let request = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: profile.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("approved".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest.clone(),
        },
        ceiling: profile.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: epoch.clone(),
    };
    let snapshot = ProviderAdmissionSnapshotV1 {
        private_invocation_digest: digest.clone(),
        caller_invocation_reference: Nonce128([9; 16]),
        request_digest: memcordon_core::workload_codec::contract_digest(&request).unwrap(),
        request,
        registry_digest: digest.clone(),
        qualification_digest: digest,
        admission_nonce: Nonce128([2; 16]),
        caller: CallerSelector::Linux { uid: 1000 },
        native_profile: profile,
    };
    let live = vec![("attempt-a".into(), snapshot)];
    let registry = PolicyRegistryV1 {
        schema_version: ContractVersionOne::default(),
        profiles: BoundedVec::default(),
        grants: BoundedVec::default(),
        active_attempt_disposition: GrantChangeDisposition::RevokeActive,
    };
    let revoked =
        Activation::next_revocations(None, GrantChangeDisposition::RevokeActive, &live).unwrap();
    let activation = Activation {
        schema_version: ContractVersionOne::default(),
        registry_digest: registry.canonical_digest().unwrap(),
        registry,
        epoch,
        revoked_admissions: revoked,
    };
    let drained = Activation::next_revocations(
        Some(&activation),
        GrantChangeDisposition::DrainExisting,
        &live,
    )
    .unwrap();
    assert_eq!(drained.as_slice(), &[Nonce128([2; 16])]);
    let serialized = serde_json::to_vec(&activation).unwrap();
    let restored: Activation = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(
        Activation::next_revocations(
            Some(&restored),
            GrantChangeDisposition::DrainExisting,
            &live
        )
        .unwrap(),
        drained
    );
    assert!(
        Activation::next_revocations(Some(&restored), GrantChangeDisposition::DrainExisting, &[])
            .unwrap()
            .as_slice()
            .is_empty()
    );
}
