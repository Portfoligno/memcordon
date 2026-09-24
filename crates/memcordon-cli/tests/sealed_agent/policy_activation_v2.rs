use crate::policy_registry::{
    Activation, ActivationV2, RegistryConfiguration, VersionedActivation,
};
use memcordon_core::workload_contract::{
    ContractVersionOne, ContractVersionTwo, Nonce128, PolicyEpoch,
};
use memcordon_core::workload_registry::{GrantChangeDisposition, PolicyRegistryV1};
use memcordon_core::workload_registry_v2::{PolicyRegistryV2, ProfileDefinitionV2, ProfileKindV2};
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

fn registry() -> PolicyRegistryV2 {
    let mut profiles = BoundedVec::default();
    for (profile, enabled) in [
        (ProfileKindV2::LinuxUnixCreateV1, true),
        (ProfileKindV2::LinuxTcp4PrivateV1, false),
    ] {
        profiles
            .try_push(ProfileDefinitionV2 {
                profile,
                reference: profile.reference(),
                enabled,
                qualification_digest: DiagnosticSha256::from_bytes([7; 32]),
            })
            .unwrap();
    }
    PolicyRegistryV2 {
        schema_version: ContractVersionTwo::default(),
        profiles,
        execution_identities: BoundedVec::default(),
        grants: BoundedVec::default(),
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    }
}

fn activation() -> ActivationV2 {
    let registry = registry();
    ActivationV2 {
        schema_version: ContractVersionTwo::default(),
        registry_digest: registry.canonical_digest().unwrap(),
        registry,
        epoch: PolicyEpoch {
            service_instance: Nonce128([3; 16]),
            revision: NonZeroU64::MIN,
        },
        revoked_admissions: BoundedVec::default(),
    }
}

#[test]
fn versioned_policy_parser_retains_v2_and_projects_only_baseline() {
    let value = activation();
    let bytes = serde_json::to_vec(&value).unwrap();
    let parsed = match VersionedActivation::parse(&bytes).unwrap() {
        VersionedActivation::V2(parsed) => parsed,
        VersionedActivation::V1(_) => panic!("V2 activation was downgraded"),
    };
    assert_eq!(parsed.registry_digest, value.registry_digest);
    assert_eq!(parsed.epoch, value.epoch);
    let baseline = parsed.baseline_projection().unwrap();
    assert_eq!(baseline.registry.profiles.as_slice().len(), 1);
    assert_eq!(baseline.registry.grants.as_slice().len(), 0);
    assert_ne!(baseline.registry_digest, parsed.registry_digest);
    assert!(matches!(
        RegistryConfiguration::parse(&serde_json::to_vec(&registry()).unwrap()).unwrap(),
        RegistryConfiguration::V2(_)
    ));
}

#[test]
fn policy_activation_rejects_tampering_and_ambiguous_versions() {
    let mut value = activation();
    value.registry_digest = DiagnosticSha256::from_bytes([8; 32]);
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = activation();
    value
        .revoked_admissions
        .try_push(Nonce128([4; 16]))
        .unwrap();
    value
        .revoked_admissions
        .try_push(Nonce128([4; 16]))
        .unwrap();
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(activation()).unwrap();
    value["schema_version"] = serde_json::json!(3);
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(activation()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let duplicate = br#"{"schema_version":2,"schema_version":2}"#;
    assert!(VersionedActivation::parse(duplicate).is_err());
    assert!(RegistryConfiguration::parse(duplicate).is_err());
}

#[test]
fn existing_v1_policy_activation_stays_v1() {
    let registry = PolicyRegistryV1 {
        schema_version: ContractVersionOne::default(),
        profiles: BoundedVec::default(),
        grants: BoundedVec::default(),
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    let activation = Activation {
        schema_version: ContractVersionOne::default(),
        registry_digest: registry.canonical_digest().unwrap(),
        registry,
        epoch: PolicyEpoch {
            service_instance: Nonce128([9; 16]),
            revision: NonZeroU64::MIN,
        },
        revoked_admissions: BoundedVec::default(),
    };
    let bytes = serde_json::to_vec(&activation).unwrap();
    assert!(matches!(
        VersionedActivation::parse(&bytes).unwrap(),
        VersionedActivation::V1(_)
    ));
    assert!(matches!(
        RegistryConfiguration::parse(&serde_json::to_vec(&activation.registry).unwrap()).unwrap(),
        RegistryConfiguration::V1(_)
    ));
}
