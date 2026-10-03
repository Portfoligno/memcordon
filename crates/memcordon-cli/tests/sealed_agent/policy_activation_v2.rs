use crate::policy_registry::{
    Activation, ActivationV2, RegistryConfiguration, VersionedActivation,
};
use memcordon_core::workload_contract::{Nonce128, PolicyEpoch};
use memcordon_core::workload_registry::{GrantChangeDisposition, RuntimePolicyRegistry};
use memcordon_core::workload_registry_v2::{
    ProfileKindV2, RuntimePrivatePolicyRegistry, RuntimePrivateProfileDefinition,
};
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

fn registry() -> RuntimePrivatePolicyRegistry {
    let mut profiles = BoundedVec::default();
    for (profile, enabled) in [
        (ProfileKindV2::LinuxUnixCreateV1, true),
        (ProfileKindV2::LinuxTcp4PrivateV1, false),
    ] {
        profiles
            .try_push(RuntimePrivateProfileDefinition {
                profile,
                reference: profile.reference(),
                enabled,
            })
            .unwrap();
    }
    RuntimePrivatePolicyRegistry {
        format: "memcordon.local-private-policy".into(),
        revision: 1,
        profiles,
        execution_identities: BoundedVec::default(),
        grants: BoundedVec::default(),
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    }
}

fn activation() -> ActivationV2 {
    let registry = registry();
    ActivationV2 {
        format: "memcordon.local-private-activation".into(),
        revision: 1,
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
fn named_private_policy_projects_only_explicit_baseline_grants() {
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
    value["revision"] = serde_json::json!(2);
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(activation()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let duplicate = br#"{"format":"memcordon.local-private-activation","revision":1,"revision":1}"#;
    assert!(VersionedActivation::parse(duplicate).is_err());
    assert!(RegistryConfiguration::parse(duplicate).is_err());
}

#[test]
fn private_journal_descriptive_nonce_is_revoked_once_and_later_drain_cannot_clear_it() {
    use crate::policy_registry::{VersionedLiveBinding, next_revocations_versioned};
    use memcordon_core::workload_admission_v2::RuntimePrivateAdmissionSnapshot;
    use memcordon_core::workload_contract::WorkloadContractV2;
    use memcordon_core::workload_registry::CallerSelector;
    let request = WorkloadContractV2::parse(include_bytes!(
        "../../../../fuzz/corpus/workload-request/baseline-v2.json"
    ))
    .unwrap();
    let metadata = RuntimePrivateAdmissionSnapshot {
        format: "memcordon.private-admission-metadata".into(),
        revision: 1,
        request_sha256: memcordon_core::workload_codec::contract_digest_v2(&request).unwrap(),
        invocation_sha256: DiagnosticSha256::from_bytes([7; 32]),
        caller: CallerSelector::Linux { uid: 1000 },
        registry_digest: activation().registry_digest,
        epoch: request.expected_epoch.clone(),
        admission_nonce: Nonce128([9; 16]),
        profile_id: request.authorized_profile.clone(),
        request,
    };
    let metadata =
        RuntimePrivateAdmissionSnapshot::parse(&serde_json::to_vec(&metadata).unwrap()).unwrap();
    let live = vec![(
        "actual-private-attempt".into(),
        VersionedLiveBinding::Private(Box::new(metadata)),
    )];
    let revoked =
        next_revocations_versioned(None, GrantChangeDisposition::RevokeActive, &live).unwrap();
    assert_eq!(revoked.as_slice(), &[Nonce128([9; 16])]);
    let mut previous = activation().baseline_projection().unwrap();
    previous.revoked_admissions = revoked;
    let previous: Activation =
        serde_json::from_slice(&serde_json::to_vec(&previous).unwrap()).unwrap();
    assert_eq!(
        next_revocations_versioned(
            Some(&previous),
            GrantChangeDisposition::DrainExisting,
            &live
        )
        .unwrap()
        .as_slice(),
        &[Nonce128([9; 16])]
    );
    let mut duplicate = live.clone();
    duplicate.extend(live);
    assert_eq!(
        next_revocations_versioned(
            Some(&previous),
            GrantChangeDisposition::DrainExisting,
            &duplicate
        )
        .unwrap()
        .as_slice()
        .len(),
        1
    );
    assert!(
        next_revocations_versioned(Some(&previous), GrantChangeDisposition::DrainExisting, &[])
            .unwrap()
            .as_slice()
            .is_empty()
    );
}

#[test]
fn named_baseline_activation_is_distinct_from_private_activation() {
    let registry = RuntimePolicyRegistry {
        format: "memcordon.local-policy".into(),
        revision: 1,
        profiles: BoundedVec::default(),
        grants: BoundedVec::default(),
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    let activation = Activation {
        format: "memcordon.local-activation".into(),
        revision: 1,
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

#[test]
fn numeric_or_saved_qualification_documents_cannot_activate() {
    let mut value = serde_json::to_value(activation()).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("format");
    object.remove("revision");
    object.insert("schema_version".into(), serde_json::json!(2));
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(registry()).unwrap();
    value["profiles"][0]["qualification_digest"] = serde_json::json!("22".repeat(32));
    assert!(RegistryConfiguration::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(activation()).unwrap();
    value["format"] = serde_json::json!("memcordon.local-activation");
    assert!(VersionedActivation::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
