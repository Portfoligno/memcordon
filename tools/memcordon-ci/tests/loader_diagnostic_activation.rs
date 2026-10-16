use memcordon_ci::windows_policy_activation::refresh_contract;
use memcordon_core::workload_contract::*;
use memcordon_core::workload_registry::*;
use memcordon_core::{BoundedVec, DiagnosticSha256};
use std::num::NonZeroU64;

#[test]
fn diagnostic_uses_actual_epoch_without_changing_request_authority() {
    let mut profiles = BoundedVec::default();
    profiles
        .try_push(RuntimeProfileDefinition {
            profile: BaselineProfile::LinuxUnixCreate,
            reference: BaselineProfile::LinuxUnixCreate.reference(),
            enabled: true,
        })
        .unwrap();
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let mut callers = BoundedVec::default();
    callers
        .try_push(CallerSelector::Linux { uid: 1000 })
        .unwrap();
    let mut approved_plans = BoundedVec::default();
    approved_plans.try_push(digest.clone()).unwrap();
    let mut grants = BoundedVec::default();
    grants
        .try_push(PolicyGrantV1 {
            id: LogicalId::new("diagnostic-owned".into()).unwrap(),
            revision: NonZeroU64::MIN,
            profile: BaselineProfile::LinuxUnixCreate.reference(),
            ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
            enabled: true,
            callers,
            approved_plans,
        })
        .unwrap();
    let registry = RuntimePolicyRegistry {
        format: "memcordon.local-policy".into(),
        revision: 1,
        profiles,
        grants,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    let prior = WorkloadContractV1 {
        schema_version: ContractVersionOne::default(),
        workload_plan_digest: digest.clone(),
        authorized_profile: BaselineProfile::LinuxUnixCreate.reference(),
        authorization: AuthorizationRef {
            grant_id: LogicalId::new("diagnostic-owned".into()).unwrap(),
            grant_revision: NonZeroU64::MIN,
            approved_plan_digest: digest,
        },
        ceiling: BaselineProfile::LinuxUnixCreate.ceiling(),
        requirements: BoundedVec::default(),
        endpoints: BoundedVec::default(),
        expected_epoch: PolicyEpoch {
            service_instance: Nonce128([1; 16]),
            revision: NonZeroU64::MIN,
        },
    };
    let epoch = PolicyEpoch {
        service_instance: Nonce128([2; 16]),
        revision: NonZeroU64::new(2).unwrap(),
    };
    let activation = serde_json::json!({
        "format":"memcordon.local-activation", "revision":1,
        "registry":registry, "registry_digest":registry.canonical_digest().unwrap(),
        "epoch":epoch, "revoked_admissions":[]
    });
    let updated =
        refresh_contract(&prior, &registry, &serde_json::to_vec(&activation).unwrap()).unwrap();
    let mut expected = prior.clone();
    expected.expected_epoch = epoch;
    assert_eq!(updated, expected);
    assert_ne!(updated.expected_epoch, prior.expected_epoch);
    for (field, value) in [
        ("format", serde_json::json!("other")),
        ("revision", serde_json::json!(2)),
        ("registry_digest", serde_json::json!("00".repeat(32))),
        ("revoked_admissions", serde_json::json!(vec![vec![3; 16]])),
        ("epoch", serde_json::Value::Null),
        (
            "epoch",
            serde_json::json!({"service_instance":vec![2;16],"revision":0}),
        ),
    ] {
        let mut invalid = activation.clone();
        invalid[field] = value;
        assert!(
            refresh_contract(&prior, &registry, &serde_json::to_vec(&invalid).unwrap(),).is_err(),
            "accepted invalid {field}"
        );
    }
    let mut different = registry.clone();
    different.active_attempt_disposition = GrantChangeDisposition::RevokeActive;
    assert!(
        refresh_contract(
            &prior,
            &different,
            &serde_json::to_vec(&activation).unwrap(),
        )
        .is_err()
    );
    let mut absent = activation.clone();
    absent.as_object_mut().unwrap().remove("epoch");
    assert!(refresh_contract(&prior, &registry, &serde_json::to_vec(&absent).unwrap(),).is_err());
    let mut unknown = activation.clone();
    unknown["unrecognized_authority"] = serde_json::json!(true);
    assert!(refresh_contract(&prior, &registry, &serde_json::to_vec(&unknown).unwrap()).is_err());
}
