use memcordon_core::{
    workload_contract::{WorkloadContractV1, WorkloadContractV2},
    workload_registry_v2::ProfileKindV2,
};
use memcordon_readiness_verifier::linux_frozen_request_digest;
use serde_json::json;

#[test]
fn frozen_v1_v2_separate_original_domains_and_semantic_references() {
    let profile = memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate;
    let v1 = json!({"schema_version":1,"workload_plan_digest":"a".repeat(64),"authorized_profile":profile.reference(),
        "authorization":{"grant_id":"installed-preserved","grant_revision":1,"approved_plan_digest":"a".repeat(64)},
        "ceiling":profile.ceiling(),"requirements":[],"endpoints":[],"expected_epoch":{"service_instance":vec![7u8;16],"revision":9}});
    let typed: WorkloadContractV1 = serde_json::from_value(v1.clone()).unwrap();
    let original = hex::encode(
        memcordon_core::workload_codec::contract_digest(&typed)
            .unwrap()
            .bytes(),
    );
    assert_eq!(linux_frozen_request_digest(&v1).unwrap(), original);
    let mut v2 = v1.clone();
    v2["schema_version"] = json!(2);
    v2["execution_identity"] = json!({"kind":"preserve-caller"});
    v2["authorized_profile"] = json!(ProfileKindV2::LinuxTcp4PrivateV1.reference());
    v2["ceiling"] = json!(ProfileKindV2::LinuxTcp4PrivateV1.ceiling());
    let typed: WorkloadContractV2 = serde_json::from_value(v2.clone()).unwrap();
    let newer = hex::encode(
        memcordon_core::workload_codec::contract_digest_v2(&typed)
            .unwrap()
            .bytes(),
    );
    assert_eq!(linux_frozen_request_digest(&v2).unwrap(), newer);
    assert_ne!(original, newer);
    let mut altered = v1.clone();
    altered["authorized_profile"]["semantic_digest"] = json!("b".repeat(64));
    assert!(linux_frozen_request_digest(&altered).is_err());
    altered = v1.clone();
    altered["ceiling"]["direct_socket_authority"] = json!("external-host-policy-accepted");
    assert!(linux_frozen_request_digest(&altered).is_err());
    altered = v2.clone();
    altered["execution_identity"] = json!({"kind":"administrator-profile","reference":{"id":"installed-delegated","semantic_digest":"c".repeat(64)}});
    assert!(linux_frozen_request_digest(&altered).is_err());
    altered = v2.clone();
    altered["authorization"]["approved_plan_digest"] = json!("d".repeat(64));
    assert!(linux_frozen_request_digest(&altered).is_err());
    altered = v2.clone();
    altered["expected_epoch"]["revision"] = json!(10);
    assert_ne!(linux_frozen_request_digest(&altered).unwrap(), newer);
    altered = v1.clone();
    altered["execution_identity"] = json!({"kind":"preserve-caller"});
    assert!(linux_frozen_request_digest(&altered).is_err());
}
