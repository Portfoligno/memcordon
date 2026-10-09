use memcordon_core::{
    workload_registry_v2::{LinuxExecutionIdentityV2, ProfileKindV2},
    workload_registry_v3::{
        ExclusiveIdentityDefinitionV3, RootLayoutDefinitionV1, RuntimeImageDefinitionV1,
        RuntimePrivatePolicyRegistryV3,
    },
};
use memcordon_readiness_verifier::linux_registry_digest;
use serde_json::{Value, json};

fn measured_vector() -> Value {
    let target = "x86_64-unknown-linux-gnu";
    let digest = "a".repeat(64);
    let image = |id: &str, path: &str| {
        json!({"format":"memcordon.runtime-image","revision":1,"image_id":id,"target":target,
        "entries":[{"kind":"regular","path":path,"sha256":digest,"size":1,"executable":true}],
        "entrypoints":[{"id":id,"path":path}],"library_directories":[],"startup_environment":[]})
    };
    let runtime = image("runtime", "bin/runtime");
    let input = image("input", "inputs/fixture");
    let runtime_ref = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(runtime.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let input_ref = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(input.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let identity = json!({"identity_id":"exclusive","enabled":true,"uid":65532,"gid":65532,"supplementary_groups":[65529,65528],
        "exclusive_use_policy":{"id":"exclusive-use","digest":"b".repeat(64)},"reservation_key":"reservation"});
    let identity_ref = serde_json::to_value(
        serde_json::from_value::<ExclusiveIdentityDefinitionV3>(identity.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let layout = json!({"format":"memcordon.root-layout","revision":1,"layout_id":"root","runtime_image":runtime_ref,"input_image":input_ref,
        "writable_roots":[{"id":"work","path":"work","byte_limit":4096,"generated_execution":true}],"output_files":["work/result"]});
    let layout_ref = serde_json::to_value(
        serde_json::from_value::<RootLayoutDefinitionV1>(layout.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let mut legacy_identity = json!({"reference":{"id":"older-account","semantic_digest":"0".repeat(64)},"enabled":true,"uid":65530,"gid":65530,
        "supplementary_groups":[65527,65526],"entrypoints":[{"id":"older-entry","absolute_path":"/opt/owned/older","sha256":digest,"size":1}]});
    legacy_identity["reference"]["semantic_digest"] = serde_json::to_value(
        serde_json::from_value::<LinuxExecutionIdentityV2>(legacy_identity.clone())
            .unwrap()
            .semantic_digest()
            .unwrap(),
    )
    .unwrap();
    let legacy = json!({"format":"memcordon.local-private-policy","revision":1,
        "profiles":[{"profile":profile,"reference":profile.reference(),"enabled":true}],"execution_identities":[legacy_identity],
        "grants":[{"id":"legacy","revision":1,"profile":profile.reference(),"ceiling":profile.ceiling(),"enabled":true,
            "callers":[{"platform":"linux","uid":65534}],"approved_plans":["c".repeat(64)],
            "execution_identity":{"kind":"administrator-profile","reference":legacy_identity["reference"]}}],"active_attempt_disposition":"drain-existing"});
    json!({"format":"memcordon.local-private-policy","revision":2,"legacy":legacy,"execution_identities":[identity],"images":[input,runtime],
        "root_layouts":[layout],"grants":[{"id":"current","revision":1,"enabled":true,"callers":[{"platform":"linux","uid":65534}],
            "approved_plans":["d".repeat(64),"e".repeat(64)],"profile":memcordon_core::workload_registry_v3::profile_reference(),
            "execution_identity":identity_ref,"runtime_image":runtime_ref,"input_image":input_ref,"root_layout":layout_ref}],
        "active_attempt_disposition":"drain-existing"})
}

#[test]
fn populated_native_codec_parity_and_reassociation_mutants() {
    // Dev-only native codec comparison: no package, policy or target executes.
    let value = measured_vector();
    let actual: RuntimePrivatePolicyRegistryV3 = serde_json::from_value(value.clone()).unwrap();
    actual.validate().unwrap();
    let expected = hex::encode(actual.canonical_digest().unwrap().bytes());
    assert_eq!(
        linux_registry_digest(&value, "x86_64-unknown-linux-gnu").unwrap(),
        expected
    );
    let mut reordered = value.clone();
    reordered["images"].as_array_mut().unwrap().reverse();
    reordered["execution_identities"][0]["supplementary_groups"]
        .as_array_mut()
        .unwrap()
        .reverse();
    reordered["grants"][0]["approved_plans"]
        .as_array_mut()
        .unwrap()
        .reverse();
    assert_eq!(
        linux_registry_digest(&reordered, "x86_64-unknown-linux-gnu").unwrap(),
        expected
    );
    let mut changed = value.clone();
    changed["grants"][0]["enabled"] = false.into();
    assert_ne!(
        linux_registry_digest(&changed, "x86_64-unknown-linux-gnu").unwrap(),
        expected
    );
    changed = value.clone();
    changed["images"][0]["entries"][0]["sha256"] = "f".repeat(64).into();
    assert_ne!(
        linux_registry_digest(&changed, "x86_64-unknown-linux-gnu").unwrap(),
        expected
    );
    changed = value.clone();
    changed["legacy"]["execution_identities"][0]["entrypoints"][0]["size"] = 2.into();
    assert_ne!(
        linux_registry_digest(&changed, "x86_64-unknown-linux-gnu").unwrap(),
        expected
    );
    changed = value.clone();
    changed["grants"][0]["unbound_authority"] = true.into();
    assert!(linux_registry_digest(&changed, "x86_64-unknown-linux-gnu").is_err());
    changed = value.clone();
    changed["grants"][0]["callers"] =
        json!([{"platform":"linux","uid":65534},{"platform":"linux","uid":65534}]);
    assert!(linux_registry_digest(&changed, "x86_64-unknown-linux-gnu").is_err());
    assert!(linux_registry_digest(&value, "aarch64-unknown-linux-gnu").is_err());
}
