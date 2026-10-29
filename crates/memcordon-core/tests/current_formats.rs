use memcordon_core::{
    canonical_json::reject_duplicate_json_keys, discovery::CapabilitiesV3,
    workload_request::WorkloadRequestV1,
};

#[test]
fn current_named_capabilities_require_exact_profile_and_wire_identity() {
    let profile = serde_json::json!({"profile":"linux-private-workload-v1","supported":true,"installed":false,"currently_available":false,"limitations":[],"request":{"format":"memcordon.workload-request","revision":1},"result":{"format":"memcordon.result","revision":3}});
    let value = serde_json::json!({"format":"memcordon.capabilities","revision":3,"tool":{"name":"memcordon","version":"test"},"host":{"os":"linux","architecture":"x86_64"},"selected":null,"available":[],"unavailable":[],"requirement":{"kind":null,"met":false,"reason":"not installed"},"profiles":[profile]});
    assert!(CapabilitiesV3::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
    for changed in [
        {
            let mut v = value.clone();
            v["revision"] = 0.into();
            v
        },
        {
            let mut v = value.clone();
            v["format"] = "example.unsupported".into();
            v
        },
        {
            let mut v = value.clone();
            v["profiles"][0]["currently_available"] = true.into();
            v
        },
        {
            let mut v = value.clone();
            v["profiles"][0]["result"]["revision"] = 0.into();
            v
        },
        {
            let mut v = value.clone();
            v["profiles"][0]["profile"] = "example-unknown-profile".into();
            v
        },
        {
            let mut v = value.clone();
            let p = v["profiles"][0].clone();
            v["profiles"].as_array_mut().unwrap().push(p);
            v
        },
        {
            let mut v = value.clone();
            v["unrecognized_field"] = true.into();
            v
        },
    ] {
        assert!(
            CapabilitiesV3::parse(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "accepted altered capabilities {changed}"
        );
    }
}

#[test]
fn neutral_json_uniqueness_keeps_resource_decimal_values_and_rejects_duplicates() {
    reject_duplicate_json_keys(br#"{"threshold":0.5,"nested":{"value":1.25}}"#).unwrap();
    assert!(reject_duplicate_json_keys(br#"{"threshold":0.5,"threshold":0.75}"#).is_err());
    let invalid=br#"{"format":"memcordon.workload-request","revision":1.5,"runtime":{"kind":"windows-sealed","profile":"windows-sealed-current-token-v1"},"requirements":[]}"#;
    assert!(WorkloadRequestV1::parse(invalid).is_err());
}

#[test]
fn current_manifest_rejects_substituted_native_protocol_mechanism_and_target() {
    use memcordon_core::{
        runtime_components::{RuntimeComponentRecord, RuntimeComponentRole},
        runtime_manifest_v2::RuntimeManifestV2,
    };
    let components = vec![
        RuntimeComponentRecord {
            id: "cli".into(),
            path: "memcordon".into(),
            role: RuntimeComponentRole::PublicCli,
            size: 1,
            mode: 0o755,
            sha256: "a".repeat(64),
        },
        RuntimeComponentRecord {
            id: "sealed-agent".into(),
            path: "memcordon-sealed-agent".into(),
            role: RuntimeComponentRole::SealedAgent,
            size: 1,
            mode: 0o755,
            sha256: "b".repeat(64),
        },
    ];
    let manifest = RuntimeManifestV2::linux(
        "test".into(),
        "a".repeat(40),
        "aarch64-unknown-linux-gnu".into(),
        components,
        true,
    )
    .unwrap();
    let original = serde_json::to_value(manifest).unwrap();
    for changed in [
        {
            let mut value = original.clone();
            value["sealed"]["native_protocols"]["provider_contract"] = 255.into();
            value
        },
        {
            let mut value = original.clone();
            value["sealed"]["mechanism"] = "unknown-mechanism".into();
            value
        },
        {
            let mut value = original.clone();
            value["target"] = "unknown-unknown-linux-gnu".into();
            value
        },
    ] {
        assert!(RuntimeManifestV2::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    }
}
