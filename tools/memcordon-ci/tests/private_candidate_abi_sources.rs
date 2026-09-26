use memcordon_ci::private_candidate_abi_facts::linux_abi_wait_matches;
use memcordon_ci::private_candidate_replay::CaseFactV1;
use memcordon_ci::private_case_semantics::CaseFactKindV1;

fn wire() -> serde_json::Value {
    serde_json::json!({
        "kind":"native-abi-v1",
        "sources": {
            "result_path":"observer/result.json", "request_path":"observer/request.json",
            "attempt_path":"observer/attempt.json",
            "attachments":["observer/request.bin","observer/report.bin","observer/stdio.bin","observer/observer.bin","observer/cleanup.bin"],
            "branches":{"architecture":"x86","x32_path":"family/x32-alternate.raw.json","i386_path":"family/i386-entry.raw.json"}
        }
    })
}

#[test]
fn native_abi_wire_preserves_original_sources_not_branch_verdicts() {
    let value = wire();
    let parsed: CaseFactV1 = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(parsed.kind(), CaseFactKindV1::Abi);
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    for field in ["branch_verified", "retirement_verified", "wait_status"] {
        let mut value = wire();
        value["sources"][field] = serde_json::json!(true);
        assert!(serde_json::from_value::<CaseFactV1>(value).is_err());
    }
    let mut value = wire();
    value["sources"]["attachments"] = serde_json::json!(["request.bin"]);
    assert!(serde_json::from_value::<CaseFactV1>(value).is_err());
}

#[test]
fn architecture_inventory_cannot_mix_compatibility_branches() {
    let mut value = wire();
    value["sources"]["branches"] = serde_json::json!({
        "architecture":"arm64", "arm32_path":"family/arm32-alternate.raw.json",
        "helper_bytes_path":"source/abi-helper.raw", "helper_metadata_path":"source/abi-helper-metadata.json"
    });
    assert!(serde_json::from_value::<CaseFactV1>(value.clone()).is_ok());
    value["sources"]["branches"]["i386_path"] = serde_json::json!("family/i386-entry.raw.json");
    assert!(serde_json::from_value::<CaseFactV1>(value).is_err());
}

#[test]
fn linux_wait_status_is_portable_and_preserves_core_flag() {
    assert!(linux_abi_wait_matches(0, 0));
    assert!(linux_abi_wait_matches(31, 31));
    assert!(linux_abi_wait_matches(31 | 128, 31));
    for status in [-1, 12, 9, 31 << 8, 255, 256, 65535] {
        assert!(!linux_abi_wait_matches(status, 31));
    }
    assert!(!linux_abi_wait_matches(31, 0));
    assert!(!linux_abi_wait_matches(127, 127));
}
