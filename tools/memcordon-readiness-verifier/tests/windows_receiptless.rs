//! Declared protocol-vector decoder tests, not native API observations.
use memcordon_readiness_verifier::validate_windows_receiptless_cause;
use serde_json::json;

#[test]
fn receiptless_cause_rejects_joint_original_replacement_and_secondary_relabeling() {
    let original = json!({"observed":{"event":{"sequence":1,"origin":"launcher","category":"monitor",
        "operation":"observe-process-identity","code":"process-inventory-observation","native_code":{"win32":1234},
        "observed_phase":"monitoring","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":null}}});
    let secondary = json!({"sequence":2,"origin":"launcher","category":"terminalization",
        "operation":"validate-terminal-response","code":"terminal-binding","native_code":null,
        "observed_phase":"terminalizing","safe_detail":"no-additional-detail","detail_redacted":true,
        "detail_truncated":false,"terminalization_reference":"first-error"});
    validate_windows_receiptless_cause(&original, &secondary).unwrap();
    let mut changed = original.clone();
    changed["observed"]["event"]["native_code"] = json!({"win32":6});
    assert!(validate_windows_receiptless_cause(&changed, &secondary).is_err());
    for (field, value) in [
        ("origin", json!("guardian-recovery")),
        ("observed_phase", json!("monitoring")),
        (
            "safe_detail",
            json!({"injected-windows-fault":{"fault":"resume"}}),
        ),
        ("detail_redacted", json!(false)),
        ("detail_truncated", json!(true)),
        ("terminalization_reference", json!(null)),
        ("native_code", json!({"win32":1234})),
    ] {
        let mut changed = secondary.clone();
        changed[field] = value;
        assert!(
            validate_windows_receiptless_cause(&original, &changed).is_err(),
            "{field}"
        );
    }
    let mut changed = secondary.clone();
    changed["native_retirement_observed"] = json!(true);
    assert!(validate_windows_receiptless_cause(&original, &changed).is_err());
}
