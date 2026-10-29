use memcordon_core::ProviderFailureDiagnosticV1;
use memcordon_readiness_verifier::{current::windows_diagnostics::validate_projection, sha256};
use serde_json::json;

#[test]
fn independent_diagnostic_commitment_matches_native_codec_and_rejects_substitution() {
    let mut value = json!({
        "schema_version":1,
        "provider_binding":{"generation":"native-generation","source_commit":"9e85dd6c20e81be68fd3a49ecaf3208eabf80cb1","runtime_manifest_sha256":sha256(b"manifest")},
        "attempt_id":sha256(b"attempt"),"request_sha256":sha256(b"request"),
        "diagnostic_sequence":2,"durable_through_sequence":1,
        "original":{"observed":{"event":{"sequence":1,"origin":"launcher","category":"launch","operation":"create-target","code":"target-create","native_code":{"win32":5},"observed_phase":"before-authorization","safe_detail":"no-additional-detail","detail_redacted":false,"detail_truncated":false,"terminalization_reference":"first-error"}}},
        "secondary":[{"sequence":2,"origin":"record-writer","category":"persistence","operation":"store-record","code":"record-io","native_code":{"errno":-1},"observed_phase":"terminalizing","safe_detail":{"count-and-limit":{"observed":9,"limit":8}},"detail_redacted":true,"detail_truncated":false,"terminalization_reference":{"secondary-error":{"index":0}}}],
        "loss":{"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":true,"writer_unavailable":false},
        "projection_sha256":sha256(b"placeholder")
    });
    let native: ProviderFailureDiagnosticV1 = serde_json::from_value(value.clone()).unwrap();
    value["projection_sha256"] = serde_json::to_value(native.canonical_digest()).unwrap();
    validate_projection(&value).unwrap();
    for field in ["attempt_id", "request_sha256"] {
        let mut changed = value.clone();
        changed[field] = json!(sha256(b"foreign"));
        assert!(validate_projection(&changed).is_err(), "{field}");
    }
    let mut changed = value.clone();
    changed["original"]["observed"]["event"]["native_code"] = json!({"win32":6});
    assert!(validate_projection(&changed).is_err());
    let mut changed = value.clone();
    changed["secondary"][0]["sequence"] = json!(1);
    let native: ProviderFailureDiagnosticV1 = serde_json::from_value(changed.clone()).unwrap();
    changed["projection_sha256"] = serde_json::to_value(native.canonical_digest()).unwrap();
    assert!(
        validate_projection(&changed).is_err(),
        "rehashing cannot hide event reordering"
    );
}
