use memcordon_readiness_verifier::{current::windows_proof::validate_windows_proof_matrix, sha256};
use serde_json::{Value, json};

fn live() -> Value {
    let attempt = sha256(b"native attempt");
    let request = sha256(b"actual launch request");
    json!({"schema_version":3,"attempt_id":attempt,"nonce":"native nonce","request_sha256":request,
        "payload":{"kind":"execution","child_pid":143},
        "process_observation":{"root_identity":{"process_id":143,"creation_time_100ns":123456}},
        "retirement_proof":{"schema_version":3,"source":"live-native","attempt_id":attempt,
            "nonce":"native nonce","request_sha256":request,"provider_generation":"installed generation",
            "launch_incarnation":"original launcher","original_boot_id":"original boot","job_identity":"held Job",
            "owner_manifest_sha256":sha256(b"actual eleven native owners"),
            "guardian_receipt_sha256":null,"current_boot_id":null,"capability_extinction":null,
            "target_completion_observed":true,"native_job_empty_observed":true,"relay_closure_observed":true,
            "guardian_completion_observed":true,"owner_capabilities_closed":true,"launch_gate_closed":true}})
}

#[test]
fn current_live_retirement_requires_actual_native_completion_and_exact_binding() {
    let valid = live();
    validate_windows_proof_matrix(&valid).unwrap();
    for field in [
        "target_completion_observed",
        "native_job_empty_observed",
        "relay_closure_observed",
        "guardian_completion_observed",
        "owner_capabilities_closed",
        "launch_gate_closed",
    ] {
        let mut invalid = valid.clone();
        invalid["retirement_proof"][field] = json!(false);
        assert!(
            validate_windows_proof_matrix(&invalid).is_err(),
            "accepted missing {field}"
        );
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        let mut invalid = valid.clone();
        invalid["retirement_proof"][field] = json!(sha256(b"another attempt"));
        assert!(
            validate_windows_proof_matrix(&invalid).is_err(),
            "accepted substituted {field}"
        );
    }
}

#[test]
fn current_retirement_rejects_unknown_fields_and_recovery_fact_substitution() {
    let valid = live();
    for revision in [1, 2, 4] {
        let mut invalid = valid.clone();
        invalid["retirement_proof"]["schema_version"] = json!(revision);
        assert!(validate_windows_proof_matrix(&invalid).is_err());
    }
    let mut unknown = valid.clone();
    unknown["retirement_proof"]["unknown_field"] = json!(true);
    assert!(validate_windows_proof_matrix(&unknown).is_err());
    let mut foreign_root = valid.clone();
    foreign_root["payload"]["child_pid"] = json!(144);
    assert!(validate_windows_proof_matrix(&foreign_root).is_err());
    let mut recovery = valid.clone();
    recovery["retirement_proof"]["guardian_receipt_sha256"] = json!(sha256(b"recovery receipt"));
    assert!(validate_windows_proof_matrix(&recovery).is_err());
    let mut extinction = valid.clone();
    extinction["retirement_proof"]["source"] = json!("capability-extinction");
    assert!(validate_windows_proof_matrix(&extinction).is_err());
}
