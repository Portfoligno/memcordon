use memcordon_readiness_verifier::{
    current::windows_component::verify_retained_binding_values, sha256,
};
use serde_json::{Value, json};

#[test]
fn retained_binding_requires_each_exact_single_native_substitution() {
    let envelope = br#"{"actual-token":"held native bytes"}"#;
    let identity = json!({"process_id":17,"creation_time_100ns":0});
    let record = json!({"schema_version":5,"record_revision":0,"terminal_response_json":null,"attempt_id":"01".repeat(32),"request_sha256":"02".repeat(32),"caller_process_identity":identity,"caller_token_sha256":sha256(envelope)});
    let baseline = json!({"attempt_id":record["attempt_id"],"nonce":"authenticated-request-nonce","request_sha256":record["request_sha256"],"process_identity":identity,"token_sha256":sha256(envelope),"accepted":true});
    let mut variants = Vec::new();
    for field in [
        "attempt-id",
        "request-sha256",
        "process-id",
        "process-birth",
        "token-sha256",
    ] {
        let mut row = baseline.clone();
        row["accepted"] = json!(false);
        row["changed_field"] = json!(field);
        match field {
            "attempt-id" => row["attempt_id"] = json!("05".repeat(32)),
            "request-sha256" => row["request_sha256"] = json!("06".repeat(32)),
            "process-id" => row["process_identity"]["process_id"] = json!(18),
            "process-birth" => row["process_identity"]["creation_time_100ns"] = json!(1),
            "token-sha256" => row["token_sha256"] = json!("07".repeat(32)),
            _ => unreachable!(),
        }
        variants.push(row);
    }
    let p = json!({"kind":"binding","caller_identity":identity,"caller_held_live":true,"baseline":baseline,"variants":variants,"record_revision_after":0,"terminal_published":false});
    verify_retained_binding_values(&p, &record, envelope).unwrap();
    for index in 0..5 {
        let mut changed = p.clone();
        changed["variants"][index]["nonce"] = json!("unreported second substitution");
        assert!(verify_retained_binding_values(&changed, &record, envelope).is_err());
    }
    let mut changed = p.clone();
    changed["variants"][1] = changed["variants"][0].clone();
    assert!(verify_retained_binding_values(&changed, &record, envelope).is_err());
    let mut changed = p.clone();
    changed["variants"].as_array_mut().unwrap().pop();
    assert!(verify_retained_binding_values(&changed, &record, envelope).is_err());
    assert!(verify_retained_binding_values(&p, &record, b"another native token envelope").is_err());
    let mut changed: Value = record.clone();
    changed["record_revision"] = json!(1);
    assert!(verify_retained_binding_values(&p, &changed, envelope).is_err());
}
