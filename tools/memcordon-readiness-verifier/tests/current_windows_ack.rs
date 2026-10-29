use memcordon_readiness_verifier::{current::windows::validate_terminal_authority, sha256};
use serde_json::json;

#[test]
fn current_ack_commits_actual_wire_bytes_and_exact_nested_native_attempt() {
    let terminal = json!({"schema_version":3,"attempt_id":"original","nonce":"original nonce","request_sha256":sha256(b"request"),"payload":{"kind":"recovered-closure"}});
    let mut response = terminal.clone();
    response["kind"] = json!("terminal");
    let bytes = serde_json::to_string(&response).unwrap();
    let delivery = json!({"attempt_id":terminal["attempt_id"],"nonce":terminal["nonce"],"request_sha256":terminal["request_sha256"],"terminal_sha256":sha256(bytes.as_bytes()),"retired_sha256":sha256(b"actual retirement acknowledgment"),"terminal_validated":true,"acknowledgement_observed":true});
    validate_terminal_authority(&terminal, &bytes, &delivery).unwrap();
    let mut replaced = terminal.clone();
    replaced["nonce"] = json!("different nonce");
    assert!(validate_terminal_authority(&replaced, &bytes, &delivery).is_err());
    let reformatted = serde_json::to_string_pretty(&response).unwrap();
    assert!(validate_terminal_authority(&terminal, &reformatted, &delivery).is_err());
    let mut unacknowledged = delivery.clone();
    unacknowledged["acknowledgement_observed"] = json!(false);
    assert!(validate_terminal_authority(&terminal, &bytes, &unacknowledged).is_err());
    let mut foreign = delivery.clone();
    foreign["attempt_id"] = json!("another attempt");
    assert!(validate_terminal_authority(&terminal, &bytes, &foreign).is_err());
    let mut forged = delivery.clone();
    forged["terminal_sha256"] = json!(sha256(b"another native frame"));
    assert!(validate_terminal_authority(&terminal, &bytes, &forged).is_err());
    let mut unvalidated = delivery.clone();
    unvalidated["terminal_validated"] = json!(false);
    assert!(validate_terminal_authority(&terminal, &bytes, &unvalidated).is_err());
    let mut unknown = delivery;
    unknown["schema_version"] = json!(1);
    assert!(validate_terminal_authority(&terminal, &bytes, &unknown).is_err());
}
