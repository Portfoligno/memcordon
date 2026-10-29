use memcordon_readiness_verifier::{current::windows::terminal_retired_digest, sha256};
use serde_json::json;

#[test]
fn independent_retired_wire_encoding_matches_actual_native_ack_frame_order() {
    let value = json!({"kind":"terminal-retired-v2","schema_version":2,"attempt_id":"01".repeat(32),"nonce":"original native nonce","request_sha256":"02".repeat(32),"terminal_response_sha256":"03".repeat(32),"disposition":"posttarget","provider_generation":"generation","original_boot_id":"boot","launch_incarnation":"04".repeat(16),"job_identity":"05".repeat(32),"owner_manifest_sha256":"06".repeat(32),"retirement_proof_sha256":"07".repeat(32),"ledger_generation":"08".repeat(32),"completion":"retirement-complete"});
    let native: memcordon_core::WindowsProviderResponseV4 =
        serde_json::from_value(value.clone()).unwrap();
    assert_eq!(
        terminal_retired_digest(&value).unwrap(),
        sha256(&serde_json::to_vec(&native).unwrap())
    );
    let mut changed = value.clone();
    changed["nonce"] = json!("another original");
    assert_ne!(
        terminal_retired_digest(&changed).unwrap(),
        terminal_retired_digest(&value).unwrap()
    );
    let mut missing = value.clone();
    missing.as_object_mut().unwrap().remove("ledger_generation");
    assert!(terminal_retired_digest(&missing).is_err());
    let mut wrong = value.clone();
    wrong["kind"] = json!("terminal");
    assert!(terminal_retired_digest(&wrong).is_err());
}
