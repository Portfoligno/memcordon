#[test]
fn authenticated_nonce_projection_preserves_all_bytes_and_original_array_wire() {
    let bytes = [
        0, 1, 0x80, 0xff, 0x10, 0xab, 0xcd, 0xef, 2, 3, 4, 5, 6, 7, 8, 9,
    ];
    let nonce = memcordon_core::workload_contract::Nonce128(bytes);
    let projected = memcordon_ci::consumer_readiness_ledger::admission_nonce_text(nonce);
    assert_eq!(projected, "000180ff10abcdef0203040506070809");
    assert_eq!(hex::decode(&projected).unwrap(), bytes);
    assert_eq!(
        serde_json::to_value(nonce).unwrap(),
        serde_json::json!(bytes)
    );
    assert!(serde_json::to_value(nonce).unwrap().is_array());
}
