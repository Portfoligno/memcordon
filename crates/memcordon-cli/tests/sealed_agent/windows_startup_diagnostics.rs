use super::*;

#[test]
fn original_startup_cause_round_trips_with_code_and_process_identity() {
    let bytes = encode_failure(19, "policy startup lease: access denied", 2000).unwrap();
    let rendered = decode_failure(&bytes, 19, 100, 2100).unwrap();
    let failure: Failure = serde_json::from_str(&rendered).unwrap();
    assert_eq!(failure.detail, "policy startup lease: access denied");
    assert_eq!(failure.process_id, std::process::id());
    assert!(!failure.truncated);
    assert!(decode_failure(&bytes, 20, 100, 2100).is_err());
    assert!(decode_failure(&bytes, 19, 100, 5000).is_err());
    assert!(decode_failure(&bytes, 19, 100, 1999).is_err());
}

#[test]
fn original_startup_cause_is_utf8_and_json_escape_bounded() {
    for detail in ["界".repeat(DETAIL_BYTES), "\0".repeat(DETAIL_BYTES + 1)] {
        let bytes = encode_failure(19, &detail, 2000).unwrap();
        assert!(bytes.len() <= RECORD_BYTES);
        let rendered = decode_failure(&bytes, 19, 0, 2000).unwrap();
        let failure: Failure = serde_json::from_str(&rendered).unwrap();
        assert!(failure.detail.len() <= DETAIL_BYTES);
        assert!(detail.starts_with(&failure.detail));
        assert!(failure.truncated);
    }
    assert!(decode_failure(&vec![b' '; RECORD_BYTES + 1], 19, 0, 2000).is_err());
}
