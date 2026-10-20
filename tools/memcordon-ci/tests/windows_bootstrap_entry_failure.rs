#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/windows/process_impl/bootstrap_entry_failure.rs"]
mod entry;

use entry::{EntryFailureV1, EntryRole, EntryStage, preserve_primary};

#[test]
fn entry_failure_wire_is_bound_to_original_nonce_and_truthful_stage() {
    let nonce = "ab".repeat(32);
    for stage in [
        EntryStage::SelfToken,
        EntryStage::ProcessIdentity,
        EntryStage::TokenEnvelope,
        EntryStage::TokenSnapshot,
    ] {
        let failure = EntryFailureV1::new(&nonce, stage, "original token operation failed");
        let decoded: EntryFailureV1 =
            serde_json::from_slice(&serde_json::to_vec(&failure).unwrap()).unwrap();
        assert_eq!(decoded, failure);
        assert_eq!(decoded.role, EntryRole::LoaderControl);
        assert_eq!(decoded.stage, stage);
        assert_eq!(
            decoded.native_code, None,
            "String errors cannot supply native status"
        );
        assert!(decoded.validate_for(&nonce).is_ok());
        assert!(decoded.validate_for(&"cd".repeat(32)).is_err());
    }
    let failure = EntryFailureV1::new(&nonce, EntryStage::SelfToken, "operation failed");
    for mutate in [
        |value: &mut EntryFailureV1| value.schema_version += 1,
        |value: &mut EntryFailureV1| value.nonce = "short".into(),
        |value: &mut EntryFailureV1| value.nonce = "AB".repeat(32),
        |value: &mut EntryFailureV1| value.native_code = Some(5),
        |value: &mut EntryFailureV1| value.detail = "x".repeat(1025),
    ] {
        let mut changed = failure.clone();
        mutate(&mut changed);
        assert!(changed.validate_for(&nonce).is_err());
    }
    for (field, value) in [("role", "holder"), ("stage", "loader-ready")] {
        let mut changed = serde_json::to_value(&failure).unwrap();
        changed[field] = serde_json::json!(value);
        assert!(serde_json::from_value::<EntryFailureV1>(changed).is_err());
    }
    let mut unknown = serde_json::to_value(&failure).unwrap();
    unknown["ready"] = serde_json::json!(true);
    assert!(serde_json::from_value::<EntryFailureV1>(unknown).is_err());
}

#[test]
fn entry_failure_detail_is_utf8_bounded_without_invented_native_code() {
    let nonce = "ab".repeat(32);
    let failure = EntryFailureV1::new(&nonce, EntryStage::TokenSnapshot, &"界".repeat(1024));
    assert!(failure.validate_for(&nonce).is_ok());
    assert!(failure.detail.len() <= 1024);
    assert!(failure.detail.chars().all(|character| character == '界'));
    assert!(failure.detail_truncated);
    assert_eq!(failure.native_code, None);
    let diagnostic = failure.diagnostic_detail();
    assert!(diagnostic.len() <= 1024);
    assert!(diagnostic.contains("TokenSnapshot"));
    assert!(diagnostic.contains("native_code=unavailable"));
    let exact = EntryFailureV1::new(&nonce, EntryStage::SelfToken, &"x".repeat(1024));
    assert_eq!(exact.detail.len(), 1024);
    assert!(!exact.detail_truncated);
}

#[test]
fn entry_report_preserves_original_error_and_bounds_only_secondary_detail() {
    let primary = "original self-token failure\nretained exactly".to_owned();
    assert_eq!(preserve_primary(primary.clone(), Ok(())), primary);
    let failed = preserve_primary(primary.clone(), Err("secondary pipe failure".into()));
    assert!(failed.starts_with(&format!(
        "{primary}; secondary bootstrap entry report failed:"
    )));
    assert!(failed.contains("secondary pipe failure"));
    let bounded = preserve_primary(primary.clone(), Err("界\n".repeat(2048)));
    let (actual_primary, secondary) = bounded
        .split_once("; secondary bootstrap entry report failed: ")
        .unwrap();
    assert_eq!(actual_primary, primary);
    assert!(secondary.len() <= 1024);
    assert!(
        !secondary.contains('\n'),
        "secondary control characters must be escaped"
    );
}
