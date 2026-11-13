#![cfg(feature = "test-support")]
use memcordon_platform::windows_private_input_record::{
    Context, ObjectRole, RECORD_BYTES, expected_sddl, readback_diagnostic,
};
fn context() -> Context {
    Context {
        role: ObjectRole::Provider,
        object_index: Some(u32::MAX),
        directory: false,
        volume_serial: Some(7),
        file_index: Some(9),
    }
}
fn acl(mask: u32) -> Vec<u8> {
    let mut value = vec![2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0];
    value.extend(mask.to_le_bytes());
    value.extend([1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
    value
}
#[test]
fn explicit_file_policy_preserves_trustees_order_and_flags() {
    for directory in [false, true] {
        let flags = if directory { "OICI" } else { "" };
        assert_eq!(
            expected_sddl(directory, "S-1-5-21-42").unwrap(),
            format!(
                "D:P(A;{flags};FRFX;;;OW)(A;{flags};FA;;;S-1-5-21-42)(A;{flags};FRFX;;;RC)(A;{flags};FA;;;SY)"
            )
        );
    }
    for sid in [
        "SY",
        "S-1-5-1)(A;;FA;;;WD)",
        "S-1-05-1",
        "S-1-5-4294967296",
        "S-1-5",
    ] {
        assert!(expected_sddl(false, sid).is_err());
    }
}
#[test]
fn protection_and_raw_bytes_remain_independent_observations() {
    let expected = acl(0x1200a9);
    let equal = readback_diagnostic(&context(), &expected, &expected, 0x1000, 1);
    assert_eq!(equal["raw_acl_equal"], true);
    assert_eq!(equal["protection_missing"], false);
    assert_eq!(equal["expected"]["aces"][0]["mask"], 0x1200a9);
    assert_eq!(equal["context"]["role"], "provider");
    assert_eq!(equal["context"]["object_index"], u32::MAX);
    let unprotected = readback_diagnostic(&context(), &expected, &expected, 0, 1);
    assert_eq!(unprotected["raw_acl_equal"], true);
    assert_eq!(unprotected["protection_missing"], true);
    assert!(unprotected["first_differing_byte"].is_null());
    let changed = acl(0x1f01ff);
    let mismatch = readback_diagnostic(&context(), &expected, &changed, 0, 1);
    assert_eq!(mismatch["raw_acl_equal"], false);
    assert_eq!(mismatch["protection_missing"], true);
    assert_eq!(mismatch["first_differing_byte"], 12);
    assert_eq!(mismatch["acceptance_authority"], false);
    assert!(mismatch["expected"]["aces"][0].get("sid").is_none());
    // Type, inheritance flags, mask, trustee, and allocation bytes must all
    // remain visible to the strict gate, even if a semantic policy could match.
    for offset in [1, 8, 9, 12, 24] {
        let mut changed = expected.clone();
        changed[offset] ^= 1;
        let value = readback_diagnostic(&context(), &expected, &changed, 0x1000, 1);
        assert_eq!(value["raw_acl_equal"], false);
        assert_eq!(value["protection_missing"], false);
        assert_eq!(value["first_differing_byte"], offset);
    }
    let mut slack = expected.clone();
    slack.extend([0, 0, 0, 0]);
    let size = u16::try_from(slack.len()).unwrap();
    slack[2..4].copy_from_slice(&size.to_le_bytes());
    let value = readback_diagnostic(&context(), &expected, &slack, 0x1000, 1);
    assert_eq!(value["raw_acl_equal"], false);
    assert_eq!(value["observed"]["used_bytes"], expected.len());
}
#[test]
fn malformed_and_large_inputs_are_bounded_without_absence_or_equality_claims() {
    let expected = acl(1);
    for end in 0..expected.len() {
        let value = readback_diagnostic(&context(), &expected, &expected[..end], 0x1000, 1);
        assert_eq!(value["observed"]["status"], "malformed");
        assert_eq!(value["raw_acl_equal"], false);
        assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
    }
    let huge = vec![255; 65535];
    let value = readback_diagnostic(&context(), &huge, &huge, 0, 1);
    assert_eq!(value["observed"]["status"], "malformed");
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);

    let mut many = expected[..8].to_vec();
    for _ in 0..9 {
        many.extend_from_slice(&expected[8..]);
    }
    let size = u16::try_from(many.len()).unwrap();
    many[2..4].copy_from_slice(&size.to_le_bytes());
    many[4..6].copy_from_slice(&9u16.to_le_bytes());
    let value = readback_diagnostic(&context(), &expected, &many, 0x1000, 1);
    assert_eq!(value["observed"]["aces"].as_array().unwrap().len(), 8);
    assert_eq!(value["observed"]["aces_omitted"], 1);
    assert!(serde_json::to_vec(&value).unwrap().len() <= RECORD_BYTES);
    // Malformed SID data in an omitted row must still be diagnosed.
    let final_sid_count = many.len() - 11;
    many[final_sid_count] = 15;
    let value = readback_diagnostic(&context(), &expected, &many, 0x1000, 1);
    assert_eq!(value["observed"]["status"], "malformed");

    let mut unsupported = expected.clone();
    unsupported[8] = 0xff;
    let value = readback_diagnostic(&context(), &expected, &unsupported, 0x1000, 1);
    assert_eq!(
        value["observed"]["aces"][0]["status"],
        "unsupported-ace-type"
    );
}
