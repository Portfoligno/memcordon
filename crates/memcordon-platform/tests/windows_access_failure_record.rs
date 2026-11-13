#![cfg(feature = "test-support")]
use memcordon_platform::windows_access_failure_record::*;

fn spec() -> ConsumerSpec {
    let session_guid = [1; 16];
    ConsumerSpec {
        version: 1,
        object_name: "\\Device\\Owned\\probe.bin".encode_utf16().collect(),
        session_name: format!(
            "Memcordon-AccessFailure-{:032x}",
            u128::from_be_bytes(session_guid)
        ),
        session_guid,
        pid: 7,
        birth: 9,
        binding: Binding {
            cutoff_qpc: 1000,
            frequency: 10,
            attempt_sha256: [3; 32],
        },
    }
}
fn row() -> Row {
    Row {
        qpc: 50,
        pid: 7,
        tid: 11,
        access_mask: 1,
        object_type: "File".encode_utf16().collect(),
        object_name: "\\Device\\Owned\\probe.bin".encode_utf16().collect(),
        token_type: 2,
        impersonation_level: 2,
        session_id: 1,
        security_descriptor_revision: 1,
        security_descriptor_control: 0x8004,
        sensitive_fields: SensitiveField::ALL
            .into_iter()
            .map(|field| SanitizedField {
                field,
                in_type: 19,
                out_type: 0,
                count: 1,
                bytes: 12,
                sha256: [255; 32],
            })
            .collect(),
    }
}
fn complete() -> Observation {
    let mut value = Observation::new(spec());
    value.record(row()).unwrap();
    value.consumer_completed = true;
    value
}

#[test]
fn emission_requires_exact_binding_window_thread_name_mask_and_complete_consumer() {
    let value = complete();
    let path = row().object_name;
    assert!(value.probe_match(&spec(), 11, 40, 60, &path, 1).is_ok());
    assert!(value.probe_match(&spec(), 12, 40, 60, &path, 1).is_err());
    assert!(value.probe_match(&spec(), 11, 51, 60, &path, 1).is_err());
    assert!(value.probe_match(&spec(), 11, 40, 60, &path, 2).is_err());
    assert!(value.probe_match(&spec(), 11, 40, 60, &path, 0).is_err());
    let mut additional_rights = value.clone();
    additional_rights.rows[0].access_mask = 0x100001;
    assert_eq!(
        additional_rights
            .probe_match(&spec(), 11, 40, 60, &path, 1)
            .unwrap()
            .access_mask,
        0x100001
    );
    assert!(value.probe_match(&spec(), 11, 40, 60, &[1], 1).is_err());
    let mut different = spec();
    different.birth += 1;
    assert!(value.probe_match(&different, 11, 40, 60, &path, 1).is_err());
    let mut incomplete = value.clone();
    incomplete.close_trace_status = 6;
    assert!(
        incomplete
            .probe_match(&spec(), 11, 40, 60, &path, 1)
            .is_err()
    );
    let mut wrong_token = value.clone();
    wrong_token.rows[0].token_type = 1;
    assert!(
        wrong_token
            .probe_match(&spec(), 11, 40, 60, &path, 1)
            .is_err()
    );
    wrong_token.rows[0].token_type = 2;
    wrong_token.rows[0].impersonation_level = 1;
    assert!(
        wrong_token
            .probe_match(&spec(), 11, 40, 60, &path, 1)
            .is_err()
    );
    let mut ambiguous = value;
    ambiguous.record(row()).unwrap();
    assert!(
        ambiguous
            .probe_match(&spec(), 11, 40, 60, &path, 1)
            .is_err()
    );
}
#[test]
fn no_event_or_unsupported_history_is_not_coverage() {
    let mut value = Observation::new(spec());
    value.consumer_completed = true;
    let path = row().object_name;
    assert!(value.probe_match(&spec(), 11, 40, 60, &path, 1).is_err());
    value.record(row()).unwrap();
    value.matched_events += 1;
    value.unsupported_events = 1;
    assert!(value.validate().is_ok());
    assert!(value.probe_match(&spec(), 11, 40, 60, &path, 1).is_err());
    value.matched_events = 0;
    assert!(value.validate().is_err());
}
#[test]
fn bounded_sanitized_inventory_rejects_missing_duplicate_and_unbounded_fields() {
    assert!(validate_sid_extent(&[1, 0, 0, 0, 0, 0, 0, 5]).is_ok());
    assert!(validate_sid_extent(&[1, 1, 0, 0, 0, 0, 0, 5]).is_err());
    assert!(validate_sid_extent(&[1, 255, 0, 0, 0, 0, 0, 5]).is_err());
    let mut item = row();
    item.sensitive_fields.pop();
    assert!(item.validate(&spec()).is_err());
    let mut item = row();
    item.sensitive_fields[0] = item.sensitive_fields[1].clone();
    assert!(item.validate(&spec()).is_err());
    let mut item = row();
    item.sensitive_fields[0].bytes = 65537;
    assert!(item.validate(&spec()).is_err());
    let mut item = row();
    item.object_name = vec![0xd800];
    assert!(item.validate(&spec()).is_err());
    let mut value = Observation::new(spec());
    value.spec.object_name = vec![0xffff; 512];
    for _ in 0..5 {
        let mut item = row();
        item.object_name = vec![0xffff; 512];
        item.object_type = vec![0xffff; 64];
        value.record(item).unwrap();
    }
    assert_eq!(value.rows.len(), 4);
    assert_eq!(value.overflow, 1);
    value.validate().unwrap();
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(bytes.len() <= RECORD_BYTES);
    assert!(
        serde_json::from_slice::<Observation>(&bytes)
            .unwrap()
            .validate()
            .is_ok()
    );
    let mut wire = serde_json::to_value(row()).unwrap();
    wire["raw_sd"] = serde_json::json!([1, 2, 3]);
    assert!(serde_json::from_value::<Row>(wire).is_err());
}
