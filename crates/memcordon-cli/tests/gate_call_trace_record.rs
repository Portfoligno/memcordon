#[path = "../src/bin/consumer_readiness_windows/gate_call_trace_record.rs"]
mod record;

use record::{NativeEntry, NativeTrace, diagnostic};

fn trace() -> NativeTrace {
    let mut trace = NativeTrace {
        version: 1,
        setup_stage: 1,
        thread_count: 1,
        thread_limit: 1,
        attached_directory: 1,
        attached_event: 1,
        armed_call_count: 1,
        called: 1,
        outer_error: 5,
        count: 1,
        clock_live: 1,
        ..NativeTrace::default()
    };
    trace.entries[0] = NativeEntry {
        sequence: 1,
        operation: 1,
        thread_id: 19,
        desired_access: 3,
        attributes_length: 48,
        root_is_null: 1,
        arguments_readable: 1,
        name_readable: 1,
        reported_name_bytes: 8,
        copied_name_units: 4,
        entered: 1,
        returned: 1,
        native_status: 0xc0000022u32 as i32,
        output_handle_readable: 1,
        ..NativeEntry::default()
    };
    // Preserve raw UTF-16 including an unpaired surrogate, not a lossy string.
    trace.entries[0].name[..4].copy_from_slice(&[92, 0xd800, 0, 0xffff]);
    trace
}

#[test]
fn raw_call_fields_and_outer_failure_remain_diagnostic_only() {
    let value = diagnostic(&trace());
    assert_eq!(value["outer_error"], 5);
    assert_eq!(value["entries"][0]["native_status"], 0xc0000022u32 as i32);
    assert_eq!(
        value["entries"][0]["name_utf16"],
        serde_json::json!([92, 0xd800, 0, 0xffff])
    );
    assert_eq!(value["acceptance_authority"], false);
    assert_eq!(value["target_identity_proved"], false);
    assert_eq!(value["invalid_record"], false);
    assert_eq!(value["coverage_inconclusive"], false);
    assert!(serde_json::to_vec(&value).unwrap().len() <= record::RECORD_BYTES);
}

#[test]
fn coverage_requires_single_call_complete_fields_and_bounded_threads() {
    for mutation in 0..9 {
        let mut value = trace();
        match mutation {
            0 => value.armed_call_count = 2,
            1 => value.thread_count = 2,
            2 => value.entries[0].entered = 0,
            3 => value.entries[0].returned = 0,
            4 => value.entries[0].reported_name_bytes = 9,
            5 => value.entries[0].name_truncated = 1,
            6 => value.entries[0].name_readable = 0,
            7 => value.entries[0].copied_name_units = 3,
            _ => value.entries[0].name_malformed = 1,
        }
        let rendered = diagnostic(&value);
        assert_eq!(
            rendered["coverage_inconclusive"], true,
            "mutation {mutation}"
        );
        assert_eq!(rendered["outer_error"], 5);
        assert_eq!(rendered["acceptance_authority"], false);
    }
    // A fully recorded denied native call is not malformed merely for denying.
    assert_eq!(diagnostic(&trace())["invalid_record"], false);
    let mut denied = trace();
    denied.entries[0].output_handle_readable = 0;
    assert_eq!(diagnostic(&denied)["coverage_inconclusive"], false);
    denied.entries[0].native_status = 0;
    assert_eq!(diagnostic(&denied)["coverage_inconclusive"], true);
}

#[test]
fn overflow_partial_and_malformed_records_cannot_claim_complete_coverage() {
    let mut value = trace();
    value.count = u32::MAX;
    value.overflow = 1;
    value.incomplete = 1;
    value.entries[0].copied_name_units = u32::MAX;
    value.entries[0].name_truncated = 1;
    value.entries[0].reported_name_bytes = 513;
    value.entries[0].name_malformed = 1;
    value.entries[0].returned = 0;
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_record"], true);
    assert_eq!(rendered["entries"].as_array().unwrap().len(), 8);
    assert_eq!(
        rendered["entries"][0]["name_utf16"]
            .as_array()
            .unwrap()
            .len(),
        256
    );
    assert!(rendered["entries"][0]["native_status"].is_null());
    assert_eq!(rendered["incomplete"], 1);
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    for mutation in [0, 1, 2] {
        let mut value = trace();
        match mutation {
            0 => value.entries[0].operation = 99,
            1 => value.entries[0].sequence = 2,
            _ => value.entries[0].root_is_null = 2,
        }
        assert_eq!(diagnostic(&value)["invalid_record"], true);
    }
}

#[test]
fn missing_trace_and_maximum_names_keep_error_and_bounds() {
    let absent = diagnostic(&NativeTrace::default());
    assert_eq!(absent["empty_or_incomplete_trace_is_inconclusive"], true);
    assert_eq!(absent["invalid_record"], true);
    let mut maximum = trace();
    maximum.count = 8;
    for (index, entry) in maximum.entries.iter_mut().enumerate() {
        *entry = NativeEntry {
            sequence: index as u32 + 1,
            operation: 2,
            copied_name_units: 256,
            reported_name_bytes: 512,
            name: [u16::MAX; 256],
            entered: 1,
            returned: 1,
            ..NativeEntry::default()
        };
    }
    let rendered = diagnostic(&maximum);
    assert_eq!(rendered["outer_error"], 5);
    assert_eq!(rendered["entries"].as_array().unwrap().len(), 8);
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(rendered["acceptance_authority"], false);
    let oversized = record::bounded_diagnostic(serde_json::json!({
        "called":1,"outer_opened":0,"outer_error":5,"extra":"x".repeat(record::RECORD_BYTES + 1)
    }));
    assert_eq!(oversized["outer_error"], 5);
    assert_eq!(oversized["coverage_inconclusive"], true);
    assert!(serde_json::to_vec(&oversized).unwrap().len() <= record::RECORD_BYTES);
}
