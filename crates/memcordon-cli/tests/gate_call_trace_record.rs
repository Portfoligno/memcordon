#[path = "../src/bin/consumer_readiness_windows/gate_call_trace_record.rs"]
mod record;

use record::{IatRecord, NativeEntry, NativeTrace, SnapshotEntry, SnapshotSummary, diagnostic};

fn snapshot(count: u32) -> SnapshotSummary {
    let mut snapshot = SnapshotSummary {
        attempted: 1,
        captured: 1,
        walk_completed: 1,
        entry_count: count,
        without_terminated_count: count,
        detail_count: count.min(8),
        detail_truncated: u32::from(count > 8),
        ..SnapshotSummary::default()
    };
    for (index, detail) in snapshot.details.iter_mut().take(count as usize).enumerate() {
        *detail = SnapshotEntry {
            process_id: 7,
            thread_id: index as u32 + 19,
            creation_time: 123,
            capture_time: 456,
            ..SnapshotEntry::default()
        };
    }
    snapshot
}

fn trace() -> NativeTrace {
    let mut trace = NativeTrace {
        version: 3,
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
        snapshot_source: 0,
        original_current_thread_id: 19,
        iat: IatRecord {
            owner_base: 0x1000,
            owner_size: 0x4000,
            original_open_event: 0x1100,
            normal_iat_start: 0x2000,
            normal_iat_end: 0x2100,
            directory_slot: 0x2000,
            event_slot: 0x2008,
            directory_original: 0x8000,
            event_original: 0x9000,
            strategy: 1,
            owner_pinned: 1,
            discovery_complete: 1,
            descriptor_count: 1,
            function_count: 2,
            directory_matches: 1,
            event_matches: 1,
            published_directory: 1,
            published_event: 1,
            protections_restored: 1,
            ..IatRecord::default()
        },
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
fn original_snapshot_states_and_cached_failure_evidence_remain_distinct() {
    for count in [0, 8, 9, 64] {
        let mut value = trace();
        value.setup_stage = 13;
        value.setup_error = 50;
        value.setup_reason = 2;
        value.thread_limit = 64;
        value.thread_count = count;
        value.first_snapshot = snapshot(count);
        value.second_snapshot = SnapshotSummary::default();
        if count > 0 {
            value.first_snapshot.details[0].flags = 1;
            value.first_snapshot.details[0].exit_time = 789;
            value.first_snapshot.details[0].exit_status = 123;
            value.first_snapshot.terminated_count = 1;
            value.first_snapshot.without_terminated_count -= 1;
        }
        let original = diagnostic(&value);
        assert_eq!(
            original["setup_reason_label"],
            "required-normal-import-missing"
        );
        assert_eq!(original["setup_error"], 50);
        assert_eq!(original["first_snapshot"]["entry_count"], count);
        assert_eq!(
            original["first_snapshot"]["retained_detail_count"],
            count.min(8)
        );
        assert_eq!(
            original["first_snapshot"]["detail_truncated"],
            u32::from(count > 8)
        );
        assert_eq!(original["second_snapshot"]["attempted"], 0);
        assert_eq!(original["coverage_inconclusive"], true);
        assert_eq!(original["invalid_record"], false);
        value.snapshot_source = 2;
        let cached = diagnostic(&value);
        assert_eq!(cached["first_snapshot"], original["first_snapshot"]);
        assert_eq!(cached["setup_error"], 50);
        assert_eq!(
            cached["snapshot_source_label"],
            "cached-original-installation-walks"
        );
    }
    let mut busy = trace();
    busy.setup_stage = 13;
    busy.setup_reason = 1;
    busy.snapshot_source = 0;
    busy.first_snapshot = SnapshotSummary::default();
    busy.second_snapshot = SnapshotSummary::default();
    assert_eq!(
        diagnostic(&busy)["setup_reason_label"],
        "installation-busy-original-evidence-unavailable"
    );
}

#[test]
fn partial_unknown_and_invalid_snapshot_fields_never_claim_complete_coverage() {
    for mutation in 0..8 {
        let mut value = trace();
        value.first_snapshot = snapshot(1);
        match mutation {
            0 => {
                value.first_snapshot.walk_completed = 0;
                value.first_snapshot.error = 5;
            }
            1 => {
                value.first_snapshot.details[0].flags = 2;
                value.first_snapshot.unknown_flags_count = 1;
            }
            2 => value.first_snapshot.entry_count = 65,
            3 => value.first_snapshot.detail_count = 9,
            4 => value.first_snapshot.without_terminated_count = u32::MAX,
            5 => value.first_snapshot.captured = 0,
            6 => value.first_snapshot.detail_truncated = 1,
            _ => value.setup_reason = 99,
        }
        let rendered = diagnostic(&value);
        assert_eq!(
            rendered["coverage_inconclusive"], true,
            "mutation {mutation}"
        );
        assert_eq!(rendered["outer_error"], 5);
        if mutation >= 2 {
            assert_eq!(rendered["invalid_record"], true);
        }
    }
    let mut partial = trace();
    partial.first_snapshot = snapshot(1);
    partial.first_snapshot.walk_completed = 0;
    partial.first_snapshot.error = 5;
    let rendered = diagnostic(&partial);
    assert_eq!(rendered["first_snapshot"]["partial"], true);
    assert_eq!(rendered["first_snapshot"]["error"], 5);
}

#[test]
fn scoped_entry_completeness_requires_valid_discovery_and_restored_publication() {
    for mutation in 0..21 {
        let mut value = trace();
        match mutation {
            0 => value.iat.directory_matches = 0,
            1 => value.iat.event_matches = 2,
            2 => value.iat.discovery_complete = 0,
            3 => value.iat.directory_slot = value.iat.event_slot,
            4 => value.iat.directory_slot += 1,
            5 => value.iat.event_slot = value.iat.normal_iat_end,
            6 => value.iat.owner_size = 1,
            7 => value.iat.original_open_event = 0,
            8 => value.iat.directory_original = 0,
            9 => value.iat.published_event = 0,
            10 => value.iat.protections_restored = 0,
            11 => value.iat.rollback_error = 5,
            12 => value.iat.protection_error = 5,
            13 => value.iat.callback_error = 50,
            14 => value.iat.strategy = 0,
            15 => value.iat.descriptor_count = 257,
            16 => value.iat.function_count = 16385,
            17 => value.iat.descriptor_count = 0,
            18 => value.iat.function_count = 1,
            19 => value.iat.normal_iat_end = 0x6000,
            _ => value.iat.normal_iat_start = 0,
        }
        let rendered = diagnostic(&value);
        assert_eq!(
            rendered["observed_entries_complete"], false,
            "mutation={mutation}"
        );
        assert_eq!(rendered["coverage_inconclusive"], true);
        assert_eq!(rendered["outer_error"], 5);
        assert_eq!(rendered["all_native_routes_observed"], false);
    }
    let mut value = trace();
    value.entries[0].operation = 2;
    let rendered = diagnostic(&value);
    assert_eq!(rendered["observed_entries_complete"], true);
    assert_eq!(rendered["absence_is_not_evidence"], true);
    assert_eq!(rendered["target_identity_proved"], false);
}

#[test]
fn maximum_snapshot_and_call_records_stay_bounded_and_keep_primary_setup_error() {
    let mut maximum = trace();
    maximum.first_snapshot = snapshot(64);
    maximum.second_snapshot = snapshot(64);
    for summary in [&mut maximum.first_snapshot, &mut maximum.second_snapshot] {
        for entry in &mut summary.details {
            entry.creation_time = u64::MAX;
            entry.exit_time = u64::MAX;
            entry.capture_time = u64::MAX;
            entry.raw_start_address = u64::MAX;
            entry.process_id = u32::MAX;
            entry.thread_id = u32::MAX;
            entry.exit_status = u32::MAX;
        }
    }
    maximum.count = 8;
    maximum.setup_error = 50;
    maximum.setup_stage = 13;
    maximum.setup_reason = 1;
    for (index, entry) in maximum.entries.iter_mut().enumerate() {
        *entry = NativeEntry {
            raw_root: u64::MAX,
            raw_output: u64::MAX,
            sequence: index as u32 + 1,
            operation: 2,
            thread_id: u32::MAX,
            desired_access: u32::MAX,
            attributes_length: u32::MAX,
            attributes_flags: u32::MAX,
            root_is_null: 1,
            arguments_readable: 1,
            name_readable: 1,
            copied_name_units: 256,
            reported_name_bytes: 512,
            name: [u16::MAX; 256],
            entered: 1,
            returned: 1,
            native_status: i32::MIN,
            output_handle_readable: 1,
            output_handle_returned: 1,
            ..NativeEntry::default()
        };
    }
    let rendered = diagnostic(&maximum);
    assert_eq!(rendered["setup_stage"], 13);
    assert_eq!(rendered["setup_error"], 50);
    assert_eq!(rendered["outer_error"], 5);
    assert_eq!(rendered["first_snapshot"]["retained_detail_count"], 8);
    assert_eq!(rendered["second_snapshot"]["retained_detail_count"], 8);
    assert_eq!(rendered["entries"].as_array().unwrap().len(), 8);
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    let oversized =
        record::bounded_diagnostic(serde_json::json!({"setup_stage":13,"setup_error":50,
        "setup_reason":1,"outer_error":5,"extra":"x".repeat(record::RECORD_BYTES+1)}));
    assert_eq!(oversized["setup_stage"], 13);
    assert_eq!(oversized["setup_error"], 50);
    assert_eq!(oversized["setup_reason"], 1);
    assert_eq!(oversized["outer_error"], 5);
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
    assert_eq!(value["coverage_inconclusive"], true);
    assert_eq!(value["observed_entries_complete"], true);
    assert_eq!(value["all_native_routes_observed"], false);
    assert_eq!(value["absence_is_not_evidence"], true);
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
            rendered["observed_entries_complete"], false,
            "mutation {mutation}"
        );
        assert_eq!(rendered["outer_error"], 5);
        assert_eq!(rendered["acceptance_authority"], false);
    }
    // A fully recorded denied native call is not malformed merely for denying.
    assert_eq!(diagnostic(&trace())["invalid_record"], false);
    let mut denied = trace();
    denied.entries[0].output_handle_readable = 0;
    assert_eq!(diagnostic(&denied)["observed_entries_complete"], true);
    denied.entries[0].native_status = 0;
    assert_eq!(diagnostic(&denied)["observed_entries_complete"], false);
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
