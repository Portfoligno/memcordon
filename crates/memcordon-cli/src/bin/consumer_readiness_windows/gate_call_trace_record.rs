//! Bounded control-child telemetry. Raw handle numbers never establish identity.

pub const ENTRY_LIMIT: usize = 8;
pub const NAME_UNITS: usize = 256;
pub const RECORD_BYTES: usize = 24 * 1024;
pub const SNAPSHOT_DETAILS: usize = 8;

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct SnapshotEntry {
    pub creation_time: u64,
    pub exit_time: u64,
    pub capture_time: u64,
    pub raw_start_address: u64,
    pub process_id: u32,
    pub thread_id: u32,
    pub flags: u32,
    pub exit_status: u32,
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct SnapshotSummary {
    pub attempted: u32,
    pub captured: u32,
    pub walk_completed: u32,
    pub error: u32,
    pub entry_count: u32,
    pub terminated_count: u32,
    pub without_terminated_count: u32,
    pub unknown_flags_count: u32,
    pub detail_count: u32,
    pub detail_truncated: u32,
    pub details: [SnapshotEntry; SNAPSHOT_DETAILS],
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct NativeEntry {
    pub raw_root: u64,
    pub raw_output: u64,
    pub sequence: u32,
    pub operation: u32,
    pub thread_id: u32,
    pub desired_access: u32,
    pub attributes_length: u32,
    pub attributes_flags: u32,
    pub root_is_null: u32,
    pub arguments_readable: u32,
    pub name_readable: u32,
    pub reported_name_bytes: u32,
    pub copied_name_units: u32,
    pub name_malformed: u32,
    pub name_truncated: u32,
    pub entered: u32,
    pub returned: u32,
    pub native_status: i32,
    pub output_handle_readable: u32,
    pub output_handle_returned: u32,
    pub name: [u16; NAME_UNITS],
}

impl Default for NativeEntry {
    fn default() -> Self {
        Self {
            raw_root: 0,
            raw_output: 0,
            sequence: 0,
            operation: 0,
            thread_id: 0,
            desired_access: 0,
            attributes_length: 0,
            attributes_flags: 0,
            root_is_null: 0,
            arguments_readable: 0,
            name_readable: 0,
            reported_name_bytes: 0,
            copied_name_units: 0,
            name_malformed: 0,
            name_truncated: 0,
            entered: 0,
            returned: 0,
            native_status: 0,
            output_handle_readable: 0,
            output_handle_returned: 0,
            name: [0; NAME_UNITS],
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug, Default)]
pub struct NativeTrace {
    pub version: u32,
    pub setup_stage: u32,
    pub setup_error: u32,
    pub attached_directory: u32,
    pub attached_event: u32,
    pub armed_call_count: u32,
    pub count: u32,
    pub overflow: u32,
    pub incomplete: u32,
    pub called: u32,
    pub outer_opened: u32,
    pub outer_error: u32,
    pub thread_count: u32,
    pub thread_limit: u32,
    pub clock_live: u32,
    pub lifetime_policy: u32,
    pub setup_reason: u32,
    pub original_current_thread_id: u32,
    pub snapshot_source: u32,
    pub reserved: u32,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub original_cutoff_qpc: u64,
    pub first_snapshot: SnapshotSummary,
    pub second_snapshot: SnapshotSummary,
    pub entries: [NativeEntry; ENTRY_LIMIT],
}

const _: () = {
    assert!(std::mem::size_of::<NativeEntry>() == 600);
    assert!(std::mem::offset_of!(NativeEntry, name) == 88);
    assert!(std::mem::size_of::<SnapshotEntry>() == 48);
    assert!(std::mem::offset_of!(SnapshotEntry, process_id) == 32);
    assert!(std::mem::size_of::<SnapshotSummary>() == 424);
    assert!(std::mem::offset_of!(SnapshotSummary, details) == 40);
    assert!(std::mem::size_of::<NativeTrace>() == 5752);
    assert!(std::mem::offset_of!(NativeTrace, first_snapshot) == 104);
    assert!(std::mem::offset_of!(NativeTrace, entries) == 952);
};

fn snapshot(summary: &SnapshotSummary) -> (serde_json::Value, bool, bool) {
    use serde_json::json;
    let invalid = [
        summary.attempted,
        summary.captured,
        summary.walk_completed,
        summary.detail_truncated,
    ]
    .into_iter()
    .any(|flag| flag > 1)
        || summary.entry_count > 64
        || summary.detail_count > SNAPSHOT_DETAILS as u32
        || summary.detail_count != summary.entry_count.min(SNAPSHOT_DETAILS as u32)
        || summary
            .terminated_count
            .checked_add(summary.without_terminated_count)
            != Some(summary.entry_count)
        || summary.unknown_flags_count > summary.entry_count
        || summary.captured > summary.attempted
        || summary.walk_completed > summary.captured
        || (summary.entry_count > 0 && summary.captured != 1)
        || summary.detail_truncated != u32::from(summary.entry_count > SNAPSHOT_DETAILS as u32);
    let inconclusive = invalid
        || summary.attempted != 1
        || summary.captured != 1
        || summary.walk_completed != 1
        || summary.error != 0
        || summary.unknown_flags_count != 0;
    let details: Vec<_> = summary.details.iter().take((summary.detail_count as usize).min(SNAPSHOT_DETAILS)).map(|entry| json!({
        "process_id":entry.process_id,"thread_id":entry.thread_id,
        "creation_time":entry.creation_time,"exit_time":entry.exit_time,"capture_time":entry.capture_time,
        "raw_flags":entry.flags,"exit_status":entry.exit_status,"opaque_start_address":entry.raw_start_address,
        "terminated_bit_set":entry.flags & 1 != 0
    })).collect();
    (
        json!({"attempted":summary.attempted,"captured":summary.captured,"walk_completed":summary.walk_completed,
        "error":summary.error,"entry_count":summary.entry_count,"terminated_bit_count":summary.terminated_count,
        "without_terminated_bit_count":summary.without_terminated_count,"unknown_flags_count":summary.unknown_flags_count,
        "retained_detail_count":summary.detail_count,"detail_truncated":summary.detail_truncated,
        "partial":summary.attempted == 1 && (summary.walk_completed != 1 || summary.error != 0),
        "invalid_record":invalid,"diagnostic_only":true,"held_identity_authority":false,"details":details}),
        invalid,
        inconclusive,
    )
}

/// Render only recorded values, retaining incomplete/invalid observations explicitly.
pub fn diagnostic(trace: &NativeTrace) -> serde_json::Value {
    use serde_json::json;
    let setup = match trace.setup_stage {
        0 => "not-attempted",
        1 => "ready",
        2 => "original-clock-refused",
        3 => "ntdll-export-unavailable",
        4 => "thread-snapshot-failed",
        5 => "thread-bound-exceeded",
        6 => "thread-open-or-owner-failed",
        7 => "transaction-begin-failed",
        8 => "thread-enlist-failed",
        9 => "directory-attach-failed",
        10 => "event-attach-failed",
        11 => "unaccounted-thread",
        12 => "commit-failed",
        13 => "setup-busy-or-unavailable",
        _ => "unknown-recorded-stage",
    };
    let reason = match trace.setup_reason {
        0 => "none-recorded",
        1 => "first-snapshot-not-single-thread",
        2 => "installation-busy-original-evidence-unavailable",
        _ => "unknown-recorded-reason",
    };
    let source = match trace.snapshot_source {
        0 => "unavailable-or-not-reached",
        1 => "original-installation-walks",
        2 => "cached-original-installation-walks",
        _ => "unknown-recorded-source",
    };
    let (first_snapshot, first_invalid, first_inconclusive) = snapshot(&trace.first_snapshot);
    let (second_snapshot, second_invalid, second_inconclusive) = snapshot(&trace.second_snapshot);
    let mut invalid = trace.version != 2
        || trace.count as usize > ENTRY_LIMIT
        || trace.setup_stage > 13
        || trace.lifetime_policy > 1
        || trace.armed_call_count > 1
        || trace.thread_count > trace.thread_limit
        || trace.setup_reason > 2
        || trace.snapshot_source > 2
        || trace.reserved != 0
        || first_invalid
        || second_invalid;
    let mut inconclusive = trace.count == 0
        || trace.overflow != 0
        || trace.incomplete != 0
        || trace.setup_stage != 1
        || trace.attached_directory != 1
        || trace.attached_event != 1
        || trace.armed_call_count != 1
        || trace.called != 1
        || trace.clock_live != 1
        || trace.snapshot_source == 0
        || first_inconclusive
        || second_inconclusive;
    invalid |= [
        trace.attached_directory,
        trace.attached_event,
        trace.overflow,
        trace.incomplete,
        trace.called,
        trace.outer_opened,
        trace.clock_live,
    ]
    .into_iter()
    .any(|flag| flag > 1);
    let entries: Vec<_> = trace.entries.iter().take((trace.count as usize).min(ENTRY_LIMIT))
        .enumerate().map(|(index, entry)| {
            let flags = [entry.root_is_null, entry.arguments_readable, entry.name_readable,
                entry.name_malformed, entry.name_truncated, entry.entered, entry.returned,
                entry.output_handle_readable, entry.output_handle_returned];
            let entry_invalid = flags.into_iter().any(|flag| flag > 1)
                || entry.copied_name_units as usize > NAME_UNITS
                || entry.sequence as usize != index + 1
                || !matches!(entry.operation, 1 | 2)
                || entry.returned > entry.entered
                || entry.name_malformed != 0 || entry.reported_name_bytes % 2 != 0
                || u64::from(entry.copied_name_units) * 2 > u64::from(entry.reported_name_bytes);
            let entry_inconclusive = entry_invalid || entry.entered != 1 || entry.returned != 1
                || entry.arguments_readable != 1 || entry.name_readable != 1
                || entry.name_truncated != 0
                || u64::from(entry.copied_name_units) * 2 != u64::from(entry.reported_name_bytes)
                || (entry.returned == 1 && entry.native_status >= 0 && entry.output_handle_readable != 1);
            invalid |= entry_invalid;
            inconclusive |= entry_inconclusive;
            json!({"sequence":entry.sequence,"operation_code":entry.operation,
                "thread_id":entry.thread_id,"desired_access":entry.desired_access,
                "attributes_length":entry.attributes_length,"attributes_flags":entry.attributes_flags,
                "root_is_null":entry.root_is_null,"opaque_raw_root":entry.raw_root,
                "opaque_raw_output":entry.raw_output,"arguments_readable":entry.arguments_readable,
                "name_readable":entry.name_readable,"reported_name_bytes":entry.reported_name_bytes,
                "copied_name_units":entry.copied_name_units,"name_malformed":entry.name_malformed,
                "name_truncated":entry.name_truncated,"name_utf16":&entry.name[..(entry.copied_name_units as usize).min(NAME_UNITS)],
                "entered":entry.entered,"returned":entry.returned,
                "native_status":if entry.returned == 1 {Some(entry.native_status)} else {None},
                "output_handle_readable":entry.output_handle_readable,
                "output_handle_returned":entry.output_handle_returned,"invalid_record":entry_invalid,
                "coverage_inconclusive":entry_inconclusive})
        }).collect();
    let value = json!({"context":"pre-handoff-control-child","diagnostic_only":true,
        "acceptance_authority":false,"target_identity_proved":false,
        "instrumented_context_may_perturb":true,"version":trace.version,
        "setup_stage":trace.setup_stage,"setup_stage_label":setup,"setup_error":trace.setup_error,
        "setup_reason":trace.setup_reason,"setup_reason_label":reason,
        "original_current_thread_id":trace.original_current_thread_id,"snapshot_source":trace.snapshot_source,"snapshot_source_label":source,
        "first_snapshot":first_snapshot,"second_snapshot":second_snapshot,
        "attached_directory":trace.attached_directory,"attached_event":trace.attached_event,
        "armed_call_count":trace.armed_call_count,"reported_count":trace.count,
        "overflow":trace.overflow,"incomplete":trace.incomplete,"invalid_record":invalid,
        "coverage_inconclusive":inconclusive || invalid,
        "called":trace.called,"outer_opened":trace.outer_opened,"outer_error":trace.outer_error,
        "thread_count":trace.thread_count,"thread_limit":trace.thread_limit,
        "clock_live":trace.clock_live,"lifetime_policy":trace.lifetime_policy,
        "hooks_retained_until_control_child_exit":trace.lifetime_policy == 1,
        "in_process_detachment_claimed":false,
        "started_qpc":trace.started_qpc,"finished_qpc":trace.finished_qpc,
        "original_cutoff_qpc":trace.original_cutoff_qpc,"entries":entries,
        "empty_or_incomplete_trace_is_inconclusive":true});
    bounded_diagnostic(value)
}

/// Apply the same cap after adding fixed control-context readback metadata.
pub fn bounded_diagnostic(value: serde_json::Value) -> serde_json::Value {
    use serde_json::json;
    if serde_json::to_writer(
        CappedWriter {
            remaining: RECORD_BYTES,
        },
        &value,
    )
    .is_ok()
    {
        value
    } else {
        json!({"context":"pre-handoff-control-child","diagnostic_only":true,
            "acceptance_authority":false,"target_identity_proved":false,
            "unavailable":"trace serialization exceeds bound","incomplete":true,"coverage_inconclusive":true,
            "setup_stage":value["setup_stage"].as_u64(),"setup_error":value["setup_error"].as_u64(),
            "setup_reason":value["setup_reason"].as_u64(),"original_current_thread_id":value["original_current_thread_id"].as_u64(),
            "snapshot_source":value["snapshot_source"].as_u64(),
            "called":value["called"].as_u64(),"outer_opened":value["outer_opened"].as_u64(),"outer_error":value["outer_error"].as_u64()})
    }
}

/// Counting sink: serialization cannot allocate an oversized output buffer.
struct CappedWriter {
    remaining: usize,
}

impl std::io::Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("trace serialization exceeds bound"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
