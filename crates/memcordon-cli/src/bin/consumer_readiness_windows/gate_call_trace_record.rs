//! Bounded control-child telemetry. Raw handle numbers never establish identity.

pub const ENTRY_LIMIT: usize = 8;
pub const NAME_UNITS: usize = 256;
pub const RECORD_BYTES: usize = 24 * 1024;

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
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub original_cutoff_qpc: u64,
    pub entries: [NativeEntry; ENTRY_LIMIT],
}

const _: () = {
    assert!(std::mem::size_of::<NativeEntry>() == 600);
    assert!(std::mem::offset_of!(NativeEntry, name) == 88);
    assert!(std::mem::size_of::<NativeTrace>() == 4888);
    assert!(std::mem::offset_of!(NativeTrace, entries) == 88);
};

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
    let mut invalid = trace.version != 1
        || trace.count as usize > ENTRY_LIMIT
        || trace.setup_stage > 13
        || trace.lifetime_policy > 1
        || trace.armed_call_count > 1
        || trace.thread_count > trace.thread_limit;
    let mut inconclusive = trace.count == 0
        || trace.overflow != 0
        || trace.incomplete != 0
        || trace.setup_stage != 1
        || trace.attached_directory != 1
        || trace.attached_event != 1
        || trace.armed_call_count != 1
        || trace.called != 1
        || trace.clock_live != 1;
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
