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
pub struct IatRecord {
    pub owner_base: u64,
    pub original_open_event: u64,
    pub normal_iat_start: u64,
    pub normal_iat_end: u64,
    pub directory_slot: u64,
    pub event_slot: u64,
    pub directory_original: u64,
    pub event_original: u64,
    pub strategy: u32,
    pub owner_pinned: u32,
    pub owner_size: u32,
    pub owner_timestamp: u32,
    pub discovery_complete: u32,
    pub descriptor_count: u32,
    pub function_count: u32,
    pub directory_matches: u32,
    pub event_matches: u32,
    pub published_directory: u32,
    pub published_event: u32,
    pub protections_restored: u32,
    pub rollback_error: u32,
    pub protection_error: u32,
    pub callback_error: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RouteNode {
    pub owner_base: u64,
    pub entry: u64,
    pub delegation_slot: u64,
    pub delegation_target: u64,
    pub owner_size: u32,
    pub owner_timestamp: u32,
    pub module_name_units: u32,
    pub module_name_truncated: u32,
    pub entry_bytes_read: u32,
    pub entry_byte_count: u32,
    pub decode_kind: u32,
    pub decode_error: u32,
    pub open_event_matches: u32,
    pub entry_revalidated: u32,
    pub slot_revalidated: u32,
    pub directory_name_matches: u32,
    pub event_name_matches: u32,
    pub reserved: u32,
    pub module_name: [u16; 96],
    pub entry_bytes: [u8; 16],
}

impl Default for RouteNode {
    fn default() -> Self {
        Self {
            owner_base: 0,
            entry: 0,
            delegation_slot: 0,
            delegation_target: 0,
            owner_size: 0,
            owner_timestamp: 0,
            module_name_units: 0,
            module_name_truncated: 0,
            entry_bytes_read: 0,
            entry_byte_count: 0,
            decode_kind: 0,
            decode_error: 0,
            open_event_matches: 0,
            entry_revalidated: 0,
            slot_revalidated: 0,
            directory_name_matches: 0,
            event_name_matches: 0,
            reserved: 0,
            module_name: [0; 96],
            entry_bytes: [0; 16],
        }
    }
}

#[repr(C)]
#[derive(Clone, Debug)]
pub struct RouteRecord {
    pub node_count: u32,
    pub node_limit: u32,
    pub hop_count: u32,
    pub route_reason: u32,
    pub callbacks_total_descriptors: u32,
    pub callbacks_total_functions: u32,
    pub original_owner_export_equal: u32,
    pub route_revalidated: u32,
    pub nodes: [RouteNode; 2],
    pub directory_descriptor_module: u64,
    pub event_descriptor_module: u64,
    pub directory_descriptor: [u8; 64],
    pub event_descriptor: [u8; 64],
    pub directory_descriptor_bytes: u32,
    pub event_descriptor_bytes: u32,
    pub directory_descriptor_truncated: u32,
    pub event_descriptor_truncated: u32,
}

impl Default for RouteRecord {
    fn default() -> Self {
        Self {
            node_count: 0,
            node_limit: 0,
            hop_count: 0,
            route_reason: 0,
            callbacks_total_descriptors: 0,
            callbacks_total_functions: 0,
            original_owner_export_equal: 0,
            route_revalidated: 0,
            nodes: std::array::from_fn(|_| RouteNode::default()),
            directory_descriptor_module: 0,
            event_descriptor_module: 0,
            directory_descriptor: [0; 64],
            event_descriptor: [0; 64],
            directory_descriptor_bytes: 0,
            event_descriptor_bytes: 0,
            directory_descriptor_truncated: 0,
            event_descriptor_truncated: 0,
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
    pub iat: IatRecord,
    pub route: RouteRecord,
    pub entries: [NativeEntry; ENTRY_LIMIT],
}

const _: () = {
    assert!(std::mem::size_of::<NativeEntry>() == 600);
    assert!(std::mem::offset_of!(NativeEntry, name) == 88);
    assert!(std::mem::size_of::<SnapshotEntry>() == 48);
    assert!(std::mem::offset_of!(SnapshotEntry, process_id) == 32);
    assert!(std::mem::size_of::<SnapshotSummary>() == 424);
    assert!(std::mem::offset_of!(SnapshotSummary, details) == 40);
    assert!(std::mem::size_of::<IatRecord>() == 128);
    assert!(std::mem::size_of::<RouteNode>() == 296);
    assert!(std::mem::offset_of!(RouteNode, module_name) == 88);
    assert!(std::mem::size_of::<RouteRecord>() == 784);
    assert!(std::mem::offset_of!(RouteRecord, nodes) == 32);
    assert!(std::mem::offset_of!(RouteRecord, directory_descriptor_module) == 624);
    assert!(std::mem::size_of::<NativeTrace>() == 6664);
    assert!(std::mem::offset_of!(NativeTrace, first_snapshot) == 104);
    assert!(std::mem::offset_of!(NativeTrace, iat) == 952);
    assert!(std::mem::offset_of!(NativeTrace, route) == 1080);
    assert!(std::mem::offset_of!(NativeTrace, entries) == 1864);
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

fn route(record: &RouteRecord, iat: &IatRecord) -> (serde_json::Value, bool, bool) {
    use serde_json::json;
    let mut invalid = record.node_count > 2
        || record.node_limit != 2
        || record.hop_count > 1
        || record.route_reason > 11
        || record.original_owner_export_equal > 1
        || record.route_revalidated > 1
        || record.callbacks_total_descriptors > 256
        || record.callbacks_total_functions > 16384
        || record.directory_descriptor_bytes > 64
        || record.event_descriptor_bytes > 64
        || record.directory_descriptor_truncated > 1
        || record.event_descriptor_truncated > 1;
    let mut ready = record.node_count > 0
        && record.node_count <= 2
        && record.hop_count.checked_add(1) == Some(record.node_count)
        && record.route_reason == 0
        && record.original_owner_export_equal == 1
        && record.route_revalidated == 1;
    let nodes:Vec<_>=record.nodes.iter().take((record.node_count as usize).min(2)).enumerate().map(|(index,node)| {
        let flags=[node.module_name_truncated,node.entry_bytes_read,node.entry_revalidated,node.slot_revalidated];
        let node_invalid=node.reserved!=0 || flags.into_iter().any(|flag|flag>1)
            || node.module_name_units>96 || node.entry_byte_count>16 || node.decode_kind>2 || node.decode_error>5;
        invalid|=node_invalid;
        let owner_end=node.owner_base.checked_add(u64::from(node.owner_size));
        ready &=node.owner_base!=0 && node.entry>=node.owner_base && owner_end.is_some_and(|end|node.entry<end)
            && node.entry_bytes_read==1 && node.entry_byte_count>0 && node.entry_revalidated==1;
        if index==0 {ready &=node.entry==iat.original_open_event;}
        if index+1<(record.node_count as usize).min(2) {
            let machine=match node.decode_kind{1=>0x8664,2=>0xaa64,_=>0};
            let decoded=super::gate_entry_route::decode(machine,node.entry,&node.entry_bytes[..(node.entry_byte_count as usize).min(16)]);
            let next=&record.nodes[index+1];
            ready &=node.entry_bytes_read==1 && node.decode_error==0 && node.open_event_matches==1
                && node.entry_revalidated==1 && node.slot_revalidated==1
                && decoded==Ok(node.delegation_slot)
                && node.delegation_slot%8==0 && node.delegation_slot>=node.owner_base
                && owner_end.is_some_and(|end|node.delegation_slot.checked_add(8).is_some_and(|slot_end|slot_end<=end))
                && node.delegation_target==next.entry && node.owner_base!=next.owner_base && node.entry!=next.entry;
        } else {ready &=node.owner_base==iat.owner_base && node.decode_kind==0 && node.decode_error==0;}
        json!({"owner_base":node.owner_base,"entry":node.entry,"delegation_slot":node.delegation_slot,
            "delegation_target":node.delegation_target,"owner_size":node.owner_size,"owner_timestamp":node.owner_timestamp,
            "module_name_units":node.module_name_units,"module_name_truncated":node.module_name_truncated,
            "module_name_utf16":&node.module_name[..(node.module_name_units as usize).min(96)],
            "entry_bytes_read":node.entry_bytes_read,"entry_byte_count":node.entry_byte_count,
            "entry_bytes":&node.entry_bytes[..(node.entry_byte_count as usize).min(16)],
            "decode_kind":node.decode_kind,"decode_error":node.decode_error,"open_event_matches":node.open_event_matches,
            "entry_revalidated":node.entry_revalidated,"slot_revalidated":node.slot_revalidated,
            "directory_name_matches":node.directory_name_matches,"event_name_matches":node.event_name_matches,
            "opaque_addresses_not_identity":true,"invalid_record":node_invalid})
    }).collect();
    let value = json!({"node_count":record.node_count,"node_limit":record.node_limit,"hop_count":record.hop_count,
        "route_reason":record.route_reason,"callbacks_total_descriptors":record.callbacks_total_descriptors,
        "callbacks_total_functions":record.callbacks_total_functions,"original_owner_export_equal":record.original_owner_export_equal,
        "route_revalidated":record.route_revalidated,"nodes":nodes,"invalid_record":invalid,
        "directory_descriptor_module":record.directory_descriptor_module,"event_descriptor_module":record.event_descriptor_module,
        "directory_descriptor_bytes":record.directory_descriptor_bytes,"event_descriptor_bytes":record.event_descriptor_bytes,
        "directory_descriptor_truncated":record.directory_descriptor_truncated,"event_descriptor_truncated":record.event_descriptor_truncated,
        "directory_descriptor":&record.directory_descriptor[..(record.directory_descriptor_bytes as usize).min(64)],
        "event_descriptor":&record.event_descriptor[..(record.event_descriptor_bytes as usize).min(64)],
        "normal_import_only":true,"opaque_addresses_not_identity":true});
    (value, invalid, ready && !invalid)
}

/// Render only recorded values, retaining incomplete/invalid observations explicitly.
pub fn diagnostic(trace: &NativeTrace) -> serde_json::Value {
    use serde_json::json;
    let setup = match trace.setup_stage {
        0 => "not-attempted",
        1 => "ready",
        2 => "original-clock-refused",
        3 => "ntdll-export-unavailable",
        4 => "original-call-owner-unavailable",
        5 => "owner-image-invalid",
        6 => "normal-import-discovery-failed",
        7 => "import-slot-safety-refused",
        8 => "data-page-write-protection-failed",
        9 => "directory-slot-publication-failed",
        10 => "event-slot-publication-failed",
        11 => "original-page-protection-restore-failed",
        12 => "import-slot-rollback-failed",
        13 => "setup-busy-or-unavailable",
        _ => "unknown-recorded-stage",
    };
    let reason = match trace.setup_reason {
        0 => "none-recorded",
        1 => "installation-busy-original-evidence-unavailable",
        2 => "required-normal-import-missing",
        3 => "duplicate-normal-import",
        4 => "original-import-export-mismatch",
        5 => "unsafe-owner-image-or-slot",
        6 => "import-callback-bound-exceeded",
        7 => "original-import-slot-changed",
        8 => "page-protection-failed",
        9 => "original-open-event-owner-address-mismatch",
        10 => "import-discovery-incomplete",
        _ => "unknown-recorded-reason",
    };
    let source = match trace.snapshot_source {
        0 => "not-collected-by-owner-iat-strategy",
        1 => "original-installation-walks",
        2 => "cached-original-installation-walks",
        _ => "unknown-recorded-source",
    };
    let (first_snapshot, first_invalid, _) = snapshot(&trace.first_snapshot);
    let (second_snapshot, second_invalid, _) = snapshot(&trace.second_snapshot);
    let iat = &trace.iat;
    let owner_end = iat.owner_base.checked_add(u64::from(iat.owner_size));
    let slot_valid = |slot: u64| {
        slot % 8 == 0
            && slot >= iat.normal_iat_start
            && slot
                .checked_add(8)
                .is_some_and(|end| end <= iat.normal_iat_end)
            && slot >= iat.owner_base
            && owner_end
                .is_some_and(|end| slot.checked_add(8).is_some_and(|slot_end| slot_end <= end))
    };
    let iat_invalid = iat.strategy > 1
        || iat.reserved != 0
        || iat.descriptor_count > 256
        || iat.function_count > 16384
        || [
            iat.owner_pinned,
            iat.discovery_complete,
            iat.published_directory,
            iat.published_event,
            iat.protections_restored,
        ]
        .into_iter()
        .any(|flag| flag > 1);
    let iat_ready = iat.strategy == 1
        && iat.owner_pinned == 1
        && iat.discovery_complete == 1
        && iat.descriptor_count > 0
        && iat.function_count >= 2
        && iat.normal_iat_start >= iat.owner_base
        && iat.normal_iat_start < iat.normal_iat_end
        && owner_end.is_some_and(|end| iat.normal_iat_end <= end)
        && iat.directory_matches == 1
        && iat.event_matches == 1
        && iat.directory_slot != iat.event_slot
        && slot_valid(iat.directory_slot)
        && slot_valid(iat.event_slot)
        && iat.owner_base != 0
        && iat.original_open_event != 0
        && iat.directory_original != 0
        && iat.event_original != 0
        && iat.published_directory == 1
        && iat.published_event == 1
        && iat.protections_restored == 1
        && iat.rollback_error == 0
        && iat.protection_error == 0
        && iat.callback_error == 0;
    let (route_value, route_invalid, route_ready) = route(&trace.route, iat);
    let mut invalid = trace.version != 4
        || trace.count as usize > ENTRY_LIMIT
        || trace.setup_stage > 13
        || trace.lifetime_policy > 1
        || trace.armed_call_count > 1
        || trace.thread_count > trace.thread_limit
        || trace.setup_reason > 10
        || trace.snapshot_source > 2
        || trace.reserved != 0
        || first_invalid
        || second_invalid
        || route_invalid;
    invalid |= iat_invalid;
    let mut inconclusive = trace.count == 0
        || trace.overflow != 0
        || trace.incomplete != 0
        || trace.setup_stage != 1
        || trace.attached_directory != 1
        || trace.attached_event != 1
        || trace.armed_call_count != 1
        || trace.called != 1
        || trace.clock_live != 1
        || !iat_ready
        || !route_ready;
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
    let iat_value = json!({
            "strategy":iat.strategy,"owner_base":iat.owner_base,"original_open_event":iat.original_open_event,
            "normal_iat_start":iat.normal_iat_start,"normal_iat_end":iat.normal_iat_end,
            "directory_slot":iat.directory_slot,"event_slot":iat.event_slot,
            "directory_original":iat.directory_original,"event_original":iat.event_original,
            "owner_pinned":iat.owner_pinned,"owner_size":iat.owner_size,"owner_timestamp":iat.owner_timestamp,
            "discovery_complete":iat.discovery_complete,"descriptor_count":iat.descriptor_count,"function_count":iat.function_count,
            "directory_matches":iat.directory_matches,"event_matches":iat.event_matches,
            "published_directory":iat.published_directory,"published_event":iat.published_event,
            "protections_restored":iat.protections_restored,"rollback_error":iat.rollback_error,
            "protection_error":iat.protection_error,"callback_error":iat.callback_error,"opaque_addresses_not_identity":true});
    let mut value = json!({"context":"pre-handoff-control-child","diagnostic_only":true,
        "acceptance_authority":false,"target_identity_proved":false,
        "instrumented_context_may_perturb":true,"version":trace.version,
        "setup_stage":trace.setup_stage,"setup_stage_label":setup,"setup_error":trace.setup_error,
        "setup_reason":trace.setup_reason,"setup_reason_label":reason,
        "original_current_thread_id":trace.original_current_thread_id,"snapshot_source":trace.snapshot_source,"snapshot_source_label":source,
        "first_snapshot":first_snapshot,"second_snapshot":second_snapshot,
        "attached_directory":trace.attached_directory,"attached_event":trace.attached_event,
        "armed_call_count":trace.armed_call_count,"reported_count":trace.count,
        "overflow":trace.overflow,"incomplete":trace.incomplete,"invalid_record":invalid,
        "coverage_inconclusive":true,
        "called":trace.called,"outer_opened":trace.outer_opened,"outer_error":trace.outer_error,
        "thread_count":trace.thread_count,"thread_limit":trace.thread_limit,
        "clock_live":trace.clock_live,"lifetime_policy":trace.lifetime_policy,
        "hooks_retained_until_control_child_exit":trace.lifetime_policy == 1,
        "in_process_detachment_claimed":false,
        "started_qpc":trace.started_qpc,"finished_qpc":trace.finished_qpc,
        "original_cutoff_qpc":trace.original_cutoff_qpc,"entries":entries,
        "empty_or_incomplete_trace_is_inconclusive":true});
    value["strategy"] = "validated-open-event-route-owner-normal-iat".into();
    value["iat"] = iat_value;
    value["route"] = route_value;
    value["observed_entries_complete"] = (!inconclusive && !invalid).into();
    value["all_native_routes_observed"] = false.into();
    value["absence_is_not_evidence"] = true.into();
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
            "observed_entries_complete":false,"all_native_routes_observed":false,"absence_is_not_evidence":true,
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
