//! Finite same-thread spawn observations, never child or object authority.
use super::{
    native_file_trace_record::{Owner, Route},
    winsock_trace_record::Node,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Write};

pub const PACKET_BYTES: usize = 9824;
pub const RECORD_BYTES: usize = 64 * 1024;
pub const ROUTES: usize = 5;
pub const ROWS: usize = 16;
pub const NAME_UNITS: usize = 128;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Row {
    pub sequence: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub raw_root: u64,
    pub raw_output: u64,
    pub secondary_output: u64,
    pub source_process: u64,
    pub source_handle: u64,
    pub target_process: u64,
    pub default_timeout: u64,
    pub operation: u32,
    pub thread_id: u32,
    pub route_index: u32,
    pub input_flags: u32,
    pub desired_access: u32,
    pub oa_length: u32,
    pub oa_attributes: u32,
    pub reported_name_bytes: u32,
    pub copied_name_units: u32,
    pub name_flags: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub pipe_type: u32,
    pub read_mode: u32,
    pub completion_mode: u32,
    pub max_instances: u32,
    pub inbound_quota: u32,
    pub outbound_quota: u32,
    pub inherit_handle: u32,
    pub duplicate_options: u32,
    pub creation_flags: u32,
    pub security_present: u32,
    pub entered: u32,
    pub returned: u32,
    pub native_status: i32,
    pub win32_result: u32,
    pub incoming_win32: u32,
    pub incoming_wsa: i32,
    pub outgoing_win32: u32,
    pub outgoing_wsa: i32,
    pub output_flags: u32,
    pub flags: u32,
    pub output_pid: u32,
    pub output_tid: u32,
    pub name: [u16; NAME_UNITS],
}
impl Default for Row {
    fn default() -> Self {
        // SAFETY: all fields are integers or fixed integer arrays; zero is valid.
        unsafe { std::mem::zeroed() }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct Packet {
    pub version: u32,
    pub packet_bytes: u32,
    pub owner_count: u32,
    pub route_count: u32,
    pub record_count: u32,
    pub total_calls: u32,
    pub total_failures: u32,
    pub dropped: u32,
    pub overflow: u32,
    pub incomplete: u32,
    pub first_failure_present: u32,
    pub scope_attempted: u32,
    pub scope_returned: u32,
    pub scope_reentry: u32,
    pub late: u32,
    pub clock_failures: u32,
    pub input_failures: u32,
    pub unmatched_scope: u32,
    pub scope_unavailable: u32,
    pub route_failures: u32,
    pub original_thread: u32,
    pub reserved: u32,
    pub cutoff_qpc: u64,
    pub frequency: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub owners: [Owner; 1],
    pub routes: [Route; ROUTES],
    pub first_failure: Row,
    pub rows: [Row; ROWS],
}
const _: () = {
    assert!(std::mem::size_of::<Row>() == 480);
    assert!(std::mem::offset_of!(Row, name) == 224);
    assert!(std::mem::size_of::<Packet>() == PACKET_BYTES);
    assert!(std::mem::offset_of!(Packet, owners) == 120);
    assert!(std::mem::offset_of!(Packet, routes) == 344);
    assert!(std::mem::offset_of!(Packet, first_failure) == 1664);
    assert!(std::mem::offset_of!(Packet, rows) == 2144);
};

fn api(operation: u32) -> Option<&'static str> {
    match operation {
        1 => Some("NtOpenFile"),
        2 => Some("NtCreateNamedPipeFile"),
        3 => Some("CreateFileW"),
        4 => Some("DuplicateHandle"),
        5 => Some("CreateProcessW"),
        _ => None,
    }
}
fn failure(row: &Row) -> bool {
    row.returned == 1
        && if row.operation <= 2 {
            row.flags & 128 != 0 && row.native_status < 0
        } else {
            row.flags & 256 != 0 && row.win32_result == 0
        }
}
fn row_valid(row: &Row, packet: &Packet) -> bool {
    api(row.operation).is_some()
        && row.sequence != 0
        && row.sequence <= u64::from(packet.total_calls)
        && row.route_index < packet.route_count
        && row.copied_name_units as usize <= NAME_UNITS
        && row.entered <= 1
        && row.returned <= 1
        && row.flags & !511 == 0
        && row.input_flags & !991 == 0
        && row.name_flags & !63 == 0
        && row.output_flags & !127 == 0
        && packet.routes[row.route_index as usize].slot.operation == row.operation
        && (row.flags & 128 == 0 || row.operation <= 2)
        && (row.flags & 256 == 0 || row.operation >= 3)
        && (row.returned == 0
            || if row.operation <= 2 {
                row.flags & 128 != 0
            } else {
                row.flags & 256 != 0
            })
        && (row.output_flags & 64 == 0
            || (row.operation == 5
                && row.returned == 1
                && row.flags & 256 != 0
                && row.win32_result != 0))
        && (row.output_flags & 2 == 0
            || (row.returned == 1 && !failure(row) && row.flags & 64 == 0))
}
pub fn validate(packet: &Packet) -> Result<(), &'static str> {
    if packet.version != 1 || packet.packet_bytes as usize != PACKET_BYTES {
        return Err("unsupported spawn packet version or extent");
    }
    if packet.reserved != 0
        || packet.owner_count > 1
        || packet.route_count as usize > ROUTES
        || packet.record_count as usize > ROWS
        || packet.scope_attempted > 1
        || packet.scope_returned > 1
        || packet.first_failure_present > 1
        || packet.overflow > 1
        || packet.record_count > packet.total_calls
        || packet.total_failures > packet.total_calls
        || (packet.first_failure_present != 0 && packet.total_failures == 0)
    {
        return Err("invalid spawn packet bounds or counters");
    }
    for owner in &packet.owners[..packet.owner_count as usize] {
        if owner.role != 1
            || owner.complete > 1
            || owner.flags & !7 != 0
            || owner.identity.entry_len > 16
            || owner.shared_owner != u32::MAX
        {
            return Err("invalid fixture import owner inventory");
        }
    }
    let mut slots = std::collections::BTreeSet::new();
    let mut operations = std::collections::BTreeSet::new();
    for route in &packet.routes[..packet.route_count as usize] {
        if route.owner_index >= packet.owner_count
            || api(route.slot.operation).is_none()
            || route.slot.slot == 0
            || route.slot.reserved != 0
            || route.slot.published > 1
            || route.slot.restored > 1
            || route.postvalidated > 1
            || route.target.entry_len > 16
            || !matches!(route.thunk_kind, 1 | 2)
            || !slots.insert(route.slot.slot)
            || !operations.insert(route.slot.operation)
        {
            return Err("invalid or duplicated spawn normal-import route");
        }
    }
    let mut sequences = std::collections::BTreeSet::new();
    for row in &packet.rows[..packet.record_count as usize] {
        if !row_valid(row, packet) || !sequences.insert(row.sequence) {
            return Err("invalid spawn invocation bounds or sequence");
        }
    }
    if packet.first_failure_present != 0
        && (!row_valid(&packet.first_failure, packet) || !failure(&packet.first_failure))
    {
        return Err("invalid pinned spawn failure");
    }
    Ok(())
}
fn node(value: &Node) -> Value {
    json!({"owner_base":value.owner_base,"entry":value.entry,"slot":value.slot,"target":value.target,
        "owner_size":value.owner_size,"timestamp":value.timestamp,"machine":value.machine,
        "entry_bytes":&value.entry_bytes[..value.entry_len.min(16) as usize],"module_name_utf16":value.module_name.as_slice()})
}
fn row(value: &Row, packet: &Packet) -> Value {
    let route = &packet.routes[value.route_index as usize];
    let native = value.operation <= 2;
    let pipe = value.operation == 2;
    let complete = value.flags & 31 == 31
        && value.flags & (32 | 64) == 0
        && value.entered == 1
        && value.returned == 1
        && value.thread_id == packet.original_thread
        && value.thread_id != 0
        && packet.frequency != 0
        && packet.started_qpc != 0
        && value.started_qpc >= packet.started_qpc
        && value.started_qpc != 0
        && value.finished_qpc >= value.started_qpc
        && value.finished_qpc < packet.cutoff_qpc
        && value.input_flags & (64 | 128 | 256) == 0
        && value.name_flags & (2 | 4) == 0
        && value.output_flags & (4 | 32) == 0
        && route.slot.published == 1
        && route.slot.restored == 0
        && route.postvalidated == 1;
    let name = &value.name[..value.copied_name_units as usize];
    let name_bytes = name
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    let full_name = value.name_flags & 32 != 0
        && value.name_flags & (2 | 4) == 0
        && value.reported_name_bytes == value.copied_name_units * 2;
    let captured_hash = Sha256::digest(&name_bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut observed = json!({"sequence":value.sequence,"operation":value.operation,"api":api(value.operation),"route_index":value.route_index,"thread_id":value.thread_id,
        "started_qpc":value.started_qpc,"finished_qpc":value.finished_qpc,"entered":value.entered,"returned":value.returned,
        "flags":value.flags,"input_flags":value.input_flags,"name_flags":value.name_flags,"output_flags":value.output_flags,
        "complete_local_observation":complete,"observed_api_failure":failure(value),
        "native_status":(native&&value.flags&128!=0&&value.returned==1).then_some(value.native_status),
        "win32_result":(!native&&value.flags&256!=0&&value.returned==1).then_some(value.win32_result),
        "status_pending":native&&value.flags&64!=0,"incoming_win32":value.incoming_win32,"incoming_wsa":value.incoming_wsa,
        "outgoing_win32":value.outgoing_win32,"outgoing_wsa":value.outgoing_wsa,
        "desired_access":(value.operation!=5).then_some(value.desired_access),"object_attributes_length":(native&&value.input_flags&(2|64)!=0).then_some(value.oa_length),
        "object_attributes":(native&&value.input_flags&2!=0).then_some(value.oa_attributes),"root_directory_scalar":(native&&value.input_flags&2!=0).then_some(value.raw_root),
        "requested_name_utf16":name,"captured_name_units":value.copied_name_units,
        "reported_name_bytes":(value.name_flags&32!=0).then_some(value.reported_name_bytes),
        "full_name_length_known":value.name_flags&32!=0,"captured_name_prefix_sha256":captured_hash,
        "full_requested_name_sha256":full_name.then_some(captured_hash.clone())});
    let extra = json!({"share_access":matches!(value.operation,1..=3).then_some(value.share_access),
        "create_disposition":matches!(value.operation,2|3).then_some(value.create_disposition),
        "create_options":native.then_some(value.create_options),"file_attributes":(value.operation==3).then_some(value.file_attributes),
        "pipe_type":pipe.then_some(value.pipe_type),"read_mode":pipe.then_some(value.read_mode),"completion_mode":pipe.then_some(value.completion_mode),
        "max_instances":pipe.then_some(value.max_instances),"inbound_quota":pipe.then_some(value.inbound_quota),"outbound_quota":pipe.then_some(value.outbound_quota),
        "default_timeout_raw_bits":(pipe&&value.input_flags&16!=0).then_some(value.default_timeout),
        "default_timeout_signed":(pipe&&value.input_flags&16!=0).then_some(value.default_timeout as i64),
        "source_process_handle_scalar":(value.operation==4).then_some(value.source_process),"source_handle_scalar":(value.operation==4).then_some(value.source_handle),
        "target_process_handle_scalar":(value.operation==4).then_some(value.target_process),"duplicate_options":(value.operation==4).then_some(value.duplicate_options),
        "inherit_handle":matches!(value.operation,4|5).then_some(value.inherit_handle),"creation_flags":(value.operation==5).then_some(value.creation_flags),
        "security_pointer_presence_bits":value.security_present,
        "output_handle_scalar":(value.returned==1&&(value.operation==3||value.output_flags&2!=0)).then_some(value.raw_output),
        "secondary_output_handle_scalar":(value.output_flags&64!=0).then_some(value.secondary_output),
        "reported_child_pid":(value.output_flags&64!=0).then_some(value.output_pid),"reported_child_tid":(value.output_flags&64!=0).then_some(value.output_tid),
        "io_status_block_observed":false,"root_handle_identity_proved":false,"denied_object_identity_proved":false,
        "child_identity_or_controller_admission_proved":false,"acceptance_authority":false});
    if let Value::Object(extra) = extra {
        observed
            .as_object_mut()
            .expect("fixed spawn row object")
            .extend(extra);
    }
    observed
}
pub fn diagnostic(packet: &Packet) -> Value {
    let checked = validate(packet);
    let valid = checked.is_ok();
    let owners=packet.owners[..packet.owner_count.min(1) as usize].iter().map(|owner|json!({"identity":node(&owner.identity),
        "role":owner.role,"stage":owner.stage,"error":owner.error,"complete":owner.complete,"descriptor_count":owner.descriptor_count,
        "function_count":owner.function_count,"flags":owner.flags,"shared_owner":owner.shared_owner})).collect::<Vec<_>>();
    let routes=packet.routes[..packet.route_count.min(ROUTES as u32) as usize].iter().map(|route|json!({"owner_index":route.owner_index,
        "slot":route.slot.slot,"original":route.slot.original,"hook":route.slot.hook,"descriptor_module":route.slot.descriptor_module,
        "operation":route.slot.operation,"api":api(route.slot.operation),"published":route.slot.published,"iat_rolled_back":route.slot.restored,
        "original_protection":route.original_protection,"postvalidated":route.postvalidated,"stage":route.stage,"error":route.error,
        "thunk_kind":route.thunk_kind,"target":node(&route.target)})).collect::<Vec<_>>();
    let rows = if valid {
        packet.rows[..packet.record_count as usize]
            .iter()
            .map(|value| row(value, packet))
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let mut observed = json!({"packet_version":packet.version,"packet_bytes":packet.packet_bytes,"packet_valid":valid,"validation_error":checked.err(),
        "limits":{"owners":1,"routes":ROUTES,"rows":ROWS,"name_units":NAME_UNITS,"record_bytes":RECORD_BYTES},
        "owner_count":packet.owner_count,"route_count":packet.route_count,"record_count":packet.record_count,"total_calls":packet.total_calls,
        "total_failures":packet.total_failures,"dropped_completed_rows":packet.dropped,"overflow":packet.overflow,"incomplete":packet.incomplete,
        "entered_without_retained_completion":packet.total_calls.saturating_sub(packet.record_count.saturating_add(packet.dropped)),
        "scope_attempted":packet.scope_attempted,"scope_returned":packet.scope_returned,"scope_reentry":packet.scope_reentry,"late":packet.late,
        "clock_failures":packet.clock_failures,"input_failures":packet.input_failures});
    let extra = json!({"unmatched_scope":packet.unmatched_scope,
        "scope_unavailable":packet.scope_unavailable,"route_failures":packet.route_failures,"original_thread":packet.original_thread,
        "started_qpc":packet.started_qpc,"finished_qpc":packet.finished_qpc,"cutoff_qpc":packet.cutoff_qpc,"frequency":packet.frequency,
        "owners":owners,"routes":routes,"rows":rows,"invalid_rows_omitted":if valid{0}else{packet.record_count},
        "first_failure_present":packet.first_failure_present,"first_failure":if valid&&packet.first_failure_present==1 {row(&packet.first_failure,packet)}else{Value::Null},
        "scope":"same-thread original Rust Command::spawn only; separate from original loader scope",
        "interpretation":"INCONCLUSIVE: missing imports, zero hits, dynamic/internal/foreign-thread routes and partial observations prove no absence or denied object",
        "environment_or_command_line_captured":false,"global_route_coverage":false,"acceptance_authority":false,"first_observed_failure_is_decisive_cause":false,
        "child_identity_or_controller_admission_proved":false,"denied_object_identity_proved":false});
    if let Value::Object(extra) = extra {
        observed
            .as_object_mut()
            .expect("fixed spawn packet object")
            .extend(extra);
    }
    observed
}
struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other(
                "spawn trace exceeds 64 KiB; no fields silently omitted",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub fn bounded(value: Value) -> io::Result<Vec<u8>> {
    let mut bytes = Capped(Vec::new());
    serde_json::to_writer(&mut bytes, &value).map_err(io::Error::other)?;
    Ok(bytes.0)
}
