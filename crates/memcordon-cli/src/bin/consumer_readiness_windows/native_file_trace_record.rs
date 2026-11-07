//! Normal-import request observations, never object or access authority.
use super::winsock_trace_record::{Node, Slot};
use serde_json::{Value, json};
use std::io::{self, Write};

pub const RECORD_BYTES: usize = 64 * 1024;
pub const PACKET_BYTES: usize = 8816;
pub const OWNERS: usize = 2;
pub const ROUTES: usize = 4;
pub const ROWS: usize = 16;
pub const NAME_UNITS: usize = 128;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Owner {
    pub identity: Node,
    pub role: u32,
    pub stage: u32,
    pub error: u32,
    pub complete: u32,
    pub descriptor_count: u32,
    pub function_count: u32,
    pub flags: u32,
    pub shared_owner: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Route {
    pub slot: Slot,
    pub target: Node,
    pub owner_index: u32,
    pub original_protection: u32,
    pub postvalidated: u32,
    pub stage: u32,
    pub error: u32,
    pub thunk_kind: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Row {
    pub sequence: u64,
    pub ldr_dependency_sequence: u64,
    pub parent_listener_sequence: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub raw_root: u64,
    pub raw_output: u64,
    pub allocation_size: u64,
    pub operation: u32,
    pub thread_id: u32,
    pub desired_access: u32,
    pub oa_length: u32,
    pub oa_attributes: u32,
    pub input_flags: u32,
    pub reported_name_bytes: u32,
    pub copied_name_units: u32,
    pub name_flags: u32,
    pub share_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub file_attributes: u32,
    pub ea_length: u32,
    pub entered: u32,
    pub returned: u32,
    pub native_status: i32,
    pub output_flags: u32,
    pub incoming_win32: u32,
    pub incoming_wsa: i32,
    pub outgoing_win32: u32,
    pub outgoing_wsa: i32,
    pub flags: u32,
    pub route_index: u32,
    pub reserved: [u32; 2],
    pub name: [u16; NAME_UNITS],
}

impl Default for Row {
    fn default() -> Self {
        // Every field is an integer or fixed integer array; zero is valid.
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
    pub attempts: u32,
    pub scopes: u32,
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
    pub owners: [Owner; OWNERS],
    pub routes: [Route; ROUTES],
    pub first_failure: Row,
    pub rows: [Row; ROWS],
}

const _: () = {
    assert!(std::mem::size_of::<Owner>() == 224);
    assert!(std::mem::size_of::<Route>() == 264);
    assert!(std::mem::size_of::<Row>() == 424);
    assert!(std::mem::offset_of!(Row, name) == 168);
    assert!(std::mem::size_of::<Packet>() == PACKET_BYTES);
    assert!(std::mem::offset_of!(Packet, owners) == 104);
    assert!(std::mem::offset_of!(Packet, routes) == 552);
    assert!(std::mem::offset_of!(Packet, first_failure) == 1608);
    assert!(std::mem::offset_of!(Packet, rows) == 2032);
};

fn row_valid(row: &Row, packet: &Packet) -> bool {
    row.reserved == [0; 2]
        && matches!(row.operation, 1 | 2)
        && row.sequence != 0
        && row.sequence <= u64::from(packet.total_calls)
        && row.route_index < packet.route_count
        && row.copied_name_units as usize <= NAME_UNITS
        && row.entered <= 1
        && row.returned <= 1
        && row.flags & !127 == 0
        && row.input_flags & !511 == 0
        && row.name_flags & !15 == 0
        && row.output_flags & !63 == 0
        && (row.output_flags & 1 == 0
            || (row.returned == 1 && row.native_status >= 0 && row.native_status != 0x103))
        && packet.routes[row.route_index as usize].slot.operation == row.operation
}

pub fn validate(packet: &Packet) -> Result<(), &'static str> {
    if packet.version != 1 || packet.packet_bytes as usize != PACKET_BYTES {
        return Err("unsupported native file packet version or extent");
    }
    if packet.reserved != 0
        || packet.owner_count as usize > OWNERS
        || packet.route_count as usize > ROUTES
        || packet.record_count as usize > ROWS
        || packet.first_failure_present > 1
        || packet.overflow > 1
        || packet.record_count > packet.total_calls
        || packet.total_failures > packet.total_calls
        || (packet.first_failure_present != 0 && packet.total_failures == 0)
    {
        return Err("invalid native file packet bounds or counters");
    }
    for (index, owner) in packet.owners[..packet.owner_count as usize]
        .iter()
        .enumerate()
    {
        if owner.role != index as u32 + 1
            || owner.complete > 1
            || owner.flags & !7 != 0
            || owner.identity.entry_len > 16
            || (owner.shared_owner != u32::MAX && owner.shared_owner >= index as u32)
        {
            return Err("invalid native file owner inventory");
        }
    }
    let mut slots = std::collections::BTreeSet::new();
    for route in &packet.routes[..packet.route_count as usize] {
        if route.owner_index >= packet.owner_count
            || !matches!(route.slot.operation, 1 | 2)
            || route.slot.reserved != 0
            || route.slot.published > 1
            || route.slot.restored > 1
            || route.postvalidated > 1
            || route.target.entry_len > 16
            || !matches!(route.thunk_kind, 1 | 2)
            || route.slot.slot == 0
            || !slots.insert(route.slot.slot)
        {
            return Err("invalid or duplicated native file route");
        }
    }
    let mut sequences = std::collections::BTreeSet::new();
    for row in &packet.rows[..packet.record_count as usize] {
        if !row_valid(row, packet) || !sequences.insert(row.sequence) {
            return Err("invalid native file invocation extent or sequence");
        }
    }
    if packet.first_failure_present != 0
        && (!row_valid(&packet.first_failure, packet)
            || packet.first_failure.returned == 0
            || packet.first_failure.native_status >= 0)
    {
        return Err("invalid pinned native file failure");
    }
    Ok(())
}

fn node(value: &Node) -> Value {
    json!({"owner_base":value.owner_base,"entry":value.entry,"slot":value.slot,
        "target":value.target,"owner_size":value.owner_size,"timestamp":value.timestamp,
        "machine":value.machine,"entry_bytes":&value.entry_bytes[..value.entry_len.min(16) as usize],
        "module_name_utf16":value.module_name.as_slice()})
}

fn row(value: &Row, packet: &Packet) -> Value {
    let route = &packet.routes[value.route_index as usize];
    let complete = value.flags & 31 == 31
        && value.flags & (32 | 64) == 0
        && value.entered == 1
        && value.returned == 1
        && value.native_status != 0x103
        && value.thread_id == packet.original_thread
        && value.thread_id != 0
        && value.ldr_dependency_sequence != 0
        && value.parent_listener_sequence != 0
        && value.started_qpc != 0
        && value.finished_qpc >= value.started_qpc
        && value.finished_qpc < packet.cutoff_qpc
        && packet.frequency != 0
        && value.input_flags & (64 | 128 | 256) == 0
        && value.name_flags & (2 | 4) == 0
        && value.output_flags & 4 == 0
        && (value.input_flags & 4 == 0
            || (value.name_flags & 1 != 0
                && value.reported_name_bytes == value.copied_name_units * 2))
        && route.slot.published == 1
        && route.slot.restored == 0
        && route.postvalidated == 1;
    json!({"sequence":value.sequence,"ldr_dependency_sequence":value.ldr_dependency_sequence,
        "parent_listener_sequence":value.parent_listener_sequence,"route_index":value.route_index,
        "api":if value.operation==1 {"NtCreateFile"}else{"NtOpenFile"},"thread_id":value.thread_id,
        "started_qpc":value.started_qpc,"finished_qpc":value.finished_qpc,
        "desired_access":value.desired_access,"object_attributes_length":value.oa_length,
        "object_attributes":value.oa_attributes,"root_directory_scalar":value.raw_root,
        "root_directory_identity_proved":false,"reported_name_bytes":value.reported_name_bytes,
        "captured_name_units":value.copied_name_units,"name_flags":value.name_flags,
        "requested_name_utf16":&value.name[..value.copied_name_units as usize],
        "requested_name_is_resolved_object":false,"input_flags":value.input_flags,
        "share_access":value.share_access,"open_or_create_options":value.create_options,
        "create_disposition":(value.operation==1).then_some(value.create_disposition),
        "file_attributes":(value.operation==1).then_some(value.file_attributes),
        "allocation_size_raw_bits":(value.operation==1 && value.input_flags&16!=0).then_some(value.allocation_size),
        "allocation_size_signed":(value.operation==1 && value.input_flags&16!=0).then_some(value.allocation_size as i64),
        "ea_length":(value.operation==1).then_some(value.ea_length),
        "entered":value.entered,"returned":value.returned,"native_status":(value.returned==1).then_some(value.native_status),
        "status_pending":value.returned==1 && value.native_status==0x103,
        "output_flags":value.output_flags,"output_handle_scalar":(value.output_flags&1!=0).then_some(value.raw_output),
        "io_status_block_observed":false,"incoming_win32":value.incoming_win32,"incoming_wsa":value.incoming_wsa,
        "outgoing_win32":value.outgoing_win32,"outgoing_wsa":value.outgoing_wsa,
        "flags":value.flags,"complete_request_observation":complete,"acceptance_authority":false})
}

pub fn diagnostic(packet: &Packet) -> Value {
    let validity = validate(packet);
    let valid = validity.is_ok();
    let owners: Vec<_> = packet.owners[..packet.owner_count.min(OWNERS as u32) as usize]
        .iter().map(|value|json!({"identity":node(&value.identity),"role":value.role,"stage":value.stage,
            "error":value.error,"complete":value.complete,"descriptor_count":value.descriptor_count,
            "function_count":value.function_count,"flags":value.flags,"shared_owner":value.shared_owner})).collect();
    let routes: Vec<_> = packet.routes[..packet.route_count.min(ROUTES as u32) as usize]
        .iter().map(|value|json!({"owner_index":value.owner_index,"slot":value.slot.slot,
            "original":value.slot.original,"hook":value.slot.hook,"descriptor_module":value.slot.descriptor_module,
            "operation":value.slot.operation,"published":value.slot.published,"iat_rolled_back":value.slot.restored,
            "original_protection":value.original_protection,"postvalidated":value.postvalidated,
            "thunk_kind":value.thunk_kind,"stage":value.stage,"error":value.error,"target":node(&value.target)})).collect();
    let rows: Vec<_> = if valid {
        packet.rows[..packet.record_count as usize]
            .iter()
            .map(|value| row(value, packet))
            .collect()
    } else {
        Vec::new()
    };
    json!({"packet_version":packet.version,"packet_bytes":packet.packet_bytes,
        "packet_valid":valid,"validation_error":validity.err(),"limits":{"owners":OWNERS,"routes":ROUTES,"rows":ROWS,"name_units":NAME_UNITS,"record_bytes":RECORD_BYTES},
        "owner_count":packet.owner_count,"route_count":packet.route_count,"record_count":packet.record_count,
        "total_calls":packet.total_calls,"total_failures":packet.total_failures,"dropped":packet.dropped,
        "overflow":packet.overflow,"incomplete":packet.incomplete,"attempts":packet.attempts,
        "scopes":packet.scopes,"scope_reentry":packet.scope_reentry,"late":packet.late,
        "clock_failures":packet.clock_failures,"input_failures":packet.input_failures,
        "unmatched_scope":packet.unmatched_scope,"scope_unavailable":packet.scope_unavailable,
        "route_failures":packet.route_failures,"original_thread":packet.original_thread,
        "cutoff_qpc":packet.cutoff_qpc,"frequency":packet.frequency,"owners":owners,"routes":routes,
        "first_failure_present":packet.first_failure_present,
        "first_failure":if valid && packet.first_failure_present==1 {row(&packet.first_failure,packet)}else{Value::Null},
        "rows":rows,"invalid_rows_omitted":if valid {0}else{packet.record_count},
        "interpretation":"INCONCLUSIVE: only verified normal-import slots are observed; absent routes, no hits, partial capture and overflow establish no absence or selection",
        "join_scope":"same-thread original Ldr interval only; no native IRP identity or resolved relative-root path",
        "denied_physical_object_proved":false,"policy_cause_proved":false,"global_route_coverage":false,"acceptance_authority":false})
}

struct Capped(Vec<u8>);
impl Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other(
                "native file request record exceeds64KiB; no fields silently omitted",
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
    let mut output = Capped(Vec::new());
    serde_json::to_writer(&mut output, &value).map_err(io::Error::other)?;
    Ok(output.0)
}
