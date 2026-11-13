//! Fixed native original-call observations. No record grants object or launch authority.
use serde_json::{Value, json};

pub const RECORD_BYTES: usize = 64 * 1024;
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    pub sequence: u64,
    pub raw_root: u64,
    pub raw_output: u64,
    pub requested_size: u64,
    pub secondary_size: u64,
    pub operation: u32,
    pub thread_id: u32,
    pub desired_access: u32,
    pub flags: u32,
    pub entered: u32,
    pub returned: u32,
    pub native_status: i32,
    pub incoming_error: u32,
    pub outgoing_error: u32,
    pub reported_name_bytes: u32,
    pub copied_name_units: u32,
    pub name_flags: u32,
    pub output_flags: u32,
    pub scalar_flags: u32,
    pub name: [u16; 256],
}
impl Default for Entry {
    fn default() -> Self {
        Self {
            sequence: 0,
            raw_root: 0,
            raw_output: 0,
            requested_size: 0,
            secondary_size: 0,
            operation: 0,
            thread_id: 0,
            desired_access: 0,
            flags: 0,
            entered: 0,
            returned: 0,
            native_status: 0,
            incoming_error: 0,
            outgoing_error: 0,
            reported_name_bytes: 0,
            copied_name_units: 0,
            name_flags: 0,
            output_flags: 0,
            scalar_flags: 0,
            name: [0; 256],
        }
    }
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Slot {
    pub slot: u64,
    pub original: u64,
    pub hook: u64,
    pub descriptor_module: u64,
    pub operation: u32,
    pub published: u32,
    pub restored: u32,
    pub reserved: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Node {
    pub owner_base: u64,
    pub entry: u64,
    pub slot: u64,
    pub target: u64,
    pub owner_size: u32,
    pub timestamp: u32,
    pub machine: u32,
    pub entry_len: u32,
    pub entry_bytes: [u8; 16],
    pub module_name: [u16; 64],
}
impl Default for Node {
    fn default() -> Self {
        Self {
            owner_base: 0,
            entry: 0,
            slot: 0,
            target: 0,
            owner_size: 0,
            timestamp: 0,
            machine: 0,
            entry_len: 0,
            entry_bytes: [0; 16],
            module_name: [0; 64],
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct Packet {
    pub version: u32,
    pub setup_stage: u32,
    pub setup_error: u32,
    pub setup_reason: u32,
    pub called: u32,
    pub original_return: i32,
    pub requested_version: u32,
    pub negotiated_version: u32,
    pub incoming_error: u32,
    pub outgoing_error: u32,
    pub armed: u32,
    pub record_count: u32,
    pub total_calls: u32,
    pub total_failures: u32,
    pub dropped: u32,
    pub overflow: u32,
    pub incomplete: u32,
    pub first_failure_present: u32,
    pub original_thread: u32,
    pub scope_flags: u32,
    pub node_count: u32,
    pub hop_count: u32,
    pub descriptor_count: u32,
    pub function_count: u32,
    pub slot_count: u32,
    pub callbacks_complete: u32,
    pub protections_restored: u32,
    pub rollback_error: u32,
    pub owner_pinned: u32,
    pub clock_live: u32,
    pub retention_error: u32,
    pub reserved: u32,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub cutoff_qpc: u64,
    pub frequency: u64,
    pub nodes: [Node; 2],
    pub slots: [Slot; 16],
    pub first_failure: Entry,
    pub entries: [Entry; 16],
}
fn operation(code: u32) -> Option<(&'static str, &'static str)> {
    Some(match code {
        1 => ("NtOpenKey", "ntstatus"),
        2 => ("NtOpenKeyEx", "ntstatus"),
        3 => ("NtQueryValueKey", "ntstatus"),
        4 => ("LdrLoadDll", "ntstatus"),
        5 => ("NtCreateEvent", "ntstatus"),
        6 => ("NtOpenEvent", "ntstatus"),
        7 => ("NtOpenDirectoryObject", "ntstatus"),
        8 => ("NtAllocateVirtualMemory", "ntstatus"),
        9 => ("RtlAllocateHeap", "pointer"),
        10 => ("RegOpenKeyExW", "lstatus"),
        11 => ("RegQueryValueExW", "lstatus"),
        12 => ("LoadLibraryExW", "pointer"),
        13 => ("CreateEventW", "pointer"),
        14 => ("OpenEventW", "pointer"),
        15 => ("HeapAlloc", "pointer"),
        16 => ("VirtualAlloc", "pointer"),
        _ => return None,
    })
}
fn entry(entry: &Entry, thread: u32) -> (Value, bool, bool) {
    let signature = operation(entry.operation);
    let invalid = signature.is_none()
        || entry.sequence == 0
        || entry.thread_id != thread
        || thread == 0
        || entry.entered > 1
        || entry.returned > 1
        || entry.returned > entry.entered
        || entry.copied_name_units > 256
        || entry.name_flags & !7 != 0
        || entry.output_flags & !3 != 0
        || entry.scalar_flags & !7 != 0
        || (entry.output_flags & 2 != 0 && entry.output_flags & 1 == 0)
        || (signature.is_some_and(|(_, domain)| domain == "pointer")
            && (!matches!(entry.native_status, 0 | 1)
                || (entry.returned == 1
                    && (entry.output_flags & 1 == 0
                        || (entry.output_flags & 2 != 0) != (entry.raw_output != 0)
                        || (entry.native_status == 0) != (entry.raw_output != 0)))));
    let required_scalars = match entry.operation {
        3 | 5 | 13 => 3,
        8 => {
            1 | if entry.returned == 1 && entry.native_status >= 0 {
                2
            } else {
                0
            }
        }
        9 | 15 | 16 => 5,
        _ => 0,
    };
    let incomplete = invalid
        || entry.entered != 1
        || entry.returned != 1
        || entry.name_flags & 6 != 0
        || entry.scalar_flags & required_scalars != required_scalars
        || entry.reported_name_bytes % 2 != 0
        || entry.reported_name_bytes < entry.copied_name_units.min(256) * 2
        || (entry.returned == 1
            && ((matches!(entry.operation, 1 | 2 | 4 | 5 | 6 | 7 | 8)
                && entry.native_status >= 0)
                || (entry.operation == 10 && entry.native_status == 0))
            && entry.output_flags & 1 == 0);
    let failure = if entry.returned == 1 && !invalid {
        signature.map(|(_, domain)| match domain {
            "ntstatus" => entry.native_status < 0,
            "lstatus" => entry.native_status != 0,
            _ => entry.raw_output == 0,
        })
    } else {
        None
    };
    (
        json!({"sequence":entry.sequence,"operation":signature.map(|value|value.0),"operation_code":entry.operation,"return_domain":signature.map(|value|value.1),
        "thread_id":entry.thread_id,"desired_access":matches!(entry.operation,1|2|5|6|7|10|14).then_some(entry.desired_access),
        "memory_protection":matches!(entry.operation,8|16).then_some(entry.desired_access),"raw_access_or_protection":entry.desired_access,
        "requested_size_semantics":match entry.operation {8|9|15|16=>"allocation-bytes",3|11=>"query-buffer-bytes",5=>"event-type",13=>"manual-reset",_=>"not-applicable-or-unavailable"},
        "flags":if entry.scalar_flags&4!=0 {Some(entry.flags)}else{None},"raw_flags":entry.flags,"entered":entry.entered,"returned":entry.returned,
        "native_status_or_adapter_marker":entry.native_status,"incoming_last_error":entry.incoming_error,"outgoing_last_error":entry.outgoing_error,
        "raw_root":entry.raw_root,"raw_output":entry.raw_output,"requested_size":if entry.scalar_flags&1!=0 {Some(entry.requested_size)}else{None},"secondary_size":if entry.scalar_flags&2!=0 {Some(entry.secondary_size)}else{None},
        "raw_requested_size":entry.requested_size,"raw_secondary_size":entry.secondary_size,"scalar_flags":entry.scalar_flags,
        "reported_name_bytes":entry.reported_name_bytes,"copied_name_units":entry.copied_name_units,"name_flags":entry.name_flags,"output_flags":entry.output_flags,
        "name_utf16":&entry.name[..(entry.copied_name_units as usize).min(256)],"name_is_unicode_text":std::char::decode_utf16(entry.name[..(entry.copied_name_units as usize).min(256)].iter().copied()).all(|value|value.is_ok()),"observed_failure":failure,"failure_is_decisive_cause":false,"raw_handles_are_identity":false,
        "invalid_record":invalid,"observation_incomplete":incomplete}),
        invalid,
        incomplete,
    )
}

pub fn diagnostic(packet: &Packet) -> Value {
    diagnostic_slots(packet, false)
}

/// Returned-module routes can contain distinct imports of the same typed API.
/// This changes data validation only; no recorded slot conveys authority.
pub fn returned_module_diagnostic(packet: &Packet) -> Value {
    diagnostic_slots(packet, true)
}

fn diagnostic_slots(packet: &Packet, repeated_operations: bool) -> Value {
    let flags = [
        packet.called,
        packet.armed,
        packet.overflow,
        packet.incomplete,
        packet.first_failure_present,
        packet.callbacks_complete,
        packet.protections_restored,
        packet.owner_pinned,
        packet.clock_live,
    ];
    let mut invalid = packet.version != 1
        || packet.setup_stage > 9
        || flags.iter().any(|value| *value > 1)
        || packet.record_count > 16
        || packet.node_count > 2
        || packet.hop_count > 1
        || packet.slot_count > 16
        || packet.descriptor_count > 512
        || packet.function_count > 32768
        || packet.scope_flags & !7 != 0
        || packet.reserved != 0
        || (packet.scope_flags & 4 != 0) != (packet.hop_count == 1)
        || packet.requested_version > u32::from(u16::MAX)
        || packet.negotiated_version > u32::from(u16::MAX)
        || packet.total_failures > packet.total_calls;
    let mut incomplete = packet.incomplete != 0
        || packet.overflow != 0
        || packet.dropped != 0
        || packet.scope_flags & 2 != 0
        || u64::from(packet.total_calls)
            > u64::from(packet.record_count) + u64::from(packet.dropped);
    invalid |= packet.total_failures == 0 && packet.first_failure_present != 0;
    incomplete |= packet.total_failures > 0 && packet.first_failure_present == 0;
    let selected_operation = |operation| {
        packet.slots[..(packet.slot_count as usize).min(16)]
            .iter()
            .any(|slot| slot.operation == operation && slot.published == 1 && slot.hook != 0)
    };
    let mut previous = 0;
    let mut ordered: Vec<_> = packet.entries[..(packet.record_count as usize).min(16)]
        .iter()
        .enumerate()
        .collect();
    ordered.sort_by_key(|(_, item)| item.sequence);
    let entries: Vec<_> = ordered
        .into_iter()
        .map(|(index, item)| {
            let (mut value, bad, partial) = entry(item, packet.original_thread);
            value["storage_index"] = json!(index);
            invalid |= bad
                || item.sequence <= previous
                || item.sequence > u64::from(packet.total_calls)
                || !selected_operation(item.operation);
            incomplete |= partial;
            previous = item.sequence;
            value
        })
        .collect();
    let first_failure = if packet.first_failure_present != 0 {
        let (value, bad, partial) = entry(&packet.first_failure, packet.original_thread);
        invalid |= bad
            || value["observed_failure"] != true
            || packet.first_failure.sequence > u64::from(packet.total_calls)
            || !selected_operation(packet.first_failure.operation);
        incomplete |= partial;
        Some(value)
    } else {
        None
    };
    let nodes:Vec<_>=packet.nodes[..(packet.node_count as usize).min(2)].iter().map(|node|{
        let units=node.module_name.iter().position(|value|*value==0).unwrap_or(64);
        invalid|=node.entry_len>16||(node.machine!=0&&![0x8664,0xaa64].contains(&node.machine));
        let metadata_available=node.owner_base!=0&&node.entry!=0&&node.owner_size!=0&&node.machine!=0;
        incomplete|=!metadata_available;
        if metadata_available {invalid|=node.entry<node.owner_base||node.owner_base.checked_add(u64::from(node.owner_size)).is_none_or(|end|node.entry>=end);}
        incomplete|=units==64;
        json!({"owner_base":node.owner_base,"entry":node.entry,"delegation_slot":node.slot,"delegation_target":node.target,"owner_size":node.owner_size,"timestamp":node.timestamp,
            "machine":node.machine,"owner_metadata_available":metadata_available,"entry_bytes":&node.entry_bytes[..(node.entry_len as usize).min(16)],"entry_byte_count":node.entry_len,"module_name_utf16":&node.module_name[..units],"module_name_prefix_only":true,"module_name_unterminated":units==64})
    }).collect();
    if packet.node_count == 1 {
        invalid |= packet.nodes[0].slot != 0 || packet.nodes[0].target != 0;
    } else if packet.node_count == 2 {
        let first = &packet.nodes[0];
        let second = &packet.nodes[1];
        invalid |= first.owner_base == second.owner_base
            || first.slot == 0
            || first.slot % 8 != 0
            || first.slot < first.owner_base
            || first
                .owner_base
                .checked_add(u64::from(first.owner_size))
                .is_none_or(|end| first.slot.checked_add(8).is_none_or(|last| last > end))
            || first.target != second.entry
            || second.slot != 0
            || second.target != 0
            || !super::gate_entry_route::decode(
                first.machine,
                first.entry,
                &first.entry_bytes[..(first.entry_len as usize).min(16)],
            )
            .is_ok_and(|slot| slot == first.slot);
    }
    let mut published = true;
    let mut operations = std::collections::BTreeSet::new();
    let mut slot_addresses = std::collections::BTreeSet::new();
    let mut original_targets = std::collections::BTreeMap::new();
    let slots:Vec<_>=packet.slots[..(packet.slot_count as usize).min(16)].iter().map(|slot|{
        let repeated = !operations.insert(slot.operation);
        invalid|=operation(slot.operation).is_none()||(!repeated_operations&&repeated)||!slot_addresses.insert(slot.slot)||slot.published>1||slot.restored>1||slot.reserved!=0;
        if let Some(original) = original_targets.insert(slot.operation, (slot.original, slot.hook)) { invalid |= original != (slot.original, slot.hook); }
        let slot_range=packet.nodes[..(packet.node_count as usize).min(2)].last().is_some_and(|node|
            slot.slot>=node.owner_base && node.owner_base.checked_add(u64::from(node.owner_size)).is_some_and(|end|slot.slot.checked_add(8).is_some_and(|last|last<=end)));
        invalid|=slot.published==1&&(slot.slot==0||slot.slot%8!=0||slot.original==0||slot.hook==0||slot.original==slot.hook||slot.descriptor_module==0||!slot_range);
        published&=slot.published==1&&slot.restored==0&&slot.hook!=0;
        incomplete|=slot.hook==0||slot.published!=1||slot.restored!=0;
        json!({"slot":slot.slot,"original":slot.original,"hook":slot.hook,"descriptor_module":slot.descriptor_module,"operation":slot.operation,"operation_name":operation(slot.operation).map(|value|value.0),"published":slot.published,"restored":slot.restored,"unsupported_or_unbound":slot.hook==0||slot.published!=1})
    }).collect();
    let complete = !invalid
        && !incomplete
        && packet.called == 1
        && packet.armed == 1
        && packet.setup_stage == 1
        && packet.setup_error == 0
        && packet.rollback_error == 0
        && packet.callbacks_complete == 1
        && packet.protections_restored == 1
        && packet.owner_pinned == 1
        && packet.clock_live == 1
        && packet.slot_count > 0
        && published
        && packet.scope_flags & 3 == 1
        && packet.requested_version == 0x0202
        && packet.node_count > 0
        && packet.hop_count + 1 == packet.node_count
        && packet.frequency > 0
        && packet.started_qpc < packet.cutoff_qpc
        && packet.finished_qpc >= packet.started_qpc
        && packet.finished_qpc < packet.cutoff_qpc;
    let mut value = json!({"format":"memcordon.fixture-winsock-original-call","revision":1,"diagnostic_only":true,"acceptance_authority":false,
        "target_identity_proved":false,"raw_handles_are_identity":false,"all_native_routes_observed":false,"coverage_inconclusive":true,"absence_is_not_evidence":true,
        "post_failure_spi_in_scope":false,"scope":"original WSAStartup caller-thread verified owner normal imports only; recovered failures are not automatically causal",
        "unobserved_paths":["provider/helper threads","dynamically resolved targets","delay imports","loaded-module imports","direct syscalls"],
        "packet_version":packet.version,"invalid_packet":invalid,"observed_entries_complete":complete,"observation_incomplete":incomplete,
        "setup_stage":packet.setup_stage,"setup_error":packet.setup_error,"setup_reason":packet.setup_reason,"called":packet.called,
        "original_startup_return":if packet.called==1 {Some(packet.original_return)}else{None},"raw_original_return":packet.original_return});
    let metadata = json!({
        "requested_version":packet.requested_version,"negotiated_version":if packet.called==1&&packet.original_return==0 {Some(packet.negotiated_version)}else{None},
        "incoming_last_error":packet.incoming_error,"outgoing_last_error":packet.outgoing_error,"armed":packet.armed,
        "reported_record_count":packet.record_count,"total_calls":packet.total_calls,"total_failures":packet.total_failures,"dropped":packet.dropped,"overflow":packet.overflow,
        "original_thread":packet.original_thread,"scope_flags":packet.scope_flags,"unsupported_imports":packet.scope_flags&2!=0,"one_hop_observed":packet.scope_flags&4!=0,"node_count":packet.node_count,"hop_count":packet.hop_count,
        "descriptor_count":packet.descriptor_count,"function_count":packet.function_count,"slot_count":packet.slot_count,"callbacks_complete":packet.callbacks_complete,
        "protections_restored":packet.protections_restored,"rollback_error":packet.rollback_error,"owner_pinned":packet.owner_pinned,"clock_live":packet.clock_live,
        "retention_error":packet.retention_error,"started_qpc":packet.started_qpc,"finished_qpc":packet.finished_qpc,"cutoff_qpc":packet.cutoff_qpc,"frequency":packet.frequency});
    value
        .as_object_mut()
        .expect("diagnostic object")
        .extend(metadata.as_object().expect("metadata object").clone());
    value["failure_order"] = json!("first observed returned failure; sequence denotes entry order");
    value["inventory_bounds_scope"] = json!(
        "aggregate maximum two owners; native per-owner limits 256 descriptors and 16384 functions"
    );
    value["nodes"] = json!(nodes);
    value["slots"] = json!(slots);
    value["first_observed_failure"] = json!(first_failure);
    value["recent_entries"] = json!(entries);
    if serde_json::to_writer(
        Capped {
            remaining: RECORD_BYTES,
        },
        &value,
    )
    .is_ok()
    {
        value
    } else {
        json!({"format":"memcordon.fixture-winsock-original-call","revision":1,"diagnostic_only":true,"acceptance_authority":false,"target_identity_proved":false,
        "all_native_routes_observed":false,"coverage_inconclusive":true,"absence_is_not_evidence":true,"post_failure_spi_in_scope":false,
        "unavailable":"record serialization exceeds bound","setup_stage":packet.setup_stage,"setup_error":packet.setup_error,"setup_reason":packet.setup_reason,
        "called":packet.called,"raw_original_return":packet.original_return,"incoming_last_error":packet.incoming_error,"outgoing_last_error":packet.outgoing_error,
        "first_observed_failure":first_failure})
    }
}
struct Capped {
    remaining: usize,
}
impl std::io::Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("Winsock diagnostic bound exhausted"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
