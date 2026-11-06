//! Original listener call observations; no recorded scalar grants authority.
use super::winsock_trace_record::{Node, Packet as DependencyPacket, Slot};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub const RECORD_BYTES: usize = 64 * 1024;

#[repr(C)]
#[derive(Default)]
pub struct Outcome {
    pub kind: u32,
    pub raw_error_present: u32,
    pub raw_error: i32,
    pub reserved: u32,
}

#[repr(C)]
pub struct Request {
    pub cutoff_qpc: u64,
    pub frequency: u64,
    pub incoming_win32: u32,
    pub incoming_wsa: i32,
    pub experiment_flags: u32,
    pub reserved: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ImageReturn {
    pub dependency_sequence: u64,
    pub parent_listener_sequence: u64,
    pub returned_base: u64,
    pub allocation_base: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub original_thread: u32,
    pub domain: u32,
    pub memory_type: u32,
    pub state: u32,
    pub virtual_query_error: u32,
    pub mapped_name_error: u32,
    pub mapped_path_units: u32,
    pub flags: u32,
    pub mapped_path: [u16; 512],
}
impl Default for ImageReturn {
    fn default() -> Self {
        Self {
            dependency_sequence: 0,
            parent_listener_sequence: 0,
            returned_base: 0,
            allocation_base: 0,
            started_qpc: 0,
            finished_qpc: 0,
            original_thread: 0,
            domain: 0,
            memory_type: 0,
            state: 0,
            virtual_query_error: 0,
            mapped_name_error: 0,
            mapped_path_units: 0,
            flags: 0,
            mapped_path: [0; 512],
        }
    }
}
#[repr(C)]
#[derive(Default)]
pub struct ReturnedImages {
    pub version: u32,
    pub enabled: u32,
    pub count: u32,
    pub dropped: u32,
    pub attempts: u32,
    pub incomplete: u32,
    pub reserved: [u32; 2],
    pub rows: [ImageReturn; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct Entry {
    pub sequence: u64,
    pub parent_sequence: u64,
    pub arguments: [u64; 6],
    pub result: u64,
    pub operation: u32,
    pub thread_id: u32,
    pub depth: u32,
    pub flags: u32,
    pub incoming_win32: u32,
    pub incoming_wsa: i32,
    pub outgoing_win32: u32,
    pub outgoing_wsa: i32,
    pub entered: u32,
    pub returned: u32,
    pub failed: u32,
    pub error_domain: u32,
    pub output_valid: u32,
    pub output_u32: u32,
    pub completion_sequence: u64,
    pub input_prefix: [u8; 32],
    pub input_bytes: u32,
    pub input_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DependencyLink {
    pub dependency_sequence: u64,
    pub timeline_sequence: u64,
    pub parent_listener_sequence: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct ReturnedModule {
    pub version: u32,
    pub setup_stage: u32,
    pub setup_error: u32,
    pub setup_reason: u32,
    pub selected: u32,
    pub armed: u32,
    pub scope_flags: u32,
    pub incomplete: u32,
    pub link_count: u32,
    pub links_dropped: u32,
    pub selection_count: u32,
    pub skipped_count: u32,
    pub parent_listener_sequence: u64,
    pub loader_dependency_sequence: u64,
    pub loader_timeline_sequence: u64,
    pub returned_module: u64,
    pub dependencies: DependencyPacket,
    pub first_failure_link: DependencyLink,
    pub links: [DependencyLink; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct LoaderLink {
    pub dependency_sequence: u64,
    pub timeline_sequence: u64,
    pub parent_listener_sequence: u64,
    pub loader_dependency_sequence: u64,
    pub loader_timeline_sequence: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct LoaderOwner {
    pub version: u32,
    pub setup_stage: u32,
    pub setup_error: u32,
    pub setup_reason: u32,
    pub selected: u32,
    pub armed: u32,
    pub scope_flags: u32,
    pub incomplete: u32,
    pub link_count: u32,
    pub links_dropped: u32,
    pub attempt_count: u32,
    pub skipped_count: u32,
    pub loader_target: u64,
    pub owner_base: u64,
    pub dependencies: DependencyPacket,
    pub first_failure_link: LoaderLink,
    pub links: [LoaderLink; 16],
    pub window_count: u32,
    pub windows_dropped: u32,
    pub first_failure_window_present: u32,
    pub windows_invalid: u32,
    pub first_failure_window: LoaderWindow,
    pub windows: [LoaderWindow; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct LoaderWindow {
    pub dependency_sequence: u64,
    pub loader_dependency_sequence: u64,
    pub parent_listener_sequence: u64,
    pub started_qpc: u64,
    pub finished_qpc: u64,
}

#[repr(C)]
#[derive(Default)]
pub struct Packet {
    pub version: u32,
    pub setup_stage: u32,
    pub setup_error: u32,
    pub setup_reason: u32,
    pub called: u32,
    pub callback_outcome: u32,
    pub callback_raw_error_present: u32,
    pub callback_raw_error: i32,
    pub armed: u32,
    pub original_thread: u32,
    pub scope_flags: u32,
    pub incomplete: u32,
    pub slot_count: u32,
    pub descriptor_count: u32,
    pub function_count: u32,
    pub callbacks_complete: u32,
    pub owner_pinned: u32,
    pub protections_restored: u32,
    pub rollback_error: u32,
    pub clock_live: u32,
    pub total_calls: u32,
    pub total_failures: u32,
    pub record_count: u32,
    pub dropped: u32,
    pub overflow: u32,
    pub first_failure_present: u32,
    pub dependency_scope_armed: u32,
    pub dependency_scope_error: u32,
    pub incoming_win32: u32,
    pub incoming_wsa: i32,
    pub outgoing_win32: u32,
    pub outgoing_wsa: i32,
    pub discovered_mask: u32,
    pub verified_mask: u32,
    pub published_mask: u32,
    pub entered_mask: u32,
    pub returned_mask: u32,
    pub failure_mask: u32,
    pub dependency_link_count: u32,
    pub dependency_links_dropped: u32,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub cutoff_qpc: u64,
    pub frequency: u64,
    pub next_sequence: u64,
    pub listener_owner_anchor: u64,
    pub owner: Node,
    pub slots: [Slot; 16],
    pub first_failure: Entry,
    pub entries: [Entry; 16],
    pub first_dependency_failure_link: DependencyLink,
    pub dependency_links: [DependencyLink; 16],
    pub dependencies: DependencyPacket,
    pub returned_module: ReturnedModule,
    pub loader_owner: LoaderOwner,
    pub returned_images: ReturnedImages,
}

const _: () = {
    use std::mem::{offset_of, size_of};
    assert!(size_of::<Outcome>() == 16);
    assert!(size_of::<Request>() == 32);
    assert!(size_of::<ImageReturn>() == 1104);
    assert!(size_of::<ReturnedImages>() == 8864);
    assert!(size_of::<Entry>() == 176);
    assert!(offset_of!(Entry, completion_sequence) == 128);
    assert!(offset_of!(Entry, input_prefix) == 136);
    assert!(size_of::<DependencyLink>() == 24);
    assert!(size_of::<ReturnedModule>() == 12136);
    assert!(offset_of!(ReturnedModule, dependencies) == 80);
    assert!(offset_of!(ReturnedModule, first_failure_link) == 11728);
    assert!(offset_of!(ReturnedModule, links) == 11752);
    assert!(size_of::<LoaderLink>() == 40);
    assert!(size_of::<LoaderWindow>() == 40);
    assert!(size_of::<LoaderOwner>() == 13088);
    assert!(offset_of!(LoaderOwner, dependencies) == 64);
    assert!(offset_of!(LoaderOwner, first_failure_link) == 11712);
    assert!(offset_of!(LoaderOwner, links) == 11752);
    assert!(offset_of!(LoaderOwner, window_count) == 12392);
    assert!(offset_of!(LoaderOwner, first_failure_window) == 12408);
    assert!(offset_of!(LoaderOwner, windows) == 12448);
    assert!(size_of::<Packet>() == 50304);
    assert!(offset_of!(Packet, returned_images) == 41440);
    assert!(offset_of!(Packet, owner) == 208);
    assert!(offset_of!(Packet, slots) == 400);
    assert!(offset_of!(Packet, first_failure) == 1168);
    assert!(offset_of!(Packet, entries) == 1344);
    assert!(offset_of!(Packet, first_dependency_failure_link) == 4160);
    assert!(offset_of!(Packet, dependency_links) == 4184);
    assert!(offset_of!(Packet, dependencies) == 4568);
    assert!(offset_of!(Packet, returned_module) == 16216);
    assert!(offset_of!(Packet, loader_owner) == 28352);
    assert!(offset_of!(Packet, loader_owner) + offset_of!(LoaderOwner, window_count) == 40744);
    assert!(
        offset_of!(Packet, loader_owner) + offset_of!(LoaderOwner, first_failure_window) == 40760
    );
    assert!(offset_of!(Packet, loader_owner) + offset_of!(LoaderOwner, windows) == 40800);
};

fn signature(operation: u32) -> Option<(&'static str, u32, usize)> {
    Some(match operation {
        1 => ("WSAStartup", 1, 2),
        2 => ("WSASocketW", 2, 6),
        3 => ("SetHandleInformation", 3, 3),
        4 => ("bind", 2, 3),
        5 => ("listen", 2, 2),
        6 => ("closesocket", 2, 1),
        7 => ("WSACleanup", 2, 0),
        _ => return None,
    })
}

fn failed(entry: &Entry) -> bool {
    let signed = entry.result as u32 as i32;
    match entry.operation {
        1 => signed != 0,
        2 => entry.result == u64::MAX,
        3 => signed == 0,
        4..=7 => signed == -1,
        _ => false,
    }
}

fn entry(value: &Entry, packet: &Packet) -> (Value, bool, bool) {
    let operation = signature(value.operation);
    let bit = if (1..=7).contains(&value.operation) {
        1 << (value.operation - 1)
    } else {
        0
    };
    let invalid = operation.is_none()
        || value.sequence == 0
        || value.sequence > packet.next_sequence
        || value.thread_id == 0
        || value.thread_id != packet.original_thread
        || value.depth >= 16
        || value.flags != 0
        || value.parent_sequence >= value.sequence
        || (value.depth == 0) != (value.parent_sequence == 0)
        || [
            value.entered,
            value.returned,
            value.failed,
            value.output_valid,
        ]
        .iter()
        .any(|flag| *flag > 1)
        || value.returned > value.entered
        || (value.returned == 1
            && (value.completion_sequence <= value.sequence
                || value.completion_sequence > packet.next_sequence))
        || (value.returned == 0 && value.completion_sequence != 0)
        || operation.is_some_and(|(_, domain, arity)| {
            value.error_domain != domain
                || value.arguments[arity..]
                    .iter()
                    .any(|argument| *argument != 0)
        })
        || value.input_bytes > 32
        || value.input_flags & !7 != 0
        || (value.input_bytes != 0 && (value.operation != 4 || value.input_flags & 1 == 0))
        || (value.output_valid == 1
            && (value.operation != 1
                || value.returned != 1
                || failed(value)
                || value.output_u32 > u32::from(u16::MAX)))
        || (value.returned == 1 && value.failed != u32::from(failed(value)))
        || packet.published_mask & bit == 0
        || (value.entered == 1 && packet.entered_mask & bit == 0)
        || (value.returned == 1 && packet.returned_mask & bit == 0)
        || (value.failed == 1 && packet.failure_mask & bit == 0);
    let noncanonical_int = value.operation != 2 && value.result > u64::from(u32::MAX);
    let scalar_indices: &[usize] = match value.operation {
        1 => &[0],
        2 => &[0, 1, 2, 4, 5],
        3 => &[1, 2],
        4 => &[2],
        5 => &[1],
        _ => &[],
    };
    let noncanonical_arguments = scalar_indices
        .iter()
        .any(|index| value.arguments[*index] > u64::from(u32::MAX))
        || (value.operation == 1 && value.arguments[0] > u64::from(u16::MAX));
    let incomplete = invalid
        || value.entered != 1
        || value.returned != 1
        || value.input_flags & 6 != 0
        || noncanonical_int
        || noncanonical_arguments
        || (value.operation == 1
            && value.returned == 1
            && !failed(value)
            && value.output_valid == 0);
    let actual_error = if invalid || value.returned != 1 || !failed(value) {
        None
    } else {
        match value.error_domain {
            1 => Some(value.result as u32 as i32),
            2 => Some(value.outgoing_wsa),
            3 => Some(value.outgoing_win32 as i32),
            _ => None,
        }
    };
    (
        json!({"sequence":value.sequence,"completion_sequence":value.completion_sequence,"parent_sequence":value.parent_sequence,"depth":value.depth,"thread_id":value.thread_id,
        "operation":operation.map(|(name,_,_)|name),"operation_code":value.operation,"arguments_raw":value.arguments,"result_raw":value.result,"result_signed_low32":(value.operation!=2).then_some(value.result as u32 as i32),
        "incoming_win32":value.incoming_win32,"incoming_wsa":value.incoming_wsa,"outgoing_win32":value.outgoing_win32,"outgoing_wsa":value.outgoing_wsa,
        "entered":value.entered,"returned":value.returned,"reported_failed":value.failed,"observed_failure":if value.returned==1{Some(failed(value))}else{None},"error_domain":value.error_domain,"original_error":actual_error,
        "startup_negotiated_version":(value.output_valid==1&&value.operation==1&&!failed(value)).then_some(value.output_u32),"output_valid":value.output_valid,"raw_output_u32":value.output_u32,
        "input_prefix":&value.input_prefix[..(value.input_bytes as usize).min(32)],"input_bytes":value.input_bytes,"input_flags":value.input_flags,
        "invalid_record":invalid,"observation_incomplete":incomplete,"failure_is_decisive_cause":false,"recorded_socket_is_authority":false}),
        invalid,
        incomplete,
    )
}

fn dependencies(packet: &DependencyPacket) -> Value {
    dependency_projection(super::winsock_trace_record::diagnostic(packet))
}

fn dependency_projection(mut value: Value) -> Value {
    let object = value.as_object_mut().expect("dependency diagnostic object");
    for key in [
        "called",
        "original_startup_return",
        "raw_original_return",
        "requested_version",
        "negotiated_version",
    ] {
        object.remove(key);
    }
    object.insert(
        "format".into(),
        json!("memcordon.fixture-listener-dependencies"),
    );
    object.insert("scope".into(),json!("previously verified startup-owner normal imports during original listener callback only"));
    object.insert("original_startup_invoked".into(), json!(false));
    object.insert("failure_is_decisive_cause".into(), json!(false));
    value
}

fn returned_module(packet: &Packet, ordinals: &mut BTreeSet<u64>) -> (Value, bool, bool) {
    let scope = &packet.returned_module;
    let events = &scope.dependencies;
    let mut invalid = scope.version != 1
        || scope.setup_stage > 9
        || scope.setup_stage == 8
        || scope.setup_reason > 8
        || [scope.selected, scope.armed, scope.incomplete]
            .iter()
            .any(|flag| *flag > 1)
        || scope.scope_flags & !3 != 0
        || scope.link_count > 16
        || scope.skipped_count > scope.selection_count
        || events.called != 0
        || events.requested_version != 0
        || events.negotiated_version != 0
        || events.original_return != 0
        || events.node_count > 1
        || events.descriptor_count > 256
        || events.function_count > 16384
        || events.hop_count != 0
        || (scope.selected == 0
            && (scope.armed != 0
                || scope.returned_module != 0
                || scope.link_count != 0
                || events.record_count != 0));
    let mut incomplete = scope.incomplete != 0
        || scope.scope_flags & 2 != 0
        || scope.links_dropped != 0
        || scope.link_count != events.record_count;
    let recent = &packet.entries[..(packet.record_count as usize).min(16)];
    if scope.selected == 1 {
        invalid |= scope.returned_module == 0
            || scope.selection_count == 0
            || scope.parent_listener_sequence == 0
            || scope.loader_dependency_sequence == 0
            || scope.loader_timeline_sequence <= scope.parent_listener_sequence
            || scope.loader_timeline_sequence > packet.next_sequence;
        if let Some(parent) = recent
            .iter()
            .find(|entry| entry.sequence == scope.parent_listener_sequence)
        {
            invalid |= parent.operation != 2
                || (parent.returned == 1
                    && scope.loader_timeline_sequence >= parent.completion_sequence);
        } else if packet.dropped == 0 {
            invalid = true;
        } else {
            incomplete = true;
        }
        let loader = packet.dependencies.entries
            [..(packet.dependencies.record_count as usize).min(16)]
            .iter()
            .find(|entry| entry.sequence == scope.loader_dependency_sequence);
        if let Some(loader) = loader {
            invalid |= loader.operation != 12
                || loader.thread_id != packet.original_thread
                || loader.returned != 1
                || loader.native_status != 0
                || loader.raw_output != scope.returned_module
                || loader.output_flags != 3
                || loader.raw_root != 0
                || loader.flags != 0;
        } else if packet.dependencies.dropped == 0 {
            invalid = true;
        } else {
            incomplete = true;
        }
        let linked = packet.dependency_links[..(packet.dependency_link_count as usize).min(16)]
            .iter()
            .any(|link| {
                link.dependency_sequence == scope.loader_dependency_sequence
                    && link.timeline_sequence == scope.loader_timeline_sequence
                    && link.parent_listener_sequence == scope.parent_listener_sequence
            });
        if !linked {
            if packet.dependency_links_dropped == 0 {
                invalid = true;
            } else {
                incomplete = true;
            }
        }
    }
    if scope.armed == 1 {
        invalid |= scope.selected != 1
            || events.armed != 1
            || events.owner_pinned != 1
            || events.callbacks_complete != 1
            || events.protections_restored != 1
            || events.original_thread != packet.original_thread
            || events.cutoff_qpc != packet.cutoff_qpc
            || events.frequency != packet.frequency
            || events.nodes[0].owner_base != scope.returned_module
            || events.node_count != 1;
    }
    let mut sequences = BTreeSet::new();
    let links = scope.links[..(scope.link_count as usize).min(16)].iter().map(|link| {
        let event = events.entries[..(events.record_count as usize).min(16)].iter().find(|entry| entry.sequence == link.dependency_sequence);
        invalid |= link.dependency_sequence == 0 || !sequences.insert(link.dependency_sequence)
            || link.timeline_sequence <= scope.loader_timeline_sequence || link.timeline_sequence > packet.next_sequence
            || !ordinals.insert(link.timeline_sequence) || event.is_none()
            || event.is_some_and(|entry| entry.thread_id != packet.original_thread)
            || link.parent_listener_sequence >= link.timeline_sequence;
        if let Some(parent) = recent.iter().find(|entry| entry.sequence == link.parent_listener_sequence) {
            invalid |= parent.returned == 1 && link.timeline_sequence >= parent.completion_sequence;
        } else if packet.dropped == 0 { invalid = true; } else { incomplete = true; }
        json!({"namespace":"returned_module","dependency_sequence":link.dependency_sequence,"timeline_sequence":link.timeline_sequence,"timeline_domain":"ENTER","parent_listener_sequence":link.parent_listener_sequence})
    }).collect::<Vec<_>>();
    let first = if events.first_failure_present == 1 {
        let link = &scope.first_failure_link;
        invalid |= link.dependency_sequence != events.first_failure.sequence
            || link.timeline_sequence <= scope.loader_timeline_sequence
            || link.timeline_sequence > packet.next_sequence
            || link.parent_listener_sequence >= link.timeline_sequence;
        if let Some(recent) = scope.links[..(scope.link_count as usize).min(16)]
            .iter()
            .find(|recent| recent.dependency_sequence == link.dependency_sequence)
        {
            invalid |= recent.timeline_sequence != link.timeline_sequence
                || recent.parent_listener_sequence != link.parent_listener_sequence;
        } else {
            invalid |= events.dropped == 0 || !ordinals.insert(link.timeline_sequence);
        }
        Some(
            json!({"namespace":"returned_module","dependency_sequence":link.dependency_sequence,"timeline_sequence":link.timeline_sequence,"timeline_domain":"ENTER","parent_listener_sequence":link.parent_listener_sequence}),
        )
    } else {
        None
    };
    let mut dependency = dependency_projection(
        super::winsock_trace_record::returned_module_diagnostic(events),
    );
    dependency["scope"] = json!(
        "one actual successful loader-return module normal imports after that load returned; loader initialization, dynamic exports and later modules are outside scope"
    );
    invalid |= scope.armed == 1 && dependency["invalid_packet"] == true;
    // No entrypoint was observed for this owner; zero entry/bytes are honest.
    if scope.armed == 1 && events.nodes[0].entry == 0 {
        dependency["owner_entrypoint_unobserved"] = json!(true);
        dependency["observed_entries_complete"] = json!(false);
    }
    (
        json!({"version":scope.version,"setup_stage":scope.setup_stage,"setup_error":scope.setup_error,"setup_reason":scope.setup_reason,"selected":scope.selected,"armed":scope.armed,"scope_flags":scope.scope_flags,"incomplete":scope.incomplete,"selection_count":scope.selection_count,"skipped_count":scope.skipped_count,"links_dropped":scope.links_dropped,"parent_listener_sequence":scope.parent_listener_sequence,"loader_dependency_sequence":scope.loader_dependency_sequence,"loader_timeline_sequence":scope.loader_timeline_sequence,"returned_module":scope.returned_module,"invalid_scope":invalid,"observation_incomplete":incomplete,"acceptance_authority":false,"provider_ready_proved":false,"WSPStartup_invocation_observed":false,"global_routes_complete":false,"original_startup_invoked":false,"links":links,"first_failure_link":first,"dependencies":dependency}),
        invalid,
        incomplete,
    )
}

fn loader_parent(packet: &Packet, link: &LoaderLink) -> (bool, bool) {
    let mut invalid = link.dependency_sequence == 0
        || link.parent_listener_sequence == 0
        || link.loader_dependency_sequence == 0
        || link.loader_dependency_sequence > u64::from(packet.dependencies.total_calls)
        || link.loader_timeline_sequence <= link.parent_listener_sequence
        || link.timeline_sequence <= link.loader_timeline_sequence
        || link.timeline_sequence > packet.next_sequence;
    let mut incomplete = false;
    let parent = packet.entries[..(packet.record_count as usize).min(16)]
        .iter()
        .find(|entry| entry.sequence == link.parent_listener_sequence)
        .or_else(|| {
            (packet.first_failure_present == 1
                && packet.first_failure.sequence == link.parent_listener_sequence)
                .then_some(&packet.first_failure)
        });
    if let Some(parent) = parent {
        invalid |= parent.operation != 2
            || (parent.returned == 1 && link.timeline_sequence >= parent.completion_sequence);
    } else if packet.dropped == 0 {
        invalid = true;
    } else {
        incomplete = true;
    }
    let startup = &packet.dependencies;
    let loader = startup.entries[..(startup.record_count as usize).min(16)]
        .iter()
        .find(|entry| entry.sequence == link.loader_dependency_sequence)
        .or_else(|| {
            (startup.first_failure_present == 1
                && startup.first_failure.sequence == link.loader_dependency_sequence)
                .then_some(&startup.first_failure)
        });
    if let Some(loader) = loader {
        invalid |= loader.operation != 12
            || loader.thread_id != packet.original_thread
            || loader.entered != 1
            || loader.returned != 1;
    } else if startup.dropped == 0 {
        invalid = true;
    } else {
        incomplete = true;
    }
    let matches = |parent: &DependencyLink| {
        parent.dependency_sequence == link.loader_dependency_sequence
            && parent.timeline_sequence == link.loader_timeline_sequence
            && parent.parent_listener_sequence == link.parent_listener_sequence
    };
    if !packet.dependency_links[..(packet.dependency_link_count as usize).min(16)]
        .iter()
        .any(matches)
        && !(startup.first_failure_present == 1 && matches(&packet.first_dependency_failure_link))
    {
        if packet.dependency_links_dropped == 0 {
            invalid = true;
        } else {
            incomplete = true;
        }
    }
    (invalid, incomplete)
}

fn loader_link(link: &LoaderLink) -> Value {
    json!({"namespace":"loader_owner","dependency_sequence":link.dependency_sequence,"timeline_sequence":link.timeline_sequence,"timeline_domain":"ENTER","parent_listener_sequence":link.parent_listener_sequence,"loader_parent_namespace":"startup","loader_dependency_sequence":link.loader_dependency_sequence,"loader_timeline_sequence":link.loader_timeline_sequence,"loader_timeline_domain":"ENTER"})
}

fn loader_window(packet: &Packet, window: &LoaderWindow, failure: bool) -> (Value, bool, bool) {
    let scope = &packet.loader_owner;
    let events = &scope.dependencies;
    let mut invalid = window.dependency_sequence == 0
        || window.dependency_sequence > u64::from(events.total_calls)
        || window.loader_dependency_sequence == 0
        || window.loader_dependency_sequence > u64::from(packet.dependencies.total_calls)
        || window.parent_listener_sequence == 0
        || packet.original_thread == 0
        || packet.frequency == 0
        || window.started_qpc == 0
        || window.started_qpc < packet.started_qpc
        || window.finished_qpc < window.started_qpc
        || window.finished_qpc > packet.finished_qpc
        || window.finished_qpc > packet.cutoff_qpc
        || (events.started_qpc != 0 && window.started_qpc < events.started_qpc)
        || (events.finished_qpc != 0 && window.finished_qpc > events.finished_qpc)
        || scope.selected != 1
        || scope.armed != 1
        || events.original_thread != packet.original_thread
        || events.cutoff_qpc != packet.cutoff_qpc
        || events.frequency != packet.frequency;
    let mut incomplete = false;
    let link = scope.links[..(scope.link_count as usize).min(16)]
        .iter()
        .find(|link| link.dependency_sequence == window.dependency_sequence)
        .or_else(|| {
            (events.first_failure_present == 1
                && scope.first_failure_link.dependency_sequence == window.dependency_sequence)
                .then_some(&scope.first_failure_link)
        });
    if let Some(link) = link {
        let (bad, partial) = loader_parent(packet, link);
        invalid |= bad
            || link.loader_dependency_sequence != window.loader_dependency_sequence
            || link.parent_listener_sequence != window.parent_listener_sequence;
        incomplete |= partial;
    } else if scope.links_dropped == 0 {
        invalid = true;
    } else {
        incomplete = true;
    }
    let event = events.entries[..(events.record_count as usize).min(16)]
        .iter()
        .find(|entry| entry.sequence == window.dependency_sequence)
        .or_else(|| {
            (events.first_failure_present == 1
                && events.first_failure.sequence == window.dependency_sequence)
                .then_some(&events.first_failure)
        });
    if let Some(event) = event {
        invalid |= event.operation != 4
            || event.thread_id != packet.original_thread
            || event.entered != 1
            || event.returned != 1
            || (failure && event.native_status >= 0);
    } else if events.dropped == 0 {
        invalid = true;
    } else {
        incomplete = true;
    }
    (
        json!({"dependency_sequence":window.dependency_sequence,"loader_dependency_sequence":window.loader_dependency_sequence,"parent_listener_sequence":window.parent_listener_sequence,"started_qpc":window.started_qpc,"finished_qpc":window.finished_qpc,"thread_id":packet.original_thread,"namespace":"loader_owner","operation":"LdrLoadDll","clock_domain":"original-QPC","invalid_window":invalid,"observation_incomplete":incomplete,"temporal_attribution_only":true}),
        invalid,
        incomplete,
    )
}

pub fn loader_window_summary(packet: &Packet) -> Value {
    let scope = &packet.loader_owner;
    let mut invalid = scope.window_count > 16
        || scope.first_failure_window_present > 1
        || u64::from(scope.window_count)
            + u64::from(scope.windows_dropped)
            + u64::from(scope.windows_invalid)
            > u64::from(scope.dependencies.total_calls)
        || (scope.first_failure_window_present == 0
            && scope.first_failure_window != LoaderWindow::default());
    let mut incomplete = scope.windows_dropped != 0 || scope.windows_invalid != 0;
    let mut seen = BTreeSet::new();
    let windows = scope.windows[..(scope.window_count as usize).min(16)]
        .iter()
        .map(|window| {
            let (value, bad, partial) = loader_window(packet, window, false);
            invalid |= bad || !seen.insert(window.dependency_sequence);
            incomplete |= partial;
            value
        })
        .collect::<Vec<_>>();
    let first = if scope.first_failure_window_present == 1 {
        let window = &scope.first_failure_window;
        let (value, bad, partial) = loader_window(packet, window, true);
        invalid |= bad || scope.window_count == 0;
        incomplete |= partial;
        if let Some(recent) = scope.windows[..(scope.window_count as usize).min(16)]
            .iter()
            .find(|recent| recent.dependency_sequence == window.dependency_sequence)
        {
            invalid |= recent != window;
        } else {
            invalid |= scope.windows_dropped == 0;
            incomplete = true;
        }
        Some(value)
    } else {
        None
    };
    for event in &scope.dependencies.entries[..(scope.dependencies.record_count as usize).min(16)] {
        if event.operation != 4 || event.returned != 1 {
            continue;
        }
        let present = scope.windows[..(scope.window_count as usize).min(16)]
            .iter()
            .any(|window| window.dependency_sequence == event.sequence)
            || (scope.first_failure_window_present == 1
                && scope.first_failure_window.dependency_sequence == event.sequence);
        invalid |= !present && scope.windows_invalid == 0 && scope.windows_dropped == 0;
        invalid |= present && event.native_status < 0 && scope.first_failure_window_present == 0;
    }
    json!({"window_count":scope.window_count,"windows_dropped":scope.windows_dropped,"first_failure_window_present":scope.first_failure_window_present,"windows_invalid":scope.windows_invalid,"first_failure_window":first,"windows":windows,"invalid_windows":invalid,"windows_observation_incomplete":incomplete,"window_clock_domain":"original-QPC","window_failure_is_decisive_cause":false})
}

fn loader_owner(packet: &Packet, ordinals: &mut BTreeSet<u64>) -> (Value, bool, bool) {
    let scope = &packet.loader_owner;
    let events = &scope.dependencies;
    let ldr_published = events.slots[..(events.slot_count as usize).min(16)]
        .iter()
        .any(|slot| slot.operation == 4 && slot.published == 1 && slot.hook != 0);
    let mut invalid = scope.version != 2
        || scope.setup_stage > 9
        || scope.setup_stage == 8
        || scope.setup_reason > 8
        || [scope.selected, scope.armed, scope.incomplete]
            .iter()
            .any(|value| *value > 1)
        || scope.scope_flags & !3 != 0
        || scope.link_count > 16
        || scope.skipped_count > scope.attempt_count
        || events.called != 0
        || events.requested_version != 0
        || events.negotiated_version != 0
        || events.original_return != 0
        || events.record_count > 16
        || events.node_count > 1
        || events.hop_count != 0
        || events.descriptor_count > 256
        || events.function_count > 16384
        || (scope.selected == 0
            && (scope.armed != 0
                || scope.loader_target != 0
                || scope.owner_base != 0
                || events.record_count != 0
                || scope.link_count != 0));
    let mut incomplete = scope.incomplete != 0
        || scope.scope_flags & 2 != 0
        || scope.links_dropped != 0
        || scope.link_count != events.record_count
        || (scope.armed == 1 && !ldr_published);
    if scope.selected == 1 {
        invalid |= scope.loader_target == 0 || scope.owner_base == 0 || scope.attempt_count == 0;
    }
    if scope.armed == 1 {
        let owner = &events.nodes[0];
        invalid |= scope.selected != 1
            || events.armed != 1
            || events.owner_pinned != 1
            || events.callbacks_complete != 1
            || events.protections_restored != 1
            || events.node_count != 1
            || owner.owner_base != scope.owner_base
            || events.original_thread != packet.original_thread
            || events.cutoff_qpc != packet.cutoff_qpc
            || events.frequency != packet.frequency
            || owner.owner_size == 0
            || scope.loader_target < owner.owner_base
            || owner
                .owner_base
                .checked_add(u64::from(owner.owner_size))
                .is_none_or(|end| scope.loader_target >= end)
            || (owner.entry != 0 && owner.entry != scope.loader_target)
            || packet.dependency_scope_armed != 1
            || !packet.dependencies.slots[..(packet.dependencies.slot_count as usize).min(16)]
                .iter()
                .any(|slot| {
                    slot.operation == 12
                        && slot.published == 1
                        && slot.original == scope.loader_target
                        && slot.hook != 0
                });
    }
    let mut sequences = BTreeSet::new();
    let links = scope.links[..(scope.link_count as usize).min(16)]
        .iter()
        .map(|link| {
            let (bad, partial) = loader_parent(packet, link);
            invalid |= bad
                || !sequences.insert(link.dependency_sequence)
                || !ordinals.insert(link.timeline_sequence)
                || !events.entries[..(events.record_count as usize).min(16)]
                    .iter()
                    .any(|event| {
                        event.sequence == link.dependency_sequence
                            && event.thread_id == packet.original_thread
                    });
            incomplete |= partial;
            loader_link(link)
        })
        .collect::<Vec<_>>();
    let first = if events.first_failure_present == 1 {
        let link = &scope.first_failure_link;
        let (bad, partial) = loader_parent(packet, link);
        invalid |= bad
            || link.dependency_sequence != events.first_failure.sequence
            || events.first_failure.thread_id != packet.original_thread;
        incomplete |= partial;
        if let Some(recent) = scope.links[..(scope.link_count as usize).min(16)]
            .iter()
            .find(|recent| recent.dependency_sequence == link.dependency_sequence)
        {
            invalid |= recent != link;
        } else {
            invalid |= events.dropped == 0 || !ordinals.insert(link.timeline_sequence);
        }
        Some(loader_link(link))
    } else {
        None
    };
    let mut dependency = dependency_projection(
        super::winsock_trace_record::returned_module_diagnostic(events),
    );
    dependency["scope"] = json!(
        "verified actual original LoadLibraryExW implementation owner's normal imports only while that unchanged original call executes; internal loader calls, direct syscalls, helper threads, dynamic/delay routes and other owners remain unobserved"
    );
    dependency["observed_entries_complete"] = json!(false);
    dependency["LdrLoadDll_normal_import_published"] = json!(ldr_published);
    invalid |= scope.armed == 1 && dependency["invalid_packet"] == true;
    incomplete |= dependency["observation_incomplete"] == true;
    let timing = loader_window_summary(packet);
    invalid |= timing["invalid_windows"] == true;
    incomplete |= timing["windows_observation_incomplete"] == true;
    let mut value = json!({"version":scope.version,"setup_stage":scope.setup_stage,"setup_error":scope.setup_error,"setup_reason":scope.setup_reason,"selected":scope.selected,"armed":scope.armed,"scope_flags":scope.scope_flags,"incomplete":scope.incomplete,"attempt_count":scope.attempt_count,"skipped_count":scope.skipped_count,"links_dropped":scope.links_dropped,"loader_target":scope.loader_target,"owner_base":scope.owner_base,"invalid_scope":invalid,"observation_incomplete":incomplete,"acceptance_authority":false,"target_identity_proved":false,"global_routes_complete":false,"original_startup_invoked":false,"original_loader_result_is_not_observer_setup_error":true,"first_observed_failure_is_decisive_cause":false,"cross_namespace_failure_return_order_proved":false,"links":links,"first_failure_link":first,"dependencies":dependency});
    value
        .as_object_mut()
        .expect("loader scope object")
        .extend(timing.as_object().expect("loader timing object").clone());
    (value, invalid, incomplete)
}

fn returned_images_diagnostic(packet: &Packet) -> Value {
    if packet.version == 4 {
        return json!({"recorded":false,"status":"unavailable-in-packet-version-4","complete":false,
            "acceptance_authority":false,"original_file_identity_proved":false});
    }
    let images = &packet.returned_images;
    let mut invalid = packet.version != 5
        || images.version != 1
        || images.enabled > 1
        || images.count > 8
        || images.incomplete > 1
        || images.reserved != [0; 2]
        || images.attempts != images.count.saturating_add(images.dropped);
    let mut rows = Vec::new();
    for (index, row) in images.rows[..(images.count as usize).min(8)]
        .iter()
        .enumerate()
    {
        let source = packet.dependencies.entries
            [..(packet.dependencies.record_count as usize).min(16)]
            .iter()
            .filter(|entry| entry.sequence == row.dependency_sequence)
            .collect::<Vec<_>>();
        let parent = packet.entries[..(packet.record_count as usize).min(16)]
            .iter()
            .filter(|entry| entry.sequence == row.parent_listener_sequence)
            .collect::<Vec<_>>();
        let linked = packet.dependency_links[..(packet.dependency_link_count as usize).min(16)]
            .iter()
            .filter(|link| {
                link.dependency_sequence == row.dependency_sequence
                    && link.parent_listener_sequence == row.parent_listener_sequence
                    && link.timeline_sequence > 0
            })
            .count()
            == 1;
        let original_load = source.first().map(|entry| {
            let units=(entry.copied_name_units as usize).min(256);
            let name=&entry.name[..units];
            let complete=source.len()==1 && entry.name_flags==1 && units>0 && units<256
                && entry.reported_name_bytes==entry.copied_name_units.saturating_mul(2)
                && !name.contains(&0) && String::from_utf16(name).is_ok()
                && entry.name[units..].iter().all(|unit|*unit==0);
            json!({"complete":complete,"operation_code":entry.operation,"sequence":entry.sequence,
                "thread_id":entry.thread_id,"raw_root":entry.raw_root,"raw_flags":entry.flags,
                "raw_output":entry.raw_output,"name_utf16":name,"name_flags":entry.name_flags,
                "entered":entry.entered,"returned":entry.returned,"output_flags":entry.output_flags,
                "native_status_or_adapter_marker":entry.native_status,
                "reported_name_bytes":entry.reported_name_bytes,"copied_name_units":entry.copied_name_units,
                "process_identity_source":"outer-original_binding","acceptance_authority":false})
        });
        let source_valid = source.len() == 1
            && source[0].operation == 12
            && source[0].entered == 1
            && source[0].returned == 1
            && source[0].raw_output == row.returned_base
            && source[0].output_flags == 3
            && source[0].native_status == 0
            && source[0].thread_id == row.original_thread
            && source[0].raw_root == 0
            && source[0].flags == 0
            && source[0].scalar_flags == 4
            && original_load
                .as_ref()
                .is_some_and(|source| source["complete"] == true);
        let parent_valid = parent.len() == 1
            && parent[0].operation == 2
            && parent[0].entered == 1
            && parent[0].returned == 1
            && parent[0].thread_id == row.original_thread;
        let units = (row.mapped_path_units as usize).min(512);
        let path = &row.mapped_path[..units];
        let path_valid = units > 0
            && units < 512
            && !path.contains(&0)
            && String::from_utf16(path).is_ok()
            && row.mapped_path[units..].iter().all(|unit| *unit == 0);
        let clock_valid = row.started_qpc > 0
            && row.started_qpc >= packet.started_qpc
            && row.finished_qpc >= row.started_qpc
            && row.finished_qpc <= packet.finished_qpc
            && row.finished_qpc < packet.cutoff_qpc;
        let row_invalid = row.domain != 0
            || row.original_thread != packet.original_thread
            || row.dependency_sequence == 0
            || row.parent_listener_sequence == 0
            || row.returned_base == 0
            || !(1..=7).contains(&row.state)
            || row.flags & !7 != 0
            || images.rows[..index]
                .iter()
                .any(|other| other.dependency_sequence == row.dependency_sequence)
            || !source_valid
            || !parent_valid
            || !linked
            || (row.state == 1
                && (row.flags != 7
                    || !clock_valid
                    || !path_valid
                    || row.allocation_base != row.returned_base
                    || row.memory_type != 0x0100_0000
                    || row.virtual_query_error != 0
                    || row.mapped_name_error != 0));
        invalid |= row_invalid;
        rows.push(json!({"dependency_sequence":row.dependency_sequence,"parent_listener_sequence":row.parent_listener_sequence,
            "original_thread":row.original_thread,"domain":row.domain,"returned_base":row.returned_base,
            "allocation_base":row.allocation_base,"memory_type":row.memory_type,"state":row.state,
            "virtual_query_error":row.virtual_query_error,"mapped_name_error":row.mapped_name_error,
            "started_qpc":row.started_qpc,"finished_qpc":row.finished_qpc,"flags":row.flags,
            "mapped_path_utf16":path,"complete":row.state==1&&!row_invalid,"invalid_row":row_invalid,
            "original_load":original_load,
            "original_file_identity_proved":false,"acceptance_authority":false}));
    }
    if images.enabled == 0 {
        invalid |= images.count != 0
            || images.attempts != 0
            || images.dropped != 0
            || images.incomplete != 0;
    }
    json!({"version":images.version,"enabled":images.enabled==1,"attempts":images.attempts,
        "count":images.count,"dropped":images.dropped,"invalid_record":invalid,
        "complete":images.enabled==1&&images.count>0&&images.incomplete==0&&images.dropped==0&&!invalid&&images.rows[..(images.count as usize).min(8)].iter().all(|row|row.state==1),
        "observation_incomplete":images.incomplete!=0||invalid,"rows":rows,
        "diagnostic_only":true,"original_file_identity_proved":false,"acceptance_authority":false})
}

pub fn diagnostic(packet: &Packet) -> Value {
    let flags = [
        packet.called,
        packet.armed,
        packet.incomplete,
        packet.callbacks_complete,
        packet.owner_pinned,
        packet.protections_restored,
        packet.clock_live,
        packet.overflow,
        packet.first_failure_present,
        packet.dependency_scope_armed,
        packet.callback_raw_error_present,
    ];
    let mut invalid = !matches!(packet.version, 4 | 5)
        || packet.setup_stage > 9
        || packet.setup_stage == 8
        || flags.iter().any(|flag| *flag > 1)
        || packet.callback_outcome > 3
        || (packet.called == 0 && packet.callback_outcome != 0)
        || (packet.called == 1 && packet.callback_outcome == 0)
        || (packet.callback_raw_error_present == 1 && packet.callback_outcome != 2)
        || packet.scope_flags & !3 != 0
        || packet.record_count > 16
        || packet.slot_count > 16
        || packet.dependency_link_count > 16
        || packet.descriptor_count > 256
        || packet.function_count > 16384
        || packet.total_failures > packet.total_calls
        || [
            packet.discovered_mask,
            packet.verified_mask,
            packet.published_mask,
            packet.entered_mask,
            packet.returned_mask,
            packet.failure_mask,
        ]
        .iter()
        .any(|mask| mask & !0x7f != 0)
        || packet.verified_mask & !packet.discovered_mask != 0
        || packet.published_mask & !packet.verified_mask != 0
        || packet.entered_mask & !packet.published_mask != 0
        || packet.returned_mask & !packet.entered_mask != 0
        || packet.failure_mask & !packet.returned_mask != 0
        || (packet.total_failures == 0 && packet.first_failure_present != 0)
        || packet.dependencies.called != 0;
    let mut incomplete = packet.incomplete != 0
        || packet.overflow != 0
        || packet.dropped != 0
        || packet.scope_flags & 2 != 0
        || packet.callback_outcome == 3
        || (packet.total_failures > 0 && packet.first_failure_present == 0)
        || u64::from(packet.total_calls)
            > u64::from(packet.record_count) + u64::from(packet.dropped);
    let mut addresses = BTreeSet::new();
    let mut originals = std::collections::BTreeMap::new();
    let owner_end = packet
        .owner
        .owner_base
        .checked_add(u64::from(packet.owner.owner_size));
    let owner_available =
        packet.owner.owner_base != 0 && packet.owner.owner_size != 0 && packet.owner.entry != 0;
    invalid |= packet.owner.entry_len > 16
        || (packet.owner.machine != 0 && ![0x8664, 0xaa64].contains(&packet.owner.machine));
    if owner_available {
        invalid |= packet.owner.entry != packet.listener_owner_anchor
            || packet.owner.entry < packet.owner.owner_base
            || owner_end.is_none_or(|end| packet.owner.entry >= end);
    }
    incomplete |= !owner_available;
    let slots=packet.slots[..(packet.slot_count as usize).min(16)].iter().map(|slot|{
        let known=signature(slot.operation).is_some();
        invalid|=!known||!addresses.insert(slot.slot)||slot.published>1||slot.restored>1||slot.reserved!=0;
        if let Some(original)=originals.insert(slot.operation,slot.original) { invalid|=original!=slot.original; }
        if slot.published==1 { invalid|=slot.slot==0||slot.slot%8!=0||slot.original==0||slot.hook==0||slot.original==slot.hook||slot.descriptor_module==0||slot.slot<packet.owner.owner_base||owner_end.is_none_or(|end|slot.slot.checked_add(8).is_none_or(|last|last>end)); }
        incomplete|=slot.published!=1||slot.restored!=0;
        json!({"operation":signature(slot.operation).map(|(name,_,_)|name),"operation_code":slot.operation,"slot":slot.slot,"original":slot.original,"hook":slot.hook,"descriptor_module":slot.descriptor_module,"published":slot.published,"restored":slot.restored,"unsupported_or_unbound":slot.hook==0||slot.published!=1})
    }).collect::<Vec<_>>();
    let mut recent = packet.entries[..(packet.record_count as usize).min(16)]
        .iter()
        .enumerate()
        .collect::<Vec<_>>();
    recent.sort_by_key(|(_, item)| item.sequence);
    let mut ordinals = BTreeSet::new();
    let mut entries = Vec::new();
    for (index, item) in &recent {
        let (mut value, bad, partial) = entry(item, packet);
        invalid |= bad
            || !ordinals.insert(item.sequence)
            || (item.returned == 1 && !ordinals.insert(item.completion_sequence));
        incomplete |= partial;
        if item.parent_sequence != 0 {
            if let Some((_, parent)) = recent
                .iter()
                .find(|(_, parent)| parent.sequence == item.parent_sequence)
            {
                invalid |= item.depth != parent.depth + 1
                    || (parent.returned == 1
                        && item.completion_sequence > parent.completion_sequence);
            } else if packet.dropped == 0 {
                invalid = true;
            }
        }
        value["storage_index"] = json!(index);
        let recovered = item.operation == 2
            && item.returned == 1
            && failed(item)
            && [10022, 10041].contains(&item.outgoing_wsa)
            && item.arguments[5] == 0x81
            && recent.iter().any(|(_, later)| {
                later.sequence > item.completion_sequence
                    && later.operation == 2
                    && later.returned == 1
                    && !failed(later)
                    && later.parent_sequence == item.parent_sequence
                    && later.arguments[..5] == item.arguments[..5]
                    && later.arguments[5] == 1
            });
        value["observed_std_socket_fallback_recovered"] = json!(recovered);
        entries.push(value);
    }
    let first_failure = if packet.first_failure_present == 1 {
        let (value, bad, partial) = entry(&packet.first_failure, packet);
        invalid |= bad || !failed(&packet.first_failure);
        incomplete |= partial;
        invalid |= recent.iter().any(|(_, item)| {
            item.returned == 1
                && failed(item)
                && item.completion_sequence < packet.first_failure.completion_sequence
        });
        if let Some((_, recent_failure)) = recent
            .iter()
            .find(|(_, item)| item.sequence == packet.first_failure.sequence)
        {
            invalid |= **recent_failure != packet.first_failure;
        }
        Some(value)
    } else {
        None
    };
    let mut dependency_sequences = BTreeSet::new();
    let links=packet.dependency_links[..(packet.dependency_link_count as usize).min(16)].iter().map(|link|{
        let exists=packet.dependencies.entries[..(packet.dependencies.record_count as usize).min(16)].iter().any(|entry|entry.sequence==link.dependency_sequence);
        invalid|=link.dependency_sequence==0||!dependency_sequences.insert(link.dependency_sequence)||link.timeline_sequence==0||link.timeline_sequence>packet.next_sequence||!exists||!ordinals.insert(link.timeline_sequence)||link.parent_listener_sequence>=link.timeline_sequence;
        if link.parent_listener_sequence!=0 {
            if let Some((_,parent))=recent.iter().find(|(_,parent)|parent.sequence==link.parent_listener_sequence) {
                invalid|=parent.returned==1&&link.timeline_sequence>=parent.completion_sequence;
            } else if packet.dropped==0 {invalid=true;}
        }
        json!({"dependency_sequence":link.dependency_sequence,"timeline_sequence":link.timeline_sequence,"parent_listener_sequence":link.parent_listener_sequence})
    }).collect::<Vec<_>>();
    incomplete |= packet.dependency_links_dropped != 0
        || packet.dependency_link_count != packet.dependencies.record_count;
    let first_dependency_link = if packet.dependencies.first_failure_present == 1 {
        let link = &packet.first_dependency_failure_link;
        invalid |= link.dependency_sequence != packet.dependencies.first_failure.sequence
            || link.timeline_sequence == 0
            || link.timeline_sequence > packet.next_sequence
            || link.parent_listener_sequence >= link.timeline_sequence;
        Some(
            json!({"dependency_sequence":link.dependency_sequence,"timeline_sequence":link.timeline_sequence,"parent_listener_sequence":link.parent_listener_sequence}),
        )
    } else {
        None
    };
    let dependency = dependencies(&packet.dependencies);
    invalid |= packet.dependency_scope_armed == 1 && dependency["invalid_packet"] == true;
    let (returned, returned_invalid, returned_incomplete) = returned_module(packet, &mut ordinals);
    invalid |= returned_invalid;
    incomplete |= returned_incomplete;
    let (loader, loader_invalid, loader_incomplete) = loader_owner(packet, &mut ordinals);
    invalid |= loader_invalid;
    incomplete |= loader_incomplete;
    let complete = !invalid
        && !incomplete
        && packet.called == 1
        && packet.armed == 1
        && packet.setup_stage == 1
        && packet.setup_error == 0
        && packet.callbacks_complete == 1
        && packet.owner_pinned == 1
        && packet.protections_restored == 1
        && packet.rollback_error == 0
        && packet.clock_live == 1
        && packet.scope_flags == 1
        && packet.published_mask != 0
        && packet.entered_mask != 0
        && packet.frequency > 0
        && packet.started_qpc < packet.cutoff_qpc
        && packet.finished_qpc >= packet.started_qpc
        && packet.finished_qpc < packet.cutoff_qpc;
    let mut value = json!({"format":"memcordon.fixture-original-rust-listener","revision":1,"diagnostic_only":true,"acceptance_authority":false,"target_identity_proved":false,"global_routes_complete":false,"coverage_inconclusive":true,"absence_is_not_evidence":true,"failure_is_decisive_cause":false,
        "invalid_packet":invalid,"observation_incomplete":incomplete,"observed_entries_complete":complete,"aggregate":{"called":packet.called,"outcome":packet.callback_outcome,"outcome_name":match packet.callback_outcome {1=>"original-Rust-Ok",2=>"original-Rust-io-error",3=>"original-Rust-panic",_=>"not-called-or-unset"},"raw_io_error":(packet.called==1&&packet.callback_outcome==2&&packet.callback_raw_error_present==1).then_some(packet.callback_raw_error),"reported_raw_error_present":packet.callback_raw_error_present,"reported_raw_error":packet.callback_raw_error},
        "setup_stage":packet.setup_stage,"setup_error":packet.setup_error,"setup_reason":packet.setup_reason,"original_thread":packet.original_thread,"scope_flags":packet.scope_flags});
    let metadata = json!({"discovered_mask":packet.discovered_mask,"verified_mask":packet.verified_mask,"published_mask":packet.published_mask,"entered_mask":packet.entered_mask,"returned_mask":packet.returned_mask,"failure_mask":packet.failure_mask,"total_calls":packet.total_calls,"total_failures":packet.total_failures,"dropped":packet.dropped,"overflow":packet.overflow,"reported_record_count":packet.record_count,"slot_count":packet.slot_count,"descriptor_count":packet.descriptor_count,"function_count":packet.function_count,"callbacks_complete":packet.callbacks_complete,"protections_restored":packet.protections_restored,"rollback_error":packet.rollback_error,"owner_pinned":packet.owner_pinned,"clock_live":packet.clock_live,
        "started_qpc":packet.started_qpc,"finished_qpc":packet.finished_qpc,"cutoff_qpc":packet.cutoff_qpc,"frequency":packet.frequency,"next_sequence":packet.next_sequence,"listener_owner_anchor":packet.listener_owner_anchor,"incoming_win32":packet.incoming_win32,"incoming_wsa":packet.incoming_wsa,"outgoing_win32":packet.outgoing_win32,"outgoing_wsa":packet.outgoing_wsa,"dependency_scope_armed":packet.dependency_scope_armed,"dependency_scope_error":packet.dependency_scope_error,"dependency_links_dropped":packet.dependency_links_dropped});
    value
        .as_object_mut()
        .expect("listener object")
        .extend(metadata.as_object().expect("listener metadata").clone());
    let units = packet
        .owner
        .module_name
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(64);
    value["owner"] = json!({"base":packet.owner.owner_base,"size":packet.owner.owner_size,"entry":packet.owner.entry,"machine":packet.owner.machine,"timestamp":packet.owner.timestamp,"entry_bytes":&packet.owner.entry_bytes[..(packet.owner.entry_len as usize).min(16)],"module_name_utf16":&packet.owner.module_name[..units],"module_name_prefix_only":true});
    value["slots"] = json!(slots);
    value["recent_entries"] = json!(entries);
    value["first_observed_failure"] = json!(first_failure);
    value["dependency_links"] = json!(links);
    value["first_dependency_failure_link"] = json!(first_dependency_link);
    value["dependencies"] = dependency;
    value["packet_version"] = json!(packet.version);
    value["returned_module"] = returned;
    value["loader_owner"] = loader;
    value["returned_images"] = returned_images_diagnostic(packet);
    bounded(value)
}

struct Capped {
    remaining: usize,
}
impl std::io::Write for Capped {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(std::io::Error::other("listener diagnostic bound exhausted"));
        }
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn fits(value: &Value, limit: usize) -> bool {
    serde_json::to_writer(Capped { remaining: limit }, value).is_ok()
}
fn small(value: Option<&Value>, limit: usize) -> Value {
    value
        .filter(|value| fits(value, limit))
        .cloned()
        .unwrap_or(Value::Null)
}

fn security_terminal(security: &Value, state: &str) -> Value {
    let mut result = json!({"state":state,"diagnostic_only":true,"acceptance_authority":false,"denied_object_proved":false,"ordinary_details_omitted_for_bound":true});
    result["original_desired_access"] = Value::Null;
    result["original_desired_access_unavailable"] = json!(true);
    result["original_file_identity_proved"] = json!(false);
    result["continuous_token_equality_proved"] = json!(false);
    result["checks_are_hypotheses"] = json!(true);
    let ancestry = security.get("ancestry");
    let mut terminal = json!({"ordinary_rows_omitted_for_bound":true});
    for (key, limit) in [
        ("terminal", 1024),
        ("terminal_phase", 64),
        ("outer_before", 128),
        ("outer_after", 128),
        ("completed_retained", 32),
        ("omitted_rows", 32),
        ("failed", 32),
        ("valid_prefixes_and_outcomes", 32),
    ] {
        terminal[key] = small(ancestry.and_then(|value| value.get(key)), limit);
    }
    result["ancestry"] = terminal;
    let source = security.get("selection");
    let mut selection = json!({});
    for (key, limit) in [
        ("path_utf16", 2048),
        ("path_sha256", 160),
        ("path_utf16_units", 32),
        ("thread_id", 32),
        ("dependency_sequence", 32),
        ("loader_dependency_sequence", 32),
        ("parent_listener_sequence", 32),
    ] {
        selection[key] = small(source.and_then(|value| value.get(key)), limit);
    }
    if selection["path_utf16_units"].is_null() {
        selection["path_utf16_units"] = source
            .and_then(|value| value.get("path_utf16"))
            .and_then(Value::as_array)
            .map(|path| json!(path.len()))
            .unwrap_or(Value::Null);
    }
    result["selection"] = selection;
    result
}

/// Apply the same cap to the model or the bridge's binding-bearing envelope.
pub fn bounded(mut value: Value) -> Value {
    if value
        .get("post_original_loader_security")
        .is_some_and(|security| !fits(security, 8192))
    {
        value["post_original_loader_security"] = security_terminal(
            &value["post_original_loader_security"],
            "omitted-for-loader-security-bound",
        );
    }
    if fits(&value, RECORD_BYTES) {
        return value;
    }
    let trace = value.get("trace").unwrap_or(&value);
    let mut summary = json!({"format":"memcordon.fixture-original-rust-listener","revision":1,"diagnostic_only":true,"acceptance_authority":false,"target_identity_proved":false,"global_routes_complete":false,"coverage_inconclusive":true,"record_omitted_for_bound":true,"observation_incomplete":true});
    summary["returned_images"] = match trace.get("returned_images") {
        Some(images) if fits(images, 12 * 1024) => images.clone(),
        _ => {
            json!({"complete":false,"observation_incomplete":true,"omitted_for_bound":true,"acceptance_authority":false})
        }
    };
    for key in [
        "packet_version",
        "original_rust_operation",
        "original_thread",
        "started_qpc",
        "finished_qpc",
        "cutoff_qpc",
        "frequency",
        "aggregate",
        "setup_stage",
        "setup_error",
        "setup_reason",
        "invalid_packet",
        "discovered_mask",
        "verified_mask",
        "published_mask",
        "entered_mask",
        "returned_mask",
        "failure_mask",
        "total_calls",
        "total_failures",
        "dropped",
        "overflow",
        "reported_record_count",
        "dependency_scope_armed",
        "dependency_scope_error",
        "first_observed_failure",
        "first_dependency_failure_link",
    ] {
        let limit = match key {
            "first_observed_failure" => 4096,
            "aggregate" => 1024,
            "first_dependency_failure_link" => 512,
            _ => 64,
        };
        summary[key] = small(trace.get(key), limit);
    }
    summary["first_observed_dependency_failure"] = small(
        trace
            .get("dependencies")
            .and_then(|dependency| dependency.get("first_observed_failure")),
        4096,
    );
    let mut dependency_summary = json!({"record_omitted_for_bound":true,"original_startup_invoked":false,"global_routes_complete":false});
    for key in [
        "setup_stage",
        "setup_error",
        "total_calls",
        "total_failures",
        "dropped",
        "overflow",
        "reported_record_count",
        "slot_count",
        "descriptor_count",
        "function_count",
        "owner_pinned",
        "protections_restored",
        "rollback_error",
    ] {
        dependency_summary[key] = small(
            trace
                .get("dependencies")
                .and_then(|dependency| dependency.get(key)),
            64,
        );
    }
    summary["dependencies"] = dependency_summary;
    let returned = trace.get("returned_module");
    let mut returned_summary = json!({"record_omitted_for_bound":true,"observation_incomplete":true,"acceptance_authority":false,"provider_ready_proved":false,"global_routes_complete":false});
    for key in [
        "version",
        "setup_stage",
        "setup_error",
        "setup_reason",
        "selected",
        "armed",
        "scope_flags",
        "incomplete",
        "selection_count",
        "skipped_count",
        "links_dropped",
        "parent_listener_sequence",
        "loader_dependency_sequence",
        "loader_timeline_sequence",
        "returned_module",
        "invalid_scope",
        "first_failure_link",
    ] {
        returned_summary[key] = small(returned.and_then(|scope| scope.get(key)), 512);
    }
    let returned_dependency = returned.and_then(|scope| scope.get("dependencies"));
    returned_summary["first_observed_failure"] = small(
        returned_dependency.and_then(|dependency| dependency.get("first_observed_failure")),
        4096,
    );
    let mut returned_counters =
        json!({"record_omitted_for_bound":true,"original_startup_invoked":false});
    for key in [
        "setup_stage",
        "setup_error",
        "total_calls",
        "total_failures",
        "dropped",
        "overflow",
        "reported_record_count",
        "slot_count",
        "descriptor_count",
        "function_count",
        "owner_pinned",
        "protections_restored",
        "rollback_error",
    ] {
        returned_counters[key] = small(
            returned_dependency.and_then(|dependency| dependency.get(key)),
            64,
        );
    }
    returned_summary["dependencies"] = returned_counters;
    summary["returned_module"] = returned_summary;
    let loader = trace.get("loader_owner");
    let mut loader_summary = json!({"record_omitted_for_bound":true,"observation_incomplete":true,"acceptance_authority":false,"target_identity_proved":false,"global_routes_complete":false,"original_startup_invoked":false,"cross_namespace_failure_return_order_proved":false});
    for key in [
        "version",
        "setup_stage",
        "setup_error",
        "setup_reason",
        "selected",
        "armed",
        "scope_flags",
        "incomplete",
        "attempt_count",
        "skipped_count",
        "links_dropped",
        "loader_target",
        "owner_base",
        "invalid_scope",
        "first_failure_link",
        "window_count",
        "windows_dropped",
        "first_failure_window_present",
        "windows_invalid",
        "first_failure_window",
        "invalid_windows",
        "windows_observation_incomplete",
        "window_clock_domain",
        "window_failure_is_decisive_cause",
    ] {
        loader_summary[key] = small(loader.and_then(|scope| scope.get(key)), 1024);
    }
    let windows = loader.and_then(|scope| scope.get("windows"));
    loader_summary["windows"] = small(windows, 16 * 1024);
    loader_summary["windows_omitted_for_bound"] =
        json!(windows.is_some_and(|value| !fits(value, 16 * 1024)));
    let loader_dependency = loader.and_then(|scope| scope.get("dependencies"));
    loader_summary["LdrLoadDll_normal_import_published"] = small(
        loader_dependency
            .and_then(|dependency| dependency.get("LdrLoadDll_normal_import_published")),
        64,
    );
    loader_summary["first_observed_failure"] = small(
        loader_dependency.and_then(|dependency| dependency.get("first_observed_failure")),
        4096,
    );
    let mut counters = json!({"record_omitted_for_bound":true,"original_startup_invoked":false});
    for key in [
        "setup_stage",
        "setup_error",
        "total_calls",
        "total_failures",
        "dropped",
        "overflow",
        "reported_record_count",
        "slot_count",
        "descriptor_count",
        "function_count",
        "owner_pinned",
        "protections_restored",
        "rollback_error",
    ] {
        counters[key] = small(
            loader_dependency.and_then(|dependency| dependency.get(key)),
            64,
        );
    }
    loader_summary["dependencies"] = counters;
    summary["loader_owner"] = loader_summary;
    let mut result = if value.get("trace").is_some() {
        json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":small(value.get("original_binding"),16*1024),"binding_omitted_if_oversize":!value.get("original_binding").is_some_and(|binding|fits(binding,16*1024)),"trace":summary,"record_omitted_for_envelope_bound":true,"acceptance_authority":false})
    } else {
        summary
    };
    if let Some(security) = value.get("post_original_loader_security") {
        result["post_original_loader_security"] = security.clone();
        if !fits(&result, RECORD_BYTES) {
            result["post_original_loader_security"] =
                security_terminal(security, "omitted-for-listener-envelope-bound");
        }
    }
    if !fits(&result, RECORD_BYTES) {
        let trace = if result.get("trace").is_some() {
            &mut result["trace"]
        } else {
            &mut result
        };
        trace["returned_images"] = json!({"complete":false,"observation_incomplete":true,"omitted_for_bound":true,"acceptance_authority":false});
    }
    result
}
