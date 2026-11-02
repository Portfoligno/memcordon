#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
mod gate_entry_route;
#[path = "../src/bin/consumer_readiness_windows/listener_trace_record.rs"]
mod record;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_record.rs"]
mod winsock_trace_record;
use record::{Entry, Packet, diagnostic};
use serde_json::json;

fn base() -> Packet {
    let mut value = Packet {
        version: 3,
        setup_stage: 1,
        called: 1,
        callback_outcome: 1,
        armed: 1,
        original_thread: 7,
        scope_flags: 1,
        callbacks_complete: 1,
        owner_pinned: 1,
        protections_restored: 1,
        clock_live: 1,
        started_qpc: 1,
        finished_qpc: 9,
        cutoff_qpc: 100,
        frequency: 10,
        listener_owner_anchor: 0x1100,
        discovered_mask: 0x7f,
        verified_mask: 0x7f,
        published_mask: 0x7f,
        slot_count: 7,
        ..Packet::default()
    };
    value.returned_module.version = 1;
    value.returned_module.dependencies.version = 1;
    value.returned_module.dependencies.original_thread = value.original_thread;
    value.returned_module.dependencies.cutoff_qpc = value.cutoff_qpc;
    value.returned_module.dependencies.frequency = value.frequency;
    value.loader_owner.version = 1;
    value.loader_owner.dependencies.version = 1;
    value.loader_owner.dependencies.original_thread = value.original_thread;
    value.loader_owner.dependencies.cutoff_qpc = value.cutoff_qpc;
    value.loader_owner.dependencies.frequency = value.frequency;
    value.owner = winsock_trace_record::Node {
        owner_base: 0x1000,
        entry: 0x1100,
        owner_size: 0x1000,
        machine: 0x8664,
        ..Default::default()
    };
    for (index, slot) in value.slots[..7].iter_mut().enumerate() {
        *slot = winsock_trace_record::Slot {
            slot: 0x1800 + index as u64 * 8,
            original: 0x2000 + index as u64,
            hook: 0x3000 + index as u64,
            descriptor_module: 0x4000,
            operation: index as u32 + 1,
            published: 1,
            ..Default::default()
        };
    }
    value
}

fn returned_scope() -> Packet {
    let mut value = base();
    install(&mut value, &[call(2, 1, 8, 42)]);
    value.dependencies.version = 1;
    value.dependencies.original_thread = 7;
    value.dependencies.total_calls = 1;
    value.dependencies.record_count = 1;
    value.dependencies.entries[0] = winsock_trace_record::Entry {
        sequence: 1,
        operation: 12,
        thread_id: 7,
        entered: 1,
        returned: 1,
        raw_output: 0x8000,
        output_flags: 3,
        scalar_flags: 4,
        ..Default::default()
    };
    value.dependency_link_count = 1;
    value.dependency_links[0] = record::DependencyLink {
        dependency_sequence: 1,
        timeline_sequence: 2,
        parent_listener_sequence: 1,
    };
    let scope = &mut value.returned_module;
    scope.selected = 1;
    scope.armed = 1;
    scope.setup_stage = 1;
    scope.scope_flags = 1;
    scope.selection_count = 1;
    scope.returned_module = 0x8000;
    scope.parent_listener_sequence = 1;
    scope.loader_dependency_sequence = 1;
    scope.loader_timeline_sequence = 2;
    scope.link_count = 1;
    scope.links[0] = record::DependencyLink {
        dependency_sequence: 1,
        timeline_sequence: 4,
        parent_listener_sequence: 1,
    };
    scope.first_failure_link = scope.links[0];
    let events = &mut scope.dependencies;
    events.version = 1;
    events.setup_stage = 1;
    events.armed = 1;
    events.owner_pinned = 1;
    events.callbacks_complete = 1;
    events.protections_restored = 1;
    events.original_thread = 7;
    events.frequency = 10;
    events.cutoff_qpc = 100;
    events.total_calls = 1;
    events.total_failures = 1;
    events.record_count = 1;
    events.first_failure_present = 1;
    events.node_count = 1;
    events.slot_count = 1;
    events.slots[0] = winsock_trace_record::Slot {
        slot: 0x8800,
        operation: 10,
        original: 0xa000,
        hook: 0xb000,
        descriptor_module: 0xc000,
        published: 1,
        ..Default::default()
    };
    events.nodes[0] = winsock_trace_record::Node {
        owner_base: 0x8000,
        owner_size: 0x1000,
        machine: 0xaa64,
        ..Default::default()
    };
    events.entries[0] = winsock_trace_record::Entry {
        sequence: 1,
        operation: 10,
        thread_id: 7,
        entered: 1,
        returned: 1,
        native_status: 2,
        ..Default::default()
    };
    events.first_failure = events.entries[0];
    value
}

fn loader_scope() -> Packet {
    let mut value = returned_scope();
    value.returned_module = record::ReturnedModule::default();
    value.returned_module.version = 1;
    value.returned_module.dependencies.version = 1;
    value.dependency_scope_armed = 1;
    let startup = &mut value.dependencies;
    startup.armed = 1;
    startup.setup_stage = 1;
    startup.owner_pinned = 1;
    startup.callbacks_complete = 1;
    startup.protections_restored = 1;
    startup.cutoff_qpc = 100;
    startup.frequency = 10;
    startup.node_count = 1;
    startup.nodes[0] = winsock_trace_record::Node {
        owner_base: 0x9000,
        entry: 0x9100,
        owner_size: 0x4000,
        machine: 0xaa64,
        ..Default::default()
    };
    startup.slot_count = 1;
    startup.slots[0] = winsock_trace_record::Slot {
        slot: 0x9800,
        operation: 12,
        original: 0xa100,
        hook: 0xb100,
        descriptor_module: 0xc000,
        published: 1,
        ..Default::default()
    };
    startup.entries[0].native_status = 1;
    startup.entries[0].raw_output = 0;
    startup.entries[0].output_flags = 1;
    startup.entries[0].outgoing_error = 5;
    startup.total_failures = 1;
    startup.first_failure_present = 1;
    startup.first_failure = startup.entries[0];
    value.first_dependency_failure_link = value.dependency_links[0];
    let scope = &mut value.loader_owner;
    scope.selected = 1;
    scope.armed = 1;
    scope.setup_stage = 1;
    scope.scope_flags = 1;
    scope.attempt_count = 1;
    scope.loader_target = 0xa100;
    scope.owner_base = 0xa000;
    scope.link_count = 1;
    scope.links[0] = record::LoaderLink {
        dependency_sequence: 1,
        timeline_sequence: 3,
        parent_listener_sequence: 1,
        loader_dependency_sequence: 1,
        loader_timeline_sequence: 2,
    };
    scope.first_failure_link = scope.links[0];
    let events = &mut scope.dependencies;
    events.setup_stage = 1;
    events.armed = 1;
    events.owner_pinned = 1;
    events.callbacks_complete = 1;
    events.protections_restored = 1;
    events.node_count = 1;
    events.nodes[0] = winsock_trace_record::Node {
        owner_base: 0xa000,
        entry: 0xa100,
        owner_size: 0x2000,
        machine: 0xaa64,
        ..Default::default()
    };
    events.slot_count = 1;
    events.slots[0] = winsock_trace_record::Slot {
        slot: 0xa800,
        operation: 4,
        original: 0xd000,
        hook: 0xe000,
        descriptor_module: 0xf000,
        published: 1,
        ..Default::default()
    };
    events.total_calls = 1;
    events.total_failures = 1;
    events.record_count = 1;
    events.first_failure_present = 1;
    events.entries[0] = winsock_trace_record::Entry {
        sequence: 1,
        operation: 4,
        thread_id: 7,
        entered: 1,
        returned: 1,
        native_status: 0xc000_0022u32 as i32,
        ..Default::default()
    };
    events.first_failure = events.entries[0];
    value
}

#[test]
fn loader_owner_records_are_bound_to_both_original_call_namespaces() {
    let value = loader_scope();
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert_eq!(
        rendered["loader_owner"]["dependencies"]["LdrLoadDll_normal_import_published"],
        true
    );
    let mut other_route = loader_scope();
    other_route.loader_owner.dependencies.slots[0].operation = 9;
    other_route.loader_owner.dependencies.entries[0].operation = 9;
    other_route.loader_owner.dependencies.entries[0].native_status = 1;
    other_route.loader_owner.dependencies.entries[0].output_flags = 1;
    other_route.loader_owner.dependencies.first_failure =
        other_route.loader_owner.dependencies.entries[0];
    let other = diagnostic(&other_route);
    assert_eq!(other["invalid_packet"], false, "{other}");
    assert_eq!(
        other["loader_owner"]["dependencies"]["LdrLoadDll_normal_import_published"],
        false
    );
    assert_eq!(other["loader_owner"]["observation_incomplete"], true);
    assert_eq!(
        other["loader_owner"]["armed"], 1,
        "other valid routes remain useful"
    );
    assert_eq!(
        rendered["loader_owner"]["links"][0]["loader_parent_namespace"],
        "startup"
    );
    assert_eq!(
        rendered["loader_owner"]["links"][0]["loader_dependency_sequence"],
        1
    );
    assert_eq!(
        rendered["loader_owner"]["dependencies"]["original_startup_invoked"],
        false
    );
    assert!(
        rendered["loader_owner"]["dependencies"]
            .get("original_startup_return")
            .is_none()
    );
    assert_eq!(
        rendered["loader_owner"]["cross_namespace_failure_return_order_proved"],
        false
    );
    for mutation in 0..16 {
        let mut bad = loader_scope();
        match mutation {
            0 => bad.loader_owner.owner_base = 0,
            1 => bad.loader_owner.loader_target = 0x20000,
            2 => bad.loader_owner.dependencies.nodes[0].owner_base += 8,
            3 => bad.loader_owner.attempt_count = 0,
            4 => bad.dependencies.slots[0].original += 8,
            5 => bad.loader_owner.scope_flags = 4,
            6 => bad.loader_owner.dependencies.hop_count = 1,
            7 => bad.loader_owner.dependencies.record_count = 17,
            8 => bad.loader_owner.links[0].dependency_sequence = 2,
            9 => bad.loader_owner.links[0].timeline_sequence = 2,
            10 => bad.loader_owner.links[0].parent_listener_sequence = 2,
            11 => bad.loader_owner.links[0].loader_dependency_sequence = 2,
            12 => bad.loader_owner.links[0].loader_timeline_sequence = 3,
            13 => bad.dependencies.entries[0].operation = 9,
            14 => bad.loader_owner.dependencies.entries[0].thread_id = 8,
            15 => bad.loader_owner.dependencies.cutoff_qpc += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            diagnostic(&bad)["invalid_packet"],
            true,
            "mutation {mutation}"
        );
    }
}

#[test]
fn evicted_loader_or_socket_parents_are_incomplete_rather_than_invented() {
    for which in 0..2 {
        let mut value = loader_scope();
        if which == 0 {
            value.dependencies.record_count = 0;
            value.dependencies.dropped = 1;
            value.dependencies.total_failures = 0;
            value.dependencies.first_failure_present = 0;
            value.dependency_link_count = 0;
            value.dependency_links_dropped = 1;
        } else {
            value.record_count = 0;
            value.first_failure_present = 0;
            value.total_failures = 0;
            value.failure_mask = 0;
            value.dropped = 1;
        }
        let rendered = diagnostic(&value);
        assert_eq!(
            rendered["invalid_packet"], false,
            "which={which}; {rendered}"
        );
        assert_eq!(rendered["loader_owner"]["observation_incomplete"], true);
        if which == 0 {
            value.dependencies.dropped = 0;
            value.dependency_links_dropped = 0;
        } else {
            value.dropped = 0;
        }
        assert_eq!(diagnostic(&value)["invalid_packet"], true);
    }
}

#[test]
fn loader_observer_setup_errors_do_not_replace_original_failed_loader_errors() {
    let mut value = loader_scope();
    value.loader_owner.setup_stage = 9;
    value.loader_owner.setup_error = 126;
    value.loader_owner.setup_reason = 5;
    value.loader_owner.incomplete = 1;
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert_eq!(rendered["loader_owner"]["setup_error"], 126);
    assert_eq!(
        rendered["dependencies"]["first_observed_failure"]["outgoing_last_error"],
        5
    );
    assert_eq!(
        rendered["loader_owner"]["first_observed_failure_is_decisive_cause"],
        false
    );
    let bounded = record::bounded(
        json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":{"pid":123},"trace":rendered,"extra":"\\\"".repeat(100000)}),
    );
    assert!(serde_json::to_vec(&bounded).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(bounded["original_binding"]["pid"], 123);
    assert_eq!(bounded["trace"]["loader_owner"]["setup_error"], 126);
    assert_eq!(
        bounded["trace"]["loader_owner"]["first_observed_failure"]["native_status_or_adapter_marker"],
        0xc000_0022u32 as i32
    );
    assert_eq!(
        bounded["trace"]["loader_owner"]["acceptance_authority"],
        false
    );
}

#[test]
fn appended_abi_and_historical_json_are_explicit_without_v1_reinterpretation() {
    use std::mem::{offset_of, size_of};
    assert_eq!(size_of::<Packet>(), 40744);
    assert_eq!(size_of::<record::ReturnedModule>(), 12136);
    assert_eq!(offset_of!(Packet, returned_module), 16216);
    assert_eq!(size_of::<record::LoaderLink>(), 40);
    assert_eq!(size_of::<record::LoaderOwner>(), 12392);
    assert_eq!(offset_of!(Packet, loader_owner), 28352);
    assert_eq!(offset_of!(record::LoaderOwner, dependencies), 64);
    assert_eq!(offset_of!(record::LoaderOwner, first_failure_link), 11712);
    assert_eq!(offset_of!(record::LoaderOwner, links), 11752);
    let mut value = base();
    value.version = 1;
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
    value.version = 2;
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
    let historical = json!({"format":"memcordon.original-rust-listener-trace","revision":1,"trace":{"format":"memcordon.fixture-original-rust-listener","revision":1,"aggregate":{"called":1,"outcome":2,"raw_io_error":2}}});
    let bytes = serde_json::to_vec(&historical).unwrap();
    let parsed = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record::bounded(parsed), historical);
}

#[test]
fn returned_owner_scope_has_its_own_sequences_and_exact_loader_binding() {
    let value = returned_scope();
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert_eq!(rendered["dependency_links"][0]["dependency_sequence"], 1);
    assert_eq!(
        rendered["returned_module"]["links"][0]["dependency_sequence"],
        1
    );
    assert_eq!(
        rendered["returned_module"]["dependencies"]["original_startup_invoked"],
        false
    );
    assert_eq!(
        rendered["returned_module"]["WSPStartup_invocation_observed"],
        false
    );
    assert_eq!(
        rendered["returned_module"]["dependencies"]["owner_entrypoint_unobserved"],
        true
    );
    let mut later_capacity = returned_scope();
    later_capacity.returned_module.setup_stage = 9;
    later_capacity.returned_module.setup_error = 50;
    later_capacity.returned_module.setup_reason = 4;
    later_capacity.returned_module.incomplete = 1;
    assert_eq!(
        diagnostic(&later_capacity)["invalid_packet"],
        false,
        "a later skipped owner does not erase the first armed route"
    );
    for mutation in 0..15 {
        let mut value = returned_scope();
        match mutation {
            0 => value.returned_module.returned_module = 0x9000,
            1 => value.returned_module.parent_listener_sequence = 99,
            2 => value.returned_module.loader_dependency_sequence = 99,
            3 => value.returned_module.loader_timeline_sequence = 3,
            4 => value.returned_module.links[0].timeline_sequence = 2,
            5 => value.returned_module.links[0].timeline_sequence = 9,
            6 => value.returned_module.dependencies.original_thread = 8,
            7 => value.returned_module.dependencies.called = 1,
            8 => value.returned_module.dependencies.cutoff_qpc = 101,
            9 => value.returned_module.dependencies.entries[0].thread_id = 8,
            10 => {
                value.returned_module.link_count = 2;
                value.returned_module.links[1] = value.returned_module.links[0];
            }
            11 => value.dependencies.entries[0].native_status = 1,
            12 => value.returned_module.first_failure_link.timeline_sequence = 5,
            13 => value.returned_module.dependencies.descriptor_count = 257,
            14 => value.returned_module.dependencies.function_count = 16385,
            _ => unreachable!(),
        }
        assert_eq!(
            diagnostic(&value)["invalid_packet"],
            true,
            "mutation {mutation}"
        );
    }
}

#[test]
fn returned_duplicate_api_slots_require_distinct_addresses_and_identical_targets() {
    let mut value = returned_scope();
    let events = &mut value.returned_module.dependencies;
    events.slot_count = 2;
    for (index, slot) in events.slots[..2].iter_mut().enumerate() {
        *slot = winsock_trace_record::Slot {
            slot: 0x8800 + index as u64 * 8,
            operation: 10,
            original: 0xa000,
            hook: 0xb000,
            descriptor_module: 0xc000,
            published: 1,
            ..Default::default()
        };
    }
    assert_eq!(diagnostic(&value)["invalid_packet"], false);
    assert_eq!(
        winsock_trace_record::diagnostic(&value.returned_module.dependencies)["invalid_packet"],
        true,
        "standalone startup remains strict"
    );
    value.returned_module.dependencies.slots[1].original += 1;
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
    value.returned_module.dependencies.slots[1].original -= 1;
    value.returned_module.dependencies.slots[1].slot = 0x8800;
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
}

#[test]
fn bounded_provider_failure_retains_namespace_binding_counters_and_saturation() {
    let mut value = returned_scope();
    value.returned_module.selection_count = u32::MAX;
    value.returned_module.skipped_count = u32::MAX - 1;
    value.returned_module.links_dropped = u32::MAX;
    value.returned_module.setup_stage = 9;
    value.returned_module.setup_error = 50;
    value.returned_module.setup_reason = 4;
    value.returned_module.dependencies.first_failure.name = [0xffff; 256];
    value
        .returned_module
        .dependencies
        .first_failure
        .copied_name_units = 256;
    value
        .returned_module
        .dependencies
        .first_failure
        .reported_name_bytes = 512;
    value.returned_module.dependencies.first_failure.name_flags = 5;
    value.returned_module.dependencies.entries[0] =
        value.returned_module.dependencies.first_failure;
    let trace = diagnostic(&value);
    let rendered = record::bounded(
        json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":{"pid":123,"descriptor_sha256":[1,2,3]},"trace":trace,"oversized":"\\\"\n".repeat(100000)}),
    );
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(rendered["original_binding"]["pid"], 123);
    assert_eq!(
        rendered["trace"]["returned_module"]["selection_count"],
        u32::MAX
    );
    assert_eq!(
        rendered["trace"]["returned_module"]["first_observed_failure"]["native_status_or_adapter_marker"],
        2
    );
    assert_eq!(
        rendered["trace"]["returned_module"]["acceptance_authority"],
        false
    );
    assert_eq!(rendered["trace"]["returned_module"]["setup_stage"], 9);
    assert_eq!(
        rendered["trace"]["returned_module"]["dependencies"]["setup_stage"],
        1
    );
    assert_eq!(
        rendered["trace"]["returned_module"]["dependencies"]["total_calls"],
        1
    );
}
fn call(operation: u32, sequence: u64, completion: u64, result: u64) -> Entry {
    Entry {
        operation,
        sequence,
        completion_sequence: completion,
        result,
        entered: 1,
        returned: 1,
        thread_id: 7,
        error_domain: match operation {
            1 => 1,
            3 => 3,
            _ => 2,
        },
        outgoing_win32: 5,
        outgoing_wsa: 2,
        ..Entry::default()
    }
}
fn install(value: &mut Packet, calls: &[Entry]) {
    value.record_count = calls.len() as u32;
    value.total_calls = calls.len() as u32;
    let mut first = None;
    for (index, entry) in calls.iter().enumerate() {
        value.entries[index] = *entry;
        value.entered_mask |= 1 << (entry.operation - 1);
        value.returned_mask |= 1 << (entry.operation - 1);
        value.next_sequence = value.next_sequence.max(entry.completion_sequence);
        if entry.failed == 1 {
            value.total_failures += 1;
            value.failure_mask |= 1 << (entry.operation - 1);
            if first.is_none_or(|previous: Entry| {
                entry.completion_sequence < previous.completion_sequence
            }) {
                first = Some(*entry);
            }
        }
    }
    if let Some(first) = first {
        value.first_failure_present = 1;
        value.first_failure = first;
    }
}

#[test]
fn every_signature_uses_its_return_domain_and_not_stale_error_state() {
    for (operation, result, error) in [
        (1, 10093, 10093),
        (2, u64::MAX, 2),
        (3, 0, 5),
        (4, u64::from(u32::MAX), 2),
        (5, u64::from(u32::MAX), 2),
        (6, u64::from(u32::MAX), 2),
        (7, u64::from(u32::MAX), 2),
    ] {
        let mut value = base();
        let mut failure = call(operation, 1, 2, result);
        failure.failed = 1;
        install(&mut value, &[failure]);
        value.callback_outcome = 2;
        value.callback_raw_error_present = 1;
        value.callback_raw_error = error;
        let rendered = diagnostic(&value);
        assert_eq!(rendered["invalid_packet"], false, "{rendered}");
        assert_eq!(rendered["recent_entries"][0]["observed_failure"], true);
        assert_eq!(rendered["recent_entries"][0]["original_error"], error);
        let success_result = match operation {
            2 => 0xffff_0000_1234_5678,
            3 => 1,
            _ => 0,
        };
        let mut value = base();
        let mut success = call(operation, 1, 2, success_result);
        if operation == 1 {
            success.output_valid = 1;
            success.output_u32 = 0x202;
        }
        install(&mut value, &[success]);
        let rendered = diagnostic(&value);
        assert_eq!(rendered["recent_entries"][0]["observed_failure"], false);
        assert!(rendered["recent_entries"][0]["original_error"].is_null());
        assert_eq!(rendered["recent_entries"][0]["result_raw"], success_result);
        assert_eq!(rendered["aggregate"]["outcome"], 1);
    }
}

#[test]
fn recovered_socket_attempt_is_distinct_from_original_result_and_later_cleanup() {
    let mut first = call(2, 1, 2, u64::MAX);
    first.arguments = [2, 1, 0, 0, 0, 0x81];
    first.outgoing_wsa = 10022;
    first.failed = 1;
    let mut retry = call(2, 3, 4, 0xdead_beef_1234_5678);
    retry.arguments = [2, 1, 0, 0, 0, 1];
    let mut value = base();
    install(&mut value, &[first, retry]);
    let rendered = diagnostic(&value);
    assert_eq!(rendered["aggregate"]["outcome_name"], "original-Rust-Ok");
    assert_eq!(
        rendered["recent_entries"][0]["observed_std_socket_fallback_recovered"],
        true
    );
    assert_eq!(rendered["failure_is_decisive_cause"], false);
    let mut bind = call(4, 5, 6, u64::from(u32::MAX));
    bind.failed = 1;
    let mut close = call(6, 7, 8, u64::from(u32::MAX));
    close.failed = 1;
    close.outgoing_wsa = 10038;
    let mut value = base();
    install(&mut value, &[first, retry, bind, close]);
    value.callback_outcome = 2;
    value.callback_raw_error_present = 1;
    value.callback_raw_error = 2;
    let rendered = diagnostic(&value);
    assert_eq!(rendered["aggregate"]["raw_io_error"], 2);
    assert_eq!(rendered["recent_entries"][2]["operation"], "bind");
    assert_eq!(rendered["recent_entries"][3]["original_error"], 10038);
    assert_eq!(
        rendered["first_observed_failure"]["operation"],
        "WSASocketW"
    );
}

#[test]
fn nested_return_order_and_ring_loss_remain_explicit() {
    let mut parent = call(4, 1, 4, u64::from(u32::MAX));
    parent.failed = 1;
    let mut child = call(3, 2, 3, 0);
    child.failed = 1;
    child.parent_sequence = 1;
    child.depth = 1;
    let mut value = base();
    install(&mut value, &[child, parent]);
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert_eq!(rendered["recent_entries"][0]["sequence"], 1);
    assert_eq!(rendered["recent_entries"][0]["storage_index"], 1);
    assert_eq!(rendered["first_observed_failure"]["sequence"], 2);
    value.dropped = 3;
    value.total_calls += 3;
    let rendered = diagnostic(&value);
    assert_eq!(rendered["observation_incomplete"], true);
    assert_eq!(rendered["global_routes_complete"], false);
    assert_eq!(rendered["acceptance_authority"], false);
}

#[test]
fn malformed_counts_domains_masks_parent_links_and_flags_are_refused_without_slicing_panics() {
    for mutation in 0..11 {
        let mut value = base();
        install(&mut value, &[call(4, 1, 2, 0)]);
        match mutation {
            0 => value.record_count = 17,
            1 => value.slot_count = 17,
            2 => value.entries[0].operation = 8,
            3 => value.entries[0].error_domain = 3,
            4 => value.entries[0].parent_sequence = 1,
            5 => value.entries[0].completion_sequence = 1,
            6 => value.entries[0].input_bytes = 33,
            7 => value.verified_mask = 0x80,
            8 => value.dependencies.called = 1,
            9 => value.dependency_link_count = 17,
            10 => value.entries[0].flags = 1,
            _ => unreachable!(),
        }
        assert_eq!(
            diagnostic(&value)["invalid_packet"],
            true,
            "mutation {mutation}"
        );
    }
    let mut value = base();
    install(&mut value, &[call(4, 1, 2, 0)]);
    value.entries[0].input_flags = 2;
    assert_eq!(diagnostic(&value)["observation_incomplete"], true);
    let mut bad = call(4, 1, 2, u64::from(u32::MAX));
    bad.failed = 1;
    bad.error_domain = 255;
    let mut value = base();
    install(&mut value, &[bad]);
    assert!(diagnostic(&value)["recent_entries"][0]["original_error"].is_null());
    value.callback_raw_error_present = 1;
    value.callback_raw_error = 87;
    let rendered = diagnostic(&value);
    assert!(rendered["aggregate"]["raw_io_error"].is_null());
    assert_eq!(rendered["aggregate"]["reported_raw_error"], 87);
}

#[test]
fn dependency_records_are_linked_to_listener_scope_without_inventing_a_startup_result() {
    let mut value = base();
    install(&mut value, &[call(4, 1, 4, 0)]);
    value.dependency_scope_armed = 1;
    value.dependency_link_count = 1;
    value.dependencies.version = 1;
    value.dependencies.original_thread = 7;
    value.dependencies.record_count = 1;
    value.dependencies.total_calls = 1;
    value.dependencies.total_failures = 1;
    value.dependencies.first_failure_present = 1;
    value.dependencies.slot_count = 1;
    value.dependencies.node_count = 1;
    value.dependencies.nodes[0] = winsock_trace_record::Node {
        owner_base: 0x4000,
        owner_size: 0x1000,
        entry: 0x4100,
        machine: 0xaa64,
        ..Default::default()
    };
    value.dependencies.slots[0] = winsock_trace_record::Slot {
        slot: 0x4800,
        original: 0x5000,
        hook: 0x6000,
        descriptor_module: 0x7000,
        operation: 10,
        published: 1,
        ..Default::default()
    };
    let dependency = winsock_trace_record::Entry {
        sequence: 1,
        thread_id: 7,
        operation: 10,
        entered: 1,
        returned: 1,
        native_status: 5,
        ..Default::default()
    };
    value.dependencies.entries[0] = dependency;
    value.dependencies.first_failure = dependency;
    value.dependency_links[0] = record::DependencyLink {
        dependency_sequence: 1,
        timeline_sequence: 2,
        parent_listener_sequence: 1,
    };
    value.first_dependency_failure_link = value.dependency_links[0];
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert_eq!(rendered["dependencies"]["original_startup_invoked"], false);
    assert!(
        rendered["dependencies"]
            .get("raw_original_return")
            .is_none()
    );
    assert!(
        rendered["dependencies"]
            .get("original_startup_return")
            .is_none()
    );
    assert_eq!(rendered["dependency_links"][0]["timeline_sequence"], 2);
    value.dependency_links[0].dependency_sequence = 2;
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
}

#[test]
fn bounded_envelope_keeps_original_error_first_failure_and_binding() {
    let mut value = base();
    let mut failure = call(4, 1, 2, u64::from(u32::MAX));
    failure.failed = 1;
    install(&mut value, &[failure]);
    value.callback_outcome = 2;
    value.callback_raw_error_present = 1;
    value.callback_raw_error = 2;
    let trace = diagnostic(&value);
    let envelope = json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":{"pid":9001,"creation_time_100ns":77,"descriptor_sha256":vec![4;32],"prior_admitted_token_envelope_sha256":vec![5;32],"current_process_token":{"sha256":vec![6;32]},"current_effective_token":{"sha256":vec![7;32]}},"trace":trace,"oversize":"x".repeat(100000)});
    let rendered = record::bounded(envelope);
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(rendered["trace"]["aggregate"]["raw_io_error"], 2);
    assert_eq!(
        rendered["trace"]["first_observed_failure"]["operation"],
        "bind"
    );
    assert_eq!(rendered["original_binding"]["pid"], 9001);
    assert_eq!(rendered["record_omitted_for_envelope_bound"], true);
    assert_eq!(rendered["trace"]["global_routes_complete"], false);
}

#[test]
fn full_native_rings_and_maximum_raw_names_stay_within_serialized_bound() {
    let mut value = base();
    let calls = (0..16)
        .map(|index| {
            let mut entry = call(4, index * 4 + 1, index * 4 + 4, 0);
            entry.input_prefix = [255; 32];
            entry.input_bytes = 32;
            entry.input_flags = 5;
            entry
        })
        .collect::<Vec<_>>();
    install(&mut value, &calls);
    value.dependency_scope_armed = 1;
    value.dependency_link_count = 16;
    value.dependencies.version = 1;
    value.dependencies.original_thread = 7;
    value.dependencies.record_count = 16;
    value.dependencies.total_calls = 16;
    value.dependencies.total_failures = 16;
    value.dependencies.first_failure_present = 1;
    value.dependencies.slot_count = 1;
    value.dependencies.node_count = 1;
    value.dependencies.nodes[0] = winsock_trace_record::Node {
        owner_base: 0x4000,
        owner_size: 0x1000,
        entry: 0x4100,
        machine: 0x8664,
        ..Default::default()
    };
    value.dependencies.slots[0] = winsock_trace_record::Slot {
        slot: 0x4800,
        original: 0x5000,
        hook: 0x6000,
        descriptor_module: 0x7000,
        operation: 10,
        published: 1,
        ..Default::default()
    };
    for index in 0..16 {
        value.dependencies.entries[index] = winsock_trace_record::Entry {
            sequence: index as u64 + 1,
            thread_id: 7,
            operation: 10,
            entered: 1,
            returned: 1,
            native_status: 5,
            reported_name_bytes: 512,
            copied_name_units: 256,
            name_flags: 1,
            name: [u16::MAX; 256],
            ..Default::default()
        };
        value.dependency_links[index] = record::DependencyLink {
            dependency_sequence: index as u64 + 1,
            timeline_sequence: index as u64 * 4 + 2,
            parent_listener_sequence: index as u64 * 4 + 1,
        };
    }
    value.dependencies.first_failure = value.dependencies.entries[0];
    value.first_dependency_failure_link = value.dependency_links[0];
    let rendered = diagnostic(&value);
    assert_eq!(rendered["invalid_packet"], false, "{rendered}");
    assert!(serde_json::to_vec(&rendered).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(rendered["acceptance_authority"], false);
    assert_eq!(rendered["global_routes_complete"], false);
}
