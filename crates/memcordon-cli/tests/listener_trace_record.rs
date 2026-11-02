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
        version: 1,
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
