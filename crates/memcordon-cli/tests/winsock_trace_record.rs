#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
mod gate_entry_route;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_record.rs"]
mod record;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_path.rs"]
mod trace_path;
use record::{Entry, Node, Packet, Slot, diagnostic};
use std::mem::{offset_of, size_of};

#[test]
fn root_and_peer_startup_records_coexist_without_overwrite() {
    use std::{
        fs::{self, OpenOptions},
        io::Write,
    };
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join(trace_path::startup_trace_leaf(false));
    let peer = temporary.path().join(trace_path::startup_trace_leaf(true));
    assert_ne!(root, peer);
    for (path, bytes) in [(&root, b"root".as_slice()), (&peer, b"peer".as_slice())] {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        assert_eq!(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::AlreadyExists
        );
    }
    assert_eq!(fs::read(root).unwrap(), b"root");
    assert_eq!(fs::read(peer).unwrap(), b"peer");
}

fn ready() -> Packet {
    let mut value = Packet {
        version: 1,
        setup_stage: 1,
        called: 1,
        original_return: 10107,
        requested_version: 0x0202,
        incoming_error: 77,
        outgoing_error: 15100,
        armed: 1,
        original_thread: 9044,
        scope_flags: 1,
        node_count: 1,
        slot_count: 1,
        callbacks_complete: 1,
        protections_restored: 1,
        owner_pinned: 1,
        clock_live: 1,
        started_qpc: 10,
        finished_qpc: 20,
        cutoff_qpc: 100,
        frequency: 1000,
        ..Packet::default()
    };
    value.nodes[0] = Node {
        owner_base: 0x100000,
        entry: 0x101000,
        owner_size: 0x10000,
        machine: 0xaa64,
        entry_len: 12,
        ..Node::default()
    };
    for (slot, unit) in value.nodes[0]
        .module_name
        .iter_mut()
        .zip("WS2_32.dll".encode_utf16())
    {
        *slot = unit;
    }
    value.slots[0] = Slot {
        slot: 0x102000,
        original: 0x200000,
        hook: 0x300000,
        descriptor_module: 0x200000,
        operation: 1,
        published: 1,
        ..Slot::default()
    };
    value
}
#[test]
fn returned_route_repeated_api_slots_do_not_weaken_standalone_validation() {
    let mut value = ready();
    value.slot_count = 2;
    value.slots[1] = Slot {
        slot: value.slots[0].slot + 8,
        ..value.slots[0]
    };
    assert_eq!(diagnostic(&value)["invalid_packet"], true);
    assert_eq!(
        record::returned_module_diagnostic(&value)["invalid_packet"],
        false
    );
    value.slots[1].original += 8;
    assert_eq!(
        record::returned_module_diagnostic(&value)["invalid_packet"],
        true
    );
    value.slots[1].original -= 8;
    value.slots[1].slot = value.slots[0].slot;
    assert_eq!(
        record::returned_module_diagnostic(&value)["invalid_packet"],
        true
    );
}
fn event(operation: u32, sequence: u64) -> Entry {
    let mut entry = Entry {
        operation,
        sequence,
        thread_id: 9044,
        entered: 1,
        returned: 1,
        desired_access: 0xf,
        native_status: if [9, 12, 13, 14, 15, 16].contains(&operation) {
            1
        } else {
            5
        },
        incoming_error: 99,
        outgoing_error: 8,
        reported_name_bytes: 6,
        copied_name_units: 3,
        name_flags: 1,
        scalar_flags: 7,
        ..Entry::default()
    };
    if (1..=8).contains(&operation) {
        entry.native_status = -1073741790;
    }
    if [9, 12, 13, 14, 15, 16].contains(&operation) {
        entry.output_flags = 1;
    }
    entry.name[..3].copy_from_slice(&[b'A' as u16, 0, b'B' as u16]);
    entry
}
fn cover(packet: &mut Packet, operations: &[u32]) {
    packet.slot_count = operations.len() as u32;
    let node = &packet.nodes[(packet.node_count as usize) - 1];
    for (index, operation) in operations.iter().enumerate() {
        packet.slots[index] = Slot {
            slot: node.owner_base + 0x2000 + (index as u64) * 8,
            operation: *operation,
            ..packet.slots[0]
        };
    }
}
#[test]
fn fixed_win64_abi_matches_native_layout_for_both_supported_machines() {
    assert_eq!(size_of::<Entry>(), 608);
    assert_eq!(offset_of!(Entry, name), 96);
    assert_eq!(size_of::<Slot>(), 48);
    assert_eq!(size_of::<Node>(), 192);
    assert_eq!(offset_of!(Node, entry_bytes), 48);
    assert_eq!(offset_of!(Node, module_name), 64);
    assert_eq!(size_of::<Packet>(), 11648);
    assert_eq!(offset_of!(Packet, original_return), 20);
    assert_eq!(offset_of!(Packet, started_qpc), 128);
    assert_eq!(offset_of!(Packet, nodes), 160);
    assert_eq!(offset_of!(Packet, slots), 544);
    assert_eq!(offset_of!(Packet, first_failure), 1312);
    assert_eq!(offset_of!(Packet, entries), 1920);
    for machine in [0x8664, 0xaa64] {
        let mut packet = ready();
        packet.nodes[0].machine = machine;
        let value = diagnostic(&packet);
        assert_eq!(value["observed_entries_complete"], true);
        assert_eq!(value["all_native_routes_observed"], false);
        assert_eq!(value["coverage_inconclusive"], true);
        assert_eq!(value["absence_is_not_evidence"], true);
        assert_eq!(value["acceptance_authority"], false);
        assert_eq!(value["target_identity_proved"], false);
    }
}
#[test]
fn native_domains_raw_arguments_last_errors_and_original_startup_return_remain_distinct() {
    let mut packet = ready();
    packet.record_count = 16;
    packet.total_calls = 16;
    packet.total_failures = 16;
    cover(&mut packet, &(1..=16).collect::<Vec<_>>());
    for (index, entry) in packet.entries.iter_mut().enumerate() {
        *entry = event(index as u32 + 1, index as u64 + 1);
        entry.raw_root = 0x55;
        entry.requested_size = 1 << 30;
        entry.secondary_size = 4096;
    }
    packet.first_failure_present = 1;
    packet.first_failure = packet.entries[0];
    let value = diagnostic(&packet);
    assert_eq!(value["original_startup_return"], 10107);
    assert!(value["negotiated_version"].is_null());
    assert_eq!(value["incoming_last_error"], 77);
    assert_eq!(value["outgoing_last_error"], 15100);
    assert_eq!(value["post_failure_spi_in_scope"], false);
    for entry in value["recent_entries"].as_array().unwrap() {
        let operation = entry["operation_code"].as_u64().unwrap();
        assert_eq!(
            entry["return_domain"],
            if operation <= 8 {
                "ntstatus"
            } else if [10, 11].contains(&operation) {
                "lstatus"
            } else {
                "pointer"
            }
        );
        assert_eq!(entry["observed_failure"], true);
        assert_eq!(entry["failure_is_decisive_cause"], false);
        assert_eq!(entry["incoming_last_error"], 99);
        assert_eq!(entry["outgoing_last_error"], 8);
        assert_eq!(entry["requested_size"], 1 << 30);
        assert_eq!(entry["secondary_size"], 4096);
        assert_eq!(entry["name_utf16"], serde_json::json!([65, 0, 66]));
        assert_eq!(entry["raw_handles_are_identity"], false);
    }
    packet.record_count = 1;
    packet.total_calls = 1;
    packet.total_failures = 0;
    packet.first_failure_present = 0;
    packet.entries[0] = event(1, 1);
    packet.entries[0].native_status = 0;
    assert_eq!(
        diagnostic(&packet)["recent_entries"][0]["observed_failure"],
        false
    ); // Stale LastError8 is not NTSTATUS.
    packet.entries[0] = event(16, 1);
    packet.entries[0].raw_output = 0x600000;
    packet.entries[0].native_status = 0;
    packet.entries[0].output_flags = 3;
    assert_eq!(
        diagnostic(&packet)["recent_entries"][0]["observed_failure"],
        false
    );
}
#[test]
fn nesting_keeps_entry_order_and_storage_provenance_without_replacing_first_returned_failure() {
    let mut packet = ready();
    packet.record_count = 3;
    packet.total_calls = 20;
    packet.total_failures = 3;
    packet.entries[0] = event(3, 20);
    packet.entries[1] = event(1, 18);
    packet.entries[2] = event(2, 19);
    cover(&mut packet, &[1, 2, 3]);
    packet.first_failure_present = 1;
    packet.first_failure = event(3, 20);
    let value = diagnostic(&packet);
    assert_eq!(value["invalid_packet"], false);
    assert_eq!(value["recent_entries"][0]["sequence"], 18);
    assert_eq!(value["recent_entries"][0]["storage_index"], 1);
    assert_eq!(value["first_observed_failure"]["sequence"], 20);
    packet.entries[2].sequence = 18;
    assert_eq!(diagnostic(&packet)["invalid_packet"], true);
    packet.entries[2].sequence = 19;
    packet.entries[2].returned = 0;
    let value = diagnostic(&packet);
    assert_eq!(value["observed_entries_complete"], false);
    assert!(value["recent_entries"][1]["observed_failure"].is_null());
}
#[test]
fn bounded_malformed_utf16_entry_flags_and_native_scope_unavailability_are_truthful() {
    let mut packet = ready();
    packet.record_count = 1;
    packet.total_calls = 1;
    packet.entries[0] = event(1, 1);
    packet.entries[0].name[..3].copy_from_slice(&[0xd800, b'A' as u16, 0xdc00]);
    let value = diagnostic(&packet);
    assert_eq!(
        value["recent_entries"][0]["name_utf16"],
        serde_json::json!([0xd800, 65, 0xdc00])
    );
    assert_eq!(value["recent_entries"][0]["name_is_unicode_text"], false);
    packet.entries[0] = event(8, 1);
    cover(&mut packet, &[8]);
    packet.entries[0].scalar_flags = 0;
    packet.entries[0].requested_size = 1234;
    packet.entries[0].secondary_size = 5678;
    let unreadable = diagnostic(&packet);
    assert!(unreadable["recent_entries"][0]["requested_size"].is_null());
    assert!(unreadable["recent_entries"][0]["secondary_size"].is_null());
    assert!(unreadable["recent_entries"][0]["flags"].is_null());
    assert_eq!(unreadable["recent_entries"][0]["raw_requested_size"], 1234);
    assert_eq!(unreadable["recent_entries"][0]["raw_secondary_size"], 5678);
    packet.entries[0].copied_name_units = u32::MAX;
    packet.entries[0].reported_name_bytes = u32::MAX;
    packet.entries[0].name_flags = 7;
    let value = diagnostic(&packet);
    assert_eq!(value["invalid_packet"], true);
    assert_eq!(value["observed_entries_complete"], false);
    assert_eq!(
        value["recent_entries"][0]["name_utf16"]
            .as_array()
            .unwrap()
            .len(),
        256
    );
    for field in [
        "node",
        "slot",
        "signature",
        "thread",
        "clock",
        "bounds",
        "unsupported",
    ] {
        let mut packet = ready();
        packet.record_count = 1;
        packet.total_calls = 1;
        packet.entries[0] = event(1, 1);
        match field {
            "node" => packet.nodes[0].machine = 0,
            "slot" => packet.slots[0].slot += 1,
            "signature" => packet.entries[0].operation = 17,
            "thread" => packet.entries[0].thread_id += 1,
            "clock" => packet.finished_qpc = packet.cutoff_qpc,
            "bounds" => packet.descriptor_count = 513,
            "unsupported" => {
                packet.slots[0].hook = 0;
                packet.slots[0].published = 0;
            }
            _ => unreachable!(),
        }
        assert_eq!(
            diagnostic(&packet)["observed_entries_complete"],
            false,
            "{field}"
        );
    }
    let mut packet = ready();
    packet.setup_stage = 8;
    packet.setup_error = 50;
    packet.called = 1;
    packet.armed = 0;
    let value = diagnostic(&packet);
    assert_eq!(value["original_startup_return"], 10107);
    assert_eq!(value["setup_error"], 50);
    assert_eq!(value["observed_entries_complete"], false);
    assert_eq!(value["post_failure_spi_in_scope"], false);
}
#[test]
fn declared_hops_slots_and_pointer_returns_must_match_the_captured_route() {
    for operation in [1, 2, 4, 5, 6, 7, 8, 10] {
        let mut packet = ready();
        cover(&mut packet, &[operation]);
        packet.record_count = 1;
        packet.total_calls = 1;
        packet.entries[0] = event(operation, 1);
        packet.entries[0].native_status = 0;
        assert_eq!(
            diagnostic(&packet)["observed_entries_complete"],
            false,
            "successful unreadable output {operation}"
        );
        packet.entries[0].raw_output = 0x600000;
        packet.entries[0].output_flags = 3;
        assert_eq!(
            diagnostic(&packet)["observed_entries_complete"],
            true,
            "successful known output {operation}"
        );
        packet.entries[0] = event(operation, 1);
        packet.total_failures = 1;
        packet.first_failure_present = 1;
        packet.first_failure = packet.entries[0];
        assert_eq!(
            diagnostic(&packet)["observed_entries_complete"],
            true,
            "failed output must stay unobserved {operation}"
        );
    }
    let mut hop = ready();
    hop.scope_flags = 5;
    hop.hop_count = 1;
    hop.node_count = 2;
    hop.nodes[0].machine = 0x8664;
    hop.nodes[0].entry_len = 6;
    hop.nodes[0].entry_bytes[..6].copy_from_slice(&[0xff, 0x25, 0xfa, 0x0f, 0, 0]);
    hop.nodes[0].slot = 0x102000;
    hop.nodes[0].target = 0x201000;
    hop.nodes[1] = Node {
        owner_base: 0x200000,
        entry: 0x201000,
        owner_size: 0x10000,
        machine: 0x8664,
        entry_len: 6,
        ..Node::default()
    };
    cover(&mut hop, &[1]);
    assert_eq!(diagnostic(&hop)["observed_entries_complete"], true);
    for case in [
        "edge",
        "decoded-slot",
        "final-slot",
        "owner-cycle",
        "missing-descriptor",
    ] {
        let saved = hop.nodes;
        let slot = hop.slots[0];
        match case {
            "edge" => hop.nodes[0].target += 1,
            "decoded-slot" => hop.nodes[0].entry_bytes[2] ^= 1,
            "final-slot" => hop.slots[0].slot = hop.nodes[0].slot,
            "owner-cycle" => hop.nodes[1].owner_base = hop.nodes[0].owner_base,
            "missing-descriptor" => hop.slots[0].descriptor_module = 0,
            _ => unreachable!(),
        }
        assert_eq!(diagnostic(&hop)["invalid_packet"], true, "{case}");
        hop.nodes = saved;
        hop.slots[0] = slot;
    }
    let mut packet = ready();
    cover(&mut packet, &[9]);
    packet.record_count = 1;
    packet.total_calls = 1;
    packet.entries[0] = event(9, 1);
    packet.entries[0].native_status = 0;
    packet.entries[0].raw_output = 0x600000;
    packet.entries[0].output_flags = 3;
    assert_eq!(diagnostic(&packet)["invalid_packet"], false);
    assert_eq!(
        diagnostic(&packet)["recent_entries"][0]["observed_failure"],
        false
    );
    for case in ["unknown-output", "null-marker", "foreign-operation"] {
        let saved = packet.entries[0];
        match case {
            "unknown-output" => packet.entries[0].output_flags = 0,
            "null-marker" => packet.entries[0].native_status = 1,
            "foreign-operation" => packet.entries[0].operation = 15,
            _ => unreachable!(),
        }
        assert_eq!(diagnostic(&packet)["invalid_packet"], true, "{case}");
        packet.entries[0] = saved;
    }
}
#[test]
fn overflow_and_maximum_raw_payload_preserve_original_and_first_failure_within_serialization_cap() {
    let mut packet = ready();
    packet.node_count = 2;
    packet.hop_count = 1;
    packet.scope_flags = 5;
    packet.nodes[1] = packet.nodes[0];
    packet.slot_count = 16;
    packet.record_count = 16;
    packet.total_calls = u32::MAX;
    packet.total_failures = 17;
    packet.dropped = u32::MAX;
    packet.overflow = 1;
    packet.incomplete = 1;
    for slot in &mut packet.slots {
        *slot = Slot {
            slot: 0x102000,
            original: u64::MAX,
            hook: u64::MAX,
            descriptor_module: u64::MAX,
            operation: 1,
            published: 1,
            ..Slot::default()
        };
    }
    for (index, entry) in packet.entries.iter_mut().enumerate() {
        *entry = event(8, index as u64 + 1);
        entry.name = [u16::MAX; 256];
        entry.copied_name_units = 256;
        entry.reported_name_bytes = 512;
        entry.raw_root = u64::MAX;
        entry.raw_output = u64::MAX;
        entry.requested_size = u64::MAX;
        entry.secondary_size = u64::MAX;
    }
    packet.first_failure_present = 1;
    packet.first_failure = packet.entries[0];
    let value = diagnostic(&packet);
    assert!(value["unavailable"].is_null());
    assert!(serde_json::to_vec(&value).unwrap().len() <= record::RECORD_BYTES);
    assert_eq!(value["original_startup_return"], 10107);
    assert_eq!(
        value["first_observed_failure"]["native_status_or_adapter_marker"],
        -1073741790
    );
    assert_eq!(value["overflow"], 1);
    assert_eq!(value["observed_entries_complete"], false);
    packet.record_count = u32::MAX;
    packet.node_count = u32::MAX;
    packet.slot_count = u32::MAX;
    let value = diagnostic(&packet);
    assert_eq!(value["recent_entries"].as_array().unwrap().len(), 16);
    assert_eq!(value["nodes"].as_array().unwrap().len(), 2);
    assert_eq!(value["slots"].as_array().unwrap().len(), 16);
    assert_eq!(value["invalid_packet"], true);
    assert!(serde_json::to_vec(&value).unwrap().len() <= record::RECORD_BYTES);
}
