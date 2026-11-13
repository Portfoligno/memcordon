#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
pub mod gate_entry_route;
#[path = "../src/bin/consumer_readiness_windows/native_file_trace_record.rs"]
mod record;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_record.rs"]
pub mod winsock_trace_record;

use record::{Packet, Row, bounded, diagnostic, validate};

fn captured() -> Packet {
    let mut packet = Packet {
        version: 1,
        packet_bytes: record::PACKET_BYTES as u32,
        owner_count: 1,
        route_count: 1,
        record_count: 1,
        total_calls: 1,
        original_thread: 7,
        cutoff_qpc: 100,
        frequency: 1000,
        ..Packet::default()
    };
    packet.owners[0].role = 1;
    packet.owners[0].shared_owner = u32::MAX;
    packet.routes[0].slot.slot = 0x1000;
    packet.routes[0].slot.operation = 1;
    packet.routes[0].slot.published = 1;
    packet.routes[0].postvalidated = 1;
    packet.routes[0].thunk_kind = 1;
    packet.rows[0] = Row {
        sequence: 1,
        ldr_dependency_sequence: 3,
        parent_listener_sequence: 4,
        started_qpc: 20,
        finished_qpc: 21,
        operation: 1,
        thread_id: 7,
        desired_access: 0x80,
        entered: 1,
        returned: 1,
        output_flags: 16,
        flags: 31,
        ..Row::default()
    };
    packet
}

#[test]
fn native_request_preserves_raw_name_status_masks_and_pending_distinctions() {
    let mut packet = captured();
    let row = &mut packet.rows[0];
    row.raw_root = 0x1234;
    row.name[..3].copy_from_slice(&[b'a' as u16, 0, 0xd800]);
    row.copied_name_units = 3;
    row.reported_name_bytes = 6;
    row.name_flags = 1 | 8;
    row.native_status = 0xc0000022u32 as i32;
    packet.total_failures = 1;
    packet.first_failure_present = 1;
    packet.first_failure = packet.rows[0];
    let value = diagnostic(&packet);
    assert!(validate(&packet).is_ok());
    assert_eq!(value["rows"][0]["desired_access"], 128);
    assert_eq!(value["rows"][0]["native_status"], -1073741790);
    assert_eq!(
        value["rows"][0]["requested_name_utf16"],
        serde_json::json!([97, 0, 55296])
    );
    assert_eq!(value["rows"][0]["root_directory_identity_proved"], false);
    assert_eq!(value["denied_physical_object_proved"], false);
    assert_eq!(value["first_failure"]["sequence"], 1);
    assert_eq!(value["rows"][0]["complete_request_observation"], true);
    packet.first_failure_present = 0;
    packet.rows[0].operation = 2;
    packet.routes[0].slot.operation = 2;
    packet.rows[0].native_status = 0x103;
    packet.rows[0].output_flags = 8 | 16;
    packet.rows[0].flags |= 64;
    let value = diagnostic(&packet);
    assert_eq!(value["rows"][0]["status_pending"], true);
    assert!(value["rows"][0]["output_handle_scalar"].is_null());
    assert!(value["rows"][0]["create_disposition"].is_null());
    assert!(value["rows"][0]["allocation_size_raw_bits"].is_null());
    assert_eq!(value["rows"][0]["io_status_block_observed"], false);
    assert_eq!(value["rows"][0]["complete_request_observation"], false);
}

#[test]
fn absent_partial_late_and_overflow_records_never_claim_absence_or_authority() {
    let empty = Packet {
        version: 1,
        packet_bytes: record::PACKET_BYTES as u32,
        ..Packet::default()
    };
    let value = diagnostic(&empty);
    assert_eq!(value["packet_valid"], true);
    assert_eq!(value["global_route_coverage"], false);
    assert!(
        value["interpretation"]
            .as_str()
            .unwrap()
            .contains("INCONCLUSIVE")
    );
    for alteration in 0..6 {
        let mut packet = captured();
        match alteration {
            0 => packet.rows[0].finished_qpc = packet.cutoff_qpc,
            1 => packet.rows[0].thread_id += 1,
            2 => packet.rows[0].flags &= !8,
            3 => packet.rows[0].name_flags |= 4,
            4 => packet.rows[0].input_flags |= 128,
            _ => packet.routes[0].postvalidated = 0,
        }
        packet.dropped = 4;
        packet.overflow = 1;
        let value = diagnostic(&packet);
        assert_eq!(value["rows"][0]["complete_request_observation"], false);
        assert_eq!(value["dropped"], 4);
        assert_eq!(value["overflow"], 1);
        assert_eq!(value["acceptance_authority"], false);
    }
}

#[test]
fn invalid_abi_counts_routes_and_name_extents_are_explicitly_rejected() {
    for alteration in 0..9 {
        let mut packet = captured();
        match alteration {
            0 => packet.version += 1,
            1 => packet.packet_bytes -= 1,
            2 => packet.record_count = 17,
            3 => packet.owner_count = 3,
            4 => packet.rows[0].copied_name_units = 129,
            5 => packet.rows[0].route_index = 4,
            6 => packet.rows[0].reserved[0] = 1,
            7 => {
                packet.route_count = 2;
                packet.routes[1] = packet.routes[0];
            }
            _ => packet.routes[0].owner_index = 1,
        }
        assert!(validate(&packet).is_err());
        let value = diagnostic(&packet);
        assert_eq!(value["packet_valid"], false);
        assert!(value["validation_error"].is_string());
        assert!(value["rows"].as_array().unwrap().is_empty());
        assert!(bounded(value).unwrap().len() <= record::RECORD_BYTES);
    }
}

#[test]
fn maximum_rows_and_pinned_failure_fit_without_silent_field_omission() {
    let mut packet = captured();
    packet.owner_count = 2;
    packet.owners[1] = packet.owners[0];
    packet.owners[1].role = 2;
    packet.owners[1].flags = 2 | 4;
    for owner in &mut packet.owners {
        owner.identity.entry_len = 16;
        owner.identity.entry_bytes.fill(u8::MAX);
        owner.identity.module_name.fill(u16::MAX);
    }
    packet.route_count = 4;
    for index in 0..4 {
        packet.routes[index] = packet.routes[0];
        packet.routes[index].slot.slot = index as u64 + 1;
        packet.routes[index].owner_index = index as u32 / 2;
        packet.routes[index].target = packet.owners[0].identity;
    }
    packet.record_count = 16;
    packet.total_calls = 20;
    packet.dropped = 4;
    packet.overflow = 1;
    packet.total_failures = 1;
    for index in 0..16 {
        packet.rows[index] = packet.rows[0];
        packet.rows[index].sequence = index as u64 + 1;
        packet.rows[index].name.fill(u16::MAX);
        packet.rows[index].copied_name_units = 128;
        packet.rows[index].reported_name_bytes = 256;
        packet.rows[index].name_flags = 1;
    }
    packet.first_failure_present = 1;
    packet.first_failure = packet.rows[15];
    packet.first_failure.sequence = 20;
    packet.first_failure.native_status = -1;
    let bytes = bounded(serde_json::json!({
        "trace":diagnostic(&packet),
        "original_binding":{"pid":u32::MAX,"birth":u64::MAX,"descriptor_sha256":([255u8;32]).as_slice(),"challenge_sha256":([255u8;32]).as_slice()},
        "provider_loader_policies":{"bounded_snapshot_budget":"x".repeat(4096)},
        "provider_loader_context":{"bounded_snapshot_budget":"x".repeat(8192)}
    })).unwrap();
    assert!(bytes.len() <= record::RECORD_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["trace"]["rows"].as_array().unwrap().len(), 16);
    assert_eq!(value["trace"]["first_failure"]["sequence"], 20);
    assert!(bounded(serde_json::json!({"oversize":"x".repeat(record::RECORD_BYTES)})).is_err());
}
