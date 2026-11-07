#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
pub mod gate_entry_route;
#[path = "../src/bin/consumer_readiness_windows/native_file_trace_record.rs"]
pub mod native_file_trace_record;
#[path = "../src/bin/consumer_readiness_windows/spawn_trace_record.rs"]
mod record;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_record.rs"]
pub mod winsock_trace_record;
use record::{Packet, Row, bounded, diagnostic, validate};

fn packet() -> Packet {
    let mut packet = Packet {
        version: 1,
        packet_bytes: record::PACKET_BYTES as u32,
        owner_count: 1,
        route_count: 5,
        scope_attempted: 1,
        scope_returned: 1,
        original_thread: 7,
        started_qpc: 10,
        finished_qpc: 100,
        cutoff_qpc: 1000,
        frequency: 1000,
        incomplete: 1,
        ..Packet::default()
    };
    packet.owners[0].role = 1;
    packet.owners[0].shared_owner = u32::MAX;
    for (index, route) in packet.routes.iter_mut().enumerate() {
        route.slot.slot = 0x1000 + index as u64 * 8;
        route.slot.operation = index as u32 + 1;
        route.slot.published = 1;
        route.postvalidated = 1;
        route.thunk_kind = 1;
    }
    packet
}
fn row(operation: u32, sequence: u64) -> Row {
    Row {
        sequence,
        operation,
        route_index: operation - 1,
        thread_id: 7,
        entered: 1,
        returned: 1,
        started_qpc: 20,
        finished_qpc: 21,
        flags: 31 | if operation <= 2 { 128 } else { 256 },
        win32_result: 1,
        output_flags: if operation <= 2 { 16 } else { 0 },
        ..Row::default()
    }
}

#[test]
fn exact_abi_and_each_api_keep_domains_arguments_and_unproved_child_outputs_distinct() {
    let mut packet = packet();
    packet.record_count = 5;
    packet.total_calls = 5;
    for operation in 1..=5 {
        packet.rows[operation as usize - 1] = row(operation, u64::from(operation));
    }
    let native = &mut packet.rows[0];
    native.native_status = 0xc0000022u32 as i32;
    native.desired_access = 0x80100000;
    native.raw_root = 0x1234;
    native.input_flags = 1 | 2 | 4;
    native.oa_length = 48;
    native.name[..3].copy_from_slice(&[97, 0, 0xd800]);
    native.copied_name_units = 3;
    native.reported_name_bytes = 6;
    native.name_flags = 1 | 8 | 32;
    native.outgoing_win32 = 999;
    packet.total_failures = 1;
    packet.first_failure_present = 1;
    packet.first_failure = *native;
    let pipe = &mut packet.rows[1];
    pipe.default_timeout = (-1000000i64) as u64;
    pipe.input_flags = 8 | 16;
    pipe.pipe_type = 1;
    pipe.inbound_quota = 4096;
    pipe.outbound_quota = 8192;
    let file = &mut packet.rows[2];
    file.raw_output = u64::MAX;
    file.win32_result = 0;
    packet.total_failures = 2;
    let duplicate = &mut packet.rows[3];
    duplicate.source_process = u64::MAX;
    duplicate.source_handle = 44;
    duplicate.target_process = u64::MAX;
    duplicate.duplicate_options = 2;
    duplicate.inherit_handle = 1;
    let process = &mut packet.rows[4];
    process.raw_output = 0x100;
    process.secondary_output = 0x104;
    process.output_pid = 99;
    process.output_tid = 100;
    process.output_flags = 1 | 2 | 64;
    process.creation_flags = 0x400;
    validate(&packet).unwrap();
    let value = diagnostic(&packet);
    let rows = &value["rows"];
    assert_eq!(rows[0]["native_status"], -1073741790);
    assert!(rows[0]["win32_result"].is_null());
    assert_eq!(rows[0]["desired_access"], 0x80100000u32);
    assert_eq!(rows[0]["root_directory_scalar"], 0x1234);
    assert_eq!(
        rows[0]["requested_name_utf16"],
        serde_json::json!([97, 0, 55296])
    );
    assert_eq!(rows[1]["default_timeout_signed"], -1000000);
    assert_eq!(rows[1]["inbound_quota"], 4096);
    assert_eq!(rows[2]["output_handle_scalar"], u64::MAX);
    assert_eq!(rows[2]["observed_api_failure"], true);
    assert!(rows[2]["native_status"].is_null());
    assert_eq!(rows[3]["source_process_handle_scalar"], u64::MAX);
    assert_eq!(rows[3]["duplicate_options"], 2);
    assert_eq!(rows[4]["reported_child_pid"], 99);
    assert_eq!(rows[4]["reported_child_tid"], 100);
    assert_eq!(
        rows[4]["child_identity_or_controller_admission_proved"],
        false
    );
    assert_eq!(value["denied_object_identity_proved"], false);
    assert_eq!(value["environment_or_command_line_captured"], false);
    assert_eq!(std::mem::size_of::<Packet>(), 9824);
    assert_eq!(std::mem::offset_of!(Row, name), 224);
}

#[test]
fn counted_names_and_truncated_win32_names_do_not_confuse_unknown_length_with_empty_name() {
    let mut packet = packet();
    packet.record_count = 1;
    packet.total_calls = 1;
    packet.rows[0] = row(3, 1);
    packet.rows[0].copied_name_units = 128;
    packet.rows[0].name.fill(97);
    packet.rows[0].name_flags = 4 | 16;
    packet.rows[0].flags &= !16;
    let value = diagnostic(&packet);
    let observed = &value["rows"][0];
    assert!(observed["reported_name_bytes"].is_null());
    assert_eq!(observed["full_name_length_known"], false);
    assert_eq!(observed["captured_name_units"], 128);
    assert!(observed["full_requested_name_sha256"].is_null());
    assert_eq!(
        observed["captured_name_prefix_sha256"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    packet.rows[0] = row(1, 1);
    packet.rows[0].name_flags = 1 | 32;
    let value = diagnostic(&packet);
    assert_eq!(value["rows"][0]["reported_name_bytes"], 0);
    assert_eq!(value["rows"][0]["full_name_length_known"], true);
}

#[test]
fn pending_late_fault_and_missing_routes_remain_inconclusive_without_synthetic_returns() {
    let mut packet = packet();
    packet.record_count = 1;
    packet.total_calls = 2;
    packet.rows[0] = row(2, 1);
    packet.rows[0].native_status = 0x103;
    packet.rows[0].flags |= 64;
    packet.rows[0].output_flags = 8 | 16;
    let value = diagnostic(&packet);
    assert_eq!(value["rows"][0]["status_pending"], true);
    assert_eq!(value["rows"][0]["complete_local_observation"], false);
    assert!(value["rows"][0]["output_handle_scalar"].is_null());
    assert_eq!(value["entered_without_retained_completion"], 1);
    for input_flags in [0, 128] {
        packet.rows[0] = row(1, 1);
        packet.rows[0].input_flags = input_flags;
        let value = diagnostic(&packet);
        for field in [
            "object_attributes_length",
            "object_attributes",
            "root_directory_scalar",
        ] {
            assert!(value["rows"][0][field].is_null());
        }
    }
    packet.rows[0].input_flags = 1 | 64;
    packet.rows[0].oa_length = 1;
    let value = diagnostic(&packet);
    assert_eq!(value["rows"][0]["object_attributes_length"], 1);
    assert!(value["rows"][0]["object_attributes"].is_null());
    assert!(value["rows"][0]["root_directory_scalar"].is_null());
    packet.rows[0].input_flags = 1 | 2;
    packet.rows[0].oa_length = 48;
    let value = diagnostic(&packet);
    assert_eq!(value["rows"][0]["object_attributes_length"], 48);
    assert_eq!(value["rows"][0]["object_attributes"], 0);
    assert_eq!(value["rows"][0]["root_directory_scalar"], 0);
    for case in 0..5 {
        packet.rows[0] = row(1, 1);
        match case {
            0 => packet.rows[0].finished_qpc = packet.cutoff_qpc,
            1 => packet.rows[0].input_flags |= 128,
            2 => packet.rows[0].flags &= !8,
            3 => packet.rows[0].thread_id += 1,
            _ => packet.routes[0].postvalidated = 0,
        }
        assert_eq!(
            diagnostic(&packet)["rows"][0]["complete_local_observation"],
            false
        );
    }
    packet.record_count = 0;
    packet.total_calls = 0;
    packet.route_count = 0;
    packet.scope_unavailable = 1;
    let value = diagnostic(&packet);
    assert_eq!(value["packet_valid"], true);
    assert_eq!(value["global_route_coverage"], false);
    assert!(
        value["interpretation"]
            .as_str()
            .unwrap()
            .contains("INCONCLUSIVE")
    );
}

#[test]
fn malformed_layout_counts_route_proofs_and_pinned_failures_are_rejected_explicitly() {
    for case in 0..10 {
        let mut packet = packet();
        packet.record_count = 1;
        packet.total_calls = 1;
        packet.rows[0] = row(1, 1);
        match case {
            0 => packet.version = 2,
            1 => packet.packet_bytes -= 1,
            2 => packet.record_count = 17,
            3 => packet.route_count = 6,
            4 => packet.owner_count = 2,
            5 => packet.rows[0].route_index = 5,
            6 => packet.rows[0].copied_name_units = 129,
            7 => packet.routes[1].slot.slot = packet.routes[0].slot.slot,
            8 => packet.routes[1].slot.operation = 1,
            _ => {
                packet.first_failure_present = 1;
                packet.total_failures = 1;
                packet.first_failure = packet.rows[0];
            }
        }
        assert!(validate(&packet).is_err(), "{case}");
        let value = diagnostic(&packet);
        assert_eq!(value["packet_valid"], false);
        assert!(value["rows"].as_array().unwrap().is_empty());
        assert!(value["validation_error"].is_string());
        assert!(bounded(value).unwrap().len() <= record::RECORD_BYTES);
    }
}

#[test]
fn maximum_rows_first_failure_and_binding_fit_the_fixed_carrier_without_hidden_omission() {
    let mut packet = packet();
    packet.record_count = 16;
    packet.total_calls = 20;
    packet.dropped = 4;
    packet.overflow = 1;
    packet.owners[0].identity.module_name.fill(u16::MAX);
    packet.owners[0].identity.entry_len = 16;
    packet.owners[0].identity.entry_bytes.fill(u8::MAX);
    for route in &mut packet.routes {
        route.target = packet.owners[0].identity;
    }
    for index in 0..16 {
        packet.rows[index] = row(index as u32 % 5 + 1, index as u64 + 5);
        packet.rows[index].name.fill(u16::MAX);
        packet.rows[index].copied_name_units = 128;
        packet.rows[index].reported_name_bytes = 256;
        packet.rows[index].name_flags = 1 | 32;
    }
    packet.total_failures = 1;
    packet.first_failure_present = 1;
    packet.first_failure = packet.rows[0];
    packet.first_failure.sequence = 1;
    packet.first_failure.native_status = -1;
    let bytes=bounded(serde_json::json!({"trace":diagnostic(&packet),"binding":{"descriptor_sha256":([255u8;32]).as_slice(),"challenge_sha256":([255u8;32]).as_slice(),"pid":u32::MAX,"birth":u64::MAX}})).unwrap();
    assert!(bytes.len() <= record::RECORD_BYTES);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["trace"]["rows"].as_array().unwrap().len(), 16);
    assert_eq!(value["trace"]["first_failure"]["sequence"], 1);
    assert!(bounded(serde_json::json!({"too_large":"x".repeat(record::RECORD_BYTES)})).is_err());
}
