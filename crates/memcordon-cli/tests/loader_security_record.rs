#[path = "../src/bin/consumer_readiness_windows/gate_entry_route.rs"]
mod gate_entry_route;
#[path = "../src/bin/consumer_readiness_windows/listener_trace_record.rs"]
mod listener_trace_record;
#[path = "../src/bin/consumer_readiness_windows/loader_security_record.rs"]
mod loader_security_record;
#[path = "../src/bin/consumer_readiness_windows/winsock_trace_record.rs"]
mod winsock_trace_record;
use listener_trace_record::{DependencyLink, Entry, LoaderLink, LoaderWindow, Packet};
use loader_security_record::{
    AncestorPhase, AncestorRole, AncestorRow, AncestryProgress, CallOutcome, CallState,
};
use loader_security_record::{RECORD_BYTES, bounded, select};
use serde_json::json;

fn succeeded() -> CallOutcome {
    CallOutcome::from_result(&Ok::<_, std::io::Error>(()))
}
fn failed(code: i32) -> CallOutcome {
    CallOutcome::from_result(&Err::<(), _>(std::io::Error::from_raw_os_error(code)))
}
fn retained(index: u32, prefix: u32) -> AncestorRow {
    AncestorRow {
        ancestor_index: index,
        selected_path_prefix_utf16_units: prefix,
        role: if index == 0 {
            AncestorRole::Root
        } else {
            AncestorRole::Ancestor
        },
        phase: AncestorPhase::Retained,
        before_open: succeeded(),
        open: succeeded(),
        after_open: succeeded(),
        query: succeeded(),
        validation: CallState::Succeeded,
        observed_directory: Some(true),
        observed_reparse: Some(false),
        after_validation: succeeded(),
        retained: true,
        ..Default::default()
    }
}

#[test]
fn ancestry_keeps_native_failure_distinct_from_cutoff_and_attribute_failure() {
    let path = "C:\\Windows\\System32\\mswsock.dll"
        .encode_utf16()
        .collect::<Vec<_>>();
    let mut row = retained(0, 3);
    row.phase = AncestorPhase::Query;
    row.query = failed(5);
    row.validation = CallState::NotInvoked;
    row.observed_directory = None;
    row.observed_reparse = None;
    row.after_validation = Default::default();
    row.retained = false;
    let mut progress = AncestryProgress::default();
    progress.record(row.clone());
    progress.outer_after = failed(1460);
    let result = progress.diagnostic(&path);
    assert_eq!(result["valid_prefixes_and_outcomes"], true);
    assert_eq!(result["terminal"]["query"]["native_error"], 5);
    assert_eq!(result["outer_after"]["native_error"], 1460);
    assert_eq!(result["terminal_phase"], "query");
    row.after_open = Default::default();
    let mut invalid = AncestryProgress::default();
    invalid.record(row);
    assert_eq!(
        invalid.diagnostic(&path)["valid_prefixes_and_outcomes"],
        false
    );
    let mut row = retained(0, 3);
    row.before_open = Default::default();
    let mut invalid = AncestryProgress::default();
    invalid.record(row);
    assert_eq!(
        invalid.diagnostic(&path)["valid_prefixes_and_outcomes"],
        false
    );
    let mut row = retained(0, 3);
    row.observed_directory = Some(false);
    let mut invalid = AncestryProgress::default();
    invalid.record(row);
    assert_eq!(
        invalid.diagnostic(&path)["valid_prefixes_and_outcomes"],
        false
    );
    assert!(serde_json::from_value::<CallState>(json!("unknown")).is_err());
    for (directory, reparse, reason) in [
        (
            false,
            false,
            loader_security_record::ValidationReason::NotDirectory,
        ),
        (
            true,
            true,
            loader_security_record::ValidationReason::ReparsePoint,
        ),
    ] {
        let mut row = retained(0, 3);
        row.phase = AncestorPhase::ValidateAttributes;
        row.validation = CallState::Failed;
        row.validation_reason = Some(reason);
        row.observed_directory = Some(directory);
        row.observed_reparse = Some(reparse);
        row.after_validation = Default::default();
        row.retained = false;
        let mut progress = AncestryProgress::default();
        progress.record(row);
        let value = progress.diagnostic(&path);
        assert_eq!(value["valid_prefixes_and_outcomes"], true);
        assert!(value["terminal"]["query"]["native_error"].is_null());
        assert_eq!(value["terminal"]["validation"], "failed");
        assert_eq!(
            value["terminal"]["after_validation"]["state"],
            "not-invoked"
        );
    }
    let mut progress = AncestryProgress::default();
    progress.record(retained(0, 3));
    progress.outer_after = failed(1460);
    progress.terminal_phase = Some(AncestorPhase::OuterAfter);
    progress.failed = true;
    let value = progress.diagnostic(&path);
    assert_eq!(value["terminal_phase"], "outer-after");
    assert_eq!(value["terminal"]["retained"], true);
    assert_eq!(value["terminal"]["query"]["state"], "succeeded");
}

#[test]
fn ancestry_terminal_survives_row_and_both_record_bounds() {
    let text = format!("C:\\{}leaf.dll", "a\\".repeat(14));
    let path = text.encode_utf16().collect::<Vec<_>>();
    let mut progress = AncestryProgress::default();
    for index in 0..10 {
        progress.record(retained(index, if index == 0 { 3 } else { 2 + 2 * index }));
    }
    let mut terminal = AncestorRow::new(10, 22, AncestorRole::Ancestor);
    terminal.phase = AncestorPhase::Open;
    terminal.before_open = succeeded();
    terminal.open = failed(5);
    progress.record(terminal);
    progress.outer_after = failed(1460);
    let ancestry = progress.diagnostic(&path);
    assert!(serde_json::to_vec(&ancestry).unwrap().len() <= loader_security_record::ANCESTRY_BYTES);
    assert_eq!(ancestry["valid_prefixes_and_outcomes"], true);
    assert_eq!(ancestry["completed_retained"], 10);
    assert_eq!(ancestry["omitted_rows"], 3);
    assert_eq!(ancestry["terminal"]["ancestor_index"], 10);
    let selection = json!({"path_utf16":path,"path_sha256":vec![7u8;32],"dependency_sequence":17,"loader_dependency_sequence":2,"parent_listener_sequence":3});
    let security = bounded(
        json!({"stage":"hold-selected-ancestry","selection":selection,"ancestry":ancestry,"padding":"x".repeat(100000)}),
    );
    assert!(serde_json::to_vec(&security).unwrap().len() <= RECORD_BYTES);
    let envelope = listener_trace_record::bounded(
        json!({"trace":{},"padding":"x".repeat(100000),"post_original_loader_security":security}),
    );
    assert!(serde_json::to_vec(&envelope).unwrap().len() <= listener_trace_record::RECORD_BYTES);
    assert_eq!(
        envelope["post_original_loader_security"]["ancestry"]["terminal"]["open"]["native_error"],
        5
    );
    assert_eq!(
        envelope["post_original_loader_security"]["selection"]["path_sha256"],
        json!(vec![7u8; 32])
    );
    assert_eq!(
        envelope["post_original_loader_security"]["selection"]["path_utf16_units"],
        path.len()
    );
    let oversize = listener_trace_record::bounded(
        json!({"trace":{},"post_original_loader_security":{"selection":selection,"ancestry":ancestry,"padding":"x".repeat(100000)}}),
    );
    assert_eq!(
        oversize["post_original_loader_security"]["ancestry"]["terminal"]["ancestor_index"],
        10
    );
    assert_eq!(
        oversize["post_original_loader_security"]["ancestry"]["outer_after"]["native_error"],
        1460
    );
    assert_eq!(
        oversize["post_original_loader_security"]["selection"]["path_sha256"],
        json!(vec![7u8; 32])
    );
    assert_eq!(
        oversize["post_original_loader_security"]["selection"]["path_utf16"],
        json!(path)
    );
    for value in [&envelope, &oversize] {
        let security = &value["post_original_loader_security"];
        assert!(security["original_desired_access"].is_null());
        assert_eq!(security["original_desired_access_unavailable"], true);
        assert_eq!(security["original_file_identity_proved"], false);
        assert_eq!(security["continuous_token_equality_proved"], false);
        assert_eq!(security["checks_are_hypotheses"], true);
    }
}

#[test]
fn ancestry_cutoff_partial_states_do_not_invent_calls_or_retention() {
    let path = "C:\\Windows\\mswsock.dll"
        .encode_utf16()
        .collect::<Vec<_>>();
    for phase in [
        AncestorPhase::BeforeOpen,
        AncestorPhase::AfterOpenBeforeQuery,
        AncestorPhase::AfterValidationBeforeRetain,
    ] {
        let mut row = AncestorRow::new(0, 3, AncestorRole::Root);
        row.phase = phase;
        match phase {
            AncestorPhase::BeforeOpen => row.before_open = failed(1460),
            AncestorPhase::AfterOpenBeforeQuery => {
                row.before_open = succeeded();
                row.open = succeeded();
                row.after_open = failed(1460);
            }
            _ => {
                row = retained(0, 3);
                row.phase = phase;
                row.after_validation = failed(1460);
                row.retained = false;
            }
        }
        let mut progress = AncestryProgress::default();
        progress.record(row);
        let value = progress.diagnostic(&path);
        assert_eq!(value["valid_prefixes_and_outcomes"], true);
        assert_eq!(value["completed_retained"], 0);
        assert_eq!(value["terminal"]["retained"], false);
    }
    let mut progress = AncestryProgress {
        outer_before: failed(1460),
        failed: true,
        terminal_phase: Some(AncestorPhase::OuterBefore),
        ..Default::default()
    };
    assert!(progress.diagnostic(&path)["terminal"].is_null());
    let mut row = retained(0, 2);
    row.role = AncestorRole::Root;
    progress = AncestryProgress::default();
    progress.record(row);
    assert_eq!(
        progress.diagnostic(&path)["valid_prefixes_and_outcomes"],
        false
    );
}

fn named(entry: &mut winsock_trace_record::Entry, path: &str) {
    entry.name = [0; 256];
    let path = path.encode_utf16().collect::<Vec<_>>();
    entry.name[..path.len()].copy_from_slice(&path);
    entry.copied_name_units = path.len() as u32;
    entry.reported_name_bytes = path.len() as u32 * 2;
    entry.name_flags = 1;
}
fn fixture(loader_sequence: u64, machine: u32) -> Packet {
    let completion = if loader_sequence == 1 { 6 } else { 8 };
    let timeline = if loader_sequence == 1 { 2 } else { 4 };
    let mut packet = Packet {
        version: 4,
        setup_stage: 1,
        called: 1,
        callback_outcome: 2,
        callback_raw_error_present: 1,
        callback_raw_error: 10106,
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
        record_count: 1,
        total_calls: 1,
        total_failures: 1,
        first_failure_present: 1,
        entered_mask: 2,
        returned_mask: 2,
        failure_mask: 2,
        next_sequence: completion,
        dependency_scope_armed: 1,
        ..Default::default()
    };
    packet.owner = winsock_trace_record::Node {
        owner_base: 0x1000,
        entry: 0x1100,
        owner_size: 0x1000,
        machine,
        ..Default::default()
    };
    for (index, slot) in packet.slots[..7].iter_mut().enumerate() {
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
    packet.entries[0] = Entry {
        sequence: 1,
        completion_sequence: completion,
        result: u64::MAX,
        operation: 2,
        thread_id: 7,
        entered: 1,
        returned: 1,
        failed: 1,
        error_domain: 2,
        outgoing_win32: 10106,
        outgoing_wsa: 10106,
        ..Default::default()
    };
    packet.first_failure = packet.entries[0];
    packet.returned_module.version = 1;
    packet.returned_module.dependencies.version = 1;
    packet.returned_module.dependencies.original_thread = 7;
    packet.returned_module.dependencies.cutoff_qpc = 100;
    packet.returned_module.dependencies.frequency = 10;
    let startup = &mut packet.dependencies;
    *startup = winsock_trace_record::Packet {
        version: 1,
        setup_stage: 1,
        armed: 1,
        owner_pinned: 1,
        callbacks_complete: 1,
        protections_restored: 1,
        original_thread: 7,
        cutoff_qpc: 100,
        frequency: 10,
        node_count: 1,
        slot_count: loader_sequence as u32,
        total_calls: loader_sequence as u32,
        record_count: loader_sequence as u32,
        total_failures: loader_sequence as u32,
        first_failure_present: 1,
        ..Default::default()
    };
    startup.nodes[0] = winsock_trace_record::Node {
        owner_base: 0x9000,
        entry: 0x9100,
        owner_size: 0x4000,
        machine,
        ..Default::default()
    };
    startup.slots[0] = winsock_trace_record::Slot {
        slot: 0x9800,
        operation: 12,
        original: 0xa100,
        hook: 0xb100,
        descriptor_module: 0xc000,
        published: 1,
        ..Default::default()
    };
    let index = loader_sequence as usize - 1;
    startup.entries[index] = winsock_trace_record::Entry {
        sequence: loader_sequence,
        operation: 12,
        thread_id: 7,
        entered: 1,
        returned: 1,
        native_status: 1,
        output_flags: 1,
        scalar_flags: 4,
        outgoing_error: 5,
        ..Default::default()
    };
    named(
        &mut startup.entries[index],
        "C:\\Windows\\system32\\mswsock.dll",
    );
    if loader_sequence == 2 {
        startup.slots[1] = winsock_trace_record::Slot {
            slot: 0x9808,
            operation: 10,
            original: 0xa200,
            hook: 0xb200,
            descriptor_module: 0xc000,
            published: 1,
            ..Default::default()
        };
        startup.entries[0] = winsock_trace_record::Entry {
            sequence: 1,
            operation: 10,
            thread_id: 7,
            entered: 1,
            returned: 1,
            native_status: 5,
            ..Default::default()
        };
        packet.dependency_links[0] = DependencyLink {
            dependency_sequence: 1,
            timeline_sequence: 2,
            parent_listener_sequence: 1,
        };
    }
    startup.first_failure = startup.entries[0];
    packet.dependency_link_count = loader_sequence as u32;
    packet.dependency_links[index] = DependencyLink {
        dependency_sequence: loader_sequence,
        timeline_sequence: timeline,
        parent_listener_sequence: 1,
    };
    packet.first_dependency_failure_link = packet.dependency_links[0];
    let scope = &mut packet.loader_owner;
    scope.version = 2;
    scope.selected = 1;
    scope.armed = 1;
    scope.setup_stage = 1;
    scope.scope_flags = 1;
    scope.attempt_count = 1;
    scope.loader_target = 0xa100;
    scope.owner_base = 0xa000;
    scope.link_count = 1;
    scope.links[0] = LoaderLink {
        dependency_sequence: 1,
        timeline_sequence: timeline + 1,
        parent_listener_sequence: 1,
        loader_dependency_sequence: loader_sequence,
        loader_timeline_sequence: timeline,
    };
    scope.first_failure_link = scope.links[0];
    let deps = &mut scope.dependencies;
    *deps = winsock_trace_record::Packet {
        version: 1,
        setup_stage: 1,
        armed: 1,
        owner_pinned: 1,
        callbacks_complete: 1,
        protections_restored: 1,
        original_thread: 7,
        frequency: 10,
        cutoff_qpc: 100,
        node_count: 1,
        slot_count: 1,
        total_calls: 1,
        total_failures: 1,
        record_count: 1,
        first_failure_present: 1,
        ..Default::default()
    };
    deps.nodes[0] = winsock_trace_record::Node {
        owner_base: 0xa000,
        entry: 0xa100,
        owner_size: 0x2000,
        machine,
        ..Default::default()
    };
    deps.slots[0] = winsock_trace_record::Slot {
        slot: 0xa800,
        operation: 4,
        original: 0xd000,
        hook: 0xe000,
        descriptor_module: 0xf000,
        published: 1,
        ..Default::default()
    };
    deps.entries[0] = winsock_trace_record::Entry {
        sequence: 1,
        operation: 4,
        thread_id: 7,
        entered: 1,
        returned: 1,
        native_status: 0xc0000022u32 as i32,
        ..Default::default()
    };
    named(&mut deps.entries[0], "C:\\Windows\\system32\\mswsock.dll");
    deps.first_failure = deps.entries[0];
    scope.window_count = 1;
    scope.first_failure_window_present = 1;
    scope.windows[0] = LoaderWindow {
        dependency_sequence: 1,
        loader_dependency_sequence: loader_sequence,
        parent_listener_sequence: 1,
        started_qpc: 4,
        finished_qpc: 5,
    };
    scope.first_failure_window = scope.windows[0];
    packet
}

#[test]
fn selects_actual_linked_name_with_distinct_architecture_sequences() {
    for (sequence, machine) in [(1, 0x8664), (2, 0xaa64)] {
        let packet = fixture(sequence, machine);
        let selected = select(&packet).unwrap();
        assert_eq!(
            selected.path,
            "C:\\Windows\\system32\\mswsock.dll"
                .encode_utf16()
                .collect::<Vec<_>>()
        );
        assert_eq!(selected.loader_dependency_sequence, sequence);
        assert_eq!(selected.dependency_sequence, 1);
        assert_eq!(selected.parent_listener_sequence, 1);
        assert_eq!(selected.thread_id, 7);
    }
}

#[test]
fn loader_selection_does_not_substitute_for_complete_original_refusal_evidence() {
    for (sequence, machine) in [(1, 0x8664), (2, 0xaa64)] {
        let packet = fixture(sequence, machine);
        let selected = select(&packet).unwrap();
        assert_eq!(
            listener_trace_record::diagnostic(&packet)["observed_entries_complete"],
            true
        );
        let refusal = listener_trace_record::original_refusal(&packet)
            .expect("complete original WSASocketW refusal");
        assert_eq!(
            (
                refusal.operation,
                refusal.domain,
                refusal.code,
                refusal.calls
            ),
            (2, 2, 10106, 1)
        );
        assert_eq!(selected.loader_dependency_sequence, sequence);

        let mut incomplete = fixture(sequence, machine);
        incomplete.callbacks_complete = 0;
        assert_eq!(
            listener_trace_record::diagnostic(&incomplete)["observed_entries_complete"],
            false
        );
        assert_eq!(select(&incomplete).unwrap(), selected);
        assert!(listener_trace_record::original_refusal(&incomplete).is_none());
    }
}

#[test]
fn refuses_incomplete_conflicting_or_cross_namespace_paths() {
    for mutation in 0..12 {
        let mut packet = fixture(2, 0xaa64);
        match mutation {
            0 => packet.dependencies.entries[1].name_flags |= 4,
            1 => packet.loader_owner.dependencies.entries[0].name_flags |= 2,
            2 => packet.dependencies.entries[1].reported_name_bytes += 2,
            3 => packet.loader_owner.links[0].loader_dependency_sequence = 1,
            4 => {
                packet
                    .loader_owner
                    .first_failure_window
                    .parent_listener_sequence = 2
            }
            5 => packet.dependencies.entries[1].thread_id = 8,
            6 => packet.loader_owner.dependencies.first_failure.name[3] = 90,
            7 => packet.loader_owner.dependencies.entries[0].name[3] = 90,
            8 => packet.loader_owner.windows[0].finished_qpc = 101,
            9 => packet.loader_owner.dependencies.entries[0].native_status = 0,
            10 => packet.dependencies.entries[1].output_flags = 3,
            _ => packet.loader_owner.first_failure_window_present = 0,
        }
        assert!(select(&packet).is_err(), "mutation {mutation}");
    }
    for path in [
        "mswsock.dll",
        "\\\\server\\share\\mswsock.dll",
        "\\Device\\Volume3\\mswsock.dll",
        "C:\\Windows\\..\\mswsock.dll",
        "C:\\Windows\\system32\\file:stream",
        "C:\\Windows\\system32\\bad.\\mswsock.dll",
    ] {
        let mut packet = fixture(1, 0x8664);
        named(&mut packet.dependencies.entries[0], path);
        packet.dependencies.first_failure = packet.dependencies.entries[0];
        named(&mut packet.loader_owner.dependencies.entries[0], path);
        packet.loader_owner.dependencies.first_failure =
            packet.loader_owner.dependencies.entries[0];
        assert!(select(&packet).is_err(), "{path}");
    }
}

#[test]
fn two_valid_failed_ldr_calls_do_not_silently_choose_a_probe_target() {
    let mut packet = fixture(1, 0x8664);
    packet.entries[0].completion_sequence = 8;
    packet.first_failure = packet.entries[0];
    packet.next_sequence = 8;
    let scope = &mut packet.loader_owner;
    scope.dependencies.total_calls = 2;
    scope.dependencies.total_failures = 2;
    scope.dependencies.record_count = 2;
    scope.dependencies.entries[1] = scope.dependencies.entries[0];
    scope.dependencies.entries[1].sequence = 2;
    scope.link_count = 2;
    scope.links[1] = scope.links[0];
    scope.links[1].dependency_sequence = 2;
    scope.links[1].timeline_sequence = 5;
    scope.window_count = 2;
    scope.windows[1] = scope.windows[0];
    scope.windows[1].dependency_sequence = 2;
    scope.windows[1].started_qpc = 5;
    scope.windows[1].finished_qpc = 6;
    assert_eq!(
        listener_trace_record::diagnostic(&packet)["invalid_packet"],
        false,
        "fixture must reach the independent selection ambiguity check"
    );
    assert!(select(&packet).is_err());
}

#[test]
fn fallback_is_finite_preserves_endpoint_error_and_never_grants_authority() {
    let mut value = json!({"format":"memcordon.post-original-loader-security","revision":1,"state":"unavailable","stage":"capture-post-original-effective-token","unavailable":{"native_error":5,"kind":"PermissionDenied"},"selection":{"path_sha256":vec![7u8;32],"thread_id":7,"dependency_sequence":1,"loader_dependency_sequence":2,"parent_listener_sequence":3},"effective_token_endpoint":{"post_return_sha256":vec![8u8;32],"before_call_sha256":vec![8u8;32],"endpoint_digest_equal":true,"endpoint_comparison_only":true},"token":{"origin":"same-thread"},"access_check_scope":"later-leaf-owner-group-dacl-only","unmodeled_inputs":["original-desired-access","original-file-object","mandatory-integrity-policy","parent-traversal","image-mapping","sharing","other-kernel-policy"],"force":"x".repeat(RECORD_BYTES*2)});
    for key in [
        "reason",
        "observation_timing",
        "file_observation_timing",
        "hypothetical_checks_unavailable",
    ] {
        value[key] = json!("x".repeat(240));
    }
    let output = bounded(value);
    assert!(serde_json::to_vec(&output).unwrap().len() <= RECORD_BYTES);
    assert_eq!(output["stage"], "capture-post-original-effective-token");
    assert_eq!(output["unavailable"]["native_error"], 5);
    assert_eq!(
        output["effective_token_endpoint"]["endpoint_digest_equal"],
        true
    );
    assert_eq!(output["selection"]["path_sha256"], json!(vec![7u8; 32]));
    assert_eq!(
        output["access_check_scope"],
        "later-leaf-owner-group-dacl-only"
    );
    assert_eq!(output["unmodeled_inputs"].as_array().unwrap().len(), 7);
    assert_eq!(output["acceptance_authority"], false);
    assert_eq!(output["denied_object_proved"], false);
    assert!(output["original_desired_access"].is_null());
}

#[test]
fn combined_extreme_field_limits_still_fit_the_independent_security_reservation() {
    let mut value = json!({"stage":"open-selected-leaf-read-control-and-attributes","state":"unavailable","unavailable":{"native_error":5,"kind":"PermissionDenied","padding":"x".repeat(410)},"selection":{"path_sha256":vec![255u8;32],"thread_id":u32::MAX,"dependency_sequence":u64::MAX,"loader_dependency_sequence":u64::MAX,"parent_listener_sequence":u64::MAX},"effective_token_endpoint":{"post_return_sha256":vec![255u8;32],"endpoint_comparison_only":true,"padding":"x".repeat(700)},"token":{"origin":"same-thread","padding":"x".repeat(900)},"later_file_open_request":{"desired_access":131200,"share_access":7,"original_request":false},"later_ancestor_open_request":{"desired_access":128,"share_access":3,"original_request":false},"token_source_requested_access":10,"access_check_duplicate_requested_access":8,"access_check_scope":"later-leaf-owner-group-dacl-only","unmodeled_inputs":["original-desired-access","original-file-object","mandatory-integrity-policy","parent-traversal","image-mapping","sharing","other-kernel-policy"],"force":"x".repeat(100000)});
    for (key, count) in [
        ("reason", 240),
        ("observation_timing", 240),
        ("file_observation_timing", 240),
        ("hypothetical_checks_unavailable", 240),
        ("security_descriptor", 490),
        ("later_file_identity", 240),
        ("generic_mapping", 240),
        ("hypothetical_checks", 2000),
    ] {
        value[key] = json!("x".repeat(count));
    }
    let result = bounded(value);
    assert!(serde_json::to_vec(&result).unwrap().len() <= RECORD_BYTES);
    assert_eq!(result["unavailable"]["native_error"], 5);
    assert_eq!(result["selection"]["path_sha256"], json!(vec![255u8; 32]));
    assert_eq!(
        result["effective_token_endpoint"]["endpoint_comparison_only"],
        true
    );
    assert_eq!(result["later_file_open_request"]["original_request"], false);
    assert!(result["original_desired_access"].is_null());
}
