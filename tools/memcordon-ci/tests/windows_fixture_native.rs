#[path = "../src/windows_fixture_native.rs"]
mod plan;

use std::time::Duration;

#[test]
fn narrow_commands_preserve_existing_targets_and_add_sqos_without_new_budgets() {
    let compile_budget = Duration::from_secs(25 * 60);
    let execution_budget = Duration::from_secs(30 * 60);
    let [compile, execute] = plan::commands(compile_budget, execution_budget);
    let base = [
        "--locked",
        "--target-dir",
        plan::TARGET_DIR,
        "--package",
        "memcordon",
        "--package",
        "memcordon-platform",
        "--test",
        "windows_namespace_primary",
        "--test",
        "windows_gate_call_trace",
        "--test",
        "windows_own_thread_deadline",
        "--test",
        "windows_winsock_call_trace",
        "--test",
        "windows_winsock_registry",
        "--test",
        "windows_private_fixture_native",
        "--test",
        "windows_private_process_native",
        "--test",
        "windows_pipe_sqos",
        "--all-features",
    ];
    assert_eq!(plan::TARGET_DIR, "target/ci/windows-fixture-native");
    assert_eq!(
        plan::TEST_SELECTOR,
        "fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities"
    );
    assert_eq!(
        plan::TRACE_TEST_SELECTOR,
        "isolated_native_mock_and_owned_event_calls_preserve_original_results"
    );
    assert_eq!(
        plan::DEADLINE_TEST_SELECTOR,
        "restricted_initial_thread_deadline_cancels_only_original_io_and_joins"
    );
    assert_eq!(
        plan::WINSOCK_TEST_SELECTOR,
        "restricted_owned_winsock_forwarding_preserves_arguments_results_and_tls_scope"
    );
    assert_eq!(
        plan::REGISTRY_TEST_SELECTOR,
        "owned_registry_projection_preserves_restricted_reads_and_refuses_mutation"
    );
    assert_eq!(
        plan::PRIVATE_FIXTURE_TEST_SELECTOR,
        "actual_main_image_requires_exact_object_content_ancestry_and_separate_output"
    );
    assert_eq!(
        plan::PRIVATE_PROCESS_TEST_SELECTOR,
        "held_child_admission_and_metadata_references_preserve_exact_owners_and_rights"
    );
    assert_eq!(
        plan::SQOS_TEST_SELECTOR,
        "owned_pipe_sqos_rows_measure_authenticated_inventory_without_policy_changes"
    );
    assert_eq!(compile.arguments, [base.as_slice(), &["--no-run"]].concat());
    assert_eq!(
        execute.arguments,
        [
            base.as_slice(),
            &[
                "--",
                "--exact",
                "--nocapture",
                plan::TEST_SELECTOR,
                plan::TRACE_TEST_SELECTOR,
                plan::DEADLINE_TEST_SELECTOR,
                plan::WINSOCK_TEST_SELECTOR,
                plan::REGISTRY_TEST_SELECTOR,
                plan::PRIVATE_FIXTURE_TEST_SELECTOR,
                plan::PRIVATE_PROCESS_TEST_SELECTOR,
                plan::SQOS_TEST_SELECTOR,
            ]
        ]
        .concat()
    );
    assert_eq!(compile.deadline, compile_budget);
    assert_eq!(execute.deadline, execution_budget);
    for command in [compile, execute] {
        for forbidden in ["--workspace", "--all-targets", "--no-fail-fast"] {
            assert!(!command.arguments.contains(&forbidden));
        }
    }
}

fn passed_harness(selector: &str, filtered: usize) -> String {
    format!(
        "running 1 test\ntest {} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.01s\n",
        selector
    )
}

fn passed_output(filtered: usize) -> String {
    [
        passed_harness(plan::TEST_SELECTOR, filtered),
        passed_harness(plan::TRACE_TEST_SELECTOR, 0),
        passed_harness(plan::DEADLINE_TEST_SELECTOR, 0),
        passed_harness(plan::WINSOCK_TEST_SELECTOR, 0),
        passed_harness(plan::REGISTRY_TEST_SELECTOR, 0),
        passed_harness(plan::PRIVATE_FIXTURE_TEST_SELECTOR, 0),
        passed_harness(plan::PRIVATE_PROCESS_TEST_SELECTOR, 0),
        passed_harness(plan::SQOS_TEST_SELECTOR, 0),
    ]
    .concat()
}

fn measured_row(case: plan::sqos::Case) -> plan::sqos::Row {
    use plan::sqos::*;
    // Portable codec data only; these values assert no native Windows outcome.
    let client = Summary {
        process_id: 10,
        process_birth: 11,
        thread_id: 12,
        token_id: 13,
        modified_id: 14,
        authentication_id: 15,
        token_type: 1,
        impersonation_level: None,
        total: 3,
        enabled: 1,
        all_sha256: [1; 32],
        enabled_sha256: [2; 32],
    };
    let mut server = client.clone();
    server.thread_id = 16;
    server.token_type = 2;
    server.impersonation_level = Some(2);
    Row {
        revision: 1,
        case,
        flags: case.flags(),
        desired_access: DESIRED_ACCESS,
        share_mode: 0,
        open_disposition: 3,
        digest_kind: "length-prefixed-le-luid-attributes-v1".into(),
        tracking: "unmeasured-stationary-context".into(),
        before_connect: client.clone(),
        before_write: client.clone(),
        after_write: client,
        server,
        inventory: Inventory::All,
        message_sha256: [3; 32],
        message_read: true,
        server_thread_token: true,
        reverted: true,
        worker_retired: true,
        negative_checks: NegativeChecks {
            authentication_rejected: 1368,
            early_disconnect_rejected: 109,
            pending_read_cancelled: 995,
        },
    }
}

fn sqos_lines() -> String {
    plan::sqos::Case::ALL
        .into_iter()
        .map(|case| {
            format!(
                "{}{}\n",
                plan::sqos::MARKER,
                plan::sqos::encode(&measured_row(case)).unwrap()
            )
        })
        .collect()
}

fn tracking_row(case: plan::sqos::TrackingCase) -> plan::sqos::TrackingRow {
    use plan::sqos::*;
    // Hypothetical codec inputs, never assertions about native SQOS defaults.
    let connect = measured_row(Case::Baseline).before_connect;
    let mut write = connect.clone();
    write.token_id += 100;
    write.modified_id += 100;
    write.token_type = 2;
    write.impersonation_level = Some(2);
    write.total = 2;
    write.all_sha256 = [4; 32];
    write.enabled_sha256 = [5; 32];
    let mut server = if case == TrackingCase::StaticFull {
        connect.clone()
    } else {
        write.clone()
    };
    server.thread_id += 1;
    server.token_id += 200;
    server.token_type = 2;
    server.impersonation_level = Some(2);
    TrackingRow {
        revision: 1,
        case,
        flags: case.flags(),
        desired_access: DESIRED_ACCESS,
        share_mode: 0,
        open_disposition: 3,
        experiment: "thread-context-replacement".into(),
        digest_kind: "length-prefixed-le-luid-attributes-v1".into(),
        inventory: classify_tracking(&connect, &write, &server),
        restored: connect.clone(),
        connect,
        post_write: write.clone(),
        write,
        server,
        message_sha256: [7; 32],
        connect_no_thread_token: true,
        restored_no_thread_token: true,
        writer_context_held_through_server_snapshot: true,
        message_read: true,
        server_thread_token: true,
        reverted: true,
        worker_retired: true,
    }
}

fn tracking_lines() -> String {
    plan::sqos::TrackingCase::ALL
        .into_iter()
        .map(|case| {
            format!(
                "{}{}\n",
                plan::sqos::TRACKING_MARKER,
                plan::sqos::encode_tracking(&tracking_row(case)).unwrap()
            )
        })
        .collect()
}

#[test]
fn tracking_has_three_separate_rows_without_assuming_the_baseline_outcome() {
    use plan::sqos::*;
    assert_eq!(
        TrackingCase::ALL.map(TrackingCase::flags),
        [0x80, 0x120080, 0x160080]
    );
    let inventory = sqos_lines();
    let tracking = tracking_lines();
    let combined = format!("{inventory}{tracking}");
    let rows = extract_tracking(combined.as_bytes()).unwrap();
    assert_eq!(rows.len(), 3);
    verify_tracking_rows(&rows).unwrap();
    let inventory_rows = extract(inventory.as_bytes()).unwrap();
    plan::verify_measurements(&inventory_rows, &rows).unwrap();
    assert!(plan::verify_measurements(&inventory_rows[..4], &rows).is_err());
    assert!(plan::verify_measurements(&inventory_rows, &rows[..2]).is_err());
    assert_eq!(
        extract(combined.as_bytes()).unwrap(),
        extract(inventory.as_bytes()).unwrap()
    );
    assert_eq!(
        extract_tracking(combined.replace('\n', "\r\n").as_bytes()).unwrap(),
        rows
    );
    for baseline in [
        TrackingInventory::ConnectAll,
        TrackingInventory::ConnectEnabled,
        TrackingInventory::WriteAll,
        TrackingInventory::WriteEnabled,
        TrackingInventory::Other,
    ] {
        let mut row = tracking_row(TrackingCase::Baseline);
        match baseline {
            TrackingInventory::ConnectAll => row.server = row.connect.clone(),
            TrackingInventory::ConnectEnabled => {
                row.server.total = row.connect.enabled;
                row.server.all_sha256 = row.connect.enabled_sha256;
            }
            TrackingInventory::WriteEnabled => {
                row.server.total = row.write.enabled;
                row.server.all_sha256 = row.write.enabled_sha256;
            }
            TrackingInventory::Other => row.server.all_sha256 = [9; 32],
            _ => {}
        }
        row.server.token_type = 2;
        row.server.impersonation_level = Some(2);
        row.server.thread_id = 99;
        row.inventory = classify_tracking(&row.connect, &row.write, &row.server);
        assert_eq!(row.inventory, baseline);
        let mut actual = rows.clone();
        actual[0] = encode_tracking(&row).unwrap();
        verify_tracking_rows(&actual).unwrap();
    }
    for connect_context in [true, false] {
        let row = tracking_row(TrackingCase::Baseline);
        let mut connect = row.connect;
        let mut write = row.write;
        let context = if connect_context {
            &mut connect
        } else {
            &mut write
        };
        context.total = context.enabled;
        context.all_sha256 = context.enabled_sha256;
        let server = context.clone();
        assert_eq!(
            classify_tracking(&connect, &write, &server),
            if connect_context {
                TrackingInventory::ConnectBoth
            } else {
                TrackingInventory::WriteBoth
            }
        );
    }
}

#[test]
fn tracking_marker_rejects_missing_duplicate_extra_malformed_and_private_fields() {
    use plan::sqos::*;
    let valid = tracking_lines();
    let lines: Vec<_> = valid.lines().collect();
    for invalid in [
        String::new(),
        sqos_lines(),
        lines[..2].join("\n"),
        [lines[0], lines[0], lines[2]].join("\n"),
        [lines[1], lines[0], lines[2]].join("\n"),
        format!("{valid}{}\n", lines[0]),
        format!("{TRACKING_MARKER}{{}}\n"),
        format!("{TRACKING_MARKER}{}\n", "x".repeat(MAX_ROW_BYTES + 1)),
        format!("{valid}{GAP_MARKER}{{\"state\":\"unavailable\"}}\n"),
    ] {
        assert!(extract_tracking(invalid.as_bytes()).is_err());
    }
    assert!(extract_tracking(&[0xff]).is_err());
    assert!(extract_tracking(&vec![b'x'; MAX_OUTPUT_BYTES + 1]).is_err());
    for field in ["environment", "raw_token", "handle", "request_bytes"] {
        let mut wire = serde_json::to_value(tracking_row(TrackingCase::Baseline)).unwrap();
        wire[field] = serde_json::json!("must not be forwarded");
        let invalid = format!("{TRACKING_MARKER}{wire}\n{}", lines[1..].join("\n"));
        assert!(extract_tracking(invalid.as_bytes()).is_err());
    }
    let invalid = valid.replace("thread-context-replacement", "in-place-token-mutation");
    assert!(extract_tracking(invalid.as_bytes()).is_err());
    let invalid = valid.replace("\"baseline\"", "\"static-effective\"");
    assert!(extract_tracking(invalid.as_bytes()).is_err());
}

#[test]
fn tracking_failed_restoration_or_context_contract_is_retained_without_passing() {
    use plan::sqos::*;
    let valid = extract_tracking(tracking_lines().as_bytes()).unwrap();
    for mutation in 0..13 {
        let mut row = tracking_row(TrackingCase::Baseline);
        match mutation {
            0 => row.connect_no_thread_token = false,
            1 => row.restored_no_thread_token = false,
            2 => row.writer_context_held_through_server_snapshot = false,
            3 => row.restored.modified_id += 1,
            4 => row.post_write.modified_id += 1,
            5 => {
                row.write.thread_id += 1;
                row.post_write = row.write.clone();
            }
            6 => {
                row.connect.token_type = 2;
                row.connect.impersonation_level = Some(2);
                row.restored = row.connect.clone();
            }
            7 => {
                row.write.token_type = 1;
                row.write.impersonation_level = None;
                row.post_write = row.write.clone();
            }
            8 => {
                row.write.enabled_sha256 = row.connect.enabled_sha256;
                row.post_write = row.write.clone();
            }
            9 => row.message_read = false,
            10 => row.server_thread_token = false,
            11 => row.reverted = false,
            _ => row.worker_retired = false,
        }
        row.inventory = classify_tracking(&row.connect, &row.write, &row.server);
        let json = encode_tracking(&row).unwrap();
        let all = format!(
            "{TRACKING_MARKER}{json}\n{}",
            valid[1..]
                .iter()
                .map(|json| format!("{TRACKING_MARKER}{json}\n"))
                .collect::<String>()
        );
        let retained = extract_tracking(all.as_bytes()).unwrap();
        assert!(
            verify_tracking_rows(&retained).is_err(),
            "mutation {mutation}"
        );
    }
    for (index, case) in [
        (1, TrackingCase::StaticFull),
        (2, TrackingCase::DynamicFull),
    ] {
        let mut row = tracking_row(case);
        row.server = if case == TrackingCase::StaticFull {
            row.write.clone()
        } else {
            row.connect.clone()
        };
        row.server.token_type = 2;
        row.server.impersonation_level = Some(2);
        row.inventory = classify_tracking(&row.connect, &row.write, &row.server);
        let mut wrong = valid.clone();
        wrong[index] = encode_tracking(&row).unwrap();
        assert!(verify_tracking_rows(&wrong).is_err());
    }
}

#[test]
fn sqos_measurements_preserve_exact_five_rows_and_redacted_scalar_scope() {
    use plan::sqos::*;
    assert_eq!(
        Case::ALL.map(Case::flags),
        [0x80, 0x120080, 0x1a0080, 0x160080, 0x1e0080]
    );
    let lines = sqos_lines();
    let extracted = extract(lines.as_bytes()).unwrap();
    assert_eq!(extracted.len(), 5);
    verify_rows(&extracted).unwrap();
    assert_eq!(
        extract(lines.replace('\n', "\r\n").as_bytes()).unwrap(),
        extracted
    );
    for (json, case) in extracted.iter().zip(Case::ALL) {
        assert!(json.len() <= MAX_ROW_BYTES);
        let row: Row = serde_json::from_str(json).unwrap();
        assert_eq!(row.case, case);
        assert_eq!(row.desired_access, 0x0012_019b);
        assert_eq!(row.share_mode, 0);
        assert_eq!(row.open_disposition, 3);
        assert_eq!(row.tracking, "unmeasured-stationary-context");
        assert_eq!(row.before_connect.token_type, 1);
        assert_eq!(row.before_connect.impersonation_level, None);
        assert_eq!(row.server.impersonation_level, Some(2));
        for forbidden in [
            "environment",
            "raw_sid",
            "handle",
            "privilege_list",
            "command",
        ] {
            assert!(!json.contains(forbidden));
        }
    }
    let client = measured_row(Case::Baseline).before_write;
    let mut server = client.clone();
    assert_eq!(classify(&client, &server), Inventory::All);
    server.total = client.enabled;
    server.all_sha256 = client.enabled_sha256;
    assert_eq!(classify(&client, &server), Inventory::Enabled);
    server.all_sha256 = [9; 32];
    assert_eq!(classify(&client, &server), Inventory::Other);
    let mut all_enabled = client.clone();
    all_enabled.enabled = all_enabled.total;
    all_enabled.enabled_sha256 = all_enabled.all_sha256;
    assert_eq!(classify(&all_enabled, &all_enabled), Inventory::Both);
    let mut changed = measured_row(Case::Baseline);
    changed.after_write.modified_id += 1;
    assert!(validate(&changed).is_err());
    let retained = encode(&changed).unwrap();
    let retained: Row = serde_json::from_str(&retained).unwrap();
    assert_eq!(
        retained.after_write.modified_id,
        changed.after_write.modified_id
    );
    let failed = format!(
        "{MARKER}{}\n{}",
        encode(&changed).unwrap(),
        lines.lines().skip(1).collect::<Vec<_>>().join("\n")
    );
    let failed_rows = extract(failed.as_bytes()).unwrap();
    assert!(verify_rows(&failed_rows).is_err());
}

#[test]
fn sqos_missing_duplicate_extra_malformed_or_unbounded_evidence_is_rejected() {
    use plan::sqos::*;
    let valid = sqos_lines();
    let lines: Vec<_> = valid.lines().collect();
    for invalid in [
        String::new(),
        lines[..4].join("\n"),
        [lines[0], lines[0], lines[2], lines[3], lines[4]].join("\n"),
        [lines[1], lines[0], lines[2], lines[3], lines[4]].join("\n"),
        format!("{valid}{}\n", lines[0]),
        format!("{MARKER}{{}}\n"),
        format!(
            "{valid}{}{{\"revision\":1,\"state\":\"unavailable\",\"detail\":\"portable gap test\"}}\n",
            GAP_MARKER
        ),
        format!("{MARKER}{}\n", "x".repeat(MAX_ROW_BYTES + 1)),
    ] {
        assert!(extract(invalid.as_bytes()).is_err(), "{invalid:?}");
    }
    assert!(extract(&[0xff]).is_err());
    assert!(extract(&vec![b'x'; MAX_OUTPUT_BYTES + 1]).is_err());
    let row = measured_row(Case::Baseline);
    for field in ["environment", "raw_sid", "handle", "extra"] {
        let mut wire = serde_json::to_value(&row).unwrap();
        wire[field] = serde_json::json!("private data must not be forwarded");
        let invalid = format!("{MARKER}{}\n{}", wire, lines[1..].join("\n"));
        assert!(extract(invalid.as_bytes()).is_err());
    }
    for mutate in 0..13 {
        let mut wrong = row.clone();
        match mutate {
            0 => wrong.flags ^= 1,
            1 => wrong.message_read = false,
            2 => wrong.server_thread_token = false,
            3 => wrong.reverted = false,
            4 => wrong.worker_retired = false,
            5 => wrong.server.enabled = wrong.server.total + 1,
            6 => wrong.negative_checks.authentication_rejected = 0,
            7 => wrong.negative_checks.early_disconnect_rejected = 0,
            8 => wrong.negative_checks.pending_read_cancelled = 0,
            9 => wrong.negative_checks.pending_read_cancelled = 5,
            10 => wrong.desired_access = 0xc000_0000,
            11 => wrong.share_mode = 1,
            _ => wrong.open_disposition = 2,
        }
        assert!(validate(&wrong).is_err());
    }
}

#[test]
fn sqos_libtest_interleaving_keeps_real_pass_and_all_measurements_required() {
    let json = format!("{}{}", sqos_lines(), tracking_lines());
    let prefix = format!("test {} ... ", plan::SQOS_TEST_SELECTOR);
    let interleaved = format!(
        "running 1 test\n{prefix}{json}ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
    );
    let ordinary = passed_harness(plan::SQOS_TEST_SELECTOR, 0);
    let output = passed_output(0).replace(&ordinary, &interleaved);
    plan::verify_selected_tests(output.as_bytes()).unwrap();
    assert_eq!(plan::sqos::extract(output.as_bytes()).unwrap().len(), 5);
    assert_eq!(
        plan::sqos::extract_tracking(output.as_bytes())
            .unwrap()
            .len(),
        3
    );
    for wrong in [
        output.replace("\nok\n", "\nFAILED\n"),
        output.replace("\nok\n", "\n"),
        output.replace(
            &prefix,
            &format!("test {} ... ", plan::PRIVATE_PROCESS_TEST_SELECTOR),
        ),
    ] {
        assert!(plan::verify_selected_tests(wrong.as_bytes()).is_err());
    }
    assert!(plan::verify_selected_tests(format!("{}ok\n", passed_output(0)).as_bytes()).is_err());
    let summary = ordinary
        .lines()
        .find(|line| line.starts_with("test result:"))
        .unwrap();
    let others = passed_output(0)
        .replace(&ordinary, "")
        .replace(&passed_harness(plan::TEST_SELECTOR, 0), "");
    let interrupted = format!(
        "running 1 test\n{prefix}{json}test {} ... ok\n{summary}\n{others}ok\n{summary}\n",
        plan::TEST_SELECTOR
    );
    assert!(plan::verify_selected_tests(interrupted.as_bytes()).is_err());
}

#[test]
fn eight_distinct_executions_preserve_prior_orders_and_accept_platform_targets_in_any_position() {
    for filtered in [0, 83] {
        let output = passed_output(filtered);
        plan::verify_selected_tests(output.as_bytes()).unwrap();
        plan::verify_selected_tests(output.replace('\n', "\r\n").as_bytes()).unwrap();
        for first in 0..4 {
            for second in 0..4 {
                for third in 0..4 {
                    if first == second || first == third || second == third {
                        continue;
                    }
                    let fourth = (0..4)
                        .find(|index| *index != first && *index != second && *index != third)
                        .unwrap();
                    let order = [first, second, third, fourth];
                    let reordered = [
                        order
                            .map(|index| passed_harness(plan::TEST_SELECTORS[index], filtered))
                            .concat(),
                        passed_harness(plan::REGISTRY_TEST_SELECTOR, filtered),
                        passed_harness(plan::PRIVATE_FIXTURE_TEST_SELECTOR, filtered),
                        passed_harness(plan::PRIVATE_PROCESS_TEST_SELECTOR, filtered),
                        passed_harness(plan::SQOS_TEST_SELECTOR, filtered),
                    ]
                    .concat();
                    plan::verify_selected_tests(reordered.as_bytes()).unwrap();
                }
            }
        }
        for offset in 0..plan::TEST_SELECTORS.len() {
            let reordered: String = (0..plan::TEST_SELECTORS.len())
                .map(|index| {
                    passed_harness(
                        plan::TEST_SELECTORS[(index + offset) % plan::TEST_SELECTORS.len()],
                        filtered,
                    )
                })
                .collect();
            plan::verify_selected_tests(reordered.as_bytes()).unwrap();
        }
    }
}

#[test]
fn zero_wrong_duplicate_or_missing_execution_evidence_cannot_pass() {
    let valid = passed_output(83);
    let wrong_name = valid.replace(plan::TEST_SELECTOR, "unrelated::native_test");
    let summary_only = valid.lines().last().unwrap();
    let selected_only = format!("test {} ... ok\n", plan::TEST_SELECTOR);
    let zero = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 83 filtered out; finished in 0.00s\n";
    for invalid in [
        String::new(),
        wrong_name,
        summary_only.to_owned(),
        selected_only,
        zero.to_owned(),
        valid.replace("running 1 test\n", ""),
        valid.replace(&format!("test {} ... ok\n", plan::TEST_SELECTOR), ""),
        valid.replace("running 1 test", "running 2 tests"),
        [valid.as_str(), valid.as_str()].concat(),
        valid.replace("running 1 test", "running 1 test\nrunning 0 tests"),
        passed_harness(plan::TEST_SELECTOR, 83),
        passed_harness(plan::TRACE_TEST_SELECTOR, 0),
        passed_harness(plan::DEADLINE_TEST_SELECTOR, 0),
        passed_harness(plan::WINSOCK_TEST_SELECTOR, 0),
        passed_harness(plan::REGISTRY_TEST_SELECTOR, 0),
        valid.replace(&passed_harness(plan::REGISTRY_TEST_SELECTOR, 0), ""),
        valid.replace(plan::REGISTRY_TEST_SELECTOR, plan::WINSOCK_TEST_SELECTOR),
        valid.replace(&passed_harness(plan::WINSOCK_TEST_SELECTOR, 0), ""),
        valid.replace(plan::WINSOCK_TEST_SELECTOR, plan::DEADLINE_TEST_SELECTOR),
        [
            passed_harness(plan::TEST_SELECTOR, 0),
            passed_harness(plan::TRACE_TEST_SELECTOR, 0),
        ]
        .concat(),
        valid.replace(plan::DEADLINE_TEST_SELECTOR, plan::TEST_SELECTOR),
        valid.replace(plan::DEADLINE_TEST_SELECTOR, plan::TRACE_TEST_SELECTOR),
        valid.replace(&passed_harness(plan::DEADLINE_TEST_SELECTOR, 0), ""),
        valid.replace(plan::TRACE_TEST_SELECTOR, plan::TEST_SELECTOR),
        valid.replace(plan::TEST_SELECTOR, plan::TRACE_TEST_SELECTOR),
        valid.replace(plan::TRACE_TEST_SELECTOR, "unknown_second_test"),
        valid.replace(&format!("test {} ... ok\n", plan::TRACE_TEST_SELECTOR), ""),
        [valid.as_str(), passed_harness("extra_test", 0).as_str()].concat(),
        format!("{valid}running 1 test\n"),
    ] {
        assert!(
            plan::verify_selected_tests(invalid.as_bytes()).is_err(),
            "{invalid:?}"
        );
    }
    assert!(plan::verify_selected_tests(&[0xff]).is_err());
    assert!(plan::verify_selected_tests(&vec![b'x'; 1024 * 1024 + 1]).is_err());
    for selector in [
        plan::PRIVATE_FIXTURE_TEST_SELECTOR,
        plan::PRIVATE_PROCESS_TEST_SELECTOR,
        plan::SQOS_TEST_SELECTOR,
    ] {
        assert!(plan::verify_selected_tests(passed_harness(selector, 0).as_bytes()).is_err());
        let missing = valid.replace(&passed_harness(selector, 0), "");
        assert!(plan::verify_selected_tests(missing.as_bytes()).is_err());
        let duplicate = valid.replace(selector, plan::REGISTRY_TEST_SELECTOR);
        assert!(plan::verify_selected_tests(duplicate.as_bytes()).is_err());
        let ignored = valid.replace(
            &format!("test {selector} ... ok"),
            &format!("test {selector} ... ignored"),
        );
        assert!(plan::verify_selected_tests(ignored.as_bytes()).is_err());
    }
}

#[test]
fn failed_ignored_measured_or_contradictory_counts_cannot_certify_execution() {
    let valid = passed_output(83);
    for invalid in [
        valid.replace(" ... ok", " ... FAILED"),
        valid.replace(" ... ok", " ... ignored"),
        valid.replace("test result: ok.", "test result: FAILED."),
        valid.replace("1 passed", "0 passed"),
        valid.replace("1 passed", "2 passed"),
        valid.replace("0 failed", "1 failed"),
        valid.replace("0 ignored", "1 ignored"),
        valid.replace("0 measured", "1 measured"),
        valid.replace("83 filtered out", "unknown filtered out"),
        valid.replace("finished in 0.01s", "finished in NaNs"),
        valid.replace("finished in 0.01s", "finished in -1s"),
        valid.replace("finished in 0.01s", "finished in "),
        valid.replace(
            &format!("test {} ... ok", plan::TRACE_TEST_SELECTOR),
            &format!("test {} ... ignored", plan::TRACE_TEST_SELECTOR),
        ),
        valid.replace(
            &format!("test {} ... ok", plan::DEADLINE_TEST_SELECTOR),
            &format!("test {} ... ignored", plan::DEADLINE_TEST_SELECTOR),
        ),
        valid.replace(
            &format!("test {} ... ok", plan::WINSOCK_TEST_SELECTOR),
            &format!("test {} ... ignored", plan::WINSOCK_TEST_SELECTOR),
        ),
        valid.replace(
            &format!("test {} ... ok", plan::REGISTRY_TEST_SELECTOR),
            &format!("test {} ... ignored", plan::REGISTRY_TEST_SELECTOR),
        ),
    ] {
        assert!(
            plan::verify_selected_tests(invalid.as_bytes()).is_err(),
            "{invalid:?}"
        );
    }
}
