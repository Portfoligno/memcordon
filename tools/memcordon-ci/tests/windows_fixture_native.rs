#[path = "../src/windows_fixture_native.rs"]
mod plan;

use std::time::Duration;

#[test]
fn narrow_commands_select_original_five_and_two_platform_native_targets_without_new_budgets() {
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
    ]
    .concat()
}

#[test]
fn seven_distinct_executions_preserve_prior_orders_and_accept_platform_targets_in_any_position() {
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
