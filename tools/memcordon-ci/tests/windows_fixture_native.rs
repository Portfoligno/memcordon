#[path = "../src/windows_fixture_native.rs"]
mod plan;

use std::time::Duration;

#[test]
fn narrow_commands_select_only_the_actual_fixture_binary_and_exact_native_test() {
    let compile_budget = Duration::from_secs(25 * 60);
    let execution_budget = Duration::from_secs(30 * 60);
    let [compile, execute] = plan::commands(compile_budget, execution_budget);
    let base = [
        "--locked",
        "--target-dir",
        plan::TARGET_DIR,
        "--package",
        "memcordon",
        "--test",
        "windows_namespace_primary",
        "--all-features",
    ];
    assert_eq!(plan::TARGET_DIR, "target/ci/windows-fixture-native");
    assert_eq!(
        plan::TEST_SELECTOR,
        "fresh_restricted_primary_opens_owned_namespace_without_inherited_gate_capabilities"
    );
    assert_eq!(compile.arguments, [base.as_slice(), &["--no-run"]].concat());
    assert_eq!(
        execute.arguments,
        [
            base.as_slice(),
            &[plan::TEST_SELECTOR, "--", "--exact", "--nocapture"]
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

fn passed_output(filtered: usize) -> String {
    format!(
        "running 1 test\ntest {} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.01s\n",
        plan::TEST_SELECTOR
    )
}

#[test]
fn successful_exact_native_execution_requires_one_real_selected_test() {
    for filtered in [0, 83] {
        let output = passed_output(filtered);
        plan::verify_one_test(output.as_bytes()).unwrap();
        plan::verify_one_test(output.replace('\n', "\r\n").as_bytes()).unwrap();
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
    ] {
        assert!(
            plan::verify_one_test(invalid.as_bytes()).is_err(),
            "{invalid:?}"
        );
    }
    assert!(plan::verify_one_test(&[0xff]).is_err());
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
    ] {
        assert!(
            plan::verify_one_test(invalid.as_bytes()).is_err(),
            "{invalid:?}"
        );
    }
}
