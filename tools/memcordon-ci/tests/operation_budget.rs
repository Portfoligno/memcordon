use memcordon_ci::command::{CiPhase, CommandSpec, remaining_budget};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

fn operation_reports(root: &Path, expected: usize) -> Vec<PathBuf> {
    let execution = root.join("target/ci/reports/execution");
    let entries: Vec<_> = std::fs::read_dir(&execution)
        .unwrap_or_else(|error| panic!("read {}: {error}", execution.display()))
        .take(expected + 1)
        .map(|entry| entry.unwrap())
        .collect();
    assert_eq!(
        entries.len(),
        expected,
        "unexpected operation count in {execution:?}: {entries:?}"
    );
    entries
        .into_iter()
        .map(|entry| {
            assert!(
                entry.file_type().unwrap().is_dir(),
                "operation is not an ordinary directory: {:?}",
                entry.path()
            );
            assert!(
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with("operation-")),
                "unexpected execution entry: {:?}",
                entry.path()
            );
            let report = entry.path().join("native-execute.json");
            assert!(
                std::fs::symlink_metadata(&report)
                    .unwrap_or_else(|error| panic!("read {}: {error}", report.display()))
                    .file_type()
                    .is_file(),
                "report is not an ordinary file: {report:?}"
            );
            report
        })
        .collect()
}

fn single_operation_report(root: &Path, program: &str, arguments: &[&str]) -> serde_json::Value {
    let paths = operation_reports(root, 1);
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&paths[0]).unwrap()).unwrap();
    assert_eq!(report["phase"], "native-execute");
    assert_eq!(report["state"], "failed");
    assert_eq!(report["program"], program);
    assert_eq!(report["arguments"], serde_json::json!(arguments));
    report
}

#[test]
fn later_phases_cannot_renew_original_operation_allowance() {
    let minutes = |value: u64| Duration::from_secs(value * 60);
    assert_eq!(
        remaining_budget(minutes(60), minutes(40), Duration::from_secs(10)).unwrap(),
        minutes(40) - Duration::from_secs(10)
    );
    assert_eq!(
        remaining_budget(minutes(25), minutes(40), Duration::from_secs(10)).unwrap(),
        minutes(25)
    );
    assert!(
        remaining_budget(minutes(1), Duration::from_secs(10), Duration::from_secs(10)).is_err()
    );
    assert!(remaining_budget(Duration::MAX, Duration::ZERO, Duration::from_secs(10)).is_err());
    assert_eq!(30 + 25 + 15 + 60, 130);
    assert_eq!(30 + 130 + 10 + 10, 180);
}

#[test]
fn exhausted_before_phase_never_starts_child() {
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("must-not-exist");
    let deadline = Instant::now();
    let result = CommandSpec::new(
        "must-not-resolve",
        directory.path(),
        Duration::from_secs(30),
    )
    .arg(&marker)
    .bounded_until(deadline)
    .phase(CiPhase::NativeExecute)
    .output();
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("BudgetExhaustedBeforePhase")
    );
    assert!(!marker.exists());
}

#[test]
fn actual_failed_process_retains_bounded_stderr_and_typed_termination() {
    let directory = tempfile::tempdir().unwrap();
    let executable = env!("CARGO_BIN_EXE_memcordon-ci");
    let output = CommandSpec::new(executable, directory.path(), Duration::from_secs(30))
        .arg("invalid-fixture-command")
        .phase(CiPhase::NativeExecute)
        .output_quiet()
        .unwrap();
    assert!(!output.status.success());
    let report =
        single_operation_report(directory.path(), executable, &["invalid-fixture-command"]);
    assert_eq!(report["state"], "failed");
    assert_eq!(report["cleanup"], "complete");
    assert!(
        report["stderr"]["text"]
            .as_str()
            .unwrap()
            .contains("invalid-fixture-command")
    );
    assert!(report["termination"].is_object());
}

#[test]
fn output_limited_process_retains_each_stream_and_real_cleanup() {
    let directory = tempfile::tempdir().unwrap();
    let result = CommandSpec::new(
        std::env::current_exe().unwrap(),
        directory.path(),
        Duration::from_secs(30),
    )
    .args(["output_cap_child", "--exact", "--ignored", "--nocapture"])
    .phase(CiPhase::NativeExecute)
    .output_quiet();
    let error = result.unwrap_err().to_string();
    assert!(error.contains("subprocess output exceeds byte limit"));
    assert!(error.contains("stderr-cap-sentinel"));
    let report = single_operation_report(
        directory.path(),
        &std::env::current_exe().unwrap().to_string_lossy(),
        &["output_cap_child", "--exact", "--ignored", "--nocapture"],
    );
    assert_eq!(report["output-limited"], true);
    assert_eq!(report["cleanup"], "complete");
    assert_eq!(report["stdout"]["truncated"], true);
    assert!(
        report["stderr"]["text"]
            .as_str()
            .unwrap()
            .contains("stderr-cap-sentinel")
    );
}

#[test]
#[ignore = "native argv output cap helper"]
fn output_cap_child() {
    use std::io::Write;
    eprintln!("stderr-cap-sentinel");
    let bytes = vec![b'x'; 64 * 1024];
    let mut stdout = std::io::stdout().lock();
    loop {
        if stdout.write_all(&bytes).is_err() {
            std::thread::sleep(Duration::from_secs(30));
            return;
        }
    }
}

#[test]
fn spawn_failure_retains_unknown_cleanup_and_no_fabricated_termination() {
    let directory = tempfile::tempdir().unwrap();
    assert!(
        CommandSpec::new(
            "missing-native-executable",
            directory.path(),
            Duration::from_secs(1)
        )
        .phase(CiPhase::NativeExecute)
        .output_quiet()
        .is_err()
    );
    let report = single_operation_report(directory.path(), "missing-native-executable", &[]);
    assert_eq!(report["cleanup"], "unknown");
    assert!(report.get("termination").is_none());
}

#[test]
fn same_phase_commands_retain_distinct_reports_without_overwriting() {
    let directory = tempfile::tempdir().unwrap();
    let executable = env!("CARGO_BIN_EXE_memcordon-ci");
    let run = |argument: &str| {
        let output = CommandSpec::new(executable, directory.path(), Duration::from_secs(30))
            .arg(argument)
            .phase(CiPhase::NativeExecute)
            .output_quiet()
            .unwrap();
        assert!(!output.status.success());
    };
    run("first-invalid-fixture-command");
    let first = operation_reports(directory.path(), 1).remove(0);
    let retained = std::fs::read(&first).unwrap();
    run("second-invalid-fixture-command");
    let reports = operation_reports(directory.path(), 2);
    assert!(reports.contains(&first));
    assert_eq!(std::fs::read(&first).unwrap(), retained);
    let mut arguments = std::collections::BTreeSet::new();
    for path in reports {
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(report["phase"], "native-execute");
        assert_eq!(report["program"], executable);
        assert_eq!(report["state"], "failed");
        assert_eq!(report["cleanup"], "complete");
        assert!(report["termination"].is_object());
        arguments.insert(
            report["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|argument| argument.as_str().unwrap().to_owned())
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(
        arguments,
        [
            vec!["first-invalid-fixture-command".to_owned()],
            vec!["second-invalid-fixture-command".to_owned()]
        ]
        .into_iter()
        .collect()
    );
}
