use memcordon_ci::command::{CiPhase, CommandSpec, remaining_budget};
use std::time::{Duration, Instant};

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
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            directory
                .path()
                .join("target/ci/reports/execution/native-execute.json"),
        )
        .unwrap(),
    )
    .unwrap();
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
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            directory
                .path()
                .join("target/ci/reports/execution/native-execute.json"),
        )
        .unwrap(),
    )
    .unwrap();
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
    let report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            directory
                .path()
                .join("target/ci/reports/execution/native-execute.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(report["cleanup"], "unknown");
    assert!(report.get("termination").is_none());
}
