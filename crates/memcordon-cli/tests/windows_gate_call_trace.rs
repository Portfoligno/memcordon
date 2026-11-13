#![cfg(all(windows, feature = "test-fixtures"))]
#[test]
fn isolated_native_mock_and_owned_event_calls_preserve_original_results() {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
    command.args(["consumer-readiness-windows", "gate-call-trace-self-check"]);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        std::time::Duration::from_secs(10),
        64 * 1024,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
