#![cfg(all(windows, feature = "test-fixtures"))]
#[test]
fn restricted_owned_winsock_forwarding_preserves_arguments_results_and_tls_scope() {
    let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let fixture = env!("CARGO_BIN_EXE_memcordon-test-fixture");
    let mut command = std::process::Command::new(fixture);
    command.stdin(std::process::Stdio::null()).args([
        "consumer-readiness-windows",
        "restricted-frontend",
        fixture,
        "consumer-readiness-windows",
        "winsock-call-trace-self-check",
    ]);
    let remaining = cutoff
        .checked_duration_since(std::time::Instant::now())
        .filter(|value| !value.is_zero())
        .expect("original combined forwarding check cutoff");
    let output =
        memcordon_testkit::run_with_deadline_output_limit(&mut command, remaining, 64 * 1024)
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
    let mut listener = std::process::Command::new(fixture);
    listener.stdin(std::process::Stdio::null()).args([
        "consumer-readiness-windows",
        "listener-call-trace-self-check",
    ]);
    let remaining = cutoff
        .checked_duration_since(std::time::Instant::now())
        .filter(|value| !value.is_zero())
        .expect("original combined forwarding check cutoff");
    let output =
        memcordon_testkit::run_with_deadline_output_limit(&mut listener, remaining, 64 * 1024)
            .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
