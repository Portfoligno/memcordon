#![cfg(all(windows, feature = "test-fixtures"))]

#[test]
fn owned_registry_projection_preserves_restricted_reads_and_refuses_mutation() {
    let fixture = env!("CARGO_BIN_EXE_memcordon-test-fixture");
    let mut command = std::process::Command::new(fixture);
    command
        .stdin(std::process::Stdio::null())
        .args(["consumer-readiness-windows", "winsock-registry-self-check"]);
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
