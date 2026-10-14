#[cfg(unix)]
#[test]
fn failed_native_command_is_rejected_before_empty_json_is_decoded() {
    use std::os::unix::process::ExitStatusExt;
    let mut output = memcordon_testkit::ObservedOutput {
        status: std::process::ExitStatus::from_raw(256),
        stdout: Vec::new(),
        stderr: b"publication phase=Flush: native failure".to_vec(),
        elapsed: std::time::Duration::ZERO,
    };
    let error = memcordon_ci::command::require_successful_output("native recovery", &output)
        .unwrap_err()
        .to_string();
    assert!(error.contains("native command failed"));
    assert!(error.contains("publication phase=Flush"));
    assert!(error.contains("stdout-bytes=0"));
    assert!(!error.contains("EOF"));
    output.status = std::process::ExitStatus::from_raw(0);
    memcordon_ci::command::require_successful_output("native recovery", &output).unwrap();
    assert!(
        serde_json::from_slice::<memcordon_core::WindowsRecoveryInventoryV1>(&output.stdout)
            .is_err()
    );
    output.status = std::process::ExitStatus::from_raw(256);
    output.stderr = vec![255; 10000];
    let error = memcordon_ci::command::require_successful_output("native recovery", &output)
        .unwrap_err()
        .to_string();
    assert!(error.contains("stderr-truncated=true"));
    assert!(error.len() < 6500);
}
