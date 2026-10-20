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

#[cfg(unix)]
fn retained_output(success: bool) -> memcordon_testkit::ObservedOutput {
    use std::os::unix::process::ExitStatusExt;
    memcordon_testkit::ObservedOutput {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: b"actual command output".to_vec(),
        stderr: b"actual uninstall refusal".to_vec(),
        elapsed: std::time::Duration::ZERO,
    }
}

#[cfg(unix)]
#[test]
fn retained_failure_keeps_command_cause_with_either_receipt_result() {
    for retention in [
        Ok(()),
        Err(memcordon_ci::CiError::Io(std::io::Error::from(
            std::io::ErrorKind::WriteZero,
        ))),
    ] {
        let receipt_failed = retention.is_err();
        let error = memcordon_ci::command::require_successful_retained_output(
            "interrupted uninstall; administrative owner retained",
            &retained_output(false),
            retention,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("administrative owner retained"));
        assert!(error.contains("native command failed"));
        assert!(error.contains("actual uninstall refusal"));
        assert!(error.contains("actual command output"));
        assert!(error.contains(&format!("receipt-error-present={receipt_failed}")));
    }
}

#[cfg(unix)]
#[test]
fn retained_success_requires_successful_receipt_without_changing_its_error_type() {
    let output = retained_output(true);
    memcordon_ci::command::require_successful_retained_output("uninstall", &output, Ok(()))
        .unwrap();
    let error = memcordon_ci::command::require_successful_retained_output(
        "uninstall",
        &output,
        Err(memcordon_ci::CiError::Io(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        ))),
    )
    .unwrap_err();
    assert!(
        matches!(error, memcordon_ci::CiError::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied)
    );
}

#[cfg(unix)]
#[test]
fn retained_failure_output_is_bounded_and_escapes_untrusted_control_characters() {
    let mut output = retained_output(false);
    output.stdout = vec![255; 10_000];
    output.stdout[0] = b'\n';
    output.stderr = vec![b'\t'; 10_000];
    let receipt = format!("receipt failed\n{}", "x".repeat(10_000));
    let error = memcordon_ci::command::require_successful_retained_output(
        "uninstall",
        &output,
        Err(memcordon_ci::CiError::Message(receipt)),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("stdout-bytes=10000"));
    assert!(error.contains("stderr-bytes=10000"));
    assert!(error.contains("stdout-truncated=true"));
    assert!(error.contains("stderr-truncated=true"));
    assert!(error.contains("receipt-error-truncated=true"));
    assert!(error.contains("\\n"));
    assert!(error.contains("\\t"));
    assert!(!error.contains('\n'));
    assert!(!error.contains('\t'));
    assert!(error.len() < 16 * 1024);
}
