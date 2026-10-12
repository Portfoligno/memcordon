#[path = "../src/release/native_package_diagnostics.rs"]
mod native_package_diagnostics;

#[test]
fn actual_status_and_install_error_survive_without_claiming_success() {
    let message = native_package_diagnostics::install_failure(
        Some(17),
        b"selected package output",
        b"original installation refusal\n",
    );
    assert!(message.contains("status=Some(17)"));
    assert!(message.contains("selected package output"));
    assert!(message.contains("original installation refusal\\n"));
    assert!(message.contains("owner retains finalization"));
    assert!(!message.contains('\n'));
    let signal = native_package_diagnostics::install_failure(None, b"", b"terminated");
    assert!(signal.contains("status=None"));
    assert!(!signal.contains("status=Some(0)"));
}

#[test]
fn large_and_non_utf8_capture_keeps_both_ends_with_finite_rendered_size() {
    let mut bytes = vec![0; 100_000];
    bytes[..4].copy_from_slice(b"HEAD");
    bytes[99_996..].copy_from_slice(b"TAIL");
    let message = native_package_diagnostics::install_failure(Some(1), &bytes, &bytes);
    assert_eq!(message.matches("HEAD").count(), 2);
    assert_eq!(message.matches("TAIL").count(), 2);
    assert_eq!(message.matches("[truncated]").count(), 2);
    assert!(message.len() < 16 * 1024);
    let invalid =
        native_package_diagnostics::install_failure(Some(1), &[0xff; 100_000], &[0xff; 100_000]);
    assert!(invalid.contains("[truncated]"));
    assert!(invalid.len() < 16 * 1024);
}
