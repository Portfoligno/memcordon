#[path = "../src/windows_caller_snapshot_diagnostic.rs"]
mod diagnostic;

#[test]
fn actual_status_and_arbitrary_streams_remain_distinct() {
    let text = diagnostic::failure(true, Some(125), b"partial\xff\n", b"access denied\0");
    assert!(text.contains("restricted=true; status=Some(125)"));
    assert!(text.contains("partial"));
    assert!(text.contains("access denied\\0"));
    assert!(!text.contains('\n'));
    assert!(diagnostic::failure(false, None, b"", b"").contains("status=None"));
}

#[test]
fn stream_excerpts_are_finite_with_truthful_lengths() {
    let bytes = vec![b'x'; 5000];
    let text = diagnostic::failure(true, Some(1), &bytes, &bytes);
    assert_eq!(text.matches("bytes=5000; truncated=true").count(), 2);
    assert!(text.len() < 8500);
}
