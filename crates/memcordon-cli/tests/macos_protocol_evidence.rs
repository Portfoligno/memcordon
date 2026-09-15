#![cfg(all(target_os = "macos", feature = "test-fixtures"))]

use memcordon_platform::test_support::macos_protocol_expectation_fixture as exchange;

#[test]
fn launch_expectation_preserves_success_errno_and_distinct_rejections() {
    exchange(0).unwrap();
    assert_eq!(exchange(1).unwrap_err().raw_os_error(), Some(libc::ENOENT));
    let detailed = exchange(2).unwrap_err();
    assert!(
        detailed
            .to_string()
            .contains("expected Released, received FailureDetail")
    );
    assert!(
        detailed
            .to_string()
            .contains("confirm target exec witness: fixture evidence")
    );
    let unexpected = exchange(3).unwrap_err();
    assert!(
        unexpected
            .to_string()
            .contains("expected Released, received Retired")
    );
    let eof = exchange(4).unwrap_err();
    assert_eq!(eof.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(eof.to_string().contains("expected Released, received EOF"));
}
