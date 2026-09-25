#![cfg(target_os = "linux")]

use crate::linux::private_release_case::candidate_fixture_output;
use crate::linux::private_release_denial::{
    IMPORT_SELECTOR, NAMESPACE_SELECTOR, PORT_COLLISION_SELECTOR, SELECTOR, expected_errno_bytes,
    expected_import_errno_bytes, expected_namespace_errno_bytes,
    expected_port_collision_errno_bytes,
};

#[test]
fn fixed_unix_denial_observation_encodes_both_exact_errnos() {
    assert_eq!(SELECTOR, "private_tcp::af_unix_socketpair_denied");
    let bytes = expected_errno_bytes();
    assert_eq!(
        i32::from_le_bytes(bytes[..4].try_into().unwrap()),
        libc::EAFNOSUPPORT
    );
    assert_eq!(
        i32::from_le_bytes(bytes[4..].try_into().unwrap()),
        libc::EPERM
    );
    let output = candidate_fixture_output(SELECTOR, &[0x42; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + bytes.len());
    assert_eq!(&output[output.len() - bytes.len()..], bytes);
    assert_eq!(
        candidate_fixture_output("private_tcp::native_tcp_bind_listen_connect", &[0x42; 32]).len(),
        [0_u8; 32].len()
    );
}

#[test]
fn fixed_import_denial_observation_encodes_exact_seccomp_errnos() {
    assert_eq!(
        IMPORT_SELECTOR,
        "private_tcp::io_uring_and_pidfd_import_denied"
    );
    let bytes = expected_import_errno_bytes();
    assert_eq!(
        i32::from_le_bytes(bytes[..4].try_into().unwrap()),
        libc::EPERM
    );
    assert_eq!(
        i32::from_le_bytes(bytes[4..].try_into().unwrap()),
        libc::EPERM
    );
    let output = candidate_fixture_output(IMPORT_SELECTOR, &[0x43; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + bytes.len());
    assert_eq!(&output[output.len() - bytes.len()..], bytes);
    assert_ne!(output, candidate_fixture_output(SELECTOR, &[0x43; 32]));
}

#[test]
fn fixed_namespace_reentry_observation_encodes_exact_seccomp_errnos() {
    assert_eq!(NAMESPACE_SELECTOR, "private_tcp::namespace_reentry_denied");
    let bytes = expected_namespace_errno_bytes();
    assert_eq!(
        i32::from_le_bytes(bytes[..4].try_into().unwrap()),
        libc::EPERM
    );
    assert_eq!(
        i32::from_le_bytes(bytes[4..].try_into().unwrap()),
        libc::EPERM
    );
    let output = candidate_fixture_output(NAMESPACE_SELECTOR, &[0x44; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + bytes.len());
    assert_eq!(&output[output.len() - bytes.len()..], bytes);
    assert_ne!(
        output,
        candidate_fixture_output(IMPORT_SELECTOR, &[0x44; 32])
    );
}

#[test]
fn fixed_port_collision_observation_binds_exact_errno_and_selector() {
    assert_eq!(
        PORT_COLLISION_SELECTOR,
        "private_tcp::port_collision_same_namespace"
    );
    let bytes = expected_port_collision_errno_bytes();
    assert_eq!(i32::from_le_bytes(bytes), libc::EADDRINUSE);
    let output = candidate_fixture_output(PORT_COLLISION_SELECTOR, &[0x45; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + bytes.len());
    assert_eq!(&output[output.len() - bytes.len()..], bytes);
    assert_ne!(output, candidate_fixture_output(SELECTOR, &[0x45; 32]));
}
