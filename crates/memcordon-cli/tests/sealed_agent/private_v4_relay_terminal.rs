#![cfg(target_os = "linux")]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::Duration;

use crate::linux::descriptor_custody::provider_owned_byte_pipes;
use crate::linux::private_execution::validate_broker_rejection;
use crate::linux::private_lifecycle::{PrivateCandidateTerminalV4, PrivateMonitorOutcome};
use crate::linux::private_relay::PrivateRelay;

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [-1_i32; 2];
    // SAFETY: successful pipe2 initializes two distinct owned descriptors.
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
        0
    );
    // SAFETY: both descriptors are uniquely owned after successful pipe2.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn write_bytes(fd: BorrowedFd<'_>, bytes: &[u8]) -> isize {
    // SAFETY: the live descriptor reads only the provided initialized bytes.
    unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) }
}

fn read_bytes(fd: BorrowedFd<'_>, bytes: &mut [u8]) -> isize {
    // SAFETY: the live descriptor writes no more than the provided capacity.
    unsafe { libc::read(fd.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) }
}

#[test]
fn private_relay_preserves_byte_directions_and_observes_all_eofs() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    let (stdin_read, stdin_write) = pipe();
    let (stdout_read, stdout_write) = pipe();
    let (stderr_read, stderr_write) = pipe();
    let mut relay =
        PrivateRelay::prepare(provider, [stdin_read, stdout_write, stderr_write]).unwrap();

    assert_eq!(write_bytes(stdin_write.as_fd(), b"input"), 5);
    assert_eq!(write_bytes(target.stdout_fd(), b"output"), 6);
    assert_eq!(write_bytes(target.stderr_fd(), b"error"), 5);
    drop(stdin_write);
    for _ in 0..16 {
        relay.tick(Duration::ZERO).unwrap();
    }
    let mut input = [0_u8; 5];
    assert_eq!(read_bytes(target.stdin_fd(), &mut input), 5);
    assert_eq!(&input, b"input");
    let mut output = [0_u8; 6];
    assert_eq!(read_bytes(stdout_read.as_fd(), &mut output), 6);
    assert_eq!(&output, b"output");
    let mut error = [0_u8; 5];
    assert_eq!(read_bytes(stderr_read.as_fd(), &mut error), 5);
    assert_eq!(&error, b"error");
    assert!(
        !relay.completed(),
        "live target writers are not terminal EOF"
    );
    drop(target);
    for _ in 0..16 {
        relay.tick(Duration::ZERO).unwrap();
        if relay.completed() {
            break;
        }
    }
    assert!(relay.completed());
    assert_eq!(read_bytes(stdout_read.as_fd(), &mut output), 0);
    assert_eq!(read_bytes(stderr_read.as_fd(), &mut error), 0);
}

#[test]
fn private_relay_rejects_wrong_direction_and_blocking_frontend() {
    let (_target, provider) = provider_owned_byte_pipes().unwrap();
    let (_stdin_read, stdin_write) = pipe();
    let (_stdout_read, stdout_write) = pipe();
    let (_stderr_read, stderr_write) = pipe();
    assert!(
        PrivateRelay::prepare(provider, [stdin_write, stdout_write, stderr_write]).is_err(),
        "frontend stdin must be readable"
    );

    let (_target, provider) = provider_owned_byte_pipes().unwrap();
    let (stdin_read, _stdin_write) = pipe();
    let (stdout_read, _stdout_write) = pipe();
    let (_stderr_read, stderr_write) = pipe();
    assert!(
        PrivateRelay::prepare(provider, [stdin_read, stdout_read, stderr_write]).is_err(),
        "frontend stdout must be writable"
    );

    let (_target, provider) = provider_owned_byte_pipes().unwrap();
    let (stdin_read, _stdin_write) = pipe();
    let (_stdout_read, stdout_write) = pipe();
    let (_stderr_read, stderr_write) = pipe();
    // SAFETY: F_GETFL reads live descriptor flags, then F_SETFL removes only
    // nonblocking from the test-owned frontend pipe description.
    let flags = unsafe { libc::fcntl(stdin_read.as_raw_fd(), libc::F_GETFL) };
    assert_ne!(flags, -1);
    assert_eq!(
        unsafe {
            libc::fcntl(
                stdin_read.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            )
        },
        0
    );
    assert!(
        PrivateRelay::prepare(provider, [stdin_read, stdout_write, stderr_write]).is_err(),
        "blocking frontend would stall cancellation"
    );

    let (_target, provider) = provider_owned_byte_pipes().unwrap();
    let (stdin_read, _stdin_write) = pipe();
    let (_stdout_read, stdout_write) = pipe();
    let file = tempfile::tempfile().unwrap();
    assert!(
        PrivateRelay::prepare(provider, [stdin_read, stdout_write, file.into()]).is_err(),
        "a regular file cannot replace a frontend byte stream"
    );
}

#[test]
fn private_relay_backpressure_is_bounded_and_target_exit_closes_stdin() {
    let (target, provider) = provider_owned_byte_pipes().unwrap();
    let (stdin_read, stdin_write) = pipe();
    let (_stdout_read, stdout_write) = pipe();
    let (_stderr_read, stderr_write) = pipe();
    let mut relay =
        PrivateRelay::prepare(provider, [stdin_read, stdout_write, stderr_write]).unwrap();
    let chunk = [42_u8; 8192];
    for _ in 0..64 {
        let written = write_bytes(stdin_write.as_fd(), &chunk);
        if written == -1 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            break;
        }
        assert!(written > 0);
    }
    for _ in 0..16 {
        relay.tick(Duration::ZERO).unwrap();
    }
    assert!(!relay.completed(), "backpressure must not fabricate EOF");
    relay.close_stdin_after_target_exit();
    drop(target);
    drop(stdin_write);
    for _ in 0..16 {
        relay.tick(Duration::ZERO).unwrap();
        if relay.completed() {
            break;
        }
    }
    assert!(
        relay.completed(),
        "target exit cancels a blocked stdin relay"
    );
}

#[test]
fn private_terminal_candidate_outcomes_remain_distinct() {
    let native_failure = PrivateCandidateTerminalV4::NativeFailure {
        phase: 7,
        detail: "exec failed".into(),
    };
    let interrupted = PrivateCandidateTerminalV4::Interrupted {
        reason: PrivateMonitorOutcome::FrontendLost,
    };
    let exited = PrivateCandidateTerminalV4::Exited { code: 0 };
    let native = serde_json::to_value(native_failure).unwrap();
    let loss = serde_json::to_value(interrupted).unwrap();
    let success_candidate = serde_json::to_value(exited).unwrap();
    assert_eq!(native["kind"], "native-failure");
    assert_eq!(loss["kind"], "interrupted");
    assert_eq!(loss["reason"], "frontend-lost");
    assert_eq!(success_candidate["kind"], "exited");
    assert_ne!(native, success_candidate);
    assert_ne!(loss, success_candidate);
}

#[test]
fn private_broker_rejection_requires_exact_attempt_and_consistent_cleanup_knowledge() {
    let attempt = [0x11; 16];
    let valid = serde_json::json!({
        "schema_version": 4,
        "attempt_id": "11111111111111111111111111111111",
        "code": "MCSEALED-NETWORK-LAUNCHER-PRE-RELEASE-REJECTED",
        "detail": "setup failed",
        "possibly_released": false,
        "cleanup_complete": true
    });
    let encoded = serde_json::to_vec(&valid).unwrap();
    assert!(validate_broker_rejection(&encoded, attempt).is_ok());
    let mut released = valid.clone();
    released["possibly_released"] = true.into();
    released["cleanup_complete"] = false.into();
    released["code"] = "MCSEALED-NETWORK-LAUNCHER-POSSIBLY-RELEASED".into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&released).unwrap(), attempt).is_ok());

    let mut changed = valid.clone();
    changed["attempt_id"] = "22222222222222222222222222222222".into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
    let mut changed = valid.clone();
    changed["schema_version"] = 3.into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
    let mut changed = valid.clone();
    changed["code"] = "MCSEALED-NETWORK-LAUNCHER-UNKNOWN".into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
    let mut changed = valid.clone();
    changed["possibly_released"] = true.into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
    let mut changed = valid.clone();
    changed["cleanup_complete"] = false.into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
    let mut changed = valid.clone();
    changed["unexpected"] = true.into();
    assert!(validate_broker_rejection(&serde_json::to_vec(&changed).unwrap(), attempt).is_err());
}
