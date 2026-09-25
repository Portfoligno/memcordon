#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::time::{Duration, Instant};

use crate::linux::private_probe_loss::{FrontendProxy, armed_response};

#[test]
fn armed_response_is_challenge_bound() {
    let left = [7_u8; 32];
    let right = [8_u8; 32];
    assert_ne!(armed_response(&left), armed_response(&right));
    assert_ne!(armed_response(&left), left);
}

#[test]
fn real_relay_frontend_is_killed_and_reaped_by_its_pidfd() {
    let challenge = [19_u8; 32];
    let mut proxy = FrontendProxy::spawn().unwrap();
    let identity = proxy.identity().clone();
    let [stdin_read, stdout_write, stderr_write] = proxy.take_relay().unwrap();
    assert!(proxy.take_relay().is_err());
    proxy.start(challenge).unwrap();
    let mut observed = [0_u8; 32];
    let stdin_read = blocking(stdin_read);
    let mut stdin = std::fs::File::from(stdin_read);
    stdin.read_exact(&mut observed).unwrap();
    assert_eq!(observed, challenge);
    let stdout_write = blocking(stdout_write);
    let mut stdout = std::fs::File::from(stdout_write);
    stdout.write_all(&armed_response(&challenge)).unwrap();
    proxy
        .wait_armed(
            armed_response(&challenge),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    assert_eq!(proxy.identity(), &identity);
    proxy.signal_loss().unwrap();
    proxy
        .reap_after_loss(Instant::now() + Duration::from_secs(3))
        .unwrap();
    drop(stderr_write);
}

#[test]
fn guardian_case_can_stop_its_still_live_frontend() {
    let challenge = [23_u8; 32];
    let mut proxy = FrontendProxy::spawn().unwrap();
    let [stdin_read, stdout_write, stderr_write] = proxy.take_relay().unwrap();
    proxy.start(challenge).unwrap();
    let stdin_read = blocking(stdin_read);
    let mut stdin = std::fs::File::from(stdin_read);
    let mut observed = [0_u8; 32];
    stdin.read_exact(&mut observed).unwrap();
    assert_eq!(observed, challenge);
    let stdout_write = blocking(stdout_write);
    let mut stdout = std::fs::File::from(stdout_write);
    stdout.write_all(&armed_response(&challenge)).unwrap();
    proxy
        .wait_armed(
            armed_response(&challenge),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
    proxy.stop(Instant::now() + Duration::from_secs(3)).unwrap();
    drop(stderr_write);
}

fn blocking(fd: OwnedFd) -> OwnedFd {
    // SAFETY: F_GETFL/F_SETFL change only this pipe end's open-file status.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
        0
    );
    fd
}
