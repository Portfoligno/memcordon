#![cfg(target_os = "linux")]

use crate::linux::cgroup::AttemptCgroup;
use crate::linux::private_guardian::{GuardianTerminalV4, GuardianTriggerV4, PrivateGuardian};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[test]
fn private_guardian_terminal_is_exact_and_cannot_claim_cleanup_on_stop() {
    let attempt_id = [7; 16];
    let claim = GuardianTerminalV4 {
        attempt_id,
        trigger: GuardianTriggerV4::FrontendLost,
        boundary_retired: true,
    };
    let bytes = claim.encode();
    assert_eq!(
        GuardianTerminalV4::decode(bytes, attempt_id).unwrap(),
        claim
    );
    assert!(GuardianTerminalV4::decode(bytes, [8; 16]).is_err());
    let mut changed = bytes;
    changed[19] = 1;
    assert!(GuardianTerminalV4::decode(changed, attempt_id).is_err());
    let mut changed = bytes;
    changed[17] = 1;
    assert!(GuardianTerminalV4::decode(changed, attempt_id).is_err());
    let mut changed = bytes;
    changed[18] = 2;
    assert!(GuardianTerminalV4::decode(changed, attempt_id).is_err());
}

#[test]
fn private_guardian_stops_and_is_reaped_without_claiming_boundary_cleanup() {
    let pid = std::process::id() as libc::pid_t;
    // SAFETY: pidfd_open receives this process's live PID and zero flags.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: successful pidfd_open transfers an owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let worker_pidfd = pidfd.try_clone().unwrap();
    let init_pidfd = pidfd.try_clone().unwrap();
    let root = TempDir::new().unwrap();
    let cgroup = AttemptCgroup::authenticated(root.path().join("test-guardian"));
    let attempt_id = [9; 16];
    let guardian = PrivateGuardian::spawn(
        attempt_id,
        pidfd.as_fd(),
        worker_pidfd.as_fd(),
        init_pidfd.as_fd(),
        cgroup,
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap();
    assert!(guardian.is_live());
    let terminal = guardian
        .stop(Instant::now() + Duration::from_secs(5))
        .unwrap();
    assert_eq!(terminal.attempt_id, attempt_id);
    assert_eq!(terminal.trigger, GuardianTriggerV4::Stopped);
    assert!(!terminal.boundary_retired);
}
