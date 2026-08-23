#![cfg(target_os = "linux")]

mod support;

use std::os::fd::{FromRawFd, OwnedFd};
use std::time::Instant;

use memcordon_sealed_agent::request::Lifetime;

#[test]
fn sealed_faults_before_authorization_never_create_marker() {
    let marker = std::path::Path::new("/tmp/memcordon-sealed-preauthorization-marker");
    let _ = std::fs::remove_file(marker);
    let request = support::request("exit", Lifetime::Command);
    let error = memcordon_sealed_agent::linux::launch::execute(
        request,
        Vec::new(),
        [0xb1; 16],
        unsafe { libc::getpid() },
        65_534,
        65_534,
        Vec::new(),
    )
    .expect_err("descriptor fault must fail before authorization");
    assert!(error.starts_with("MCSEALED-DESCRIPTOR-SET:"));
    assert!(!marker.exists());
}

fn fake_cgroup(identity: &str, populated: bool) -> tempfile::TempDir {
    let directory = tempfile::TempDir::new().unwrap();
    std::fs::write(directory.path().join("cgroup.kill"), b"").unwrap();
    std::fs::write(
        directory.path().join("cgroup.events"),
        if populated {
            b"populated 1\n"
        } else {
            b"populated 0\n"
        },
    )
    .unwrap();
    let _ = identity;
    directory
}

#[test]
fn sealed_cgroup_kill_failure_never_reports_retirement() {
    let directory = tempfile::TempDir::new().unwrap();
    std::fs::write(directory.path().join("cgroup.events"), b"populated 0\n").unwrap();
    let error = memcordon_sealed_agent::linux::cgroup::AttemptCgroup::authenticated(
        directory.path().to_path_buf(),
    )
    .kill_and_retire(Instant::now())
    .expect_err("missing cgroup.kill must fail retirement");
    assert!(error.contains("CGROUP"));
}

#[test]
fn sealed_persistent_populated_state_blocks_restart() {
    let directory = fake_cgroup("persistent", true);
    let error = memcordon_sealed_agent::linux::cgroup::AttemptCgroup::authenticated(
        directory.path().to_path_buf(),
    )
    .kill_and_retire(Instant::now())
    .expect_err("populated cgroup must not retire");
    assert!(error.starts_with("MCSEALED-CGROUP-NOT-EMPTY:"));
}

#[test]
fn sealed_namespace_init_reap_delay_blocks_result() {
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        std::thread::sleep(std::time::Duration::from_secs(30));
        unsafe { libc::_exit(0) };
    }
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) } as i32;
    assert!(pidfd >= 0);
    let wait = unsafe { libc::waitpid(child, std::ptr::null_mut(), libc::WNOHANG) };
    assert_eq!(wait, 0, "live namespace init cannot be reported reaped");
    unsafe {
        libc::kill(child, libc::SIGKILL);
        libc::waitpid(child, std::ptr::null_mut(), 0);
        drop(OwnedFd::from_raw_fd(pidfd));
    }
}

#[test]
fn sealed_guardian_reap_failure_blocks_result() {
    let facts = support::execute("child", Lifetime::Command).unwrap();
    assert!(
        facts.guardian_reaped,
        "terminal receipt requires guardian reap"
    );
    support::assert_retired(&facts);
}
