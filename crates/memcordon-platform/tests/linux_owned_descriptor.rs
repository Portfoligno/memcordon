#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

#[test]
fn checked_close_delivers_native_eof_for_the_exact_owned_endpoint() {
    let (mut sender, mut receiver) = UnixStream::pair().unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    sender.write_all(b"owned-close").unwrap();
    memcordon_platform::linux_checked_close(OwnedFd::from(sender)).unwrap();
    let mut observed = Vec::new();
    receiver.read_to_end(&mut observed).unwrap();
    assert_eq!(observed, b"owned-close");
}

#[test]
fn cgroup_retirement_refuses_live_and_unlinked_non_cgroup_directories() {
    let directory = tempfile::tempdir().unwrap();
    let child = directory.path().join("held");
    std::fs::create_dir(&child).unwrap();
    let held = std::fs::File::open(&child).unwrap();
    assert!(memcordon_platform::linux_cgroup_retirement(&held).is_err());
    std::fs::remove_dir(&child).unwrap();
    // A zero-link ordinary inode is not cgroup retirement evidence.
    assert!(memcordon_platform::linux_cgroup_retirement(&held).is_err());
}
