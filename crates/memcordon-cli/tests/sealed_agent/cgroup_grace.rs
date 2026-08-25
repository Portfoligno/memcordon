#![cfg(all(target_os = "linux", feature = "test-support"))]

use std::fs;
use std::time::{Duration, Instant};

use crate::linux::cgroup::AttemptCgroup;
use crate::request::{DeadlineScope, LaunchPolicyV2, Lifetime, SwapLimit};

fn cgroup(populated: bool) -> (tempfile::TempDir, AttemptCgroup) {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("cgroup.events"),
        format!("populated {}\n", u8::from(populated)),
    )
    .unwrap();
    let cgroup = AttemptCgroup::authenticated(directory.path().to_owned());
    (directory, cgroup)
}

fn command_policy(grace_millis: u64, absolute_deadline_millis: Option<u64>) -> LaunchPolicyV2 {
    LaunchPolicyV2 {
        memory_limit_bytes: None,
        swap_limit: SwapLimit::Bytes(0),
        absolute_deadline_millis,
        deadline_scope: DeadlineScope::Attempt,
        lifetime: Lifetime::Command,
        poll_interval_millis: 5,
        signal_grace_millis: 0,
        command_exit_grace_millis: grace_millis,
        limit_grace_millis: 0,
    }
}

#[test]
fn command_exit_grace_returns_when_cgroup_drains() {
    let (directory, cgroup) = cgroup(true);
    let events = directory.path().join("cgroup.events");
    let updater = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(75));
        let replacement = events.with_extension("events.new");
        fs::write(&replacement, b"populated 0\n").unwrap();
        fs::rename(replacement, events).unwrap();
    });
    let started = Instant::now();
    let deadline_exceeded = crate::linux::launch::wait_command_exit_grace_for_test(
        &cgroup,
        &command_policy(2_000, None),
    )
    .unwrap();
    let elapsed = started.elapsed();
    updater.join().unwrap();
    assert!(!deadline_exceeded);
    assert!(elapsed >= Duration::from_millis(50));
    assert!(elapsed < Duration::from_millis(1_000));
    assert!(
        cgroup
            .wait_until_empty(Instant::now(), Duration::ZERO)
            .unwrap()
    );
}

#[test]
fn attempt_deadline_remains_authoritative_during_command_exit_grace() {
    let (_directory, cgroup) = cgroup(true);
    let deadline = crate::linux::clock::monotonic_millis()
        .unwrap()
        .saturating_add(75);
    let started = Instant::now();
    let deadline_exceeded = crate::linux::launch::wait_command_exit_grace_for_test(
        &cgroup,
        &command_policy(2_000, Some(deadline)),
    )
    .unwrap();
    let elapsed = started.elapsed();
    assert!(deadline_exceeded);
    assert!(elapsed >= Duration::from_millis(50));
    assert!(elapsed < Duration::from_millis(1_000));
}

#[test]
fn command_exit_grace_expiry_is_not_misclassified_as_deadline() {
    let (_directory, cgroup) = cgroup(true);
    let started = Instant::now();
    let deadline_exceeded =
        crate::linux::launch::wait_command_exit_grace_for_test(&cgroup, &command_policy(75, None))
            .unwrap();
    let elapsed = started.elapsed();
    assert!(!deadline_exceeded);
    assert!(elapsed >= Duration::from_millis(50));
    assert!(elapsed < Duration::from_millis(1_000));
}
