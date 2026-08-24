use std::fs;

use memcordon_platform::test_support::ProcessIdentity;

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use memcordon_core::{DeadlinePolicy, DeadlineScope, Policy};

#[cfg(target_os = "linux")]
use memcordon_platform::AttemptContext;

#[test]
fn process_identity_publication_atomically_replaces_destination() {
    let temporary = tempfile::tempdir().expect("temporary directory should exist");
    let path = temporary.path().join("identity.pid");
    fs::write(&path, b"").expect("incomplete destination should write");

    let identity = ProcessIdentity {
        pid: 42,
        birth: 1_234_567_890,
    };
    identity
        .publish_to(&path)
        .expect("process identity should publish");

    assert_eq!(
        fs::read_to_string(&path).expect("published identity should read"),
        "42 1234567890\n"
    );
    let entries: Vec<_> = fs::read_dir(temporary.path())
        .expect("temporary directory should read")
        .collect::<Result<_, _>>()
        .expect("temporary directory entries should read");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].path(), path);
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_attempt_deadline_uses_the_full_budget_for_each_attempt() {
    let mut policy = Policy::unbounded();
    policy.deadline =
        Some(DeadlinePolicy::new(Duration::from_secs(30), DeadlineScope::Attempt).unwrap());
    let context = AttemptContext {
        supervision_offset: Duration::from_secs(25),
        supervision_deadline_remaining: Some(Duration::from_secs(5)),
    };

    assert_eq!(
        memcordon_platform::test_support::linux_sealed_deadline_duration(
            &policy,
            context,
            Duration::from_secs(7),
        ),
        Some(Duration::from_secs(30))
    );
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_supervision_retry_uses_only_the_remaining_budget() {
    let mut policy = Policy::unbounded();
    policy.deadline =
        Some(DeadlinePolicy::new(Duration::from_secs(30), DeadlineScope::Supervision).unwrap());
    let initial = AttemptContext {
        supervision_offset: Duration::ZERO,
        supervision_deadline_remaining: None,
    };
    let retry = AttemptContext {
        supervision_offset: Duration::from_secs(25),
        supervision_deadline_remaining: Some(Duration::from_secs(5)),
    };
    let expired_retry = AttemptContext {
        supervision_offset: Duration::from_secs(30),
        supervision_deadline_remaining: Some(Duration::ZERO),
    };

    assert_eq!(
        memcordon_platform::test_support::linux_sealed_deadline_duration(
            &policy,
            initial,
            Duration::from_secs(7),
        ),
        Some(Duration::from_secs(30))
    );
    assert_eq!(
        memcordon_platform::test_support::linux_sealed_deadline_duration(
            &policy,
            retry,
            Duration::from_secs(2),
        ),
        Some(Duration::from_secs(3))
    );
    assert_eq!(
        memcordon_platform::test_support::linux_sealed_deadline_duration(
            &policy,
            expired_retry,
            Duration::from_secs(2),
        ),
        Some(Duration::ZERO)
    );
}
