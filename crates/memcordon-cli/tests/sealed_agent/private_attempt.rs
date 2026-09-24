#![cfg(target_os = "linux")]

use crate::linux::private_attempt::{
    DurablePrivateAttempt, PrivateAttemptPhase, PrivateAttemptRecordV4, ProcessIdentityV4,
    ReleaseKnowledge,
};
use crate::linux::private_lifecycle::PrivateAttemptOwner;
use memcordon_core::{BoundedText, DiagnosticSha256};
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use tempfile::TempDir;

const IDENTITY: &str = "abababababababababababababababab";

fn allocated() -> PrivateAttemptRecordV4 {
    PrivateAttemptRecordV4::allocated(
        BoundedText::new(IDENTITY).unwrap(),
        BoundedText::new("boot-1").unwrap(),
        ProcessIdentityV4 {
            pid: 123,
            start_time: 456,
        },
        DiagnosticSha256::from_bytes([7; 32]),
    )
    .unwrap()
}

#[test]
fn v4_allocated_record_roundtrips_and_recovery_preserves_it() {
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    assert_eq!(durable.read_back().unwrap(), allocated());
    let bytes = std::fs::read(state.path().join(IDENTITY)).unwrap();
    assert!(crate::linux::recovery::integrity_valid(
        std::str::from_utf8(&bytes).unwrap()
    ));
    assert!(
        crate::linux::attempt::parse_durable_policy(std::str::from_utf8(&bytes).unwrap()).is_err()
    );
    let ambiguous =
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
    assert_eq!(ambiguous, vec![IDENTITY.to_owned()]);
    assert!(state.path().join(IDENTITY).exists());
}

#[test]
fn v4_parser_rejects_corruption_and_unearned_release_claims() {
    let state = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    let mut bytes = std::fs::read(state.path().join(IDENTITY)).unwrap();
    bytes[15] ^= 1;
    assert!(PrivateAttemptRecordV4::parse(&bytes).is_err());
    assert!(durable.read_back().is_ok());

    let record = std::fs::read_to_string(state.path().join(IDENTITY)).unwrap();
    let (body, _) = record.rsplit_once("digest=").unwrap();
    let changed = body.replace("\"phase\":\"allocated\"", "\"phase\":\"release-intent\"");
    assert_ne!(changed, body);
    let digest: String = memcordon_core::workload_codec::hash_bytes(changed.as_bytes()).into();
    assert!(
        PrivateAttemptRecordV4::parse(format!("{changed}digest={digest}\n").as_bytes()).is_err()
    );

    let changed = body.replace("\"phase\":\"allocated\"", "\"phase\":\"future-phase\"");
    assert_ne!(changed, body);
    let digest: String = memcordon_core::workload_codec::hash_bytes(changed.as_bytes()).into();
    assert!(
        PrivateAttemptRecordV4::parse(format!("{changed}digest={digest}\n").as_bytes()).is_err()
    );

    let mut forged = allocated();
    forged.phase = PrivateAttemptPhase::ReleaseIntent;
    forged.release_knowledge = ReleaseKnowledge::PossiblyReleased;
    assert!(forged.validate().is_err());
    let mut forged = allocated();
    forged.phase = PrivateAttemptPhase::CleanupIncomplete;
    assert!(forged.validate().is_err());
    let mut forged = allocated();
    forged.frontend.start_time = 0;
    assert!(forged.validate().is_err());
}

#[test]
fn v4_interrupted_transition_remains_ambiguous_and_is_not_deleted() {
    let state = TempDir::new().unwrap();
    let cgroup = TempDir::new().unwrap();
    let _durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    let canonical = state.path().join(IDENTITY);
    let temporary = canonical.with_extension("new");
    std::fs::copy(&canonical, &temporary).unwrap();
    let ambiguous =
        crate::linux::recovery::recover_test_roots(state.path(), cgroup.path()).unwrap();
    assert!(ambiguous.contains(&IDENTITY.to_owned()));
    assert!(ambiguous.contains(&format!("{IDENTITY}.new")));
    assert!(canonical.exists());
    assert!(temporary.exists());
}

#[test]
fn v4_process_identity_requires_the_exact_live_pidfd() {
    let pid = std::process::id() as libc::pid_t;
    // SAFETY: pidfd_open receives this process's live PID and zero flags.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    // SAFETY: a successful pidfd_open returns a fresh owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity = ProcessIdentityV4::observe(pid, pidfd.as_fd()).unwrap();
    assert_eq!(identity.pid, pid as u32);
    assert!(ProcessIdentityV4::observe(pid + 1, pidfd.as_fd()).is_err());
}

#[test]
fn private_owner_refuses_unfrozen_authority_without_erasing_record() {
    let state = TempDir::new().unwrap();
    let durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    assert!(PrivateAttemptOwner::new(durable).is_err());
    assert!(state.path().join(IDENTITY).exists());
}

#[test]
fn v4_early_retirement_is_only_available_before_native_boundary() {
    let state = TempDir::new().unwrap();
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    assert!(durable.boundary_created().is_err());
    durable.retire_unallocated().unwrap();
    assert!(!state.path().join(IDENTITY).exists());
}

#[test]
fn v4_cleanup_failure_stays_durable_and_blocks_release() {
    let state = TempDir::new().unwrap();
    let mut durable = DurablePrivateAttempt::create_for_test(state.path(), allocated()).unwrap();
    durable.cleanup_incomplete("native cleanup failed").unwrap();
    let persisted = durable.read_back().unwrap();
    assert_eq!(persisted.phase, PrivateAttemptPhase::CleanupIncomplete);
    assert_eq!(persisted.release_knowledge, ReleaseKnowledge::NotReleased);
    assert!(durable.boundary_created().is_err());
    assert!(state.path().join(IDENTITY).exists());
}
