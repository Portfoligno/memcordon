use std::fs;

use memcordon_platform::test_support::ProcessIdentity;

#[cfg(windows)]
#[test]
#[ignore = "child fixture selected explicitly by windows_held_identity_observes_original_process_retirement"]
fn windows_held_identity_child_fixture() {
    std::thread::sleep(std::time::Duration::from_secs(30));
}

#[cfg(windows)]
#[test]
fn windows_held_identity_observes_original_process_retirement() {
    assert!(
        memcordon_platform::test_support::windows_native_work_cutoff(std::time::Instant::now())
            .is_err()
    );
    let (ticks_before, frequency_before) =
        memcordon_platform::test_support::windows_performance_counter().unwrap();
    let (cutoff, frequency) = memcordon_platform::test_support::windows_native_work_cutoff(
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    let (ticks_after, frequency_after) =
        memcordon_platform::test_support::windows_performance_counter().unwrap();
    assert_eq!(frequency, frequency_before);
    assert_eq!(frequency, frequency_after);
    assert!(cutoff >= ticks_before);
    assert!(cutoff <= ticks_after + frequency * 5);
    struct ChildOwner(std::process::Child);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let image = std::env::current_exe().unwrap();
    let console_path = memcordon_platform::test_support::windows_console_host_path().unwrap();
    assert!(console_path.is_absolute());
    assert_eq!(console_path.file_name().unwrap(), "conhost.exe");
    let image_file = fs::File::open(&image).unwrap();
    let image_identity =
        memcordon_platform::test_support::windows_held_file_identity(&image_file).unwrap();
    assert_eq!(image_identity.length, image_file.metadata().unwrap().len());
    let expired = memcordon_platform::test_support::windows_processes_for_image_until(
        &image,
        std::time::Instant::now(),
    );
    assert!(matches!(expired, Err(error) if error.kind() == std::io::ErrorKind::TimedOut));
    let live = memcordon_platform::test_support::windows_processes_for_image_until(
        &image,
        std::time::Instant::now() + std::time::Duration::from_secs(5),
    )
    .unwrap();
    assert!(live.iter().any(|process| {
        process.identity.pid == std::process::id() && !process.has_exited().unwrap()
    }));
    let mut child = ChildOwner(
        std::process::Command::new(&image)
            .args([
                "--ignored",
                "--exact",
                "windows_held_identity_child_fixture",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
    );
    let held = memcordon_platform::test_support::windows_processes_for_image(&image)
        .unwrap()
        .into_iter()
        .find(|process| process.identity.pid == child.0.id())
        .unwrap();
    assert_ne!(held.identity.birth, 0);
    assert!(!held.has_exited().unwrap());
    let root = memcordon_platform::test_support::windows_processes_for_image(&image)
        .unwrap()
        .into_iter()
        .find(|process| process.identity.pid == std::process::id())
        .unwrap();
    let direct = root
        .direct_children_for_image_until(
            &image,
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert!(
        direct
            .iter()
            .any(|process| process.identity == held.identity)
    );
    assert!(direct.iter().all(|process| {
        process.identity.birth >= root.identity.birth
            && process.native_parent_process_id().unwrap() == root.identity.pid
            && process.identity != root.identity
    }));
    let diagnostic = root
        .diagnose_unheld_direct_children(
            &[root.identity],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert_eq!(diagnostic["accepted_family_modified"], false);
    assert_eq!(diagnostic["job_membership_established"], false);
    let observed = diagnostic["records"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["snapshot_pid"] == child.0.id())
        .unwrap();
    assert_eq!(
        observed["birth"].as_u64().map(u128::from),
        Some(held.identity.birth)
    );
    assert_eq!(observed["native_parent_pid"], root.identity.pid);
    assert!(!observed["image_utf16"].as_array().unwrap().is_empty());
    let known = root
        .diagnose_unheld_direct_children(
            &[root.identity, held.identity],
            std::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .unwrap();
    assert!(
        known["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record["snapshot_pid"] != child.0.id())
    );
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(held.has_exited().unwrap());
    // The held native object remains observable after process-table retirement.
    assert!(held.has_exited().unwrap());
    let remaining = memcordon_platform::test_support::windows_processes_for_image(&image).unwrap();
    for process in remaining
        .iter()
        .filter(|process| process.identity == held.identity)
    {
        assert!(process.has_exited().unwrap());
    }
    // The census must still acquire the genuinely live original test process.
    assert!(
        remaining
            .iter()
            .any(|process| process.identity.pid == std::process::id())
    );
}

#[cfg(all(unix, not(target_os = "macos")))]
use memcordon_platform::test_support::unix_session_member_from_stat;

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

#[cfg(all(unix, not(target_os = "macos")))]
#[test]
fn unix_session_scan_continues_after_a_process_disappears() {
    let session = 41;
    assert_eq!(
        unix_session_member_from_stat(
            session,
            90,
            Err(std::io::Error::from_raw_os_error(libc::ESRCH)),
        )
        .unwrap(),
        None
    );
    assert_eq!(
        unix_session_member_from_stat(session, 91, Ok("91 (fixture) S 1 1 41".to_owned()),)
            .unwrap(),
        Some(91)
    );
    let error = unix_session_member_from_stat(
        session,
        92,
        Err(std::io::Error::from_raw_os_error(libc::EACCES)),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
}

#[cfg(target_os = "linux")]
#[test]
fn sealed_attempt_deadline_uses_the_full_budget_for_each_attempt() {
    let mut policy = Policy::unbounded();
    policy.deadline =
        Some(DeadlinePolicy::new(Duration::from_secs(30), DeadlineScope::Attempt).unwrap());
    let context = AttemptContext {
        macos_run_origin_ns: None,
        macos_work_expires_ns: None,
        restart_attempt: 0,
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
        macos_run_origin_ns: None,
        macos_work_expires_ns: None,
        restart_attempt: 0,
        supervision_offset: Duration::ZERO,
        supervision_deadline_remaining: None,
    };
    let retry = AttemptContext {
        macos_run_origin_ns: None,
        macos_work_expires_ns: None,
        restart_attempt: 1,
        supervision_offset: Duration::from_secs(25),
        supervision_deadline_remaining: Some(Duration::from_secs(5)),
    };
    let expired_retry = AttemptContext {
        macos_run_origin_ns: None,
        macos_work_expires_ns: None,
        restart_attempt: 2,
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
