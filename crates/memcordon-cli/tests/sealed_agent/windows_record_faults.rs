use super::*;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};

const CHILD_FIXTURE: &str = "windows::record::record_fault_tests::native_lifetime_child";

struct ChildLifetime(Child);

impl Drop for ChildLifetime {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn lifetime_child() -> ChildLifetime {
    ChildLifetime(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_FIXTURE, "--ignored", "--nocapture"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

#[test]
#[ignore = "guardian runtime subprocess fixture with explicitly duplicated capabilities"]
fn native_guardian_runtime_child() {
    let handles: [u64; 5] = serde_json::from_reader(std::io::stdin()).unwrap();
    let [job, frontend, worker, disarm, ready] = handles.map(|handle| {
        super::super::pipe::OwnedHandle::new(usize::try_from(handle).unwrap() as _).unwrap()
    });
    let mut inside = 0;
    assert_ne!(
        unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                windows_sys::Win32::System::Threading::GetCurrentProcess(),
                job.raw(),
                &raw mut inside,
            )
        },
        0
    );
    assert_eq!(inside, 0);
    assert_ne!(
        unsafe { windows_sys::Win32::System::Threading::SetEvent(ready.raw()) },
        0
    );
    super::super::guardian::wait_authority_and_cleanup(
        &job,
        &frontend,
        &worker,
        &disarm,
        None,
        Duration::from_secs(5),
    )
    .unwrap();
}

fn runtime_guardian(
    job: &super::super::job::Job,
    worker: &ChildLifetime,
) -> (ChildLifetime, super::super::pipe::OwnedHandle) {
    use windows_sys::Win32::Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, WaitForSingleObject,
    };
    let private_event = || {
        super::super::pipe::OwnedHandle::new(unsafe {
            CreateEventW(std::ptr::null(), 1, 0, std::ptr::null())
        })
        .unwrap()
    };
    let disarm = private_event();
    let ready = private_event();
    let mut guardian = ChildLifetime(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows::record::record_fault_tests::native_guardian_runtime_child",
                "--ignored",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let handles = [
        job.handle(),
        unsafe { GetCurrentProcess() },
        worker.0.as_raw_handle(),
        disarm.raw(),
        ready.raw(),
    ]
    .map(|handle| {
        let mut remote = std::ptr::null_mut();
        assert_ne!(
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    handle,
                    guardian.0.as_raw_handle(),
                    &raw mut remote,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            },
            0
        );
        remote as usize as u64
    });
    serde_json::to_writer(guardian.0.stdin.as_mut().unwrap(), &handles).unwrap();
    drop(guardian.0.stdin.take());
    assert_eq!(
        unsafe { WaitForSingleObject(ready.raw(), 10_000) },
        WAIT_OBJECT_0
    );
    (guardian, disarm)
}

#[test]
#[ignore = "subprocess fixture invoked with a private stdin control pipe"]
fn native_lifetime_child() {
    let mut command = [0_u8; 1];
    std::io::stdin().read_exact(&mut command).unwrap();
    let _descendant = (command[0] == b'D').then(lifetime_child);
    let _ = std::io::stdin().read_exact(&mut command);
}

#[test]
#[ignore = "crash fixture invoked with a private stdin control pipe"]
fn native_publication_crash_child() {
    let (path, after_rename): (PathBuf, bool) = serde_json::from_reader(std::io::stdin()).unwrap();
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&read_record_bounded(&path).unwrap()).unwrap();
    let expected = record.record_revision;
    record.record_revision += 1;
    record
        .publish_at(&path, expected, |phase| {
            if phase
                == if after_rename {
                    PublicationPhase::AfterRename
                } else {
                    PublicationPhase::Rename
                }
            {
                std::process::exit(73);
            }
            Ok(())
        })
        .unwrap();
    panic!("crash checkpoint was not reached");
}

#[test]
fn native_publisher_process_exit_preserves_atomic_old_or_new_record() {
    for after_rename in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.json");
        let mut record = observed_record();
        record.publish_at(&path, 0, |_| Ok(())).unwrap();
        let mut publisher = ChildLifetime(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows::record::record_fault_tests::native_publication_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        serde_json::to_writer(publisher.0.stdin.as_mut().unwrap(), &(&path, after_rename)).unwrap();
        drop(publisher.0.stdin.take());
        assert_eq!(publisher.0.wait().unwrap().code(), Some(73));
        let retained: WindowsAttemptRecordV1 =
            serde_json::from_slice(&read_record_bounded(&path).unwrap()).unwrap();
        authenticate(&retained, &retained.attempt_id).unwrap();
        assert_eq!(retained.record_revision, if after_rename { 2 } else { 1 });
        assert_eq!(
            retained.causal_diagnostics.original,
            record.causal_diagnostics.original
        );
        assert_eq!(record.record_revision, 1);
    }
}

fn observed_record() -> WindowsAttemptRecordV1 {
    let digest = "19".repeat(32);
    let mut record = WindowsAttemptRecordV1::new(
        digest.clone(),
        digest.clone(),
        WindowsProcessIdentityV1 {
            process_id: 1,
            creation_time_100ns: 1,
        },
        digest.clone(),
        digest,
    )
    .unwrap();
    record.record_revision = 1;
    record
        .causal_diagnostics
        .observe(memcordon_core::CausalEventV1 {
            sequence: 0,
            origin: memcordon_core::DiagnosticOriginV1::Launcher,
            category: memcordon_core::FailureCategoryV1::Monitor,
            operation: memcordon_core::FailureOperationV1::ObserveProcessIdentity,
            code: memcordon_core::FailureCodeV1::ProcessInventoryObservation,
            native_code: Some(memcordon_core::NativeFailureCodeV1::Win32(1234)),
            observed_phase: memcordon_core::AttemptObservationPhaseV1::Monitoring,
            safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    record
}

#[test]
fn native_publication_fault_matrix_preserves_original_and_honest_commit_boundary() {
    for phase in [
        PublicationPhase::ReadPrevious,
        PublicationPhase::Serialize,
        PublicationPhase::CreateStaging,
        PublicationPhase::WritePrefix,
        PublicationPhase::WriteRemainder,
        PublicationPhase::Flush,
        PublicationPhase::Rename,
        PublicationPhase::AfterRename,
        PublicationPhase::Readback,
    ] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.json");
        let mut committed = observed_record();
        committed.publish_at(&path, 0, |_| Ok(())).unwrap();
        let before = read_record_bounded(&path).unwrap();
        let original = committed.causal_diagnostics.original.clone();
        let mut candidate = committed.clone();
        candidate.record_revision += 1;
        let result = candidate.publish_at(&path, 1, |observed| {
            if observed == phase {
                Err(format!("injected native publication failure: {phase:?}"))
            } else {
                Ok(())
            }
        });
        assert!(result.is_err(), "fault {phase:?} did not fail");
        let after = read_record_bounded(&path).unwrap();
        let retained: WindowsAttemptRecordV1 = serde_json::from_slice(&after).unwrap();
        authenticate(&retained, &retained.attempt_id).unwrap();
        assert_eq!(retained.causal_diagnostics.original, original);
        if matches!(
            phase,
            PublicationPhase::AfterRename | PublicationPhase::Readback
        ) {
            assert_eq!(retained.record_revision, 2);
        } else {
            assert_eq!(
                after, before,
                "uncommitted fault {phase:?} changed authority"
            );
        }
        assert_eq!(
            committed.record_revision, 1,
            "unconfirmed publication changed caller acknowledgment"
        );
    }
}

#[test]
fn stale_revision_original_replacement_and_staging_collision_never_publish() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    let mut record = observed_record();
    record.publish_at(&path, 0, |_| Ok(())).unwrap();
    let before = read_record_bounded(&path).unwrap();
    let mut stale = record.clone();
    stale.record_revision = 2;
    assert!(stale.publish_at(&path, 0, |_| Ok(())).is_err());
    let mut replacement = stale.clone();
    replacement.causal_diagnostics.original = memcordon_core::OriginalFailureV1::Unavailable {
        reason: memcordon_core::OriginalUnavailableReasonV1::RecordUnavailable,
    };
    assert!(replacement.publish_at(&path, 1, |_| Ok(())).is_err());
    let staged = path.with_extension("json.new");
    fs::create_dir(&staged).unwrap();
    assert!(stale.publish_at(&path, 1, |_| Ok(())).is_err());
    assert_eq!(read_record_bounded(&path).unwrap(), before);
}

#[test]
fn native_rename_sharing_failure_retains_typed_code_and_original() {
    use std::os::windows::fs::OpenOptionsExt;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    let mut committed = observed_record();
    committed.publish_at(&path, 0, |_| Ok(())).unwrap();
    let before = read_record_bounded(&path).unwrap();
    let _capture = super::super::diagnostics::AttemptDiagnosticScope::enter();
    let mut journal = committed.causal_diagnostics.clone();
    let protected = fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)
        .unwrap();
    let mut candidate = committed.clone();
    candidate.record_revision += 1;
    assert!(candidate.publish_at(&path, 1, |_| Ok(())).is_err());
    let mut source = memcordon_core::WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut source);
    let memcordon_core::OriginalFailureV1::Observed { event } = source.original else {
        panic!("native rename cause not captured");
    };
    assert_eq!(
        event.native_code,
        Some(memcordon_core::NativeFailureCodeV1::Win32(32))
    );
    assert_eq!(
        event.origin,
        memcordon_core::DiagnosticOriginV1::RecordWriter
    );
    journal.observe_secondary(event).unwrap();
    assert_eq!(journal.original, committed.causal_diagnostics.original);
    drop(protected);
    assert_eq!(read_record_bounded(&path).unwrap(), before);
}

#[test]
fn both_native_disk_full_codes_are_captured_before_formatting() {
    for code in [39, 112] {
        let _capture = super::super::diagnostics::AttemptDiagnosticScope::enter();
        let _message = publication_io_error(io::Error::from_raw_os_error(code));
        unsafe {
            windows_sys::Win32::Foundation::SetLastError(5);
        }
        let mut journal = memcordon_core::WindowsCausalDiagnosticsV1::default();
        super::super::diagnostics::merge_into(&mut journal);
        let memcordon_core::OriginalFailureV1::Observed { event } = journal.original else {
            panic!("native persistence cause not captured");
        };
        assert_eq!(
            event.native_code,
            Some(memcordon_core::NativeFailureCodeV1::Win32(code as u32))
        );
        assert_eq!(
            event.category,
            memcordon_core::FailureCategoryV1::Persistence
        );
    }
}

#[test]
fn frozen_native_publication_does_not_own_workload_job_cleanup() {
    for guardian_cleanup in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.json");
        let mut record = observed_record();
        let cleanup_record = record.clone();
        let attempt_id = record.attempt_id.clone();
        let cleanup_path = path.clone();
        let lane = super::super::attempt_store::test_publisher_lane(
            &attempt_id,
            move |record, revision| {
                let _publication_owner =
                    super::super::attempt_store::PublicationGuard::acquire(&record.attempt_id)?;
                record.publish_at(&cleanup_path, revision, |_| Ok(()))
            },
        )
        .unwrap();
        let (frozen, wait_frozen) = std::sync::mpsc::sync_channel(1);
        let (release, wait_release) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _publication_owner =
                super::super::attempt_store::PublicationGuard::acquire(&record.attempt_id).unwrap();
            record.publish_at(&path, 0, |phase| {
                if phase == PublicationPhase::Flush {
                    frozen.send(()).unwrap();
                    wait_release.recv_timeout(Duration::from_secs(60)).unwrap();
                }
                Ok(())
            })
        });
        wait_frozen.recv_timeout(Duration::from_secs(10)).unwrap();
        let job = super::super::job::Job::create_nested_canary(None).unwrap();
        let mut target = lifetime_child();
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::JobObjects::AssignProcessToJobObject(
                    job.handle(),
                    target.0.as_raw_handle(),
                )
            },
            0
        );
        target.0.stdin.as_mut().unwrap().write_all(b"D").unwrap();
        let live_deadline = Instant::now() + Duration::from_secs(10);
        while job.active_processes_observed().unwrap() != 2 {
            assert!(
                Instant::now() < live_deadline,
                "target descendant did not enter workload Job"
            );
            std::thread::yield_now();
        }
        let mut worker_authority = lifetime_child();
        let (mut guardian, disarm) = runtime_guardian(&job, &worker_authority);
        assert!(guardian.0.try_wait().unwrap().is_none());
        if guardian_cleanup {
            worker_authority.0.kill().unwrap();
            worker_authority.0.wait().unwrap();
        } else {
            let started = Instant::now();
            super::super::launcher_service::drop_attempt_cleanup_for_test(
                &job,
                disarm.raw(),
                guardian.0.as_raw_handle(),
                cleanup_record,
            );
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "production cleanup waited for the frozen publication lane"
            );
        }
        assert!(
            job.wait_empty_observed(Instant::now() + Duration::from_secs(5))
                .unwrap()
        );
        assert!(target.0.wait().unwrap().code().is_some());
        if !guardian_cleanup {
            assert_ne!(
                unsafe { windows_sys::Win32::System::Threading::SetEvent(disarm.raw()) },
                0
            );
        }
        let guardian_deadline = Instant::now() + Duration::from_secs(10);
        while guardian.0.try_wait().unwrap().is_none() {
            assert!(
                Instant::now() < guardian_deadline,
                "guardian did not retire while writer was frozen"
            );
            std::thread::yield_now();
        }
        assert!(
            !worker.is_finished(),
            "writer was not still frozen during Job cleanup"
        );
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        lane.finish().unwrap();
    }
}
