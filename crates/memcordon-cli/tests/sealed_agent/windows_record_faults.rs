use super::*;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};

const CHILD_FIXTURE: &str = "windows::record::record_fault_tests::native_lifetime_child";

#[test]
fn publication_mutex_policy_accepts_service_owners_and_rejects_other_accounts() {
    use super::super::security::{SecurityDescriptor, publication_mutex_sddl};

    for owner in ["S-1-5-18", "S-1-5-19"] {
        SecurityDescriptor::from_sddl(&publication_mutex_sddl(owner).unwrap())
            .expect("native parser must accept each explicit service-owner policy");
    }
    for owner in ["S-1-5-32-544", "S-1-5-20", "S-1-1-0", ""] {
        assert!(publication_mutex_sddl(owner).is_err());
    }
}

#[test]
fn publication_mutex_preserves_exclusivity_without_owner_mutation_rights() {
    use super::super::attempt_store::PublicationGuard;
    use windows_sys::Win32::System::Threading::OpenMutexW;

    let attempt = digest(format!("publication-policy-{}", std::process::id()).as_bytes());
    let guard = PublicationGuard::acquire_for_test(&attempt).unwrap();
    let contender = attempt.clone();
    let error = std::thread::spawn(move || {
        PublicationGuard::acquire_for_test(&contender)
            .err()
            .expect("another thread must not acquire the held publication mutex")
    })
    .join()
    .unwrap();
    assert_eq!(error, "attempt publication owner is unavailable");

    let name: Vec<u16> = format!("Global\\MemCordon.Attempt.Writer.{attempt}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: name is terminated and remains live for the native open call.
    let mutation = unsafe { OpenMutexW(0x000c_0000, 0, name.as_ptr()) };
    let error = std::io::Error::last_os_error();
    assert!(
        mutation.is_null(),
        "owner must not receive WRITE_DAC or WRITE_OWNER"
    );
    assert_eq!(error.raw_os_error(), Some(5));
    drop(guard);
    assert!(PublicationGuard::acquire_for_test(&attempt).is_ok());
}

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
    let mut receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_publisher_process_exit_preserves_atomic_old_or_new_record",
    );
    for after_rename in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.json");
        let mut record = observed_record();
        record.publish_at(&path, 0, |_| Ok(())).unwrap();
        let before = read_record_bounded(&path).unwrap();
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
        let mut created = windows_sys::Win32::Foundation::FILETIME::default();
        let mut exited = windows_sys::Win32::Foundation::FILETIME::default();
        let mut kernel = windows_sys::Win32::Foundation::FILETIME::default();
        let mut user = windows_sys::Win32::Foundation::FILETIME::default();
        // SAFETY: Child retains the live process handle until wait completes;
        // all FILETIME outputs are writable and remain live throughout the call.
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::Threading::GetProcessTimes(
                    publisher.0.as_raw_handle(),
                    &mut created,
                    &mut exited,
                    &mut kernel,
                    &mut user,
                )
            },
            0
        );
        let publisher_pid = publisher.0.id();
        let publisher_birth =
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
        serde_json::to_writer(publisher.0.stdin.as_mut().unwrap(), &(&path, after_rename)).unwrap();
        drop(publisher.0.stdin.take());
        assert_eq!(publisher.0.wait().unwrap().code(), Some(73));
        let after = read_record_bounded(&path).unwrap();
        let retained: WindowsAttemptRecordV1 = serde_json::from_slice(&after).unwrap();
        authenticate(&retained, &retained.attempt_id).unwrap();
        assert_eq!(retained.record_revision, if after_rename { 2 } else { 1 });
        assert_eq!(
            retained.causal_diagnostics.original,
            record.causal_diagnostics.original
        );
        assert_eq!(record.record_revision, 1);
        if let Some(receipt) = receipt.as_mut() {
            receipt.record(
                if after_rename {
                    "crash-after-rename"
                } else {
                    "crash-before-rename"
                },
                &before,
                &after,
                &record.causal_diagnostics.original,
                record.record_revision,
                retained.record_revision,
                false,
                None,
            );
            receipt.publisher_process(super::super::readiness_receipt::PublisherProcess {
                process_id: publisher_pid,
                creation_time_100ns: publisher_birth,
                held_before_input_delivery: true,
                exit_status: 73,
                retirement_observed: true,
            });
        }
    }
    if let Some(receipt) = receipt {
        receipt.finish("writer");
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
fn service_and_core_v4_records_use_identical_optional_disposition_bytes() {
    for disposition in [
        None,
        Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort),
    ] {
        let record = WindowsAttemptRecordV1 {
            terminal_disposition: disposition,
            ..observed_record()
        };
        let service = serde_json::to_vec(&record).unwrap();
        let core = serde_json::to_vec(&decoded_v4(&record)).unwrap();
        assert_eq!(service, core);
    }
    let mut preterminal = observed_record();
    preterminal.validate_for_store_for_test().unwrap();
    authenticate(&preterminal, &preterminal.attempt_id).unwrap();
}

#[test]
fn worker_thread_identity_is_in_authenticated_durable_record() {
    let mut record = observed_record();
    record.worker_identity = Some(WindowsProcessIdentityV1 {
        process_id: 42,
        creation_time_100ns: 7,
    });
    record.worker_thread_identity = Some(memcordon_core::WindowsWorkerThreadIdentityV1 {
        thread_id: 43,
        creation_time_100ns: 8,
    });
    record.validate_for_store_for_test().unwrap();
    authenticate(&record, &record.attempt_id).unwrap();
    let decoded: memcordon_core::WindowsDurableAttemptRecordV4 =
        serde_json::from_slice(&canonical_record_bytes(&record).unwrap()).unwrap();
    assert_eq!(
        decoded.worker_thread_identity,
        record.worker_thread_identity
    );
}

#[test]
fn native_publication_fault_matrix_preserves_original_and_honest_commit_boundary() {
    let mut receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_publication_fault_matrix_preserves_original_and_honest_commit_boundary",
    );
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
        if let Some(receipt) = receipt.as_mut() {
            let phase_name = match phase {
                PublicationPhase::ReadPrevious => "read-previous",
                PublicationPhase::Serialize => "serialize",
                PublicationPhase::CreateStaging => "create-staging",
                PublicationPhase::WritePrefix => "write-prefix",
                PublicationPhase::WriteRemainder => "write-remainder",
                PublicationPhase::Flush => "flush",
                PublicationPhase::Rename => "rename",
                PublicationPhase::AfterRename => "after-rename",
                PublicationPhase::Readback => "readback",
            };
            receipt.record(
                phase_name,
                &before,
                &after,
                &original,
                committed.record_revision,
                retained.record_revision,
                result.is_err(),
                None,
            );
        }
    }
    if let Some(receipt) = receipt {
        receipt.finish("writer");
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
    let mut receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_rename_sharing_failure_retains_typed_code_and_original",
    );
    use std::os::windows::ffi::OsStrExt;
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
    let probe = directory.path().join("native-replacement-probe");
    fs::write(&probe, b"replacement probe").unwrap();
    let probe_name: Vec<u16> = probe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination_name: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: both names are live terminated UTF-16 buffers. The retained
    // destination handle excludes delete sharing throughout both operations.
    let replaced = unsafe {
        MoveFileExW(
            probe_name.as_ptr(),
            destination_name.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    let expected_code = std::io::Error::last_os_error().raw_os_error().unwrap();
    assert_eq!(replaced, 0);
    let mut reached_rename = false;
    assert!(
        candidate
            .publish_at(&path, 1, |phase| {
                reached_rename |= phase == PublicationPhase::Rename;
                Ok(())
            })
            .is_err()
    );
    assert!(reached_rename);
    let mut source = memcordon_core::WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut source);
    let memcordon_core::OriginalFailureV1::Observed { event } = source.original else {
        panic!("native rename cause not captured");
    };
    assert_eq!(
        event.native_code,
        Some(memcordon_core::NativeFailureCodeV1::Win32(
            u32::try_from(expected_code).unwrap()
        ))
    );
    assert_eq!(
        event.origin,
        memcordon_core::DiagnosticOriginV1::RecordWriter
    );
    journal.observe_secondary(event).unwrap();
    assert_eq!(journal.original, committed.causal_diagnostics.original);
    drop(protected);
    let after = read_record_bounded(&path).unwrap();
    assert_eq!(after, before);
    let retained: WindowsAttemptRecordV1 = serde_json::from_slice(&after).unwrap();
    authenticate(&retained, &retained.attempt_id).unwrap();
    if let Some(mut receipt) = receipt.take() {
        receipt.record(
            "native-sharing-rename",
            &before,
            &after,
            &committed.causal_diagnostics.original,
            committed.record_revision,
            retained.record_revision,
            true,
            Some(memcordon_core::NativeFailureCodeV1::Win32(
                u32::try_from(expected_code).unwrap(),
            )),
        );
        receipt.finish("writer");
    }
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
    let receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup",
    );
    let mut observations = Vec::new();
    for guardian_cleanup in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("attempt.json");
        let mut record = observed_record();
        let cleanup_record = record.clone();
        let attempt_id = record.attempt_id.clone();
        let cleanup_path = path.clone();
        let (attempted, wait_attempted) = std::sync::mpsc::sync_channel(1);
        let lane = super::super::attempt_store::test_publisher_lane(
            &attempt_id,
            move |record, revision| {
                let publication_owner =
                    super::super::attempt_store::PublicationGuard::acquire_for_test(
                        &record.attempt_id,
                    );
                attempted
                    .send(publication_owner.as_ref().err().cloned())
                    .unwrap();
                let _publication_owner = publication_owner?;
                record.publish_at(&cleanup_path, revision, |_| Ok(()))
            },
        )
        .unwrap();
        let (frozen, wait_frozen) = std::sync::mpsc::sync_channel(1);
        let (release, wait_release) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let _publication_owner =
                super::super::attempt_store::PublicationGuard::acquire_for_test(&record.attempt_id)
                    .unwrap();
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
        let job_members: Vec<_> = job
            .process_ids()
            .unwrap()
            .into_iter()
            .map(super::super::readiness_receipt::HeldNativeProcess::open)
            .collect();
        assert_eq!(job_members.len(), 2);
        assert!(job_members.iter().all(|process| !process.exited()));
        assert!(
            job_members
                .iter()
                .all(|process| job.contains(process.raw()).unwrap())
        );
        let held_worker =
            super::super::readiness_receipt::HeldNativeProcess::open(worker_authority.0.id());
        let held_guardian =
            super::super::readiness_receipt::HeldNativeProcess::open(guardian.0.id());
        assert!(!held_worker.exited() && !held_guardian.exited());
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
        assert!(job_members.iter().all(|process| process.exited()));
        assert!(held_guardian.exited());
        let worker_retired_during_cleanup = held_worker.exited();
        assert_eq!(worker_retired_during_cleanup, guardian_cleanup);
        let active_after = job.active_processes_observed().unwrap();
        assert_eq!(active_after, 0);
        if !guardian_cleanup {
            assert_eq!(
                wait_attempted
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap(),
                Some("attempt publication owner is unavailable".to_owned())
            );
        }
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        let publication = lane.finish();
        if guardian_cleanup {
            publication.unwrap();
        } else {
            assert_eq!(
                publication.unwrap_err(),
                "attempt cleanup publication is unconfirmed"
            );
        }
        let committed: WindowsAttemptRecordV1 = serde_json::from_slice(
            &read_record_bounded(&directory.path().join("attempt.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(committed.record_revision, 1);
        assert!(!committed.cleanup_state.termination_requested);
        if let Some(receipt) = receipt.as_ref() {
            let phase = if guardian_cleanup {
                "guardian"
            } else {
                "worker"
            };
            let after = read_record_bounded(&directory.path().join("attempt.json")).unwrap();
            authenticate(&committed, &committed.attempt_id).unwrap();
            observations.push(serde_json::json!({
                "cleanup_owner":phase,"job_active_before":job_members.len(),"job_active_after":active_after,
                "job_members":job_members.iter().map(|process| serde_json::json!({"identity":process.identity,
                    "held_before_cleanup":true,"retirement_observed":process.exited()})).collect::<Vec<_>>(),
                "worker_identity":held_worker.identity,"worker_retired_during_cleanup":worker_retired_during_cleanup,
                "guardian_identity":held_guardian.identity,"guardian_retired_during_cleanup":held_guardian.exited(),
                "writer_frozen_during_cleanup":true,"cleanup_publication_confirmed":false,
                "after_record":receipt.retain(&format!("{phase}.after.json"), &after),
                "original":receipt.retain(&format!("{phase}.original.json"), &serde_json::to_vec(&committed.causal_diagnostics.original).unwrap())
            }));
        }
    }
    if let Some(receipt) = receipt {
        receipt.finish_payload(
            serde_json::json!({"kind":"writer-frozen","observations":observations}),
        );
    }
}

#[test]
#[ignore = "requires explicit owned native component receipt input"]
fn native_settlement_reservation_requires_local_writer_retirement() {
    let receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_settlement_reservation_requires_local_writer_retirement",
    ).expect("native reservation test requires explicit owned component input");
    let attempt_id = receipt.attempt_id();
    let request_sha256 = digest(attempt_id.as_bytes());
    let admission_directory = tempfile::tempdir().unwrap();
    let admission_root = admission_directory.path().to_owned();
    let path = admission_root
        .join(&attempt_id)
        .with_extension("writer.json");
    assert!(!path.exists(), "owned component reservation must be fresh");
    reserve_owned_component_writer_for_test(&admission_root, &attempt_id, &request_sha256).unwrap();
    struct Reservation(PathBuf, String);
    impl Drop for Reservation {
        fn drop(&mut self) {
            let _ = retire_owned_component_writer_for_test(&self.0, &self.1, true);
        }
    }
    let reservation = Reservation(admission_root.clone(), attempt_id.clone());
    let writer_directory = tempfile::tempdir().unwrap();
    let writer_path = writer_directory.path().join("attempt.json");
    let publish_path = writer_path.clone();
    let mut candidate = observed_record();
    candidate.attempt_id = attempt_id.clone();
    candidate.request_sha256 = request_sha256.clone();
    let (frozen, wait_frozen) = std::sync::mpsc::sync_channel(1);
    let (release, wait_release) = std::sync::mpsc::sync_channel(1);
    let publisher = std::thread::spawn(move || {
        candidate.publish_at(&publish_path, 0, |phase| {
            if phase == PublicationPhase::Flush {
                frozen.send(()).unwrap();
                wait_release.recv_timeout(Duration::from_secs(60)).unwrap();
            }
            Ok(())
        })
    });
    wait_frozen.recv_timeout(Duration::from_secs(10)).unwrap();
    assert!(!publisher.is_finished());
    let before = read_record_bounded(&path).unwrap();
    let owner = super::super::readiness_receipt::HeldNativeProcess::open(std::process::id());
    assert!(!owner.exited());
    let refusal =
        retire_owned_component_writer_for_test(&admission_root, &attempt_id, false).unwrap_err();
    assert_eq!(
        refusal,
        "cannot release a live writer reservation without local retirement proof"
    );
    let after_refusal = read_record_bounded(&path).unwrap();
    assert_eq!(before, after_refusal);
    assert!(!publisher.is_finished());
    release.send(()).unwrap();
    publisher.join().unwrap().unwrap();
    let published_bytes = read_record_bounded(&writer_path).unwrap();
    let published: WindowsAttemptRecordV1 = serde_json::from_slice(&published_bytes).unwrap();
    authenticate(&published, &attempt_id).unwrap();
    assert_eq!(published.record_revision, 1);
    retire_owned_component_writer_for_test(&admission_root, &attempt_id, true).unwrap();
    assert!(!path.exists());
    drop(reservation);
    let before_path = receipt.retain("reservation.before.json", &before);
    let after_path = receipt.retain("reservation.after-refusal.json", &after_refusal);
    let published_path = receipt.retain("reservation.published.json", &published_bytes);
    receipt.finish_payload(serde_json::json!({"kind":"writer-reservation",
        "attempt_id":attempt_id,"request_sha256":request_sha256,"owner_identity":owner.identity,
        "owner_held_live_during_refusal":true,"before_reservation":before_path,
        "after_refusal_reservation":after_path,"retirement_without_local_proof":refusal,
        "writer_frozen_during_refusal":true,"writer_joined_before_retirement":true,
        "published_record":published_path,
        "local_writer_retirement_proved":true,"reservation_absent_after_retirement":true}));
}

#[test]
fn native_durable_record_rejects_provider_generation_substitution() {
    let receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_durable_record_rejects_provider_generation_substitution",
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    let mut record = observed_record();
    record.publish_at(&path, 0, |_| Ok(())).unwrap();
    let bytes = read_record_bounded(&path).unwrap();
    authenticate(&record, &record.attempt_id).unwrap();
    memcordon_core::parse_and_authenticate_windows_attempt_record_v4(
        &bytes,
        &record.attempt_id,
        &record.provider_generation,
    )
    .unwrap();
    let wrong_generation = digest(record.provider_generation.as_bytes());
    assert_ne!(wrong_generation, record.provider_generation);
    let refusal = memcordon_core::parse_and_authenticate_windows_attempt_record_v4(
        &bytes,
        &record.attempt_id,
        &wrong_generation,
    )
    .unwrap_err();
    assert_eq!(read_record_bounded(&path).unwrap(), bytes);
    if let Some(receipt) = receipt {
        let record_path = receipt.retain("generation.record.json", &bytes);
        receipt.finish_payload(
            serde_json::json!({"kind":"binding-generation","record":record_path,
            "attempt_id":record.attempt_id,"provider_generation":record.provider_generation,
            "substituted_generation":wrong_generation,"refusal":refusal}),
        );
    }
}

#[test]
#[ignore = "requires an explicitly installed isolated native component provider and receipt input"]
fn native_provider_projection_preserves_original_and_reports_bounded_loss() {
    let receipt = super::super::readiness_receipt::begin(
        "windows::record::record_fault_tests::native_provider_projection_preserves_original_and_reports_bounded_loss",
    ).expect("native projection test requires explicit component input");
    let mut record = observed_record();
    let original = record.causal_diagnostics.original.clone();
    let memcordon_core::OriginalFailureV1::Observed { event } = &original else {
        panic!("fixture must have original cause");
    };
    let secondary_attempts = memcordon_core::MAX_DIAGNOSTIC_SECONDARY_EVENTS + 17;
    for _ in 0..secondary_attempts {
        record
            .causal_diagnostics
            .observe_secondary(event.clone())
            .unwrap();
    }
    assert_eq!(record.causal_diagnostics.original, original);
    assert_eq!(
        record.causal_diagnostics.secondary.as_slice().len(),
        memcordon_core::MAX_DIAGNOSTIC_SECONDARY_EVENTS
    );
    assert_eq!(record.causal_diagnostics.loss.secondary_events_omitted, 17);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    record.publish_at(&path, 0, |_| Ok(())).unwrap();
    let bytes = read_record_bounded(&path).unwrap();
    authenticate(&record, &record.attempt_id).unwrap();
    let (projection, availability) = provider_projection(Some(&record));
    assert_eq!(
        availability,
        memcordon_core::DiagnosticProjectionAvailabilityV1::Available
    );
    let projection = projection.unwrap();
    assert_eq!(projection.original, original);
    assert_eq!(projection.loss.secondary_events_omitted, 17);
    let projection_bytes = serde_json::to_vec(&projection).unwrap();
    assert!(projection_bytes.len() <= memcordon_core::MAX_DIAGNOSTIC_PROJECTION_BYTES);
    let record_path = receipt.retain("projection.record.json", &bytes);
    let projection_path = receipt.retain("projection.public.json", &projection_bytes);
    let original_path = receipt.retain(
        "projection.original.json",
        &serde_json::to_vec(&original).unwrap(),
    );
    receipt.finish_payload(serde_json::json!({"kind":"binding-projection","record":record_path,
        "projection":projection_path,"original":original_path,"secondary_attempts":secondary_attempts,
        "availability":availability}));
}
