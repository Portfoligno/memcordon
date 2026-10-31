use super::*;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command, Stdio};

#[test]
fn expired_guardian_causal_projection_never_reads_or_exports_native_receipt() {
    let record = observed_record();
    assert!(
        guardian_causal_projection_if_eligible(&record, false, || {
            panic!("expired diagnostics must not read protected receipt");
        })
        .unwrap()
        .is_none()
    );
}

#[path = "windows_v3_fixture.rs"]
mod terminal_fixture;

fn snapshot_predicate_fixture() -> WindowsAttemptRecordV1 {
    let mut record = observed_record();
    let _rejection = terminal_fixture::postauthorization_failure(
        &mut record,
        WindowsProcessIdentityV1 {
            process_id: 2,
            creation_time_100ns: 2,
        },
        true,
        "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
        memcordon_core::BoundarySetupPhase::TargetCreation,
    );
    record.authorization_unix_millis = Some(1);
    record.worker_thread_identity = Some(memcordon_core::WindowsWorkerThreadIdentityV1 {
        thread_id: 1,
        creation_time_100ns: 1,
    });
    record
}

#[test]
fn snapshot_classifier_distinguishes_every_ordered_invariant_without_values() {
    let base = snapshot_predicate_fixture();
    assert_eq!(base.snapshot_violation(&base, base.record_revision), None);
    assert_eq!(
        base.snapshot_violation(&base, base.record_revision + 1),
        Some(SnapshotInvariant::ExpectedRevision)
    );
    macro_rules! case {
        ($kind:ident, |$previous:ident, $candidate:ident| $change:block) => {{
            #[allow(unused_mut)]
            let mut $previous = base.clone();
            #[allow(unused_mut)]
            let mut $candidate = base.clone();
            $candidate.record_revision += 1;
            $change
            assert_eq!($candidate.snapshot_violation(&$previous, $previous.record_revision), Some(SnapshotInvariant::$kind), stringify!($kind));
        }};
    }
    case!(RetentionAdmittedTime, |p, c| {
        c.diagnostic_retention.admitted_monotonic_millis += 1;
    });
    case!(RetentionExpiresTime, |p, c| {
        c.diagnostic_retention.expires_monotonic_millis += 1;
    });
    case!(RetentionTombstone, |p, c| {
        c.diagnostic_retention.tombstone =
            Some(memcordon_core::OriginalUnavailableReasonV1::RecordUnavailable);
    });
    case!(ProviderIncarnation, |p, c| {
        c.provider_incarnation = "different".into();
    });
    case!(LaunchIncarnation, |p, c| {
        c.launch_incarnation = "different".into();
    });
    case!(Nonce, |p, c| {
        c.nonce = "different".into();
    });
    case!(OwnerManifest, |p, c| {
        c.owner_manifest = None;
    });
    case!(RecoveryAuthorization, |p, c| {
        c.recovery_authorization = None;
    });
    case!(PublicationReservation, |p, c| {
        c.terminal_publication_reserved = false;
    });
    case!(TerminalSeed, |p, c| {
        c.terminal_seed = None;
    });
    case!(RetirementProof, |p, c| {
        c.retirement_proof = None;
    });
    case!(RequestDigest, |p, c| {
        c.request_sha256 = "different".into();
    });
    case!(CallerProcess, |p, c| {
        c.caller_process_identity.process_id += 1;
    });
    case!(CallerToken, |p, c| {
        c.caller_token_sha256 = "different".into();
    });
    case!(JobIdentity, |p, c| {
        c.job_identity_sha256 = "different".into();
    });
    case!(WorkerProcess, |p, c| {
        c.worker_identity = None;
    });
    case!(WorkerThread, |p, c| {
        c.worker_thread_identity = None;
    });
    case!(BootIdentity, |p, c| {
        c.boot_identity = "different".into();
    });
    case!(AuthorizationTime, |p, c| {
        c.authorization_unix_millis = None;
    });
    case!(ResumeRegression, |p, c| {
        p.resume_attempted = true;
    });
    case!(ReleaseRegression, |p, c| {
        p.target_released = true;
    });
    case!(TerminationRegression, |p, c| {
        p.cleanup_state.termination_requested = true;
    });
    case!(ActiveZeroRegression, |p, c| {
        p.cleanup_state.active_processes_zero = true;
    });
    case!(GuardianReapedRegression, |p, c| {
        p.cleanup_state.guardian_reaped = true;
    });
    case!(FinalHandlesRegression, |p, c| {
        p.cleanup_state.final_handles_closed = true;
    });
    case!(CausalSecondaryPrefix, |p, c| {
        let memcordon_core::OriginalFailureV1::Observed { event } =
            p.causal_diagnostics.original.clone()
        else {
            panic!("fixture original absent")
        };
        p.causal_diagnostics.observe_secondary(event).unwrap();
    });
    case!(StateTransition, |p, c| {
        p.state = WindowsAttemptStateV1::Authorized;
        c.state = WindowsAttemptStateV1::BoundaryCreated;
    });
    case!(CausalSequenceRegression, |p, c| {
        c.causal_diagnostics = memcordon_core::WindowsCausalDiagnosticsV1::default();
    });
    case!(OriginalFailureReplacement, |p, c| {
        let memcordon_core::OriginalFailureV1::Observed { event } =
            &mut c.causal_diagnostics.original
        else {
            panic!("fixture original absent")
        };
        event.native_code = Some(memcordon_core::NativeFailureCodeV1::Win32(4321));
    });
    case!(TerminalOutbox, |p, c| {
        p.terminal_response_json = Some(std::sync::Arc::from(
            serde_json::to_string(&serde_json::json!({"fixture":"retained-terminal-outbox"}))
                .unwrap(),
        ));
    });
}

#[test]
fn snapshot_retention_expiry_exception_remains_narrow() {
    let mut previous = observed_record();
    previous.boot_identity = "original-boot-no-longer-current".into();
    let mut expired = previous.clone();
    expired.causal_diagnostics = memcordon_core::WindowsCausalDiagnosticsV1::default();
    expired.causal_diagnostics.original = memcordon_core::OriginalFailureV1::Unavailable {
        reason: memcordon_core::OriginalUnavailableReasonV1::RetentionExpired,
    };
    expired.diagnostic_retention.tombstone =
        Some(memcordon_core::OriginalUnavailableReasonV1::RetentionExpired);
    assert_eq!(
        expired.snapshot_violation(&previous, previous.record_revision),
        None
    );
    let eligible = observed_record();
    assert!(diagnostic_export_eligible(&eligible));
    let mut refused = eligible.clone();
    refused.causal_diagnostics = expired.causal_diagnostics.clone();
    refused.diagnostic_retention.tombstone = expired.diagnostic_retention.tombstone;
    assert_eq!(
        refused.snapshot_violation(&eligible, eligible.record_revision),
        Some(SnapshotInvariant::RetentionTombstone)
    );
    expired.diagnostic_retention.expires_monotonic_millis += 1;
    assert_eq!(
        expired.snapshot_violation(&previous, previous.record_revision),
        Some(SnapshotInvariant::RetentionExpiresTime)
    );
}

#[test]
fn fallback_original_survives_authenticated_successive_publications() {
    use super::super::diagnostics;
    let _scope = diagnostics::AttemptDiagnosticScope::enter();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    let mut record = observed_record();
    let memcordon_core::OriginalFailureV1::Observed { event } =
        record.causal_diagnostics.original.clone()
    else {
        panic!("fixture original absent")
    };
    record.causal_diagnostics = memcordon_core::WindowsCausalDiagnosticsV1::default();
    diagnostics::observe_uncaptured_failure(&mut record.causal_diagnostics, event.clone());
    record.publish_at(&path, 0, |_| Ok(())).unwrap();
    let original = record.causal_diagnostics.original.clone();
    for expected in [1, 2] {
        let bytes = read_record_bounded(&path).unwrap();
        let previous: WindowsAttemptRecordV1 = serde_json::from_slice(&bytes).unwrap();
        authenticate(&previous, &record.attempt_id).unwrap();
        diagnostics::set_phase(memcordon_core::AttemptObservationPhaseV1::Cleaning);
        diagnostics::capture(event.clone());
        let mut next = previous.clone();
        diagnostics::merge_into(&mut next.causal_diagnostics);
        next.record_revision = expected + 1;
        next.publish_at(&path, expected, |_| Ok(())).unwrap();
        assert_eq!(next.causal_diagnostics.original, original);
        assert!(
            next.causal_diagnostics
                .secondary
                .as_slice()
                .starts_with(previous.causal_diagnostics.secondary.as_slice())
        );
        assert_eq!(next.causal_diagnostics.sequence, expected + 1);
        record = next;
    }
    assert_eq!(record.causal_diagnostics.sequence, 3);
    assert!(!path.with_extension("json.new").exists());
}

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
    assert_eq!(error, "attempt publication writer is busy (WAIT_TIMEOUT)");

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
        assert_ne!(
            (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime),
            0
        );
        serde_json::to_writer(publisher.0.stdin.as_mut().unwrap(), &(&path, after_rename)).unwrap();
        drop(publisher.0.stdin.take());
        assert_eq!(publisher.0.wait().unwrap().code(), Some(73));
        let after = read_record_bounded(&path).unwrap();
        let retained: WindowsAttemptRecordV1 = serde_json::from_slice(&after).unwrap();
        authenticate(&retained, &retained.attempt_id).unwrap();
        assert_eq!(retained.record_revision, if after_rename { 2 } else { 1 });
        if after_rename {
            assert_ne!(after, before);
        } else {
            assert_eq!(after, before);
        }
        assert_eq!(
            retained.causal_diagnostics.original,
            record.causal_diagnostics.original
        );
        assert_eq!(record.record_revision, 1);
    }
}

#[test]
#[ignore = "outbox crash fixture invoked through its exclusive stdin pipe"]
fn native_outbox_crash_child() {
    let (path, after_rename, response): (PathBuf, bool, memcordon_core::WindowsLauncherResponseV4) =
        serde_json::from_reader(std::io::stdin()).unwrap();
    let mut record: WindowsAttemptRecordV1 =
        serde_json::from_slice(&read_record_bounded(&path).unwrap()).unwrap();
    record
        .stage_terminal_response_with_store_for_test(&response, |candidate| {
            let expected = candidate.record_revision;
            candidate.record_revision = expected.checked_add(1).unwrap();
            let terminal = candidate.terminal_response_json.is_some();
            candidate.publish_at(&path, expected, |phase| {
                if terminal
                    && phase
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
        })
        .unwrap();
    panic!("actual terminal outbox publication crash was not reached");
}

#[test]
#[ignore = "runs isolated native publisher crash subprocesses"]
fn native_terminal_outbox_crash_preserves_exact_replay_boundary() {
    for after_rename in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("owned-outbox.json");
        let mut record = observed_record();
        let identity = memcordon_core::WindowsProcessIdentityV1 {
            process_id: 412,
            creation_time_100ns: 991337,
        };
        record.guardian_identity = Some(identity.clone());
        record.target_identity = Some(identity.clone());
        record.nonce = "native-outbox-crash".into();
        terminal_fixture::bind_owner_manifest(&mut record, &identity);
        record.state = WindowsAttemptStateV1::Authorized;
        record.authorization_unix_millis = Some(1);
        record
            .begin_postauthorization_retirement_for_test()
            .unwrap();
        record.cleanup_state.active_processes_zero = true;
        record.cleanup_state.guardian_reaped = true;
        record.complete_rejection_cleanup_for_test().unwrap();
        let rejection = terminal_fixture::postauthorization_failure(
            &mut record,
            identity,
            false,
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT",
            memcordon_core::BoundarySetupPhase::Authorization,
        );
        let response = memcordon_core::WindowsLauncherResponseV4::Reject {
            schema_version: memcordon_core::WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
            attempt_id: record.attempt_id.clone(),
            nonce: record.nonce.clone(),
            request_sha256: record.request_sha256.clone(),
            rejection,
        };
        let authority = response.terminal_authority_json().unwrap();
        record.record_revision = 1;
        record.publish_at(&path, 0, |_| Ok(())).unwrap();
        let before = read_record_bounded(&path).unwrap();
        let mut publisher = ChildLifetime(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows::record::record_fault_tests::native_outbox_crash_child",
                    "--ignored",
                    "--nocapture",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let held = super::super::native_process::HeldNativeProcess::open(publisher.0.id());
        assert!(!held.exited());
        serde_json::to_writer(
            publisher.0.stdin.as_mut().unwrap(),
            &(&path, after_rename, &response),
        )
        .unwrap();
        drop(publisher.0.stdin.take());
        assert_eq!(publisher.0.wait().unwrap().code(), Some(73));
        assert!(held.exited());
        let after = read_record_bounded(&path).unwrap();
        let retained: WindowsAttemptRecordV1 = serde_json::from_slice(&after).unwrap();
        authenticate(&retained, &retained.attempt_id).unwrap();
        assert_eq!(retained.record_revision, if after_rename { 3 } else { 2 });
        assert_eq!(
            retained.causal_diagnostics.original,
            record.causal_diagnostics.original
        );
        let replay = super::super::record::pending_owned_component_response_for_test(
            &path,
            &record.attempt_id,
            &record.nonce,
            &record.request_sha256,
            &record.caller_process_identity,
            &record.caller_token_sha256,
        )
        .unwrap();
        if after_rename {
            assert_eq!(
                replay.as_ref().unwrap().terminal_authority_json().unwrap(),
                authority
            );
        } else {
            assert!(replay.is_none());
        }
        assert_eq!(
            read_record_bounded(&path).unwrap(),
            after,
            "query-only replay cannot rewrite the crash boundary"
        );
        if !after_rename {
            assert_ne!(
                after, before,
                "pre-rename crash must still retain the nonterminal published revision"
            );
        }
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
    let decoded: memcordon_core::WindowsDurableAttemptRecordV5 =
        serde_json::from_slice(&canonical_record_bytes(&record).unwrap()).unwrap();
    assert_eq!(
        decoded.worker_thread_identity,
        record.worker_thread_identity
    );
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
    assert!(
        stale
            .publish_at(&path, 0, |_| Ok(()))
            .unwrap_err()
            .contains("invariant=ExpectedRevision;")
    );
    assert!(!path.with_extension("json.new").exists());
    let mut replacement = stale.clone();
    replacement.causal_diagnostics.original = memcordon_core::OriginalFailureV1::Unavailable {
        reason: memcordon_core::OriginalUnavailableReasonV1::RecordUnavailable,
    };
    assert!(
        replacement
            .publish_at(&path, 1, |_| Ok(()))
            .unwrap_err()
            .contains("invariant=OriginalFailureReplacement;")
    );
    assert!(!path.with_extension("json.new").exists());
    let staged = path.with_extension("json.new");
    fs::create_dir(&staged).unwrap();
    assert!(stale.publish_at(&path, 1, |_| Ok(())).is_err());
    assert_eq!(read_record_bounded(&path).unwrap(), before);
}

#[test]
fn native_rename_sharing_failure_retains_typed_code_and_original() {
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
fn replacement_diagnostics_fit_original_carrier_and_preserve_native_cause() {
    let _capture = super::super::diagnostics::AttemptDiagnosticScope::enter();
    let error = io::Error::from_raw_os_error(5);
    let original = publication_io_error(error);
    let long_name = "界😀".repeat(MAX_TERMINALIZATION_DETAIL_BYTES);
    let source = PathBuf::from("C:\\missing-publication-source").join(&long_name);
    let destination = PathBuf::from("C:\\missing-publication-destination").join(long_name);
    let message = replacement_failure_context(&original, Some(5), &source, &destination);
    assert!(message.starts_with(&original));
    assert!(message.len() <= MAX_TERMINALIZATION_DETAIL_BYTES * 3 / 4);
    let (_, json) = message.split_once("; replacement-context=").unwrap();
    let context: serde_json::Value = serde_json::from_str(json).unwrap();
    assert_eq!(context["api"], "MoveFileExW");
    assert!(context.get("omitted").is_some() || context["source"]["truncated"] == true);
    let mut journal = memcordon_core::WindowsCausalDiagnosticsV1::default();
    super::super::diagnostics::merge_into(&mut journal);
    let memcordon_core::OriginalFailureV1::Observed { event } = journal.original else {
        panic!("original replacement failure absent");
    };
    assert_eq!(
        event.native_code,
        Some(memcordon_core::NativeFailureCodeV1::Win32(5))
    );
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
            .map(super::super::native_process::HeldNativeProcess::open)
            .collect();
        assert_eq!(job_members.len(), 2);
        assert!(job_members.iter().all(|process| !process.exited()));
        assert!(
            job_members
                .iter()
                .all(|process| job.contains(process.raw()).unwrap())
        );
        let held_worker =
            super::super::native_process::HeldNativeProcess::open(worker_authority.0.id());
        let held_guardian = super::super::native_process::HeldNativeProcess::open(guardian.0.id());
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
        let retirement_deadline = Instant::now() + Duration::from_secs(5);
        while !job_members.iter().all(|process| process.exited()) {
            assert!(
                Instant::now() < retirement_deadline,
                "held workload processes did not retire after Job accounting became empty"
            );
            std::thread::yield_now();
        }
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
                Some("attempt publication writer is busy (WAIT_TIMEOUT)".to_owned())
            );
        }
        release.send(()).unwrap();
        worker.join().unwrap().unwrap();
        let publication = lane.finish();
        if guardian_cleanup {
            publication.unwrap();
        } else {
            let error = publication.unwrap_err();
            assert!(error.starts_with("attempt cleanup publication is unconfirmed;"));
            assert!(error.contains(
                "first-publisher-error=attempt publication writer is busy (WAIT_TIMEOUT)"
            ));
        }
        let committed: WindowsAttemptRecordV1 = serde_json::from_slice(
            &read_record_bounded(&directory.path().join("attempt.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(committed.record_revision, 1);
        assert!(!committed.cleanup_state.termination_requested);
        authenticate(&committed, &committed.attempt_id).unwrap();
    }
}

#[test]
fn staged_attempt_requires_its_live_exact_writer_reservation() {
    let root = tempfile::tempdir().unwrap();
    let admissions = tempfile::tempdir().unwrap();
    let attempt_id = digest(b"live-staged-attempt-accounting");
    let request = digest(b"live-staged-request");
    let staged = root.path().join(&attempt_id).with_extension("json.new");
    std::fs::write(&staged, b"partial writer-owned bytes").unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    reserve_owned_component_writer_for_test(admissions.path(), &attempt_id, &request).unwrap();
    let admission_path = admissions
        .path()
        .join(&attempt_id)
        .with_extension("writer.json");
    let admission_bytes = std::fs::read(&admission_path).unwrap();
    let stage_bytes = std::fs::read(&staged).unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).unwrap());
    assert_eq!(std::fs::read(&staged).unwrap(), stage_bytes);
    assert_eq!(std::fs::read(&admission_path).unwrap(), admission_bytes);
    let mut invalid: serde_json::Value = serde_json::from_slice(&admission_bytes).unwrap();
    invalid["attempt_id"] = serde_json::json!(digest(b"foreign-stage"));
    std::fs::write(&admission_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    let mut invalid: serde_json::Value = serde_json::from_slice(&admission_bytes).unwrap();
    invalid["owner_process_identities"][0]["creation_time_100ns"] = serde_json::json!(1);
    std::fs::write(&admission_path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    std::fs::write(&admission_path, &admission_bytes).unwrap();
    let alias = root.path().join("linked-stage");
    std::fs::hard_link(&staged, &alias).unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    std::fs::remove_file(alias).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&staged)
        .unwrap()
        .set_len(memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64 + 1)
        .unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    std::fs::remove_file(&staged).unwrap();
    std::fs::create_dir(&staged).unwrap();
    assert!(reserved_writer_stage_for_test(&staged, admissions.path()).is_err());
    assert!(
        !reserved_writer_stage_for_test(&root.path().join("unknown-entry"), admissions.path())
            .unwrap()
    );
    retire_owned_component_writer_for_test(admissions.path(), &attempt_id, true).unwrap();
}

#[test]
#[ignore = "runs an isolated frozen native publisher"]
fn native_settlement_reservation_requires_local_writer_retirement() {
    let attempt_id = digest(b"local-native-writer-reservation");
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
    let owner = super::super::native_process::HeldNativeProcess::open(std::process::id());
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
}

#[test]
fn native_durable_record_rejects_provider_generation_substitution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("attempt.json");
    let mut record = observed_record();
    record.publish_at(&path, 0, |_| Ok(())).unwrap();
    let bytes = read_record_bounded(&path).unwrap();
    authenticate(&record, &record.attempt_id).unwrap();
    memcordon_core::parse_and_authenticate_windows_attempt_record_v5(
        &bytes,
        &record.attempt_id,
        &record.provider_generation,
    )
    .unwrap();
    let wrong_generation = digest(record.provider_generation.as_bytes());
    assert_ne!(wrong_generation, record.provider_generation);
    memcordon_core::parse_and_authenticate_windows_attempt_record_v5(
        &bytes,
        &record.attempt_id,
        &wrong_generation,
    )
    .unwrap_err();
    assert_eq!(read_record_bounded(&path).unwrap(), bytes);
}

#[test]
#[ignore = "runs current native provider projection and recovery vectors"]
fn native_provider_projection_preserves_original_and_reports_bounded_loss() {
    let mut record = observed_record();
    assert!(record.guardian_identity.is_none());
    // The temporary record uses its real compiled generation. The remaining
    // binding fields are explicit fixture inputs, not an installed package.
    let binding = memcordon_core::PublicProviderBindingV1 {
        generation: memcordon_core::BoundedText::new(record.provider_generation.as_str()).unwrap(),
        source_commit: memcordon_core::BoundedText::new(&"12".repeat(20)).unwrap(),
        runtime_manifest_sha256: memcordon_core::hash_bytes(
            b"native provider projection fixture manifest",
        ),
    };
    assert!(binding.is_consistent());
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
    let (projection, availability) =
        provider_projection_with_binding(Some(&record), || Ok(binding.clone()));
    let stored: WindowsAttemptRecordV1 = serde_json::from_slice(&bytes).unwrap();
    authenticate(&stored, &stored.attempt_id).unwrap();
    assert_eq!(
        serde_json::to_value(&stored).unwrap(),
        serde_json::to_value(&record).unwrap()
    );
    assert_eq!(
        availability,
        memcordon_core::DiagnosticProjectionAvailabilityV1::Available
    );
    let projection = projection.unwrap();
    assert_eq!(projection.original, original);
    assert_eq!(projection.loss.secondary_events_omitted, 17);
    let projection_bytes = serde_json::to_vec(&projection).unwrap();
    assert!(projection_bytes.len() <= memcordon_core::MAX_DIAGNOSTIC_PROJECTION_BYTES);
    let (unavailable, reason) = provider_projection_with_binding(Some(&record), || {
        Err("fixture binding intentionally unavailable".into())
    });
    assert!(unavailable.is_none());
    assert_eq!(
        reason,
        memcordon_core::DiagnosticProjectionAvailabilityV1::ProviderBindingUnavailable
    );
    let mut foreign_binding = binding.clone();
    foreign_binding.generation =
        memcordon_core::BoundedText::new("foreign-fixture-generation").unwrap();
    assert!(foreign_binding.is_consistent());
    assert_ne!(foreign_binding.generation, binding.generation);
    let (unavailable, reason) =
        provider_projection_with_binding(Some(&record), || Ok(foreign_binding.clone()));
    assert!(unavailable.is_none());
    assert_eq!(
        reason,
        memcordon_core::DiagnosticProjectionAvailabilityV1::ProviderBindingUnavailable
    );
    let (unavailable, reason) = provider_projection_with_binding(None, || {
        panic!("absent record must not resolve installed state")
    });
    assert!(unavailable.is_none());
    assert_eq!(
        reason,
        memcordon_core::DiagnosticProjectionAvailabilityV1::RecordUnavailable
    );
    let mut expired_record = record.clone();
    expired_record.diagnostic_retention.tombstone =
        Some(memcordon_core::OriginalUnavailableReasonV1::RetentionExpired);
    let (unavailable, reason) = provider_projection_with_binding(Some(&expired_record), || {
        panic!("expired record must not resolve installed state")
    });
    assert!(unavailable.is_none());
    assert_eq!(
        reason,
        memcordon_core::DiagnosticProjectionAvailabilityV1::RetentionExpired
    );
    let mut recovered_record = record.clone();
    let rejection = terminal_fixture::postauthorization_failure(
        &mut recovered_record,
        WindowsProcessIdentityV1 {
            process_id: 2,
            creation_time_100ns: 2,
        },
        true,
        "MCSEALED-WINDOWS-AUTHORITY-LOSS",
        memcordon_core::BoundarySetupPhase::Retirement,
    );
    assert!(recovered_record.guardian_identity.is_none());
    assert_eq!(
        binding.generation.as_str(),
        recovered_record.provider_generation
    );
    recovered_record.terminal_disposition =
        Some(memcordon_core::WindowsAttemptTerminalDispositionV1::Posttarget);
    let mut transport_event = event.clone();
    transport_event.sequence = 0;
    transport_event.category = memcordon_core::FailureCategoryV1::Transport;
    transport_event.operation = memcordon_core::FailureOperationV1::DeliverResponse;
    transport_event.code = memcordon_core::FailureCodeV1::ControlTransport;
    transport_event.native_code = Some(memcordon_core::NativeFailureCodeV1::Win32(232));
    transport_event.observed_phase = memcordon_core::AttemptObservationPhaseV1::Cleaning;
    transport_event.safe_detail = memcordon_core::SafeDiagnosticDetailV1::InjectedWindowsFault {
        fault: memcordon_core::WindowsSealedFault::FrontendDisconnectedAfterAuthorization,
    };
    recovered_record.causal_diagnostics = memcordon_core::WindowsCausalDiagnosticsV1::default();
    recovered_record
        .causal_diagnostics
        .observe(transport_event)
        .unwrap();
    recovered_record.causal_diagnostics.durable_through_sequence =
        Some(recovered_record.causal_diagnostics.sequence);
    let transport_projection = memcordon_core::ProviderFailureDiagnosticV1::from_journal(
        projection.provider_binding.clone(),
        &recovered_record.attempt_id,
        &recovered_record.request_sha256,
        &recovered_record.causal_diagnostics,
    )
    .unwrap();
    let response = memcordon_core::WindowsLauncherResponseV4::Reject {
        schema_version: memcordon_core::WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION,
        attempt_id: recovered_record.attempt_id.clone(),
        nonce: recovered_record.nonce.clone(),
        request_sha256: recovered_record.request_sha256.clone(),
        rejection,
    };
    let authority = response.terminal_authority_json().unwrap();
    let stripped: memcordon_core::WindowsLauncherResponseV4 =
        serde_json::from_str(&authority).unwrap();
    assert!(
        matches!(&stripped, memcordon_core::WindowsLauncherResponseV4::Reject {
        rejection, ..
    } if rejection.provider_failure.is_none())
    );
    let recovered =
        bound_recovery_terminal_response_with_binding(&recovered_record, &authority, || {
            Ok(binding.clone())
        })
        .unwrap();
    assert!(
        matches!(&recovered, memcordon_core::WindowsLauncherResponseV4::Reject {
        rejection, ..
    } if rejection.provider_failure.as_ref() == Some(&transport_projection))
    );
    assert_eq!(recovered.terminal_authority_json().unwrap(), authority);
    for unavailable_binding in [false, true] {
        let unavailable =
            bound_recovery_terminal_response_with_binding(&recovered_record, &authority, || {
                if unavailable_binding {
                    Err("fixture binding intentionally unavailable".into())
                } else {
                    Ok(foreign_binding.clone())
                }
            })
            .unwrap();
        assert!(
            matches!(&unavailable, memcordon_core::WindowsLauncherResponseV4::Reject { rejection, .. } if rejection.provider_failure.is_none())
        );
        assert_eq!(unavailable.terminal_authority_json().unwrap(), authority);
    }
    let mut foreign = recovered_record.clone();
    foreign.request_sha256 = "ab".repeat(32);
    assert!(
        bound_recovery_terminal_response_with_binding(&foreign, &authority, || {
            panic!("foreign recovery outbox must fail before resolving installed state")
        })
        .is_err()
    );
    recovered_record.diagnostic_retention.tombstone =
        Some(memcordon_core::OriginalUnavailableReasonV1::RetentionExpired);
    let expired =
        bound_recovery_terminal_response_with_binding(&recovered_record, &authority, || {
            panic!("expired recovery diagnostics must not resolve installed state")
        })
        .unwrap();
    assert!(
        matches!(&expired, memcordon_core::WindowsLauncherResponseV4::Reject {
        rejection, ..
    } if rejection.provider_failure.is_none())
    );
    assert_eq!(expired.terminal_authority_json().unwrap(), authority);
}
