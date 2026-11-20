use super::*;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, GetCurrentProcess, PROCESS_INFORMATION, STARTUPINFOW,
    TerminateProcess,
};

#[test]
fn guardian_refusal_facts_are_closed_bounded_and_phase_specific() {
    assert_eq!(
        process_open_failure(io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)).unwrap(),
        ProcessLiveness::PidAbsent {
            raw_os_error: ERROR_INVALID_PARAMETER as i32
        }
    );
    assert!(process_open_failure(io::Error::from_raw_os_error(5)).is_err());
    let expected = WindowsProcessIdentityV1 {
        process_id: u32::MAX,
        creation_time_100ns: u64::MAX,
    };
    let observations = [
        ProcessLiveness::PidAbsent {
            raw_os_error: ERROR_INVALID_PARAMETER as i32,
        },
        ProcessLiveness::Signaled {
            wait_status: WAIT_OBJECT_0,
        },
        ProcessLiveness::IdentityMismatch {
            observed: WindowsProcessIdentityV1 {
                process_id: u32::MAX - 1,
                creation_time_100ns: u64::MAX - 1,
            },
            wait_status: 258,
        },
    ];
    for (observation, reason) in
        observations
            .iter()
            .zip(["pid-absent", "process-signaled", "identity-mismatch"])
    {
        for (phase, label) in [
            (
                GuardianObservationPhase::BeforeInventory,
                "before-record-inventory",
            ),
            (
                GuardianObservationPhase::AfterInventory,
                "after-record-inventory",
            ),
        ] {
            let detail = guardian_liveness_refusal(&expected, observation, phase).unwrap();
            assert!(
                detail.len() < 512,
                "complete facts must fit existing 1024-byte query detail even with transport prefixes"
            );
            assert!(detail.contains(label));
            assert!(detail.contains(reason));
            assert!(detail.contains(&expected.process_id.to_string()));
            assert!(detail.contains(&expected.creation_time_100ns.to_string()));
            assert_eq!(
                detail.contains("observed-pid="),
                matches!(observation, ProcessLiveness::IdentityMismatch { .. })
            );
        }
    }
    assert!(
        guardian_liveness_refusal(
            &expected,
            &ProcessLiveness::Live,
            GuardianObservationPhase::BeforeInventory
        )
        .is_none()
    );
}

#[test]
fn scoped_guardian_scan_requires_the_original_durable_release() {
    use memcordon_core::{BoundedText, PublicProviderBindingV1};

    // SAFETY: the pseudo handle names this process for identity readback.
    let guardian = super::super::process::process_identity(unsafe { GetCurrentProcess() }).unwrap();
    // SAFETY: query-only access to this process, retained for the whole inventory.
    let owner = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            guardian.process_id,
        )
    })
    .unwrap();
    let target = WindowsProcessIdentityV1 {
        process_id: guardian.process_id + 1,
        creation_time_100ns: guardian.creation_time_100ns + 1,
    };
    let query = GuardianReleaseQuery {
        target: &target,
        guardian: &owner,
        cutoff: Instant::now() + Duration::from_secs(30),
    };
    let mut pending_record = WindowsAttemptRecordV1::new(
        digest(b"release fixture attempt"),
        digest(b"release fixture request"),
        guardian.clone(),
        digest(b"release fixture caller"),
        digest(b"release fixture job"),
    )
    .unwrap();
    pending_record.guardian_identity = Some(guardian.clone());
    pending_record.target_identity = Some(target.clone());
    super::record_fault_tests::terminal_fixture::bind_owner_manifest(&mut pending_record, &target);
    pending_record.worker_identity = Some(guardian.clone());
    pending_record.worker_thread_identity = Some(current_worker_thread_identity().unwrap());
    pending_record.state = WindowsAttemptStateV1::Authorized;
    pending_record.authorization_unix_millis = Some(1);
    pending_record.resume_attempted = true;
    pending_record.record_revision = 5;
    pending_record.causal_diagnostics.durable_through_sequence = Some(0);
    let boot = pending_record.boot_identity.clone();
    let provider = PublicProviderBindingV1 {
        generation: BoundedText::new(&pending_record.provider_generation).unwrap(),
        source_commit: BoundedText::new(&"12".repeat(20)).unwrap(),
        runtime_manifest_sha256: memcordon_core::hash_bytes(b"release fixture manifest"),
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let path = root.join(format!("{}.json", pending_record.attempt_id));
    let publish = |candidate: &mut WindowsAttemptRecordV1, path: &Path| {
        fs::write(path, candidate.authenticated_store_bytes().unwrap()).unwrap();
    };
    let scan = |query: &GuardianReleaseQuery<'_>| {
        let verify = |phase| query.require_live(&guardian, phase);
        verify(GuardianObservationPhase::BeforeInventory)?;
        scan_guardian_records(root, &guardian, &provider, &boot, Some(query), verify)
    };
    let read_release = || {
        let GuardianInventoryObservation::Release(snapshot) = scan(&query).unwrap() else {
            panic!("expected scoped release observation");
        };
        snapshot
    };
    publish(&mut pending_record, &path);
    let pending = read_release();
    assert!(pending.state == GuardianReleaseState::Pending);
    assert!(read_release().verify_after_pending(&pending).is_ok());
    let mut before_resume = pending_record.clone();
    before_resume.resume_attempted = false;
    publish(&mut before_resume, &path);
    assert!(scan(&query).is_err());
    publish(&mut pending_record, &path);
    assert!(
        scan_guardian_records(root, &guardian, &provider, &boot, None, |_| {
            panic!("legacy one-shot must return the existing release refusal")
        })
        .is_err()
    );

    let extra_id = digest(b"second inventory entry");
    let extra = root.join(format!("{extra_id}.json"));
    fs::write(&extra, b"malformed").unwrap();
    assert!(scan(&query).is_err());
    let mut duplicate = pending_record.clone();
    duplicate
        .owner_manifest
        .as_mut()
        .unwrap()
        .attempt_id
        .clone_from(&extra_id);
    duplicate.attempt_id = extra_id;
    publish(&mut duplicate, &extra);
    assert!(scan(&query).is_err());
    fs::remove_file(&extra).unwrap();

    let mut released = pending_record.clone();
    released.target_released = true;
    publish(&mut released, &path);
    assert!(read_release().verify_after_pending(&pending).is_err());
    released.record_revision += 1;
    publish(&mut released, &path);
    let observed = read_release();
    assert!(observed.state == GuardianReleaseState::Released);
    assert!(observed.verify_after_pending(&pending).is_ok());
    let mut skipped_revision = released.clone();
    skipped_revision.record_revision += 1;
    publish(&mut skipped_revision, &path);
    assert!(read_release().verify_after_pending(&pending).is_err());
    publish(&mut released, &path);

    let expired = GuardianReleaseQuery {
        cutoff: Instant::now(),
        ..query
    };
    assert!(scan(&expired).is_err());
    let wrong_target = WindowsProcessIdentityV1 {
        creation_time_100ns: target.creation_time_100ns + 1,
        ..target
    };
    let wrong_query = GuardianReleaseQuery {
        target: &wrong_target,
        ..query
    };
    assert!(scan(&wrong_query).is_err());
    let mut wrong_birth = guardian.clone();
    wrong_birth.creation_time_100ns += 1;
    assert!(
        scan_guardian_records(root, &guardian, &provider, &boot, Some(&query), |phase| {
            query.require_live(&wrong_birth, phase)
        })
        .is_err()
    );

    let changes: [fn(&mut WindowsAttemptRecordV1); 6] = [
        |value| value.request_sha256 = digest(b"other request"),
        |value| value.nonce.push('x'),
        |value| value.worker_identity.as_mut().unwrap().creation_time_100ns += 1,
        |value| {
            value
                .worker_thread_identity
                .as_mut()
                .unwrap()
                .creation_time_100ns += 1
        },
        |value| {
            value
                .recovery_authorization
                .as_mut()
                .unwrap()
                .launch_logon_identity += 1
        },
        |value| value.authorization_unix_millis = Some(2),
    ];
    for change in changes {
        let mut changed = released.clone();
        change(&mut changed);
        publish(&mut changed, &path);
        assert!(read_release().verify_after_pending(&pending).is_err());
    }

    let mut failed = released.clone();
    failed
        .causal_diagnostics
        .observe(memcordon_core::CausalEventV1 {
            sequence: 0,
            origin: memcordon_core::DiagnosticOriginV1::Launcher,
            category: memcordon_core::FailureCategoryV1::Launch,
            operation: memcordon_core::FailureOperationV1::ResumeTarget,
            code: memcordon_core::FailureCodeV1::TargetResume,
            native_code: None,
            observed_phase: memcordon_core::AttemptObservationPhaseV1::ResumeAttempted,
            safe_detail: memcordon_core::SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        })
        .unwrap();
    failed.causal_diagnostics.durable_through_sequence = Some(failed.causal_diagnostics.sequence);
    publish(&mut failed, &path);
    assert!(scan(&query).is_err());
    let mut lost = released.clone();
    lost.causal_diagnostics.loss.writer_unavailable = true;
    publish(&mut lost, &path);
    assert!(scan(&query).is_err());
    let mut changed_sequence = released.clone();
    changed_sequence.terminalization.sequence += 1;
    publish(&mut changed_sequence, &path);
    assert!(scan(&query).is_err());
    released
        .transition(WindowsAttemptStateV1::Terminating)
        .unwrap();
    released.cleanup_state.termination_requested = true;
    publish(&mut released, &path);
    assert!(scan(&query).is_err());
    fs::remove_file(&path).unwrap();
    assert!(scan(&query).is_err());
}

struct SuspendedOwner {
    process: OwnedHandle,
    _thread: Option<OwnedHandle>,
    deadline: Instant,
}
impl Drop for SuspendedOwner {
    fn drop(&mut self) {
        // SAFETY: only this fixture's never-resumed original process is stopped.
        unsafe {
            TerminateProcess(self.process.raw(), 0xed16_0000);
        }
        let remaining = self
            .deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(u128::from(u32::MAX - 1)) as u32;
        // SAFETY: the exact process owner remains held; timeout cannot detach it.
        if unsafe { WaitForSingleObject(self.process.raw(), remaining) } != WAIT_OBJECT_0 {
            std::process::abort();
        }
    }
}

#[test]
fn original_native_process_observations_distinguish_live_birth_mismatch_and_signal() {
    let deadline = Instant::now() + Duration::from_secs(30);
    // SAFETY: the pseudo handle is query-only and remains valid for this process.
    let current = unsafe { GetCurrentProcess() };
    let expected = super::super::process::process_identity(current).unwrap();
    assert_eq!(
        observe_process_liveness(expected.clone()).unwrap(),
        ProcessLiveness::Live
    );
    assert!(process_identity_is_live(expected.clone()).unwrap());
    let mut mismatch = expected.clone();
    mismatch.creation_time_100ns ^= 1;
    assert!(
        matches!(observe_process_liveness(mismatch.clone()).unwrap(), ProcessLiveness::IdentityMismatch { observed, wait_status: 258 } if observed == expected)
    );
    assert!(!process_identity_is_live(mismatch).unwrap());

    let application: Vec<u16> = std::env::current_exe()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let startup = STARTUPINFOW {
        cb: size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut information = PROCESS_INFORMATION::default();
    assert!(Instant::now() < deadline);
    // SAFETY: no inherited handles or command line; child is never resumed.
    assert_ne!(
        unsafe {
            CreateProcessW(
                application.as_ptr(),
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED,
                ptr::null(),
                ptr::null(),
                &startup,
                &mut information,
            )
        },
        0
    );
    let mut owner = SuspendedOwner {
        process: OwnedHandle::new(information.hProcess).unwrap(),
        _thread: None,
        deadline,
    };
    owner._thread = Some(OwnedHandle::new(information.hThread).unwrap());
    let child = super::super::process::process_identity(owner.process.raw()).unwrap();
    assert_eq!(
        observe_held_process_liveness(owner.process.raw(), child.clone()).unwrap(),
        ProcessLiveness::Live
    );
    assert!(Instant::now() < deadline);
    // SAFETY: terminate only the never-resumed fixture through its original owner.
    assert_ne!(unsafe { TerminateProcess(owner.process.raw(), 23) }, 0);
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32;
    // SAFETY: bounded wait on the same original process, not a numeric PID reopen.
    assert_eq!(
        unsafe { WaitForSingleObject(owner.process.raw(), remaining) },
        WAIT_OBJECT_0
    );
    assert!(Instant::now() < deadline);
    assert_eq!(
        observe_held_process_liveness(owner.process.raw(), child).unwrap(),
        ProcessLiveness::Signaled {
            wait_status: WAIT_OBJECT_0
        }
    );
}
