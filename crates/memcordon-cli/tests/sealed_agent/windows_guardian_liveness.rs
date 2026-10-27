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
