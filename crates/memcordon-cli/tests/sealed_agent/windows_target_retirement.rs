use super::*;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
};

struct NativeSuspendedOwner {
    process: OwnedHandle,
    thread: OwnedHandle,
}

impl Drop for NativeSuspendedOwner {
    fn drop(&mut self) {
        // SAFETY: this guard owns an independent handle to the exact child.
        // It must reap even when an assertion or the tested cleanup fails.
        unsafe {
            TerminateProcess(self.process.raw(), 0xed15_0000);
            WaitForSingleObject(self.process.raw(), 2_000);
        }
    }
}

#[test]
fn held_suspended_target_outside_selected_job_is_terminated_without_resume() {
    let application: Vec<u16> = std::env::current_exe()
        .unwrap()
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: this native C descriptor permits a zero-initialized layout.
    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    // SAFETY: process creation initializes every returned native handle field.
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: application is terminated, writable outputs have the native
    // layout, no handles are inherited, and the child is never resumed.
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
                &raw mut process,
            )
        },
        0
    );
    let owner = NativeSuspendedOwner {
        process: OwnedHandle::new(process.hProcess).unwrap(),
        thread: OwnedHandle::new(process.hThread).unwrap(),
    };
    let target = SuspendedTarget {
        process: super::super::duplicate_owned(owner.process.raw()).unwrap(),
        thread: super::super::duplicate_owned(owner.thread.raw()).unwrap(),
        process_snapshot: None,
        _desktop_lease: None,
        desktop_binding: String::new(),
        process_id: process.dwProcessId,
        creation_observation: TargetCreationObservation {
            used_create_process_as_user: false,
            job_list_present: false,
            handle_list_present: false,
            post_create_job_assignment: false,
            unexpected_handle_count: 0,
            loader_qualification: None,
        },
    };
    // SAFETY: no attributes or name are requested; the returned empty Job
    // belongs only to this test and never receives the child process.
    let job = OwnedHandle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) }).unwrap();
    let mut inside = 0;
    // SAFETY: both handles remain owned and inside is writable.
    assert_ne!(
        unsafe { IsProcessInJob(target.handle(), job.raw(), &raw mut inside) },
        0
    );
    assert_eq!(inside, 0);
    // SAFETY: terminating the separate owned Job cannot terminate this child.
    assert_ne!(unsafe { TerminateJobObject(job.raw(), 125) }, 0);
    assert!(!target.wait(Duration::ZERO).unwrap());

    target.terminate_if_live(125).unwrap();
    assert!(target.wait(Duration::from_secs(2)).unwrap());
    assert_eq!(target.exit_status().unwrap(), 125);
    target.terminate_if_live(126).unwrap();
    assert_eq!(target.exit_status().unwrap(), 125);
    target.close_for_retirement().unwrap();
}
