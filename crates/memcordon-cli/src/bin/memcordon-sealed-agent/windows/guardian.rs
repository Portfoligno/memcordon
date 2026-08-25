use std::ffi::OsString;
use std::io;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::JobObjects::{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
    QueryInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitForMultipleObjects};

use super::pipe::OwnedHandle;

pub fn run(arguments: &[OsString]) -> Result<(), String> {
    let [
        handle_arguments @ ..,
        attempt_id,
        cleanup_deadline,
        readiness_delay,
    ] = arguments
    else {
        return Err(
            "windows-guardian requires five inherited handles, attempt id, cleanup deadline, and readiness delay"
                .to_owned(),
        );
    };
    let values = handle_arguments
        .iter()
        .map(|argument| {
            argument
                .to_string_lossy()
                .parse::<u64>()
                .map(|value| value as usize as HANDLE)
                .map_err(|_| "guardian handle argument is invalid".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [job, frontend, worker, disarm, ready] = values.as_slice() else {
        return Err("windows-guardian requires exactly five inherited handles".to_owned());
    };
    let attempt_id = attempt_id.to_string_lossy();
    super::record::validate_attempt_id(&attempt_id)?;
    let cleanup_deadline = cleanup_deadline
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| "guardian cleanup deadline is invalid".to_owned())?;
    let readiness_delay = readiness_delay
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| "guardian readiness delay is invalid".to_owned())?;
    if [*job, *frontend, *worker, *disarm, *ready]
        .iter()
        .any(|handle| handle.is_null())
    {
        return Err("windows-guardian received a null inherited handle".to_owned());
    }
    let job = OwnedHandle::new(*job)?;
    let frontend = OwnedHandle::new(*frontend)?;
    let worker = OwnedHandle::new(*worker)?;
    let disarm = OwnedHandle::new(*disarm)?;
    let ready = OwnedHandle::new(*ready)?;
    if readiness_delay != 0 {
        std::thread::sleep(Duration::from_millis(readiness_delay));
    }
    // SAFETY: ready is a private inherited event dedicated to this guardian.
    if unsafe { windows_sys::Win32::System::Threading::SetEvent(ready.raw()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let watched = [frontend.raw(), worker.raw(), disarm.raw()];
    // SAFETY: all three handles are live and the array remains valid throughout
    // the non-alertable wait.
    let result =
        unsafe { WaitForMultipleObjects(watched.len() as u32, watched.as_ptr(), 0, INFINITE) };
    if result == WAIT_OBJECT_0 + 2 {
        return Ok(());
    }
    if result != WAIT_OBJECT_0 && result != WAIT_OBJECT_0 + 1 {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: frontend or launcher died before disarm, and guardian owns a live
    // Job handle specifically for terminal cleanup authority.
    if unsafe { TerminateJobObject(job.raw(), 0xC000_013A) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    wait_job_empty(
        job.raw(),
        Instant::now() + Duration::from_millis(cleanup_deadline),
    )?;
    super::record::write_guardian_receipt(&attempt_id)
}

fn wait_job_empty(job: HANDLE, deadline: Instant) -> Result<(), String> {
    while Instant::now() < deadline {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: job is a live inherited Job handle and the output structure
        // matches the requested information class.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err("guardian Job did not become empty after termination".to_owned())
}
