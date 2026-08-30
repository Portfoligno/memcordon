use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING,
    SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
    StartServiceCtrlDispatcherW,
};

use memcordon_core::{WINDOWS_CONTROL_PIPE, WINDOWS_LAUNCHER_PIPE, WINDOWS_SESSION_BROKER_PIPE};

use super::pipe::wide_null;

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static ROLE: AtomicU8 = AtomicU8::new(0);
static mut STATUS_HANDLE: SERVICE_STATUS_HANDLE = ptr::null_mut();

pub fn dispatch(
    name: &str,
    role: u8,
    entry: unsafe extern "system" fn(u32, *mut *mut u16),
) -> Result<(), String> {
    STOP_REQUESTED.store(false, Ordering::SeqCst);
    ROLE.store(role, Ordering::SeqCst);
    let mut name = wide_null(name);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(entry),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table is terminated, all strings stay live until dispatcher
    // returns, and the entrypoint has the SCM-required ABI.
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub unsafe fn announce_starting(name: &str) -> Result<(), String> {
    let name = wide_null(name);
    // SAFETY: name is NUL-terminated and handler has the required ABI.
    let status_handle = unsafe { RegisterServiceCtrlHandlerW(name.as_ptr(), Some(handler)) };
    if status_handle.is_null() {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: service callback serialization ensures only this service process
    // writes its status handle.
    unsafe { STATUS_HANDLE = status_handle };
    set_state_with_progress(SERVICE_START_PENDING, 0, 0, 0, 1, 60_000)
}

pub fn announce_running() -> Result<(), String> {
    set_state(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0)
}

pub fn stop_requested() -> bool {
    STOP_REQUESTED.load(Ordering::SeqCst)
}

pub fn announce_stopped(exit_code: u32) {
    let _ = set_state(SERVICE_STOPPED, 0, exit_code);
}

pub fn announce_startup_failed(service_specific_exit_code: u32) {
    let _ = set_state_with_progress(
        SERVICE_STOPPED,
        0,
        ERROR_SERVICE_SPECIFIC_ERROR,
        service_specific_exit_code,
        0,
        0,
    );
}

fn set_state(state: u32, accepted: u32, exit_code: u32) -> Result<(), String> {
    set_state_with_progress(state, accepted, exit_code, 0, 0, 0)
}

fn set_state_with_progress(
    state: u32,
    accepted: u32,
    exit_code: u32,
    service_specific_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) -> Result<(), String> {
    let status = service_status(
        state,
        accepted,
        exit_code,
        service_specific_exit_code,
        checkpoint,
        wait_hint,
    );
    // SAFETY: STATUS_HANDLE is initialized before status changes and status is
    // a live fixed-size input structure.
    let handle = unsafe { STATUS_HANDLE };
    if handle.is_null() || unsafe { SetServiceStatus(handle, &raw const status) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub(crate) fn service_status(
    state: u32,
    accepted: u32,
    exit_code: u32,
    service_specific_exit_code: u32,
    checkpoint: u32,
    wait_hint: u32,
) -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: service_specific_exit_code,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint,
    }
}

unsafe extern "system" fn handler(control: u32) {
    if control != SERVICE_CONTROL_STOP {
        return;
    }
    STOP_REQUESTED.store(true, Ordering::SeqCst);
    let _ = set_state(SERVICE_STOP_PENDING, 0, 0);
    let endpoint = match ROLE.load(Ordering::SeqCst) {
        1 => WINDOWS_CONTROL_PIPE,
        2 => WINDOWS_LAUNCHER_PIPE,
        3 => WINDOWS_SESSION_BROKER_PIPE,
        _ => return,
    };
    let _ = super::pipe::connect(endpoint);
}
