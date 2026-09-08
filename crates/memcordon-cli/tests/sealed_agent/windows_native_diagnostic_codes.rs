use super::*;
use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, SetLastError};
use windows_sys::Win32::System::Threading::CreateEventW;

fn event_handle() -> OwnedHandle {
    // SAFETY: anonymous test event has no optional security/name pointers.
    OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) }).unwrap()
}

#[test]
fn job_wrappers_capture_native_codes_before_last_error_changes() {
    // Valid event handles deliberately have the wrong native object type.
    // Their owners remain live, avoiding stale handle values and double-close.
    let job = Job {
        handle: event_handle(),
        completion_port: event_handle(),
    };
    for (error, operation) in [
        (
            job.process_ids_observed().unwrap_err(),
            memcordon_core::FailureOperationV1::QueryJobAccounting,
        ),
        (
            job.peak_memory_observed().unwrap_err(),
            memcordon_core::FailureOperationV1::QueryPeakMemory,
        ),
        (
            job.take_notification_observed().unwrap_err(),
            memcordon_core::FailureOperationV1::ReadJobNotification,
        ),
        (
            job.terminate_observed(1).unwrap_err(),
            memcordon_core::FailureOperationV1::TerminateJob,
        ),
    ] {
        // SAFETY: changes only this test thread's last-error slot.
        unsafe {
            SetLastError(1234);
        }
        assert_eq!(error.operation, operation);
        assert_eq!(
            error.source.raw_os_error(),
            Some(ERROR_INVALID_HANDLE as i32)
        );
    }
}
