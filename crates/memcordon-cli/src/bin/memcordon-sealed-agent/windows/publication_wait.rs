//! Exact nonblocking publication-wait outcomes. This renders observations;
//! a busy writer is scheduling dependency, never terminal authority.

pub const WAIT_TIMEOUT_STATUS: u32 = 258;

pub fn failure_detail(status: u32, native_error: Option<i32>) -> Option<String> {
    match status {
        0 | 128 => None, // WAIT_OBJECT_0 / WAIT_ABANDONED
        WAIT_TIMEOUT_STATUS => Some("attempt publication writer is busy (WAIT_TIMEOUT)".into()),
        u32::MAX => Some(format!(
            "attempt publication wait failed (WAIT_FAILED); native_error={native_error:?}"
        )),
        _ => Some(format!(
            "attempt publication wait returned unexpected native status {status}"
        )),
    }
}
