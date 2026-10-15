//! Query-only retirement of an already held original native worker thread.
use std::io;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::time::Instant;

#[allow(unsafe_code)] // Observe only the caller's retained synchronization/query handle.
pub fn wait_until(thread: &OwnedHandle, cutoff: Instant) -> io::Result<u32> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{GetExitCodeThread, INFINITE, WaitForSingleObject};
    let remaining = cutoff
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "original worker settlement cutoff exhausted",
            )
        })?;
    let milliseconds = remaining
        .as_millis()
        .min(u128::from(INFINITE.saturating_sub(1))) as u32;
    // SAFETY: this borrowed handle remains owned throughout the bounded native wait.
    match unsafe { WaitForSingleObject(thread.as_raw_handle(), milliseconds) } {
        WAIT_OBJECT_0 => {
            let mut status = 0;
            // SAFETY: the original exited thread handle and writable scalar remain live.
            if unsafe { GetExitCodeThread(thread.as_raw_handle(), &mut status) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(status)
            }
        }
        WAIT_TIMEOUT => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original worker did not settle before recovery cutoff",
        )),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        observed => Err(io::Error::other(format!(
            "original worker wait returned unexpected native status {observed:#x}"
        ))),
    }
}
