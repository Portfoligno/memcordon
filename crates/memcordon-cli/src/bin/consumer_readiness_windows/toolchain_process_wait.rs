use std::io;
use std::os::windows::io::AsRawHandle;
use std::process::Child;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

pub(super) fn wait_retired(owner: &impl AsRawHandle, milliseconds: u32) -> io::Result<()> {
    // SAFETY: the borrowed owned process handle remains valid throughout the finite wait.
    match unsafe { WaitForSingleObject(owner.as_raw_handle(), milliseconds) } {
        0 => Ok(()),
        u32::MAX => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other(
            "compiler retirement not signaled before original cutoff",
        )),
    }
}

pub(super) fn terminate_failed_child(
    child: &mut Child,
    remaining: impl FnOnce() -> io::Result<u32>,
) -> (bool, io::Result<Option<i32>>) {
    let request = child.kill();
    match wait_retired(child, remaining().unwrap_or(0)) {
        Ok(()) => (true, child.wait().map(|status| status.code())),
        Err(wait) => (false, request.and(Err(wait))),
    }
}
