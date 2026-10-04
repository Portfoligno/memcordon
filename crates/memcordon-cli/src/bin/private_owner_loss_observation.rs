//! Native termination observation for already-held owner-loss fixture pidfds.
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, BorrowedFd};
#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn pidfd_exited(pidfd: BorrowedFd<'_>) -> Result<bool, String> {
    // The fixture must not treat readiness on another descriptor kind as proof
    // of process death. This is kernel descriptor metadata, not a PID lookup.
    let descriptor = Path::new("/proc/self/fd").join(pidfd.as_raw_fd().to_string());
    let kind = std::fs::read_link(descriptor).map_err(|error| error.to_string())?;
    if kind != Path::new("anon_inode:[pidfd]") {
        return Err("owner-loss observation requires an actual held pidfd".into());
    }
    let mut observed = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll borrows one initialized record and the live held descriptor.
    let status = unsafe { libc::poll(&raw mut observed, 1, 0) };
    if status < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    poll_exited(status, observed.revents)
}

pub fn poll_exited(status: i32, revents: i16) -> Result<bool, String> {
    if status == 0 && revents == 0 {
        return Ok(false);
    }
    // An exited pidfd is readable; after reaping it can also report hangup.
    // Error, invalid or unrelated readiness never proves native termination.
    if status == 1 && revents & libc::POLLIN != 0 && revents & !(libc::POLLIN | libc::POLLHUP) == 0
    {
        return Ok(true);
    }
    Err(format!(
        "owner-loss pidfd observation failed: poll={status}, revents={revents}"
    ))
}
