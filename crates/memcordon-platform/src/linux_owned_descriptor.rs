//! Checked retirement of a uniquely owned Linux file descriptor.
#![cfg(target_os = "linux")]

use std::io;
use std::os::fd::{IntoRawFd, OwnedFd};

/// Consume the owner and observe the actual native close result once.
///
/// A failed Linux close does not permit safely re-adopting or retrying the raw
/// descriptor: its number may already have been released and reused. Callers
/// must preserve the error as cleanup uncertainty rather than invent an owner.
pub fn checked_close(descriptor: OwnedFd) -> io::Result<()> {
    let raw = descriptor.into_raw_fd();
    // SAFETY: the unique OwnedFd was consumed immediately above. No surviving
    // Rust owner may close this descriptor, and this call is never retried.
    let result = unsafe { libc::close(raw) };
    if result == -1 {
        let error = io::Error::last_os_error();
        Err(error)
    } else {
        Ok(())
    }
}
