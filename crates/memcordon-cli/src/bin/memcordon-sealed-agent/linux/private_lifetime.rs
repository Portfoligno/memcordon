//! Native descendant reaping by the owning init, before PID namespace exit.

use crate::request::Lifetime;

/// Returning from command lifetime is not cleanup proof: the caller must
/// still exit its owned namespace and the provider must observe retirement.
pub fn reap_private_descendants(lifetime: Lifetime) -> Result<usize, String> {
    let flags = match lifetime {
        Lifetime::Command => libc::WNOHANG,
        Lifetime::Workload => 0,
    };
    let mut reaped = 0_usize;
    loop {
        // SAFETY: this init owns the namespace children; waitpid only observes
        // their native status and does not act on an externally supplied PID.
        let pid = unsafe { libc::waitpid(-1, std::ptr::null_mut(), flags) };
        if pid > 0 {
            reaped += 1;
        } else if pid == 0 {
            return Ok(reaped);
        } else {
            let error = std::io::Error::last_os_error();
            match error.raw_os_error() {
                Some(libc::EINTR) => continue,
                Some(libc::ECHILD) => return Ok(reaped),
                _ => return Err(format!("MCSEALED-PRIVATE-INIT: descendant wait: {error}")),
            }
        }
    }
}
