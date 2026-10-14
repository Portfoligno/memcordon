//! Test injection borrows the actual child owner and never consumes wait status.
use super::{Child, ChildOwner};
use std::io;
use std::time::Instant;

pub fn classify_stop(expected: i32, observed: i32, code: i32, signal: i32) -> io::Result<bool> {
    if expected <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid owned stop identity",
        ));
    }
    if observed == 0 {
        return Ok(false);
    }
    if observed == expected && code == libc::CLD_STOPPED && signal == libc::SIGSTOP {
        return Ok(true);
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "owned stop mismatch: expected={expected}; observed={observed}; code={code}; signal={signal}"
        ),
    ))
}

pub(super) fn stop_owned(child: &Child, deadline: Instant) -> io::Result<()> {
    let ChildOwner::Local(local) = &child.owner else {
        return Err(io::Error::other(
            "stop injection requires local child ownership",
        ));
    };
    if child.status.is_some() || !local.retirement.owns_child() {
        return Err(io::Error::other(
            "stop injection requires exact unreaped Owned ticket",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned stop setup deadline expired",
        ));
    }
    // A logical ticket alone cannot detect a contract-violating external
    // waiter. Reuse the native WNOWAIT preflight, which charges actual ECHILD.
    if child.observe_until(deadline)?.is_some() {
        return Err(io::Error::other(
            "stop injection requires a live unreaped child",
        ));
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned stop native preflight expired",
        ));
    }
    // SAFETY: borrowed LocalChild retains exact unreaped wait ownership, and
    // the runtime cannot claim an Owned ticket until this borrower is gone.
    if unsafe { libc::kill(local.kernel.pid, libc::SIGSTOP) } != 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned stop acknowledgment expired",
            ));
        }
        if !local.retirement.owns_child() {
            return Err(io::Error::other("owned stop ticket changed"));
        }
        let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
        // SAFETY: exact locally owned child, initialized output; WNOWAIT never
        // transfers/reaps its wait obligation or authorizes a later PID signal.
        if unsafe {
            libc::waitid(
                libc::P_PID,
                local.kernel.pid as libc::id_t,
                info.as_mut_ptr(),
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            if error.raw_os_error() == Some(libc::ECHILD) {
                local.retirement.ownership_lost(&error);
            }
            return Err(error);
        }
        // SAFETY: successful waitid initialized the zeroed native output.
        let info = unsafe { info.assume_init() };
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned stop acknowledgment expired after observation",
            ));
        }
        if classify_stop(local.kernel.pid, info.si_pid, info.si_code, info.si_status)? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned stop confirmation expired",
                ));
            }
            return Ok(());
        }
        std::thread::yield_now();
    }
}
