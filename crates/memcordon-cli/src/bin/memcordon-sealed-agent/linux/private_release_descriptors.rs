//! Target-side post-exec descriptor witness for one release-matrix case.
//! The owner separately verifies the gated table before its release byte.

use std::ffi::CStr;

pub(crate) const SELECTOR: &str = "private_tcp::descriptor_table_and_stdio_bound";

pub(crate) fn expected_projection() -> [u8; 4] {
    [3, 1, 1, 1]
}

pub(crate) fn observe_target_projection() -> Result<[u8; 4], String> {
    for (fd, direction) in [
        (0, libc::O_RDONLY),
        (1, libc::O_WRONLY),
        (2, libc::O_WRONLY),
    ] {
        super::descriptor_custody::verify_pipe_end(fd, direction)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE-FIXTURE: stdio {fd}: {error}"))?;
        // SAFETY: F_GETFD only queries the live fixed descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC != 0 {
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: stdio descriptor flags differ".into());
        }
    }
    for fd in [3, 4] {
        // SAFETY: F_GETFD does not mutate the fd table. The gated control and
        // pinned ELF slots must have closed on target execveat.
        if unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1
            || std::io::Error::last_os_error().raw_os_error() != Some(libc::EBADF)
        {
            return Err(
                "MCSEALED-PRIVATE-RELEASE-FIXTURE: transient gated fd survived exec".into(),
            );
        }
    }
    // SAFETY: opendir opens the target's own proc fd directory. The closure
    // below runs to completion before closedir releases this one observer fd.
    let directory = unsafe { libc::opendir(c"/proc/self/fd".as_ptr()) };
    if directory.is_null() {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE-FIXTURE: fd inventory: {}",
            std::io::Error::last_os_error()
        ));
    }
    let observed = (|| -> Result<[u8; 4], String> {
        // SAFETY: directory is a live DIR from opendir.
        let observer_fd = unsafe { libc::dirfd(directory) };
        if observer_fd < 3 {
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: observer fd overlaps stdio".into());
        }
        let mut seen = [false; 3];
        loop {
            // SAFETY: Linux exposes this thread's errno location. Clearing it
            // distinguishes readdir EOF from a failed enumeration.
            unsafe { *libc::__errno_location() = 0 };
            // SAFETY: directory stays live through this loop; readdir's name
            // is copied to a Rust string before the next call.
            let entry = unsafe { libc::readdir(directory) };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: fd enumeration failed".into());
                }
                break;
            }
            // SAFETY: POSIX dirent d_name is NUL terminated for a live entry.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }
                .to_str()
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: fd name differs")?;
            if name == "." || name == ".." {
                continue;
            }
            let fd: i32 = name
                .parse()
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: nonnumeric fd leaf")?;
            if fd == observer_fd {
                continue;
            }
            let index: usize = fd
                .try_into()
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE-FIXTURE: negative fd leaf")?;
            let slot = seen
                .get_mut(index)
                .ok_or("MCSEALED-PRIVATE-RELEASE-FIXTURE: inherited descriptor leaked")?;
            if *slot {
                return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: duplicate fd leaf".into());
            }
            *slot = true;
        }
        if seen != [true; 3] {
            return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: stdio inventory incomplete".into());
        }
        Ok(expected_projection())
    })();
    // SAFETY: directory was opened exactly once and is no longer used.
    if unsafe { libc::closedir(directory) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE-FIXTURE: fd observer close failed".into());
    }
    observed
}
