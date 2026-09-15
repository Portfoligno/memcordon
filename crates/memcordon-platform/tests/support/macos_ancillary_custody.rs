//! Feature-gated characterization of the production ancillary ownership parser.
use super::*;
use std::os::fd::IntoRawFd;

fn identity(fd: RawFd) -> io::Result<(libc::dev_t, libc::ino_t)> {
    let mut status = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(fd, status.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let status = unsafe { status.assume_init() };
    Ok((status.st_dev, status.st_ino))
}

fn released(fd: RawFd, expected: (libc::dev_t, libc::ino_t)) -> io::Result<()> {
    // The sentinel keeps this anonymous inode alive. Another test may reuse
    // the descriptor number, but cannot independently open the same inode.
    if identity(fd).ok() == Some(expected) {
        return Err(io::Error::other("received descriptor leaked"));
    }
    Ok(())
}

pub fn ancillary_custody_fixture() -> io::Result<()> {
    for case in [
        "truncated",
        "duplicate",
        "negative",
        "partial-header",
        "partial-word",
    ] {
        let sentinel = tempfile::tempfile()?;
        let expected = identity(sentinel.as_raw_fd())?;
        let partial = case.starts_with("partial-");
        let transferred = if partial {
            sentinel.as_raw_fd()
        } else {
            duplicate(sentinel.as_raw_fd(), 3)?.into_raw_fd()
        };
        let second = match case {
            "duplicate" => transferred,
            "negative" => -1,
            _ => sentinel.as_raw_fd(),
        };
        let words = [transferred, second];
        let payload = std::mem::size_of_val(&words);
        let space = unsafe { libc::CMSG_SPACE(payload as u32) } as usize;
        let mut ancillary = vec![0usize; space.div_ceil(std::mem::size_of::<usize>())];
        let header = ancillary.as_mut_ptr().cast::<libc::cmsghdr>();
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(payload as u32);
            std::ptr::copy_nonoverlapping(
                words.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                words.len(),
            );
        }
        let returned = match case {
            "truncated" => {
                (unsafe { libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) }) as usize
            }
            "partial-header" => std::mem::size_of::<libc::cmsghdr>() - 1,
            "partial-word" => {
                (unsafe { libc::CMSG_LEN(0) }) as usize + std::mem::size_of::<RawFd>() - 1
            }
            _ => (unsafe { libc::CMSG_LEN(payload as u32) }) as usize,
        };
        // SAFETY: only the first complete, nonnegative descriptor is transferred.
        // Repeated words have one owner; incomplete words and bytes outside the
        // returned extent convey no ownership and contain a live sentinel.
        let flags = if matches!(case, "duplicate" | "negative") {
            0
        } else {
            libc::MSG_CTRUNC
        };
        if unsafe { receive_rights(&ancillary, returned, flags) }.is_ok() {
            return Err(error());
        }
        if !partial {
            released(transferred, expected)?;
        }
        if identity(sentinel.as_raw_fd())? != expected {
            return Err(error());
        }
    }
    for count in [MAX_FDS + 2, MAX_FDS + 64] {
        let sentinel = tempfile::tempfile()?;
        let expected = identity(sentinel.as_raw_fd())?;
        let receiver = send_packet_fixture(b"custody", &vec![sentinel.as_raw_fd(); count])?;
        let (payload, rights) = receive_packet(&receiver)?;
        if payload != b"custody" || rights.len() != count {
            return Err(error());
        }
        let transferred = rights.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        for fd in &transferred {
            if identity(*fd)? != expected {
                return Err(io::Error::other("wrong received descriptor identity"));
            }
        }
        drop(rights);
        for fd in transferred {
            released(fd, expected)?;
        }
        if identity(sentinel.as_raw_fd())? != expected {
            return Err(error());
        }
    }
    Ok(())
}
