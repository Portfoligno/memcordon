//! Held namespace-init status evidence required before Completed.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub(super) fn require_target_status(
    observed: &mut Option<i32>,
    channel: &mut Option<File>,
    deadline: Option<Instant>,
) -> Result<(), String> {
    if observed.is_none() {
        let observation_limit = Instant::now() + Duration::from_secs(1);
        let observation_deadline = deadline.map_or(observation_limit, |original| {
            original.min(observation_limit)
        });
        *observed = channel
            .take()
            .map(|status| read_status_until(status, observation_deadline))
            .transpose()?
            .flatten();
    }
    if observed.is_none() {
        return Err(
            "MCSEALED-PRIVATE-MONITOR: retained namespace init exited without actual target wait status"
                .into(),
        );
    }
    Ok(())
}

pub(super) fn read_status_until(status: File, deadline: Instant) -> Result<Option<i32>, String> {
    let fd = status.as_raw_fd();
    // SAFETY: F_GETFL/F_SETFL act on the provider-only status read end. The
    // init holds a separate write-end file description.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-OWNER: status nonblocking: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut bytes = [0_u8; 4];
    let mut read_bytes = 0_usize;
    while read_bytes < bytes.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-OWNER: status deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll synchronously borrows one live status descriptor.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if ready <= 0 || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("MCSEALED-PRIVATE-OWNER: status poll failed".into());
        }
        // SAFETY: read writes only the remaining initialized stack buffer.
        let count = unsafe {
            libc::read(
                fd,
                bytes[read_bytes..].as_mut_ptr().cast(),
                bytes.len() - read_bytes,
            )
        };
        if count > 0 {
            read_bytes += count as usize;
        } else if count == 0 {
            return if read_bytes == 0 {
                Ok(None)
            } else {
                Err("MCSEALED-PRIVATE-OWNER: partial target status".into())
            };
        } else if !matches!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN | libc::EINTR)
        ) {
            return Err(format!(
                "MCSEALED-PRIVATE-OWNER: status read: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    let status = i32::from_be_bytes(bytes);
    if !libc::WIFEXITED(status) && !libc::WIFSIGNALED(status) {
        return Err(
            "MCSEALED-PRIVATE-OWNER: target status is not a native terminal wait status".into(),
        );
    }
    Ok(Some(status))
}
