//! Held namespace-init status evidence required before Completed.
use std::fs::File;
use std::io::Write;
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

pub(super) fn wait_and_publish_target_status(
    child: libc::pid_t,
    writer: &mut File,
) -> Result<i32, String> {
    if child <= 0 {
        return Err("MCSEALED-PRIVATE-INIT: invalid exact target child".into());
    }
    let raw = loop {
        let mut raw = 0;
        // SAFETY: trusted init alone owns this exact direct child's wait.
        let waited = unsafe { libc::waitpid(child, &raw mut raw, 0) };
        if waited == child {
            break raw;
        }
        if waited == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-INIT: exact target wait failed: errno={:?}; {error}",
                error.raw_os_error()
            ));
        }
        return Err(format!(
            "MCSEALED-PRIVATE-INIT: exact target wait returned unexpected child {waited}"
        ));
    };
    if !libc::WIFEXITED(raw) && !libc::WIFSIGNALED(raw) {
        return Err("MCSEALED-PRIVATE-INIT: exact target wait is not terminal".into());
    }
    writer.write_all(&raw.to_be_bytes()).map_err(|error| {
        format!(
            "MCSEALED-PRIVATE-INIT: publish actual target status: errno={:?}; {error}",
            error.raw_os_error()
        )
    })?;
    Ok(raw)
}

pub(super) fn publish_target_before_descendant_drain(
    child: libc::pid_t,
    writer: &mut File,
    drain: impl FnOnce() -> Result<(), String>,
) -> Result<i32, String> {
    let raw = wait_and_publish_target_status(child, writer)?;
    drain()?;
    Ok(raw)
}

pub(super) fn bounded_retirement_detail(detail: &str, limit: usize) -> String {
    if detail.len() <= limit {
        return detail.to_owned();
    }
    let marker = "...[truncated]...";
    let available = limit
        .checked_sub(marker.len())
        .filter(|available| *available > 0)
        .expect("retirement diagnostic bound must accommodate truncation marker");
    let mut head = available * 2 / 3;
    while !detail.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = detail.len() - (available - available * 2 / 3);
    while !detail.is_char_boundary(tail) {
        tail += 1;
    }
    format!("{}{}{}", &detail[..head], marker, &detail[tail..])
}

pub(super) fn capture_target_status_until(
    observed: &mut Option<i32>,
    channel: &mut Option<File>,
    deadline: Instant,
) -> Result<Option<i32>, String> {
    if let Some(raw) = *observed {
        return Ok(Some(raw));
    }
    let captured = match channel.take() {
        Some(status) => read_status_until(status, deadline)?,
        None => None,
    };
    *observed = captured;
    Ok(captured)
}

pub(super) fn preserve_status_through_containment<T>(
    captured: Result<T, String>,
    contain: impl FnOnce() -> Result<(), String>,
) -> Result<T, String> {
    // Never let status loss bypass the existing immediate containment action,
    // even when its original observation deadline has already expired.
    let containment = contain();
    match (captured, containment) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(status), Ok(())) => Err(bounded_retirement_detail(&status, 256)),
        (Ok(_), Err(cleanup)) => Err(bounded_retirement_detail(&cleanup, 1024)),
        (Err(status), Err(cleanup)) => Err(format!(
            "{}; native containment also failed: {}",
            bounded_retirement_detail(&status, 256),
            bounded_retirement_detail(&cleanup, 1024)
        )),
    }
}

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
