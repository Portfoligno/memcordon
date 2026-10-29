//! Query-only custody of the original root control worker. Never signals it.
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

pub(super) struct ControlQueryOwner {
    pidfd: OwnedFd,
}
impl ControlQueryOwner {
    pub(super) fn capture(
        expected: &memcordon_core::execution_facts::NativeProcessV2,
    ) -> Result<Self, String> {
        let pid = i32::try_from(expected.pid).map_err(|_| "control PID exceeds native range")?;
        if pid <= 0 {
            return Err("control identity is absent".into());
        }
        // SAFETY: pidfd_open returns a query/poll handle to this exact process.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        // SAFETY: successful pidfd_open returned one fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let path = Path::new("/proc")
            .join(expected.pid.to_string())
            .join("stat");
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|error| error.to_string())?
            .take(64 * 1024)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        let end = bytes
            .iter()
            .rposition(|byte| *byte == b')')
            .ok_or("control process stat command field absent")?;
        let tail = bytes
            .get(end..)
            .and_then(|tail| tail.strip_prefix(b") "))
            .ok_or("control process stat suffix malformed")?;
        const STATE_FIELD: usize = 3;
        const STARTTIME_FIELD: usize = 22;
        let value = tail
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .nth(STARTTIME_FIELD - STATE_FIELD)
            .ok_or("control process birth field absent")?;
        let birth = std::str::from_utf8(value)
            .map_err(|error| error.to_string())?
            .parse::<u64>()
            .map_err(|error| error.to_string())?;
        if birth != expected.birth {
            return Err("control process birth differs from original association".into());
        }
        Ok(Self { pidfd })
    }

    pub(super) fn settled(&self) -> Result<bool, String> {
        let mut descriptor = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the held pidfd and writable pollfd remain live through poll.
        if unsafe { libc::poll(&raw mut descriptor, 1, 0) } < 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err("original control pidfd became invalid".into());
        }
        Ok(descriptor.revents & libc::POLLIN != 0)
    }
    pub(super) fn wait(
        &self,
        cutoff: Instant,
        mut step: impl FnMut() -> Result<(), String>,
    ) -> Result<(), String> {
        loop {
            if self.settled()? {
                return Ok(());
            }
            if Instant::now() >= cutoff {
                return Err(
                    "original control worker handle custody did not settle before cleanup cutoff"
                        .into(),
                );
            }
            step()?;
            let mut descriptor = libc::pollfd {
                fd: self.pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            let duration = cutoff
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20));
            let timeout = i32::try_from(duration.as_millis())
                .map_err(|_| "control poll duration exceeds range")?;
            // SAFETY: this polls only the held process descriptor, without signal rights.
            if unsafe { libc::poll(&raw mut descriptor, 1, timeout) } < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
    }
}
