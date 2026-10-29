//! Kernel process identity and current native allocation phases.
use serde::{Deserialize, Serialize};
use std::os::fd::{AsRawFd, BorrowedFd};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateAttemptPhase {
    Allocated,
    BoundaryCreated,
    GuardianReady,
    TargetGated,
    ReleaseIntent,
    ExecutionObserved,
    Retiring,
    Retired,
    CleanupIncomplete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentityV4 {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MixedDirectoryIdentityV2 {
    pub device: u64,
    pub inode: u64,
}

impl ProcessIdentityV4 {
    pub fn observe(pid: libc::pid_t, pidfd: BorrowedFd<'_>) -> Result<Self, String> {
        if pid <= 0 {
            return Err("native process PID is invalid".into());
        }
        let path = std::path::Path::new("/proc/self/fdinfo").join(pidfd.as_raw_fd().to_string());
        let info = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
        let bound = info
            .lines()
            .find_map(|line| line.strip_prefix("Pid:").map(str::trim))
            .ok_or("pidfd lacks kernel PID binding")?
            .parse::<libc::pid_t>()
            .map_err(|e| e.to_string())?;
        if bound != pid {
            return Err("pidfd differs from selected process".into());
        }
        let mut poll = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized descriptor record, with a zero timeout.
        if unsafe { libc::poll(&raw mut poll, 1, 0) } != 0 || poll.revents != 0 {
            return Err("selected process is no longer live".into());
        }
        let start_time = super::envelope::process_start_time(pid)?;
        // SAFETY: the same borrowed pidfd remains held throughout observation.
        if unsafe { libc::poll(&raw mut poll, 1, 0) } != 0 || poll.revents != 0 {
            return Err("selected process exited during identity readback".into());
        }
        Ok(Self {
            pid: pid as u32,
            start_time,
        })
    }
}
