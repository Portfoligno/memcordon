use std::time::Duration;

use memcordon_core::{CommandSpec, Error, ErrorCategory, Policy, RunOutcome};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct BackendInfo {
    pub name: &'static str,
    pub class: &'static str,
    pub metric: &'static str,
    pub hard_limit: bool,
    pub startup_containment: &'static str,
    pub limitations: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ProbeReport {
    pub selected: Option<BackendInfo>,
    pub available: Vec<BackendInfo>,
    pub unavailable: Vec<UnavailableBackend>,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnavailableBackend {
    pub name: &'static str,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Execution {
    pub outcome: RunOutcome,
    pub backend: BackendInfo,
    pub child_pid: u32,
    pub duration: Duration,
}

pub fn probe() -> ProbeReport {
    #[cfg(target_os = "macos")]
    {
        let backend = crate::macos_watchdog::info();
        ProbeReport {
            selected: Some(backend.clone()),
            available: vec![backend],
            unavailable: vec![UnavailableBackend {
                name: "kernel-backed",
                reason: "macOS has no supported public aggregate workload memory controller"
                    .to_owned(),
            }],
        }
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux_cgroup::probe()
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows_job::probe()
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        crate::unix_watchdog::probe()
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        ProbeReport {
            selected: None,
            available: Vec::new(),
            unavailable: vec![UnavailableBackend {
                name: "platform",
                reason: "this target is not supported".to_owned(),
            }],
        }
    }
}

pub fn run(policy: Policy, command: &CommandSpec) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }

    #[cfg(target_os = "macos")]
    {
        crate::macos_watchdog::run(policy, command)
    }
    #[cfg(target_os = "linux")]
    {
        crate::linux_cgroup::run(policy, command)
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows_job::run(policy, command)
    }
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    {
        crate::unix_watchdog::run(policy, command)
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (policy, command);
        Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-PLATFORM",
            "this target is not supported",
        ))
    }
}

pub fn cleanup_stale(dry_run: bool) -> Result<Vec<String>, Error> {
    #[cfg(target_os = "linux")]
    {
        crate::linux_cgroup::cleanup_stale(dry_run)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dry_run;
        Ok(Vec::new())
    }
}
