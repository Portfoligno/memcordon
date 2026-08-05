use std::time::Duration;

use memcordon_core::{CommandSpec, Error, ErrorCategory, Policy, RunOutcome};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct BackendInfo {
    pub name: &'static str,
    pub containment_supported: bool,
    pub memory_supported: bool,
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
    pub authorization_offset: Option<Duration>,
    pub cleanup_facts: BackendCleanupFacts,
}

#[derive(Clone, Debug, Default)]
pub struct BackendCleanupFacts {
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub helpers_reaped: bool,
    pub containment_removed: bool,
    pub containment_incapable_of_live_members: bool,
    pub errors: Vec<String>,
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

#[cfg(target_os = "linux")]
#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(
    policy: Policy,
    command: &CommandSpec,
    memcordon_executable: &std::path::Path,
) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }

    let signal = crate::signal::SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    crate::linux_cgroup::run_attempt(
        policy,
        command,
        memcordon_executable,
        &signal,
        crate::supervisor::AttemptContext {
            supervision_offset: Duration::ZERO,
            supervision_deadline_remaining: None,
        },
    )
}

#[cfg(target_os = "macos")]
#[allow(clippy::result_large_err)]
pub fn run(
    policy: Policy,
    command: &CommandSpec,
    memcordon_executable: &std::path::Path,
) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }
    let signal = crate::signal::SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    crate::macos_watchdog::run_attempt(
        policy,
        command,
        memcordon_executable,
        &signal,
        crate::supervisor::AttemptContext {
            supervision_offset: Duration::ZERO,
            supervision_deadline_remaining: None,
        },
    )
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(policy: Policy, command: &CommandSpec) -> Result<Execution, Error> {
    if policy.poll_interval < Duration::from_millis(10) {
        return Err(Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-POLL-INTERVAL",
            "watchdog poll interval must be at least 10ms",
        ));
    }

    #[cfg(target_os = "windows")]
    {
        let console = crate::windows_job::ConsoleControl::install().map_err(|error| {
            Error::new(ErrorCategory::Setup, "MCSETUP-CONSOLE", error.to_string())
                .with_os_error(&error)
        })?;
        crate::windows_job::run_attempt(
            policy,
            command,
            &console,
            crate::supervisor::AttemptContext {
                supervision_offset: Duration::ZERO,
                supervision_deadline_remaining: None,
            },
        )
    }
    #[cfg(all(unix, not(target_os = "macos")))]
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

#[allow(
    clippy::result_large_err,
    reason = "the cleanup boundary preserves the public categorized Error contract"
)]
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
