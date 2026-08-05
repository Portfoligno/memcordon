#![deny(unsafe_op_in_unsafe_fn)]

mod backend;
#[cfg(unix)]
mod guardian;
#[cfg(target_os = "linux")]
mod linux_cgroup;
#[cfg(target_os = "macos")]
mod macos_watchdog;
mod signal;
mod supervisor;
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod unix_watchdog;
#[cfg(target_os = "windows")]
mod windows_job;

pub use backend::{
    BackendCleanupFacts, BackendInfo, Execution, ProbeReport, cleanup_stale, probe, run,
};
pub use supervisor::{
    AttemptContext, AttemptExecution, SupervisorRequest, capabilities, supervise,
};
