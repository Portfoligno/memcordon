//! Native supervision backends and capability reporting.
//!
//! Linux and Windows can provide sealed supervision through their installed,
//! qualified companion providers. Other backends reject a sealed request
//! before target authorization.

#![deny(unsafe_op_in_unsafe_fn)]

mod backend;
#[cfg(unix)]
mod guardian;
#[cfg(target_os = "linux")]
mod linux_cgroup;
#[cfg(target_os = "macos")]
mod macos_watchdog;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod sealed;
mod signal;
mod supervisor;
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod unix_watchdog;
#[cfg(target_os = "windows")]
mod windows_job;

pub use backend::{
    BackendCleanupFacts, BackendInfo, BoundaryQualification, BoundarySupport, Execution,
    ProbeReport, SealedAvailability, cleanup_stale, probe, run,
};
#[cfg(target_os = "windows")]
pub use supervisor::certify_windows_platform_mutant;
pub use supervisor::{
    AttemptContext, AttemptExecution, SupervisorRequest, capabilities, capabilities_for, supervise,
};
