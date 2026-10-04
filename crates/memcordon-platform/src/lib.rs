//! Native supervision backends and capability reporting.
//!
//! Linux and Windows can provide sealed supervision through their installed,
//! qualified companion providers. Other backends reject a sealed request
//! before target authorization.

#![deny(unsafe_op_in_unsafe_fn)]

mod backend;
#[cfg(all(unix, not(target_os = "macos")))]
mod guardian;
#[cfg(target_os = "linux")]
mod linux_cgroup;
#[cfg(target_os = "macos")]
mod macos_deadline;
#[cfg(target_os = "macos")]
mod macos_envelope;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use macos_deadline::continuous_nanos as macos_continuous_nanos;
#[cfg(target_os = "macos")]
mod macos_launch;
#[cfg(target_os = "macos")]
mod macos_result_delivery;
#[cfg(target_os = "macos")]
mod macos_result_frame;
#[cfg(target_os = "macos")]
pub use macos_launch::LaunchRuntime as MacosLaunchRuntime;
#[cfg(target_os = "macos")]
pub use macos_result_delivery::{
    DeliveryLimits, DeliveryObservation, DeliveryOutcome, DeliveryRequest, DeliveryStage,
    MacosDeliveryRuntime, WriterImage,
};
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use macos_result_frame::WriterFrame;
#[cfg(target_os = "macos")]
mod macos_watchdog;
#[cfg(target_os = "macos")]
pub use macos_launch::enveloped_helper as macos_enveloped_helper;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use macos_launch::helper as macos_helper;
#[cfg(target_os = "macos")]
#[doc(hidden)]
pub use macos_launch::inspector_helper as macos_inspector;
#[cfg(any(target_os = "linux", target_os = "windows"))]
mod sealed;
#[cfg(all(target_os = "linux", feature = "test-support"))]
#[doc(hidden)]
pub use sealed::client::NativeByteRelayProbe;
#[cfg(target_os = "linux")]
pub use sealed::client::{private_discovery, private_plan};
#[cfg(target_os = "windows")]
pub use sealed::windows::{
    converge_windows_recovery, observe_windows_guardian_attempt, recover_windows_attempt,
};
mod signal;
mod supervisor;
/// Resolve an exact workload declaration with the authenticated provider without
/// creating an attempt or reserving target resources.
pub fn workload_plan(
    contract: &memcordon_core::workload_contract::WorkloadContractV1,
) -> Result<memcordon_core::workload_evidence::RuntimeWorkloadResolution, String> {
    #[cfg(target_os = "linux")]
    {
        sealed::client::workload_plan(contract)
    }
    #[cfg(target_os = "windows")]
    {
        sealed::windows::workload_plan(contract)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = contract;
        Err("authenticated workload planning is unavailable on this platform".into())
    }
}
/// Read caller-filtered profiles and exact grant/plan references without allocating an attempt.
pub fn workload_discovery() -> Result<memcordon_core::workload_discovery::WorkloadDiscovery, String>
{
    #[cfg(target_os = "linux")]
    {
        sealed::client::workload_discovery()
    }
    #[cfg(target_os = "windows")]
    {
        sealed::windows::workload_discovery()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err("authenticated sealed workload discovery is unsupported on this platform".into())
    }
}
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod unix_watchdog;
#[cfg(target_os = "windows")]
pub mod windows_file;
#[cfg(target_os = "windows")]
mod windows_job;
#[cfg(all(target_os = "windows", feature = "test-support"))]
mod windows_stack_diagnostics;
#[cfg(all(target_os = "windows", feature = "test-support"))]
#[doc(hidden)]
pub use windows_stack_diagnostics::WindowsStackPhaseCaptureGuard;

pub use backend::{
    BackendCleanupFacts, BackendInfo, BoundaryReadiness, BoundarySupport, Execution, ProbeReport,
    SealedAvailability, cleanup_stale, probe, run,
};
#[cfg(target_os = "macos")]
pub use signal::{CallerSignalSnapshot, CancellationHandle};
#[cfg(target_os = "windows")]
pub use supervisor::certify_windows_platform_mutant;
pub use supervisor::{
    AttemptContext, AttemptExecution, SupervisorRequest, capabilities, capabilities_for, supervise,
};
#[cfg(target_os = "macos")]
pub use supervisor::{MacosExecutionContext, macos_supervise_from};
