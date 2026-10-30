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
#[cfg(target_os = "linux")]
mod linux_cgroup_retirement;
#[cfg(target_os = "linux")]
mod linux_owned_descriptor;
#[cfg(target_os = "linux")]
pub use linux_cgroup_retirement::{LinuxCgroupRetirement, linux_cgroup_retirement};
#[cfg(target_os = "linux")]
#[doc(hidden)]
pub use linux_owned_descriptor::checked_close as linux_checked_close;
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
#[cfg(feature = "test-support")]
#[doc(hidden)]
pub mod startup_cleanup_observation;
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
pub use sealed::client::{
    WorkloadFrontendRequest, acknowledge_workload_attempt, recover_workload_attempt,
};
#[cfg(target_os = "windows")]
pub use sealed::windows::{
    AuthenticatedWindowsTerminalObservation, MAX_TERMINAL_OBSERVATION_BYTES,
    WindowsPreparedObservationScope, WindowsTerminalObservationScope, converge_windows_recovery,
    observe_windows_guardian_attempt, recover_windows_attempt,
    recover_windows_attempt_with_request,
};
mod signal;
#[cfg(all(target_os = "windows", feature = "test-support"))]
pub use sealed::windows::observe_windows_owner_request;
#[cfg(unix)]
pub mod workload_outputs;
pub mod workload_transport;

pub fn current_workload_profile_installed() -> bool {
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    {
        return sealed::current_profile_installed();
    }
    #[allow(unreachable_code)]
    false
}
#[cfg(all(target_os = "windows", feature = "test-support"))]
#[doc(hidden)]
pub use sealed::windows::{
    WindowsCertificationObservation, WindowsCertificationScope, WindowsCertificationSelection,
    WindowsLoaderDiagnosticObservation, WindowsLoaderDiagnosticScope,
    direct_runtime_volume_target_for_test, open_protected_runtime_for_test,
    protected_runtime_descriptor_for_test, runtime_security_descriptor_bounds_for_test,
};
mod supervisor;
#[cfg(feature = "test-support")]
pub mod test_support;
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
mod unix_watchdog;
#[cfg(target_os = "windows")]
pub mod windows_file;
#[cfg(windows)]
mod windows_io_deadline;
#[cfg(target_os = "windows")]
mod windows_job;
#[cfg(windows)]
pub use windows_io_deadline::SynchronousIoDeadline as WindowsSynchronousIoDeadline;
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
