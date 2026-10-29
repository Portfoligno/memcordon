//! Native containment used only by black-box process tests.

#[cfg(target_os = "linux")]
pub fn workload_start_bytes(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    request: &memcordon_core::workload_request::WorkloadRequestV1,
    frontend: &crate::WorkloadFrontendRequest,
) -> Result<Vec<u8>, String> {
    crate::sealed::client::encode_start_for_test(policy, command, request, frontend)
}

mod ci_interrupt;
pub use ci_interrupt::{CiInterrupt, CiInterruptRegistration, CiInterruptToken};

#[cfg(target_os = "linux")]
mod linux_image_custody_transport;
#[cfg(target_os = "linux")]
pub use linux_image_custody_transport::{
    IMAGE_CUSTODY_PACKET_BOUND, ImageCustodyFdBudget, ImageCustodyPacket, ImageCustodyPeer,
    ImageCustodySocket, image_custody_current_peer, image_custody_cutoff_nanos,
    image_custody_deadline, image_custody_fd_budget, image_custody_monotonic_nanos,
    image_custody_parent_pid,
};

#[cfg(target_os = "linux")]
#[path = "private_network_source.rs"]
mod private_network_source;

#[cfg(target_os = "linux")]
#[path = "private_unix_detector.rs"]
mod private_unix_detector;

#[cfg(target_os = "linux")]
#[path = "private_host_network_source.rs"]
mod private_host_network_source;

#[cfg(target_os = "linux")]
pub use private_host_network_source::HostNetworkWatchV1;

#[cfg(not(target_os = "linux"))]
pub struct HostNetworkWatchV1 {
    pins: [(u64, u64); 4],
}
#[cfg(not(target_os = "linux"))]
impl HostNetworkWatchV1 {
    pub fn start() -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host continuity observation requires native GNU Linux",
        ))
    }
    pub fn object_pins(&self) -> &[(u64, u64); 4] {
        &self.pins
    }
    pub fn finish(self) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host continuity observation requires native GNU Linux",
        ))
    }
}

/// Actual bounded positive detector sources from isolated observer namespaces.
#[cfg(target_os = "linux")]
pub fn private_sample_unix_detector(
    challenge: [u8; 32],
) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    private_unix_detector::sample(challenge)
}

#[cfg(target_os = "linux")]
pub fn private_sample_network_namespace(
    pid: u32,
    start_ticks: u64,
) -> std::io::Result<std::collections::BTreeMap<String, Vec<u8>>> {
    private_network_source::sample(pid, start_ticks)
}

#[cfg(unix)]
pub fn private_observer_monotonic_ns() -> std::io::Result<u64> {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes one valid timespec owned by this call.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut time) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let seconds = u64::try_from(time.tv_sec).map_err(std::io::Error::other)?;
    let nanos = u64::try_from(time.tv_nsec).map_err(std::io::Error::other)?;
    if nanos >= 1_000_000_000 {
        return Err(std::io::Error::other(
            "native monotonic clock nanoseconds differ",
        ));
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or_else(|| std::io::Error::other("native monotonic clock overflow"))
}

#[cfg(target_os = "linux")]
pub fn private_observer_clock_ticks_per_second() -> std::io::Result<u64> {
    // SAFETY: sysconf queries one supported scalar without pointer operands.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    u64::try_from(ticks)
        .ok()
        .filter(|ticks| *ticks > 0)
        .ok_or_else(|| std::io::Error::other("native clock ticks query failed"))
}

/// Spawn the root-controlled public CLI gate with exact nonroot credentials
/// and retained control endpoints. Ownership ends immediately after spawn,
/// so the root parent cannot accidentally mask a child's control-socket EOF.
#[cfg(target_os = "linux")]
pub fn spawn_private_public_child(
    mut command: std::process::Command,
    uid: u32,
    gid: u32,
    gate_reader: std::os::fd::OwnedFd,
    gate_writer: std::os::fd::OwnedFd,
    reuse: Option<std::os::fd::OwnedFd>,
) -> std::io::Result<std::process::Child> {
    use std::os::fd::AsRawFd;
    if uid == 0
        || gid == 0
        || gate_reader.as_raw_fd() < 3
        || gate_writer.as_raw_fd() < 3
        || reuse.as_ref().is_some_and(|fd| fd.as_raw_fd() < 3)
    {
        return Err(std::io::Error::other(
            "public child credential/control identity differs",
        ));
    }
    // Duplicate all endpoints away from fixed destinations before fork. This
    // prevents a destination mapping from clobbering another source endpoint.
    let duplicate = |fd: &std::os::fd::OwnedFd| -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::FromRawFd;
        // SAFETY: fd is held throughout this call, and successful fcntl returns
        // a new exclusively owned descriptor with close-on-exec set.
        let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        if raw < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) })
    };
    let reader = duplicate(&gate_reader)?;
    let reuse = reuse.as_ref().map(duplicate).transpose()?;
    let writer = gate_writer.as_raw_fd();
    configure_child_setup(
        &mut command,
        ChildSetup::PublicCredentialsAndGate {
            uid,
            gid,
            reader,
            reuse,
            writer,
        },
    );
    command.spawn()
}

#[cfg(target_os = "linux")]
pub fn private_public_gate_byte(fd: i32) -> std::io::Result<u8> {
    if fd != 3 {
        return Err(std::io::Error::other("public gate descriptor differs"));
    }
    // SAFETY: read is given a valid one-byte mutable buffer. Descriptor 3 is
    // not closed here; CLOEXEC retires it at the dedicated child's exec.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut byte = 0_u8;
        let count = libc::read(fd, (&raw mut byte).cast(), 1);
        let error = std::io::Error::last_os_error();
        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if count != 1 {
            return Err(error);
        }
        Ok(byte)
    }
}

/// Retain a pidfd while independently reading the matching process starttime.
/// Duplicate one exact live descriptor and measure its socket metadata. The
/// retained pidfd and two starttime checks reject PID reuse; failure is not a
/// guessed socket type. The copied descriptor is closed on every return.
#[cfg(target_os = "linux")]
pub fn private_observe_process_socket(
    pid: u32,
    start_time: u64,
    target_fd: i32,
) -> std::io::Result<(u64, i32, i32)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::fs::MetadataExt;
    if pid == 0 || start_time == 0 || target_fd < 0 {
        return Err(std::io::Error::other("socket source identity incomplete"));
    }
    let stat_path = std::path::Path::new("/proc")
        .join(pid.to_string())
        .join("stat");
    let check = || -> std::io::Result<()> {
        let stat = std::fs::read_to_string(&stat_path)?;
        let (head, fields) = stat
            .rsplit_once(") ")
            .ok_or_else(|| std::io::Error::other("socket source stat malformed"))?;
        let (observed_pid, _) = head
            .split_once(" (")
            .ok_or_else(|| std::io::Error::other("socket source PID absent"))?;
        let observed_start = fields
            .split_whitespace()
            .nth(19)
            .ok_or_else(|| std::io::Error::other("socket source start absent"))?;
        if observed_pid.parse::<u32>().map_err(std::io::Error::other)? != pid
            || observed_start
                .parse::<u64>()
                .map_err(std::io::Error::other)?
                != start_time
        {
            return Err(std::io::Error::other("socket source identity changed"));
        }
        Ok(())
    };
    // SAFETY: each successful syscall creates one exclusively owned descriptor.
    let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw_pidfd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    check()?;
    let raw_copy =
        unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target_fd, 0) } as i32;
    if raw_copy < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let copy = unsafe { OwnedFd::from_raw_fd(raw_copy) };
    let file = std::fs::File::from(copy);
    let inode = file.metadata()?.ino();
    let measure = |option| -> std::io::Result<i32> {
        let mut value = 0_i32;
        let mut size = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: getsockopt writes only the live scalar and length slots.
        if unsafe {
            libc::getsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                option,
                (&raw mut value).cast(),
                &raw mut size,
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if size as usize != std::mem::size_of_val(&value) {
            return Err(std::io::Error::other("socket option scalar size differs"));
        }
        Ok(value)
    };
    let kind = measure(libc::SO_TYPE)?;
    let domain = measure(libc::SO_DOMAIN)?;
    check()?;
    if inode == 0 {
        return Err(std::io::Error::other("socket source inode is zero"));
    }
    Ok((inode, kind, domain))
}

/// Retain a pidfd while independently reading the matching process starttime.
/// ESRCH, disappearance, reuse, or readiness proves that recorded identity is
/// no longer running; a live matching identity returns false.
#[cfg(target_os = "linux")]
pub fn private_recorded_process_exited(pid: u32, start_time: u64) -> std::io::Result<bool> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if pid == 0 || start_time == 0 {
        return Err(std::io::Error::other("process identity incomplete"));
    }
    // SAFETY: pidfd_open reads one positive PID without signalling it.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as i32;
    if raw < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(true);
        }
        return Err(error);
    }
    // SAFETY: the successful syscall returned a new exclusively owned fd.
    let descriptor = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
    let stat = match std::fs::read_to_string(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("stat"),
    ) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(true),
        Err(error) => return Err(error),
    };
    let (header, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| std::io::Error::other("proc stat delimiter differs"))?;
    let (observed_pid, _) = header
        .split_once(" (")
        .ok_or_else(|| std::io::Error::other("proc stat header differs"))?;
    let observed_pid = observed_pid.parse::<u32>().map_err(std::io::Error::other)?;
    let observed_start = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| std::io::Error::other("proc starttime absent"))?
        .parse::<u64>()
        .map_err(std::io::Error::other)?;
    if observed_pid != pid {
        return Err(std::io::Error::other("proc stat PID differs"));
    }
    if observed_start != start_time {
        return Ok(true);
    }
    let mut poll = libc::pollfd {
        fd: descriptor.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll receives one valid retained descriptor and writable record.
    let ready = unsafe { libc::poll(&raw mut poll, 1, 0) };
    if ready < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ready == 1 && poll.revents & libc::POLLIN != 0)
}
#[cfg(target_os = "macos")]
pub use crate::macos_launch::control_fixture::{
    buffered_child_status_does_not_delay_inventory,
    complete_exec_receipt_survives_post_write_deadline,
    delayed_child_status_cannot_be_confused_with_inventory,
    delayed_child_status_retains_observation_and_reaping,
};
#[cfg(target_os = "macos")]
pub use crate::macos_launch::protocol_expectation_fixture as macos_protocol_expectation_fixture;
#[cfg(windows)]
mod windows_file_identity;
#[cfg(windows)]
pub use windows_file_identity::windows_file_identity;
#[cfg(windows)]
mod windows_trace_volume;
#[cfg(windows)]
pub use windows_trace_volume::windows_trace_volume;
#[cfg(windows)]
mod windows_reparse;
#[cfg(windows)]
pub use windows_reparse::windows_reparse_data;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod native_access;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use native_access::{UnsearchableDirectory, unsearchable_directory};
#[cfg(target_os = "macos")]
mod system_input;
#[cfg(target_os = "macos")]
pub use system_input::macos_read_only_descriptor_path;
#[cfg(target_os = "macos")]
pub fn macos_signal_installation(
    failure: Option<usize>,
    interrupt: Option<usize>,
) -> std::io::Result<Option<i32>> {
    crate::signal::SignalSource::installation_fixture(failure, interrupt)
}
#[cfg(target_os = "macos")]
pub struct MacosAdmission(crate::signal::LaunchAdmission);
#[cfg(target_os = "macos")]
impl Default for MacosAdmission {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(target_os = "macos")]
impl MacosAdmission {
    pub fn new() -> Self {
        Self(crate::signal::LaunchAdmission::Host(
            crate::CancellationHandle::new(),
        ))
    }
    pub fn record(&self, signal: i32) {
        self.0.record_for_test(signal);
    }
    pub fn commit(&self) -> std::io::Result<()> {
        self.0.commit()
    }
    pub fn interruption(&self) -> Option<i32> {
        self.0.interruption()
    }
    pub fn next_attempt(&self) {
        self.0.next_attempt();
    }
}
#[cfg(target_os = "macos")]
pub use crate::macos_deadline::retirement_mutation_probe as macos_retirement_mutation_probe;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::inspector_eof_retirement as macos_inspector_eof_retirement;

#[cfg(target_os = "macos")]
pub use crate::macos_watchdog::inventory_reconciliation as macos_inventory_reconciliation;
#[cfg(target_os = "macos")]
pub use crate::macos_watchdog::pending_inventory_turn_wait as macos_pending_inventory_turn_wait;
#[cfg(target_os = "macos")]
pub use crate::macos_watchdog::pid_inventory_reply as macos_pid_inventory_reply;

#[cfg(target_os = "macos")]
pub use crate::macos_launch::clock_jump as macos_clock_jump;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::control_flood as macos_control_flood;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_heartbeat as macos_delayed_heartbeat;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_inventory_completion as macos_delayed_inventory_completion;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_inventory_deadline as macos_delayed_inventory_deadline;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_inventory_response as macos_delayed_inventory_response;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_observed_status as macos_delayed_observed_status;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_reaped_status as macos_delayed_reaped_status;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_released_receipt as macos_delayed_released_receipt;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::delayed_retired_receipt as macos_delayed_retired_receipt;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::expired_control_request_preserves_retirement as macos_expired_control_request_preserves_retirement;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::partial_control_frame_invalidates_retirement as macos_partial_control_frame_invalidates_retirement;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::repeated_stop as macos_repeated_stop;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::resource_recovery as macos_resource_recovery;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::running_guardian_loss as macos_running_guardian_loss;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::submillisecond_deadline as macos_submillisecond_deadline;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::timer_mutation_detected as macos_timer_mutation_detected;
#[cfg(target_os = "macos")]
pub use crate::macos_launch::{
    LaunchFault as MacosLaunchFault, StartupDeadlineObservations,
    cancellation_fault as macos_cancellation_fault, disarm_timeout as macos_disarm_timeout,
    owned_stop_observation as macos_owned_stop_observation,
    rejects_protocol as macos_rejects_protocol,
    startup_deadline_fault as macos_startup_deadline_fault,
    startup_deadline_fault_observations as macos_startup_deadline_fault_observations,
    startup_deadline_observations as macos_startup_deadline_observations,
    startup_fault as macos_startup_fault,
};
#[cfg(target_os = "macos")]
pub use crate::macos_launch::{
    custody_wrapper as macos_custody_wrapper,
    guardian_inspector_wrapper as macos_guardian_inspector_wrapper,
    inspector_cancel_after_exit as macos_inspector_cancel_after_exit,
    inspector_stall as macos_inspector_stall,
};
#[cfg(target_os = "macos")]
pub use crate::macos_launch::{
    empty_inventory_query_transition as macos_empty_inventory_query_transition,
    nonempty_inventory_query_transition as macos_nonempty_inventory_query_transition,
};

#[cfg(target_os = "macos")]
pub use crate::macos_envelope::transfer_fixture as macos_envelope_transfer_fixture;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Child, Command};

#[cfg(target_os = "linux")]
use memcordon_core::ByteSize;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub birth: u128,
}

/// Capture identity only while the caller still owns this unreaped child.
#[cfg(target_os = "macos")]
pub fn macos_owned_child_identity(child: &Child) -> io::Result<ProcessIdentity> {
    process_identity(child.id())
}

/// Read-only, finite diagnostic census of the original admitted process group.
#[cfg(target_os = "macos")]
pub fn macos_owned_compile_sample(root: ProcessIdentity) -> Result<serde_json::Value, String> {
    crate::macos_watchdog::owned_compile_sample(root.pid, root.birth)
}

#[cfg(target_os = "linux")]
pub fn linux_limit_delta_is_authoritative() -> bool {
    crate::linux_cgroup::test_limit_delta()
}

#[cfg(target_os = "linux")]
pub fn linux_configure(path: &std::path::Path, limit: u64) -> io::Result<()> {
    crate::linux_cgroup::test_configure(path, ByteSize::from_bytes(limit))
}

#[cfg(target_os = "linux")]
pub fn linux_monitor_errors(path: &std::path::Path) -> bool {
    crate::linux_cgroup::test_monitor_errors(path)
}

#[cfg(target_os = "linux")]
pub fn linux_verify(path: &std::path::Path, pid: i32) -> io::Result<()> {
    crate::linux_cgroup::test_verify(path, pid)
}

#[cfg(target_os = "linux")]
pub fn linux_launcher_status(bytes: &[u8]) -> io::Result<Option<i32>> {
    crate::linux_cgroup::test_launcher_status(bytes)
}

#[cfg(target_os = "linux")]
pub fn sealed_terminal_spawn_error(
    payload: &[u8],
) -> Result<Option<memcordon_core::Error>, String> {
    let terminal = crate::sealed::client::parse_terminal(payload)?;
    let crate::sealed::client::TerminalExecStatus::Failed { class, os_code } = terminal.exec_status
    else {
        return Ok(None);
    };
    let cleanup = memcordon_core::CleanupSummary {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        errors: Vec::new(),
        ..memcordon_core::CleanupSummary::default()
    };
    let restart_safety = crate::sealed::client::terminal_restart_safety(&terminal);
    Ok(Some(crate::sealed::client::terminal_spawn_error(
        &terminal,
        class,
        os_code,
        cleanup,
        restart_safety,
    )))
}

#[cfg(target_os = "linux")]
pub fn sealed_terminal_v2_is_valid(payload: &[u8]) -> Result<(), String> {
    crate::sealed::client::parse_terminal(payload).map(|_| ())
}

#[cfg(target_os = "linux")]
pub fn sealed_readiness_is_valid(payload: &[u8]) -> Result<(), String> {
    crate::sealed::client::parse_readiness(payload).map(|_| ())
}

#[cfg(windows)]
pub fn read_windows_current_response_until(
    file: &std::fs::File,
    budget: std::time::Duration,
    progress: &mut dyn FnMut() -> std::io::Result<()>,
) -> Result<memcordon_core::WindowsProviderResponseV4, String> {
    crate::sealed::windows::read_current_response_for_test(file, budget, progress)
}

#[cfg(target_os = "linux")]
pub fn sealed_provider_pairing_is_exact(
    cli_version: &str,
    provider_version: &str,
    cli_channel: &str,
    provider_channel: &str,
) -> Result<(), String> {
    crate::sealed::client::validate_exact_provider_pairing(
        cli_version,
        provider_version,
        cli_channel,
        provider_channel,
    )
}

#[cfg(target_os = "linux")]
pub fn sealed_provider_installation_diagnostic() -> String {
    crate::sealed::client::provider_installation_error(
        "provider endpoint unavailable",
        &std::io::Error::from(std::io::ErrorKind::NotFound),
    )
}

#[cfg(target_os = "linux")]
pub fn sealed_rejection_v1(
    payload: &[u8],
) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    crate::sealed::client::parse_rejection(payload)
}

#[cfg(target_os = "linux")]
pub fn linux_launcher_status_timeout() -> io::ErrorKind {
    crate::linux_cgroup::test_launcher_status_timeout()
}

#[cfg(target_os = "linux")]
pub fn linux_probe_from_results(
    standard: Result<(), String>,
    provider: Result<(String, String), String>,
) -> crate::ProbeReport {
    crate::linux_cgroup::compose_probe(
        standard,
        provider.map(|(provider_identity, observation_digest)| {
            crate::sealed::client::ProbeReceipt {
                version: env!("CARGO_PKG_VERSION").to_owned(),
                provider_identity,
                control_service_identity: "memcordon-sealed-agent.service:v2".to_owned(),
                launcher_service_identity: "memcordon-sealed-launcher.service:v2".to_owned(),
                observation_digest,
            }
        }),
    )
}

#[cfg(target_os = "linux")]
pub fn linux_sealed_deadline_duration(
    policy: &memcordon_core::Policy,
    context: crate::AttemptContext,
    setup_elapsed: std::time::Duration,
) -> Option<std::time::Duration> {
    crate::sealed::client::effective_deadline_duration(policy, context, setup_elapsed)
}

pub fn backend_selection_matches(
    selected: &memcordon_core::BackendCapabilityReport,
    observed: &memcordon_core::BackendCapabilityReport,
    metric: memcordon_core::Metric,
) -> bool {
    crate::supervisor::test_backend_selection_matches(selected, observed, metric)
}

pub use crate::supervisor::test_supervise_backend_execution as supervise_backend_execution;
pub use crate::supervisor::test_supervise_counted_failed_attempt as supervise_counted_failed_attempt;
pub use crate::supervisor::test_supervise_failed_attempt as supervise_failed_attempt;
pub use crate::supervisor::test_validate_backend_execution as validate_backend_execution;

#[allow(clippy::result_large_err)]
pub fn backend_selection_drift_execution(
    selected: memcordon_core::BackendCapabilityReport,
    observed: memcordon_core::BackendCapabilityReport,
    metric: memcordon_core::Metric,
) -> Result<memcordon_core::SupervisionExecution, memcordon_core::Error> {
    crate::supervisor::test_backend_selection_drift_execution(selected, observed, metric)
}

#[cfg(windows)]
pub fn windows_preflight_backend_capabilities(
    observation: memcordon_core::WindowsProviderProbeV1,
) -> memcordon_core::BackendCapabilityReport {
    crate::capabilities_for(
        &crate::windows_job::info_from_probe(observation),
        memcordon_core::BoundaryRequirement::Sealed,
    )
}

#[cfg(windows)]
pub fn windows_runtime_backend_capabilities(
    observation: memcordon_core::WindowsProviderProbeV1,
) -> memcordon_core::BackendCapabilityReport {
    crate::capabilities_for(
        &crate::sealed::windows::info(observation),
        memcordon_core::BoundaryRequirement::Sealed,
    )
}

pub fn sealed_deadline_rejection_is_outside_attempt(
    policy: &memcordon_core::Policy,
    context: crate::AttemptContext,
    error: &memcordon_core::Error,
) -> bool {
    crate::supervisor::test_sealed_deadline_rejection_is_outside_attempt(policy, context, error)
}

#[cfg(windows)]
pub fn windows_encode_command_line(
    program: std::ffi::OsString,
    arguments: Vec<std::ffi::OsString>,
) -> Vec<u16> {
    let command = memcordon_core::CommandSpec::new(program).args(arguments);
    crate::windows_job::test_encode_command_line(&command)
}

#[cfg(windows)]
pub fn windows_target_remains_suspended_until_assignment() -> io::Result<bool> {
    crate::windows_job::test_target_remains_suspended_until_assignment()
}

#[cfg(windows)]
pub fn windows_kill_on_job_close() -> io::Result<bool> {
    crate::windows_job::test_kill_on_job_close()
}

#[cfg(windows)]
pub fn windows_nested_assignment() -> io::Result<bool> {
    crate::windows_job::test_nested_assignment()
}

#[cfg(windows)]
pub fn windows_assignment_failure() -> io::Result<bool> {
    crate::windows_job::test_assignment_failure()
}

#[cfg(windows)]
pub fn windows_empty_accounting_survives_consumed_zero_notification() -> io::Result<bool> {
    crate::windows_job::test_empty_accounting_survives_consumed_zero_notification()
}

#[cfg(windows)]
pub fn windows_zero_notification_outweighs_stale_accounting() -> io::Result<bool> {
    crate::windows_job::test_zero_notification_outweighs_stale_accounting()
}

#[cfg(windows)]
pub fn windows_nonempty_accounting_requires_cleanup_without_zero_notification() -> io::Result<bool>
{
    crate::windows_job::test_nonempty_accounting_requires_cleanup_without_zero_notification()
}

#[cfg(windows)]
pub fn windows_token_group_entries_range(
    byte_length: usize,
    entry_count: usize,
) -> Result<std::ops::Range<usize>, String> {
    crate::sealed::windows::checked_token_group_entries_range(byte_length, entry_count)
}

#[cfg(windows)]
pub fn windows_token_group_entries(
    storage: &[u8],
    byte_length: usize,
) -> Result<Vec<(usize, u32)>, String> {
    crate::sealed::windows::token_group_entries(storage, byte_length).map(|entries| {
        entries
            .iter()
            .map(|entry| (entry.Sid as usize, entry.Attributes))
            .collect()
    })
}

#[cfg(windows)]
pub fn windows_token_group_sid_range(
    storage: &[u8],
    byte_length: usize,
    sid_offset: usize,
) -> Result<std::ops::Range<usize>, String> {
    let sid = storage.as_ptr().wrapping_add(sid_offset).cast();
    crate::sealed::windows::checked_token_group_sid_range(storage, byte_length, sid)
}

#[cfg(windows)]
pub fn windows_token_group_storage_contains(
    storage: &[u8],
    byte_length: usize,
    expected: &[u32],
) -> Result<bool, String> {
    crate::sealed::windows::token_group_storage_contains(storage, byte_length, expected)
}

#[cfg(windows)]
pub fn windows_token_user_sid_range(
    storage: &[u8],
    byte_length: usize,
) -> Result<std::ops::Range<usize>, String> {
    crate::sealed::windows::token_user_sid(storage, byte_length).map(|sid| {
        let start = sid.as_ptr() as usize - storage.as_ptr() as usize;
        start..start + sid.len()
    })
}

#[cfg(windows)]
pub fn windows_token_user_storage_matches(
    storage: &[u8],
    byte_length: usize,
    expected: &[u32],
) -> Result<bool, String> {
    crate::sealed::windows::token_user_storage_matches(storage, byte_length, expected)
}

#[cfg(windows)]
struct WindowsTestToken(windows_sys::Win32::Foundation::HANDLE);

#[cfg(windows)]
impl Drop for WindowsTestToken {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(windows)]
pub fn windows_current_token_contains_world_sid() -> Result<bool, String> {
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TokenGroups, WinWorldSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = WindowsTestToken(token);
    let word_size = std::mem::size_of::<u32>();
    let mut expected = vec![0_u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(word_size)];
    let mut expected_byte_length = u32::try_from(expected.len() * word_size)
        .map_err(|_| "well-known SID buffer length exceeds u32".to_owned())?;
    if unsafe {
        CreateWellKnownSid(
            WinWorldSid,
            std::ptr::null_mut(),
            expected.as_mut_ptr().cast(),
            &raw mut expected_byte_length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    crate::sealed::windows::token_groups_contain(token.0, TokenGroups, &expected)
}

#[cfg(windows)]
pub fn windows_current_token_user_sid_string() -> Result<String, String> {
    use windows_sys::Win32::Security::TOKEN_QUERY;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = WindowsTestToken(token);
    crate::sealed::windows::token_user_sid_string(token.0)
}

#[cfg(not(windows))]
fn process_probe_is_absent(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::NotFound {
        return true;
    }
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::ESRCH)
    }
    #[cfg(not(unix))]
    {
        false
    }
}

impl ProcessIdentity {
    pub fn current() -> io::Result<Self> {
        Self::for_pid(std::process::id())
    }

    pub fn for_pid(pid: u32) -> io::Result<Self> {
        process_identity(pid)
    }

    pub fn still_exists(self) -> io::Result<bool> {
        #[cfg(windows)]
        {
            windows_process_identity_is_live(self)
        }
        #[cfg(not(windows))]
        match Self::for_pid(self.pid) {
            Ok(current) => Ok(current == self),
            Err(error) if process_probe_is_absent(&error) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub fn publish_to(self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        writeln!(temporary, "{} {}", self.pid, self.birth)?;
        temporary.flush()?;
        temporary
            .persist(path)
            .map(|_| ())
            .map_err(|error| error.error)
    }
}

#[cfg(windows)]
fn windows_process_identity_is_live(identity: ProcessIdentity) -> io::Result<bool> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_PARAMETER, FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        WaitForSingleObject,
    };

    // SAFETY: this query-only handle binds native birth and exit observations
    // to the same process object, even if its numeric PID is later reused.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            identity.pid,
        )
    };
    if process.is_null() {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == i32::try_from(ERROR_INVALID_PARAMETER).ok() {
            Ok(false)
        } else {
            Err(error)
        };
    }
    // SAFETY: OpenProcess returned one owned handle, closed on every exit.
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output pointers are live and the held process is queryable.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let birth = (u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime);
    if birth != identity.birth {
        return Ok(false);
    }
    // SAFETY: SYNCHRONIZE access permits a nonblocking native exit observation.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_OBJECT_0 => Ok(false),
        WAIT_TIMEOUT => Ok(true),
        _ => Err(io::Error::last_os_error()),
    }
}

/// Query-only handles retained by the Windows installed-fixture leak observer.
/// The unique staged image path keeps the observation specific to one case.
#[cfg(windows)]
pub struct WindowsImageProcess {
    pub identity: ProcessIdentity,
    _handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
#[path = "windows_thread_activity.rs"]
mod windows_thread_activity;
#[cfg(windows)]
pub use windows_thread_activity::WindowsThreadActivitySample;

#[cfg(windows)]
#[path = "windows_wait_observer.rs"]
mod windows_wait_observer;
#[cfg(windows)]
pub use windows_wait_observer::{
    WINDOWS_WAIT_OBSERVER_BOUND, WindowsWaitInherited, WindowsWaitObserver,
    WindowsWaitObserverRetirement, WindowsWaitObserverSnapshot, WindowsWaitThreadHandle,
    windows_observe_transferred_wait_cleanup, windows_unresolved_wait_owner_count,
};

#[cfg(windows)]
fn windows_process_observation_error(
    operation: &str,
    pid: Option<u32>,
    error: io::Error,
) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "native process observation {operation}; pid={pid:?}; raw-os-error={:?}; {error}",
            error.raw_os_error(),
        ),
    )
}

#[cfg(windows)]
impl WindowsImageProcess {
    /// Diagnostic-only token facts from this original retained process. A
    /// retired process or changed binding is unavailable, never a PID lookup.
    pub fn original_token_envelope(
        &self,
        deadline: std::time::Instant,
    ) -> io::Result<memcordon_core::WindowsCallerTokenEnvelopeV1> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
        use windows_sys::Win32::{
            Foundation::{FILETIME, WAIT_OBJECT_0, WAIT_TIMEOUT},
            Security::TOKEN_QUERY,
            System::Threading::{
                GetProcessId, GetProcessTimes, OpenProcessToken, WaitForSingleObject,
            },
        };
        let live = || -> io::Result<()> {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original retained token observation cutoff exhausted",
                ));
            }
            // SAFETY: query only the same retained process, never reopen its PID.
            match unsafe { WaitForSingleObject(self._handle.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        "original retained process retired before token observation completed",
                    ));
                }
                _ => return Err(io::Error::last_os_error()),
            }
            let mut birth = FILETIME::default();
            let mut exit = FILETIME::default();
            let mut kernel = FILETIME::default();
            let mut user = FILETIME::default();
            // SAFETY: complete fixed native outputs and the original query-only handle.
            let pid = unsafe { GetProcessId(self._handle.as_raw_handle()) };
            if pid == 0
                || unsafe {
                    GetProcessTimes(
                        self._handle.as_raw_handle(),
                        &mut birth,
                        &mut exit,
                        &mut kernel,
                        &mut user,
                    )
                } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let observed_birth =
                (u128::from(birth.dwHighDateTime) << 32) | u128::from(birth.dwLowDateTime);
            if pid != self.identity.pid || observed_birth != self.identity.birth {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "original retained process token binding differs",
                ));
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original retained token observation cutoff exhausted",
                ));
            }
            Ok(())
        };
        live()?;
        let mut token = std::ptr::null_mut();
        // SAFETY: TOKEN_QUERY only on the original retained hProcess; no privilege adjustment.
        if unsafe { OpenProcessToken(self._handle.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcessToken transfers exactly one native owner.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        live()?;
        let envelope = memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle())
            .map_err(io::Error::other)?;
        live()?;
        Ok(envelope)
    }

    /// Read-only diagnostic sampling of this original process object. This
    /// cannot add a process to the admitted family or prove compiler completion.
    pub fn begin_thread_activity_sample(
        &self,
        deadline: std::time::Instant,
    ) -> io::Result<WindowsThreadActivitySample> {
        windows_thread_activity::begin(&self._handle, self.identity, deadline)
    }

    /// Diagnostic-only census of direct children absent from the caller's held
    /// identities. These observations do not establish Job membership or add
    /// any process to the independently accepted family.
    pub fn diagnose_unheld_direct_children(
        &self,
        known: &[ProcessIdentity],
        deadline: std::time::Instant,
    ) -> io::Result<serde_json::Value> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, FILETIME, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
            TH32CS_SNAPPROCESS,
        };
        use windows_sys::Win32::System::Threading::{
            GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            QueryFullProcessImageNameW, WaitForSingleObject,
        };
        let error_value = |error: io::Error| {
            let detail = error.to_string();
            serde_json::json!({"kind":format!("{:?}",error.kind()),"raw_os_error":error.raw_os_error(),
                "detail":detail.chars().take(512).collect::<String>(),"detail_truncated":detail.chars().count()>512})
        };
        if std::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original child diagnostic cutoff exhausted",
            ));
        }
        if known.len() > 8192 || !known.contains(&self.identity) || self.has_exited()? {
            return Err(io::Error::other(
                "diagnostic root is not independently held live",
            ));
        }
        // SAFETY: query-only snapshot has no mutable caller-owned buffers.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful snapshot transfers one owned native handle.
        let snapshot = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(snapshot) };
        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        // SAFETY: held snapshot and correctly sized writable entry.
        let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
        if found == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut scanned = 0usize;
        let mut direct = 0usize;
        let mut unheld = 0usize;
        let mut records = Vec::new();
        let mut scan_truncated = false;
        let mut deadline_exhausted = false;
        while found != 0 {
            if std::time::Instant::now() >= deadline {
                deadline_exhausted = true;
                break;
            }
            scanned += 1;
            if scanned > 131_072 {
                scan_truncated = true;
                break;
            }
            if entry.th32ParentProcessID == self.identity.pid {
                direct += 1;
                if direct > 128 {
                    scan_truncated = true;
                    break;
                }
                let mut record = serde_json::json!({"snapshot_pid":entry.th32ProcessID,
                    "snapshot_parent_pid":entry.th32ParentProcessID});
                // SAFETY: query-only access to this enumerated candidate PID.
                let raw = unsafe {
                    OpenProcess(
                        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                        0,
                        entry.th32ProcessID,
                    )
                };
                let mut is_known = false;
                if raw.is_null() {
                    record["open_error"] = error_value(io::Error::last_os_error());
                } else {
                    // SAFETY: successful open transfers one native handle.
                    let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
                    let mut creation = FILETIME::default();
                    let mut exit = FILETIME::default();
                    let mut kernel = FILETIME::default();
                    let mut user = FILETIME::default();
                    // SAFETY: same query-capable handle and writable FILETIMEs.
                    if unsafe {
                        GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user)
                    } == 0
                    {
                        record["birth_error"] = error_value(io::Error::last_os_error());
                    } else {
                        let birth = (u64::from(creation.dwHighDateTime) << 32)
                            | u64::from(creation.dwLowDateTime);
                        let identity = ProcessIdentity {
                            pid: entry.th32ProcessID,
                            birth: u128::from(birth),
                        };
                        is_known = known.contains(&identity);
                        record["birth"] = serde_json::json!(birth);
                        record["predates_root"] =
                            serde_json::json!(identity.birth < self.identity.birth);
                        if !is_known && records.len() < 8 {
                            let candidate = WindowsImageProcess {
                                identity,
                                _handle: handle,
                            };
                            match candidate.native_parent_process_id() {
                                Ok(parent) => {
                                    record["native_parent_pid"] = serde_json::json!(parent)
                                }
                                Err(error) => record["native_parent_error"] = error_value(error),
                            }
                            let mut image = [0u16; 2048];
                            let mut units = image.len() as u32;
                            // SAFETY: same held process and bounded writable UTF16 buffer.
                            if unsafe {
                                QueryFullProcessImageNameW(raw, 0, image.as_mut_ptr(), &mut units)
                            } == 0
                            {
                                record["image_error"] = error_value(io::Error::last_os_error());
                            } else if units as usize >= image.len() {
                                record["image_error"] = serde_json::json!({"detail":"native image length exceeds diagnostic bound"});
                            } else {
                                record["image_utf16"] = serde_json::json!(&image[..units as usize]);
                            }
                            // SAFETY: original candidate handle retains SYNCHRONIZE.
                            let wait = unsafe { WaitForSingleObject(raw, 0) };
                            let wait_error = if wait == windows_sys::Win32::Foundation::WAIT_FAILED
                            {
                                Some(io::Error::last_os_error())
                            } else {
                                None
                            };
                            record["zero_wait_raw"] = serde_json::json!(wait);
                            if let Some(error) = wait_error {
                                record["wait_error"] = error_value(error);
                            }
                        }
                    }
                }
                if !is_known {
                    unheld += 1;
                    if records.len() < 8 {
                        records.push(record);
                    }
                }
            }
            // SAFETY: same held snapshot and correctly sized writable entry.
            found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
            if found == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(error);
                }
            }
        }
        let root_exited_after = self.has_exited()?;
        Ok(
            serde_json::json!({"format":"memcordon.windows-unheld-direct-child-diagnostic","revision":1,
            "root_pid":self.identity.pid,"root_birth":self.identity.birth,"root_exited_after":root_exited_after,
            "job_membership_established":false,"accepted_family_modified":false,
            "snapshot_entries_observed":scanned.min(131_072),"direct_candidates_observed":direct.min(128),
            "scan_truncated":scan_truncated,"deadline_exhausted":deadline_exhausted,
            "unheld_candidates_observed":unheld,"records_truncated":unheld>records.len(),"records":records}),
        )
    }

    /// Reads the actual creator PID from this same retained native process
    /// object. Callers must separately hold and compare the parent's birth and
    /// liveness; a PID alone is not an ancestry identity.
    pub fn native_parent_process_id(&self) -> io::Result<u32> {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)]
        struct BasicInformation {
            reserved1: usize,
            peb: usize,
            reserved2: [usize; 2],
            process_id: usize,
            parent_process_id: usize,
        }
        #[link(name = "ntdll")]
        unsafe extern "system" {
            fn NtQueryInformationProcess(
                process: windows_sys::Win32::Foundation::HANDLE,
                class: u32,
                information: *mut std::ffi::c_void,
                length: u32,
                returned: *mut u32,
            ) -> i32;
        }
        let mut information = BasicInformation {
            reserved1: 0,
            peb: 0,
            reserved2: [0; 2],
            process_id: 0,
            parent_process_id: 0,
        };
        let mut returned = 0;
        // SAFETY: the process handle remains owned by this object, class0 writes
        // only the correctly sized native-width initialized output structure.
        let status = unsafe {
            NtQueryInformationProcess(
                self._handle.as_raw_handle(),
                0,
                (&mut information as *mut BasicInformation).cast(),
                std::mem::size_of::<BasicInformation>() as u32,
                &mut returned,
            )
        };
        if status < 0 {
            return Err(io::Error::other(format!(
                "held native parent NtQueryInformationProcess(class0) failed; pid={}; NTSTATUS={status:#x}",
                self.identity.pid,
            )));
        }
        if returned as usize != std::mem::size_of::<BasicInformation>()
            || information.process_id != self.identity.pid as usize
        {
            return Err(io::Error::other(
                "held native parent query returned a different process identity",
            ));
        }
        u32::try_from(information.parent_process_id)
            .map_err(|_| io::Error::other("native parent PID exceeds DWORD width"))
    }

    /// Reads exit status from the same retained native process handle.
    pub fn native_exit_status(&self) -> io::Result<Option<u32>> {
        use std::os::windows::io::AsRawHandle;
        if !self.has_exited()? {
            return Ok(None);
        }
        let mut status = 0;
        // SAFETY: this owner retains the original queryable process handle and
        // status storage remains writable throughout this synchronous query.
        if unsafe {
            windows_sys::Win32::System::Threading::GetExitCodeProcess(
                self._handle.as_raw_handle(),
                &mut status,
            )
        } == 0
        {
            return Err(windows_process_observation_error(
                "GetExitCodeProcess",
                Some(self.identity.pid),
                io::Error::last_os_error(),
            ));
        }
        Ok(Some(status))
    }
    /// Observe retirement of the original held process, independently of PID reuse.
    pub fn has_exited(&self) -> io::Result<bool> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        // SAFETY: this owner retains a live process handle with SYNCHRONIZE access.
        match unsafe { WaitForSingleObject(self._handle.as_raw_handle(), 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(windows_process_observation_error(
                "WaitForSingleObject(process,0)",
                Some(self.identity.pid),
                io::Error::last_os_error(),
            )),
        }
    }
}

#[cfg(windows)]
pub fn windows_processes_for_image(image: &Path) -> io::Result<Vec<WindowsImageProcess>> {
    windows_processes_for_image_inner(image, None, None)
}

#[cfg(windows)]
pub fn windows_performance_counter() -> io::Result<(u64, u64)> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut frequency = 0i64;
    let mut ticks = 0i64;
    // SAFETY: both native outputs point to live correctly sized scalar storage.
    if unsafe { QueryPerformanceFrequency(&raw mut frequency) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: ticks points to live correctly sized scalar storage.
    if unsafe { QueryPerformanceCounter(&raw mut ticks) } == 0 {
        return Err(io::Error::last_os_error());
    }
    match (u64::try_from(ticks), u64::try_from(frequency)) {
        (Ok(ticks), Ok(frequency)) if frequency != 0 => Ok((ticks, frequency)),
        _ => Err(io::Error::other("invalid native performance counter")),
    }
}

#[cfg(windows)]
pub fn windows_native_work_cutoff(deadline: std::time::Instant) -> io::Result<(u64, u64)> {
    // Sample the shared native clock first: time spent transferring the budget
    // must shorten the child's deadline rather than extend the original cutoff.
    let (sampled, frequency) = windows_performance_counter()?;
    let remaining = deadline
        .checked_duration_since(std::time::Instant::now())
        .ok_or_else(|| io::Error::other("native work cutoff already expired"))?;
    let ticks = remaining
        .as_nanos()
        .checked_mul(u128::from(frequency))
        .ok_or_else(|| io::Error::other("native work cutoff conversion overflow"))?
        / 1_000_000_000;
    let ticks = u64::try_from(ticks)
        .map_err(|_| io::Error::other("native work cutoff exceeds clock range"))?;
    if ticks == 0 {
        return Err(io::Error::other(
            "native work cutoff has no whole counter ticks",
        ));
    }
    sampled
        .checked_add(ticks)
        .map(|cutoff| (cutoff, frequency))
        .ok_or_else(|| io::Error::other("native work cutoff clock overflow"))
}

#[cfg(windows)]
pub fn windows_console_host_path() -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut units = [0u16; 2048];
    // SAFETY: the native API receives the exact writable buffer capacity.
    let length = unsafe { GetSystemDirectoryW(units.as_mut_ptr(), units.len() as u32) };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= units.len() {
        return Err(io::Error::other(
            "native system directory exceeds finite bound",
        ));
    }
    let directory =
        std::path::PathBuf::from(std::ffi::OsString::from_wide(&units[..length as usize]));
    if !directory.is_absolute() {
        return Err(io::Error::other("native system directory is not absolute"));
    }
    Ok(directory.join("conhost.exe"))
}

#[cfg(windows)]
#[derive(serde::Serialize)]
pub struct WindowsHeldFileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
    pub length: u64,
}

#[cfg(windows)]
pub fn windows_held_file_identity(file: &std::fs::File) -> io::Result<WindowsHeldFileIdentity> {
    let metadata = windows_held_file_metadata(file)?;
    Ok(WindowsHeldFileIdentity {
        volume_serial: metadata.volume_serial,
        file_index: metadata.file_index,
        length: metadata.length,
    })
}

#[cfg(windows)]
pub struct WindowsHeldFileMetadata {
    pub volume_serial: u32,
    pub file_index: u64,
    pub length: u64,
    pub attributes: u32,
    pub links: u32,
}

/// Query the same retained File without exporting a native handle or changing access.
#[cfg(windows)]
pub fn windows_held_file_metadata(file: &std::fs::File) -> io::Result<WindowsHeldFileMetadata> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    // SAFETY: the plain writable output is initialized and the borrowed file remains owned.
    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the caller retains the readable file and the native output is valid.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WindowsHeldFileMetadata {
        volume_serial: information.dwVolumeSerialNumber,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        length: (u64::from(information.nFileSizeHigh) << 32) | u64::from(information.nFileSizeLow),
        attributes: information.dwFileAttributes,
        links: information.nNumberOfLinks,
    })
}

#[cfg(windows)]
struct WindowsFileOperationError {
    operation: &'static str,
    parameters: String,
    cause_text: String,
    cause: io::Error,
}

#[cfg(windows)]
impl std::fmt::Display for WindowsFileOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "native-operation={}; kind={:?}; original-raw-os-error={:?}; {}; cause={}",
            self.operation,
            self.cause.kind(),
            self.cause.raw_os_error(),
            self.parameters,
            self.cause_text
        )
    }
}

#[cfg(windows)]
impl std::fmt::Debug for WindowsFileOperationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

#[cfg(windows)]
impl std::error::Error for WindowsFileOperationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

#[cfg(windows)]
fn windows_file_operation_error(
    operation: &'static str,
    parameters: String,
    cause: io::Error,
) -> io::Error {
    fn bounded(value: &str, limit: usize) -> String {
        if value.len() <= limit {
            return value.to_owned();
        }
        let mut end = limit;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        format!("{} [omitted-bytes={}]", &value[..end], value.len() - end)
    }
    let kind = cause.kind();
    struct Prefix(String);
    const CAUSE_BOUND: usize = 512;
    impl std::fmt::Write for Prefix {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let mut end = (CAUSE_BOUND - self.0.len()).min(text.len());
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            self.0.push_str(&text[..end]);
            if end != text.len() {
                Err(std::fmt::Error)
            } else {
                Ok(())
            }
        }
    }
    let mut prefix = Prefix(String::with_capacity(CAUSE_BOUND));
    if std::fmt::write(&mut prefix, format_args!("{cause}")).is_err() {
        prefix
            .0
            .push_str(" [cause-format-incomplete; omitted-bytes=unknown]");
    }
    let cause_text = prefix.0;
    io::Error::new(
        kind,
        WindowsFileOperationError {
            operation,
            parameters: bounded(&parameters, 1024),
            cause_text,
            cause,
        },
    )
}

/// Prepare only an exclusively created writable diagnostic stage before its
/// persistent metadata snapshot; the destination is never modified here.
#[cfg(windows)]
pub fn windows_prepare_persistent_stage(
    file: &std::fs::File,
    deadline: std::time::Instant,
) -> io::Result<WindowsHeldFileMetadata> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FileBasicInfo, SetFileInformationByHandle,
    };
    let live = || {
        if std::time::Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original persistent-stage cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    };
    live()?;
    let before = windows_held_file_metadata(file).map_err(|cause| {
        windows_file_operation_error(
            "prepare-source-metadata",
            "held-source=true; metadata=unavailable".into(),
            cause,
        )
    })?;
    if before.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || before.links != 1
    {
        return Err(io::Error::other(
            "persistent stage is not an ordinary single-link held file",
        ));
    }
    let basic = FILE_BASIC_INFO {
        CreationTime: 0,
        LastAccessTime: 0,
        LastWriteTime: 0,
        ChangeTime: 0,
        FileAttributes: FILE_ATTRIBUTE_NORMAL,
    };
    live()?;
    // SAFETY: same held writable file and full native structure; zero time
    // fields preserve times while explicitly preparing persistent attributes.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileBasicInfo,
            (&basic as *const FILE_BASIC_INFO).cast(),
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        )
    } == 0
    {
        let cause = io::Error::last_os_error();
        return Err(windows_file_operation_error(
            "prepare-FileBasicInfo",
            format!(
                "class={FileBasicInfo}; native-bytes={}; selected-attributes={FILE_ATTRIBUTE_NORMAL}; source-volume={}; source-file={}; source-length={}; source-attributes={}; source-links={}; expected-caller-access=0x00110180(READ_ATTRIBUTES|WRITE_ATTRIBUTES|DELETE|SYNCHRONIZE); expected-caller-share=0x5(READ|DELETE)",
                std::mem::size_of::<FILE_BASIC_INFO>(),
                before.volume_serial,
                before.file_index,
                before.length,
                before.attributes,
                before.links
            ),
            cause,
        ));
    }
    live()?;
    let after = windows_held_file_metadata(file).map_err(|cause|windows_file_operation_error(
        "prepare-post-metadata",format!("class={FileBasicInfo}; selected-attributes={FILE_ATTRIBUTE_NORMAL}; source-volume={}; source-file={}; source-length={}; source-attributes-before={}; source-links={}",before.volume_serial,before.file_index,before.length,before.attributes,before.links),cause))?;
    if (
        before.volume_serial,
        before.file_index,
        before.links,
        before.length,
    ) != (
        after.volume_serial,
        after.file_index,
        after.links,
        after.length,
    ) || after.attributes != FILE_ATTRIBUTE_NORMAL
    {
        return Err(io::Error::other(
            "held persistent stage identity or prepared attributes differ",
        ));
    }
    live()?;
    Ok(after)
}

#[cfg(windows)]
#[path = "windows_rename_status.rs"]
mod windows_rename_status;

#[cfg(windows)]
use windows_rename_status::{
    Completion as WindowsSynchronousStatus, classify as windows_synchronous_status,
};

#[cfg(windows)]
fn windows_rename_live(deadline: std::time::Instant) -> io::Result<()> {
    if std::time::Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original held rename cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn windows_rename_component(name: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;
    const NATIVE_PATH_UNITS: usize = 32768;
    let units: Vec<u16> = name.encode_wide().take(NATIVE_PATH_UNITS).collect();
    if units.is_empty()
        || units.len() >= NATIVE_PATH_UNITS
        || name == std::ffi::OsStr::new(".")
        || name == std::ffi::OsStr::new("..")
        || units.iter().any(|unit| {
            matches!(*unit, 0)
                || *unit == u16::from(b'/')
                || *unit == u16::from(b'\\')
                || *unit == u16::from(b':')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "held rename requires one bounded native filename component",
        ));
    }
    Ok(units)
}

#[cfg(windows)]
fn windows_rename_nt_error(operation: &'static str, parameters: String, status: i32) -> io::Error {
    // SAFETY: NTSTATUS translation has no pointers or ownership effects.
    let code = unsafe { windows_sys::Win32::Foundation::RtlNtStatusToDosError(status) };
    windows_file_operation_error(
        operation,
        format!("native-status={status:#010x}; {parameters}"),
        io::Error::from_raw_os_error(code as i32),
    )
}

/// A metadata/DELETE owner opened synchronously relative to its original held
/// parent. Arbitrary (possibly asynchronous) File handles cannot construct it.
#[cfg(windows)]
pub struct WindowsSynchronousRenameSource {
    source: std::fs::File,
    parent: std::fs::File,
    deadline: std::time::Instant,
}

/// Knowledge that the native rename committed. Verify only AFTER disarming
/// cleanup of the old name; a failed proof cannot undo the committed mutation.
#[cfg(windows)]
pub struct WindowsRenameCommitted {
    status: i32,
    information: usize,
    deadline: std::time::Instant,
}

#[cfg(windows)]
impl WindowsRenameCommitted {
    pub fn verify(self, deadline: std::time::Instant) -> io::Result<()> {
        if self.status != windows_sys::Win32::Foundation::STATUS_SUCCESS {
            return Err(windows_rename_nt_error(
                "rename-completed-IOSB",
                format!("committed=true; iosb-information={}", self.information),
                self.status,
            ));
        }
        windows_rename_live(self.deadline.min(deadline))
    }
}

/// Open ONLY an existing original stage, never create or follow a reparse.
/// The independent reader remains the caller's continuous byte-custody owner.
#[cfg(windows)]
pub fn windows_open_synchronous_rename_source(
    parent: &std::fs::File,
    stage_name: &std::ffi::OsStr,
    expected_readback: &std::fs::File,
    deadline: std::time::Instant,
) -> io::Result<WindowsSynchronousRenameSource> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
    use windows_sys::Wdk::Storage::FileSystem::{
        FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        NtCreateFile,
    };
    use windows_sys::Win32::Foundation::{
        INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE, UNICODE_STRING,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
    windows_rename_live(deadline)?;
    let mut units = windows_rename_component(stage_name)?;
    let length = units
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "stage name exceeds native UNICODE_STRING length",
            )
        })?;
    units.push(0);
    let maximum_length = units
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|bytes| u16::try_from(bytes).ok())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "stage name exceeds native UNICODE_STRING backing extent",
            )
        })?;
    let parent = parent.try_clone()?;
    let expected = windows_held_file_metadata(expected_readback)?;
    let parent_metadata = windows_held_file_metadata(&parent)?;
    if expected.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || expected.links != 1
        || parent_metadata.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || parent_metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || expected.volume_serial != parent_metadata.volume_serial
    {
        return Err(io::Error::other(
            "original stage/parent type, link or volume differs",
        ));
    }
    let mut name = UNICODE_STRING {
        Length: length,
        MaximumLength: maximum_length,
        Buffer: units.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: u32::try_from(std::mem::size_of::<OBJECT_ATTRIBUTES>())
            .expect("native object attributes size"),
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &raw mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: std::ptr::null_mut(),
        SecurityQualityOfService: std::ptr::null_mut(),
    };
    let mut handle = std::ptr::null_mut();
    let mut iosb = IO_STATUS_BLOCK::default();
    windows_rename_live(deadline)?;
    // SAFETY: bounded native structures remain live throughout the synchronous
    // existing-file open. Root authority is the original held parent, with no
    // inheritance, creation, data-write access or reparse-following capability.
    let status = unsafe {
        NtCreateFile(
            &raw mut handle,
            FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | DELETE | SYNCHRONIZE,
            &attributes,
            &raw mut iosb,
            std::ptr::null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    match windows_synchronous_status(status) {
        WindowsSynchronousStatus::InvariantViolation => std::process::abort(),
        WindowsSynchronousStatus::Failure => {
            if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
                // SAFETY: immediately adopt any returned owned handle, including on error.
                drop(unsafe { std::fs::File::from_raw_handle(handle) });
            }
            return Err(windows_rename_nt_error(
                "rename-source-NtCreateFile",
                format!(
                    "parent-volume={}; parent-file={}; name-units={}; access=0x00110180; share=0x5; disposition={FILE_OPEN}; synchronous=true",
                    parent_metadata.volume_serial,
                    parent_metadata.file_index,
                    units.len() - 1
                ),
                status,
            ));
        }
        WindowsSynchronousStatus::Success => {}
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "synchronous stage open returned an invalid handle",
        ));
    }
    // SAFETY: exact native success transfers its sole returned handle into RAII
    // before any fallible status, cutoff or identity verification.
    let source = unsafe { std::fs::File::from_raw_handle(handle) };
    // SAFETY: a completed synchronous open supplies the status arm of IOSB.
    let completed = unsafe { iosb.Anonymous.Status };
    if completed != windows_sys::Win32::Foundation::STATUS_SUCCESS {
        return Err(windows_rename_nt_error(
            "rename-source-completed-IOSB",
            format!("iosb-information={}", iosb.Information),
            completed,
        ));
    }
    windows_rename_live(deadline)?;
    let actual = windows_held_file_metadata(&source)?;
    let retained = windows_held_file_metadata(expected_readback)?;
    let stamp = |value: &WindowsHeldFileMetadata| {
        (
            value.volume_serial,
            value.file_index,
            value.length,
            value.attributes,
            value.links,
        )
    };
    if stamp(&actual) != stamp(&expected) || stamp(&retained) != stamp(&expected) {
        return Err(io::Error::other(
            "synchronous stage differs from original held readback",
        ));
    }
    windows_rename_live(deadline)?;
    Ok(WindowsSynchronousRenameSource {
        source,
        parent,
        deadline,
    })
}

#[cfg(windows)]
impl WindowsSynchronousRenameSource {
    pub fn as_file(&self) -> &std::fs::File {
        &self.source
    }

    /// Atomically rename relative to the original parent through the closed
    /// synchronous owner. Caller must disarm old-name cleanup immediately on Ok.
    #[cfg(windows)]
    pub fn rename(
        &self,
        target_name: &std::ffi::OsStr,
        deadline: std::time::Instant,
    ) -> io::Result<WindowsRenameCommitted> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Wdk::Storage::FileSystem::{
            FILE_RENAME_INFORMATION, FILE_RENAME_INFORMATION_0, FILE_RENAME_POSIX_SEMANTICS,
            FILE_RENAME_REPLACE_IF_EXISTS, FileRenameInformationEx, NtSetInformationFile,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
        };
        use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;
        let deadline = self.deadline.min(deadline);
        let source = &self.source;
        let parent = &self.parent;
        let live = || {
            if std::time::Instant::now() >= deadline {
                Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "original held rename cutoff exhausted",
                ))
            } else {
                Ok(())
            }
        };
        live()?;
        let name = windows_rename_component(target_name)?;
        let source_metadata = windows_held_file_metadata(source).map_err(|cause| {
            windows_file_operation_error(
                "rename-source-metadata",
                "held-source=true; metadata=unavailable".into(),
                cause,
            )
        })?;
        let parent_metadata = windows_held_file_metadata(parent).map_err(|cause|windows_file_operation_error(
        "rename-parent-metadata",format!("held-parent=true; parent-metadata=unavailable; source-volume={}; source-file={}; source-length={}; source-attributes={}; source-links={}",source_metadata.volume_serial,source_metadata.file_index,source_metadata.length,source_metadata.attributes,source_metadata.links),cause))?;
        if source_metadata.attributes != FILE_ATTRIBUTE_NORMAL
            || source_metadata.links != 1
            || parent_metadata.attributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || parent_metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || source_metadata.volume_serial != parent_metadata.volume_serial
        {
            return Err(io::Error::other(
                "held rename prepared source/parent type, link or volume differs",
            ));
        }
        let invalid_extent = || {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "held rename native filename extent overflows",
            )
        };
        let name_bytes = name
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .ok_or_else(invalid_extent)?;
        let offset = std::mem::offset_of!(FILE_RENAME_INFORMATION, FileName);
        let bytes = offset
            .checked_add(name_bytes)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u16>()))
            .ok_or_else(invalid_extent)?
            .max(std::mem::size_of::<FILE_RENAME_INFORMATION>());
        let native_bytes = u32::try_from(bytes).map_err(|_| invalid_extent())?;
        // Typed allocation guarantees the native SDK structure's alignment on each
        // architecture. Checked offset/byte lengths include room for a zero terminator.
        let mut buffer = vec![
            FILE_RENAME_INFORMATION::default();
            bytes.div_ceil(std::mem::size_of::<FILE_RENAME_INFORMATION>())
        ];
        // SAFETY: initialize every allocation byte, including native ABI padding,
        // before writing union/handle/integer fields (all-zero is valid for them).
        unsafe {
            std::ptr::write_bytes(
                buffer.as_mut_ptr().cast::<u8>(),
                0,
                buffer.len() * std::mem::size_of::<FILE_RENAME_INFORMATION>(),
            )
        };
        buffer[0].Anonymous = FILE_RENAME_INFORMATION_0 {
            Flags: FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
        };
        buffer[0].RootDirectory = parent.as_raw_handle();
        buffer[0].FileNameLength = u32::try_from(name_bytes).map_err(|_| invalid_extent())?;
        // SAFETY: native-aligned allocation covers the checked offset, all filename
        // units and an explicit terminator; source and destination do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                name.len(),
            );
            buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(offset)
                .cast::<u16>()
                .add(name.len())
                .write(0);
        }
        let mut iosb = IO_STATUS_BLOCK::default();
        live()?;
        // SAFETY: this source's private constructor guarantees synchronous native
        // I/O; the original parent, aligned native request and IOSB remain live
        // throughout completion. No asynchronous/overlapped owner can enter here.
        let status = unsafe {
            NtSetInformationFile(
                source.as_raw_handle(),
                &raw mut iosb,
                buffer.as_ptr().cast(),
                native_bytes,
                FileRenameInformationEx,
            )
        };
        match windows_synchronous_status(status) {
            WindowsSynchronousStatus::Success => {
                // SAFETY: exact synchronous success completed IOSB. Merely copy it;
                // NO fallible work or cutoff check before caller cleanup disarm.
                return Ok(WindowsRenameCommitted {
                    status: unsafe { iosb.Anonymous.Status },
                    information: iosb.Information,
                    deadline,
                });
            }
            // A nonzero nonnegative status violates the closed synchrony/commit
            // contract. Do not unwind/free buffers or run old-name cleanup while
            // an outstanding or ambiguously committed operation may still exist.
            WindowsSynchronousStatus::InvariantViolation => std::process::abort(),
            WindowsSynchronousStatus::Failure => {}
        }
        const NAME_CONTEXT_BYTES: usize = 64;
        let prefix: Vec<_> = name
            .iter()
            .take(NAME_CONTEXT_BYTES / std::mem::size_of::<u16>())
            .copied()
            .collect();
        Err(windows_rename_nt_error(
            "rename-NtSetInformationFile",
            format!(
                "class={FileRenameInformationEx}; flags={}; native-bytes={native_bytes}; allocation-bytes={}; native-size={}; native-align={}; filename-offset={offset}; name-units={}; name-bytes={name_bytes}; root-present={}; source-volume={}; source-file={}; source-length={}; source-attributes={}; source-links={}; parent-volume={}; parent-file={}; parent-length={}; parent-attributes={}; parent-links={}; expected-caller-access=0x00110180(READ_ATTRIBUTES|WRITE_ATTRIBUTES|DELETE|SYNCHRONIZE); expected-caller-share=0x5(READ|DELETE); name-omitted-units={}; name-prefix-utf16={prefix:?}",
                FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS,
                buffer.len() * std::mem::size_of::<FILE_RENAME_INFORMATION>(),
                std::mem::size_of::<FILE_RENAME_INFORMATION>(),
                std::mem::align_of::<FILE_RENAME_INFORMATION>(),
                name.len(),
                !buffer[0].RootDirectory.is_null(),
                source_metadata.volume_serial,
                source_metadata.file_index,
                source_metadata.length,
                source_metadata.attributes,
                source_metadata.links,
                parent_metadata.volume_serial,
                parent_metadata.file_index,
                parent_metadata.length,
                parent_metadata.attributes,
                parent_metadata.links,
                name.len() - prefix.len()
            ),
            status,
        ))
    }
}

/// Observe image candidates under the original caller cutoff. A query-failed
/// terminal transition is excluded only after this same owned object signals.
#[cfg(windows)]
pub fn windows_processes_for_image_until(
    image: &Path,
    deadline: std::time::Instant,
) -> io::Result<Vec<WindowsImageProcess>> {
    windows_processes_for_image_inner(image, Some(deadline), None)
}

#[cfg(windows)]
impl WindowsImageProcess {
    /// Hold only image-verified direct children of this still-held live root.
    pub fn direct_children_for_image_until(
        &self,
        image: &Path,
        deadline: std::time::Instant,
    ) -> io::Result<Vec<WindowsImageProcess>> {
        if self.has_exited()? {
            return Err(io::Error::other("original direct-child root is retired"));
        }
        let children = windows_processes_for_image_inner(image, Some(deadline), Some(self))?;
        if self.has_exited()? {
            return Err(io::Error::other(
                "original direct-child root retired during census",
            ));
        }
        Ok(children)
    }
}

#[cfg(windows)]
fn windows_processes_for_image_inner(
    image: &Path,
    deadline: Option<std::time::Instant>,
    root: Option<&WindowsImageProcess>,
) -> io::Result<Vec<WindowsImageProcess>> {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{
        ERROR_NO_MORE_FILES, FILETIME, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    };
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    };

    let expected = std::fs::canonicalize(image)
        .map_err(|error| {
            windows_process_observation_error("canonicalize expected image", None, error)
        })?
        .to_string_lossy()
        .to_lowercase();
    let expected_name = image
        .file_name()
        .ok_or_else(|| io::Error::other("fixture image has no filename"))?
        .to_string_lossy()
        .to_lowercase();
    // SAFETY: a process snapshot has no mutable external buffers.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        return Err(windows_process_observation_error(
            "CreateToolhelp32Snapshot(processes)",
            None,
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: snapshot is a new owned handle and is closed on all exits.
    let _snapshot_owner = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(snapshot) };
    // SAFETY: the Windows enumeration API initializes the remaining fields.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = u32::try_from(std::mem::size_of::<PROCESSENTRY32W>())
        .expect("Windows process entry size fits u32");
    // SAFETY: snapshot and entry are valid for enumeration.
    let mut found = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    if !found {
        return Err(windows_process_observation_error(
            "Process32FirstW",
            None,
            io::Error::last_os_error(),
        ));
    }
    let mut matching = Vec::new();
    while found {
        if deadline.is_some_and(|cutoff| std::time::Instant::now() >= cutoff) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original image census cutoff expired",
            ));
        }
        let name_len = entry
            .szExeFile
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..name_len]).to_lowercase();
        if name == expected_name
            && root.is_none_or(|owner| entry.th32ParentProcessID == owner.identity.pid)
        {
            // SAFETY: query-only access to an enumerated PID.
            let raw = unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    entry.th32ProcessID,
                )
            };
            if raw.is_null() {
                let original = io::Error::last_os_error();
                // A matching image that cannot be inspected is never interpreted as absent.
                let error = windows_process_observation_error(
                    "OpenProcess(QUERY_LIMITED_INFORMATION|SYNCHRONIZE)",
                    Some(entry.th32ProcessID),
                    original,
                );
                return Err(io::Error::new(
                    error.kind(),
                    format!(
                        "{error}; snapshot-parent-pid={}; snapshot-name-utf16={:?}; snapshot-name-terminated={}; held-root-filter-pid-birth={:?}; original-cutoff-present={}; original-cutoff-expired={:?}; owned-process-identity-established=false; retirement-established=false",
                        entry.th32ParentProcessID,
                        &entry.szExeFile[..name_len],
                        name_len < entry.szExeFile.len(),
                        root.map(|owner| (owner.identity.pid, owner.identity.birth)),
                        deadline.is_some(),
                        deadline.map(|cutoff| std::time::Instant::now() >= cutoff),
                    ),
                ));
            }
            // SAFETY: OpenProcess returned one owned non-null handle.
            let handle = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
            if let Some(owner) = root {
                let mut creation = FILETIME::default();
                let mut exit = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                // SAFETY: the same held query handle and writable native outputs.
                if unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) }
                    == 0
                {
                    return Err(windows_process_observation_error(
                        "direct child GetProcessTimes",
                        Some(entry.th32ProcessID),
                        io::Error::last_os_error(),
                    ));
                }
                let birth = (u128::from(creation.dwHighDateTime) << 32)
                    | u128::from(creation.dwLowDateTime);
                if birth < owner.identity.birth || entry.th32ProcessID == owner.identity.pid {
                    drop(handle);
                    // SAFETY: snapshot and entry remain held and writable.
                    found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
                    continue;
                }
            }
            let mut units = [0u16; 32768];
            let mut length = u32::try_from(units.len()).expect("image path buffer fits u32");
            // SAFETY: handle and path buffer are valid, with writable length.
            if unsafe { QueryFullProcessImageNameW(raw, 0, units.as_mut_ptr(), &mut length) } == 0 {
                let image_error = windows_process_observation_error(
                    "QueryFullProcessImageNameW",
                    Some(entry.th32ProcessID),
                    io::Error::last_os_error(),
                );
                // A process can terminate after the snapshot/open and lose its
                // image before this query. Exclude it only when this same held
                // native object positively proves retirement. A live or unknown
                // candidate remains an inspection refusal, never an absence.
                use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
                use windows_sys::Win32::System::Threading::WaitForSingleObject;
                // SAFETY: handle stays owned here and already has SYNCHRONIZE.
                match unsafe { WaitForSingleObject(raw, 0) } {
                    WAIT_OBJECT_0 => {}
                    WAIT_TIMEOUT => {
                        let mut creation = FILETIME::default();
                        let mut exit = FILETIME::default();
                        let mut kernel = FILETIME::default();
                        let mut user = FILETIME::default();
                        // SAFETY: the original query-capable handle remains owned,
                        // and all four FILETIME outputs are writable.
                        let (birth, exit_filetime) = if unsafe {
                            GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user)
                        } != 0
                        {
                            (
                                format!(
                                    "{}",
                                    (u64::from(creation.dwHighDateTime) << 32)
                                        | u64::from(creation.dwLowDateTime)
                                ),
                                format!(
                                    "{}",
                                    (u64::from(exit.dwHighDateTime) << 32)
                                        | u64::from(exit.dwLowDateTime)
                                ),
                            )
                        } else {
                            let error = io::Error::last_os_error();
                            let unavailable = format!(
                                "unavailable(kind={:?},raw-os-error={:?})",
                                error.kind(),
                                error.raw_os_error()
                            );
                            (unavailable.clone(), unavailable)
                        };
                        let mut exit_code = 0;
                        // SAFETY: the same query-capable handle remains owned and
                        // exit_code is writable. A terminal status permits a
                        // bounded wait, but only the held object's signal proves retirement.
                        let (exit_code, terminal_status) =
                            if unsafe { GetExitCodeProcess(raw, &mut exit_code) } != 0 {
                                (
                                    exit_code.to_string(),
                                    exit_code
                                        != windows_sys::Win32::Foundation::STILL_ACTIVE as u32,
                                )
                            } else {
                                let error = io::Error::last_os_error();
                                (
                                    format!(
                                        "unavailable(kind={:?},raw-os-error={:?})",
                                        error.kind(),
                                        error.raw_os_error()
                                    ),
                                    false,
                                )
                            };
                        // SAFETY: the original SYNCHRONIZE handle remains owned.
                        // This second zero-wait never changes the original refusal.
                        let subsequent_wait = unsafe { WaitForSingleObject(raw, 0) };
                        let subsequent_wait_error =
                            if subsequent_wait == windows_sys::Win32::Foundation::WAIT_FAILED {
                                let error = io::Error::last_os_error();
                                format!(
                                    "kind={:?},raw-os-error={:?}",
                                    error.kind(),
                                    error.raw_os_error()
                                )
                            } else {
                                "none".to_owned()
                            };
                        let mut cutoff_wait = "not-attempted".to_owned();
                        if let Some(cutoff) = deadline.filter(|_| terminal_status) {
                            match cutoff.checked_duration_since(std::time::Instant::now()) {
                                Some(remaining) => {
                                    let millis =
                                        remaining.as_millis().min(u128::from(u32::MAX - 1)) as u32;
                                    // SAFETY: the exact original SYNCHRONIZE handle remains
                                    // owned. This is one finite wait under the caller cutoff.
                                    let observed = unsafe { WaitForSingleObject(raw, millis) };
                                    let wait_error = if observed
                                        == windows_sys::Win32::Foundation::WAIT_FAILED
                                    {
                                        Some(io::Error::last_os_error())
                                    } else {
                                        None
                                    };
                                    let within_cutoff = std::time::Instant::now() < cutoff;
                                    if observed == WAIT_OBJECT_0 && within_cutoff {
                                        drop(handle);
                                        // SAFETY: snapshot and entry remain owned and valid.
                                        found =
                                            unsafe { Process32NextW(snapshot, &mut entry) } != 0;
                                        continue;
                                    }
                                    cutoff_wait = format!(
                                        "raw={observed},within-original-cutoff={within_cutoff},error={wait_error:?}"
                                    );
                                }
                                None => {
                                    cutoff_wait = "original-cutoff-expired".to_owned();
                                }
                            }
                        }
                        return Err(io::Error::new(
                            image_error.kind(),
                            format!(
                                "{image_error}; same-held-handle-retirement=not-signaled; snapshot-parent-pid={}; same-held-handle-birth={birth}; lifecycle-query-order=GetProcessTimes,GetExitCodeProcess,WaitForSingleObject-zero; exit-filetime-100ns={exit_filetime}; raw-exit-code={exit_code}; subsequent-zero-wait-raw={subsequent_wait}; subsequent-zero-wait-error={subsequent_wait_error}; original-cutoff-retirement-wait={cutoff_wait}",
                                entry.th32ParentProcessID,
                            ),
                        ));
                    }
                    _ => {
                        let retirement_error = windows_process_observation_error(
                            "WaitForSingleObject(image-query-failure,0)",
                            Some(entry.th32ProcessID),
                            io::Error::last_os_error(),
                        );
                        return Err(io::Error::new(
                            image_error.kind(),
                            format!(
                                "{image_error}; retirement observation unavailable: {retirement_error}"
                            ),
                        ));
                    }
                }
                // Advance the original snapshot below; do not query a retired
                // object's removed image or fabricate its process identity.
                // Close before enumeration so CloseHandle cannot replace its
                // terminal GetLastError value when the snapshot is exhausted.
                drop(handle);
                // SAFETY: snapshot and entry remain valid for enumeration.
                found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
                continue;
            }
            let observed = std::fs::canonicalize(Path::new(&String::from_utf16_lossy(
                &units[..length as usize],
            )))
            .map_err(|error| {
                windows_process_observation_error(
                    "canonicalize observed image",
                    Some(entry.th32ProcessID),
                    error,
                )
            })?
            .to_string_lossy()
            .to_lowercase();
            if observed == expected {
                let mut creation = FILETIME::default();
                let mut exit = FILETIME::default();
                let mut kernel = FILETIME::default();
                let mut user = FILETIME::default();
                // SAFETY: all FILETIME outputs are writable and handle remains open.
                if unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) }
                    == 0
                {
                    return Err(windows_process_observation_error(
                        "GetProcessTimes",
                        Some(entry.th32ProcessID),
                        io::Error::last_os_error(),
                    ));
                }
                let process = WindowsImageProcess {
                    identity: ProcessIdentity {
                        pid: entry.th32ProcessID,
                        birth: (u128::from(creation.dwHighDateTime) << 32)
                            | u128::from(creation.dwLowDateTime),
                    },
                    _handle: handle,
                };
                match root {
                    Some(owner)
                        if process.identity.birth < owner.identity.birth
                            || process.native_parent_process_id()? != owner.identity.pid =>
                    {
                        return Err(io::Error::other(
                            "held direct-child identity or native parent differs",
                        ));
                    }
                    _ => {}
                }
                matching.push(process);
            }
        }
        // SAFETY: snapshot and entry remain valid for the next query.
        found = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    // SAFETY: GetLastError reads this thread's immediately preceding enumeration result.
    let enumeration_error = unsafe { GetLastError() };
    if enumeration_error != ERROR_NO_MORE_FILES {
        return Err(windows_process_observation_error(
            "Process32NextW",
            None,
            io::Error::from_raw_os_error(i32::try_from(enumeration_error).unwrap_or(i32::MAX)),
        ));
    }
    if deadline.is_some_and(|cutoff| std::time::Instant::now() >= cutoff) {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original image census cutoff expired",
        ));
    }
    Ok(matching)
}

#[cfg(windows)]
pub fn windows_available_memory_bytes() -> io::Result<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: Windows fills the initialized structure after its exact size is supplied.
    let mut status: MEMORYSTATUSEX = unsafe { std::mem::zeroed() };
    status.dwLength = u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>())
        .expect("Windows memory status size fits u32");
    // SAFETY: the pointer refers to a writable MEMORYSTATUSEX.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(status.ullAvailPhys)
}

#[cfg(target_os = "linux")]
pub fn assert_native_containment(expected_memory: u64) -> io::Result<()> {
    let membership = std::fs::read_to_string("/proc/self/cgroup")?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| io::Error::other("fixture is not in a unified cgroup"))?;
    if !relative
        .split('/')
        .any(|part| part.starts_with("memcordon-"))
    {
        return Err(io::Error::other(
            "fixture was observable before MemCordon cgroup assignment",
        ));
    }
    let memory_max = std::fs::read_to_string(
        std::path::Path::new("/sys/fs/cgroup")
            .join(relative.trim_start_matches('/'))
            .join("memory.max"),
    )?;
    if memory_max.trim() != expected_memory.to_string() {
        return Err(io::Error::other(
            "fixture cgroup does not have the MemCordon memory limit",
        ));
    }
    Ok(())
}

#[cfg(unix)]
pub fn force_terminate(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: the caller supplies the process id of the wrapper it just spawned.
    if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub fn request_interrupt(pid: u32) -> io::Result<()> {
    let pid = i32::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: the caller supplies the process id of the wrapper it just spawned.
    if unsafe { libc::kill(pid, libc::SIGTERM) } == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub fn force_terminate(pid: u32) -> io::Result<()> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_TERMINATE, TerminateProcess};

    // SAFETY: the process id belongs to the wrapper spawned by the calling test.
    let process = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if process.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: process is a live owned handle with terminate access.
    let result = unsafe { TerminateProcess(process, 137) };
    // SAFETY: process is uniquely owned by this function.
    unsafe { CloseHandle(process) };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
pub fn assert_native_containment(expected_memory: u64) -> io::Result<()> {
    use std::mem::{MaybeUninit, size_of};
    use windows_sys::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        QueryInformationJobObject,
    };

    // A null handle queries the current process's immediate job. In a nested runner this
    // distinguishes MemCordon's inner job from any outer CI containment job.
    let mut information =
        unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
    // SAFETY: the null handle selects the immediate job and the output buffer has the exact class
    // size documented by QueryInformationJobObject.
    let result = unsafe {
        QueryInformationJobObject(
            std::ptr::null_mut(),
            JobObjectExtendedLimitInformation,
            (&raw mut information).cast(),
            u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap_or(u32::MAX),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else if information.JobMemoryLimit != usize::try_from(expected_memory).unwrap_or(usize::MAX)
        || information.BasicLimitInformation.LimitFlags
            & (JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            != JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    {
        Err(io::Error::other(
            "fixture immediate job does not have the MemCordon memory and kill-on-close limits",
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
pub fn assert_native_containment(_expected_memory: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native containment assertion is only available on Linux and Windows",
    ))
}

#[cfg(target_os = "linux")]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    let stat = std::fs::read_to_string(
        std::path::Path::new("/proc")
            .join(pid.to_string())
            .join("stat"),
    )?;
    let after_name = stat
        .rsplit_once(')')
        .map(|(_, fields)| fields)
        .ok_or_else(|| io::Error::other("malformed Linux process stat"))?;
    let birth = after_name
        .split_whitespace()
        .nth(19)
        .and_then(|field| field.parse::<u128>().ok())
        .ok_or_else(|| io::Error::other("Linux process stat lacks start identity"))?;
    Ok(ProcessIdentity { pid, birth })
}

#[cfg(target_os = "macos")]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    use std::mem::{MaybeUninit, size_of};

    const PROC_PIDTBSDINFO: i32 = 3;
    #[repr(C)]
    struct ProcBsdInfo {
        flags: u32,
        status: u32,
        xstatus: u32,
        pid: u32,
        ppid: u32,
        uid: u32,
        gid: u32,
        ruid: u32,
        rgid: u32,
        svuid: u32,
        svgid: u32,
        rfu_1: u32,
        comm: [libc::c_char; 16],
        name: [libc::c_char; 32],
        nfiles: u32,
        pgid: u32,
        pjobc: u32,
        e_tdev: u32,
        e_tpgid: u32,
        nice: i32,
        start_tvsec: u64,
        start_tvusec: u64,
    }
    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidinfo(
            pid: libc::c_int,
            flavor: libc::c_int,
            arg: u64,
            buffer: *mut libc::c_void,
            buffersize: libc::c_int,
        ) -> libc::c_int;
    }
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = i32::try_from(size_of::<ProcBsdInfo>()).map_err(io::Error::other)?;
    // SAFETY: info is writable for the exact declared structure size.
    let read = unsafe {
        proc_pidinfo(
            i32::try_from(pid).map_err(io::Error::other)?,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if read != size {
        let error = io::Error::last_os_error();
        return Err(if error.raw_os_error() == Some(libc::ESRCH) {
            io::Error::new(io::ErrorKind::NotFound, error)
        } else {
            error
        });
    }
    // SAFETY: proc_pidinfo initialized the full structure after exact-size success.
    let info = unsafe { info.assume_init() };
    Ok(ProcessIdentity {
        pid,
        birth: u128::from(info.start_tvsec) * 1_000_000 + u128::from(info.start_tvusec),
    })
}

#[cfg(windows)]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: pid is a plain process identity and requested access is query-only.
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            io::Error::last_os_error(),
        ));
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all FILETIME pointers are valid writable structures.
    let result =
        unsafe { GetProcessTimes(process, &mut creation, &mut exit, &mut kernel, &mut user) };
    // SAFETY: process is an owned handle opened above.
    unsafe { CloseHandle(process) };
    if result == 0 {
        return Err(io::Error::last_os_error());
    }
    let birth = (u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime);
    Ok(ProcessIdentity { pid, birth })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn process_identity(pid: u32) -> io::Result<ProcessIdentity> {
    Ok(ProcessIdentity { pid, birth: 0 })
}

#[cfg(unix)]
use std::os::unix::process::CommandExt;

#[cfg(unix)]
#[derive(Debug)]
pub struct OuterTestBoundary {
    session: i32,
}

#[cfg(unix)]
impl OuterTestBoundary {
    pub fn configure(command: &mut Command) -> io::Result<()> {
        configure_child_setup(command, ChildSetup::Session);
        Ok(())
    }

    pub fn after_spawn(child: &Child) -> io::Result<Self> {
        Ok(Self {
            session: i32::try_from(child.id()).map_err(io::Error::other)?,
        })
    }

    pub fn terminate(&self) -> io::Result<()> {
        terminate_unix_session(self.session, || Ok(()))
    }
}

#[cfg(unix)]
enum ChildSetup {
    Session,
    #[cfg(target_os = "linux")]
    TraceExec,
    InheritDescriptor(std::os::fd::OwnedFd),
    #[cfg(target_os = "linux")]
    InheritDescriptorAt {
        descriptor: std::os::fd::OwnedFd,
        destination: i32,
    },
    #[cfg(target_os = "linux")]
    PublicCredentialsAndGate {
        uid: u32,
        gid: u32,
        reader: std::os::fd::OwnedFd,
        reuse: Option<std::os::fd::OwnedFd>,
        writer: std::os::fd::RawFd,
    },
}

/// Stop this original child at its kernel exec event, before user code runs.
#[cfg(target_os = "linux")]
pub fn configure_native_exec_observation(command: &mut Command) {
    configure_child_setup(command, ChildSetup::TraceExec);
}

/// A genuine exec stop owned by the spawning thread. Exit reaping remains with
/// the original runner; dropping an unreleased stop kills only this child.
#[cfg(target_os = "linux")]
pub struct NativeExecObservation {
    pid: libc::pid_t,
    released: bool,
}

#[cfg(target_os = "linux")]
impl NativeExecObservation {
    pub fn acquire(child: &Child, deadline: std::time::Instant) -> io::Result<Self> {
        let owner = Self {
            pid: i32::try_from(child.id()).map_err(io::Error::other)?,
            released: false,
        };
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "native exec observation deadline",
                ));
            }
            // SAFETY: siginfo is a writable native output; WNOWAIT preserves
            // every exit result for the original Child wait owner.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    owner.pid as libc::id_t,
                    &mut info,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            // SAFETY: waitid initialized this siginfo output.
            if unsafe { info.si_pid() } == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
                continue;
            }
            if info.si_code != libc::CLD_TRAPPED || unsafe { info.si_status() } != libc::SIGTRAP {
                return Err(io::Error::other(
                    "original child did not reach its native exec trap",
                ));
            }
            // SAFETY: requesting only WSTOPPED cannot reap an exit if an
            // external signal races the previously observed stop.
            let mut consumed: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    owner.pid as libc::id_t,
                    &mut consumed,
                    libc::WSTOPPED | libc::WNOHANG,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { consumed.si_pid() } != owner.pid
                || consumed.si_code != libc::CLD_TRAPPED
                || unsafe { consumed.si_status() } != libc::SIGTRAP
            {
                return Err(io::Error::other("native exec trap changed before custody"));
            }
            return Ok(owner);
        }
    }

    pub fn release(mut self) -> io::Result<()> {
        // SAFETY: this spawning thread owns the validated trace stop; signal0
        // suppresses the synthetic exec trap and resumes the original program.
        if unsafe {
            libc::ptrace(
                libc::PTRACE_DETACH,
                self.pid,
                std::ptr::null_mut::<libc::c_void>(),
                std::ptr::null_mut::<libc::c_void>(),
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.released = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for NativeExecObservation {
    fn drop(&mut self) {
        if !self.released {
            // SAFETY: an unreaped original child cannot reuse this PID. Do not
            // reap here: the bounded runner retains sole native exit ownership.
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
            }
        }
    }
}

/// Retain an owned CLOEXEC endpoint and inherit it only in this command's child.
/// This does not create a session; it composes with `OuterTestBoundary::configure`.
#[cfg(unix)]
pub fn inherit_test_descriptor(
    command: &mut Command,
    descriptor: std::os::fd::OwnedFd,
) -> io::Result<std::os::fd::RawFd> {
    use std::os::fd::AsRawFd;
    let raw = descriptor.as_raw_fd();
    // SAFETY: the descriptor remains owned and live throughout this inspection.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if raw < 3 || flags & libc::FD_CLOEXEC == 0 {
        return Err(io::Error::other(
            "test endpoint must be nonstandard and CLOEXEC",
        ));
    }
    configure_child_setup(command, ChildSetup::InheritDescriptor(descriptor));
    Ok(raw)
}

/// Place an owned hostile test descriptor at the selected nonstandard slot
/// only in this command's child; the parent never clears its CLOEXEC flag.
#[cfg(target_os = "linux")]
pub fn inherit_test_descriptor_at(
    command: &mut Command,
    descriptor: std::os::fd::OwnedFd,
    destination: i32,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    if descriptor.as_raw_fd() < 3 || !(3..=4096).contains(&destination) {
        return Err(io::Error::other(
            "test descriptor slot outside finite nonstandard bound",
        ));
    }
    configure_child_setup(
        command,
        ChildSetup::InheritDescriptorAt {
            descriptor,
            destination,
        },
    );
    Ok(())
}

/// Read the original host's bounded native IPv4 interface census.
#[cfg(target_os = "linux")]
pub fn native_nonloopback_ipv4() -> io::Result<std::net::Ipv4Addr> {
    let mut first = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes the pointer to its owned native list.
    if unsafe { libc::getifaddrs(&mut first) } != 0 {
        return Err(io::Error::last_os_error());
    }
    struct Addresses(*mut libc::ifaddrs);
    impl Drop for Addresses {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns the getifaddrs allocation.
            unsafe { libc::freeifaddrs(self.0) }
        }
    }
    let _owner = Addresses(first);
    let mut current = first;
    let mut count = 0usize;
    while !current.is_null() {
        count += 1;
        if count > 4096 {
            return Err(io::Error::other(
                "native interface census exceeds finite bound",
            ));
        }
        // SAFETY: each link remains valid until the unique allocation guard drops.
        let interface = unsafe { &*current };
        // SAFETY: the kernel list identifies the address family before the cast.
        if !interface.ifa_addr.is_null()
            && unsafe { (*interface.ifa_addr).sa_family } == libc::AF_INET as libc::sa_family_t
        {
            // SAFETY: AF_INET addresses have the sockaddr_in layout.
            let address = unsafe { &*interface.ifa_addr.cast::<libc::sockaddr_in>() };
            let ip = std::net::Ipv4Addr::from(address.sin_addr.s_addr.to_ne_bytes());
            if !ip.is_loopback()
                && !ip.is_unspecified()
                && !ip.is_multicast()
                && interface.ifa_flags & libc::IFF_UP as u32 != 0
            {
                return Ok(ip);
            }
        }
        current = interface.ifa_next;
    }
    Err(io::Error::other(
        "original host has no required nonloopback IPv4 destination",
    ))
}

#[cfg(target_os = "linux")]
pub fn native_test_bind_mount(
    source: &std::ffi::CStr,
    destination: &std::ffi::CStr,
) -> io::Result<()> {
    // SAFETY: CStr provides valid terminated paths; MS_BIND ignores filesystem/data.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            destination.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn native_test_unmount(destination: &std::ffi::CStr, abort: bool) -> io::Result<()> {
    // SAFETY: the caller retains its exact task-owned mount destination.
    if unsafe {
        libc::umount2(
            destination.as_ptr(),
            if abort { libc::MNT_DETACH } else { 0 },
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn configure_child_setup(command: &mut Command, setup: ChildSetup) {
    use std::os::fd::AsRawFd;
    // SAFETY: the callback performs only async-signal-safe native credential,
    // session and descriptor calls.
    // The captured OwnedFd retains endpoint ownership for the Command lifetime.
    unsafe {
        command.pre_exec(move || {
            match &setup {
                ChildSetup::Session => {
                    if libc::setsid() == -1 {
                        return Err(io::Error::last_os_error());
                    }
                }
                #[cfg(target_os = "linux")]
                ChildSetup::TraceExec => {
                    if libc::ptrace(
                        libc::PTRACE_TRACEME,
                        0,
                        std::ptr::null_mut::<libc::c_void>(),
                        std::ptr::null_mut::<libc::c_void>(),
                    ) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                ChildSetup::InheritDescriptor(descriptor) => {
                    let raw = descriptor.as_raw_fd();
                    let flags = libc::fcntl(raw, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(raw, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                #[cfg(target_os = "linux")]
                ChildSetup::InheritDescriptorAt {
                    descriptor,
                    destination,
                } => {
                    if libc::dup2(descriptor.as_raw_fd(), *destination) != *destination
                        || libc::fcntl(*destination, libc::F_SETFD, 0) != 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                #[cfg(target_os = "linux")]
                ChildSetup::PublicCredentialsAndGate {
                    uid,
                    gid,
                    reader,
                    reuse,
                    writer,
                } => {
                    if libc::setgroups(0, std::ptr::null()) != 0
                        || libc::setresgid(*gid, *gid, *gid) != 0
                        || libc::setresuid(*uid, *uid, *uid) != 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    if libc::dup2(reader.as_raw_fd(), 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    if *writer != 3 {
                        libc::close(*writer);
                    }
                    if let Some(fd) = reuse {
                        if libc::dup2(fd.as_raw_fd(), 4) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                }
            }
            Ok(())
        });
    }
}

/// Interpret one procfs stat result while scanning a Unix session.
///
/// Exposed only so the test-support crate can deterministically cover disappearing procfs entries.
#[cfg(all(unix, not(target_os = "macos")))]
#[doc(hidden)]
pub fn unix_session_member_from_stat(
    session: i32,
    pid: i32,
    stat: io::Result<String>,
) -> io::Result<Option<i32>> {
    let stat = match stat {
        Ok(stat) => stat,
        Err(error) if process_probe_is_absent(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(after_name) = stat.rsplit_once(')').map(|(_, fields)| fields) else {
        return Ok(None);
    };
    let member_session = after_name
        .split_whitespace()
        .nth(3)
        .and_then(|field| field.parse::<i32>().ok());
    Ok((member_session == Some(session)).then_some(pid))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn unix_session_members(session: i32) -> io::Result<Vec<i32>> {
    let mut members = Vec::new();
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        if let Some(pid) = unix_session_member_from_stat(
            session,
            pid,
            std::fs::read_to_string(entry.path().join("stat")),
        )? {
            members.push(pid);
        }
    }
    Ok(members)
}

#[cfg(target_os = "macos")]
fn unix_session_members(session: i32) -> io::Result<Vec<i32>> {
    use std::mem::size_of;
    use std::ptr;

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    }

    // Querying once without a buffer returns the current process count. Reserve slack for races.
    let count = unsafe { proc_listallpids(ptr::null_mut(), 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pids = vec![0_i32; usize::try_from(count).map_err(io::Error::other)? + 64];
    let bytes = pids
        .len()
        .checked_mul(size_of::<i32>())
        .and_then(|value| i32::try_from(value).ok())
        .ok_or_else(|| io::Error::other("process inventory is too large"))?;
    // SAFETY: the buffer is writable for the exact byte count supplied.
    let found = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), bytes) };
    if found < 0 {
        return Err(io::Error::last_os_error());
    }
    pids.truncate(usize::try_from(found).map_err(io::Error::other)?);
    let mut members = Vec::new();
    for pid in pids {
        if pid <= 0 {
            continue;
        }
        // SAFETY: getsid accepts a process identity and does not dereference Rust memory.
        if unsafe { libc::getsid(pid) } == session {
            members.push(pid);
        }
    }
    Ok(members)
}

#[cfg(unix)]
fn terminate_unix_session(
    session: i32,
    mut reap: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    use std::collections::BTreeSet;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    let mut first_error = None;
    let mut signalled = BTreeSet::new();
    loop {
        reap()?;
        let mut members = Vec::new();
        for pid in unix_session_members(session)? {
            let Ok(pid_value) = u32::try_from(pid) else {
                continue;
            };
            match process_identity(pid_value) {
                Ok(identity) => members.push((pid, identity)),
                Err(error) if process_probe_is_absent(&error) => {}
                Err(error) => return Err(error),
            }
        }
        if members.is_empty() {
            // The boundary outcome is authoritative: a signal may be rejected for a
            // short-lived privilege-separated descendant which then exits on its own.
            return Ok(());
        }
        for (pid, identity) in members {
            if signalled.contains(&identity) {
                continue;
            }
            // SAFETY: kill accepts a process identity and does not dereference Rust memory.
            if unsafe { libc::kill(pid, libc::SIGKILL) } == -1 {
                let error = io::Error::last_os_error();
                if !process_probe_is_absent(&error) && first_error.is_none() {
                    first_error = Some(error);
                }
            } else {
                signalled.insert(identity);
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(first_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "test-owned Unix session did not become empty",
                )
            }));
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[cfg(windows)]
#[derive(Debug)]
pub struct OuterTestBoundary {
    job: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl OuterTestBoundary {
    pub fn configure(command: &mut Command) -> io::Result<()> {
        use std::os::windows::process::CommandExt;
        use windows_sys::Win32::System::Threading::{CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED};

        command.creation_flags(CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP);
        Ok(())
    }

    pub fn after_spawn(child: &Child) -> io::Result<Self> {
        use std::mem::size_of;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
        };
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        // SAFETY: null security/name creates an unnamed job owned by this process.
        let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if job.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let length = u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            .map_err(io::Error::other)?;
        // SAFETY: the information pointer is valid for the supplied structure size.
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                length,
            )
        };
        // SAFETY: Child's raw handle is valid while `child` is borrowed.
        let assigned = unsafe { AssignProcessToJobObject(job, child.as_raw_handle().cast()) };
        if configured == 0 || assigned == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: job was created successfully and has not yet been closed.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }

        // The standard Child API exposes the process handle but not the primary thread handle.
        // Enumerate the just-created process's threads while it remains suspended, then resume
        // them only after assignment to the kill-on-close Job Object.
        // SAFETY: snapshot flags and process id are plain values.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }
        let mut entry = THREADENTRY32 {
            dwSize: u32::try_from(size_of::<THREADENTRY32>()).map_err(io::Error::other)?,
            ..Default::default()
        };
        let mut found = false;
        // SAFETY: entry points to initialized writable storage of the declared size.
        let mut available = unsafe { Thread32First(snapshot, &mut entry) } != 0;
        while available {
            if entry.th32OwnerProcessID == child.id() {
                // SAFETY: the thread id came from the OS snapshot.
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                if !thread.is_null() {
                    // SAFETY: the handle has suspend/resume access and is closed below.
                    if unsafe { ResumeThread(thread) } != u32::MAX {
                        found = true;
                    }
                    unsafe { windows_sys::Win32::Foundation::CloseHandle(thread) };
                }
            }
            // SAFETY: entry remains valid writable storage.
            available = unsafe { Thread32Next(snapshot, &mut entry) } != 0;
        }
        // SAFETY: snapshot is an owned valid handle.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(snapshot) };
        if !found {
            let error = io::Error::other("could not resume suspended test process thread");
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Err(error);
        }
        Ok(Self { job })
    }

    pub fn terminate(&self) -> io::Result<()> {
        // SAFETY: job remains valid for the lifetime of this boundary.
        if unsafe { windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(windows)]
impl Drop for OuterTestBoundary {
    fn drop(&mut self) {
        // SAFETY: job is uniquely owned by this value.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.job) };
    }
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug)]
pub struct OuterTestBoundary;

impl OuterTestBoundary {
    /// Reap the owned direct child while retiring its boundary. A killed Unix
    /// child remains a session member until its parent consumes the exit status.
    pub fn terminate_and_reap(&self, child: &mut Child) -> io::Result<()> {
        #[cfg(unix)]
        {
            terminate_unix_session(self.session, || child.try_wait().map(|_| ()))
        }
        #[cfg(not(unix))]
        {
            self.terminate()?;
            #[cfg(not(windows))]
            child.kill()?;
            child.wait().map(|_| ())
        }
    }
}

#[cfg(not(any(unix, windows)))]
impl OuterTestBoundary {
    pub fn configure(_command: &mut Command) -> io::Result<()> {
        Ok(())
    }

    pub fn after_spawn(_child: &Child) -> io::Result<Self> {
        Ok(Self)
    }

    pub fn terminate(&self) -> io::Result<()> {
        Ok(())
    }
}
