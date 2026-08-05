use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, DeadlineEvidence,
    Enforcement, Error, ErrorCategory, InitialSpawnFailure, Interruption, Lifetime, LimitEvidence,
    Metric, Policy, RunOutcome, RunState, StateMachine,
};

use crate::backend::{BackendCleanupFacts, BackendInfo, Execution};
use crate::guardian::Guardian;
use crate::signal::SignalSource;

const PROC_PIDTBSDINFO: i32 = 3;
const PROC_PIDTASKINFO: i32 = 4;
const RUSAGE_INFO_V2: i32 = 2;
const CLEANUP_DEADLINE: Duration = Duration::from_secs(3);

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn bounded_pause(duration: Duration) {
    let timeout = duration.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: zero-descriptor poll is a bounded kernel wait and remains signal-interruptible.
    unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
    fn proc_pidinfo(
        pid: libc::c_int,
        flavor: libc::c_int,
        arg: u64,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
    fn proc_pid_rusage(
        pid: libc::c_int,
        flavor: libc::c_int,
        buffer: *mut libc::c_void,
    ) -> libc::c_int;
}

#[repr(C)]
#[derive(Clone, Copy)]
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

#[repr(C)]
#[derive(Clone, Copy)]
struct RusageInfoV2 {
    uuid: [u8; 16],
    user_time: u64,
    system_time: u64,
    pkg_idle_wkups: u64,
    interrupt_wkups: u64,
    pageins: u64,
    wired_size: u64,
    resident_size: u64,
    phys_footprint: u64,
    proc_start_abstime: u64,
    proc_exit_abstime: u64,
    child_user_time: u64,
    child_system_time: u64,
    child_pkg_idle_wkups: u64,
    child_interrupt_wkups: u64,
    child_pageins: u64,
    child_elapsed_abstime: u64,
    diskio_bytesread: u64,
    diskio_byteswritten: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcTaskInfo {
    virtual_size: u64,
    resident_size: u64,
    total_user: u64,
    total_system: u64,
    threads_user: u64,
    threads_system: u64,
    policy: i32,
    faults: i32,
    pageins: i32,
    cow_faults: i32,
    messages_sent: i32,
    messages_received: i32,
    syscalls_mach: i32,
    syscalls_unix: i32,
    context_switches: i32,
    thread_count: i32,
    running_threads: i32,
    priority: i32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ProcessIdentity {
    pid: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[derive(Clone, Copy)]
struct ProcessSnapshot {
    identity: ProcessIdentity,
    parent_pid: i32,
    process_group: i32,
}

struct ExitWatcher {
    descriptor: i32,
}

impl ExitWatcher {
    fn new(pid: i32) -> io::Result<Self> {
        let ident = usize::try_from(pid).map_err(|_| io::Error::other("negative child PID"))?;
        // SAFETY: `kqueue` has no preconditions and returns an owned descriptor on success.
        let descriptor = unsafe { libc::kqueue() };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        let event = libc::kevent {
            ident,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        // SAFETY: the changelist points to one initialized event and no output list is supplied.
        let result = unsafe {
            libc::kevent(
                descriptor,
                &raw const event,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            // SAFETY: `descriptor` is owned by this function.
            unsafe {
                libc::close(descriptor);
            }
            return Err(error);
        }
        Ok(Self { descriptor })
    }

    fn wait(&self, timeout: Duration) -> io::Result<()> {
        let seconds = libc::time_t::try_from(timeout.as_secs()).unwrap_or(libc::time_t::MAX);
        let nanoseconds = libc::c_long::from(timeout.subsec_nanos());
        let timespec = libc::timespec {
            tv_sec: seconds,
            tv_nsec: nanoseconds,
        };
        let mut event = MaybeUninit::<libc::kevent>::uninit();
        // SAFETY: the output list has room for one event and `timespec` is initialized.
        let result = unsafe {
            libc::kevent(
                self.descriptor,
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &raw const timespec,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Ok(())
    }
}

impl Drop for ExitWatcher {
    fn drop(&mut self) {
        // SAFETY: the descriptor is uniquely owned and closed exactly once here.
        unsafe {
            libc::close(self.descriptor);
        }
    }
}

pub fn info() -> BackendInfo {
    BackendInfo {
        name: "macos-watchdog",
        containment_supported: true,
        memory_supported: true,
        class: "watchdog",
        metric: "physical-footprint-sum",
        hard_limit: false,
        startup_containment: "new process group established before target exec",
        limitations: vec![
            "sampled accounting can miss short memory bursts",
            "usage can overshoot before termination",
            "an undiscovered descendant can escape by creating a new session",
        ],
    }
}

#[allow(
    clippy::result_large_err,
    reason = "execution propagates the categorized Error unchanged through the public boundary"
)]
pub fn run_attempt(
    policy: Policy,
    command: &CommandSpec,
    memcordon_executable: &std::path::Path,
    signal_source: &SignalSource,
    context: crate::supervisor::AttemptContext,
) -> Result<Execution, Error> {
    if policy.enforcement == Enforcement::Hard {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCSETUP-HARD-UNAVAILABLE",
            "hard enforcement is unavailable on macOS; select watchdog or auto",
        ));
    }
    let started = Instant::now();
    let mut state = StateMachine::default();
    state
        .transition(RunState::Prepared)
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-STATE", error.to_string()))?;
    let authorized = Instant::now();
    let mut child = spawn_contained(command)?;
    state
        .transition(RunState::SpawnedGated)
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-STATE", error.to_string()))?;
    state
        .transition(RunState::Running)
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-STATE", error.to_string()))?;
    let child_pid = child.id();
    let root_pid = i32::try_from(child_pid).map_err(|_| {
        Error::new(
            ErrorCategory::Spawn,
            "MCSPAWN-PID-RANGE",
            "child PID cannot be represented by native process APIs",
        )
    })?;
    let guardian = match Guardian::spawn(root_pid, memcordon_executable) {
        Ok(guardian) => guardian,
        Err(error) => {
            // SAFETY: the direct child owns a process group whose ID is `root_pid`.
            unsafe {
                libc::kill(-root_pid, libc::SIGKILL);
            }
            let cleanup_deadline = context.clamp_deadline(started, CLEANUP_DEADLINE);
            let direct_child_reaped = loop {
                match child.try_wait() {
                    Ok(Some(_)) => break true,
                    Ok(None) if Instant::now() < cleanup_deadline => {
                        bounded_pause(
                            Duration::from_millis(10)
                                .min(cleanup_deadline.saturating_duration_since(Instant::now())),
                        );
                    }
                    Ok(None) | Err(_) => break false,
                }
            };
            let mut failure = Error::new(
                ErrorCategory::Setup,
                "MCSETUP-GUARDIAN",
                format!("could not start workload guardian: {error}"),
            )
            .with_os_error(&error)
            .with_restart_safety(memcordon_core::RestartSafetyProof {
                direct_child_reaped,
                workload_empty: None,
                helpers_reaped: true,
                containment_removed: false,
                containment_incapable_of_live_members: false,
                errors: (!direct_child_reaped)
                    .then(|| {
                        "direct child could not be reaped after guardian setup failure".to_owned()
                    })
                    .into_iter()
                    .collect(),
            });
            failure =
                failure.with_authorization_offset(authorized.saturating_duration_since(started));
            return Err(failure);
        }
    };
    let exit_watcher = ExitWatcher::new(root_pid).ok();
    let mut known = HashSet::new();
    if let Ok(snapshot) = process_snapshot(root_pid) {
        known.insert(snapshot.identity);
    }
    let mut stored_status = None;
    let mut peak = 0_u64;

    let mut pending_signal = None;
    let mut outcome = loop {
        let mut cycle_error = None;
        let mut completion = None;
        match try_reap(&mut child, &mut stored_status) {
            Ok(Some(status)) => {
                if policy.lifetime == Lifetime::Command {
                    completion = Some(status);
                }
            }
            Ok(None) => {}
            Err(error) => {
                cycle_error = Some(error);
            }
        }

        match discover(root_pid, &mut known) {
            Ok(snapshots) => {
                if policy.lifetime == Lifetime::Workload
                    && stored_status.is_some()
                    && snapshots.is_empty()
                {
                    completion = Some(
                        stored_status
                            .clone()
                            .unwrap_or(ChildTermination::Unavailable),
                    );
                }
                if let Some(limit) = policy.memory {
                    match sample(&snapshots, policy.metric) {
                        Ok(usage) => {
                            peak = peak.max(usage);
                            if usage >= limit.bytes() {
                                let cleanup = terminate_and_cleanup(
                                    &mut child,
                                    &mut stored_status,
                                    root_pid,
                                    &mut known,
                                    if policy.limit_grace.is_zero() {
                                        libc::SIGKILL
                                    } else {
                                        libc::SIGTERM
                                    },
                                    policy.limit_grace,
                                    context.supervision_deadline(started),
                                );
                                break RunOutcome::LimitExceeded {
                                    limit,
                                    observed: Some(ByteSize::from_bytes(usage)),
                                    peak: Some(ByteSize::from_bytes(peak)),
                                    evidence: LimitEvidence {
                                        backend: "macos-watchdog".to_owned(),
                                        metric: metric_name(policy.metric).to_owned(),
                                        detail: "sampled aggregate reached configured limit"
                                            .to_owned(),
                                    },
                                    child_after_termination: stored_status.clone(),
                                    cleanup,
                                };
                            }
                        }
                        Err(error) => {
                            cycle_error = Some(error);
                        }
                    }
                }
            }
            Err(error) => {
                if cycle_error.is_none() {
                    cycle_error = Some(error);
                }
            }
        }

        if let Some(deadline) = policy.deadline {
            let active_duration = context
                .supervision_deadline_remaining
                .unwrap_or_else(|| deadline.duration());
            if authorized.elapsed() >= active_duration {
                let grace_started = Instant::now();
                let effective_grace =
                    context
                        .supervision_deadline(started)
                        .map_or(policy.limit_grace, |deadline| {
                            policy
                                .limit_grace
                                .min(deadline.saturating_duration_since(Instant::now()))
                        });
                let cleanup = terminate_and_cleanup(
                    &mut child,
                    &mut stored_status,
                    root_pid,
                    &mut known,
                    if effective_grace.is_zero() {
                        libc::SIGKILL
                    } else {
                        libc::SIGTERM
                    },
                    effective_grace,
                    context.supervision_deadline(started),
                );
                let observed = authorized.elapsed();
                break RunOutcome::DeadlineExceeded {
                    deadline: DeadlineEvidence::new(
                        millis(deadline.duration()),
                        deadline.scope(),
                        "pre-spawn".to_owned(),
                        millis(context.supervision_offset + active_duration),
                        millis(context.supervision_offset + observed),
                        millis(policy.limit_grace),
                        millis(grace_started.elapsed().min(effective_grace)),
                        (!policy.limit_grace.is_zero()).then(|| "sigterm-process-group".to_owned()),
                        Some("sigkill-process-group".to_owned()),
                    )
                    .map_err(|_| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCLIMIT-DEADLINE-EVIDENCE",
                            "deadline evidence is inconsistent",
                        )
                    })?,
                    child_after_termination: stored_status.clone(),
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup,
                };
            }
        }

        if let Some(error) = cycle_error {
            let cleanup = terminate_and_cleanup(
                &mut child,
                &mut stored_status,
                root_pid,
                &mut known,
                libc::SIGKILL,
                Duration::ZERO,
                context.supervision_deadline(started),
            );
            break RunOutcome::MonitorFailed {
                error,
                child_after_termination: stored_status.clone(),
                cleanup,
            };
        }

        if let Some(signal) = pending_signal.take().or_else(|| signal_source.take()) {
            let cleanup = terminate_and_cleanup(
                &mut child,
                &mut stored_status,
                root_pid,
                &mut known,
                signal,
                policy.signal_grace,
                context.supervision_deadline(started),
            );
            break RunOutcome::Interrupted {
                signal: Interruption { signal },
                child_after_termination: stored_status.clone(),
                cleanup,
            };
        }

        if let Some(status) = completion {
            let cleanup = if policy.lifetime == Lifetime::Workload {
                CleanupSummary {
                    direct_child_reaped: true,
                    workload_empty: Some(true),
                    ..CleanupSummary::default()
                }
            } else {
                cleanup_after_direct_exit(
                    &mut child,
                    &mut stored_status,
                    root_pid,
                    &mut known,
                    context.supervision_deadline(started),
                )
            };
            break RunOutcome::Exited {
                child: status,
                peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                cleanup,
            };
        }

        if let Some(watcher) = &exit_watcher {
            if let Err(error) = watcher.wait(policy.poll_interval) {
                let cleanup = terminate_and_cleanup(
                    &mut child,
                    &mut stored_status,
                    root_pid,
                    &mut known,
                    libc::SIGKILL,
                    Duration::ZERO,
                    context.supervision_deadline(started),
                );
                break RunOutcome::MonitorFailed {
                    error: format!("kqueue wait failed: {error}"),
                    child_after_termination: stored_status.clone(),
                    cleanup,
                };
            }
        } else {
            pending_signal = signal_source.wait(policy.poll_interval).ok().flatten();
        }
    };

    let mut helpers_reaped = true;
    if let Err(error) = guardian.disarm(context.clamp_deadline(started, CLEANUP_DEADLINE)) {
        helpers_reaped = false;
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "guardian-disarm".to_owned(),
            message: error.to_string(),
        });
    }
    state.transition(RunState::Cleaning).map_err(|error| {
        Error::new(ErrorCategory::Cleanup, "MCCLEANUP-STATE", error.to_string())
    })?;
    state.transition(RunState::Finished).map_err(|error| {
        Error::new(ErrorCategory::Cleanup, "MCCLEANUP-STATE", error.to_string())
    })?;
    let mut backend = info();
    backend.metric = metric_name(policy.metric);
    let cleanup = outcome.cleanup();
    let cleanup_facts = BackendCleanupFacts {
        direct_child_reaped: cleanup.direct_child_reaped,
        workload_empty: cleanup.workload_empty,
        helpers_reaped,
        containment_removed: false,
        containment_incapable_of_live_members: cleanup.workload_empty == Some(true),
        errors: cleanup
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.operation, error.message))
            .collect(),
    };
    Ok(Execution {
        outcome,
        backend,
        child_pid,
        duration: started.elapsed(),
        authorization_offset: Some(authorized.saturating_duration_since(started)),
        cleanup_facts,
    })
}

#[allow(
    clippy::result_large_err,
    reason = "the launch layer preserves one categorized Error representation through execution"
)]
fn spawn_contained(command: &CommandSpec) -> Result<Child, Error> {
    let mut builder = Command::new(command.program());
    builder.args(command.arguments()).process_group(0);
    builder.spawn().map_err(|error| {
        let code = if error.kind() == io::ErrorKind::NotFound {
            "MCSPAWN-NOT-FOUND"
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            "MCSPAWN-NOT-EXECUTABLE"
        } else {
            "MCSPAWN-FAILED"
        };
        let failure = match code {
            "MCSPAWN-NOT-FOUND" => Some(InitialSpawnFailure::NotFound),
            "MCSPAWN-NOT-EXECUTABLE" => Some(InitialSpawnFailure::NotExecutable),
            _ => None,
        };
        let mut result = Error::new(
            ErrorCategory::Spawn,
            code,
            format!(
                "could not execute command {}: {error}",
                command.program().to_string_lossy()
            ),
        )
        .with_os_error(&error);
        result.launch_phase = Some("target-spawn-failed");
        failure.map_or(result.clone(), |failure| {
            result.with_initial_spawn_failure(failure)
        })
    })
}

fn try_reap(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
) -> Result<Option<ChildTermination>, String> {
    if let Some(status) = stored.clone() {
        return Ok(Some(status));
    }
    match child.try_wait() {
        Ok(Some(status)) => {
            let termination = termination_from_status(status);
            *stored = Some(termination.clone());
            Ok(Some(termination))
        }
        Ok(None) => Ok(None),
        Err(error) => Err(format!("direct-child wait failed: {error}")),
    }
}

fn termination_from_status(status: ExitStatus) -> ChildTermination {
    if let Some(code) = status.code() {
        ChildTermination::ExitCode { code }
    } else if let Some(signal) = status.signal() {
        ChildTermination::UnixSignal { signal }
    } else {
        ChildTermination::Unavailable
    }
}

fn terminate_and_cleanup(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    initial_signal: i32,
    grace: Duration,
    supervision_deadline: Option<Instant>,
) -> CleanupSummary {
    let mut summary = CleanupSummary {
        graceful_attempted: initial_signal != libc::SIGKILL,
        force_attempted: initial_signal == libc::SIGKILL,
        ..CleanupSummary::default()
    };
    signal_workload(root_pid, known, initial_signal, &mut summary);
    if initial_signal != libc::SIGKILL && !grace.is_zero() {
        let grace_deadline = Instant::now()
            .checked_add(grace)
            .unwrap_or_else(Instant::now);
        let grace_deadline =
            supervision_deadline.map_or(grace_deadline, |deadline| grace_deadline.min(deadline));
        while Instant::now() < grace_deadline {
            if try_reap(child, stored).ok().flatten().is_some() {
                break;
            }
            bounded_pause(
                Duration::from_millis(10)
                    .min(grace_deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
    if initial_signal != libc::SIGKILL {
        summary.force_attempted = true;
        signal_workload(root_pid, known, libc::SIGKILL, &mut summary);
    }

    let deadline = Instant::now()
        .checked_add(CLEANUP_DEADLINE)
        .unwrap_or_else(Instant::now);
    let deadline = supervision_deadline.map_or(deadline, |supervision| deadline.min(supervision));
    let mut empty = false;
    while Instant::now() < deadline {
        match discover(root_pid, known) {
            Ok(snapshots) => {
                if snapshots.is_empty() {
                    empty = true;
                    break;
                }
                for survivor in snapshots {
                    kill_pid(survivor.identity.pid, libc::SIGKILL, &mut summary);
                }
            }
            Err(error) => {
                summary.errors.push(CleanupErrorRecord {
                    operation: "discover".to_owned(),
                    message: error,
                });
                break;
            }
        }
        bounded_pause(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    summary.workload_empty = Some(empty);

    while stored.is_none() && Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(status)) => *stored = Some(termination_from_status(status)),
            Ok(None) => bounded_pause(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(error) => {
                summary.errors.push(CleanupErrorRecord {
                    operation: "reap-direct-child".to_owned(),
                    message: error.to_string(),
                });
                break;
            }
        }
    }
    if stored.is_none() {
        summary.errors.push(CleanupErrorRecord {
            operation: "reap-direct-child".to_owned(),
            message: "cleanup deadline expired".to_owned(),
        });
    }
    summary.direct_child_reaped = stored.is_some();
    summary
}

fn cleanup_after_direct_exit(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    supervision_deadline: Option<Instant>,
) -> CleanupSummary {
    match discover(root_pid, known) {
        Ok(snapshots)
            if snapshots
                .iter()
                .all(|snapshot| snapshot.identity.pid == root_pid) =>
        {
            CleanupSummary {
                direct_child_reaped: stored.is_some(),
                workload_empty: Some(true),
                ..CleanupSummary::default()
            }
        }
        Ok(_) => terminate_and_cleanup(
            child,
            stored,
            root_pid,
            known,
            libc::SIGKILL,
            Duration::ZERO,
            supervision_deadline,
        ),
        Err(error) => {
            let mut summary = terminate_and_cleanup(
                child,
                stored,
                root_pid,
                known,
                libc::SIGKILL,
                Duration::ZERO,
                supervision_deadline,
            );
            summary.errors.push(CleanupErrorRecord {
                operation: "normal-exit-discovery".to_owned(),
                message: error,
            });
            summary
        }
    }
}

fn signal_workload(
    root_pid: i32,
    known: &HashSet<ProcessIdentity>,
    signal: i32,
    summary: &mut CleanupSummary,
) {
    // SAFETY: negative `root_pid` intentionally addresses the child-owned process group.
    let result = unsafe { libc::kill(-root_pid, signal) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            summary.errors.push(CleanupErrorRecord {
                operation: "signal-process-group".to_owned(),
                message: error.to_string(),
            });
        }
    }
    for identity in known {
        kill_pid(identity.pid, signal, summary);
    }
}

fn kill_pid(pid: i32, signal: i32, summary: &mut CleanupSummary) {
    // SAFETY: `pid` comes from the native process table and the signal is a valid constant.
    let result = unsafe { libc::kill(pid, signal) };
    if result != 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            summary.errors.push(CleanupErrorRecord {
                operation: format!("signal-pid-{pid}"),
                message: error.to_string(),
            });
        }
    }
}

fn discover(
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
) -> Result<Vec<ProcessSnapshot>, String> {
    let all = list_processes()?;
    let by_pid: HashMap<_, _> = all
        .iter()
        .copied()
        .map(|snapshot| (snapshot.identity.pid, snapshot))
        .collect();
    known.retain(|identity| {
        by_pid
            .get(&identity.pid)
            .is_some_and(|snapshot| snapshot.identity == *identity)
    });
    if let Some(root) = by_pid.get(&root_pid) {
        known.insert(root.identity);
    }

    let mut changed = true;
    while changed {
        changed = false;
        for snapshot in &all {
            if (snapshot.process_group == root_pid
                || known
                    .iter()
                    .any(|identity| identity.pid == snapshot.parent_pid))
                && known.insert(snapshot.identity)
            {
                changed = true;
            }
        }
    }
    Ok(all
        .into_iter()
        .filter(|snapshot| known.contains(&snapshot.identity))
        .collect())
}

fn list_processes() -> Result<Vec<ProcessSnapshot>, String> {
    // SAFETY: a null buffer with length zero is the documented sizing query.
    let count = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
    if count < 0 {
        return Err(format!(
            "proc_listallpids sizing failed: {}",
            io::Error::last_os_error()
        ));
    }
    let capacity = usize::try_from(count)
        .unwrap_or(0)
        .saturating_add(128)
        .max(128);
    let mut pids = vec![0_i32; capacity];
    let byte_len = pids
        .len()
        .checked_mul(std::mem::size_of::<i32>())
        .and_then(|bytes| i32::try_from(bytes).ok())
        .ok_or_else(|| "process list buffer is too large".to_owned())?;
    // SAFETY: `pids` is writable for exactly `byte_len` bytes.
    let filled = unsafe { proc_listallpids(pids.as_mut_ptr().cast(), byte_len) };
    if filled < 0 {
        return Err(format!(
            "proc_listallpids failed: {}",
            io::Error::last_os_error()
        ));
    }
    pids.truncate(usize::try_from(filled).unwrap_or(0).min(pids.len()));
    Ok(pids
        .into_iter()
        .filter(|pid| *pid > 0)
        .filter_map(|pid| process_snapshot(pid).ok())
        .collect())
}

fn process_snapshot(pid: i32) -> Result<ProcessSnapshot, io::Error> {
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = i32::try_from(std::mem::size_of::<ProcBsdInfo>())
        .map_err(|_| io::Error::other("proc_bsdinfo size cannot fit c_int"))?;
    // SAFETY: `info` points to writable storage of `size` bytes and is initialized only if the
    // function reports that exact structure size.
    let read = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if read != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful exact-size call initialized the entire structure.
    let info = unsafe { info.assume_init() };
    Ok(ProcessSnapshot {
        identity: ProcessIdentity {
            pid,
            start_seconds: info.start_tvsec,
            start_microseconds: info.start_tvusec,
        },
        parent_pid: i32::try_from(info.ppid).unwrap_or(i32::MAX),
        process_group: i32::try_from(info.pgid).unwrap_or(i32::MAX),
    })
}

fn sample(snapshots: &[ProcessSnapshot], metric: Metric) -> Result<u64, String> {
    let mut total = 0_u64;
    for snapshot in snapshots {
        match process_usage(snapshot.identity.pid, metric) {
            Ok(value) => total = total.saturating_add(value),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(error) => {
                return Err(format!(
                    "proc_pid_rusage failed for known member pid={}: {error}",
                    snapshot.identity.pid
                ));
            }
        }
    }
    Ok(total)
}

fn process_usage(pid: i32, metric: Metric) -> Result<u64, io::Error> {
    let mut usage = MaybeUninit::<RusageInfoV2>::zeroed();
    // SAFETY: `usage` has the layout required by RUSAGE_INFO_V2 and points to writable storage.
    let result = unsafe { proc_pid_rusage(pid, RUSAGE_INFO_V2, usage.as_mut_ptr().cast()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a zero return initialized the selected rusage structure.
    let usage = unsafe { usage.assume_init() };
    Ok(match metric {
        Metric::Native | Metric::PhysicalFootprint => usage.phys_footprint,
        Metric::Rss => usage.resident_size,
        Metric::Virtual => return process_virtual_size(pid),
    })
}

fn process_virtual_size(pid: i32) -> Result<u64, io::Error> {
    let mut task = MaybeUninit::<ProcTaskInfo>::zeroed();
    let size = i32::try_from(std::mem::size_of::<ProcTaskInfo>())
        .map_err(|_| io::Error::other("proc_taskinfo size cannot fit c_int"))?;
    // SAFETY: `task` is writable for `size` bytes and is initialized only after an exact-size
    // successful query.
    let read = unsafe { proc_pidinfo(pid, PROC_PIDTASKINFO, 0, task.as_mut_ptr().cast(), size) };
    if read != size {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the exact-size successful call initialized the structure.
    Ok(unsafe { task.assume_init() }.virtual_size)
}

const fn metric_name(metric: Metric) -> &'static str {
    match metric {
        Metric::Native | Metric::PhysicalFootprint => "physical-footprint-sum",
        Metric::Rss => "rss-sum",
        Metric::Virtual => "virtual-size-sum",
    }
}
