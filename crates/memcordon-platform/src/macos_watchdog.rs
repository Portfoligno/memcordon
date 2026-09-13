use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::MaybeUninit;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::time::{Duration, Instant};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, DeadlineEvidence,
    Enforcement, Error, ErrorCategory, InitialSpawnFailure, Interruption, Lifetime, LimitEvidence,
    Metric, Policy, RunOutcome, RunState, StateMachine,
};

use crate::backend::{BackendCleanupFacts, BackendInfo, Execution};
use crate::macos_launch::Child;
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
pub(crate) struct ProcessIdentity {
    pub(crate) pid: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[derive(Clone, Copy)]
struct ProcessSnapshot {
    identity: ProcessIdentity,
    parent_pid: i32,
    process_group: i32,
    zombie: bool,
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
        boundary_support: crate::backend::standard_boundary_support(
            "process-group-pre-spawn",
            true,
            "a certified entitlement-backed process-event authority is not installed",
            &[
                "signed Endpoint Security system extension",
                "root launch daemon",
            ],
        ),
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
    let startup_deadline = context.clamp_deadline(started, Duration::from_secs(5));
    let startup_deadline = policy.deadline.map_or(startup_deadline, |deadline| {
        startup_deadline.min(started + deadline.duration())
    });
    let startup_cleanup_deadline = context
        .supervision_deadline(started)
        .map_or(startup_deadline + CLEANUP_DEADLINE, |deadline| {
            deadline.min(startup_deadline + CLEANUP_DEADLINE)
        });
    let launch_result = crate::macos_launch::launch(
        command,
        memcordon_executable,
        startup_deadline,
        startup_cleanup_deadline,
    );
    if let (Some(deadline), Err(startup)) = (policy.deadline, &launch_result) {
        let active = context
            .supervision_deadline_remaining
            .unwrap_or_else(|| deadline.duration());
        if startup.error.kind() == io::ErrorKind::TimedOut && started.elapsed() >= active {
            let complete = startup.diagnostic.cleanup.state
                == memcordon_core::NativeStartupCleanupStateV1::Complete;
            let mut errors: Vec<CleanupErrorRecord> = startup
                .diagnostic
                .cleanup
                .errors
                .iter()
                .map(|error| CleanupErrorRecord {
                    operation: format!("{:?}", error.operation),
                    message: error.detail.clone(),
                })
                .collect();
            if !complete && errors.is_empty() {
                errors.push(CleanupErrorRecord {
                    operation: "startup-cleanup".into(),
                    message: "native startup cleanup remains an owned, unverified obligation"
                        .into(),
                });
            }
            let cleanup = CleanupSummary {
                direct_child_reaped: complete,
                workload_empty: complete.then_some(true),
                errors,
                ..CleanupSummary::default()
            };
            let mut facts = crate::backend::StandardLaunchFacts::gated_target();
            if startup.diagnostic.guardian_ready {
                facts.record_guardian_spawn_completed();
            }
            if startup.diagnostic.release_sent {
                facts.record_containment_before_authorization();
                facts.record_authorization_released();
            }
            let backend = info();
            let (launch, restart_safety, boundary_detail) =
                crate::backend::standard_execution_evidence(
                    &backend,
                    facts,
                    BackendCleanupFacts {
                        direct_child_reaped: complete,
                        workload_empty: cleanup.workload_empty,
                        helpers_reaped: complete,
                        containment_removed: false,
                        containment_incapable_of_live_members: complete,
                        errors: cleanup
                            .errors
                            .iter()
                            .map(|error| error.message.clone())
                            .collect(),
                    },
                );
            return Ok(Execution {
                policy_enforcement: Default::default(),
                outcome: RunOutcome::DeadlineExceeded {
                    deadline: DeadlineEvidence::new(
                        millis(deadline.duration()),
                        deadline.scope(),
                        "pre-spawn".into(),
                        millis(context.supervision_offset + active),
                        millis(context.supervision_offset + started.elapsed()),
                        millis(policy.limit_grace),
                        0,
                        None,
                        None,
                    )
                    .map_err(|error| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCLIMIT-DEADLINE-EVIDENCE",
                            error.to_string(),
                        )
                    })?,
                    child_after_termination: None,
                    peak: None,
                    cleanup,
                },
                backend,
                child_pid: startup.diagnostic.launcher_pid.unwrap_or(0),
                duration: started.elapsed(),
                authorization_offset: startup
                    .authorized
                    .map(|instant| instant.saturating_duration_since(started)),
                launch,
                restart_safety,
                boundary_detail,
            });
        }
    }
    let launch = launch_result.map_err(|startup| {
        let mut failure = Error::new(
            ErrorCategory::Setup,
            "MCSETUP-GUARDIAN",
            format!(
                "native launch phase={} helper={:?} cwd={:?}: {}",
                startup.phase, memcordon_executable, startup.diagnostic.cwd, startup.error
            ),
        )
        .with_os_error(&startup.error);
        failure.launch_phase = Some(startup.phase);
        failure.target_released = startup.diagnostic.release_sent;
        failure.guardian_ready_before_release = startup.diagnostic.guardian_ready;
        failure.workload_may_be_alive = startup.diagnostic.cleanup.state
            != memcordon_core::NativeStartupCleanupStateV1::Complete;
        failure.authorization_offset = startup
            .authorized
            .map(|authorized| authorized.saturating_duration_since(started));
        if !failure.workload_may_be_alive {
            failure.restart_safety = Some(memcordon_core::RestartSafetyProof {
                direct_child_reaped: true,
                workload_empty: Some(true),
                helpers_reaped: true,
                containment_removed: false,
                containment_incapable_of_live_members: true,
                sealed_boundary_retired: false,
                errors: Vec::new(),
            });
        }
        failure.native_startup = Some(startup.diagnostic);
        if startup.phase == "target-exec" {
            failure.category = ErrorCategory::Spawn;
            failure.launch_phase = Some("target-spawn-failed");
            failure.code = match startup.error.kind() {
                io::ErrorKind::NotFound => "MCSPAWN-NOT-FOUND",
                io::ErrorKind::PermissionDenied => "MCSPAWN-NOT-EXECUTABLE",
                _ => "MCSPAWN-FAILED",
            };
            failure.initial_spawn_failure = match startup.error.kind() {
                io::ErrorKind::NotFound => Some(InitialSpawnFailure::NotFound),
                io::ErrorKind::PermissionDenied => Some(InitialSpawnFailure::NotExecutable),
                _ => None,
            };
        }
        failure
    })?;
    let mut child = launch.child;
    let guardian = launch.guardian;
    let authorized = launch.authorized;
    let mut launch_facts = crate::backend::StandardLaunchFacts::gated_target();
    launch_facts.record_containment_before_authorization();
    launch_facts.record_guardian_spawn_completed();
    launch_facts.record_authorization_released();
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
    let exit_watcher = ExitWatcher::new(root_pid).ok();
    let mut known = HashSet::new();
    let initial_inspection_deadline =
        policy
            .deadline
            .map_or(Instant::now() + Duration::from_millis(100), |deadline| {
                (started
                    + context
                        .supervision_deadline_remaining
                        .unwrap_or_else(|| deadline.duration()))
                .min(Instant::now() + Duration::from_millis(100))
            });
    if let Ok(snapshot) = inspect_until(initial_inspection_deadline, move || {
        process_snapshot(root_pid).map_err(|error| error.to_string())
    }) {
        known.insert(snapshot.identity);
    }
    let cleanup_expiry = std::cell::Cell::new(None);
    let cleanup_budget = || {
        if let Some(deadline) = cleanup_expiry.get() {
            return Some(deadline);
        }
        let cap = policy
            .limit_grace
            .max(policy.signal_grace)
            .saturating_add(CLEANUP_DEADLINE);
        let deadline = context
            .supervision_deadline(started)
            .map_or(Instant::now() + cap, |deadline| {
                deadline.min(Instant::now() + cap)
            });
        cleanup_expiry.set(Some(deadline));
        Some(deadline)
    };
    let mut stored_status = None;
    let mut peak = 0_u64;

    let mut pending_signal = None;
    let mut command_exit_grace_started = None;
    let mut outcome = loop {
        let mut cycle_error = guardian.alive().err().map(|error| error.to_string());
        let mut completion = None;
        let mut workload_empty = false;
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

        let inspection_deadline =
            policy
                .deadline
                .map_or(Instant::now() + Duration::from_millis(250), |deadline| {
                    (started
                        + context
                            .supervision_deadline_remaining
                            .unwrap_or_else(|| deadline.duration()))
                    .min(Instant::now() + Duration::from_millis(250))
                });
        match discover(
            root_pid,
            &mut known,
            inspection_deadline,
            InspectionAdmission::Immediate,
        ) {
            Ok(snapshots) => {
                workload_empty = snapshots.is_empty();
                if policy.lifetime == Lifetime::Workload
                    && stored_status.is_some()
                    && workload_empty
                {
                    completion = Some(
                        stored_status
                            .clone()
                            .unwrap_or(ChildTermination::Unavailable),
                    );
                }
                if let Some(limit) = policy.memory {
                    match sample(&snapshots, policy.metric, inspection_deadline) {
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
                                    cleanup_budget(),
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
            if started.elapsed() >= active_duration {
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
                    cleanup_budget(),
                );
                let observed = started.elapsed();
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
                cleanup_budget(),
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
                cleanup_budget(),
            );
            break RunOutcome::Interrupted {
                signal: Interruption { signal },
                child_after_termination: stored_status.clone(),
                cleanup,
            };
        }

        if let Some(status) = completion {
            let completed = if policy.lifetime == Lifetime::Workload || workload_empty {
                workload_empty
            } else if policy.command_exit_grace.is_zero() {
                true
            } else {
                let grace_started = command_exit_grace_started.get_or_insert_with(Instant::now);
                grace_started.elapsed() >= policy.command_exit_grace
            };
            if completed {
                let cleanup = if workload_empty {
                    CleanupSummary {
                        direct_child_reaped: false,
                        workload_empty: Some(true),
                        ..CleanupSummary::default()
                    }
                } else {
                    cleanup_after_direct_exit(
                        &mut child,
                        &mut stored_status,
                        root_pid,
                        &mut known,
                        cleanup_budget(),
                    )
                };
                break RunOutcome::Exited {
                    child: status,
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup,
                };
            }
        }

        let wait = command_exit_grace_started.map_or(policy.poll_interval, |grace_started| {
            policy.poll_interval.min(
                policy
                    .command_exit_grace
                    .saturating_sub(grace_started.elapsed()),
            )
        });
        let wait = policy.deadline.map_or(wait, |deadline| {
            wait.min(
                context
                    .supervision_deadline_remaining
                    .unwrap_or_else(|| deadline.duration())
                    .saturating_sub(started.elapsed()),
            )
        });
        if stored_status.is_some() {
            pending_signal = signal_source.wait(wait).ok().flatten();
        } else if let Some(watcher) = &exit_watcher {
            if let Err(error) = watcher.wait(wait) {
                let cleanup = terminate_and_cleanup(
                    &mut child,
                    &mut stored_status,
                    root_pid,
                    &mut known,
                    libc::SIGKILL,
                    Duration::ZERO,
                    cleanup_budget(),
                );
                break RunOutcome::MonitorFailed {
                    error: format!("kqueue wait failed: {error}"),
                    child_after_termination: stored_status.clone(),
                    cleanup,
                };
            }
        } else {
            pending_signal = signal_source.wait(wait).ok().flatten();
        }
    };

    let cleanup_deadline =
        cleanup_budget().expect("cleanup budget always has an absolute deadline");
    let child_reaped = if outcome.cleanup().workload_empty == Some(true) {
        child.retire(cleanup_deadline)
    } else {
        Err(io::Error::other(
            "root identity retained until guardian emergency cleanup retires",
        ))
    };
    outcome.cleanup_mut().direct_child_reaped = child_reaped.is_ok();
    if let Err(error) = child_reaped {
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "reap-direct-child".into(),
            message: error.to_string(),
        });
    }
    let mut helpers_reaped = true;
    let retirement = if outcome.cleanup().workload_empty == Some(true) {
        guardian.disarm(cleanup_deadline)
    } else {
        drop(guardian);
        Err(io::Error::other(
            "workload cleanup is incomplete; guardian retains emergency cleanup responsibility",
        ))
    };
    if let Err(error) = retirement {
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
    let (launch, restart_safety, boundary_detail) =
        crate::backend::standard_execution_evidence(&backend, launch_facts, cleanup_facts);
    Ok(Execution {
        policy_enforcement: Default::default(),
        outcome,
        backend,
        child_pid,
        duration: started.elapsed(),
        authorization_offset: Some(authorized.saturating_duration_since(started)),
        launch,
        restart_safety,
        boundary_detail,
    })
}

fn try_reap(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
) -> Result<Option<ChildTermination>, String> {
    if let Some(status) = stored.clone() {
        return Ok(Some(status));
    }
    match child.observe() {
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
    signal_workload(
        root_pid,
        known,
        initial_signal,
        &mut summary,
        supervision_deadline,
    );
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
        signal_workload(
            root_pid,
            known,
            libc::SIGKILL,
            &mut summary,
            supervision_deadline,
        );
    }

    let deadline = Instant::now()
        .checked_add(CLEANUP_DEADLINE)
        .unwrap_or_else(Instant::now);
    let deadline = supervision_deadline.map_or(deadline, |supervision| deadline.min(supervision));
    let mut empty = false;
    while Instant::now() < deadline {
        match discover(root_pid, known, deadline, InspectionAdmission::Cleanup) {
            Ok(snapshots) => {
                if snapshots.is_empty() {
                    empty = true;
                    break;
                }
                for survivor in snapshots {
                    kill_identity(survivor.identity, libc::SIGKILL, &mut summary, deadline);
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
        match child.observe() {
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
    summary.direct_child_reaped = false;
    summary
}

fn cleanup_after_direct_exit(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    supervision_deadline: Option<Instant>,
) -> CleanupSummary {
    let deadline = supervision_deadline.map_or(Instant::now() + CLEANUP_DEADLINE, |deadline| {
        deadline.min(Instant::now() + CLEANUP_DEADLINE)
    });
    match discover(root_pid, known, deadline, InspectionAdmission::Cleanup) {
        Ok(snapshots)
            if snapshots
                .iter()
                .all(|snapshot| snapshot.identity.pid == root_pid) =>
        {
            CleanupSummary {
                direct_child_reaped: false,
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
    cleanup_deadline: Option<Instant>,
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
    let deadline = cleanup_deadline.unwrap_or_else(|| Instant::now() + Duration::from_millis(100));
    for identity in known {
        kill_identity(*identity, signal, summary, deadline);
    }
}

pub(crate) fn root_identity(pid: i32) -> io::Result<ProcessIdentity> {
    let snapshot = process_snapshot(pid)?;
    if snapshot.process_group != pid {
        return Err(io::Error::other("launcher does not own its process group"));
    }
    Ok(snapshot.identity)
}

pub(crate) fn kill_bound_group(identity: ProcessIdentity) {
    let deadline = Instant::now() + Duration::from_millis(100);
    let _ = inspect_until(deadline, move || {
        if process_snapshot(identity.pid).is_ok_and(|current| {
            current.identity == identity && current.process_group == identity.pid
        }) && Instant::now() < deadline
        {
            // SAFETY: the current native start identity matches the bound launcher leader.
            unsafe { libc::kill(-identity.pid, libc::SIGKILL) };
        }
        Ok(())
    });
}

pub(crate) fn guardian_members(identity: ProcessIdentity, known: &mut HashSet<ProcessIdentity>) {
    // This is sampled process custody, not a new hard containment guarantee.
    // Retaining a living member lets crash cleanup survive the root being reaped
    // by init after the wrapper dies.
    let captured = known.clone();
    let result = inspect_until(Instant::now() + Duration::from_millis(100), move || {
        let all = list_processes()?;
        let bound = all.iter().any(|snapshot| {
            snapshot.identity == identity
                || (captured.contains(&snapshot.identity) && snapshot.process_group == identity.pid)
        });
        Ok(all
            .into_iter()
            .filter(|snapshot| {
                !snapshot.zombie
                    && (captured.contains(&snapshot.identity)
                        || (bound && snapshot.process_group == identity.pid))
            })
            .map(|snapshot| snapshot.identity)
            .collect::<HashSet<_>>())
    });
    if let Ok(current) = result {
        *known = current;
    }
}

pub(crate) fn kill_guardian_members(identity: ProcessIdentity, known: &HashSet<ProcessIdentity>) {
    kill_bound_group(identity);
    let mut summary = CleanupSummary::default();
    let deadline = Instant::now() + Duration::from_millis(100);
    for member in known {
        kill_identity(*member, libc::SIGKILL, &mut summary, deadline);
    }
}

fn kill_identity(
    identity: ProcessIdentity,
    signal: i32,
    summary: &mut CleanupSummary,
    deadline: Instant,
) {
    if Instant::now() >= deadline {
        if !summary
            .errors
            .iter()
            .any(|error| error.operation == "validate-process-identity")
        {
            summary.errors.push(CleanupErrorRecord {
                operation: "validate-process-identity".into(),
                message:
                    "identity inspection deadline expired with signalling obligations remaining"
                        .into(),
            });
        }
        return;
    }
    let result = inspect_with_admission(deadline, InspectionAdmission::Cleanup, move || {
        let mut summary = CleanupSummary::default();
        if process_snapshot(identity.pid).is_ok_and(|current| current.identity == identity)
            && Instant::now() < deadline
        {
            kill_pid(identity.pid, signal, &mut summary);
        }
        Ok(summary.errors)
    });
    match result {
        Ok(errors) => summary.errors.extend(errors),
        Err(message) => summary.errors.push(CleanupErrorRecord {
            operation: "validate-process-identity".into(),
            message,
        }),
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
    deadline: Instant,
    admission: InspectionAdmission,
) -> Result<Vec<ProcessSnapshot>, String> {
    let captured = known.clone();
    let (snapshots, updated) = inspect_with_admission(deadline, admission, move || {
        let mut captured = captured;
        let result = discover_native(root_pid, &mut captured)?;
        Ok((result, captured))
    })?;
    *known = updated;
    Ok(snapshots)
}

type Inspection = Box<dyn FnOnce() + Send>;
static INSPECTOR: std::sync::OnceLock<Result<std::sync::mpsc::SyncSender<Inspection>, String>> =
    std::sync::OnceLock::new();

pub(crate) fn inspect_until<T: Send + 'static>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    inspect_with_admission(deadline, InspectionAdmission::Immediate, operation)
}

#[derive(Clone, Copy)]
pub(crate) enum InspectionAdmission {
    Immediate,
    Cleanup,
}

pub(crate) fn inspect_with_admission<T: Send + 'static>(
    deadline: Instant,
    admission: InspectionAdmission,
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    inspect_with_admission_observer(deadline, admission, operation, || {})
}

#[cfg(feature = "test-support")]
pub(crate) fn inspect_until_admitted<T: Send + 'static>(
    deadline: Instant,
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
    admitted: impl FnOnce(),
) -> Result<T, String> {
    inspect_with_admission_observer(
        deadline,
        InspectionAdmission::Immediate,
        operation,
        admitted,
    )
}

fn inspect_with_admission_observer<T: Send + 'static>(
    deadline: Instant,
    admission: InspectionAdmission,
    operation: impl FnOnce() -> Result<T, String> + Send + 'static,
    admitted: impl FnOnce(),
) -> Result<T, String> {
    if Instant::now() >= deadline {
        return Err("process inspection deadline expired before admission".into());
    }
    let worker = INSPECTOR
        .get_or_init(|| {
            let (send, receive) = std::sync::mpsc::sync_channel::<Inspection>(1);
            std::thread::Builder::new()
                .name("memcordon-process-inspector".into())
                .spawn(move || {
                    while let Ok(operation) = receive.recv() {
                        operation();
                    }
                })
                .map_err(|error| error.to_string())?;
            Ok(send)
        })
        .as_ref()
        .map_err(Clone::clone)?;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let mut inspection: Inspection = Box::new(move || {
        if Instant::now() < deadline {
            let _ = send.send(operation());
        }
    });
    loop {
        if Instant::now() >= deadline {
            return Err("process inspection deadline expired before admission".into());
        }
        match worker.try_send(inspection) {
            Ok(()) => {
                admitted();
                break;
            }
            Err(std::sync::mpsc::TrySendError::Full(pending)) => {
                if matches!(admission, InspectionAdmission::Immediate) {
                    return Err("process inspector is busy".into());
                }
                // Cleanup retains this unsubmitted operation and its original deadline.
                // No native operation is retried, and the queue remains bounded.
                inspection = pending;
                bounded_pause(
                    Duration::from_millis(1)
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err("process inspector is unavailable".into());
            }
        }
    }
    receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| {
            "process inspection deadline expired; worker remains runtime-owned".to_owned()
        })?
}

fn discover_native(
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
        .filter(|snapshot| !snapshot.zombie && known.contains(&snapshot.identity))
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
    if capacity > 32768 {
        return Err("native process inventory exceeds 32768 entries".into());
    }
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
        zombie: info.status == 5,
    })
}

fn sample(snapshots: &[ProcessSnapshot], metric: Metric, deadline: Instant) -> Result<u64, String> {
    let snapshots = snapshots.to_vec();
    inspect_until(deadline, move || sample_native(&snapshots, metric))
}

fn sample_native(snapshots: &[ProcessSnapshot], metric: Metric) -> Result<u64, String> {
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
