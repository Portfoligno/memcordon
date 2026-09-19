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
pub(crate) const CLEANUP_DEADLINE: Duration = Duration::from_secs(3);
const PENDING_INVENTORY_HEARTBEAT_INTERVAL: Duration = Duration::from_millis(500);
const WATCHDOG_TURN_MAX: Duration = Duration::from_millis(20);

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn bounded_pause(duration: Duration) {
    let timeout = duration.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: zero-descriptor poll is a bounded kernel wait and remains signal-interruptible.
    unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
}

fn watchdog_turn_wait(
    poll_interval: Duration,
    command_exit_grace_remaining: Option<Duration>,
    inventory_pending: bool,
) -> Duration {
    let wait = if inventory_pending {
        poll_interval.max(Duration::from_millis(1))
    } else {
        command_exit_grace_remaining.map_or(poll_interval, |remaining| poll_interval.min(remaining))
    };
    wait.min(WATCHDOG_TURN_MAX)
}

#[cfg(feature = "test-support")]
pub fn pending_inventory_turn_wait(
    poll_interval: Duration,
    command_exit_grace_remaining: Duration,
) -> Duration {
    watchdog_turn_wait(poll_interval, Some(command_exit_grace_remaining), true)
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_listpids(
        kind: u32,
        typeinfo: u32,
        buffer: *mut libc::c_void,
        buffersize: libc::c_int,
    ) -> libc::c_int;
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[derive(Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProcessSnapshot {
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
    if inspection_obligations() != 0 {
        return Err(Error::new(
            ErrorCategory::Setup,
            "MCSETUP-INSPECTION-PENDING",
            "a previous native inspection remains owned; new workload creation is refused",
        ));
    }
    if policy.enforcement == Enforcement::Hard {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCSETUP-HARD-UNAVAILABLE",
            "hard enforcement is unavailable on macOS; select watchdog or auto",
        ));
    }
    let started = Instant::now();
    let current_tick = crate::macos_deadline::continuous_nanos()
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string()))?;
    // Relative execution offsets start here, alongside `started`. The first
    // deadline/runtime origin can predate this call; using it for authorization
    // would count caller preparation twice when the supervisor adds its offset.
    let attempt_origin = if context.restart_attempt == 0 {
        context.macos_run_origin_ns.unwrap_or(current_tick)
    } else {
        current_tick
    };
    let work_expiry = match context.macos_work_expires_ns {
        Some(expiry) => Some(expiry),
        None => policy
            .deadline
            .map(|deadline| crate::macos_deadline::add(attempt_origin, deadline.duration()))
            .transpose()
            .map_err(|error| {
                Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string())
            })?,
    };
    crate::macos_deadline::add(
        work_expiry.unwrap_or(attempt_origin),
        policy
            .limit_grace
            .max(policy.signal_grace)
            .max(policy.command_exit_grace),
    )
    .and_then(|force| crate::macos_deadline::add(force, Duration::from_secs(4)))
    .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string()))?;
    let mut state = StateMachine::default();
    state
        .transition(RunState::Prepared)
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-STATE", error.to_string()))?;
    let startup_deadline = context.clamp_deadline(started, Duration::from_secs(5));
    let startup_deadline = policy.deadline.map_or(startup_deadline, |deadline| {
        startup_deadline.min(started + deadline.duration())
    });
    let startup_deadline = work_expiry.map_or(startup_deadline, |expiry| {
        startup_deadline
            .min(Instant::now() + Duration::from_nanos(expiry.saturating_sub(current_tick)))
    });
    let startup_cleanup_deadline = startup_deadline + CLEANUP_DEADLINE;
    let startup_expiry = work_expiry
        .map_or(
            crate::macos_deadline::add(attempt_origin, Duration::from_secs(5)),
            |expiry| Ok(expiry.min(attempt_origin.saturating_add(5_000_000_000))),
        )
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string()))?;
    let boot_identity = crate::macos_deadline::boot_identity()
        .map_err(|error| Error::new(ErrorCategory::Setup, "MCSETUP-CLOCK", error.to_string()))?;
    let retained_owner = std::cell::RefCell::new(None::<memcordon_core::OwnerIdentity>);
    let runtime = |release,
                   target_pid,
                   terminal,
                   force,
                   complete|
     -> Result<memcordon_core::RuntimeEvidenceV1, Error> {
        let retired = crate::macos_deadline::continuous_nanos().map_err(|error| {
            Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
        })?;
        let retire = crate::macos_deadline::add(force, CLEANUP_DEADLINE).map_err(|error| {
            Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
        })?;
        let delivery =
            crate::macos_deadline::add(retire, Duration::from_secs(1)).map_err(|error| {
                Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
            })?;
        let complete = complete && !matches!(release, memcordon_core::ReleaseEvidence::Unknown);
        Ok(memcordon_core::RuntimeEvidenceV1 {
            schema_version: 1,
            clock: memcordon_core::ClockDomain::DarwinContinuousTicksV1 {
                boot_identity: boot_identity.clone(),
                ticks_per_second: 1_000_000_000,
            },
            run_origin: context.macos_run_origin_ns.unwrap_or(attempt_origin),
            attempt_origin,
            work_expires: work_expiry,
            startup_expires: startup_expiry,
            release,
            target_pid,
            terminal_observed: Some(terminal),
            force_requested: None,
            force_expires: Some(force),
            retirement_expires: Some(retire),
            delivery_expires: Some(delivery),
            retirement: if complete && retired <= retire {
                memcordon_core::RetirementEvidence::Complete {
                    at: retired,
                    target_reaped_or_absent: true,
                    group_reconciled: true,
                    detached_identities_discharged: true,
                    native_obligations_settled: true,
                    policy_retired: true,
                }
            } else {
                memcordon_core::RetirementEvidence::Unconfirmed {
                    last_owner: retained_owner.borrow().clone(),
                }
            },
            delivery: memcordon_core::DeliveryEvidence::NotSubmitted,
        })
    };
    let launch_result = crate::macos_launch::launch_controlled(
        command,
        memcordon_executable,
        startup_deadline,
        startup_cleanup_deadline,
        work_expiry,
        policy.limit_grace,
        policy.signal_grace,
        signal_source,
    );
    if let Err(startup) = &launch_result {
        let interruption = signal_source.take();
        let expired = policy.deadline.is_some()
            && (startup.error.kind() == io::ErrorKind::TimedOut || interruption.is_some())
            && work_expiry.is_some_and(|expiry| {
                startup.cancellation_observed.map_or_else(
                    || crate::macos_deadline::continuous_nanos().is_ok_and(|now| now >= expiry),
                    |observed| observed >= expiry,
                )
            });
        if interruption.is_some() || expired {
            let active = work_expiry.map_or(Duration::ZERO, |expiry| {
                Duration::from_nanos(expiry.saturating_sub(attempt_origin))
            });
            let complete = startup.diagnostic.cleanup.state
                == memcordon_core::NativeStartupCleanupStateV1::Complete
                && !matches!(startup.release, memcordon_core::ReleaseEvidence::Unknown);
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
            let mut backend = info();
            backend.metric = metric_name(policy.metric);
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
                outcome: if !expired {
                    RunOutcome::Interrupted {
                        signal: Interruption {
                            signal: interruption.expect("observed interruption"),
                        },
                        child_after_termination: None,
                        cleanup,
                    }
                } else {
                    let deadline = policy.deadline.expect("expired policy deadline");
                    RunOutcome::DeadlineExceeded {
                        deadline: DeadlineEvidence::new(
                            millis(deadline.duration()),
                            deadline.scope(),
                            "pre-spawn".into(),
                            millis(context.supervision_offset + active),
                            millis(
                                context.supervision_offset
                                    + Duration::from_nanos(
                                        crate::macos_deadline::continuous_nanos()
                                            .map_err(|error| {
                                                Error::new(
                                                    ErrorCategory::Monitor,
                                                    "MCMONITOR-CLOCK",
                                                    error.to_string(),
                                                )
                                            })?
                                            .saturating_sub(attempt_origin),
                                    ),
                            ),
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
                    }
                },
                backend,
                child_pid: startup
                    .diagnostic
                    .launcher_pid
                    .and_then(std::num::NonZeroU32::new),
                runtime: Some(runtime(
                    startup.release.clone(),
                    startup
                        .diagnostic
                        .launcher_pid
                        .and_then(std::num::NonZeroU32::new),
                    startup
                        .cancellation_observed
                        .map_or_else(|| crate::macos_deadline::continuous_nanos(), Ok)
                        .map_err(|error| {
                            Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                        })?,
                    if expired {
                        work_expiry.unwrap_or(startup_expiry)
                    } else {
                        startup
                            .cancellation_force
                            .map_or_else(|| crate::macos_deadline::continuous_nanos(), Ok)
                            .map_err(|error| {
                                Error::new(
                                    ErrorCategory::Monitor,
                                    "MCMONITOR-CLOCK",
                                    error.to_string(),
                                )
                            })?
                    },
                    complete,
                )?),
                duration: started.elapsed(),
                authorization_offset: match startup.release {
                    memcordon_core::ReleaseEvidence::Issued { at, .. } => {
                        Some(Duration::from_nanos(at.saturating_sub(current_tick)))
                    }
                    _ => None,
                },
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
        failure.target_pid = startup.diagnostic.launcher_pid;
        failure.guardian_ready_before_release = startup.diagnostic.guardian_ready;
        failure.workload_may_be_alive = startup.diagnostic.cleanup.state
            != memcordon_core::NativeStartupCleanupStateV1::Complete;
        failure.authorization_offset = match startup.release {
            memcordon_core::ReleaseEvidence::Issued { at, .. } => {
                Some(Duration::from_nanos(at.saturating_sub(current_tick)))
            }
            _ => None,
        };
        failure.cgroup_verified_before_release = startup.diagnostic.release_sent;
        if let Ok(now) = crate::macos_deadline::continuous_nanos() {
            failure.runtime = runtime(
                startup.release.clone(),
                startup
                    .diagnostic
                    .launcher_pid
                    .and_then(std::num::NonZeroU32::new),
                now,
                now,
                !failure.workload_may_be_alive,
            )
            .ok();
        }
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
    let force_receipt = guardian.force_receipt().map_err(|error| {
        Error::new(
            ErrorCategory::Monitor,
            "MCMONITOR-GUARDIAN",
            error.to_string(),
        )
    })?;
    let guardian_pid = guardian.pid();
    if let Ok(identity) = inspect_until(Instant::now() + Duration::from_millis(100), move || {
        process_snapshot(guardian_pid as i32)
            .map(|snapshot| snapshot.identity)
            .map_err(|error| error.to_string())
    }) {
        if let Some(start_identity) = identity
            .start_seconds
            .checked_mul(1_000_000)
            .and_then(|value| value.checked_add(identity.start_microseconds))
        {
            *retained_owner.borrow_mut() =
                std::num::NonZeroU32::new(guardian_pid).map(|pid| memcordon_core::OwnerIdentity {
                    pid,
                    start_identity,
                });
        }
    }
    let release_tick = launch.release_tick;
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
    let terminal_tick = std::cell::Cell::new(None);
    let force_tick = std::cell::Cell::new(None);
    let cleanup_budget = || {
        terminal_tick.set(
            terminal_tick
                .get()
                .or_else(|| crate::macos_deadline::continuous_nanos().ok()),
        );
        force_tick.set(force_tick.get().or(terminal_tick.get()));
        if let Some(deadline) = cleanup_expiry.get() {
            return Some(deadline);
        }
        let cap = CLEANUP_DEADLINE;
        let deadline = Instant::now() + cap;
        cleanup_expiry.set(Some(deadline));
        Some(deadline)
    };
    let mut stored_status = None;
    let mut peak = 0_u64;

    let mut pending_signal = None;
    let terminate_and_cleanup = |child: &mut Child,
                                 stored: &mut Option<ChildTermination>,
                                 root,
                                 known: &mut HashSet<ProcessIdentity>,
                                 inventory_query: &mut Option<u64>,
                                 signal,
                                 grace,
                                 deadline| {
        retire_workload(
            &guardian,
            child,
            stored,
            root,
            known,
            inventory_query,
            (signal, grace),
            deadline,
        )
    };
    let mut command_exit_grace_started = None;
    let mut inventory_query = None;
    let mut next_heartbeat = Instant::now();
    let mut outcome = loop {
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
        let mut cycle_error = None;
        let mut completion = None;
        let mut workload_empty = false;
        match try_reap(&mut child, &mut stored_status, inspection_deadline) {
            Ok(Some(status)) => {
                if policy.lifetime == Lifetime::Command {
                    completion = Some(status);
                    command_exit_grace_started.get_or_insert_with(Instant::now);
                }
            }
            Ok(None) => {}
            Err(error) => {
                cycle_error = Some(error);
            }
        }
        // The sampling deadline controls admission. Once admitted, retain one
        // transaction across watchdog turns so host signals and native work
        // deadlines remain responsive while inspectors finish within the fixed
        // retirement reserve. Never replace a pending query with a retry.
        let mut inventory_result = None;
        let inventory_was_pending = inventory_query.is_some();
        if let Some(query) = inventory_query {
            match guardian.poll_inventory(query) {
                Ok(Some(inventory)) => {
                    inventory_query = None;
                    inventory_result = Some(Ok(inventory));
                }
                Ok(None) => {}
                Err(error) => {
                    inventory_query = None;
                    inventory_result = Some(Err(error));
                }
            }
        }
        // An admitted inventory response is itself a live transaction. Poll it
        // before emitting another control frame, and send heartbeats at a fixed
        // cadence within the lease while it remains pending. This prevents an exited
        // command with zero grace from flooding the guardian's control socket.
        if inventory_result.is_none()
            && (!inventory_was_pending || Instant::now() >= next_heartbeat)
        {
            if let Err(error) = guardian.alive(inspection_deadline) {
                cycle_error = Some(error.to_string());
            }
            next_heartbeat = Instant::now() + PENDING_INVENTORY_HEARTBEAT_INTERVAL;
        }
        if inventory_query.is_none() && inventory_result.is_none() {
            let inventory_response_deadline = inspection_deadline
                .checked_add(CLEANUP_DEADLINE)
                .expect("fixed inventory response reserve is representable");
            let inventory_response_deadline = if let Some(expiry) = work_expiry {
                let now = crate::macos_deadline::continuous_nanos().map_err(|error| {
                    Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                })?;
                let retirement = crate::macos_deadline::add(
                    crate::macos_deadline::add(expiry, policy.limit_grace).map_err(|error| {
                        Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                    })?,
                    CLEANUP_DEADLINE,
                )
                .map_err(|error| {
                    Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                })?;
                inventory_response_deadline
                    .min(Instant::now() + Duration::from_nanos(retirement.saturating_sub(now)))
            } else {
                inventory_response_deadline
            };
            match guardian.begin_inventory_with_metric(
                policy.memory.map(|_| policy.metric),
                inspection_deadline,
                inventory_response_deadline,
            ) {
                Ok(query) => inventory_query = Some(query),
                Err(error) => inventory_result = Some(Err(error)),
            }
        }
        if !inventory_was_pending && let Some(query) = inventory_query {
            match guardian.poll_inventory(query) {
                Ok(Some(inventory)) => {
                    inventory_query = None;
                    inventory_result = Some(Ok(inventory));
                }
                Ok(None) => {}
                Err(error) => {
                    inventory_query = None;
                    inventory_result = Some(Err(error));
                }
            }
        }
        match inventory_result {
            None => {}
            Some(Ok((snapshots, identities, sample))) => {
                known = identities;
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
                if let Some(limit) = policy.memory.filter(|_| !workload_empty) {
                    match sample
                        .ok_or_else(|| "guardian sample response missing".to_owned())
                        .and_then(|sample| sample)
                    {
                        Ok(usage) => {
                            peak = peak.max(usage);
                            if usage >= limit.bytes() {
                                let now =
                                    crate::macos_deadline::continuous_nanos().map_err(|error| {
                                        Error::new(
                                            ErrorCategory::Monitor,
                                            "MCMONITOR-CLOCK",
                                            error.to_string(),
                                        )
                                    })?;
                                terminal_tick.set(Some(now));
                                force_tick.set(Some(
                                    crate::macos_deadline::add(now, policy.limit_grace).map_err(
                                        |error| {
                                            Error::new(
                                                ErrorCategory::Monitor,
                                                "MCMONITOR-CLOCK",
                                                error.to_string(),
                                            )
                                        },
                                    )?,
                                ));
                                cleanup_expiry.set(Some(
                                    Instant::now() + policy.limit_grace + CLEANUP_DEADLINE,
                                ));
                                let cleanup = terminate_and_cleanup(
                                    &mut child,
                                    &mut stored_status,
                                    root_pid,
                                    &mut known,
                                    &mut inventory_query,
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
            Some(Err(error)) => {
                if cycle_error.is_none() {
                    cycle_error = Some(error);
                }
            }
        }

        if let Some(deadline) = policy.deadline {
            let active_duration = work_expiry.map_or(deadline.duration(), |expiry| {
                Duration::from_nanos(expiry.saturating_sub(attempt_origin))
            });
            let clock_now = crate::macos_deadline::continuous_nanos().map_err(|error| {
                Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
            })?;
            if work_expiry.is_some_and(|expiry| clock_now >= expiry) {
                let observed = Duration::from_nanos(clock_now.saturating_sub(attempt_origin));
                terminal_tick.set(Some(clock_now));
                let grace_started = Instant::now();
                let continuous_force = crate::macos_deadline::add(
                    work_expiry.expect("deadline exists"),
                    policy.limit_grace,
                )
                .map_err(|error| {
                    Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                })?;
                let force = Instant::now()
                    + Duration::from_nanos(continuous_force.saturating_sub(clock_now));
                force_tick.set(Some(continuous_force));
                let effective_grace = force.saturating_duration_since(Instant::now());
                let remaining_retirement = crate::macos_deadline::remaining_retirement(
                    continuous_force,
                    clock_now,
                    CLEANUP_DEADLINE,
                )
                .map_err(|error| {
                    Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                })?;
                cleanup_expiry.set(Some(Instant::now() + remaining_retirement));
                let cleanup = terminate_and_cleanup(
                    &mut child,
                    &mut stored_status,
                    root_pid,
                    &mut known,
                    &mut inventory_query,
                    if effective_grace.is_zero() {
                        libc::SIGKILL
                    } else {
                        libc::SIGTERM
                    },
                    effective_grace,
                    cleanup_budget(),
                );
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
                &mut inventory_query,
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
            let now = crate::macos_deadline::continuous_nanos().map_err(|error| {
                Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
            })?;
            terminal_tick.set(Some(now));
            force_tick.set(Some(
                crate::macos_deadline::add(now, policy.signal_grace).map_err(|error| {
                    Error::new(ErrorCategory::Monitor, "MCMONITOR-CLOCK", error.to_string())
                })?,
            ));
            cleanup_expiry.set(Some(
                Instant::now() + policy.signal_grace + CLEANUP_DEADLINE,
            ));
            let cleanup = terminate_and_cleanup(
                &mut child,
                &mut stored_status,
                root_pid,
                &mut known,
                &mut inventory_query,
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

        if let Some(status) = completion.filter(|_| inventory_query.is_none()) {
            let completed = if policy.lifetime == Lifetime::Workload || workload_empty {
                workload_empty
            } else if policy.command_exit_grace.is_zero() {
                true
            } else {
                let grace_started = command_exit_grace_started.get_or_insert_with(Instant::now);
                grace_started.elapsed() >= policy.command_exit_grace
            };
            if completed {
                // Natural completion starts its own fixed retirement reserve,
                // including when no termination or final memory sample is needed.
                let completion_deadline = cleanup_budget();
                let cleanup = if workload_empty {
                    CleanupSummary {
                        direct_child_reaped: false,
                        workload_empty: Some(true),
                        ..CleanupSummary::default()
                    }
                } else {
                    cleanup_after_direct_exit(
                        &guardian,
                        &mut child,
                        &mut stored_status,
                        root_pid,
                        &mut known,
                        &mut inventory_query,
                        completion_deadline,
                    )
                };
                break RunOutcome::Exited {
                    child: status,
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup,
                };
            }
        }

        let command_exit_grace_remaining = command_exit_grace_started.map(|grace_started| {
            policy
                .command_exit_grace
                .saturating_sub(grace_started.elapsed())
        });
        let wait = watchdog_turn_wait(
            policy.poll_interval,
            command_exit_grace_remaining,
            inventory_query.is_some(),
        );
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
                    &mut inventory_query,
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
    let inspections_settled = inspection_obligations() == 0;
    let child_reaped = if outcome.cleanup().workload_empty == Some(true) && inspections_settled {
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
    let mut helpers_reaped = inspections_settled;
    if !helpers_reaped {
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "retire-frontend-inspection".into(),
            message: "a queued or active native inspection remains runtime-owned".into(),
        });
    }
    let retirement = if outcome.cleanup().workload_empty == Some(true) && inspections_settled {
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
    let mut runtime = runtime(
        memcordon_core::ReleaseEvidence::Issued {
            at: release_tick,
            exec_confirmed: true,
        },
        std::num::NonZeroU32::new(child_pid),
        terminal_tick.get().unwrap_or(attempt_origin),
        force_tick.get().unwrap_or(attempt_origin),
        restart_safety.is_safe(),
    )?;
    let force_requested = force_receipt.load(std::sync::atomic::Ordering::Acquire);
    runtime.force_requested = (force_requested != 0).then_some(force_requested);
    if let Some(at) = runtime.force_requested {
        // The guardian can observe expiry and request force before the frontend
        // wakes. Its receipt is a concrete terminal observation in the same clock.
        runtime.terminal_observed = Some(
            runtime
                .terminal_observed
                .map_or(at, |observed| observed.min(at)),
        );
    }
    Ok(Execution {
        policy_enforcement: Default::default(),
        outcome,
        backend,
        child_pid: std::num::NonZeroU32::new(child_pid),
        runtime: Some(runtime),
        duration: started.elapsed(),
        authorization_offset: Some(Duration::from_nanos(
            release_tick.saturating_sub(current_tick),
        )),
        launch,
        restart_safety,
        boundary_detail,
    })
}

fn try_reap(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    deadline: Instant,
) -> Result<Option<ChildTermination>, String> {
    if let Some(status) = stored.clone() {
        return Ok(Some(status));
    }
    match child.observe_until(deadline) {
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

fn retirement_inventory(
    guardian: &crate::macos_launch::Guardian,
    inventory_query: &mut Option<u64>,
    deadline: Instant,
) -> Result<(Vec<ProcessSnapshot>, HashSet<ProcessIdentity>), String> {
    if let Some(query) = *inventory_query {
        loop {
            match guardian.poll_inventory(query) {
                Ok(Some((snapshots, identities, _))) => {
                    *inventory_query = None;
                    return Ok((snapshots, identities));
                }
                Ok(None) if Instant::now() < deadline => bounded_pause(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
                Ok(None) => {
                    return Err(
                        "retirement deadline expired with an admitted inventory query pending"
                            .into(),
                    );
                }
                Err(error) => {
                    *inventory_query = None;
                    return Err(error);
                }
            }
        }
    }
    guardian.inventory(deadline)
}

fn retire_workload(
    guardian: &crate::macos_launch::Guardian,
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    _root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    inventory_query: &mut Option<u64>,
    termination: (i32, Duration),
    retirement_deadline: Option<Instant>,
) -> CleanupSummary {
    let (initial_signal, grace) = termination;
    let mut summary = CleanupSummary {
        graceful_attempted: initial_signal != libc::SIGKILL,
        force_attempted: initial_signal == libc::SIGKILL,
        ..CleanupSummary::default()
    };
    let started = Instant::now();
    let deadline = retirement_deadline.unwrap_or_else(|| started + grace + CLEANUP_DEADLINE);
    let abandon_inventory = *inventory_query;
    match guardian.signal_stop_with_inventory(initial_signal, grace, deadline, abandon_inventory) {
        Ok(()) => *inventory_query = None,
        Err(error) => {
            summary.errors.push(CleanupErrorRecord {
                operation: "guardian-stop".into(),
                message: error.to_string(),
            });
        }
    }
    let mut empty = false;
    while Instant::now() < deadline {
        match retirement_inventory(guardian, inventory_query, deadline) {
            Ok((snapshots, identities)) => {
                *known = identities;
                if snapshots.is_empty() {
                    empty = true;
                    break;
                }
            }
            Err(message) => {
                summary.errors.push(CleanupErrorRecord {
                    operation: "guardian-retirement-inventory".into(),
                    message,
                });
                break;
            }
        }
        if started.elapsed() >= grace {
            summary.force_attempted = true;
        }
        bounded_pause(
            Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
    summary.workload_empty = empty.then_some(true);
    if !empty && summary.errors.is_empty() {
        summary.errors.push(CleanupErrorRecord {
            operation: "guardian-retirement-inventory".into(),
            message: "retirement deadline expired with unresolved workload membership".into(),
        });
    }
    while stored.is_none() && Instant::now() < deadline {
        match child.observe_until(deadline) {
            Ok(Some(status)) => *stored = Some(termination_from_status(status)),
            Ok(None) => bounded_pause(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            ),
            Err(error) => {
                summary.errors.push(CleanupErrorRecord {
                    operation: "observe-direct-child".into(),
                    message: error.to_string(),
                });
                break;
            }
        }
    }
    if stored.is_none() {
        summary.errors.push(CleanupErrorRecord {
            operation: "observe-direct-child".into(),
            message: "retirement deadline expired".into(),
        });
    }
    summary
}

fn cleanup_after_direct_exit(
    guardian: &crate::macos_launch::Guardian,
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    inventory_query: &mut Option<u64>,
    supervision_deadline: Option<Instant>,
) -> CleanupSummary {
    let deadline = supervision_deadline.map_or(Instant::now() + CLEANUP_DEADLINE, |deadline| {
        deadline.min(Instant::now() + CLEANUP_DEADLINE)
    });
    match retirement_inventory(guardian, inventory_query, deadline) {
        Ok((snapshots, _))
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
        Ok(_) => retire_workload(
            guardian,
            child,
            stored,
            root_pid,
            known,
            inventory_query,
            (libc::SIGKILL, Duration::ZERO),
            supervision_deadline,
        ),
        Err(error) => {
            let mut summary = retire_workload(
                guardian,
                child,
                stored,
                root_pid,
                known,
                inventory_query,
                (libc::SIGKILL, Duration::ZERO),
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

type Inspection = Box<dyn FnOnce() + Send>;
static INSPECTION_OBLIGATIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn inspection_obligations() -> usize {
    INSPECTION_OBLIGATIONS.load(std::sync::atomic::Ordering::Acquire)
}

struct InspectionObligation;

impl InspectionObligation {
    fn reserve() -> Self {
        INSPECTION_OBLIGATIONS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Self
    }
}

impl Drop for InspectionObligation {
    fn drop(&mut self) {
        INSPECTION_OBLIGATIONS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

static INSPECTOR: std::sync::OnceLock<Result<std::sync::mpsc::SyncSender<Inspection>, String>> =
    std::sync::OnceLock::new();
static EMERGENCY_INSPECTOR: std::sync::OnceLock<
    Result<std::sync::mpsc::SyncSender<Inspection>, String>,
> = std::sync::OnceLock::new();

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
    let lane = match admission {
        InspectionAdmission::Immediate => &INSPECTOR,
        InspectionAdmission::Cleanup => &EMERGENCY_INSPECTOR,
    };
    let worker = lane
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
    let obligation = InspectionObligation::reserve();
    let mut inspection: Inspection = Box::new(move || {
        if Instant::now() < deadline {
            let result = operation();
            drop(obligation);
            let _ = send.send(result);
        } else {
            drop(obligation);
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
    let inventory = list_inventory()?;
    let mut relevant = HashSet::from([root_pid]);
    relevant.extend(known.iter().map(|identity| identity.pid));
    if !inventory.unresolved.is_empty() {
        let mut changed = true;
        while changed {
            changed = false;
            for snapshot in &inventory.snapshots {
                if (snapshot.process_group == root_pid || relevant.contains(&snapshot.parent_pid))
                    && relevant.insert(snapshot.identity.pid)
                {
                    changed = true;
                }
            }
        }
        relevant.extend(list_pids(
            2,
            u32::try_from(root_pid).map_err(|_| "invalid root group")?,
        )?);
        let parents: Vec<_> = relevant.iter().copied().collect();
        for parent in parents {
            relevant.extend(list_pids(
                6,
                u32::try_from(parent).map_err(|_| "invalid parent identity")?,
            )?);
        }
    }
    reconcile_inventory(root_pid, known, inventory, &relevant)
}

pub(crate) fn guardian_inventory(
    root: i32,
    known: &mut HashSet<ProcessIdentity>,
    signal: Option<i32>,
) -> Result<Vec<ProcessSnapshot>, String> {
    let snapshots = discover_native(root, known)?;
    if let Some(signal) = signal {
        for snapshot in &snapshots {
            match process_snapshot(snapshot.identity.pid) {
                Ok(current) if current.identity == snapshot.identity => {
                    let mut summary = CleanupSummary::default();
                    kill_pid(snapshot.identity.pid, signal, &mut summary);
                    if let Some(error) = summary.errors.first() {
                        return Err(error.message.clone());
                    }
                }
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
                Err(error) => return Err(format!("guardian identity is unconfirmed: {error}")),
            }
        }
    }
    Ok(snapshots)
}

fn reconcile_inventory(
    root_pid: i32,
    known: &mut HashSet<ProcessIdentity>,
    inventory: Inventory,
    relevant: &HashSet<i32>,
) -> Result<Vec<ProcessSnapshot>, String> {
    let by_pid: HashMap<_, _> = inventory
        .snapshots
        .iter()
        .copied()
        .map(|snapshot| (snapshot.identity.pid, snapshot))
        .collect();
    // Metadata uncertainty does not discharge an already observed identity.
    known.retain(|identity| {
        inventory.unresolved.contains(&identity.pid)
            || by_pid
                .get(&identity.pid)
                .is_some_and(|snapshot| snapshot.identity == *identity)
    });
    if let Some(root) = by_pid.get(&root_pid) {
        known.insert(root.identity);
    }
    let mut changed = true;
    while changed {
        changed = false;
        for snapshot in &inventory.snapshots {
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
    if inventory
        .unresolved
        .iter()
        .any(|pid| relevant.contains(pid) || known.iter().any(|identity| identity.pid == *pid))
    {
        return Err(
            "workload identity has unresolved native metadata; absence is unconfirmed".into(),
        );
    }
    Ok(inventory
        .snapshots
        .into_iter()
        .filter(|snapshot| !snapshot.zombie && known.contains(&snapshot.identity))
        .collect())
}

struct Inventory {
    snapshots: Vec<ProcessSnapshot>,
    unresolved: Vec<i32>,
}

#[cfg(feature = "test-support")]
pub type InventoryReconciliation = (Result<Vec<i32>, String>, Vec<(i32, u64)>);

#[cfg(feature = "test-support")]
pub fn inventory_reconciliation(
    known: &[(i32, u64)],
    snapshots: &[(i32, u64, i32, i32, bool)],
    unresolved: &[i32],
    relevant: &[i32],
) -> InventoryReconciliation {
    let mut known: HashSet<_> = known
        .iter()
        .map(|(pid, birth)| ProcessIdentity {
            pid: *pid,
            start_seconds: *birth,
            start_microseconds: 0,
        })
        .collect();
    let inventory = Inventory {
        snapshots: snapshots
            .iter()
            .map(|(pid, birth, parent, group, zombie)| ProcessSnapshot {
                identity: ProcessIdentity {
                    pid: *pid,
                    start_seconds: *birth,
                    start_microseconds: 0,
                },
                parent_pid: *parent,
                process_group: *group,
                zombie: *zombie,
            })
            .collect(),
        unresolved: unresolved.to_vec(),
    };
    let result = reconcile_inventory(
        100,
        &mut known,
        inventory,
        &relevant.iter().copied().collect(),
    )
    .map(|snapshots| {
        snapshots
            .iter()
            .map(|snapshot| snapshot.identity.pid)
            .collect()
    });
    let mut retained: Vec<_> = known
        .iter()
        .map(|identity| (identity.pid, identity.start_seconds))
        .collect();
    retained.sort_unstable();
    (result, retained)
}

fn list_inventory() -> Result<Inventory, String> {
    let pids = list_pids(1, 0)?;
    let mut inventory = Inventory {
        snapshots: Vec::new(),
        unresolved: Vec::new(),
    };
    for pid in pids.into_iter().filter(|pid| *pid > 0) {
        match process_snapshot(pid) {
            Ok(snapshot) => inventory.snapshots.push(snapshot),
            Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {}
            Err(_) => inventory.unresolved.push(pid),
        }
    }
    Ok(inventory)
}

fn list_pids(kind: u32, identity: u32) -> Result<Vec<i32>, String> {
    // The direct API returns bytes (unlike proc_listallpids' PID count). A fixed
    // native capacity makes both allocation and overflow interpretation explicit.
    let mut pids = vec![0_i32; 32768];
    let byte_length = pids
        .len()
        .checked_mul(std::mem::size_of::<i32>())
        .and_then(|length| i32::try_from(length).ok())
        .ok_or("PID buffer range")?;
    // SAFETY: __error is this thread's errno; clear it before the native call so
    // a zero reply cannot inherit a prior ESRCH and certify false absence.
    unsafe {
        *libc::__error() = 0;
    }
    // SAFETY: storage is writable for byte_length bytes and selectors are native constants.
    let filled = unsafe { proc_listpids(kind, identity, pids.as_mut_ptr().cast(), byte_length) };
    let error = io::Error::last_os_error();
    decode_pid_inventory(kind, pids, filled, error)
}

fn decode_pid_inventory(
    kind: u32,
    mut pids: Vec<i32>,
    filled: i32,
    error: io::Error,
) -> Result<Vec<i32>, String> {
    if filled < 0 || (filled == 0 && error.raw_os_error() != Some(0)) {
        return Err(format!("native PID inventory failed: {error}"));
    }
    let bytes = usize::try_from(filled).map_err(|_| "negative PID byte count")?;
    if bytes
        >= pids
            .len()
            .checked_mul(std::mem::size_of::<i32>())
            .ok_or("PID buffer range")?
    {
        return Err("native process inventory saturated; absence is unconfirmed".into());
    }
    if bytes % std::mem::size_of::<i32>() != 0 || (kind == 1 && bytes == 0) {
        return Err("native process inventory has an invalid byte count".into());
    }
    pids.truncate(bytes / std::mem::size_of::<i32>());
    pids.retain(|pid| *pid > 0);
    Ok(pids)
}

#[cfg(feature = "test-support")]
pub fn pid_inventory_reply(
    kind: u32,
    pids: Vec<i32>,
    filled: i32,
    errno: i32,
) -> Result<Vec<i32>, String> {
    decode_pid_inventory(kind, pids, filled, io::Error::from_raw_os_error(errno))
}

#[cfg(feature = "test-support")]
pub(crate) fn fixture_root_exited(pid: i32) -> io::Result<bool> {
    match process_snapshot(pid) {
        Ok(snapshot) => Ok(snapshot.zombie),
        // Darwin may stop publishing BSD metadata for a zombie. The fixture's
        // stopped guardian still owns this unreaped PID, so reuse is impossible.
        Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(true),
        Err(error) => Err(error),
    }
}

fn process_snapshot(pid: i32) -> Result<ProcessSnapshot, io::Error> {
    let mut info = MaybeUninit::<ProcBsdInfo>::zeroed();
    let size = i32::try_from(std::mem::size_of::<ProcBsdInfo>())
        .map_err(|_| io::Error::other("proc_bsdinfo size cannot fit c_int"))?;
    // SAFETY: `info` points to writable storage of `size` bytes and is initialized only if the
    // function reports that exact structure size.
    unsafe {
        *libc::__error() = 0;
    }
    let read = unsafe { proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, info.as_mut_ptr().cast(), size) };
    if read != size {
        let error = io::Error::last_os_error();
        return Err(if read > 0 || error.raw_os_error() == Some(0) {
            io::Error::other("native process metadata reply has an invalid size")
        } else {
            error
        });
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

pub(crate) fn sample_native(snapshots: &[ProcessSnapshot], metric: Metric) -> Result<u64, String> {
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
