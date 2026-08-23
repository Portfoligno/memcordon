use std::collections::HashMap;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, DeadlineEvidence,
    Enforcement, Error, ErrorCategory, InitialSpawnFailure, Interruption, Lifetime, LimitEvidence,
    Policy, RestartSafetyProof, RunOutcome, SwapPolicy,
};

use crate::backend::{
    BackendCleanupFacts, BackendInfo, Execution, ProbeReport, UnavailableBackend,
};
use crate::guardian::Guardian;
use crate::signal::SignalSource;

const CLEANUP_DEADLINE: Duration = Duration::from_secs(5);
const LAUNCHER_STATUS_DEADLINE: Duration = Duration::from_secs(10);
const LAUNCHER_STATUS_MAGIC: &[u8; 4] = b"MCLS";
const LAUNCHER_STATUS_VERSION: u8 = 1;
const LAUNCHER_STATUS_LENGTH: usize = 12;
const LAUNCHER_STATUS_READY: u8 = 1;
const LAUNCHER_STATUS_ERROR: u8 = 2;

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn bounded_pause(duration: Duration) {
    let timeout = duration.as_millis().min(i32::MAX as u128) as i32;
    // SAFETY: zero-descriptor poll is a bounded kernel wait and remains signal-interruptible.
    unsafe { libc::poll(std::ptr::null_mut(), 0, timeout) };
}

pub fn probe() -> ProbeReport {
    match delegated_parent(true) {
        Ok(path) => {
            if let Err(error) = probe_delegated_parent(&path) {
                return unavailable(error);
            }
            let backend = info();
            ProbeReport {
                selected: Some(backend.clone()),
                available: vec![backend],
                unavailable: Vec::new(),
            }
        }
        Err(error) => unavailable(error),
    }
}

fn probe_delegated_parent(parent: &Path) -> Result<(), String> {
    let child = create_cgroup(parent).map_err(|error| {
        format!(
            "cannot create a probe cgroup under {}: {error}",
            parent.display()
        )
    })?;
    let controls = check_probe_cgroup(&child);
    let removal = fs::remove_dir(&child).map_err(|error| {
        format!(
            "cannot remove the empty probe cgroup {}: {error}",
            child.display()
        )
    });
    match (controls, removal) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(check_error), Err(removal_error)) => Err(format!("{check_error}; {removal_error}")),
    }
}

fn check_probe_cgroup(path: &Path) -> Result<(), String> {
    let required = [
        "cgroup.procs",
        "cgroup.events",
        "cgroup.kill",
        "memory.current",
        "memory.events",
        "memory.max",
        "memory.swap.max",
    ];
    if let Some(missing) = required.iter().find(|name| !path.join(name).exists()) {
        return Err(format!("probe cgroup {} lacks {missing}", path.display()));
    }
    for readable in [
        "cgroup.procs",
        "cgroup.events",
        "memory.current",
        "memory.events",
        "memory.max",
    ] {
        fs::read_to_string(path.join(readable)).map_err(|error| {
            format!(
                "cannot read {readable} in probe cgroup {}: {error}",
                path.display()
            )
        })?;
    }
    fs::write(path.join("memory.max"), "max\n").map_err(|error| {
        format!(
            "cannot write memory.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    let memory_max = fs::read_to_string(path.join("memory.max")).map_err(|error| {
        format!(
            "cannot read back memory.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    if memory_max.trim() != "max" {
        return Err(format!(
            "memory.max read-back in probe cgroup {} was {memory_max:?}",
            path.display()
        ));
    }
    fs::write(path.join("memory.swap.max"), "0\n").map_err(|error| {
        format!(
            "cannot write memory.swap.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    let memory_swap_max = fs::read_to_string(path.join("memory.swap.max")).map_err(|error| {
        format!(
            "cannot read back memory.swap.max in probe cgroup {}: {error}",
            path.display()
        )
    })?;
    if memory_swap_max.trim() != "0" {
        return Err(format!(
            "memory.swap.max read-back in probe cgroup {} was {memory_swap_max:?}",
            path.display()
        ));
    }
    Ok(())
}

fn unavailable(reason: String) -> ProbeReport {
    ProbeReport {
        selected: None,
        available: Vec::new(),
        unavailable: vec![UnavailableBackend {
            name: "linux-cgroup-v2",
            reason,
        }],
    }
}

#[allow(
    clippy::result_large_err,
    reason = "cleanup propagates the categorized Error unchanged through the public boundary"
)]
pub fn cleanup_stale(dry_run: bool) -> Result<Vec<String>, Error> {
    let parent = delegated_parent(false).map_err(|message| {
        Error::new(
            ErrorCategory::Setup,
            "MCSETUP-CGROUP-NOT-DELEGATED",
            message,
        )
    })?;
    // SAFETY: geteuid has no preconditions.
    let prefix = format!("memcordon-{}-", unsafe { libc::geteuid() });
    let entries = fs::read_dir(&parent).map_err(setup_io)?;
    let mut cleaned = Vec::new();
    for entry in entries {
        let entry = entry.map_err(setup_io)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(&prefix) || !entry.file_type().map_err(setup_io)?.is_dir() {
            continue;
        }
        let path = entry.path();
        if !path.join("cgroup.procs").exists()
            || !path.join("cgroup.events").exists()
            || !path.join("cgroup.kill").exists()
        {
            continue;
        }
        let populated =
            parse_key_values(&fs::read_to_string(path.join("cgroup.events")).map_err(setup_io)?)
                .map_err(setup_io)?
                .get("populated")
                .copied()
                .unwrap_or(0)
                != 0;
        if populated {
            // Cleanup never kills or removes a live cgroup merely because its name matches.
            continue;
        }
        if !dry_run {
            fs::remove_dir(&path).map_err(setup_io)?;
        }
        cleaned.push(path.display().to_string());
    }
    Ok(cleaned)
}

fn info() -> BackendInfo {
    BackendInfo {
        name: "linux-cgroup-v2",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "linux-cgroup-memory",
        hard_limit: true,
        startup_containment: "gated launcher assigned to cgroup before target exec",
        limitations: vec![
            "requires delegated cgroup v2 memory controller",
            "kernel may temporarily report memory.current above memory.max",
            "swap accounting is a separate policy",
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
    memcordon_executable: &Path,
    signal_source: &SignalSource,
    context: crate::supervisor::AttemptContext,
) -> Result<Execution, Error> {
    if policy.enforcement == Enforcement::Watchdog {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-LINUX-WATCHDOG",
            "the Linux sampled watchdog is not enabled; no target was launched",
        ));
    }
    let started = Instant::now();
    let parent = delegated_parent(policy.memory.is_some()).map_err(|message| {
        Error::new(
            ErrorCategory::Setup,
            "MCSETUP-CGROUP-NOT-DELEGATED",
            message,
        )
    })?;
    let path = create_cgroup(&parent).map_err(setup_io)?;
    let mut cgroup = Cgroup { path };
    cgroup.configure(&policy).map_err(setup_io)?;
    let baseline = if policy.memory.is_some() {
        Some(cgroup.memory_events().map_err(setup_io)?)
    } else {
        None
    };
    let (mut child, release_fd, exec_status_fd) = spawn_gated(command, memcordon_executable)?;
    let child_pid = match i32::try_from(child.id()) {
        Ok(child_pid) => child_pid,
        Err(_) => {
            let mut failure = Error::new(
                ErrorCategory::Spawn,
                "MCSPAWN-PID-RANGE",
                "child PID cannot be represented by native APIs",
            );
            failure.launch_phase = Some("launcher-spawned");
            let abort = abort_gated(
                &mut cgroup,
                &mut child,
                Some(release_fd),
                exec_status_fd,
                context.clamp_deadline(started, CLEANUP_DEADLINE),
            );
            failure.workload_may_be_alive = abort.workload_may_be_alive;
            record_failure_cleanup(&mut failure, abort.cleanup, true, false);
            return Err(failure);
        }
    };
    let ready_deadline = context.clamp_deadline(started, LAUNCHER_STATUS_DEADLINE);
    if let Err(error) = receive_launcher_ready(exec_status_fd, ready_deadline) {
        let abort = abort_gated(
            &mut cgroup,
            &mut child,
            Some(release_fd),
            exec_status_fd,
            context.clamp_deadline(started, CLEANUP_DEADLINE),
        );
        let supervision_expired = error.kind() == io::ErrorKind::TimedOut
            && context
                .supervision_deadline(started)
                .is_some_and(|deadline| deadline <= ready_deadline);
        let mut failure = helper_setup_error(
            if supervision_expired {
                "MCSUPERVISION-DEADLINE-BEFORE-AUTHORIZATION"
            } else {
                "MCSETUP-MEMCORDON-LAUNCHER-PROTOCOL"
            },
            memcordon_executable,
            error,
        );
        failure.target_pid = u32::try_from(child_pid).ok();
        failure.launch_phase = Some("launcher-ready");
        failure.workload_may_be_alive = abort.workload_may_be_alive;
        record_failure_cleanup(&mut failure, abort.cleanup, true, false);
        return Err(failure);
    }
    if let Err(error) = cgroup
        .assign(child_pid)
        .and_then(|()| cgroup.verify(child_pid))
    {
        let abort = abort_gated(
            &mut cgroup,
            &mut child,
            Some(release_fd),
            exec_status_fd,
            context.clamp_deadline(started, CLEANUP_DEADLINE),
        );
        let mut failure = setup_io(error);
        failure.target_pid = u32::try_from(child_pid).ok();
        failure.launch_phase = Some("cgroup-assignment");
        failure.workload_may_be_alive = abort.workload_may_be_alive;
        record_failure_cleanup(&mut failure, abort.cleanup, true, false);
        return Err(failure);
    }
    let guardian = match Guardian::spawn(child_pid, memcordon_executable) {
        Ok(guardian) => guardian,
        Err(error) => {
            let abort = abort_gated(
                &mut cgroup,
                &mut child,
                Some(release_fd),
                exec_status_fd,
                context.clamp_deadline(started, CLEANUP_DEADLINE),
            );
            let mut failure =
                helper_setup_error("MCSETUP-MEMCORDON-GUARDIAN", memcordon_executable, error);
            failure.target_pid = u32::try_from(child_pid).ok();
            failure.launch_phase = Some("guardian-start");
            failure.cgroup_verified_before_release = true;
            failure.workload_may_be_alive = abort.workload_may_be_alive;
            record_failure_cleanup(&mut failure, abort.cleanup, true, false);
            return Err(failure);
        }
    };
    let authorized = Instant::now();
    if let Err(error) = release_launcher(release_fd) {
        let cleanup_deadline = context.clamp_deadline(started, CLEANUP_DEADLINE);
        let abort = abort_gated(
            &mut cgroup,
            &mut child,
            None,
            exec_status_fd,
            cleanup_deadline,
        );
        let mut cleanup = abort.cleanup;
        let guardian_shutdown = guardian.disarm_until(cleanup_deadline);
        for error in guardian_shutdown.errors {
            cleanup
                .errors
                .push(cleanup_error(error.operation, error.error));
        }
        let mut failure = setup_io(error);
        failure.target_pid = u32::try_from(child_pid).ok();
        failure.launch_phase = Some("launcher-release");
        failure.cgroup_verified_before_release = true;
        failure.workload_may_be_alive =
            abort.workload_may_be_alive || guardian_shutdown.may_be_alive;
        record_failure_cleanup(
            &mut failure,
            cleanup,
            !guardian_shutdown.may_be_alive,
            false,
        );
        return Err(failure);
    }
    let exec_status_deadline = context.clamp_deadline(started, LAUNCHER_STATUS_DEADLINE);
    let mut launcher_deadline_outcome = None;
    match receive_exec_result(exec_status_fd, exec_status_deadline) {
        Ok(None) => {}
        Ok(Some(error)) => {
            let mut stored = None;
            let mut cleanup = cgroup.cleanup_workload(
                &mut child,
                &mut stored,
                false,
                context.clamp_deadline(started, CLEANUP_DEADLINE),
            );
            let helpers_reaped =
                match guardian.disarm(context.clamp_deadline(started, CLEANUP_DEADLINE)) {
                    Ok(()) => true,
                    Err(error) => {
                        cleanup.errors.push(cleanup_error("guardian-disarm", error));
                        false
                    }
                };
            let containment_removed = match cgroup.remove() {
                Ok(()) => true,
                Err(error) => {
                    cleanup.errors.push(cleanup_error("remove-cgroup", error));
                    false
                }
            };
            let mut failure = spawn_error(error, command);
            failure.target_pid = u32::try_from(child_pid).ok();
            failure.launch_phase = Some("target-spawn-failed");
            failure =
                failure.with_authorization_offset(authorized.saturating_duration_since(started));
            failure.cgroup_verified_before_release = true;
            record_failure_cleanup(&mut failure, cleanup, helpers_reaped, containment_removed);
            return Err(failure);
        }
        Err(error)
            if error.kind() == io::ErrorKind::TimedOut
                && context
                    .supervision_deadline(started)
                    .is_some_and(|deadline| deadline <= exec_status_deadline) =>
        {
            let mut stored = None;
            let cleanup = cgroup.cleanup_workload(
                &mut child,
                &mut stored,
                true,
                context.clamp_deadline(started, CLEANUP_DEADLINE),
            );
            let deadline = policy
                .deadline
                .expect("supervision deadline requires policy deadline");
            let active_duration = context
                .supervision_deadline_remaining
                .expect("classified supervision deadline has remaining duration");
            let observed = authorized.elapsed();
            launcher_deadline_outcome = Some(RunOutcome::DeadlineExceeded {
                deadline: DeadlineEvidence::new(
                    millis(deadline.duration()),
                    deadline.scope(),
                    "installed-cli-release-byte".to_owned(),
                    millis(context.supervision_offset + active_duration),
                    millis(context.supervision_offset + observed),
                    millis(policy.limit_grace),
                    0,
                    None,
                    Some("cgroup-kill".to_owned()),
                )
                .map_err(|_| {
                    Error::new(
                        ErrorCategory::Monitor,
                        "MCLIMIT-DEADLINE-EVIDENCE",
                        "deadline evidence is inconsistent",
                    )
                })?,
                child_after_termination: stored.clone(),
                peak: policy.memory.map(|_| ByteSize::from_bytes(0)),
                cleanup,
            });
        }
        Err(error) => {
            let mut stored = None;
            let mut cleanup = cgroup.cleanup_workload(
                &mut child,
                &mut stored,
                true,
                context.clamp_deadline(started, CLEANUP_DEADLINE),
            );
            let helpers_reaped =
                match guardian.disarm(context.clamp_deadline(started, CLEANUP_DEADLINE)) {
                    Ok(()) => true,
                    Err(error) => {
                        cleanup.errors.push(cleanup_error("guardian-disarm", error));
                        false
                    }
                };
            let containment_removed = match cgroup.remove() {
                Ok(()) => true,
                Err(error) => {
                    cleanup.errors.push(cleanup_error("remove-cgroup", error));
                    false
                }
            };
            let mut failure = helper_setup_error(
                "MCSETUP-MEMCORDON-LAUNCHER-PROTOCOL",
                memcordon_executable,
                error,
            );
            failure.target_pid = u32::try_from(child_pid).ok();
            failure.launch_phase = Some("launcher-exec-status");
            failure =
                failure.with_authorization_offset(authorized.saturating_duration_since(started));
            failure.cgroup_verified_before_release = true;
            record_failure_cleanup(&mut failure, cleanup, helpers_reaped, containment_removed);
            return Err(failure);
        }
    }
    let monitor_failure_ready = monitor_failure_ready_file(command);
    let mut stored = None;
    let mut peak = 0_u64;
    let mut pending_signal = None;
    let mut command_exit_grace_started = None;
    let mut outcome = if let Some(outcome) = launcher_deadline_outcome {
        outcome
    } else {
        loop {
            let mut cycle_error = None;
            let direct_status = match try_reap(&mut child, &mut stored) {
                Ok(status) => status,
                Err(error) => {
                    cycle_error = Some(format!("direct-child wait failed: {error}"));
                    None
                }
            };

            let memory_due = baseline.as_ref().is_some_and(|baseline| {
                cgroup
                    .memory_events()
                    .ok()
                    .is_some_and(|events| limit_delta(baseline, &events).is_some())
            });
            if let Some(deadline) = policy.deadline {
                let active_duration = context
                    .supervision_deadline_remaining
                    .unwrap_or_else(|| deadline.duration());
                if authorized.elapsed() >= active_duration && !memory_due {
                    let grace_started = Instant::now();
                    let effective_grace = context.supervision_deadline(started).map_or(
                        policy.limit_grace,
                        |deadline| {
                            policy
                                .limit_grace
                                .min(deadline.saturating_duration_since(Instant::now()))
                        },
                    );
                    let interrupted = if !policy.limit_grace.is_zero() {
                        cgroup.signal_group(child_pid, libc::SIGTERM);
                        signal_source.wait(effective_grace).ok().flatten()
                    } else {
                        signal_source.take()
                    };
                    if let Some(signal) = interrupted {
                        cgroup.signal_group(child_pid, signal);
                    }
                    let cleanup = cgroup.cleanup_workload(
                        &mut child,
                        &mut stored,
                        true,
                        context.clamp_deadline(started, CLEANUP_DEADLINE),
                    );
                    let observed = authorized.elapsed();
                    if let Some(signal) = interrupted {
                        break RunOutcome::Interrupted {
                            signal: Interruption { signal },
                            child_after_termination: stored.clone(),
                            cleanup,
                        };
                    }
                    break RunOutcome::DeadlineExceeded {
                        deadline: DeadlineEvidence::new(
                            millis(deadline.duration()),
                            deadline.scope(),
                            "installed-cli-release-byte".to_owned(),
                            millis(context.supervision_offset + active_duration),
                            millis(context.supervision_offset + observed),
                            millis(policy.limit_grace),
                            millis(grace_started.elapsed().min(effective_grace)),
                            (!policy.limit_grace.is_zero())
                                .then(|| "sigterm-process-group".to_owned()),
                            Some("cgroup-kill".to_owned()),
                        )
                        .map_err(|_| {
                            Error::new(
                                ErrorCategory::Monitor,
                                "MCLIMIT-DEADLINE-EVIDENCE",
                                "deadline evidence is inconsistent",
                            )
                        })?,
                        child_after_termination: stored.clone(),
                        peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                        cleanup,
                    };
                }
            }

            let events = match baseline
                .as_ref()
                .map(|_| cgroup.memory_events())
                .transpose()
            {
                Ok(events) => events,
                Err(error) => {
                    let cleanup = cgroup.cleanup_workload(
                        &mut child,
                        &mut stored,
                        true,
                        context.clamp_deadline(started, CLEANUP_DEADLINE),
                    );
                    break RunOutcome::MonitorFailed {
                        error: format!("memory.events read failed: {error}"),
                        child_after_termination: stored.clone(),
                        cleanup,
                    };
                }
            };
            // A cgroup OOM can reap the direct child before the next monitor pass. Collect the
            // authoritative kernel event before classifying that stored SIGKILL as an ordinary exit.
            if let (Some(baseline), Some(events), Some(limit)) =
                (baseline.as_ref(), events.as_ref(), policy.memory)
            {
                if let Some(mut detail) = limit_delta(baseline, events) {
                    let observed = match cgroup.current(monitor_failure_ready.as_deref()) {
                        Ok(usage) => {
                            peak = peak.max(usage);
                            Some(ByteSize::from_bytes(usage))
                        }
                        Err(error) => {
                            detail.push_str("; memory.current unavailable after confirmed limit: ");
                            detail.push_str(&error.to_string());
                            None
                        }
                    };
                    let interrupted = if !policy.limit_grace.is_zero() {
                        cgroup.signal_group(child_pid, libc::SIGTERM);
                        let grace = context.supervision_deadline(started).map_or(
                            policy.limit_grace,
                            |deadline| {
                                policy
                                    .limit_grace
                                    .min(deadline.saturating_duration_since(Instant::now()))
                            },
                        );
                        signal_source.wait(grace).ok().flatten()
                    } else {
                        signal_source.take()
                    };
                    if let Some(signal) = interrupted {
                        cgroup.signal_group(child_pid, signal);
                    }
                    let cleanup = cgroup.cleanup_workload(
                        &mut child,
                        &mut stored,
                        true,
                        context.clamp_deadline(started, CLEANUP_DEADLINE),
                    );
                    if let Some(signal) = interrupted {
                        break RunOutcome::Interrupted {
                            signal: Interruption { signal },
                            child_after_termination: stored.clone(),
                            cleanup,
                        };
                    }
                    break RunOutcome::LimitExceeded {
                        limit,
                        observed,
                        peak: Some(ByteSize::from_bytes(
                            cgroup.peak().unwrap_or(peak).max(peak),
                        )),
                        evidence: LimitEvidence {
                            backend: "linux-cgroup-v2".to_owned(),
                            metric: "linux-cgroup-memory".to_owned(),
                            detail,
                        },
                        child_after_termination: stored.clone(),
                        cleanup,
                    };
                }
            }

            if let Some(error) = cycle_error {
                let cleanup = cgroup.cleanup_workload(
                    &mut child,
                    &mut stored,
                    true,
                    context.clamp_deadline(started, CLEANUP_DEADLINE),
                );
                break RunOutcome::MonitorFailed {
                    error,
                    child_after_termination: stored.clone(),
                    cleanup,
                };
            }

            if policy.memory.is_some() {
                let usage = match cgroup.current(monitor_failure_ready.as_deref()) {
                    Ok(usage) => usage,
                    Err(error) => {
                        let cleanup = cgroup.cleanup_workload(
                            &mut child,
                            &mut stored,
                            true,
                            context.clamp_deadline(started, CLEANUP_DEADLINE),
                        );
                        break RunOutcome::MonitorFailed {
                            error: format!("memory.current read failed: {error}"),
                            child_after_termination: stored.clone(),
                            cleanup,
                        };
                    }
                };
                peak = peak.max(usage);
            }
            if let Some(signal) = pending_signal.take().or_else(|| signal_source.take()) {
                cgroup.signal_group(child_pid, signal);
                if !policy.signal_grace.is_zero() {
                    let grace = context.supervision_deadline(started).map_or(
                        policy.signal_grace,
                        |deadline| {
                            policy
                                .signal_grace
                                .min(deadline.saturating_duration_since(Instant::now()))
                        },
                    );
                    let _ = signal_source.wait(grace);
                }
                let cleanup = cgroup.cleanup_workload(
                    &mut child,
                    &mut stored,
                    true,
                    context.clamp_deadline(started, CLEANUP_DEADLINE),
                );
                break RunOutcome::Interrupted {
                    signal: Interruption { signal },
                    child_after_termination: stored.clone(),
                    cleanup,
                };
            }
            if let Some(status) = direct_status {
                let workload_empty = match cgroup.populated() {
                    Ok(populated) => !populated,
                    Err(error) => {
                        let cleanup = cgroup.cleanup_workload(
                            &mut child,
                            &mut stored,
                            true,
                            context.clamp_deadline(started, CLEANUP_DEADLINE),
                        );
                        break RunOutcome::MonitorFailed {
                            error: format!("cgroup.events read failed: {error}"),
                            child_after_termination: stored.clone(),
                            cleanup,
                        };
                    }
                };
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
                            direct_child_reaped: true,
                            workload_empty: Some(true),
                            ..CleanupSummary::default()
                        }
                    } else {
                        cgroup.cleanup_workload(
                            &mut child,
                            &mut stored,
                            false,
                            context.clamp_deadline(started, CLEANUP_DEADLINE),
                        )
                    };
                    break RunOutcome::Exited {
                        child: status,
                        peak: policy
                            .memory
                            .map(|_| ByteSize::from_bytes(cgroup.peak().unwrap_or(peak).max(peak))),
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
            pending_signal = signal_source.wait(wait).ok().flatten();
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
    let mut containment_removed = true;
    if let Err(error) = cgroup.remove() {
        containment_removed = false;
        outcome.cleanup_mut().errors.push(CleanupErrorRecord {
            operation: "remove-cgroup".to_owned(),
            message: error.to_string(),
        });
    }
    let cleanup = outcome.cleanup();
    let cleanup_facts = BackendCleanupFacts {
        direct_child_reaped: cleanup.direct_child_reaped,
        workload_empty: cleanup.workload_empty,
        helpers_reaped,
        containment_removed,
        containment_incapable_of_live_members: cleanup.workload_empty == Some(true),
        sealed_boundary_retired: false,
        errors: cleanup
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.operation, error.message))
            .collect(),
    };
    Ok(Execution {
        outcome,
        backend: info(),
        child_pid: u32::try_from(child_pid).unwrap_or_default(),
        duration: started.elapsed(),
        authorization_offset: Some(authorized.saturating_duration_since(started)),
        cleanup_facts,
    })
}

fn delegated_parent(require_memory: bool) -> Result<PathBuf, String> {
    let mount = Path::new("/sys/fs/cgroup");
    fs::read_to_string(mount.join("cgroup.controllers"))
        .map_err(|error| format!("cgroup v2 unified hierarchy unavailable: {error}"))?;
    let membership = fs::read_to_string("/proc/self/cgroup")
        .map_err(|error| format!("cannot read process cgroup membership: {error}"))?;
    let relative = membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or_else(|| "process is not in a unified cgroup v2 hierarchy".to_owned())?;
    let current = mount.join(relative.trim_start_matches('/'));
    let mut ancestor = current.parent();
    while let Some(candidate) = ancestor {
        if candidate == mount {
            break;
        }
        if has_systemd_delegate_marker(candidate)? {
            prepare_delegated_root(candidate, require_memory)?;
            return Ok(candidate.to_path_buf());
        }
        ancestor = candidate.parent();
    }
    Err(format!(
        "process cgroup {} is not below a marked systemd delegation boundary",
        current.display()
    ))
}

fn has_systemd_delegate_marker(path: &Path) -> Result<bool, String> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "cgroup path {} contains an interior NUL byte",
            path.display()
        )
    })?;
    let mut value = [0_u8; 16];
    // SAFETY: both C strings are NUL-terminated and `value` is writable for its full length.
    let length = unsafe {
        libc::getxattr(
            path.as_ptr(),
            c"user.delegate".as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if length < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENODATA) {
            return Ok(false);
        }
        return Err(format!(
            "cannot inspect systemd delegation marker on {}: {error}",
            path.to_string_lossy()
        ));
    }
    let length = usize::try_from(length)
        .map_err(|_| "systemd delegation marker length is invalid".to_owned())?;
    Ok(value.get(..length) == Some(b"1"))
}

fn prepare_delegated_root(path: &Path, require_memory: bool) -> Result<(), String> {
    let members = fs::read_to_string(path.join("cgroup.procs")).map_err(|error| {
        format!(
            "cannot read delegation-root membership at {}: {error}",
            path.display()
        )
    })?;
    if !members.trim().is_empty() {
        return Err(format!(
            "systemd delegation root {} contains processes",
            path.display()
        ));
    }
    if !require_memory {
        return Ok(());
    }
    let controllers = fs::read_to_string(path.join("cgroup.controllers")).map_err(|error| {
        format!(
            "cannot read delegated controllers at {}: {error}",
            path.display()
        )
    })?;
    if !controllers.split_whitespace().any(|item| item == "memory") {
        return Err(format!(
            "systemd delegation root {} does not delegate the memory controller",
            path.display()
        ));
    }
    let subtree_control = path.join("cgroup.subtree_control");
    let enabled = fs::read_to_string(&subtree_control).map_err(|error| {
        format!(
            "cannot read cgroup.subtree_control at {}: {error}",
            path.display()
        )
    })?;
    if !enabled.split_whitespace().any(|item| item == "memory") {
        fs::write(&subtree_control, "+memory\n").map_err(|error| {
            format!(
                "cannot enable memory controller at systemd delegation root {}: {error}",
                path.display()
            )
        })?;
    }
    let enabled = fs::read_to_string(&subtree_control).map_err(|error| {
        format!(
            "cannot verify cgroup.subtree_control at {}: {error}",
            path.display()
        )
    })?;
    if !enabled.split_whitespace().any(|item| item == "memory") {
        return Err(format!(
            "memory controller did not remain enabled at systemd delegation root {}",
            path.display()
        ));
    }
    Ok(())
}

fn create_cgroup(parent: &Path) -> io::Result<PathBuf> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    let path = parent.join(format!(
        "memcordon-{uid}-{}-{:x}",
        std::process::id(),
        nonce
    ));
    fs::create_dir(&path)?;
    Ok(path)
}

struct Cgroup {
    path: PathBuf,
}

impl Cgroup {
    fn configure(&self, policy: &Policy) -> io::Result<()> {
        let Some(memory) = policy.memory else {
            return Ok(());
        };
        let oom_group = self.path.join("memory.oom.group");
        if oom_group.exists() {
            fs::write(oom_group, "1\n")?;
        }
        fs::write(
            self.path.join("memory.max"),
            format!("{}\n", memory.bytes()),
        )?;
        match policy.swap {
            SwapPolicy::Bytes(bytes) => {
                let swap = self.path.join("memory.swap.max");
                if !swap.exists() {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "resolved swap policy requires memory.swap.max",
                    ));
                }
                fs::write(swap, format!("{}\n", bytes.bytes()))?;
            }
            SwapPolicy::Unlimited => {
                fs::write(self.path.join("memory.swap.max"), "max\n")?;
            }
            SwapPolicy::Host => {}
        }
        Ok(())
    }

    fn assign(&self, pid: i32) -> io::Result<()> {
        fs::write(self.path.join("cgroup.procs"), format!("{pid}\n"))
    }

    fn verify(&self, pid: i32) -> io::Result<()> {
        let members = fs::read_to_string(self.path.join("cgroup.procs"))?;
        if members.lines().any(|line| line.trim() == pid.to_string()) {
            Ok(())
        } else {
            Err(io::Error::other(
                "gated launcher cgroup assignment did not persist",
            ))
        }
    }

    fn memory_events(&self) -> io::Result<HashMap<String, u64>> {
        parse_key_values(&fs::read_to_string(self.path.join("memory.events"))?)
    }

    fn current(&self, monitor_failure_ready: Option<&Path>) -> io::Result<u64> {
        if monitor_failure_ready.is_some_and(Path::exists) {
            return Err(io::Error::other(
                "certification fixture induced a supervisor monitor read failure",
            ));
        }
        parse_u64_file(&self.path.join("memory.current"))
    }

    fn peak(&self) -> io::Result<u64> {
        parse_u64_file(&self.path.join("memory.peak"))
    }

    fn populated(&self) -> io::Result<bool> {
        Ok(
            parse_key_values(&fs::read_to_string(self.path.join("cgroup.events"))?)?
                .get("populated")
                .copied()
                .unwrap_or(0)
                != 0,
        )
    }

    fn signal_group(&self, process_group: i32, signal: i32) {
        // SAFETY: the process group was created for the gated launcher.
        unsafe {
            libc::kill(-process_group, signal);
        }
    }

    fn kill_all(&self, summary: &mut CleanupSummary, deadline: Instant) {
        let kill_file = self.path.join("cgroup.kill");
        if kill_file.exists() {
            if let Err(error) = fs::write(kill_file, "1\n") {
                summary.errors.push(cleanup_error("cgroup.kill", error));
            }
            return;
        }
        for _ in 0..20 {
            if Instant::now() >= deadline {
                return;
            }
            let members = match fs::read_to_string(self.path.join("cgroup.procs")) {
                Ok(members) => members,
                Err(error) => {
                    summary
                        .errors
                        .push(cleanup_error("read-cgroup.procs", error));
                    return;
                }
            };
            if members.trim().is_empty() {
                return;
            }
            for pid in members
                .lines()
                .filter_map(|line| line.trim().parse::<i32>().ok())
            {
                // SAFETY: PIDs came directly from this package-owned cgroup.
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                }
            }
            bounded_pause(
                Duration::from_millis(10).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }

    fn cleanup_workload(
        &self,
        child: &mut Child,
        stored: &mut Option<ChildTermination>,
        force: bool,
        deadline: Instant,
    ) -> CleanupSummary {
        let mut summary = CleanupSummary {
            force_attempted: force,
            ..CleanupSummary::default()
        };
        self.cleanup_members(&mut summary, deadline);
        while stored.is_none() && Instant::now() < deadline {
            match child.try_wait() {
                Ok(Some(status)) => *stored = Some(termination(status)),
                Ok(None) => bounded_pause(
                    Duration::from_millis(10)
                        .min(deadline.saturating_duration_since(Instant::now())),
                ),
                Err(error) => {
                    summary
                        .errors
                        .push(cleanup_error("reap-direct-child", error));
                    break;
                }
            }
        }
        if stored.is_none() {
            summary.errors.push(cleanup_error(
                "reap-direct-child",
                io::Error::new(io::ErrorKind::TimedOut, "cleanup deadline expired"),
            ));
        }
        summary.direct_child_reaped = stored.is_some();
        summary
    }

    fn cleanup_members(&self, summary: &mut CleanupSummary, deadline: Instant) {
        if self.populated().unwrap_or(true) {
            summary.force_attempted = true;
            self.kill_all(summary, deadline);
        }
        let mut empty = false;
        while Instant::now() < deadline {
            match self.populated() {
                Ok(false) => {
                    empty = true;
                    break;
                }
                Ok(true) => self.kill_all(summary, deadline),
                Err(error) => {
                    summary
                        .errors
                        .push(cleanup_error("verify-cgroup-empty", error));
                    break;
                }
            }
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            bounded_pause(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
        }
        summary.workload_empty = Some(empty);
    }

    fn remove(&mut self) -> io::Result<()> {
        fs::remove_dir(&self.path)
    }
}

#[cfg(feature = "test-support")]
fn monitor_failure_ready_file(command: &CommandSpec) -> Option<PathBuf> {
    if Path::new(command.program()).file_name()?.to_str()? != "memcordon-test-fixture"
        || command.arguments().first()?.to_str()? != "monitor-failure"
        || command.arguments().get(1)?.to_str()? != "--pid-file"
    {
        return None;
    }
    command.arguments().get(2).map(PathBuf::from)
}

#[cfg(not(feature = "test-support"))]
fn monitor_failure_ready_file(_command: &CommandSpec) -> Option<PathBuf> {
    None
}

impl Drop for Cgroup {
    fn drop(&mut self) {
        if self.path.exists() {
            let mut summary = CleanupSummary::default();
            self.kill_all(&mut summary, Instant::now() + CLEANUP_DEADLINE);
            let _ = fs::remove_dir(&self.path);
        }
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the launch layer preserves one categorized Error representation through execution"
)]
fn spawn_gated(
    command: &CommandSpec,
    memcordon_executable: &Path,
) -> Result<(Child, RawFd, RawFd), Error> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: storage is valid for two descriptors.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(setup_io(io::Error::last_os_error()));
    }
    // The launcher must not retain the parent's write end after exec.
    // SAFETY: the descriptor came from `pipe`.
    if unsafe { libc::fcntl(descriptors[1], libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let error = io::Error::last_os_error();
        close_pair(descriptors);
        return Err(setup_io(error));
    }
    let mut exec_status = [0_i32; 2];
    // SAFETY: storage is valid for two descriptors and O_CLOEXEC applies to both new ends.
    if unsafe { libc::pipe2(exec_status.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let error = io::Error::last_os_error();
        close_pair(descriptors);
        return Err(setup_io(error));
    }
    // The installed helper must inherit the status writer; its hidden launcher marks it CLOEXEC
    // immediately before executing the target so EOF proves a successful exec.
    // SAFETY: exec_status[1] is the uniquely owned writer returned by pipe2.
    if unsafe { libc::fcntl(exec_status[1], libc::F_SETFD, 0) } != 0 {
        let error = io::Error::last_os_error();
        close_pair(descriptors);
        close_pair(exec_status);
        return Err(setup_io(error));
    }
    let mut builder = Command::new(memcordon_executable);
    // Establish the launcher's process group in the child before exec. A parent-side setpgid
    // after Command::spawn returns is too late because the launcher executable has already run.
    builder
        .process_group(0)
        .arg("__launcher")
        .arg(descriptors[0].to_string())
        .arg(exec_status[1].to_string())
        .arg("--")
        .arg(command.program())
        .args(command.arguments());
    match builder.spawn() {
        Ok(child) => {
            // SAFETY: only the child uses the read end after successful spawn.
            unsafe {
                libc::close(descriptors[0]);
                libc::close(exec_status[1]);
            }
            Ok((child, descriptors[1], exec_status[0]))
        }
        Err(error) => {
            close_pair(descriptors);
            close_pair(exec_status);
            Err(helper_setup_error(
                "MCSETUP-MEMCORDON-LAUNCHER",
                memcordon_executable,
                error,
            ))
        }
    }
}

fn receive_launcher_ready(descriptor: RawFd, deadline: Instant) -> io::Result<()> {
    let first = read_launcher_status(descriptor, deadline)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "MemCordon launcher exited before its readiness record",
        )
    })?;
    match decode_launcher_status(first)? {
        LauncherStatus::Ready => Ok(()),
        LauncherStatus::Error(error) => {
            require_launcher_eof(descriptor, deadline)?;
            Err(error)
        }
    }
}

fn receive_exec_result(descriptor: RawFd, deadline: Instant) -> io::Result<Option<io::Error>> {
    let result = receive_exec_result_before(descriptor, deadline);
    // SAFETY: this function owns the status reader and closes it exactly once before returning.
    unsafe { libc::close(descriptor) };
    result
}

fn receive_exec_result_before(
    descriptor: RawFd,
    deadline: Instant,
) -> io::Result<Option<io::Error>> {
    match read_launcher_status(descriptor, deadline)? {
        None => Ok(None),
        Some(record) => match decode_launcher_status(record)? {
            LauncherStatus::Error(error) => {
                require_launcher_eof(descriptor, deadline)?;
                Ok(Some(error))
            }
            LauncherStatus::Ready => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "MemCordon launcher sent readiness more than once",
            )),
        },
    }
}

fn require_launcher_eof(descriptor: RawFd, deadline: Instant) -> io::Result<()> {
    if read_launcher_status(descriptor, deadline)?.is_none() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MemCordon launcher sent trailing status data",
        ))
    }
}

enum LauncherStatus {
    Ready,
    Error(io::Error),
}

fn decode_launcher_status(record: [u8; LAUNCHER_STATUS_LENGTH]) -> io::Result<LauncherStatus> {
    if &record[..4] != LAUNCHER_STATUS_MAGIC
        || record[4] != LAUNCHER_STATUS_VERSION
        || record[6..8] != [0, 0]
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MemCordon launcher sent an invalid status record",
        ));
    }
    let errno = i32::from_ne_bytes(record[8..12].try_into().expect("fixed status record"));
    match (record[5], errno) {
        (LAUNCHER_STATUS_READY, 0) => Ok(LauncherStatus::Ready),
        (LAUNCHER_STATUS_ERROR, errno) if errno > 0 => {
            Ok(LauncherStatus::Error(io::Error::from_raw_os_error(errno)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "MemCordon launcher sent an invalid status kind or errno",
        )),
    }
}

fn read_launcher_status(
    descriptor: RawFd,
    deadline: Instant,
) -> io::Result<Option<[u8; LAUNCHER_STATUS_LENGTH]>> {
    // SAFETY: F_GETFL/F_SETFL only inspect and update flags on this live pipe descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut record = [0_u8; LAUNCHER_STATUS_LENGTH];
    let mut offset = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = if remaining.is_zero() {
            0
        } else {
            remaining.as_millis().clamp(1, i32::MAX as u128) as i32
        };
        let mut poll = libc::pollfd {
            fd: descriptor,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll points to one initialized pollfd for the duration of this call.
        let ready = unsafe { libc::poll(&raw mut poll, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        // SAFETY: the remaining record buffer is writable and descriptor is a live pipe reader.
        let read = unsafe {
            libc::read(
                descriptor,
                record[offset..].as_mut_ptr().cast(),
                record.len() - offset,
            )
        };
        if read == 0 {
            return if offset == 0 {
                Ok(None)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "MemCordon launcher status record was truncated",
                ))
            };
        }
        if read < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() == io::ErrorKind::WouldBlock {
                if ready == 0 || Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for MemCordon launcher status",
                    ));
                }
                continue;
            }
            return Err(error);
        }
        offset += usize::try_from(read).expect("read returned a positive byte count");
        if offset == record.len() {
            return Ok(Some(record));
        }
    }
}

fn release_launcher(descriptor: RawFd) -> io::Result<()> {
    let marker = 1_u8;
    // SAFETY: descriptor is the owned write end and marker is readable for one byte.
    let result = unsafe { libc::write(descriptor, (&raw const marker).cast(), 1) };
    // SAFETY: release descriptor is consumed exactly once.
    unsafe {
        libc::close(descriptor);
    }
    if result == 1 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

struct GatedAbort {
    cleanup: CleanupSummary,
    workload_may_be_alive: bool,
}

fn record_failure_cleanup(
    failure: &mut Error,
    cleanup: CleanupSummary,
    helpers_reaped: bool,
    containment_removed: bool,
) {
    failure.restart_safety = Some(RestartSafetyProof {
        direct_child_reaped: cleanup.direct_child_reaped,
        workload_empty: cleanup.workload_empty,
        helpers_reaped,
        containment_removed,
        containment_incapable_of_live_members: cleanup.workload_empty == Some(true),
        errors: cleanup
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.operation, error.message))
            .collect(),
    });
    failure.cleanup = cleanup;
}

fn abort_gated(
    cgroup: &mut Cgroup,
    child: &mut Child,
    release_fd: Option<RawFd>,
    exec_status_fd: RawFd,
    deadline: Instant,
) -> GatedAbort {
    // SAFETY: closing without a release byte prevents the launcher from executing the target.
    unsafe {
        if let Some(release_fd) = release_fd {
            libc::close(release_fd);
        }
        libc::close(exec_status_fd);
    }
    let mut cleanup = CleanupSummary {
        force_attempted: true,
        ..CleanupSummary::default()
    };
    let process_group = i32::try_from(child.id()).ok().filter(|value| *value > 0);
    if let Some(process_group) = process_group {
        // SAFETY: spawn_gated established the child as leader of this dedicated process group.
        if unsafe { libc::kill(-process_group, libc::SIGKILL) } != 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                cleanup
                    .errors
                    .push(cleanup_error("terminate-launcher-process-group", error));
            }
        }
    } else {
        cleanup.errors.push(cleanup_error(
            "identify-launcher-process-group",
            io::Error::other("child PID cannot identify a native process group"),
        ));
    }
    match child.kill() {
        Err(error) if error.raw_os_error() != Some(libc::ESRCH) => {
            cleanup
                .errors
                .push(cleanup_error("terminate-launcher", error));
        }
        _ => {}
    }
    cgroup.cleanup_members(&mut cleanup, deadline);

    let mut direct_child_reaped = false;
    let mut reap_failed = false;
    let mut process_group_absent = false;
    let mut process_group_check_failed = process_group.is_none();
    loop {
        if !direct_child_reaped && !reap_failed {
            match child.try_wait() {
                Ok(Some(_)) => direct_child_reaped = true,
                Ok(None) => {}
                Err(error) => {
                    cleanup
                        .errors
                        .push(cleanup_error("reap-direct-child", error));
                    reap_failed = true;
                }
            }
        }
        if !process_group_absent && !process_group_check_failed {
            let process_group = process_group.expect("checked above");
            // SAFETY: signal zero only queries the dedicated process group's existence.
            if unsafe { libc::kill(-process_group, 0) } != 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ESRCH) {
                    process_group_absent = true;
                } else {
                    cleanup
                        .errors
                        .push(cleanup_error("verify-launcher-process-group-empty", error));
                    process_group_check_failed = true;
                }
            }
        }
        if (direct_child_reaped || reap_failed)
            && (process_group_absent || process_group_check_failed)
        {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        bounded_pause(Duration::from_millis(10).min(deadline.saturating_duration_since(now)));
    }
    if !direct_child_reaped && !reap_failed {
        cleanup.errors.push(cleanup_error(
            "reap-direct-child",
            io::Error::new(
                io::ErrorKind::TimedOut,
                "direct child did not exit before the cleanup deadline",
            ),
        ));
    }
    if !process_group_absent && !process_group_check_failed {
        cleanup.errors.push(cleanup_error(
            "verify-launcher-process-group-empty",
            io::Error::new(
                io::ErrorKind::TimedOut,
                "launcher process group remained live after the cleanup deadline",
            ),
        ));
    }
    cleanup.direct_child_reaped = direct_child_reaped;
    if let Err(error) = cgroup.remove() {
        cleanup.errors.push(cleanup_error("remove-cgroup", error));
    }
    let workload_may_be_alive =
        !direct_child_reaped || !process_group_absent || cleanup.workload_empty != Some(true);
    GatedAbort {
        cleanup,
        workload_may_be_alive,
    }
}

fn close_pair(descriptors: [RawFd; 2]) {
    // SAFETY: both descriptors came from the same successful pipe call.
    unsafe {
        libc::close(descriptors[0]);
        libc::close(descriptors[1]);
    }
}

fn try_reap(
    child: &mut Child,
    stored: &mut Option<ChildTermination>,
) -> io::Result<Option<ChildTermination>> {
    if let Some(status) = stored.clone() {
        return Ok(Some(status));
    }
    child.try_wait().map(|status| {
        status.map(|status| {
            let status = termination(status);
            *stored = Some(status.clone());
            status
        })
    })
}

fn termination(status: ExitStatus) -> ChildTermination {
    if let Some(code) = status.code() {
        ChildTermination::ExitCode { code }
    } else if let Some(signal) = status.signal() {
        ChildTermination::UnixSignal { signal }
    } else {
        ChildTermination::Unavailable
    }
}

fn limit_delta(baseline: &HashMap<String, u64>, current: &HashMap<String, u64>) -> Option<String> {
    ["max", "oom", "oom_kill", "oom_group_kill"]
        .into_iter()
        .find(|key| {
            current.get(*key).copied().unwrap_or(0) > baseline.get(*key).copied().unwrap_or(0)
        })
        .map(|key| {
            format!(
                "memory.events {key} increased from {} to {}",
                baseline.get(key).copied().unwrap_or(0),
                current.get(key).copied().unwrap_or(0)
            )
        })
}

fn parse_key_values(input: &str) -> io::Result<HashMap<String, u64>> {
    input
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields
                .next()
                .ok_or_else(|| io::Error::other("missing cgroup counter name"))?;
            let value = fields
                .next()
                .ok_or_else(|| io::Error::other("missing cgroup counter value"))?
                .parse()
                .map_err(|error| io::Error::other(format!("invalid cgroup counter: {error}")))?;
            Ok((key.to_owned(), value))
        })
        .collect()
}

fn parse_u64_file(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?
        .trim()
        .parse()
        .map_err(|error| io::Error::other(format!("invalid value in {}: {error}", path.display())))
}

fn setup_io(error: io::Error) -> Error {
    Error::new(ErrorCategory::Setup, "MCSETUP-CGROUP", error.to_string()).with_os_error(&error)
}

fn helper_setup_error(code: &'static str, executable: &Path, error: io::Error) -> Error {
    Error::new(
        ErrorCategory::Setup,
        code,
        format!(
            "could not execute installed MemCordon helper {}: {error}",
            executable.display()
        ),
    )
    .with_os_error(&error)
}

fn spawn_error(error: io::Error, command: &CommandSpec) -> Error {
    let code = match error.raw_os_error() {
        Some(libc::ENOENT | libc::ENOTDIR) => "MCSPAWN-NOT-FOUND",
        Some(libc::EACCES | libc::EPERM | libc::ENOEXEC | libc::EISDIR) => "MCSPAWN-NOT-EXECUTABLE",
        _ => "MCSPAWN-FAILED",
    };
    let failure = match code {
        "MCSPAWN-NOT-FOUND" => Some(InitialSpawnFailure::NotFound),
        "MCSPAWN-NOT-EXECUTABLE" => Some(InitialSpawnFailure::NotExecutable),
        _ => None,
    };
    let result = Error::new(
        ErrorCategory::Spawn,
        code,
        format!(
            "could not launch gated command {}: {error}",
            command.program().to_string_lossy()
        ),
    )
    .with_os_error(&error);
    failure.map_or(result.clone(), |failure| {
        result.with_initial_spawn_failure(failure)
    })
}

fn cleanup_error(operation: &str, error: io::Error) -> CleanupErrorRecord {
    CleanupErrorRecord {
        operation: operation.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn test_limit_delta() -> bool {
    let baseline = HashMap::from([("max".to_owned(), 4)]);
    let current = HashMap::from([("max".to_owned(), 5)]);
    limit_delta(&baseline, &baseline).is_none() && limit_delta(&baseline, &current).is_some()
}

#[cfg(feature = "test-support")]
pub(crate) fn test_configure(path: &Path, limit: ByteSize) -> io::Result<()> {
    Cgroup {
        path: path.to_path_buf(),
    }
    .configure(&Policy::new(limit))
}

#[cfg(feature = "test-support")]
pub(crate) fn test_monitor_errors(path: &Path) -> bool {
    let cgroup = Cgroup {
        path: path.to_path_buf(),
    };
    cgroup.current(None).is_err() && cgroup.memory_events().is_err() && cgroup.populated().is_err()
}

#[cfg(feature = "test-support")]
pub(crate) fn test_verify(path: &Path, pid: i32) -> io::Result<()> {
    Cgroup {
        path: path.to_path_buf(),
    }
    .verify(pid)
}

#[cfg(feature = "test-support")]
pub(crate) fn test_launcher_status(bytes: &[u8]) -> io::Result<Option<i32>> {
    let mut descriptors = [0_i32; 2];
    // SAFETY: storage is valid for both descriptors.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut offset = 0;
    while offset < bytes.len() {
        // SAFETY: remaining bytes are readable and the descriptor is the owned pipe writer.
        let written = unsafe {
            libc::write(
                descriptors[1],
                bytes[offset..].as_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            close_pair(descriptors);
            return Err(error);
        }
        offset += usize::try_from(written).expect("write returned a nonnegative byte count");
    }
    // SAFETY: closing the uniquely owned writer makes the finite test transcript observable.
    unsafe { libc::close(descriptors[1]) };
    let deadline = Instant::now() + LAUNCHER_STATUS_DEADLINE;
    if let Err(error) = receive_launcher_ready(descriptors[0], deadline) {
        // SAFETY: readiness does not consume the reader on error.
        unsafe { libc::close(descriptors[0]) };
        return Err(error);
    }
    receive_exec_result(descriptors[0], Instant::now() + LAUNCHER_STATUS_DEADLINE)
        .map(|error| error.and_then(|error| error.raw_os_error()))
}

#[cfg(feature = "test-support")]
pub(crate) fn test_launcher_status_timeout() -> io::ErrorKind {
    let mut descriptors = [0_i32; 2];
    // SAFETY: storage is valid for both descriptors.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return io::Error::last_os_error().kind();
    }
    let result = read_launcher_status(descriptors[0], Instant::now())
        .expect_err("a live launcher status pipe without a complete record must time out");
    close_pair(descriptors);
    result.kind()
}
