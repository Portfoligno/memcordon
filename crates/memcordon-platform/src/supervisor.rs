use std::path::PathBuf;
use std::time::{Duration, Instant};

use memcordon_core::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    CapabilityStatusReport, CommandSpec, Error, ErrorCategory, LaunchEvidence,
    MemoryCapabilityReport, Policy, RestartAction, RestartCondition, RestartCoordinator,
    RestartDecisionKind, RestartDecisionRecord, RestartPolicy, RestartSafetyProof, RestartSummary,
    RestartWaitKind, RunOutcome, SupervisionAggregates, SupervisionDeadlineEvidence,
    SupervisionErrorRecord, SupervisionExecution, SupervisionPhase, SupervisionTerminal,
    WaitCompletion,
};

use crate::backend::{BackendInfo, Execution};
#[cfg(unix)]
use crate::signal::SignalSource;

trait InterruptionWait {
    fn wait(&self, duration: Duration) -> std::io::Result<Option<i32>>;
    fn execute_attempt(
        &self,
        request: &SupervisorRequest,
        context: AttemptContext,
    ) -> Result<AttemptExecution, Box<Error>>;
}

#[cfg(unix)]
impl InterruptionWait for SignalSource {
    fn wait(&self, duration: Duration) -> std::io::Result<Option<i32>> {
        SignalSource::wait(self, duration)
    }
    fn execute_attempt(
        &self,
        request: &SupervisorRequest,
        context: AttemptContext,
    ) -> Result<AttemptExecution, Box<Error>> {
        run_unix_attempt(request, self, context).map_err(Box::new)
    }
}

#[cfg(target_os = "windows")]
impl InterruptionWait for crate::windows_job::ConsoleControl {
    fn wait(&self, duration: Duration) -> std::io::Result<Option<i32>> {
        crate::windows_job::ConsoleControl::wait(self, duration)
    }
    fn execute_attempt(
        &self,
        request: &SupervisorRequest,
        context: AttemptContext,
    ) -> Result<AttemptExecution, Box<Error>> {
        let execution = crate::windows_job::run_attempt(
            request.policy.clone(),
            &request.command,
            self,
            context,
        )
        .map_err(Box::new)?;
        Ok(attempt_execution(execution))
    }
}

#[derive(Clone, Debug)]
pub struct SupervisorRequest {
    pub policy: Policy,
    pub restart: RestartPolicy,
    pub command: CommandSpec,
    pub memcordon_executable: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct AttemptExecution {
    pub execution: Execution,
    pub launch: LaunchEvidence,
    pub restart_safety: RestartSafetyProof,
}

#[derive(Clone, Copy, Debug)]
pub struct AttemptContext {
    pub supervision_offset: Duration,
    pub supervision_deadline_remaining: Option<Duration>,
}

impl AttemptContext {
    pub(crate) fn supervision_deadline(self, attempt_started: Instant) -> Option<Instant> {
        self.supervision_deadline_remaining
            .and_then(|remaining| attempt_started.checked_add(remaining))
    }

    pub(crate) fn clamp_deadline(self, attempt_started: Instant, local: Duration) -> Instant {
        let local_deadline = Instant::now()
            .checked_add(local)
            .unwrap_or_else(Instant::now);
        self.supervision_deadline(attempt_started)
            .map_or(local_deadline, |supervision| {
                local_deadline.min(supervision)
            })
    }
}

pub fn capabilities(info: &BackendInfo) -> BackendCapabilityReport {
    BackendCapabilityReport {
        name: info.name.to_owned(),
        containment: CapabilityStatusReport {
            supported: info.containment_supported,
            reason: None,
        },
        memory: Some(MemoryCapabilityReport {
            supported: info.memory_supported,
            class: info.class.to_owned(),
            metric: info.metric.to_owned(),
            reason: None,
        }),
        deadline: CapabilityStatusReport {
            supported: true,
            reason: None,
        },
        restart: CapabilityStatusReport {
            supported: true,
            reason: None,
        },
        deadline_scopes: vec![
            memcordon_core::DeadlineScope::Attempt,
            memcordon_core::DeadlineScope::Supervision,
        ],
        deadline_origin: Some(deadline_origin().to_owned()),
        restart_conditions: memcordon_core::RestartConditions::BOTH,
        persistent_restart_state: false,
        startup_containment: info.startup_containment.to_owned(),
        restart_cleanup_condition:
            "direct child and helpers reaped, workload empty, containment removed or inert"
                .to_owned(),
        limitations: info
            .limitations
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    }
}

#[cfg(unix)]
#[allow(clippy::result_large_err)]
pub fn supervise(request: SupervisorRequest) -> Result<SupervisionExecution, Error> {
    let signal = SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    supervise_with(request, &signal)
}

#[cfg(target_os = "windows")]
#[allow(clippy::result_large_err)]
pub fn supervise(request: SupervisorRequest) -> Result<SupervisionExecution, Error> {
    let console = crate::windows_job::ConsoleControl::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-CONSOLE", error.to_string()).with_os_error(&error)
    })?;
    supervise_with(request, &console)
}

#[cfg(not(any(unix, target_os = "windows")))]
#[allow(clippy::result_large_err)]
pub fn supervise(_request: SupervisorRequest) -> Result<SupervisionExecution, Error> {
    Err(Error::new(
        ErrorCategory::Unsupported,
        "MCUNSUPPORTED-SUPERVISOR",
        "the shared platform supervisor is unavailable on this target",
    ))
}

#[allow(clippy::result_large_err)]
fn supervise_with<I: InterruptionWait>(
    request: SupervisorRequest,
    signal: &I,
) -> Result<SupervisionExecution, Error> {
    let started = Instant::now();
    let mut history = AttemptHistory::default();
    let mut aggregates = SupervisionAggregates::default();
    let mut targets_authorized = 0_u64;
    let mut kind = AttemptKind::Initial;
    let mut coordinator = match request.restart.clone() {
        RestartPolicy::Never => None,
        RestartPolicy::OnLimits(settings) => {
            Some(RestartCoordinator::new(settings).map_err(controller_error)?)
        }
    };
    let mut backend = None;
    let mut supervision_origin_offset = None;
    loop {
        let attempt_started = started.elapsed();
        let context = AttemptContext {
            supervision_offset: attempt_started,
            supervision_deadline_remaining: supervision_remaining(
                &request.policy,
                supervision_origin_offset,
                attempt_started,
            ),
        };
        if supervision_origin_offset.is_some()
            && context.supervision_deadline_remaining == Some(Duration::ZERO)
        {
            let outside_deadline = outside_deadline_evidence(
                &request.policy,
                supervision_origin_offset,
                attempt_started,
                SupervisionPhase::Backoff,
            )
            .map_err(|error| *error)?;
            return SupervisionExecution::new(
                backend.unwrap_or_else(unsupported_capability),
                SupervisionTerminal::DeadlineOutsideAttempt {
                    evidence: outside_deadline
                        .clone()
                        .expect("expired supervision deadline supplies evidence"),
                },
                history,
                aggregates,
                coordinator
                    .as_ref()
                    .map_or_else(RestartSummary::default, |value| value.summary().clone()),
                outside_deadline,
                millis(started.elapsed()),
                targets_authorized,
            )
            .map_err(model_error);
        }
        let result = signal.execute_attempt(&request, context);
        match result {
            Err(error) => {
                let error = *error;
                if error.code == "MCSUPERVISION-DEADLINE-BEFORE-AUTHORIZATION" {
                    let outside_deadline = outside_deadline_evidence(
                        &request.policy,
                        supervision_origin_offset,
                        started.elapsed(),
                        SupervisionPhase::AttemptSetup,
                    )
                    .map_err(|error| *error)?;
                    return SupervisionExecution::new(
                        backend.unwrap_or_else(unsupported_capability),
                        SupervisionTerminal::DeadlineOutsideAttempt {
                            evidence: outside_deadline
                                .clone()
                                .expect("expired supervision deadline supplies evidence"),
                        },
                        history,
                        aggregates,
                        coordinator
                            .as_ref()
                            .map_or_else(RestartSummary::default, |value| value.summary().clone()),
                        outside_deadline,
                        millis(started.elapsed()),
                        targets_authorized,
                    )
                    .map_err(model_error);
                }
                let number = history.total.checked_add(1).ok_or_else(counter_error)?;
                if error.target_released != error.authorization_offset.is_some() {
                    return Err(Error::new(
                        ErrorCategory::Monitor,
                        "MCRESTART-AUTHORIZATION-EVIDENCE",
                        "target release and authorization offset evidence disagree",
                    ));
                }
                let record_error =
                    error_record(&error, Some(number), SupervisionPhase::AttemptSetup, kind);
                if error.target_released {
                    targets_authorized = targets_authorized
                        .checked_add(1)
                        .ok_or_else(counter_error)?;
                }
                history
                    .append(
                        AttemptRecord {
                            number,
                            kind,
                            phase: AttemptPhase::Failed,
                            target_pid: error.target_pid,
                            started_offset_ms: Some(millis(attempt_started)),
                            authorized_offset_ms: error
                                .authorization_offset
                                .map(|offset| millis(attempt_started + offset)),
                            terminal_offset_ms: None,
                            finished_offset_ms: millis(started.elapsed()),
                            outcome: None,
                            error: Some(record_error.clone()),
                            restart_decision: RestartDecisionRecord::default(),
                            launch: launch_from_error(&error),
                            restart_safety: proof_from_error(&error),
                        },
                        &mut aggregates,
                    )
                    .map_err(model_error)?;
                let capability = backend.unwrap_or_else(unsupported_capability);
                return SupervisionExecution::new(
                    capability,
                    SupervisionTerminal::Error {
                        attempt_number: Some(number),
                        error: record_error,
                    },
                    history,
                    aggregates,
                    coordinator
                        .as_ref()
                        .map_or_else(RestartSummary::default, |value| value.summary().clone()),
                    None,
                    millis(started.elapsed()),
                    targets_authorized,
                )
                .map_err(model_error);
            }
            Ok(attempt) => {
                if supervision_origin_offset.is_none() {
                    supervision_origin_offset = attempt
                        .execution
                        .authorization_offset
                        .map(|offset| attempt_started + offset);
                }
                backend.get_or_insert_with(|| capabilities(&attempt.execution.backend));
                targets_authorized = targets_authorized
                    .checked_add(1)
                    .ok_or_else(counter_error)?;
                let number = history.total.checked_add(1).ok_or_else(counter_error)?;
                let outcome = attempt.execution.outcome.clone();
                let trigger = restart_condition(&outcome);
                let mut decision = RestartDecisionRecord::default();
                let action = match (&mut coordinator, trigger) {
                    (Some(coordinator), Some(trigger)) => coordinator
                        .on_limit(
                            trigger,
                            started.elapsed(),
                            &attempt.restart_safety,
                            &mut decision,
                        )
                        .map_err(controller_error)?,
                    (Some(_), None) => {
                        RestartAction::Stop(RestartDecisionKind::NoneConditionNotSelected)
                    }
                    (None, _) => RestartAction::Stop(RestartDecisionKind::NoneDisabled),
                };
                let mut next_kind = AttemptKind::Restart;
                let mut stop = true;
                let mut outside_deadline = None;
                if let RestartAction::Wait {
                    duration,
                    kind: wait_kind,
                } = action
                {
                    stop = false;
                    let wait_started = Instant::now();
                    let remaining = supervision_remaining(
                        &request.policy,
                        supervision_origin_offset,
                        started.elapsed(),
                    );
                    let bounded = remaining.map_or(duration, |value| duration.min(value));
                    let interrupted = signal.wait(bounded).map_err(|error| {
                        Error::new(ErrorCategory::Wait, "MCWAIT-RESTART", error.to_string())
                            .with_os_error(&error)
                    })?;
                    let completion = if interrupted.is_some() {
                        WaitCompletion::Interrupted
                    } else if remaining.is_some_and(|value| wait_started.elapsed() >= value) {
                        outside_deadline = outside_deadline_evidence(
                            &request.policy,
                            supervision_origin_offset,
                            started.elapsed(),
                            if wait_kind == RestartWaitKind::CircuitCooldown {
                                SupervisionPhase::Cooldown
                            } else {
                                SupervisionPhase::Backoff
                            },
                        )
                        .map_err(|error| *error)?;
                        WaitCompletion::SupervisionDeadline
                    } else {
                        WaitCompletion::Completed
                    };
                    let after = coordinator
                        .as_mut()
                        .expect("wait requires coordinator")
                        .complete_wait(
                            completion,
                            wait_started.elapsed(),
                            supervision_remaining(
                                &request.policy,
                                supervision_origin_offset,
                                started.elapsed(),
                            ),
                            &mut decision,
                        )
                        .map_err(controller_error)?;
                    match after {
                        RestartAction::Launch { half_open, .. } => {
                            next_kind = if half_open {
                                AttemptKind::HalfOpen
                            } else {
                                AttemptKind::Restart
                            };
                        }
                        RestartAction::Stop(_) => stop = true,
                        RestartAction::Wait { .. } => {
                            return Err(controller_error(
                                memcordon_core::RestartControllerError::InvalidTransition,
                            ));
                        }
                    }
                    if wait_kind == RestartWaitKind::CircuitCooldown && !stop {
                        next_kind = AttemptKind::HalfOpen;
                    }
                }
                history
                    .append(
                        AttemptRecord {
                            number,
                            kind,
                            phase: AttemptPhase::Completed,
                            target_pid: Some(attempt.execution.child_pid),
                            started_offset_ms: Some(millis(attempt_started)),
                            authorized_offset_ms: attempt
                                .execution
                                .authorization_offset
                                .map(|offset| millis(attempt_started + offset)),
                            terminal_offset_ms: Some(millis(
                                attempt_started + attempt.execution.duration,
                            )),
                            finished_offset_ms: millis(started.elapsed()),
                            outcome: Some(outcome.clone()),
                            error: None,
                            restart_decision: decision,
                            launch: attempt.launch,
                            restart_safety: attempt.restart_safety,
                        },
                        &mut aggregates,
                    )
                    .map_err(model_error)?;
                if stop {
                    let terminal = outside_deadline.as_ref().map_or_else(
                        || SupervisionTerminal::AttemptOutcome {
                            attempt_number: number,
                            outcome,
                        },
                        |evidence| SupervisionTerminal::DeadlineOutsideAttempt {
                            evidence: evidence.clone(),
                        },
                    );
                    return SupervisionExecution::new(
                        backend.expect("successful attempt supplies backend"),
                        terminal,
                        history,
                        aggregates,
                        coordinator
                            .as_ref()
                            .map_or_else(RestartSummary::default, |value| value.summary().clone()),
                        outside_deadline,
                        millis(started.elapsed()),
                        targets_authorized,
                    )
                    .map_err(model_error);
                }
                kind = next_kind;
            }
        }
    }
}

#[allow(clippy::result_large_err)]
#[cfg(unix)]
fn run_unix_attempt(
    request: &SupervisorRequest,
    signal: &SignalSource,
    context: AttemptContext,
) -> Result<AttemptExecution, Error> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let helper = request.memcordon_executable.as_deref().ok_or_else(|| {
        Error::new(
            ErrorCategory::Usage,
            "MCUSAGE-MEMCORDON-EXECUTABLE",
            "Unix execution requires an explicit MemCordon helper path",
        )
    })?;
    #[cfg(target_os = "linux")]
    let execution = crate::linux_cgroup::run_attempt(
        request.policy.clone(),
        &request.command,
        helper,
        signal,
        context,
    )?;
    #[cfg(target_os = "macos")]
    let execution = crate::macos_watchdog::run_attempt(
        request.policy.clone(),
        &request.command,
        helper,
        signal,
        context,
    )?;
    #[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
    let execution = crate::unix_watchdog::run(request.policy.clone(), &request.command)?;
    Ok(attempt_execution(execution))
}

fn attempt_execution(execution: Execution) -> AttemptExecution {
    let facts = execution.cleanup_facts.clone();
    AttemptExecution {
        launch: LaunchEvidence {
            mechanism: launch_mechanism().to_owned(),
            target_released: true,
            containment_verified_before_authorization: true,
            guardian_started_before_authorization: cfg!(any(
                target_os = "linux",
                target_os = "macos"
            )),
            target_spawn_error_reported: false,
        },
        restart_safety: RestartSafetyProof {
            direct_child_reaped: facts.direct_child_reaped,
            workload_empty: facts.workload_empty,
            helpers_reaped: facts.helpers_reaped,
            containment_removed: facts.containment_removed,
            containment_incapable_of_live_members: facts.containment_incapable_of_live_members,
            errors: facts.errors,
        },
        execution,
    }
}

fn supervision_remaining(
    policy: &Policy,
    origin: Option<Duration>,
    elapsed: Duration,
) -> Option<Duration> {
    let origin = origin?;
    policy.deadline.and_then(|deadline| {
        if deadline.scope() == memcordon_core::DeadlineScope::Supervision {
            Some(
                deadline
                    .duration()
                    .saturating_sub(elapsed.saturating_sub(origin)),
            )
        } else {
            None
        }
    })
}

fn outside_deadline_evidence(
    policy: &Policy,
    origin: Option<Duration>,
    observed: Duration,
    terminal_phase: SupervisionPhase,
) -> Result<Option<SupervisionDeadlineEvidence>, Box<Error>> {
    let Some(origin) = origin else {
        return Ok(None);
    };
    let Some(deadline) = policy.deadline else {
        return Ok(None);
    };
    let expires = origin + deadline.duration();
    let evidence = memcordon_core::DeadlineEvidence::new(
        millis(deadline.duration()),
        memcordon_core::DeadlineScope::Supervision,
        deadline_origin().to_owned(),
        millis(expires),
        millis(observed.max(expires)),
        millis(policy.limit_grace),
        0,
        None,
        None,
    )
    .map_err(|_| {
        Box::new(Error::new(
            ErrorCategory::Monitor,
            "MCSUPERVISION-DEADLINE-EVIDENCE",
            "supervision deadline evidence is inconsistent",
        ))
    })?;
    Ok(Some(SupervisionDeadlineEvidence {
        evidence,
        terminal_phase,
    }))
}

fn restart_condition(outcome: &RunOutcome) -> Option<RestartCondition> {
    match outcome {
        RunOutcome::LimitExceeded { .. } => Some(RestartCondition::MemoryLimit),
        RunOutcome::DeadlineExceeded { deadline, .. }
            if deadline.scope() == memcordon_core::DeadlineScope::Attempt =>
        {
            Some(RestartCondition::Deadline)
        }
        _ => None,
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
fn controller_error(error: memcordon_core::RestartControllerError) -> Error {
    Error::new(
        ErrorCategory::Monitor,
        "MCRESTART-CONTROLLER",
        error.to_string(),
    )
}
fn model_error(error: memcordon_core::SupervisionModelError) -> Error {
    Error::new(ErrorCategory::Monitor, "MCRESTART-MODEL", error.to_string())
}
fn counter_error() -> Error {
    Error::new(
        ErrorCategory::Monitor,
        "MCRESTART-COUNTER-RANGE",
        "supervision counter exhausted",
    )
}
fn error_record(
    error: &Error,
    attempt_number: Option<u64>,
    phase: SupervisionPhase,
    kind: AttemptKind,
) -> SupervisionErrorRecord {
    SupervisionErrorRecord {
        category: format!("{:?}", error.category).to_ascii_lowercase(),
        code: error.code.to_owned(),
        message: error.message.clone(),
        os_code: error.os_code,
        attempt_number,
        supervision_phase: phase,
        launch_phase: error.launch_phase.map(str::to_owned),
        target_released: error.target_released,
        workload_may_be_alive: error.workload_may_be_alive,
        initial_spawn_failure: if kind == AttemptKind::Initial {
            error.initial_spawn_failure
        } else {
            None
        },
    }
}
fn proof_from_error(error: &Error) -> RestartSafetyProof {
    if let Some(proof) = &error.restart_safety {
        return proof.clone();
    }
    RestartSafetyProof {
        direct_child_reaped: false,
        workload_empty: None,
        helpers_reaped: false,
        containment_removed: false,
        containment_incapable_of_live_members: false,
        errors: vec![format!(
            "{}: setup failure has no complete backend resource proof",
            error.code
        )],
    }
}
fn launch_from_error(error: &Error) -> LaunchEvidence {
    LaunchEvidence {
        mechanism: launch_mechanism().to_owned(),
        target_released: error.target_released,
        containment_verified_before_authorization: error.cgroup_verified_before_release,
        guardian_started_before_authorization: error.guardian_ready_before_release,
        target_spawn_error_reported: error.launch_phase == Some("target-spawn-failed"),
    }
}
fn unsupported_capability() -> BackendCapabilityReport {
    BackendCapabilityReport {
        name: "unresolved".to_owned(),
        containment: CapabilityStatusReport {
            supported: false,
            reason: Some("attempt setup failed before backend selection".to_owned()),
        },
        memory: None,
        deadline: CapabilityStatusReport {
            supported: false,
            reason: None,
        },
        restart: CapabilityStatusReport {
            supported: false,
            reason: None,
        },
        deadline_scopes: Vec::new(),
        deadline_origin: None,
        restart_conditions: memcordon_core::RestartConditions::NONE,
        persistent_restart_state: false,
        startup_containment: String::new(),
        restart_cleanup_condition: String::new(),
        limitations: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn launch_mechanism() -> &'static str {
    "installed-cli-launcher-release-gate"
}
#[cfg(target_os = "macos")]
fn launch_mechanism() -> &'static str {
    "process-group-pre-spawn"
}
#[cfg(target_os = "windows")]
fn launch_mechanism() -> &'static str {
    "suspended-process-job-assignment"
}
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn launch_mechanism() -> &'static str {
    "unsupported-unix"
}
#[cfg(not(any(unix, target_os = "windows")))]
fn launch_mechanism() -> &'static str {
    "unsupported-platform"
}
#[cfg(target_os = "linux")]
fn deadline_origin() -> &'static str {
    "installed-cli-release-byte"
}
#[cfg(target_os = "macos")]
fn deadline_origin() -> &'static str {
    "pre-spawn"
}
#[cfg(target_os = "windows")]
fn deadline_origin() -> &'static str {
    "suspended-thread-resume"
}
#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn deadline_origin() -> &'static str {
    "unsupported"
}
#[cfg(not(any(unix, target_os = "windows")))]
fn deadline_origin() -> &'static str {
    "unsupported"
}
