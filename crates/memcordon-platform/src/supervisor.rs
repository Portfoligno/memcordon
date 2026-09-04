use std::path::PathBuf;
use std::time::{Duration, Instant};

use memcordon_core::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    BoundaryCapability, BoundaryClass, BoundaryRequirement, CapabilityStatusReport, CommandSpec,
    Error, ErrorCategory, LaunchEvidence, MemoryCapabilityReport, Policy, RestartAction,
    RestartCondition, RestartCoordinator, RestartDecisionKind, RestartDecisionRecord,
    RestartPolicy, RestartSafetyProof, RestartSummary, RestartWaitKind, RunOutcome,
    SupervisionAggregates, SupervisionDeadlineEvidence, SupervisionErrorRecord,
    SupervisionExecution, SupervisionPhase, SupervisionTerminal, WaitCompletion,
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
        if !windows_standard_route_selected(request.policy.boundary(), None) {
            return attempt_execution(crate::sealed::windows::run(
                &request.policy,
                &request.command,
                self,
                context,
            )?)
            .map_err(Box::new);
        }
        let execution = crate::windows_job::run_attempt(
            request.policy.clone(),
            &request.command,
            self,
            context,
        )
        .map_err(Box::new)?;
        attempt_execution(execution).map_err(Box::new)
    }
}

#[cfg(target_os = "windows")]
fn windows_standard_route_selected(
    boundary: BoundaryRequirement,
    mutant: Option<memcordon_core::WindowsSealedMutant>,
) -> bool {
    boundary != BoundaryRequirement::Sealed
        || mutant == Some(memcordon_core::WindowsSealedMutant::FallBackToStandard)
}

#[cfg(target_os = "windows")]
pub fn certify_windows_platform_mutant(
    mutant: memcordon_core::WindowsSealedMutant,
) -> Option<memcordon_core::WindowsMutantNativeObservationV1> {
    match mutant {
        memcordon_core::WindowsSealedMutant::FallBackToStandard => {
            let ordinary_route_sealed =
                !windows_standard_route_selected(BoundaryRequirement::Sealed, None);
            let mutant_route_standard =
                windows_standard_route_selected(BoundaryRequirement::Sealed, Some(mutant));
            Some(
                memcordon_core::WindowsMutantNativeObservationV1::PlatformRouteFallback {
                    ordinary_route_sealed,
                    mutant_route_standard,
                },
            )
        }
        memcordon_core::WindowsSealedMutant::AdvertiseWithoutCertificate => {
            crate::sealed::windows::certify_qualification_predicate_mutant(mutant)
        }
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct SupervisorRequest {
    pub policy: Policy,
    pub restart: RestartPolicy,
    pub command: CommandSpec,
    pub memcordon_executable: Option<PathBuf>,
    pub resolved_backend: Option<BackendCapabilityReport>,
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
    capabilities_for(info, BoundaryRequirement::Standard)
}

pub fn capabilities_for(
    info: &BackendInfo,
    requirement: BoundaryRequirement,
) -> BackendCapabilityReport {
    let (boundary_qualification, sealed_unavailable) = match &info.boundary_support.sealed {
        crate::backend::SealedAvailability::Available { qualification, .. } => (
            Some(memcordon_core::BoundaryQualificationReport {
                provider_identity: qualification.provider_identity.clone(),
                receipt_digest: qualification.receipt_digest.clone(),
                mechanism: qualification.mechanism.clone(),
            }),
            None,
        ),
        crate::backend::SealedAvailability::Unavailable {
            reason,
            prerequisites,
        } => (
            None,
            Some(memcordon_core::SealedUnavailableReport {
                reason: reason.clone(),
                prerequisites: prerequisites.clone(),
            }),
        ),
    };
    let boundary = match requirement {
        BoundaryRequirement::Standard => info.boundary_support.standard.clone(),
        BoundaryRequirement::Sealed => match &info.boundary_support.sealed {
            crate::backend::SealedAvailability::Available { capability, .. } => capability.clone(),
            crate::backend::SealedAvailability::Unavailable {
                reason,
                prerequisites,
            } => BoundaryCapability {
                class: BoundaryClass::Unavailable,
                mechanism: "sealed-provider-unavailable".to_owned(),
                limitations: std::iter::once(reason.clone())
                    .chain(
                        prerequisites
                            .iter()
                            .map(|value| format!("prerequisite: {value}")),
                    )
                    .collect(),
                ..BoundaryCapability::default()
            },
        },
    };
    BackendCapabilityReport {
        name: info.name.to_owned(),
        containment: CapabilityStatusReport {
            supported: info.containment_supported,
            reason: None,
        },
        boundary,
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
        boundary_qualification,
        sealed_unavailable,
    }
}

#[cfg(unix)]
#[allow(clippy::result_large_err)]
pub fn supervise(request: SupervisorRequest) -> Result<SupervisionExecution, Error> {
    let resolved_backend = validate_resolved_backend(&request)?;
    let signal = SignalSource::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-SIGNAL", error.to_string()).with_os_error(&error)
    })?;
    supervise_with(request, &signal, resolved_backend)
}

#[cfg(target_os = "windows")]
#[allow(clippy::result_large_err)]
pub fn supervise(request: SupervisorRequest) -> Result<SupervisionExecution, Error> {
    let resolved_backend = validate_resolved_backend(&request)?;
    let console = crate::windows_job::ConsoleControl::install().map_err(|error| {
        Error::new(ErrorCategory::Setup, "MCSETUP-CONSOLE", error.to_string()).with_os_error(&error)
    })?;
    supervise_with(request, &console, resolved_backend)
}

#[allow(clippy::result_large_err)]
fn validate_resolved_backend(
    request: &SupervisorRequest,
) -> Result<Option<BackendCapabilityReport>, Error> {
    let Some(backend) = request.resolved_backend.clone() else {
        if request.policy.boundary() != BoundaryRequirement::Sealed {
            return Ok(None);
        }
        // No target, helper, or boundary was created. Keep every cleanup fact
        // false/unknown instead of presenting non-applicable work as observed.
        let restart_safety = RestartSafetyProof::default();
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCBOUNDARY-UNSUPPORTED",
            "certified sealed supervision was not resolved before launch; the target was not authorized",
        )
        .with_restart_safety(restart_safety.clone())
        .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
            requested: BoundaryRequirement::Sealed,
            mechanism: None,
            phase: memcordon_core::BoundarySetupPhase::ProviderConnection,
            target_created: false,
            target_released: false,
            cleanup_attempted: false,
            restart_safety,
        }));
    };
    let expected = match request.policy.boundary() {
        BoundaryRequirement::Standard => memcordon_core::BoundaryClass::Standard,
        BoundaryRequirement::Sealed => memcordon_core::BoundaryClass::Sealed,
    };
    if backend.name.is_empty() || backend.boundary.class != expected {
        return Err(Error::new(
            ErrorCategory::Setup,
            "MCBACKEND-SELECTION-MISMATCH",
            "resolved backend does not satisfy the requested boundary",
        ));
    }
    Ok(Some(backend))
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
    resolved_backend: Option<BackendCapabilityReport>,
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
    let mut backend = resolved_backend;
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
                if error.code == "MCSUPERVISION-DEADLINE-BEFORE-AUTHORIZATION"
                    || sealed_deadline_rejection_is_outside_attempt(
                        &request.policy,
                        context,
                        &error,
                    )
                {
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
                            launch: launch_from_error(
                                &error,
                                request.policy.boundary(),
                                backend.as_ref(),
                            ),
                            restart_safety: proof_from_error(&error),
                            boundary_detail: boundary_failure_detail(
                                &error,
                                request.policy.boundary(),
                                backend.as_ref(),
                            ),
                        },
                        &mut aggregates,
                    )
                    .map_err(model_error)?;
                let capability = backend.unwrap_or_else(unsupported_capability);
                return SupervisionExecution::new(
                    capability,
                    SupervisionTerminal::Error {
                        attempt_number: Some(number),
                        error: Box::new(record_error),
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
                let observed =
                    capabilities_for(&attempt.execution.backend, request.policy.boundary());
                if backend.as_ref().is_some_and(|selected| {
                    !backend_selection_matches(selected, &observed, request.policy.metric)
                }) {
                    return Err(Error::new(
                        ErrorCategory::Monitor,
                        "MCBACKEND-SELECTION-DRIFT",
                        "runtime backend evidence disagrees with the resolved backend",
                    )
                    .with_restart_safety(attempt.restart_safety));
                }
                backend = Some(observed);
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
                            boundary_detail: attempt.execution.boundary_detail,
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

fn sealed_deadline_rejection_is_outside_attempt(
    policy: &Policy,
    context: AttemptContext,
    error: &Error,
) -> bool {
    let Some(deadline) = policy.deadline else {
        return false;
    };
    if deadline.scope() != memcordon_core::DeadlineScope::Supervision
        || context.supervision_deadline_remaining.is_none()
        || error.category != ErrorCategory::Setup
        || error.code != "MCSEALED-PROVIDER-REJECTION"
        || error.target_released
        || error.authorization_offset.is_some()
        || error.workload_may_be_alive
        || error.launch_phase != Some("authorization")
    {
        return false;
    }
    let (Some(rejection), Some(failure)) = (
        error.provider_rejection.as_ref(),
        error.boundary_setup_failure.as_ref(),
    ) else {
        return false;
    };
    rejection.schema_version == 1
        && rejection.code == "MCSEALED-AUTHORIZATION"
        && rejection.phase == memcordon_core::BoundarySetupPhase::Authorization
        && rejection.target_created
        && !rejection.target_released
        && rejection.cleanup_attempted
        && rejection
            .restart_safety
            .is_safe_for(BoundaryRequirement::Sealed)
        && error.os_code == rejection.os_code
        && error.restart_safety.as_ref() == Some(&rejection.restart_safety)
        && failure.requested == BoundaryRequirement::Sealed
        && failure.mechanism.as_deref() == Some("linux-pid-namespace-cgroup-v2")
        && failure.phase == rejection.phase
        && failure.target_created == rejection.target_created
        && failure.target_released == rejection.target_released
        && failure.cleanup_attempted == rejection.cleanup_attempted
        && failure.restart_safety == rejection.restart_safety
}

#[cfg(feature = "test-support")]
pub(crate) fn test_sealed_deadline_rejection_is_outside_attempt(
    policy: &Policy,
    context: AttemptContext,
    error: &Error,
) -> bool {
    sealed_deadline_rejection_is_outside_attempt(policy, context, error)
}

#[allow(clippy::result_large_err)]
#[cfg(unix)]
fn run_unix_attempt(
    request: &SupervisorRequest,
    signal: &SignalSource,
    context: AttemptContext,
) -> Result<AttemptExecution, Error> {
    #[cfg(target_os = "linux")]
    if request.policy.boundary() == BoundaryRequirement::Sealed {
        return attempt_execution(crate::sealed::client::run(
            &request.policy,
            &request.command,
            context,
        )?);
    }
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
    attempt_execution(execution)
}

#[allow(clippy::result_large_err)]
fn attempt_execution(execution: Execution) -> Result<AttemptExecution, Error> {
    validate_backend_execution(&execution)?;
    Ok(AttemptExecution {
        launch: execution.launch.clone(),
        restart_safety: execution.restart_safety.clone(),
        execution,
    })
}

#[allow(clippy::result_large_err)]
fn validate_backend_execution(execution: &Execution) -> Result<(), Error> {
    if memcordon_core::boundary_evidence_is_consistent(
        &execution.launch,
        &execution.restart_safety,
        &execution.boundary_detail,
    ) {
        Ok(())
    } else {
        Err(Error::new(
            ErrorCategory::Monitor,
            "MCBOUNDARY-EVIDENCE",
            "backend returned contradictory launch or retirement evidence",
        ))
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

fn backend_selection_matches(
    selected: &BackendCapabilityReport,
    observed: &BackendCapabilityReport,
    metric: memcordon_core::Metric,
) -> bool {
    let mut expected = selected.clone();
    if metric != memcordon_core::Metric::Native {
        if let Some(memory) = expected
            .memory
            .as_mut()
            .filter(|memory| memory.class == "watchdog")
        {
            memory.metric = watchdog_metric(metric).to_owned();
        }
    }
    expected == *observed
}

const fn watchdog_metric(metric: memcordon_core::Metric) -> &'static str {
    match metric {
        memcordon_core::Metric::Native | memcordon_core::Metric::PhysicalFootprint => {
            "physical-footprint-sum"
        }
        memcordon_core::Metric::Rss => "rss-sum",
        memcordon_core::Metric::Virtual => "virtual-size-sum",
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn test_backend_selection_matches(
    selected: &BackendCapabilityReport,
    observed: &BackendCapabilityReport,
    metric: memcordon_core::Metric,
) -> bool {
    backend_selection_matches(selected, observed, metric)
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
        provider_rejection: error.provider_rejection.clone(),
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
        sealed_boundary_retired: false,
        errors: vec![format!(
            "{}: setup failure has no complete backend resource proof",
            error.code
        )],
    }
}
fn launch_from_error(
    error: &Error,
    requested: BoundaryRequirement,
    backend: Option<&BackendCapabilityReport>,
) -> LaunchEvidence {
    let mechanism = backend
        .map(|backend| backend.boundary.mechanism.clone())
        .filter(|mechanism| !mechanism.is_empty())
        .unwrap_or_else(|| launch_mechanism().to_owned());
    let sealed = requested == BoundaryRequirement::Sealed;
    LaunchEvidence {
        mechanism,
        target_released: error.target_released,
        containment_verified_before_authorization: error.cgroup_verified_before_release,
        guardian_started_before_authorization: error.guardian_ready_before_release,
        target_spawn_error_reported: error.launch_phase == Some("target-spawn-failed"),
        boundary_requested: requested,
        boundary_effective: if error.target_released && sealed {
            BoundaryClass::Sealed
        } else if sealed {
            BoundaryClass::Unavailable
        } else {
            BoundaryClass::Standard
        },
        boundary_assignment_verified: sealed && error.cgroup_verified_before_release,
        boundary_reconfiguration_denied: sealed && error.cgroup_verified_before_release,
        inherited_resources_restricted: sealed && error.cgroup_verified_before_release,
        frontend_loss_cleanup_authority_verified: sealed && error.guardian_ready_before_release,
    }
}

fn boundary_failure_detail(
    error: &Error,
    requested: BoundaryRequirement,
    backend: Option<&BackendCapabilityReport>,
) -> memcordon_core::BoundaryMechanismEvidence {
    if let Some(failure) = &error.boundary_setup_failure {
        return memcordon_core::BoundaryMechanismEvidence::SetupFailure {
            provider_mechanism: failure
                .mechanism
                .clone()
                .or_else(|| backend.map(|backend| backend.boundary.mechanism.clone()))
                .unwrap_or_else(|| "unresolved-boundary-setup".to_owned()),
            requested,
        };
    }
    if requested == BoundaryRequirement::Sealed {
        return memcordon_core::BoundaryMechanismEvidence::SetupFailure {
            provider_mechanism: backend
                .map(|backend| backend.boundary.mechanism.clone())
                .filter(|mechanism| !mechanism.is_empty())
                .unwrap_or_else(|| "unresolved-sealed-setup".to_owned()),
            requested,
        };
    }
    memcordon_core::BoundaryMechanismEvidence::Standard {
        backend: backend
            .map(|backend| backend.name.clone())
            .unwrap_or_else(|| "setup-failed-before-selection".to_owned()),
    }
}
fn unsupported_capability() -> BackendCapabilityReport {
    BackendCapabilityReport {
        name: "unresolved".to_owned(),
        containment: CapabilityStatusReport {
            supported: false,
            reason: Some("attempt setup failed before backend selection".to_owned()),
        },
        boundary: BoundaryCapability {
            class: BoundaryClass::Unavailable,
            mechanism: "unavailable".to_owned(),
            limitations: vec!["certified sealed supervision is unavailable".to_owned()],
            ..BoundaryCapability::default()
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
        boundary_qualification: None,
        sealed_unavailable: None,
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
