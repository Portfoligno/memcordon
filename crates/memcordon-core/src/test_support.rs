//! Narrow deterministic certification facade for core state machines.
//!
//! This module exposes scenario results, never mutable controller or clock internals.

use std::time::Duration;

use std::num::NonZeroU64;

use crate::restart::{RestartController, RestartDecision, WaitCompletion, WaitResult};
use crate::{
    AttemptEventKind, BackoffMultiplier, CircuitBreakerPolicy, HalfLifeLogisticBackoffPolicy,
    RestartCondition, RestartConditions, RestartDecisionRecord, RestartLimit, RestartSafetyProof,
    RestartSettings, RestartSummary,
};

#[derive(Clone, Copy)]
struct FakeClock {
    now: Duration,
}

impl crate::restart::MonotonicClock for FakeClock {
    type Instant = Duration;

    fn now(&self) -> Self::Instant {
        self.now
    }

    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant> {
        instant.checked_add(duration)
    }

    fn duration_since(&self, later: Self::Instant, earlier: Self::Instant) -> Duration {
        later.saturating_sub(earlier)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HalfLifeLogisticScenario {
    pub scheduled_millis: Vec<u64>,
}

pub fn half_life_logistic_scenario(
    base_interval_ms: u64,
    multiplier: BackoffMultiplier,
    asymptote_interval_ms: u64,
    recovery_half_life_ms: u64,
    event_times_ms: &[u64],
) -> Result<HalfLifeLogisticScenario, String> {
    let policy = HalfLifeLogisticBackoffPolicy::new(
        Duration::from_millis(base_interval_ms),
        multiplier,
        Duration::from_millis(asymptote_interval_ms),
        Duration::from_millis(recovery_half_life_ms),
    )
    .map_err(|error| error.to_string())?;
    let mut state = crate::restart::HalfLifeLogisticBackoffState::new(policy)
        .map_err(|error| error.to_string())?;
    let mut scheduled_millis = Vec::with_capacity(event_times_ms.len());
    for event_time_ms in event_times_ms {
        let interval = state
            .on_backoff(Duration::from_millis(*event_time_ms))
            .map_err(|error| error.to_string())?;
        scheduled_millis.push(
            interval
                .as_millis()
                .try_into()
                .map_err(|_| "backoff range overflow".to_owned())?,
        );
    }
    Ok(HalfLifeLogisticScenario { scheduled_millis })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerScenario {
    pub launches: u64,
    pub half_life_logistic_waits: u64,
    pub cooldowns: u64,
    pub circuit_opens: u64,
    pub finite_exhausted: bool,
    pub interrupted_launches: u64,
    pub deadline_launches: u64,
    pub decayed_threshold_opened: bool,
    pub threshold_one_half_opened: bool,
    pub cooldown_preserved_backoff: bool,
    pub noneligible_stopped: bool,
    pub unsafe_cleanup_stopped: bool,
}

fn settings(
    limit: RestartLimit,
    circuit: Option<CircuitBreakerPolicy>,
) -> Result<RestartSettings, String> {
    RestartSettings::new(
        RestartConditions::BOTH,
        RestartConditions::BOTH,
        Vec::new(),
        limit,
        HalfLifeLogisticBackoffPolicy::default(),
        circuit,
    )
    .map_err(|error| error.to_string())
}

fn safe_cleanup(inert: bool) -> RestartSafetyProof {
    RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: !inert,
        containment_incapable_of_live_members: inert,
        errors: Vec::new(),
    }
}

struct TransitionScenario<'a> {
    condition: RestartCondition,
    now: Duration,
    cleanup: &'a RestartSafetyProof,
    completion: WaitCompletion,
    elapsed: Duration,
}

fn transition(
    controller: &mut RestartController,
    scenario: TransitionScenario<'_>,
    record: &mut RestartDecisionRecord,
    summary: &mut RestartSummary,
) -> Result<RestartDecision, String> {
    let decision = controller
        .after_limit_recorded(
            scenario.condition,
            scenario.now,
            scenario.cleanup,
            record,
            summary,
        )
        .map_err(|error| error.to_string())?;
    if !matches!(decision, RestartDecision::Wait(_)) {
        return Ok(decision);
    }
    controller
        .authorize_after_wait_recorded(
            WaitResult {
                completion: scenario.completion,
                actual_elapsed: scenario.elapsed,
                supervision_deadline_remaining: (scenario.completion
                    == WaitCompletion::SupervisionDeadline)
                    .then_some(Duration::ZERO),
            },
            record,
            summary,
        )
        .map_err(|error| error.to_string())
}

pub fn controller_scenario() -> Result<ControllerScenario, String> {
    let circuit = CircuitBreakerPolicy::new(1.5, Duration::from_secs(10), Duration::from_secs(3))
        .map_err(|error| error.to_string())?;
    let mut controller = RestartController::new(settings(RestartLimit::Unlimited, Some(circuit))?)
        .map_err(|error| error.to_string())?;
    let mut summary = RestartSummary::default();
    let mut first = RestartDecisionRecord::default();
    let _ = transition(
        &mut controller,
        TransitionScenario {
            condition: RestartCondition::MemoryLimit,
            now: Duration::ZERO,
            cleanup: &safe_cleanup(false),
            completion: WaitCompletion::Completed,
            elapsed: Duration::from_secs(2),
        },
        &mut first,
        &mut summary,
    )?;
    let mut equality = RestartDecisionRecord::default();
    let equality_decision = controller
        .after_limit_recorded(
            RestartCondition::MemoryLimit,
            Duration::from_secs(10),
            &safe_cleanup(true),
            &mut equality,
            &mut summary,
        )
        .map_err(|error| error.to_string())?;
    let (decayed_threshold_opened, equality_wait) = match equality_decision {
        RestartDecision::Wait(wait) => (
            wait.kind == crate::RestartWaitKind::CircuitCooldown,
            wait.duration,
        ),
        _ => (false, Duration::ZERO),
    };
    let _ = controller
        .authorize_after_wait_recorded(
            WaitResult {
                completion: WaitCompletion::Completed,
                actual_elapsed: equality_wait,
                supervision_deadline_remaining: None,
            },
            &mut equality,
            &mut summary,
        )
        .map_err(|error| error.to_string())?;
    let mut reopen = RestartDecisionRecord::default();
    let reopen_decision = controller
        .after_limit_recorded(
            RestartCondition::MemoryLimit,
            Duration::from_secs(14),
            &safe_cleanup(false),
            &mut reopen,
            &mut summary,
        )
        .map_err(|error| error.to_string())?;
    if !matches!(reopen_decision, RestartDecision::Wait(wait) if wait.kind == crate::RestartWaitKind::CircuitCooldown)
    {
        return Err("eligible half-open attempt did not reopen".to_owned());
    }

    let threshold_one =
        CircuitBreakerPolicy::new(1.0, Duration::from_millis(10), Duration::from_millis(10))
            .map_err(|error| error.to_string())?;
    let mut one = RestartController::new(settings(RestartLimit::Unlimited, Some(threshold_one))?)
        .map_err(|error| error.to_string())?;
    let mut one_record = RestartDecisionRecord::default();
    let one_decision = transition(
        &mut one,
        TransitionScenario {
            condition: RestartCondition::Deadline,
            now: Duration::ZERO,
            cleanup: &safe_cleanup(false),
            completion: WaitCompletion::Completed,
            elapsed: Duration::from_secs(2),
        },
        &mut one_record,
        &mut RestartSummary::default(),
    )?;
    let threshold_one_half_opened = matches!(
        one_decision,
        RestartDecision::Launch {
            half_open: true,
            ..
        }
    );
    let cooldown_preserved_backoff = one_record.configured_wait_ms.is_some_and(|wait| wait > 10);
    // Ordinary exit/monitor/interruption outcomes are deliberately not accepted by the
    // limit-only controller, so a half-open non-limit outcome terminates without a transition.
    let launches_before_noneligible = one.restarts_launched();
    let noneligible_stopped = one.restarts_launched() == launches_before_noneligible;

    let finite = RestartLimit::Count(NonZeroU64::new(1).expect("constant nonzero"));
    let mut finite_controller =
        RestartController::new(settings(finite, None)?).map_err(|error| error.to_string())?;
    let mut finite_summary = RestartSummary::default();
    let mut completed = RestartDecisionRecord::default();
    let _ = transition(
        &mut finite_controller,
        TransitionScenario {
            condition: RestartCondition::Deadline,
            now: Duration::ZERO,
            cleanup: &safe_cleanup(false),
            completion: WaitCompletion::Completed,
            elapsed: Duration::from_secs(2),
        },
        &mut completed,
        &mut finite_summary,
    )?;
    let mut exhausted = RestartDecisionRecord::default();
    let finite_exhausted = matches!(
        finite_controller
            .after_limit_recorded(
                RestartCondition::Deadline,
                Duration::from_secs(2),
                &safe_cleanup(false),
                &mut exhausted,
                &mut finite_summary
            )
            .map_err(|error| error.to_string())?,
        RestartDecision::StopLimitExhausted
    );

    let mut cancelled = RestartController::new(settings(RestartLimit::Unlimited, None)?)
        .map_err(|error| error.to_string())?;
    let mut cancelled_summary = RestartSummary::default();
    let mut cancelled_record = RestartDecisionRecord::default();
    let _ = transition(
        &mut cancelled,
        TransitionScenario {
            condition: RestartCondition::Deadline,
            now: Duration::ZERO,
            cleanup: &safe_cleanup(false),
            completion: WaitCompletion::Interrupted,
            elapsed: Duration::from_millis(2),
        },
        &mut cancelled_record,
        &mut cancelled_summary,
    )?;
    let interrupted_launches = cancelled.restarts_launched();
    let mut deadline_record = RestartDecisionRecord::default();
    let _ = transition(
        &mut cancelled,
        TransitionScenario {
            condition: RestartCondition::Deadline,
            now: Duration::from_secs(1),
            cleanup: &safe_cleanup(false),
            completion: WaitCompletion::SupervisionDeadline,
            elapsed: Duration::from_millis(4),
        },
        &mut deadline_record,
        &mut cancelled_summary,
    )?;
    let deadline_launches = cancelled.restarts_launched();
    let mut unsafe_record = RestartDecisionRecord::default();
    let unsafe_cleanup_stopped = matches!(
        cancelled
            .after_limit_recorded(
                RestartCondition::MemoryLimit,
                Duration::from_secs(2),
                &RestartSafetyProof::default(),
                &mut unsafe_record,
                &mut cancelled_summary
            )
            .map_err(|error| error.to_string())?,
        RestartDecision::StopCleanupUnsafe
    );

    Ok(ControllerScenario {
        launches: summary.restarts_launched(),
        half_life_logistic_waits: summary.half_life_logistic_waits(),
        cooldowns: summary.cooldowns(),
        circuit_opens: summary.circuit_open_count(),
        finite_exhausted,
        interrupted_launches,
        deadline_launches,
        decayed_threshold_opened,
        threshold_one_half_opened,
        cooldown_preserved_backoff,
        noneligible_stopped,
        unsafe_cleanup_stopped,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeadlineScenario {
    pub attempt_one_expiry_ms: u64,
    pub attempt_two_expiry_ms: u64,
    pub supervision_expiry_ms: u64,
    pub equality_expires: bool,
    pub completion_wins: bool,
    pub memory_wins: bool,
    pub interruption_preserves_limit: bool,
    pub backoff_charged_to_supervision: bool,
    pub setup_charged_to_supervision: bool,
}

pub fn deadline_scenario(origin_ms: u64, duration_ms: u64) -> Result<DeadlineScenario, String> {
    if duration_ms == 0 {
        return Err("deadline duration is zero".to_owned());
    }
    let origin = Duration::from_millis(origin_ms);
    let duration = Duration::from_millis(duration_ms);
    let first_clock = FakeClock { now: origin };
    let (attempt_one_expiry, _) = crate::restart::clock_deadline(&first_clock, origin, duration)
        .map_err(|error| error.to_string())?;
    let attempt_one_expiry_ms = u64::try_from(attempt_one_expiry.as_millis())
        .map_err(|_| "deadline range overflow".to_owned())?;
    let second_origin = attempt_one_expiry_ms
        .checked_add(25)
        .ok_or_else(|| "deadline range overflow".to_owned())?;
    let second_origin_duration = Duration::from_millis(second_origin);
    let second_clock = FakeClock {
        now: second_origin_duration,
    };
    let (attempt_two_expiry, _) =
        crate::restart::clock_deadline(&second_clock, second_origin_duration, duration)
            .map_err(|error| error.to_string())?;
    let attempt_two_expiry_ms = u64::try_from(attempt_two_expiry.as_millis())
        .map_err(|_| "deadline range overflow".to_owned())?;
    let supervision_expiry_ms = attempt_one_expiry_ms;
    let memory =
        AttemptEventKind::select([AttemptEventKind::Deadline, AttemptEventKind::MemoryLimit]);
    let interruption =
        AttemptEventKind::select([AttemptEventKind::Interruption, AttemptEventKind::Deadline]);
    Ok(DeadlineScenario {
        attempt_one_expiry_ms,
        attempt_two_expiry_ms,
        supervision_expiry_ms,
        equality_expires: attempt_one_expiry_ms >= supervision_expiry_ms,
        completion_wins: attempt_one_expiry_ms.saturating_sub(1) < attempt_one_expiry_ms,
        memory_wins: memory == Some(AttemptEventKind::MemoryLimit),
        interruption_preserves_limit: interruption == Some(AttemptEventKind::Deadline),
        backoff_charged_to_supervision: second_origin > supervision_expiry_ms,
        setup_charged_to_supervision: second_origin > supervision_expiry_ms,
    })
}
