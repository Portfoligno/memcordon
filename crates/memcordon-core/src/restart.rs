use std::num::NonZeroU64;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::{RestartDecisionKind, RestartDecisionRecord, RestartSafetyProof, RestartSummary};

pub(crate) trait MonotonicClock {
    type Instant: Copy + Ord;

    fn now(&self) -> Self::Instant;
    fn checked_add(&self, instant: Self::Instant, duration: Duration) -> Option<Self::Instant>;
    fn duration_since(&self, later: Self::Instant, earlier: Self::Instant) -> Duration;
}

#[derive(Clone, Copy)]
struct LogicalClock {
    now: Duration,
}

impl MonotonicClock for LogicalClock {
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

pub(crate) fn clock_deadline<C: MonotonicClock>(
    clock: &C,
    origin: C::Instant,
    duration: Duration,
) -> Result<(C::Instant, Duration), RestartControllerError> {
    let deadline = clock
        .checked_add(origin, duration)
        .ok_or(RestartControllerError::CounterRange)?;
    Ok((deadline, clock.duration_since(clock.now(), origin)))
}

pub const HALF_LIFE_LOGISTIC_MODEL: &str = "half-life-logistic-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestartConditions(u8);

impl Default for RestartConditions {
    fn default() -> Self {
        Self::NONE
    }
}

impl RestartConditions {
    pub const NONE: Self = Self(0);
    pub const MEMORY_LIMIT: Self = Self(1);
    pub const DEADLINE: Self = Self(2);
    pub const BOTH: Self = Self(3);

    pub const fn contains(self, condition: RestartCondition) -> bool {
        self.0 & condition.bit() != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl Serialize for RestartConditions {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut names = Vec::with_capacity(2);
        if self.contains(RestartCondition::MemoryLimit) {
            names.push("memory-limit");
        }
        if self.contains(RestartCondition::Deadline) {
            names.push("deadline");
        }
        names.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RestartConditions {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let names = Vec::<String>::deserialize(deserializer)?;
        let mut value = Self::NONE;
        for name in names {
            let bit = match name.as_str() {
                "memory-limit" => Self::MEMORY_LIMIT.0,
                "deadline" => Self::DEADLINE.0,
                _ => return Err(serde::de::Error::custom("unknown restart condition")),
            };
            if value.0 & bit != 0 {
                return Err(serde::de::Error::custom("duplicate restart condition"));
            }
            value.0 |= bit;
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartCondition {
    MemoryLimit,
    Deadline,
}

impl RestartCondition {
    const fn bit(self) -> u8 {
        match self {
            Self::MemoryLimit => 1,
            Self::Deadline => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "count", rename_all = "kebab-case")]
pub enum RestartLimit {
    Unlimited,
    Count(NonZeroU64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct BackoffMultiplier {
    numerator: u32,
    denominator: u32,
}

impl<'de> Deserialize<'de> for BackoffMultiplier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            numerator: u32,
            denominator: u32,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.numerator, wire.denominator).map_err(serde::de::Error::custom)
    }
}

impl BackoffMultiplier {
    pub fn new(numerator: u32, denominator: u32) -> Result<Self, MultiplierParseError> {
        if denominator == 0 || numerator < denominator {
            return Err(MultiplierParseError::Syntax);
        }
        let upper = u64::from(denominator)
            .checked_mul(100)
            .ok_or(MultiplierParseError::Range)?;
        if u64::from(numerator) > upper {
            return Err(MultiplierParseError::Syntax);
        }
        let divisor = gcd(u64::from(numerator), u64::from(denominator));
        Ok(Self {
            numerator: u32::try_from(u64::from(numerator) / divisor)
                .map_err(|_| MultiplierParseError::Range)?,
            denominator: u32::try_from(u64::from(denominator) / divisor)
                .map_err(|_| MultiplierParseError::Range)?,
        })
    }

    pub fn two() -> Self {
        Self {
            numerator: 2,
            denominator: 1,
        }
    }

    pub const fn numerator(self) -> u32 {
        self.numerator
    }

    pub const fn denominator(self) -> u32 {
        self.denominator
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum MultiplierParseError {
    #[error("multiplier must be an unsigned decimal from one through 100")]
    Syntax,
    #[error("multiplier exceeds its supported exact range")]
    Range,
}

impl FromStr for BackoffMultiplier {
    type Err = MultiplierParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() || value.starts_with(['+', '-']) || value.contains(['e', 'E']) {
            return Err(MultiplierParseError::Syntax);
        }
        let mut pieces = value.split('.');
        let whole = pieces.next().ok_or(MultiplierParseError::Syntax)?;
        let fraction = pieces.next();
        if pieces.next().is_some()
            || whole.is_empty()
            || !whole.bytes().all(|byte| byte.is_ascii_digit())
            || fraction.is_some_and(|digits| {
                digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit())
            })
        {
            return Err(MultiplierParseError::Syntax);
        }
        let digits = fraction.unwrap_or("");
        let exponent = u32::try_from(digits.len()).map_err(|_| MultiplierParseError::Range)?;
        let denominator = 10_u64
            .checked_pow(exponent)
            .ok_or(MultiplierParseError::Range)?;
        let whole = whole
            .parse::<u64>()
            .map_err(|_| MultiplierParseError::Range)?;
        let fractional = if digits.is_empty() {
            0
        } else {
            digits
                .parse::<u64>()
                .map_err(|_| MultiplierParseError::Range)?
        };
        let numerator = whole
            .checked_mul(denominator)
            .and_then(|number| number.checked_add(fractional))
            .ok_or(MultiplierParseError::Range)?;
        let divisor = gcd(numerator, denominator);
        let numerator =
            u32::try_from(numerator / divisor).map_err(|_| MultiplierParseError::Range)?;
        let denominator =
            u32::try_from(denominator / divisor).map_err(|_| MultiplierParseError::Range)?;
        Self::new(numerator, denominator)
    }
}

const fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HalfLifeLogisticBackoffPolicy {
    base_interval: Duration,
    multiplier: BackoffMultiplier,
    asymptote_interval: Duration,
    recovery_half_life: Duration,
}

impl Serialize for HalfLifeLogisticBackoffPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("HalfLifeLogisticBackoffPolicy", 4)?;
        state.serialize_field(
            "base_interval_ms",
            &duration_millis(self.base_interval).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("multiplier", &self.multiplier)?;
        state.serialize_field(
            "asymptote_interval_ms",
            &duration_millis(self.asymptote_interval).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field(
            "recovery_half_life_ms",
            &duration_millis(self.recovery_half_life).map_err(serde::ser::Error::custom)?,
        )?;
        state.end()
    }
}

impl Default for HalfLifeLogisticBackoffPolicy {
    fn default() -> Self {
        Self {
            base_interval: Duration::from_millis(250),
            multiplier: BackoffMultiplier {
                numerator: 4,
                denominator: 1,
            },
            asymptote_interval: Duration::from_secs(900),
            recovery_half_life: Duration::from_secs(900),
        }
    }
}

impl HalfLifeLogisticBackoffPolicy {
    pub fn new(
        base_interval: Duration,
        multiplier: BackoffMultiplier,
        asymptote_interval: Duration,
        recovery_half_life: Duration,
    ) -> Result<Self, RestartControllerError> {
        let value = Self {
            base_interval,
            multiplier,
            asymptote_interval,
            recovery_half_life,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn base_interval(self) -> Duration {
        self.base_interval
    }
    pub const fn multiplier(self) -> BackoffMultiplier {
        self.multiplier
    }
    pub const fn asymptote_interval(self) -> Duration {
        self.asymptote_interval
    }
    pub const fn recovery_half_life(self) -> Duration {
        self.recovery_half_life
    }
    pub fn validate(self) -> Result<(), RestartControllerError> {
        let base_interval = duration_millis(self.base_interval)?;
        let asymptote_interval = duration_millis(self.asymptote_interval)?;
        let recovery_half_life = duration_millis(self.recovery_half_life)?;
        if base_interval == 0 || asymptote_interval == 0 || recovery_half_life == 0 {
            return Err(RestartControllerError::InvalidBackoff);
        }
        let _ = half_life_logistic_next_millis(
            base_interval,
            base_interval,
            asymptote_interval,
            self.multiplier,
            recovery_half_life,
            0,
        )?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for HalfLifeLogisticBackoffPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            base_interval_ms: u64,
            multiplier: BackoffMultiplier,
            asymptote_interval_ms: u64,
            recovery_half_life_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            Duration::from_millis(wire.base_interval_ms),
            wire.multiplier,
            Duration::from_millis(wire.asymptote_interval_ms),
            Duration::from_millis(wire.recovery_half_life_ms),
        )
        .map_err(serde::de::Error::custom)
    }
}

pub fn half_life_logistic_next_millis(
    base_interval: u64,
    current_interval: u64,
    asymptote_interval: u64,
    multiplier: BackoffMultiplier,
    recovery_half_life: u64,
    elapsed_since_last_backoff: u64,
) -> Result<u64, RestartControllerError> {
    if base_interval == 0 || asymptote_interval == 0 || recovery_half_life == 0 {
        return Err(RestartControllerError::InvalidBackoff);
    }
    let decay_factor = (-(elapsed_since_last_backoff as f64 / recovery_half_life as f64)).exp2();
    let interval_delta = i128::from(current_interval) - i128::from(base_interval);
    let recovered_interval = base_interval as f64 + interval_delta as f64 * decay_factor;
    let normalized_recovered = recovered_interval / asymptote_interval as f64;
    let multiplier = multiplier.numerator() as f64 / multiplier.denominator() as f64;
    // The reciprocal form stays monotone from zero through the horizontal limit.
    let normalized_denominator = normalized_recovered.recip() + (multiplier - 1.0);
    let normalized_next = multiplier / normalized_denominator;
    let next_interval = (asymptote_interval as f64 * normalized_next).ceil();
    Ok(next_interval as u64)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HalfLifeLogisticBackoffState {
    policy: HalfLifeLogisticBackoffPolicy,
    current_interval: Duration,
    last_backoff_at: Option<Duration>,
}

impl HalfLifeLogisticBackoffState {
    pub fn new(policy: HalfLifeLogisticBackoffPolicy) -> Result<Self, RestartControllerError> {
        policy.validate()?;
        Ok(Self {
            current_interval: policy.base_interval,
            last_backoff_at: None,
            policy,
        })
    }

    pub const fn current_interval(&self) -> Duration {
        self.current_interval
    }

    pub const fn last_backoff_at(&self) -> Option<Duration> {
        self.last_backoff_at
    }

    pub fn effective_interval(&self, now: Duration) -> Result<Duration, RestartControllerError> {
        let Some(last_backoff_at) = self.last_backoff_at else {
            return Ok(self.policy.base_interval);
        };
        let elapsed = now
            .checked_sub(last_backoff_at)
            .ok_or(RestartControllerError::BackoffTimeReversed)?;
        let base_interval = duration_millis(self.policy.base_interval)?;
        let current_interval = duration_millis(self.current_interval)?;
        let recovery_half_life = duration_millis(self.policy.recovery_half_life)?;
        let decay_factor = (-(duration_millis(elapsed)? as f64 / recovery_half_life as f64)).exp2();
        let interval_delta = i128::from(current_interval) - i128::from(base_interval);
        let recovered = base_interval as f64 + interval_delta as f64 * decay_factor;
        Ok(Duration::from_millis(recovered.ceil() as u64))
    }

    pub fn on_backoff(&mut self, now: Duration) -> Result<Duration, RestartControllerError> {
        let elapsed = match self.last_backoff_at {
            Some(last_backoff_at) => now
                .checked_sub(last_backoff_at)
                .ok_or(RestartControllerError::BackoffTimeReversed)?,
            None => Duration::ZERO,
        };
        let next_interval = half_life_logistic_next_millis(
            duration_millis(self.policy.base_interval)?,
            duration_millis(self.current_interval)?,
            duration_millis(self.policy.asymptote_interval)?,
            self.policy.multiplier,
            duration_millis(self.policy.recovery_half_life)?,
            duration_millis(elapsed)?,
        )?;
        self.current_interval = Duration::from_millis(next_interval);
        self.last_backoff_at = Some(now);
        Ok(self.current_interval)
    }
}

fn duration_millis(duration: Duration) -> Result<u64, RestartControllerError> {
    duration
        .as_millis()
        .try_into()
        .map_err(|_| RestartControllerError::BackoffRange)
}

#[derive(Clone, Copy, Debug)]
pub struct CircuitBreakerPolicy {
    threshold: f64,
    half_life: Duration,
    cooldown: Duration,
}

impl PartialEq for CircuitBreakerPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.threshold == other.threshold
            && self.half_life == other.half_life
            && self.cooldown == other.cooldown
    }
}

impl Eq for CircuitBreakerPolicy {}

impl Serialize for CircuitBreakerPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CircuitBreakerPolicy", 3)?;
        state.serialize_field("threshold", &self.threshold)?;
        state.serialize_field(
            "half_life_ms",
            &duration_millis(self.half_life).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field(
            "cooldown_ms",
            &duration_millis(self.cooldown).map_err(serde::ser::Error::custom)?,
        )?;
        state.end()
    }
}

impl CircuitBreakerPolicy {
    pub fn new(
        threshold: f64,
        half_life: Duration,
        cooldown: Duration,
    ) -> Result<Self, RestartControllerError> {
        let value = Self {
            threshold,
            half_life,
            cooldown,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn threshold(self) -> f64 {
        self.threshold
    }
    pub const fn half_life(self) -> Duration {
        self.half_life
    }
    pub const fn cooldown(self) -> Duration {
        self.cooldown
    }
    pub fn validate(self) -> Result<(), RestartControllerError> {
        if !self.threshold.is_finite()
            || self.threshold <= 0.0
            || self.half_life < Duration::from_millis(1)
        {
            return Err(RestartControllerError::InvalidCircuit);
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for CircuitBreakerPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            threshold: f64,
            half_life_ms: u64,
            cooldown_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.threshold,
            Duration::from_millis(wire.half_life_ms),
            Duration::from_millis(wire.cooldown_ms),
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DormantRestartCondition {
    pub condition: RestartCondition,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestartSettings {
    configured_conditions: RestartConditions,
    effective_conditions: RestartConditions,
    dormant_conditions: Vec<DormantRestartCondition>,
    limit: RestartLimit,
    backoff: HalfLifeLogisticBackoffPolicy,
    circuit_breaker: Option<CircuitBreakerPolicy>,
}

impl RestartSettings {
    pub fn new(
        configured_conditions: RestartConditions,
        effective_conditions: RestartConditions,
        dormant_conditions: Vec<DormantRestartCondition>,
        limit: RestartLimit,
        backoff: HalfLifeLogisticBackoffPolicy,
        circuit_breaker: Option<CircuitBreakerPolicy>,
    ) -> Result<Self, RestartControllerError> {
        let value = Self {
            configured_conditions,
            effective_conditions,
            dormant_conditions,
            limit,
            backoff,
            circuit_breaker,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn configured_conditions(&self) -> RestartConditions {
        self.configured_conditions
    }
    pub const fn effective_conditions(&self) -> RestartConditions {
        self.effective_conditions
    }
    pub fn dormant_conditions(&self) -> &[DormantRestartCondition] {
        &self.dormant_conditions
    }
    pub const fn limit(&self) -> RestartLimit {
        self.limit
    }
    pub const fn backoff(&self) -> HalfLifeLogisticBackoffPolicy {
        self.backoff
    }
    pub const fn circuit_breaker(&self) -> Option<CircuitBreakerPolicy> {
        self.circuit_breaker
    }
    pub fn validate(&self) -> Result<(), RestartControllerError> {
        if self.effective_conditions.is_empty()
            || self.effective_conditions.0 & !self.configured_conditions.0 != 0
        {
            return Err(RestartControllerError::NoEffectiveCondition);
        }
        let dormant = self.configured_conditions.0 & !self.effective_conditions.0;
        let mut seen = 0_u8;
        for condition in &self.dormant_conditions {
            let bit = condition.condition.bit();
            if condition.reason.is_empty() || dormant & bit == 0 || seen & bit != 0 {
                return Err(RestartControllerError::InvalidConditions);
            }
            seen |= bit;
        }
        if seen != dormant {
            return Err(RestartControllerError::InvalidConditions);
        }
        self.backoff.validate()?;
        if let Some(circuit) = self.circuit_breaker {
            circuit.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for RestartSettings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            configured_conditions: RestartConditions,
            effective_conditions: RestartConditions,
            dormant_conditions: Vec<DormantRestartCondition>,
            limit: RestartLimit,
            backoff: HalfLifeLogisticBackoffPolicy,
            circuit_breaker: Option<CircuitBreakerPolicy>,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.configured_conditions,
            wire.effective_conditions,
            wire.dormant_conditions,
            wire.limit,
            wire.backoff,
            wire.circuit_breaker,
        )
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum RestartPolicy {
    Never,
    OnLimits(RestartSettings),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartWaitKind {
    HalfLifeLogisticBackoff,
    CircuitCooldown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScheduledRestart {
    pub kind: RestartWaitKind,
    pub duration: Duration,
    pub restart_number: u64,
    pub half_life_logistic_sequence_index: Option<u64>,
    pub circuit_state: CircuitState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaitCompletion {
    Completed,
    Interrupted,
    SupervisionDeadline,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaitResult {
    pub completion: WaitCompletion,
    pub actual_elapsed: Duration,
    pub supervision_deadline_remaining: Option<Duration>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartDecision {
    StopConditionNotSelected,
    StopLimitExhausted,
    StopCleanupUnsafe,
    StopInterrupted,
    StopSupervisionDeadline,
    Wait(ScheduledRestart),
    Launch {
        restart_number: u64,
        half_open: bool,
    },
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RestartControllerError {
    #[error("restart policy has no effective condition")]
    NoEffectiveCondition,
    #[error("restart configured, effective, and dormant conditions are inconsistent")]
    InvalidConditions,
    #[error("invalid half-life logistic backoff policy")]
    InvalidBackoff,
    #[error("half-life logistic backoff arithmetic is out of range")]
    BackoffRange,
    #[error("backoff event time moved backward")]
    BackoffTimeReversed,
    #[error("invalid circuit breaker policy")]
    InvalidCircuit,
    #[error("restart counter is out of range")]
    CounterRange,
    #[error("restart wait state was not respected")]
    InvalidTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestartAction {
    Stop(RestartDecisionKind),
    Wait {
        duration: Duration,
        kind: RestartWaitKind,
    },
    Launch {
        restart_number: u64,
        half_open: bool,
    },
}

#[derive(Clone, Debug)]
pub struct RestartCoordinator {
    controller: RestartController,
    summary: RestartSummary,
}

impl RestartCoordinator {
    pub fn new(settings: RestartSettings) -> Result<Self, RestartControllerError> {
        Ok(Self {
            controller: RestartController::new(settings)?,
            summary: RestartSummary::default(),
        })
    }
    pub fn on_limit(
        &mut self,
        condition: RestartCondition,
        now: Duration,
        cleanup: &RestartSafetyProof,
        record: &mut RestartDecisionRecord,
    ) -> Result<RestartAction, RestartControllerError> {
        let decision = self.controller.after_limit_recorded(
            condition,
            now,
            cleanup,
            record,
            &mut self.summary,
        )?;
        Ok(action(decision, record.decision))
    }
    pub fn complete_wait(
        &mut self,
        completion: WaitCompletion,
        actual_elapsed: Duration,
        supervision_deadline_remaining: Option<Duration>,
        record: &mut RestartDecisionRecord,
    ) -> Result<RestartAction, RestartControllerError> {
        let decision = self.controller.authorize_after_wait_recorded(
            WaitResult {
                completion,
                actual_elapsed,
                supervision_deadline_remaining,
            },
            record,
            &mut self.summary,
        )?;
        Ok(action(decision, record.decision))
    }
    pub fn summary(&self) -> &RestartSummary {
        &self.summary
    }
}

fn action(decision: RestartDecision, stop: RestartDecisionKind) -> RestartAction {
    match decision {
        RestartDecision::Wait(wait) => RestartAction::Wait {
            duration: wait.duration,
            kind: wait.kind,
        },
        RestartDecision::Launch {
            restart_number,
            half_open,
        } => RestartAction::Launch {
            restart_number,
            half_open,
        },
        RestartDecision::StopConditionNotSelected
        | RestartDecision::StopLimitExhausted
        | RestartDecision::StopCleanupUnsafe
        | RestartDecision::StopInterrupted
        | RestartDecision::StopSupervisionDeadline => RestartAction::Stop(stop),
    }
}

#[derive(Clone, Debug)]
pub struct RestartController {
    settings: RestartSettings,
    restarts_launched: u64,
    backoff: HalfLifeLogisticBackoffState,
    half_life_logistic_sequence_index: u64,
    circuit_pressure: f64,
    last_circuit_event_at: Option<Duration>,
    circuit_state: CircuitState,
    pending: Option<ScheduledRestart>,
}

impl RestartController {
    pub fn new(settings: RestartSettings) -> Result<Self, RestartControllerError> {
        settings.validate()?;
        Ok(Self {
            backoff: HalfLifeLogisticBackoffState::new(settings.backoff)?,
            settings,
            restarts_launched: 0,
            half_life_logistic_sequence_index: 0,
            circuit_pressure: 0.0,
            last_circuit_event_at: None,
            circuit_state: CircuitState::Closed,
            pending: None,
        })
    }

    pub const fn restarts_launched(&self) -> u64 {
        self.restarts_launched
    }

    pub fn after_limit_recorded(
        &mut self,
        condition: RestartCondition,
        now: Duration,
        cleanup: &RestartSafetyProof,
        record: &mut RestartDecisionRecord,
        summary: &mut RestartSummary,
    ) -> Result<RestartDecision, RestartControllerError> {
        let clock = LogicalClock { now };
        let (_, elapsed) = clock_deadline(&clock, Duration::ZERO, now)?;
        let now = elapsed;
        summary.enabled = true;
        record.trigger = Some(condition);
        if !self.settings.effective_conditions.contains(condition) {
            record.decision = RestartDecisionKind::NoneConditionNotSelected;
            return Ok(RestartDecision::StopConditionNotSelected);
        }
        if !cleanup.is_safe() {
            record.decision = RestartDecisionKind::NoneCleanupUnsafe;
            return Ok(RestartDecision::StopCleanupUnsafe);
        }
        if !self.has_remaining_launch() {
            record.decision = RestartDecisionKind::NoneLimitExhausted;
            summary.restart_limit_exhausted = true;
            return Ok(RestartDecision::StopLimitExhausted);
        }
        if self.pending.is_some() {
            return Err(RestartControllerError::InvalidTransition);
        }

        let sequence_index = self.half_life_logistic_sequence_index;
        let logistic_wait = self.backoff.on_backoff(now)?;
        self.half_life_logistic_sequence_index = self
            .half_life_logistic_sequence_index
            .checked_add(1)
            .ok_or(RestartControllerError::CounterRange)?;
        let opens = self.record_eligible_event(now)?;
        let half_open_failed = self.circuit_state == CircuitState::HalfOpen;
        let scheduled = if opens || half_open_failed {
            self.circuit_state = CircuitState::Open;
            let cooldown = self
                .settings
                .circuit_breaker
                .ok_or(RestartControllerError::InvalidCircuit)?
                .cooldown;
            ScheduledRestart {
                kind: RestartWaitKind::CircuitCooldown,
                duration: logistic_wait.max(cooldown),
                restart_number: self.next_restart_number()?,
                half_life_logistic_sequence_index: Some(sequence_index),
                circuit_state: CircuitState::Open,
            }
        } else {
            ScheduledRestart {
                kind: RestartWaitKind::HalfLifeLogisticBackoff,
                duration: logistic_wait,
                restart_number: self.next_restart_number()?,
                half_life_logistic_sequence_index: Some(sequence_index),
                circuit_state: CircuitState::Closed,
            }
        };
        self.pending = Some(scheduled);
        record.decision = match scheduled.kind {
            RestartWaitKind::HalfLifeLogisticBackoff => {
                RestartDecisionKind::HalfLifeLogisticBackoff
            }
            RestartWaitKind::CircuitCooldown => RestartDecisionKind::CircuitCooldown,
        };
        record.restart_number = Some(scheduled.restart_number);
        record.half_life_logistic_sequence_index = scheduled.half_life_logistic_sequence_index;
        record.configured_wait_ms = Some(duration_millis(scheduled.duration)?);
        record.wait_kind = Some(scheduled.kind);
        record.circuit_state = scheduled.circuit_state;
        match scheduled.kind {
            RestartWaitKind::HalfLifeLogisticBackoff => {
                summary.half_life_logistic_waits = summary
                    .half_life_logistic_waits
                    .checked_add(1)
                    .ok_or(RestartControllerError::CounterRange)?
            }
            RestartWaitKind::CircuitCooldown => {
                summary.cooldowns = summary
                    .cooldowns
                    .checked_add(1)
                    .ok_or(RestartControllerError::CounterRange)?;
                summary.circuit_open_count = summary
                    .circuit_open_count
                    .checked_add(1)
                    .ok_or(RestartControllerError::CounterRange)?;
            }
        }
        summary.final_circuit_state = self.circuit_state;
        Ok(RestartDecision::Wait(scheduled))
    }

    pub fn authorize_after_wait_recorded(
        &mut self,
        result: WaitResult,
        record: &mut RestartDecisionRecord,
        summary: &mut RestartSummary,
    ) -> Result<RestartDecision, RestartControllerError> {
        let scheduled = self
            .pending
            .take()
            .ok_or(RestartControllerError::InvalidTransition)?;
        record.actual_wait_ms = Some(duration_millis(result.actual_elapsed)?);
        match result.completion {
            WaitCompletion::Interrupted => {
                record.decision = RestartDecisionKind::AbortedByInterruption;
                return Ok(RestartDecision::StopInterrupted);
            }
            WaitCompletion::SupervisionDeadline => {
                record.decision = RestartDecisionKind::NoneTerminalDeadline;
                record.supervision_deadline_truncated_wait = true;
                return Ok(RestartDecision::StopSupervisionDeadline);
            }
            WaitCompletion::Completed => {}
        }
        if result.actual_elapsed < scheduled.duration {
            return Err(RestartControllerError::InvalidTransition);
        }
        if result
            .supervision_deadline_remaining
            .is_some_and(|remaining| remaining.is_zero())
        {
            record.decision = RestartDecisionKind::NoneTerminalDeadline;
            record.supervision_deadline_truncated_wait = true;
            return Ok(RestartDecision::StopSupervisionDeadline);
        }
        if !self.has_remaining_launch() {
            record.decision = RestartDecisionKind::NoneLimitExhausted;
            summary.restart_limit_exhausted = true;
            return Ok(RestartDecision::StopLimitExhausted);
        }
        self.restarts_launched = self
            .restarts_launched
            .checked_add(1)
            .ok_or(RestartControllerError::CounterRange)?;
        let half_open = scheduled.kind == RestartWaitKind::CircuitCooldown;
        self.circuit_state = if half_open {
            CircuitState::HalfOpen
        } else {
            CircuitState::Closed
        };
        record.decision = if half_open {
            RestartDecisionKind::HalfOpenLaunch
        } else {
            record.decision
        };
        record.circuit_state = self.circuit_state;
        summary.restarts_launched = self.restarts_launched;
        summary.final_circuit_state = self.circuit_state;
        Ok(RestartDecision::Launch {
            restart_number: self.restarts_launched,
            half_open,
        })
    }

    fn has_remaining_launch(&self) -> bool {
        match self.settings.limit {
            RestartLimit::Unlimited => true,
            RestartLimit::Count(limit) => self.restarts_launched < limit.get(),
        }
    }

    fn next_restart_number(&self) -> Result<u64, RestartControllerError> {
        self.restarts_launched
            .checked_add(1)
            .ok_or(RestartControllerError::CounterRange)
    }

    fn record_eligible_event(&mut self, now: Duration) -> Result<bool, RestartControllerError> {
        let Some(circuit) = self.settings.circuit_breaker else {
            return Ok(false);
        };
        let decay = match self.last_circuit_event_at {
            Some(previous) => {
                let elapsed = now
                    .checked_sub(previous)
                    .ok_or(RestartControllerError::BackoffTimeReversed)?;
                let elapsed_ms = duration_millis(elapsed)? as f64;
                let half_life_ms = duration_millis(circuit.half_life)? as f64;
                (-(elapsed_ms / half_life_ms)).exp2()
            }
            None => 0.0,
        };
        self.circuit_pressure = 1.0 + self.circuit_pressure * decay;
        self.last_circuit_event_at = Some(now);
        Ok(self.circuit_pressure >= circuit.threshold)
    }
}
