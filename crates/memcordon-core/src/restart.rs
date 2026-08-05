use std::collections::VecDeque;
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

pub const LOGISTIC_MODEL: &str = "logistic-odds-v1";

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
        if denominator == 0 || numerator <= denominator {
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
    #[error("multiplier must be an unsigned decimal greater than one and at most 100")]
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
pub struct LogisticBackoffPolicy {
    initial: Duration,
    multiplier: BackoffMultiplier,
    maximum: Duration,
}

impl Serialize for LogisticBackoffPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("LogisticBackoffPolicy", 3)?;
        state.serialize_field(
            "initial_ms",
            &duration_millis(self.initial).map_err(serde::ser::Error::custom)?,
        )?;
        state.serialize_field("multiplier", &self.multiplier)?;
        state.serialize_field(
            "maximum_ms",
            &duration_millis(self.maximum).map_err(serde::ser::Error::custom)?,
        )?;
        state.end()
    }
}

impl Default for LogisticBackoffPolicy {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            multiplier: BackoffMultiplier::two(),
            maximum: Duration::from_secs(30),
        }
    }
}

impl LogisticBackoffPolicy {
    pub fn new(
        initial: Duration,
        multiplier: BackoffMultiplier,
        maximum: Duration,
    ) -> Result<Self, RestartControllerError> {
        let value = Self {
            initial,
            multiplier,
            maximum,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn initial(self) -> Duration {
        self.initial
    }
    pub const fn multiplier(self) -> BackoffMultiplier {
        self.multiplier
    }
    pub const fn maximum(self) -> Duration {
        self.maximum
    }
    pub fn validate(self) -> Result<(), RestartControllerError> {
        if self.initial < Duration::from_millis(10) || self.maximum < self.initial {
            return Err(RestartControllerError::InvalidBackoff);
        }
        let current = duration_millis(self.initial)?;
        let maximum = duration_millis(self.maximum)?;
        let _ = logistic_next_millis(current, maximum, self.multiplier)?;
        Ok(())
    }
}

impl<'de> Deserialize<'de> for LogisticBackoffPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            initial_ms: u64,
            multiplier: BackoffMultiplier,
            maximum_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            Duration::from_millis(wire.initial_ms),
            wire.multiplier,
            Duration::from_millis(wire.maximum_ms),
        )
        .map_err(serde::de::Error::custom)
    }
}

pub fn logistic_next_millis(
    current: u64,
    maximum: u64,
    multiplier: BackoffMultiplier,
) -> Result<u64, RestartControllerError> {
    if current == 0 || maximum == 0 || current > maximum {
        return Err(RestartControllerError::InvalidBackoff);
    }
    let carrying = u128::from(maximum);
    let p = u128::from(multiplier.numerator());
    let q = u128::from(multiplier.denominator());
    let numerator = carrying
        .checked_mul(p)
        .and_then(|value| value.checked_mul(u128::from(current)))
        .ok_or(RestartControllerError::BackoffRange)?;
    let denominator = carrying
        .checked_mul(q)
        .and_then(|value| {
            p.checked_sub(q)
                .and_then(|difference| difference.checked_mul(u128::from(current)))
                .and_then(|addition| value.checked_add(addition))
        })
        .ok_or(RestartControllerError::BackoffRange)?;
    let rounded = numerator
        .checked_add(
            denominator
                .checked_sub(1)
                .ok_or(RestartControllerError::BackoffRange)?,
        )
        .ok_or(RestartControllerError::BackoffRange)?
        / denominator;
    let bounded = rounded.max(u128::from(current)).min(carrying);
    u64::try_from(bounded).map_err(|_| RestartControllerError::BackoffRange)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LogisticBackoffState {
    policy: LogisticBackoffPolicy,
    current_ms: u64,
}

impl LogisticBackoffState {
    pub fn new(policy: LogisticBackoffPolicy) -> Result<Self, RestartControllerError> {
        policy.validate()?;
        Ok(Self {
            current_ms: duration_millis(policy.initial)?,
            policy,
        })
    }

    pub const fn current_millis(&self) -> u64 {
        self.current_ms
    }

    pub fn advance(&mut self) -> Result<(), RestartControllerError> {
        self.current_ms = logistic_next_millis(
            self.current_ms,
            duration_millis(self.policy.maximum)?,
            self.policy.multiplier,
        )?;
        Ok(())
    }
}

fn duration_millis(duration: Duration) -> Result<u64, RestartControllerError> {
    duration
        .as_millis()
        .try_into()
        .map_err(|_| RestartControllerError::BackoffRange)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CircuitBreakerPolicy {
    burst: NonZeroU64,
    window: Duration,
    cooldown: Duration,
}

impl Serialize for CircuitBreakerPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("CircuitBreakerPolicy", 3)?;
        state.serialize_field("burst", &self.burst)?;
        state.serialize_field(
            "window_ms",
            &duration_millis(self.window).map_err(serde::ser::Error::custom)?,
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
        burst: NonZeroU64,
        window: Duration,
        cooldown: Duration,
    ) -> Result<Self, RestartControllerError> {
        let value = Self {
            burst,
            window,
            cooldown,
        };
        value.validate()?;
        Ok(value)
    }
    pub const fn burst(self) -> NonZeroU64 {
        self.burst
    }
    pub const fn window(self) -> Duration {
        self.window
    }
    pub const fn cooldown(self) -> Duration {
        self.cooldown
    }
    pub fn validate(self) -> Result<(), RestartControllerError> {
        if self.window < Duration::from_millis(10) || self.cooldown < Duration::from_millis(10) {
            return Err(RestartControllerError::InvalidCircuit);
        }
        usize::try_from(self.burst.get()).map_err(|_| RestartControllerError::CounterRange)?;
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
            burst: NonZeroU64,
            window_ms: u64,
            cooldown_ms: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.burst,
            Duration::from_millis(wire.window_ms),
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
    backoff: LogisticBackoffPolicy,
    circuit_breaker: Option<CircuitBreakerPolicy>,
}

impl RestartSettings {
    pub fn new(
        configured_conditions: RestartConditions,
        effective_conditions: RestartConditions,
        dormant_conditions: Vec<DormantRestartCondition>,
        limit: RestartLimit,
        backoff: LogisticBackoffPolicy,
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
    pub const fn backoff(&self) -> LogisticBackoffPolicy {
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
            backoff: LogisticBackoffPolicy,
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
    LogisticBackoff,
    CircuitCooldown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScheduledRestart {
    pub kind: RestartWaitKind,
    pub duration: Duration,
    pub restart_number: u64,
    pub logistic_sequence_index: Option<u64>,
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
    #[error("invalid logistic backoff policy")]
    InvalidBackoff,
    #[error("logistic backoff arithmetic is out of range")]
    BackoffRange,
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
    logistic_current_ms: u64,
    logistic_sequence_index: u64,
    eligible_events: VecDeque<Duration>,
    circuit_state: CircuitState,
    pending: Option<ScheduledRestart>,
}

impl RestartController {
    pub fn new(settings: RestartSettings) -> Result<Self, RestartControllerError> {
        settings.validate()?;
        Ok(Self {
            logistic_current_ms: duration_millis(settings.backoff.initial)?,
            settings,
            restarts_launched: 0,
            logistic_sequence_index: 0,
            eligible_events: VecDeque::new(),
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

        let opens = self.record_eligible_event(now)?;
        let half_open_failed = self.circuit_state == CircuitState::HalfOpen;
        let scheduled = if opens || half_open_failed {
            self.circuit_state = CircuitState::Open;
            ScheduledRestart {
                kind: RestartWaitKind::CircuitCooldown,
                duration: self
                    .settings
                    .circuit_breaker
                    .ok_or(RestartControllerError::InvalidCircuit)?
                    .cooldown,
                restart_number: self.next_restart_number()?,
                logistic_sequence_index: None,
                circuit_state: CircuitState::Open,
            }
        } else {
            let sequence_index = self.logistic_sequence_index;
            let wait = Duration::from_millis(self.logistic_current_ms);
            self.logistic_current_ms = logistic_next_millis(
                self.logistic_current_ms,
                duration_millis(self.settings.backoff.maximum)?,
                self.settings.backoff.multiplier,
            )?;
            self.logistic_sequence_index = self
                .logistic_sequence_index
                .checked_add(1)
                .ok_or(RestartControllerError::CounterRange)?;
            ScheduledRestart {
                kind: RestartWaitKind::LogisticBackoff,
                duration: wait,
                restart_number: self.next_restart_number()?,
                logistic_sequence_index: Some(sequence_index),
                circuit_state: CircuitState::Closed,
            }
        };
        self.pending = Some(scheduled);
        record.decision = match scheduled.kind {
            RestartWaitKind::LogisticBackoff => RestartDecisionKind::LogisticBackoff,
            RestartWaitKind::CircuitCooldown => RestartDecisionKind::CircuitCooldown,
        };
        record.restart_number = Some(scheduled.restart_number);
        record.logistic_sequence_index = scheduled.logistic_sequence_index;
        record.configured_wait_ms = Some(duration_millis(scheduled.duration)?);
        record.wait_kind = Some(scheduled.kind);
        record.circuit_state = scheduled.circuit_state;
        match scheduled.kind {
            RestartWaitKind::LogisticBackoff => {
                summary.logistic_waits = summary
                    .logistic_waits
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
        while self
            .eligible_events
            .front()
            .is_some_and(|old| now.saturating_sub(*old) > circuit.window)
        {
            self.eligible_events.pop_front();
        }
        self.eligible_events.push_back(now);
        let capacity = usize::try_from(circuit.burst.get())
            .map_err(|_| RestartControllerError::CounterRange)?;
        while self.eligible_events.len() > capacity {
            self.eligible_events.pop_front();
        }
        Ok(self.eligible_events.len() >= capacity)
    }
}
