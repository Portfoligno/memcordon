use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::{
    ByteSize, ChildTermination, CircuitState, CleanupSummary, DeadlineEvidence, RestartCondition,
    RestartWaitKind, RunOutcome,
};

pub const DETAILED_ATTEMPT_CAPACITY: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupervisionPhase {
    InitialSetup,
    AttemptSetup,
    ActiveAttempt,
    LimitGrace,
    Cleanup,
    Backoff,
    Cooldown,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptKind {
    Initial,
    Restart,
    HalfOpen,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttemptPhase {
    Setup,
    Authorized,
    Running,
    Cleanup,
    Completed,
    Failed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct LaunchEvidence {
    pub mechanism: String,
    pub target_released: bool,
    pub containment_verified_before_authorization: bool,
    pub guardian_started_before_authorization: bool,
    pub target_spawn_error_reported: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestartSafetyProof {
    pub direct_child_reaped: bool,
    pub workload_empty: Option<bool>,
    pub helpers_reaped: bool,
    pub containment_removed: bool,
    pub containment_incapable_of_live_members: bool,
    pub errors: Vec<String>,
}

impl RestartSafetyProof {
    pub fn is_safe(&self) -> bool {
        self.direct_child_reaped
            && self.workload_empty == Some(true)
            && self.helpers_reaped
            && (self.containment_removed || self.containment_incapable_of_live_members)
            && self.errors.is_empty()
    }

    pub fn from_cleanup(cleanup: &CleanupSummary) -> Self {
        Self {
            direct_child_reaped: cleanup.direct_child_reaped,
            workload_empty: cleanup.workload_empty,
            helpers_reaped: false,
            containment_removed: false,
            containment_incapable_of_live_members: false,
            errors: cleanup
                .errors
                .iter()
                .map(|error| format!("{}: {}", error.operation, error.message))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisionErrorRecord {
    pub category: String,
    pub code: String,
    pub message: String,
    pub os_code: Option<i32>,
    pub attempt_number: Option<u64>,
    pub supervision_phase: SupervisionPhase,
    pub launch_phase: Option<String>,
    pub target_released: bool,
    pub workload_may_be_alive: bool,
    pub initial_spawn_failure: Option<crate::InitialSpawnFailure>,
}

impl SupervisionErrorRecord {
    pub const fn terminal_status(&self) -> i32 {
        match self.initial_spawn_failure {
            Some(failure) => failure.exit_code(),
            None => 125,
        }
    }

    fn provenance_is_consistent(&self) -> bool {
        self.initial_spawn_failure.is_none()
            || (self.category == "spawn"
                && self.supervision_phase == SupervisionPhase::AttemptSetup
                && self.launch_phase.as_deref() == Some("target-spawn-failed")
                && self.attempt_number.is_some())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartDecisionKind {
    NoneDisabled,
    NoneConditionNotSelected,
    NoneLimitExhausted,
    NoneCleanupUnsafe,
    NoneTerminalDeadline,
    LogisticBackoff,
    CircuitCooldown,
    HalfOpenLaunch,
    AbortedByInterruption,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RestartDecisionRecord {
    pub trigger: Option<RestartCondition>,
    pub decision: RestartDecisionKind,
    pub restart_number: Option<u64>,
    pub logistic_sequence_index: Option<u64>,
    pub configured_wait_ms: Option<u64>,
    pub actual_wait_ms: Option<u64>,
    pub wait_kind: Option<RestartWaitKind>,
    pub circuit_state: CircuitState,
    pub supervision_deadline_truncated_wait: bool,
}

impl Default for RestartDecisionRecord {
    fn default() -> Self {
        Self {
            trigger: None,
            decision: RestartDecisionKind::NoneDisabled,
            restart_number: None,
            logistic_sequence_index: None,
            configured_wait_ms: None,
            actual_wait_ms: None,
            wait_kind: None,
            circuit_state: CircuitState::Closed,
            supervision_deadline_truncated_wait: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AttemptRecord {
    pub number: u64,
    pub kind: AttemptKind,
    pub phase: AttemptPhase,
    pub target_pid: Option<u32>,
    pub started_offset_ms: Option<u64>,
    pub authorized_offset_ms: Option<u64>,
    pub terminal_offset_ms: Option<u64>,
    pub finished_offset_ms: u64,
    pub outcome: Option<RunOutcome>,
    pub error: Option<SupervisionErrorRecord>,
    pub restart_decision: RestartDecisionRecord,
    pub launch: LaunchEvidence,
    pub restart_safety: RestartSafetyProof,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct AttemptHistory {
    pub first: Option<AttemptRecord>,
    pub recent: VecDeque<AttemptRecord>,
    pub total: u64,
    pub omitted: u64,
}

impl AttemptHistory {
    fn validate(&self) -> bool {
        if self.total == 0 {
            return self.first.is_none() && self.recent.is_empty() && self.omitted == 0;
        }
        if self.first.as_ref().map(|record| record.number) != Some(1) {
            return false;
        }
        let retained = self.retained() as u64;
        if retained > self.total || self.omitted != self.total - retained {
            return false;
        }
        let expected_recent_start = self.total.saturating_sub(self.recent.len() as u64) + 1;
        self.recent.iter().enumerate().all(|(index, record)| {
            record.number == expected_recent_start + index as u64 && record.is_consistent()
        }) && self
            .first
            .as_ref()
            .is_some_and(AttemptRecord::is_consistent)
    }
    pub fn append(
        &mut self,
        mut record: AttemptRecord,
        aggregates: &mut SupervisionAggregates,
    ) -> Result<u64, SupervisionModelError> {
        let number = self
            .total
            .checked_add(1)
            .ok_or(SupervisionModelError::CounterRange)?;
        if record.number == 0 {
            record.number = number;
        } else if record.number != number {
            return Err(SupervisionModelError::AttemptNumber);
        }
        let mut next_aggregates = aggregates.clone();
        if let Some(outcome) = &record.outcome {
            next_aggregates.observe_outcome(outcome)?;
        } else if record.error.is_some() {
            next_aggregates.observe_setup_failure()?;
        }
        let next_omitted =
            if self.first.is_some() && self.recent.len() == DETAILED_ATTEMPT_CAPACITY - 1 {
                Some(
                    self.omitted
                        .checked_add(1)
                        .ok_or(SupervisionModelError::CounterRange)?,
                )
            } else {
                None
            };
        self.total = number;
        if self.first.is_none() {
            self.first = Some(record);
            *aggregates = next_aggregates;
            return Ok(number);
        }
        if let Some(omitted) = next_omitted {
            self.recent.pop_front();
            self.omitted = omitted;
        }
        self.recent.push_back(record);
        *aggregates = next_aggregates;
        Ok(number)
    }

    pub fn retained(&self) -> usize {
        usize::from(self.first.is_some()) + self.recent.len()
    }

    pub fn records(&self) -> impl Iterator<Item = &AttemptRecord> {
        self.first.iter().chain(self.recent.iter())
    }
}

impl AttemptRecord {
    fn is_consistent(&self) -> bool {
        self.number > 0
            && self.outcome.is_some() != self.error.is_some()
            && self
                .error
                .as_ref()
                .is_none_or(|error| error.attempt_number == Some(self.number))
            && ((self.outcome.is_some() && self.phase == AttemptPhase::Completed)
                || (self.error.is_some() && self.phase == AttemptPhase::Failed))
            && self
                .started_offset_ms
                .is_none_or(|start| start <= self.finished_offset_ms)
            && self.authorized_offset_ms.is_none_or(|authorized| {
                self.started_offset_ms
                    .is_some_and(|start| start <= authorized)
                    && authorized <= self.finished_offset_ms
            })
            && self.terminal_offset_ms.is_none_or(|terminal| {
                self.started_offset_ms
                    .is_some_and(|start| start <= terminal)
                    && terminal <= self.finished_offset_ms
            })
            && match (self.authorized_offset_ms, self.terminal_offset_ms) {
                (Some(authorized), Some(terminal)) => authorized <= terminal,
                _ => true,
            }
    }
}

impl<'de> Deserialize<'de> for AttemptRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            number: u64,
            kind: AttemptKind,
            phase: AttemptPhase,
            target_pid: Option<u32>,
            started_offset_ms: Option<u64>,
            authorized_offset_ms: Option<u64>,
            terminal_offset_ms: Option<u64>,
            finished_offset_ms: u64,
            outcome: Option<RunOutcome>,
            error: Option<SupervisionErrorRecord>,
            restart_decision: RestartDecisionRecord,
            launch: LaunchEvidence,
            restart_safety: RestartSafetyProof,
        }
        let wire = Wire::deserialize(deserializer)?;
        let record = Self {
            number: wire.number,
            kind: wire.kind,
            phase: wire.phase,
            target_pid: wire.target_pid,
            started_offset_ms: wire.started_offset_ms,
            authorized_offset_ms: wire.authorized_offset_ms,
            terminal_offset_ms: wire.terminal_offset_ms,
            finished_offset_ms: wire.finished_offset_ms,
            outcome: wire.outcome,
            error: wire.error,
            restart_decision: wire.restart_decision,
            launch: wire.launch,
            restart_safety: wire.restart_safety,
        };
        if !record.is_consistent() {
            return Err(serde::de::Error::custom("invalid attempt record"));
        }
        Ok(record)
    }
}

impl<'de> Deserialize<'de> for AttemptHistory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            first: Option<AttemptRecord>,
            recent: VecDeque<AttemptRecord>,
            total: u64,
            omitted: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let history = Self {
            first: wire.first,
            recent: wire.recent,
            total: wire.total,
            omitted: wire.omitted,
        };
        if !history.validate() {
            return Err(serde::de::Error::custom("invalid attempt history"));
        }
        Ok(history)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisionAggregates {
    pub child_exits: u64,
    pub memory_limits: u64,
    pub deadlines: u64,
    pub interruptions: u64,
    pub monitor_failures: u64,
    pub setup_failures: u64,
    pub max_peak: Option<ByteSize>,
}

impl SupervisionAggregates {
    pub fn observe_outcome(&mut self, outcome: &RunOutcome) -> Result<(), SupervisionModelError> {
        let counter = match outcome {
            RunOutcome::Exited { .. } => &mut self.child_exits,
            RunOutcome::LimitExceeded { .. } => &mut self.memory_limits,
            RunOutcome::DeadlineExceeded { .. } => &mut self.deadlines,
            RunOutcome::Interrupted { .. } => &mut self.interruptions,
            RunOutcome::MonitorFailed { .. } => &mut self.monitor_failures,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(SupervisionModelError::CounterRange)?;
        let peak = match outcome {
            RunOutcome::Exited { peak, .. }
            | RunOutcome::LimitExceeded { peak, .. }
            | RunOutcome::DeadlineExceeded { peak, .. } => *peak,
            RunOutcome::Interrupted { .. } | RunOutcome::MonitorFailed { .. } => None,
        };
        if peak > self.max_peak {
            self.max_peak = peak;
        }
        Ok(())
    }

    pub fn observe_setup_failure(&mut self) -> Result<(), SupervisionModelError> {
        self.setup_failures = self
            .setup_failures
            .checked_add(1)
            .ok_or(SupervisionModelError::CounterRange)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SupervisionDeadlineEvidence {
    pub evidence: DeadlineEvidence,
    pub terminal_phase: SupervisionPhase,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SupervisionTerminal {
    AttemptOutcome {
        attempt_number: u64,
        outcome: RunOutcome,
    },
    DeadlineOutsideAttempt {
        evidence: SupervisionDeadlineEvidence,
    },
    Error {
        attempt_number: Option<u64>,
        error: SupervisionErrorRecord,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RestartSummary {
    pub(crate) enabled: bool,
    pub(crate) restarts_launched: u64,
    pub(crate) restart_limit_exhausted: bool,
    pub(crate) logistic_waits: u64,
    pub(crate) cooldowns: u64,
    pub(crate) circuit_open_count: u64,
    pub(crate) final_circuit_state: CircuitState,
}

impl RestartSummary {
    pub const fn enabled(&self) -> bool {
        self.enabled
    }
    pub const fn restarts_launched(&self) -> u64 {
        self.restarts_launched
    }
    pub const fn restart_limit_exhausted(&self) -> bool {
        self.restart_limit_exhausted
    }
    pub const fn logistic_waits(&self) -> u64 {
        self.logistic_waits
    }
    pub const fn cooldowns(&self) -> u64 {
        self.cooldowns
    }
    pub const fn circuit_open_count(&self) -> u64 {
        self.circuit_open_count
    }
    pub const fn final_circuit_state(&self) -> CircuitState {
        self.final_circuit_state
    }
    pub(crate) fn is_consistent(&self, targets_authorized: u64) -> bool {
        self.restarts_launched <= targets_authorized
            && (targets_authorized == 0 || self.restarts_launched == targets_authorized - 1)
            && (!self.enabled || targets_authorized > 0)
    }
    fn is_standalone_valid(&self) -> bool {
        self.cooldowns <= self.circuit_open_count
            && (self.enabled
                || (self.restarts_launched == 0
                    && !self.restart_limit_exhausted
                    && self.logistic_waits == 0
                    && self.cooldowns == 0
                    && self.circuit_open_count == 0
                    && self.final_circuit_state == CircuitState::Closed))
    }
}

impl<'de> Deserialize<'de> for RestartSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            enabled: bool,
            restarts_launched: u64,
            restart_limit_exhausted: bool,
            logistic_waits: u64,
            cooldowns: u64,
            circuit_open_count: u64,
            final_circuit_state: CircuitState,
        }
        let wire = Wire::deserialize(deserializer)?;
        let summary = Self {
            enabled: wire.enabled,
            restarts_launched: wire.restarts_launched,
            restart_limit_exhausted: wire.restart_limit_exhausted,
            logistic_waits: wire.logistic_waits,
            cooldowns: wire.cooldowns,
            circuit_open_count: wire.circuit_open_count,
            final_circuit_state: wire.final_circuit_state,
        };
        if !summary.is_standalone_valid() {
            return Err(serde::de::Error::custom("invalid restart summary"));
        }
        Ok(summary)
    }
}

impl Default for RestartSummary {
    fn default() -> Self {
        Self {
            enabled: false,
            restarts_launched: 0,
            restart_limit_exhausted: false,
            logistic_waits: 0,
            cooldowns: 0,
            circuit_open_count: 0,
            final_circuit_state: CircuitState::Closed,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SupervisionExecution {
    backend: BackendCapabilityReport,
    terminal: SupervisionTerminal,
    attempts: AttemptHistory,
    aggregates: SupervisionAggregates,
    restart: RestartSummary,
    deadline: Option<SupervisionDeadlineEvidence>,
    duration_ms: u64,
    targets_authorized: u64,
    wrapper_exit_code: i32,
    phase: SupervisionPhase,
}

impl<'de> Deserialize<'de> for SupervisionExecution {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            backend: BackendCapabilityReport,
            terminal: SupervisionTerminal,
            attempts: AttemptHistory,
            aggregates: SupervisionAggregates,
            restart: RestartSummary,
            deadline: Option<SupervisionDeadlineEvidence>,
            duration_ms: u64,
            targets_authorized: u64,
            wrapper_exit_code: i32,
            phase: SupervisionPhase,
        }
        let wire = Wire::deserialize(deserializer)?;
        let execution = Self::new(
            wire.backend,
            wire.terminal,
            wire.attempts,
            wire.aggregates,
            wire.restart,
            wire.deadline,
            wire.duration_ms,
            wire.targets_authorized,
        )
        .map_err(serde::de::Error::custom)?;
        if execution.wrapper_exit_code != wire.wrapper_exit_code || execution.phase != wire.phase {
            return Err(serde::de::Error::custom(
                "derived supervision terminal fields disagree",
            ));
        }
        Ok(execution)
    }
}

impl SupervisionExecution {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: BackendCapabilityReport,
        terminal: SupervisionTerminal,
        attempts: AttemptHistory,
        aggregates: SupervisionAggregates,
        restart: RestartSummary,
        deadline: Option<SupervisionDeadlineEvidence>,
        duration_ms: u64,
        targets_authorized: u64,
    ) -> Result<Self, SupervisionModelError> {
        let aggregate_total = aggregates
            .child_exits
            .checked_add(aggregates.memory_limits)
            .and_then(|v| v.checked_add(aggregates.deadlines))
            .and_then(|v| v.checked_add(aggregates.interruptions))
            .and_then(|v| v.checked_add(aggregates.monitor_failures))
            .and_then(|v| v.checked_add(aggregates.setup_failures))
            .ok_or(SupervisionModelError::CounterRange)?;
        if aggregate_total != attempts.total
            || !attempts.validate()
            || attempts.retained() > DETAILED_ATTEMPT_CAPACITY
            || attempts.omitted != attempts.total.saturating_sub(attempts.retained() as u64)
            || restart.restarts_launched > targets_authorized
            || (targets_authorized > 0 && restart.restarts_launched != targets_authorized - 1)
        {
            return Err(SupervisionModelError::InconsistentExecution);
        }
        let (wrapper_exit_code, outside_deadline, terminal_attempt) = match &terminal {
            SupervisionTerminal::AttemptOutcome {
                attempt_number,
                outcome,
            } => (outcome_status(outcome), false, Some(*attempt_number)),
            SupervisionTerminal::DeadlineOutsideAttempt { evidence } => {
                if evidence.evidence.scope() != crate::DeadlineScope::Supervision {
                    return Err(SupervisionModelError::InconsistentExecution);
                }
                (123, true, None)
            }
            SupervisionTerminal::Error {
                attempt_number,
                error,
            } => (error.terminal_status(), false, *attempt_number),
        };
        let latest = attempts.records().last();
        let terminal_matches_latest = match &terminal {
            SupervisionTerminal::AttemptOutcome {
                attempt_number,
                outcome,
            } => latest.is_some_and(|record| {
                record.number == *attempt_number && record.outcome.as_ref() == Some(outcome)
            }),
            SupervisionTerminal::Error {
                attempt_number: Some(attempt_number),
                error,
            } => {
                error.provenance_is_consistent()
                    && error.attempt_number == Some(*attempt_number)
                    && latest.is_some_and(|record| {
                        record.number == *attempt_number && record.error.as_ref() == Some(error)
                    })
            }
            SupervisionTerminal::Error {
                attempt_number: None,
                error,
            } => error.provenance_is_consistent() && error.attempt_number.is_none(),
            SupervisionTerminal::DeadlineOutsideAttempt { .. } => true,
        };
        if terminal_attempt.is_some_and(|number| number == 0 || number != attempts.total)
            || !terminal_matches_latest
            || outside_deadline != deadline.is_some()
        {
            return Err(SupervisionModelError::InconsistentExecution);
        }
        Ok(Self {
            backend,
            terminal,
            attempts,
            aggregates,
            restart,
            deadline,
            duration_ms,
            targets_authorized,
            wrapper_exit_code,
            phase: SupervisionPhase::Completed,
        })
    }

    pub fn backend(&self) -> &BackendCapabilityReport {
        &self.backend
    }
    pub fn terminal(&self) -> &SupervisionTerminal {
        &self.terminal
    }
    pub fn attempts(&self) -> &AttemptHistory {
        &self.attempts
    }
    pub fn aggregates(&self) -> &SupervisionAggregates {
        &self.aggregates
    }
    pub fn restart(&self) -> &RestartSummary {
        &self.restart
    }
    pub fn deadline(&self) -> Option<&SupervisionDeadlineEvidence> {
        self.deadline.as_ref()
    }
    pub const fn duration_ms(&self) -> u64 {
        self.duration_ms
    }
    pub const fn targets_authorized(&self) -> u64 {
        self.targets_authorized
    }
    pub const fn wrapper_exit_code(&self) -> i32 {
        self.wrapper_exit_code
    }
    pub const fn phase(&self) -> SupervisionPhase {
        self.phase
    }
}

pub(crate) fn outcome_status(outcome: &RunOutcome) -> i32 {
    match outcome {
        RunOutcome::LimitExceeded { .. } => 124,
        RunOutcome::DeadlineExceeded { .. } => 123,
        RunOutcome::MonitorFailed { .. } => 125,
        RunOutcome::Interrupted { signal, .. } => 128_i32.saturating_add(signal.signal),
        RunOutcome::Exited {
            child: _, cleanup, ..
        } if !cleanup.errors.is_empty()
            || !cleanup.direct_child_reaped
            || cleanup.workload_empty == Some(false) =>
        {
            125
        }
        RunOutcome::Exited { child, .. } => match child {
            ChildTermination::ExitCode { code } => *code,
            ChildTermination::UnixSignal { signal } => 128_i32.saturating_add(*signal),
            ChildTermination::WindowsStatus { status } => i32::try_from(*status).unwrap_or(125),
            ChildTermination::Unavailable => 125,
        },
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityStatusReport {
    pub supported: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemoryCapabilityReport {
    pub supported: bool,
    pub class: String,
    pub metric: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendCapabilityReport {
    pub name: String,
    pub containment: CapabilityStatusReport,
    pub memory: Option<MemoryCapabilityReport>,
    pub deadline: CapabilityStatusReport,
    pub restart: CapabilityStatusReport,
    pub deadline_scopes: Vec<crate::DeadlineScope>,
    pub deadline_origin: Option<String>,
    pub restart_conditions: crate::RestartConditions,
    pub persistent_restart_state: bool,
    pub startup_containment: String,
    pub restart_cleanup_condition: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionModelError {
    CounterRange,
    AttemptNumber,
    InconsistentExecution,
}

impl std::fmt::Display for SupervisionModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::CounterRange => "supervision counter is out of range",
            Self::AttemptNumber => "attempt numbers must be nonzero and strictly consecutive",
            Self::InconsistentExecution => {
                "supervision terminal, attempts, aggregates, or counters are inconsistent"
            }
        })
    }
}

impl std::error::Error for SupervisionModelError {}
