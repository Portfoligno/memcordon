use std::ffi::OsStr;
#[cfg(unix)]
use std::fs::File;
use std::io::Write;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::{
    AttemptRecord, BackendCapabilityReport, DETAILED_ATTEMPT_CAPACITY, DeadlineScope,
    DormantRestartCondition, Error, ErrorCategory, RestartConditions, RestartLimit, RestartSummary,
    SupervisionAggregates, SupervisionExecution, SupervisionPhase, SupervisionTerminal,
};

pub const EXECUTION_REPORT_SCHEMA_VERSION: u32 = 6;
pub const PLAN_REPORT_SCHEMA_VERSION: u32 = 5;
pub const DOCTOR_REPORT_SCHEMA_VERSION: u32 = 3;
pub const CLEAN_REPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize)]
pub struct MemcordonReport {
    pub schema_version: u32,
    pub tool: ToolReport,
    pub invocation: InvocationReport,
    pub policy: PolicyEnvelopeReport,
    pub backend: Option<BackendCapabilityReport>,
    pub supervision: Option<SupervisionReport>,
    pub attempts: Vec<AttemptRecord>,
    pub error: Option<ExecutionErrorReport>,
}

impl MemcordonReport {
    pub fn schema6(
        tool: ToolReport,
        invocation: InvocationReport,
        policy: PolicyEnvelopeReport,
        backend: Option<BackendCapabilityReport>,
        supervision: Option<SupervisionExecution>,
        error: Option<ExecutionErrorReport>,
    ) -> Result<Self, ReportModelError> {
        if supervision.is_some() == error.is_some() {
            return Err(ReportModelError::TerminalEnvelope);
        }
        invocation.validate()?;
        policy.validate(&invocation)?;
        validate_boundary_envelope(&policy, backend.as_ref())?;
        let (supervision, attempts) = supervision.map_or((None, Vec::new()), |execution| {
            let attempts = execution.attempts().records().cloned().collect();
            (
                Some(SupervisionReport::from_execution(&execution)),
                attempts,
            )
        });
        if let Some(summary) = &supervision {
            validate_attempt_history(summary, &attempts)?;
        }
        Ok(Self {
            schema_version: EXECUTION_REPORT_SCHEMA_VERSION,
            tool,
            invocation,
            policy,
            backend,
            supervision,
            attempts,
            error,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportModelError {
    SchemaVersion,
    TerminalEnvelope,
    AttemptHistory,
    InvocationBudgets,
    PolicyEnvelope,
}

impl std::fmt::Display for ReportModelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SchemaVersion => "unsupported report schema version",
            Self::TerminalEnvelope => "report must contain exactly one supervision result or error",
            Self::AttemptHistory => "report attempt history is inconsistent",
            Self::InvocationBudgets => "report budget tokens and normalized tokens disagree",
            Self::PolicyEnvelope => "requested and effective report policies disagree",
        })
    }
}
impl std::error::Error for ReportModelError {}

impl<'de> Deserialize<'de> for MemcordonReport {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            schema_version: u32,
            tool: ToolReport,
            invocation: InvocationReport,
            policy: PolicyEnvelopeReport,
            backend: Option<BackendCapabilityReport>,
            supervision: Option<SupervisionReport>,
            attempts: Vec<AttemptRecord>,
            error: Option<ExecutionErrorReport>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.schema_version != EXECUTION_REPORT_SCHEMA_VERSION {
            return Err(serde::de::Error::custom(ReportModelError::SchemaVersion));
        }
        if wire.supervision.is_some() == wire.error.is_some() {
            return Err(serde::de::Error::custom(ReportModelError::TerminalEnvelope));
        }
        if let Some(summary) = &wire.supervision {
            validate_attempt_history(summary, &wire.attempts).map_err(serde::de::Error::custom)?;
        } else if !wire.attempts.is_empty() {
            return Err(serde::de::Error::custom(ReportModelError::AttemptHistory));
        }
        wire.invocation
            .validate()
            .map_err(serde::de::Error::custom)?;
        wire.policy
            .validate(&wire.invocation)
            .map_err(serde::de::Error::custom)?;
        validate_boundary_envelope(&wire.policy, wire.backend.as_ref())
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            schema_version: wire.schema_version,
            tool: wire.tool,
            invocation: wire.invocation,
            policy: wire.policy,
            backend: wire.backend,
            supervision: wire.supervision,
            attempts: wire.attempts,
            error: wire.error,
        })
    }
}

fn validate_boundary_envelope(
    policy: &PolicyEnvelopeReport,
    backend: Option<&BackendCapabilityReport>,
) -> Result<(), ReportModelError> {
    let Some(backend) = backend else {
        return Ok(());
    };
    if !backend.boundary.is_consistent() {
        return Err(ReportModelError::PolicyEnvelope);
    }
    let expected = match policy.requested.boundary {
        crate::BoundaryRequirement::Standard => backend.boundary.class,
        crate::BoundaryRequirement::Sealed
            if backend.boundary.class == crate::BoundaryClass::Sealed =>
        {
            crate::BoundaryClass::Sealed
        }
        crate::BoundaryRequirement::Sealed => crate::BoundaryClass::Unavailable,
    };
    if policy.effective.boundary != expected {
        return Err(ReportModelError::PolicyEnvelope);
    }
    Ok(())
}

fn validate_attempt_history(
    summary: &SupervisionReport,
    attempts: &[AttemptRecord],
) -> Result<(), ReportModelError> {
    let retained = attempts.len();
    let total = summary.attempt_history.total;
    let aggregate_total = summary
        .aggregate
        .child_exits
        .checked_add(summary.aggregate.memory_limits)
        .and_then(|value| value.checked_add(summary.aggregate.deadlines))
        .and_then(|value| value.checked_add(summary.aggregate.interruptions))
        .and_then(|value| value.checked_add(summary.aggregate.monitor_failures))
        .and_then(|value| value.checked_add(summary.aggregate.setup_failures));
    if retained > DETAILED_ATTEMPT_CAPACITY
        || summary.attempt_history.retained != retained
        || summary.attempt_history.capacity != DETAILED_ATTEMPT_CAPACITY
        || summary.attempt_history.truncated != (summary.attempt_history.omitted != 0)
        || total != summary.attempt_records_created
        || aggregate_total != Some(total)
        || summary.targets_authorized > total
        || u64::try_from(retained)
            .ok()
            .and_then(|value| value.checked_add(summary.attempt_history.omitted))
            != Some(total)
        || !summary.restart.is_consistent(summary.targets_authorized)
        || summary.phase != SupervisionPhase::Completed
        || terminal_status(&summary.terminal) != summary.wrapper_exit_code
    {
        return Err(ReportModelError::AttemptHistory);
    }
    if total == 0 {
        if !attempts.is_empty() {
            return Err(ReportModelError::AttemptHistory);
        }
    } else {
        let Some(first) = attempts.first() else {
            return Err(ReportModelError::AttemptHistory);
        };
        if first.number != 1 {
            return Err(ReportModelError::AttemptHistory);
        }
        if retained > 1 {
            let tail_len =
                u64::try_from(retained - 1).map_err(|_| ReportModelError::AttemptHistory)?;
            let tail_start = total
                .checked_sub(tail_len)
                .and_then(|value| value.checked_add(1))
                .ok_or(ReportModelError::AttemptHistory)?;
            if attempts[1..].iter().enumerate().any(|(index, record)| {
                u64::try_from(index)
                    .ok()
                    .and_then(|offset| tail_start.checked_add(offset))
                    != Some(record.number)
            }) {
                return Err(ReportModelError::AttemptHistory);
            }
        } else if total != 1 {
            return Err(ReportModelError::AttemptHistory);
        }
    }
    let last = attempts.last();
    let terminal_matches = match &summary.terminal {
        SupervisionTerminal::AttemptOutcome {
            attempt_number,
            outcome,
        } => {
            *attempt_number == total
                && last.is_some_and(|record| {
                    record.number == *attempt_number && record.outcome.as_ref() == Some(outcome)
                })
        }
        SupervisionTerminal::DeadlineOutsideAttempt { .. } => true,
        SupervisionTerminal::Error {
            attempt_number: Some(attempt_number),
            error,
        } => {
            *attempt_number == total
                && last.is_some_and(|record| {
                    record.number == *attempt_number && record.error.as_ref() == Some(error)
                })
        }
        SupervisionTerminal::Error {
            attempt_number: None,
            ..
        } => true,
    };
    if !terminal_matches {
        return Err(ReportModelError::AttemptHistory);
    }
    Ok(())
}

fn terminal_status(terminal: &SupervisionTerminal) -> i32 {
    match terminal {
        SupervisionTerminal::AttemptOutcome { outcome, .. } => {
            crate::supervision::outcome_status(outcome)
        }
        SupervisionTerminal::DeadlineOutsideAttempt { .. } => 123,
        SupervisionTerminal::Error { error, .. } => error.terminal_status(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttemptHistoryReport {
    pub capacity: usize,
    pub retained: usize,
    pub total: u64,
    pub omitted: u64,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SupervisionReport {
    pub phase: SupervisionPhase,
    pub duration_ms: u64,
    pub attempt_records_created: u64,
    pub targets_authorized: u64,
    pub wrapper_exit_code: i32,
    pub terminal: SupervisionTerminal,
    pub attempt_history: AttemptHistoryReport,
    pub aggregate: SupervisionAggregates,
    pub restart: RestartSummary,
}

impl SupervisionReport {
    fn from_execution(execution: &SupervisionExecution) -> Self {
        Self {
            phase: execution.phase(),
            duration_ms: execution.duration_ms(),
            attempt_records_created: execution.attempts().total,
            targets_authorized: execution.targets_authorized(),
            wrapper_exit_code: execution.wrapper_exit_code(),
            terminal: execution.terminal().clone(),
            attempt_history: AttemptHistoryReport {
                capacity: DETAILED_ATTEMPT_CAPACITY,
                retained: execution.attempts().retained(),
                total: execution.attempts().total,
                omitted: execution.attempts().omitted,
                truncated: execution.attempts().omitted != 0,
            },
            aggregate: execution.aggregates().clone(),
            restart: execution.restart().clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ToolReport {
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BudgetTokenReport {
    pub kind: BudgetKindReport,
    pub token: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BudgetKindReport {
    Memory,
    Time,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvocationReport {
    pub syntax: String,
    pub budget_tokens: Vec<BudgetTokenReport>,
    pub memory_token: Option<String>,
    pub deadline_token: Option<String>,
    pub argv: Vec<NativeArgument>,
}

impl InvocationReport {
    fn validate(&self) -> Result<(), ReportModelError> {
        if self.syntax != "plus-budgets-v1" || self.budget_tokens.len() > 2 {
            return Err(ReportModelError::InvocationBudgets);
        }
        let memory: Vec<_> = self
            .budget_tokens
            .iter()
            .filter(|token| token.kind == BudgetKindReport::Memory)
            .collect();
        let deadline: Vec<_> = self
            .budget_tokens
            .iter()
            .filter(|token| token.kind == BudgetKindReport::Time)
            .collect();
        if memory.len() > 1
            || deadline.len() > 1
            || memory.first().map(|token| token.token.as_str()) != self.memory_token.as_deref()
            || deadline.first().map(|token| token.token.as_str()) != self.deadline_token.as_deref()
        {
            return Err(ReportModelError::InvocationBudgets);
        }
        Ok(())
    }
}

impl PolicyEnvelopeReport {
    fn validate(&self, invocation: &InvocationReport) -> Result<(), ReportModelError> {
        if self.requested.memory.is_some() != invocation.memory_token.is_some()
            || self.requested.deadline.is_some() != invocation.deadline_token.is_some()
            || self.requested.restart.enabled != self.effective.restart.enabled
            || (!self.requested.restart.enabled
                && (self.requested.restart.backoff.is_some()
                    || self.requested.restart.circuit_breaker.is_some()
                    || !self.requested.restart.configured_conditions.is_empty()
                    || !self.effective.restart.conditions.is_empty()))
            || (self
                .effective
                .restart
                .conditions
                .contains(crate::RestartCondition::MemoryLimit)
                && self.requested.memory.is_none())
            || (self
                .effective
                .restart
                .conditions
                .contains(crate::RestartCondition::Deadline)
                && self.requested.deadline.is_none())
        {
            return Err(ReportModelError::PolicyEnvelope);
        }
        for condition in [
            crate::RestartCondition::MemoryLimit,
            crate::RestartCondition::Deadline,
        ] {
            if self.effective.restart.conditions.contains(condition)
                && !self
                    .requested
                    .restart
                    .configured_conditions
                    .contains(condition)
            {
                return Err(ReportModelError::PolicyEnvelope);
            }
            let expected_dormant = self
                .requested
                .restart
                .configured_conditions
                .contains(condition)
                && !self.effective.restart.conditions.contains(condition);
            let matches = self
                .effective
                .restart
                .dormant_conditions
                .iter()
                .filter(|dormant| dormant.condition == condition)
                .count();
            if matches != usize::from(expected_dormant)
                || self
                    .effective
                    .restart
                    .dormant_conditions
                    .iter()
                    .any(|dormant| dormant.reason.is_empty())
            {
                return Err(ReportModelError::PolicyEnvelope);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeArgument {
    pub display: String,
    pub raw: Option<NativeArgumentRaw>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeArgumentRaw {
    pub encoding: String,
    pub data: String,
}

impl NativeArgument {
    pub fn from_os(value: &OsStr) -> Self {
        let display = value.to_string_lossy().into_owned();
        if let Some(text) = value.to_str() {
            return Self {
                display: text.to_owned(),
                raw: None,
            };
        }
        #[cfg(unix)]
        let raw = {
            use std::os::unix::ffi::OsStrExt;
            NativeArgumentRaw {
                encoding: "unix-bytes-base64".to_owned(),
                data: STANDARD.encode(value.as_bytes()),
            }
        };
        #[cfg(windows)]
        let raw = {
            use std::os::windows::ffi::OsStrExt;
            let bytes: Vec<u8> = value.encode_wide().flat_map(u16::to_le_bytes).collect();
            NativeArgumentRaw {
                encoding: "windows-u16le-base64".to_owned(),
                data: STANDARD.encode(bytes),
            }
        };
        #[cfg(not(any(unix, windows)))]
        let raw = NativeArgumentRaw {
            encoding: "unsupported-platform-native-encoding-unavailable".to_owned(),
            data: String::new(),
        };
        Self {
            display,
            raw: Some(raw),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyEnvelopeReport {
    pub requested: RequestedPolicyReport,
    pub effective: EffectivePolicyReport,
    pub effects: Vec<OptionEffectReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestedPolicyReport {
    pub boundary: crate::BoundaryRequirement,
    pub memory: Option<RequestedMemoryPolicyReport>,
    pub deadline: Option<DeadlinePolicyReport>,
    pub wait_for: String,
    pub signal_grace_ms: u64,
    pub command_exit_grace_ms: u64,
    pub limit_grace_ms: u64,
    pub restart: RequestedRestartPolicyReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestedMemoryPolicyReport {
    pub limit_bytes: u64,
    pub enforcement: String,
    pub metric: String,
    pub poll_interval_ms: u64,
    pub swap: SwapReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeadlinePolicyReport {
    pub duration_ms: u64,
    pub scope: DeadlineScope,
    pub origin: Option<String>,
    pub clock: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestedRestartPolicyReport {
    pub enabled: bool,
    pub enablement_source: Option<String>,
    pub configured_conditions: RestartConditions,
    pub limit: RestartLimit,
    pub backoff: Option<BackoffPolicyReport>,
    pub circuit_breaker: Option<CircuitBreakerPolicyReport>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackoffPolicyReport {
    pub model: String,
    pub base_interval_ms: u64,
    pub multiplier_numerator: u32,
    pub multiplier_denominator: u32,
    pub asymptote_interval_ms: u64,
    pub recovery_half_life_ms: u64,
    pub quantization: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CircuitBreakerPolicyReport {
    pub threshold: f64,
    pub half_life_ms: u64,
    pub cooldown_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectivePolicyReport {
    pub boundary: crate::BoundaryClass,
    pub memory: Option<EffectiveMemoryPolicyReport>,
    pub deadline: Option<DeadlinePolicyReport>,
    pub wait_for: String,
    pub signal_grace_ms: u64,
    pub command_exit_grace_ms: u64,
    pub limit_grace_ms: u64,
    pub restart: EffectiveRestartPolicyReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectiveMemoryPolicyReport {
    pub limit_bytes: u64,
    pub enforcement: String,
    pub metric: String,
    pub poll_interval_ms: Option<u64>,
    pub swap: Option<SwapReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EffectiveRestartPolicyReport {
    pub enabled: bool,
    pub conditions: RestartConditions,
    pub dormant_conditions: Vec<DormantRestartCondition>,
    pub cleanup_proof_required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum SwapReport {
    Bytes { bytes: u64 },
    Unlimited,
    Host,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum OptionEffectReport {
    Applied {
        option: String,
    },
    Adjusted {
        option: String,
        requested: String,
        effective: String,
        reason: String,
    },
    Ignored {
        option: String,
        requested: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExecutionErrorReport {
    pub category: String,
    pub code: String,
    pub message: String,
    pub os_code: Option<i32>,
    pub attempt_number: Option<u64>,
    pub supervision_phase: Option<String>,
    pub launch_phase: Option<String>,
    pub target_released: bool,
    pub workload_may_be_alive: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanReport {
    pub schema_version: u32,
    pub tool: ToolReport,
    pub budget_tokens: Vec<BudgetTokenReport>,
    pub request: RequestedPolicyReport,
    pub resolution: PlanResolutionReport,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PlanResolutionReport {
    pub backend: BackendCapabilityReport,
    pub effective: EffectivePolicyReport,
    pub effects: Vec<OptionEffectReport>,
    pub limitations: Vec<String>,
    pub launch_proof: bool,
    pub backoff_sample_ms: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub tool: ToolReport,
    pub host: HostReport,
    pub selected: Option<BackendCapabilityReport>,
    pub available: Vec<BackendCapabilityReport>,
    pub unavailable: Vec<UnavailableCapabilityReport>,
    pub requirement: RequirementReport,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostReport {
    pub os: String,
    pub architecture: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UnavailableCapabilityReport {
    pub name: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RequirementReport {
    pub kind: Option<String>,
    pub met: bool,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CleanReport {
    pub schema_version: u32,
    pub dry_run: bool,
    pub cleaned: Vec<String>,
}

#[allow(clippy::result_large_err)]
pub fn write_report_atomic(path: &Path, report: &MemcordonReport) -> Result<(), Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let result = (|| -> Result<(), std::io::Error> {
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer_pretty(temporary.as_file_mut(), report)?;
        temporary.write_all(b"\n")?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary.persist(path).map_err(|error| error.error)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    result.map_err(|error| report_error(path, error))
}

fn report_error(path: &Path, error: std::io::Error) -> Error {
    Error::new(
        ErrorCategory::Report,
        "MCREPORT-WRITE",
        format!("could not write report {}: {error}", path.display()),
    )
    .with_os_error(&error)
}
