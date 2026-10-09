use super::scenario::{ExpectedExit, ObservedLifecycle, ScenarioSpec};
use serde::{Deserialize, Serialize};

const SUPPORTED_EXECUTION_SCHEMA: u32 = 10;
#[derive(Debug, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum ReleaseEvidence {
    NotIssued {},
    Issued { at: u64, exec_confirmed: bool },
    Unknown {},
}
#[derive(Debug, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum RetirementEvidence {
    Complete {
        at: u64,
        target_reaped_or_absent: bool,
        group_reconciled: bool,
        detached_identities_discharged: bool,
        native_obligations_settled: bool,
        policy_retired: bool,
    },
    Pending,
    Unconfirmed,
}
#[derive(Debug, Deserialize)]
struct RuntimeEvidence {
    schema_version: u32,
    release: ReleaseEvidence,
    target_pid: Option<i32>,
    retirement: RetirementEvidence,
}
#[derive(Debug, Deserialize)]
struct InvocationEvidence {
    deadline_token: Option<String>,
}
#[derive(Debug, Deserialize)]
struct AppliedDeadlineEvidence {
    duration_ms: u64,
    scope: String,
    origin: String,
}
#[derive(Debug, Deserialize)]
struct EffectivePolicyEvidence {
    deadline: AppliedDeadlineEvidence,
}
#[derive(Debug, Deserialize)]
struct PolicyEvidence {
    effective: EffectivePolicyEvidence,
}
#[derive(Debug, Deserialize)]
struct SupervisionEvidence {
    phase: String,
    wrapper_exit_code: i32,
    targets_authorized: u64,
    attempt_records_created: u64,
}
#[derive(Debug, Deserialize)]
struct LaunchEvidence {
    target_released: bool,
    guardian_started_before_authorization: bool,
    target_spawn_error_reported: bool,
}
#[derive(Debug, Deserialize)]
struct RestartSafetyEvidence {
    direct_child_reaped: bool,
    helpers_reaped: bool,
    workload_empty: Option<bool>,
    errors: Vec<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
struct CleanupEvidence {
    direct_child_reaped: bool,
    workload_empty: Option<bool>,
    errors: Vec<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
struct DeadlineEvidence {
    duration_ms: u64,
    origin: String,
    scope: String,
    expires_offset_ms: u64,
    observed_offset_ms: u64,
    overshoot_ms: u64,
}
#[derive(Debug, Deserialize)]
struct OutcomeEvidence {
    outcome: String,
    cleanup: CleanupEvidence,
    deadline: DeadlineEvidence,
}
#[derive(Debug, Deserialize)]
struct AttemptEvidence {
    phase: String,
    target_pid: Option<i32>,
    authorized_offset_ms: Option<u64>,
    runtime: RuntimeEvidence,
    outcome: OutcomeEvidence,
    launch: LaunchEvidence,
    restart_safety: RestartSafetyEvidence,
    error: Option<serde_json::Value>,
}
#[derive(Debug, Deserialize)]
struct ExecutionReport {
    schema_version: u32,
    invocation: InvocationEvidence,
    policy: PolicyEvidence,
    supervision: SupervisionEvidence,
    attempts: Vec<AttemptEvidence>,
    error: Option<serde_json::Value>,
}
#[derive(Debug, Serialize)]
pub(super) struct ReportProof {
    pub(super) lifecycle: ObservedLifecycle,
    pub(super) target_pid: Option<i32>,
    pub(super) authorized_offset_milliseconds: Option<u64>,
    pub(super) deadline_overshoot_milliseconds: u64,
    pub(super) production_retirement_complete: bool,
    pub(super) production_workload_empty: bool,
}
fn ensure(condition: bool, detail: &str) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(detail.into())
    }
}
pub(super) fn classify_report(bytes: &[u8], spec: ScenarioSpec) -> Result<ReportProof, String> {
    let report: ExecutionReport = serde_json::from_slice(bytes)
        .map_err(|error| error.to_string().chars().take(512).collect::<String>())?;
    ensure(
        report.schema_version == SUPPORTED_EXECUTION_SCHEMA,
        "unsupported execution report schema",
    )?;
    ensure(report.error.is_none(), "execution report has an error")?;
    ensure(
        report.attempts.len() == 1 && report.supervision.attempt_records_created == 1,
        "expected exactly one attempt",
    )?;
    ensure(
        report.supervision.phase == "completed",
        "supervision is not completed",
    )?;
    ensure(
        matches!(spec.expected_exit, ExpectedExit::Code(_))
            && report.supervision.wrapper_exit_code == 123,
        "reported supervision exit is not the deadline result",
    )?;
    ensure(
        report.invocation.deadline_token.as_deref() == spec.budget.token(),
        "report work budget differs from scenario",
    )?;
    let applied_deadline = &report.policy.effective.deadline;
    ensure(
        applied_deadline.origin == "before-helper-setup" && applied_deadline.scope == "attempt",
        "effective deadline does not begin before helper setup",
    )?;
    let attempt = &report.attempts[0];
    ensure(
        attempt.phase == "completed" && attempt.error.is_none(),
        "attempt incomplete or has an error",
    )?;
    ensure(
        attempt.runtime.schema_version == 1,
        "unsupported runtime evidence schema",
    )?;
    ensure(
        attempt.outcome.outcome == "deadline-exceeded",
        "terminal outcome is not deadline-exceeded",
    )?;
    ensure(
        attempt.outcome.cleanup.errors.is_empty() && attempt.restart_safety.errors.is_empty(),
        "production cleanup has errors",
    )?;
    ensure(
        attempt.outcome.cleanup.direct_child_reaped
            && attempt.restart_safety.direct_child_reaped
            && attempt.restart_safety.helpers_reaped,
        "production reaping incomplete",
    )?;
    ensure(
        attempt.outcome.cleanup.workload_empty == Some(true)
            && attempt.restart_safety.workload_empty == Some(true),
        "production workload not empty",
    )?;
    let retirement_at = match attempt.runtime.retirement {
        RetirementEvidence::Complete {
            at,
            target_reaped_or_absent: true,
            group_reconciled: true,
            detached_identities_discharged: true,
            native_obligations_settled: true,
            policy_retired: true,
        } => at,
        _ => return Err("production retirement incomplete".into()),
    };
    let deadline = &attempt.outcome.deadline;
    ensure(
        deadline.origin == "pre-spawn" && deadline.scope == "attempt",
        "deadline does not begin before target startup",
    )?;
    ensure(
        deadline
            .observed_offset_ms
            .checked_sub(deadline.expires_offset_ms)
            == Some(deadline.overshoot_ms),
        "deadline overshoot contradicts offsets",
    )?;
    if let Some(budget) = spec.budget.duration() {
        ensure(
            u128::from(deadline.duration_ms) == budget.as_millis()
                && deadline.expires_offset_ms >= deadline.duration_ms,
            "deadline duration differs from work budget",
        )?;
    }
    ensure(
        applied_deadline.duration_ms == deadline.duration_ms,
        "effective and terminal deadlines differ",
    )?;
    ensure(
        attempt
            .authorized_offset_ms
            .is_none_or(|offset| offset <= deadline.observed_offset_ms),
        "authorization follows terminal deadline observation",
    )?;
    let lifecycle = match attempt.runtime.release {
        ReleaseEvidence::NotIssued {} => {
            ensure(
                report.supervision.targets_authorized == 0
                    && attempt.authorized_offset_ms.is_none()
                    && attempt.target_pid.is_none()
                    && attempt.runtime.target_pid.is_none()
                    && !attempt.launch.target_released
                    && !attempt.launch.guardian_started_before_authorization
                    && !attempt.launch.target_spawn_error_reported,
                "contradictory pre-authorization evidence",
            )?;
            ObservedLifecycle::PreAuthorizationExpired
        }
        ReleaseEvidence::Issued {
            at,
            exec_confirmed: true,
        } => {
            ensure(
                retirement_at >= at
                    && report.supervision.targets_authorized == 1
                    && attempt.authorized_offset_ms.is_some()
                    && attempt.target_pid.is_some_and(|pid| pid > 0)
                    && attempt.target_pid == attempt.runtime.target_pid
                    && attempt.launch.target_released
                    && attempt.launch.guardian_started_before_authorization
                    && !attempt.launch.target_spawn_error_reported,
                "contradictory authorized evidence",
            )?;
            ObservedLifecycle::AuthorizedExpired
        }
        _ => return Err("release is unknown or execution is not confirmed".into()),
    };
    Ok(ReportProof {
        lifecycle,
        target_pid: attempt.target_pid,
        authorized_offset_milliseconds: attempt.authorized_offset_ms,
        deadline_overshoot_milliseconds: deadline.overshoot_ms,
        production_retirement_complete: true,
        production_workload_empty: true,
    })
}
