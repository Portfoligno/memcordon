#![forbid(unsafe_code)]

mod error;
mod outcome;
mod policy;
mod report;
mod restart;
mod state_machine;
mod supervision;
#[cfg(feature = "test-support")]
pub mod test_support;

pub use error::{Error, ErrorCategory, InitialSpawnFailure};
pub use outcome::{
    AttemptEventKind, ChildTermination, CleanupErrorRecord, CleanupSummary, DeadlineEvidence,
    Interruption, LimitEvidence, RunOutcome,
};
pub use policy::{
    ByteSize, ByteSizeParseError, CommandSpec, DeadlinePolicyError, Enforcement, Lifetime, Metric,
    Policy, SwapPolicy,
};
pub use policy::{DeadlinePolicy, DeadlineScope};
pub use report::{
    AttemptHistoryReport, BackoffPolicyReport, BudgetKindReport, BudgetTokenReport,
    CLEAN_REPORT_SCHEMA_VERSION, CircuitBreakerPolicyReport, CleanReport,
    DOCTOR_REPORT_SCHEMA_VERSION, DeadlinePolicyReport, DoctorReport,
    EXECUTION_REPORT_SCHEMA_VERSION, EffectiveMemoryPolicyReport, EffectivePolicyReport,
    EffectiveRestartPolicyReport, ExecutionErrorReport, HostReport, InvocationReport,
    MemcordonReport, NativeArgument, NativeArgumentRaw, OptionEffectReport,
    PLAN_REPORT_SCHEMA_VERSION, PlanReport, PlanResolutionReport, PolicyEnvelopeReport,
    ReportModelError, RequestedMemoryPolicyReport, RequestedPolicyReport,
    RequestedRestartPolicyReport, RequirementReport, SupervisionReport, SwapReport, ToolReport,
    UnavailableCapabilityReport, write_report_atomic,
};
pub use restart::{
    BackoffMultiplier, CircuitBreakerPolicy, CircuitState, DormantRestartCondition, LOGISTIC_MODEL,
    LogisticBackoffPolicy, RestartAction, RestartCondition, RestartConditions,
    RestartControllerError, RestartCoordinator, RestartLimit, RestartPolicy, RestartSettings,
    RestartWaitKind, WaitCompletion,
};
pub use state_machine::{RunState, StateMachine, StateTransitionError};
pub use supervision::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    CapabilityStatusReport, DETAILED_ATTEMPT_CAPACITY, LaunchEvidence, MemoryCapabilityReport,
    RestartDecisionKind, RestartDecisionRecord, RestartSafetyProof, RestartSummary,
    SupervisionAggregates, SupervisionDeadlineEvidence, SupervisionErrorRecord,
    SupervisionExecution, SupervisionModelError, SupervisionPhase, SupervisionTerminal,
};
