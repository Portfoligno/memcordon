//! Platform-neutral supervision policy and evidence models.
//!
//! [`BoundaryRequirement::Sealed`] requests a certified process-supervision
//! boundary and never permits fallback to standard supervision. Capability,
//! launch, and cleanup facts remain distinct so consumers can validate the
//! contract without selecting a platform mechanism.

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

pub use error::{
    BoundarySetupFailure, BoundarySetupPhase, Error, ErrorCategory, InitialSpawnFailure,
    ProviderRejectionEvidence,
};
pub use outcome::{
    AttemptEventKind, ChildTermination, CleanupErrorRecord, CleanupSummary, DeadlineEvidence,
    Interruption, LimitEvidence, RunOutcome,
};
pub use policy::{
    BoundaryRequirement, ByteSize, ByteSizeParseError, CommandSpec, DeadlinePolicyError,
    Enforcement, Lifetime, Metric, Policy, SwapPolicy,
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
    BackoffMultiplier, CircuitBreakerPolicy, CircuitState, DormantRestartCondition,
    HALF_LIFE_LOGISTIC_MODEL, HalfLifeLogisticBackoffPolicy, HalfLifeLogisticBackoffState,
    RestartAction, RestartCondition, RestartConditions, RestartControllerError, RestartCoordinator,
    RestartLimit, RestartPolicy, RestartSettings, RestartWaitKind, WaitCompletion,
    half_life_logistic_next_millis,
};
pub use state_machine::{RunState, StateMachine, StateTransitionError};
pub use supervision::{
    AttemptHistory, AttemptKind, AttemptPhase, AttemptRecord, BackendCapabilityReport,
    BoundaryCapability, BoundaryClass, BoundaryMechanismEvidence, BoundaryQualificationReport,
    CapabilityStatusReport, CredentialTransitionDisposition, DETAILED_ATTEMPT_CAPACITY,
    LaunchEvidence, LinuxSealedEvidenceV2, MacosSealedEvidence, MemoryCapabilityReport,
    RestartDecisionKind, RestartDecisionRecord, RestartSafetyProof, RestartSummary,
    SealedUnavailableReport, SupervisionAggregates, SupervisionDeadlineEvidence,
    SupervisionErrorRecord, SupervisionExecution, SupervisionModelError, SupervisionPhase,
    SupervisionTerminal, WindowsSealedEvidenceV2, boundary_evidence_is_consistent,
};
