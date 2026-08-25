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
mod windows_sealed;

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
pub use windows_sealed::{
    NativeWindowsCommandV1, WINDOWS_CONTROL_PIPE, WINDOWS_CONTROL_SERVICE_NAME,
    WINDOWS_LAUNCHER_PIPE, WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_MAX_FRAME_BYTES,
    WINDOWS_MAX_JOB_PROCESS_IDENTITIES, WINDOWS_PREAUTHORIZATION_FAULTS,
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_PUBLIC_PROTOCOL_VERSION,
    WINDOWS_QUALIFICATION_SCHEMA_VERSION, WINDOWS_RELEASE_MUTANT_VARIANTS, WINDOWS_RELEASE_MUTANTS,
    WINDOWS_RETIREMENT_FAULTS, WindowsAttemptStateV1, WindowsAuthorityLossEvidenceV1,
    WindowsCallerTokenEnvelopeV1, WindowsCertificationObservationsV1, WindowsCertificationPhaseV1,
    WindowsCleanupProcessCreationEvidenceV1, WindowsDurableAttemptRecordV1,
    WindowsDurableCleanupStateV1, WindowsEnvironmentEntryV1, WindowsFaultRejectionObservationV1,
    WindowsLaunchBrokerRequestV1, WindowsLaunchPolicyV1, WindowsLaunchRequestV1,
    WindowsLauncherRequestV1, WindowsLauncherResponseV1, WindowsLifetimeV1,
    WindowsMutantHookObservationV1, WindowsMutantKillEvidenceV1, WindowsMutantNativeObservationV1,
    WindowsMutantNativeReceiptV1, WindowsMutantObservationV1,
    WindowsPreauthorizationFaultMatrixEvidenceV1, WindowsProcessIdentityV1,
    WindowsProviderRequestV1, WindowsProviderResponseV1, WindowsQualificationReceiptV1,
    WindowsRemoteStreamV1, WindowsRetirementFaultMatrixEvidenceV1, WindowsSealedFault,
    WindowsSealedMutant, WindowsStreamRoleV1, WindowsTerminalReceiptV1,
    WindowsTokenMatrixEvidenceV1, WindowsTokenScenarioEvidenceV1, decode_windows_command_line,
    encode_windows_command_line, encode_windows_environment_block,
    parse_and_authenticate_windows_attempt_record, validate_windows_security_descriptor_text,
    validate_windows_stream_manifest, windows_attempt_transition_allowed,
    windows_certification_transition_allowed,
};
