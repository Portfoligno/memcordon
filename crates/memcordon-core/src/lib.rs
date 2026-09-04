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
mod windows_pe;
mod windows_sealed;

pub use error::{
    BoundarySetupFailure, BoundarySetupPhase, Error, ErrorCategory, InitialSpawnFailure,
    PROVIDER_REJECTION_MAX_DETAIL_BYTES, ProviderRejectionEvidence,
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
    SupervisionTerminal, WindowsLoaderCleanupOutcomeV1, WindowsLoaderCleanupStatusV1,
    WindowsLoaderNativeStatusV1, WindowsLoaderQualificationFailureV2,
    WindowsLoaderQualificationOutcomeV2, WindowsLoaderQualificationStageV2,
    WindowsLoaderReadyEvidenceV1, WindowsSealedEvidenceV2, boundary_evidence_is_consistent,
};
pub use windows_pe::{
    WINDOWS_PE_MACHINE_AMD64, WINDOWS_PE_MACHINE_ARM64, WindowsPeExport, WindowsPeExportTarget,
    WindowsPeImportDescriptor, WindowsPeImportSymbol, WindowsPeImports, WindowsPeLoaderContract,
    parse_windows_pe_imports, parse_windows_pe_loader_contract,
    parse_windows_pe_mapped_loader_contract, verify_session_broker_pe,
    verify_target_desktop_bootstrap_pe,
};
pub use windows_sealed::{
    NativeWindowsCommandV1, WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT, WINDOWS_CONTROL_PIPE,
    WINDOWS_CONTROL_SERVICE_NAME, WINDOWS_GUARDIAN_PIPE_PREFIX, WINDOWS_GUARDIAN_SERVICE_PREFIX,
    WINDOWS_GUARDIAN_SLOT_COUNT, WINDOWS_LAUNCHER_PIPE, WINDOWS_LAUNCHER_SERVICE_NAME,
    WINDOWS_MAX_FRAME_BYTES, WINDOWS_MAX_JOB_PROCESS_IDENTITIES,
    WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS, WINDOWS_PREAUTHORIZATION_FAULTS,
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_PUBLIC_PROTOCOL_VERSION,
    WINDOWS_QUALIFICATION_SCHEMA_VERSION, WINDOWS_RELEASE_MUTANT_VARIANTS, WINDOWS_RELEASE_MUTANTS,
    WINDOWS_RETIREMENT_FAULTS, WINDOWS_SESSION_BROKER_PIPE, WINDOWS_SESSION_BROKER_SERVICE_NAME,
    WindowsAttemptRetainedV1, WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1,
    WindowsAuthorityLossEvidenceV1, WindowsCallerTokenEnvelopeV1,
    WindowsCertificationObservationsV1, WindowsCertificationPhaseV1,
    WindowsCleanupProcessCreationEvidenceV1, WindowsControlRequestStatusV1,
    WindowsDurableAttemptRecordV1, WindowsDurableCleanupStateV1, WindowsEnvironmentEntryV1,
    WindowsFaultRejectionObservationV1, WindowsLaunchBrokerRequestV1, WindowsLaunchPolicyV1,
    WindowsLaunchRequestV1, WindowsLauncherRequestV1, WindowsLauncherResponseV1, WindowsLifetimeV1,
    WindowsMutantHookObservationV1, WindowsMutantKillEvidenceV1, WindowsMutantNativeObservationV1,
    WindowsMutantNativeReceiptV1, WindowsMutantObservationV1,
    WindowsPreauthorizationFaultMatrixEvidenceV1, WindowsProcessIdentityV1,
    WindowsProviderRequestV1, WindowsProviderResponseV1, WindowsPublicFrameFailureV1,
    WindowsPublicFramePhaseV1, WindowsPublicTerminalRecoveryV1, WindowsQualificationReceiptV1,
    WindowsRelayEventV1, WindowsRelayPhaseV1, WindowsRemoteStreamV1, WindowsReplayOutboxStageV1,
    WindowsReplayPendingV1, WindowsRetirementFaultMatrixEvidenceV1, WindowsSealedFault,
    WindowsSealedMutant, WindowsServiceSelfAttestationV1, WindowsStreamRoleV1,
    WindowsTerminalReceiptV1, WindowsTerminalReplayDecisionV1, WindowsTerminalRetiredV1,
    WindowsTerminalizationCheckpointV1, WindowsTerminalizationErrorStageV1,
    WindowsTerminalizationErrorV1, WindowsTerminalizationOwnerV1, WindowsTerminalizationStatusV1,
    WindowsTokenMatrixEvidenceV1, WindowsTokenScenarioEvidenceV1, decode_windows_command_line,
    encode_windows_command_line, encode_windows_environment_block,
    parse_and_authenticate_windows_attempt_record,
    parse_windows_certification_frontend_handle_values, validate_windows_security_descriptor_text,
    validate_windows_stream_manifest, windows_attempt_transition_allowed,
    windows_certification_argument_prelude_len, windows_certification_transition_allowed,
    windows_service_attestation_challenge_is_valid, windows_terminal_outbox_is_bound,
};
