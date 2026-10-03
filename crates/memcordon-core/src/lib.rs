//! Platform-neutral supervision policy and evidence models.
//!
//! [`BoundaryRequirement::Sealed`] requests a certified process-supervision
//! boundary and never permits fallback to standard supervision. Capability,
//! launch, and cleanup facts remain distinct so consumers can validate the
//! contract without selecting a platform mechanism.

#![forbid(unsafe_code)]

pub mod canonical_json;
pub mod diagnostics;
pub mod historical_public_reports;
pub mod historical_workload_evidence;
pub use historical_public_reports::{HistoricalDoctorReport, HistoricalPlanReport};
pub mod product_fixture;
pub mod provider_rejection_wire;
pub mod runtime_evidence;
pub mod runtime_manifest;
pub mod runtime_readiness;
pub use runtime_evidence::*;
pub mod report_v11;
pub mod result_v1;
pub use result_v1::{ReportFormat, ResultReport, ResultV1};
pub mod private_runtime;
pub mod workload_admission_v2;
pub mod workload_codec;
pub mod workload_contract;
pub mod workload_discovery;
pub mod workload_discovery_v2;
pub mod workload_evidence;
pub mod workload_evidence_v2;
pub mod workload_limits;
pub mod workload_registry;
pub mod workload_registry_v2;
pub use diagnostics::*;
mod error;
mod outcome;
mod policy;
mod report;
mod restart;
mod state_machine;
mod supervision;
#[cfg(feature = "test-support")]
pub mod test_support;
mod windows_capability_owner;
mod windows_guardian_receipt;
mod windows_pe;
mod windows_process_observation;
mod windows_recovery_authorization;
mod windows_sealed;

pub use error::{
    BoundarySetupFailure, BoundarySetupPhase, Error, ErrorCategory, InitialSpawnFailure,
    NativeHelperIdentityV1, NativeStartupCleanupErrorV1, NativeStartupCleanupStateV1,
    NativeStartupCleanupV1, NativeStartupDiagnosticV1, NativeStartupOperationV1,
    NativeStartupPhaseV1, OperationalAttemptFailure, PROVIDER_REJECTION_MAX_DETAIL_BYTES,
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
    EffectiveRestartPolicyReport, ExecutionErrorReport, HistoricalMemcordonReport, HostReport,
    InvocationReport, MemcordonReport, NativeArgument, NativeArgumentRaw, OptionEffectReport,
    PLAN_REPORT_SCHEMA_VERSION, PlanReport, PlanResolutionReport, PolicyEnvelopeReport,
    ReportModelError, ReportWritePhase, RequestedMemoryPolicyReport, RequestedPolicyReport,
    RequestedRestartPolicyReport, RequirementReport, SupervisionReport, SwapReport, ToolReport,
    UnavailableCapabilityReport, WINDOWS_EXECUTION_REPORT_SCHEMA_V11,
    WindowsTerminalDeliveryEvidenceV1, write_report_atomic, write_report_bytes_atomic,
};
#[cfg(feature = "test-support")]
pub use report::{
    write_report_atomic_with_test_barrier, write_report_atomic_with_test_observer,
    write_report_bytes_atomic_with_test_observer,
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
    BackendSelectionDriftEvidence, BoundaryCapability, BoundaryClass, BoundaryMechanismEvidence,
    BoundaryQualificationReport, CapabilityStatusReport, CredentialTransitionDisposition,
    DETAILED_ATTEMPT_CAPACITY, LaunchEvidence, LinuxSealedEvidenceV2, MacosSealedEvidence,
    MemoryCapabilityReport, RestartDecisionKind, RestartDecisionRecord, RestartSafetyProof,
    RestartSummary, SealedUnavailableReport, SupervisionAggregates, SupervisionDeadlineEvidence,
    SupervisionErrorRecord, SupervisionExecution, SupervisionModelError, SupervisionPhase,
    SupervisionTerminal, WindowsLoaderCleanupOutcomeV1, WindowsLoaderCleanupStatusV1,
    WindowsLoaderNativeStatusV1, WindowsLoaderQualificationFailureV2,
    WindowsLoaderQualificationOutcomeV2, WindowsLoaderQualificationStageV2,
    WindowsLoaderReadyEvidenceV1, WindowsSealedEvidenceV2, boundary_evidence_is_consistent,
};
pub use windows_capability_owner::{
    WINDOWS_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION, WINDOWS_CAPABILITY_OWNER_ROLE_COUNT,
    WindowsCapabilityOwnerEntryV1, WindowsCapabilityOwnerManifestV1, WindowsCapabilityOwnerRoleV1,
};
pub use windows_guardian_receipt::{WindowsGuardianReceiptBinding, WindowsGuardianReceiptV2};
pub use windows_pe::{
    WINDOWS_PE_MACHINE_AMD64, WINDOWS_PE_MACHINE_ARM64, WindowsPeExport, WindowsPeExportTarget,
    WindowsPeImportDescriptor, WindowsPeImportSymbol, WindowsPeImports, WindowsPeLoaderContract,
    parse_windows_pe_imports, parse_windows_pe_loader_contract,
    parse_windows_pe_mapped_loader_contract, verify_session_broker_pe,
    verify_target_desktop_bootstrap_imports, verify_target_desktop_bootstrap_pe,
};
pub use windows_process_observation::{
    BoundedProcessIdentitySample, ProcessObservationCountersV1, ProcessObservationCoverageV1,
    ProcessObservationOmissionsV1, ProcessObservationPolicyV1,
    ProcessObservationUnavailableReasonV1, ProcessObserver, ProcessSampleEntryV1,
    WINDOWS_PROCESS_IDENTITY_QUERIES_PER_TICK, WINDOWS_PROCESS_OBSERVATION_SCHEMA_VERSION,
    WINDOWS_PROCESS_OBSERVATION_WIRE_BYTES, WINDOWS_PROCESS_SAMPLE_INTERVAL_MILLIS,
    WINDOWS_PROCESS_SAMPLE_STORAGE_BYTES, WINDOWS_PROCESS_SNAPSHOT_QUERIES_PER_TICK,
    WINDOWS_PROCESS_SNAPSHOT_STORAGE_BYTES, WindowsJobAccountingObservationV1,
    WindowsProcessObservationV2, WindowsQualificationMembershipWitnessV1,
    WindowsQualificationWitnessRoleV1,
};
pub use windows_recovery_authorization::{
    WindowsRecoveryAccessFloorV1, WindowsRecoveryAuthorizationV1, WindowsRecoveryCallerEvidenceV1,
    WindowsRecoveryPolicyV1,
};
pub use windows_sealed::{
    NativeWindowsCommandV1, WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT, WINDOWS_CONTROL_PIPE,
    WINDOWS_CONTROL_REQUIRED_PRIVILEGES, WINDOWS_CONTROL_SERVICE_NAME,
    WINDOWS_GUARDIAN_PIPE_PREFIX, WINDOWS_GUARDIAN_SERVICE_PREFIX, WINDOWS_GUARDIAN_SLOT_COUNT,
    WINDOWS_LAUNCHER_PIPE, WINDOWS_LAUNCHER_REQUIRED_PRIVILEGES, WINDOWS_LAUNCHER_SERVICE_NAME,
    WINDOWS_MAX_FRAME_BYTES, WINDOWS_MAX_JOB_PROCESS_IDENTITIES,
    WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS, WINDOWS_PREAUTHORIZATION_FAULTS,
    WINDOWS_PRIVATE_PROTOCOL_VERSION, WINDOWS_PUBLIC_PROTOCOL_VERSION,
    WINDOWS_RELEASE_MUTANT_VARIANTS, WINDOWS_RELEASE_MUTANTS, WINDOWS_RETIREMENT_FAULTS,
    WINDOWS_SESSION_BROKER_PIPE, WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES,
    WINDOWS_SESSION_BROKER_SERVICE_NAME, WindowsAttemptRetainedV1, WindowsAttemptRetainedV2,
    WindowsAttemptStateV1, WindowsAttemptTerminalDispositionV1, WindowsAuthorityLossEvidenceV1,
    WindowsCallerTokenEnvelopeV1, WindowsCertificationObservationsV1,
    WindowsCertificationObservationsV2, WindowsCertificationPhaseV1,
    WindowsCleanupProcessCreationEvidenceV1, WindowsControlRequestStatusV1,
    WindowsDurableAttemptRecordV1, WindowsDurableAttemptRecordV4, WindowsDurableCleanupStateV1,
    WindowsEnvironmentEntryV1, WindowsFaultRejectionObservationV1,
    WindowsFaultRejectionObservationV2, WindowsGuardianAttemptObservation,
    WindowsLaunchBrokerRequestV1, WindowsLaunchPolicyV1, WindowsLaunchRequestV1,
    WindowsLauncherRequestV1, WindowsLauncherRequestV3, WindowsLauncherResponseV1,
    WindowsLauncherResponseV3, WindowsLifetimeV1, WindowsMissingRetirementProofV1,
    WindowsMutantHookObservationV1, WindowsMutantKillEvidenceV1, WindowsMutantNativeObservationV1,
    WindowsMutantNativeReceiptV1, WindowsMutantObservationV1, WindowsPackageCleanupOutcomeV1,
    WindowsPreauthorizationFaultMatrixEvidenceV1, WindowsPreauthorizationFaultMatrixEvidenceV2,
    WindowsProcessIdentityV1, WindowsProviderProbeV1, WindowsProviderRejectionDispositionV2,
    WindowsProviderRejectionV2, WindowsProviderReplacementQuiescenceV1, WindowsProviderRequestV1,
    WindowsProviderRequestV3, WindowsProviderResponseV1, WindowsProviderResponseV3,
    WindowsPublicFrameFailureV1, WindowsPublicFramePhaseV1, WindowsPublicTerminalRecoveryV1,
    WindowsRecoveryInventoryV1, WindowsRelayEventV1, WindowsRelayPhaseV1, WindowsRemoteStreamV1,
    WindowsReplayOutboxStageV1, WindowsReplayPendingV1, WindowsReplayPendingV2,
    WindowsRetainedRecordBindingV1, WindowsRetainedRecordUnavailableReasonV1,
    WindowsRetirementFaultMatrixEvidenceV1, WindowsRetirementFaultMatrixEvidenceV2,
    WindowsRetirementLedgerCompletionV1, WindowsRetirementProofSourceV2, WindowsRetirementProofV2,
    WindowsSealedFault, WindowsSealedMutant, WindowsServiceSelfAttestationV1, WindowsStreamRoleV1,
    WindowsTerminalLifecycleV1, WindowsTerminalPayloadV2, WindowsTerminalReceiptV1,
    WindowsTerminalReceiptV2, WindowsTerminalReplayDecisionV1, WindowsTerminalRetiredV1,
    WindowsTerminalRetiredV2, WindowsTerminalSeedV2, WindowsTerminalizationCheckpointV1,
    WindowsTerminalizationErrorStageV1, WindowsTerminalizationErrorV1,
    WindowsTerminalizationOwnerV1, WindowsTerminalizationStatusV1, WindowsTokenMatrixEvidenceV1,
    WindowsTokenScenarioEvidenceV1, WindowsWorkerThreadIdentityV1,
    authenticate_decoded_windows_attempt_record, authenticate_decoded_windows_attempt_record_v4,
    decode_windows_command_line, encode_windows_command_line, encode_windows_environment_block,
    parse_and_authenticate_windows_attempt_record,
    parse_and_authenticate_windows_attempt_record_v4,
    parse_windows_certification_frontend_handle_values, validate_windows_security_descriptor_text,
    validate_windows_stream_manifest, windows_attempt_transition_allowed,
    windows_certification_argument_prelude_len, windows_certification_transition_allowed,
    windows_provider_replacement_quiescence, windows_service_attestation_challenge_is_valid,
    windows_terminal_outbox_is_bound, windows_terminal_outbox_is_bound_v3,
};
