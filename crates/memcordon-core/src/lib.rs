//! Platform-neutral supervision policy and evidence models.
//!
//! [`BoundaryRequirement::Sealed`] requests a certified process-supervision
//! boundary and never permits fallback to standard supervision. Capability,
//! launch, and cleanup facts remain distinct so consumers can validate the
//! contract without selecting a platform mechanism.

#![forbid(unsafe_code)]

pub mod canonical_json;
pub mod diagnostics;
pub mod discovery;
pub mod execution_facts;
pub mod identifiers;
pub mod native_readiness;
pub mod provider_rejection_wire;
pub mod runtime_components;
pub mod runtime_evidence;
pub mod runtime_manifest_v2;
pub use runtime_evidence::*;
pub mod result_v3;
pub use execution_facts::{ReportFormat, ResultReport};
pub use result_v3::ResultV3;
pub use windows_sealed::*;
pub mod elf_closure;
pub mod workload_bundle;
pub mod workload_chunks;
pub mod workload_files;
pub mod workload_limits;
pub mod workload_request;
pub mod workload_requirements;
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
mod windows_capability_owner_v2;
mod windows_guardian_receipt;
mod windows_pe;
mod windows_process_observation;
mod windows_recovery_authorization;
mod windows_sealed;
mod windows_startup_diagnostic;

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
    CLEAN_REPORT_SCHEMA_VERSION, CircuitBreakerPolicyReport, CleanReport, DeadlinePolicyReport,
    DoctorReport, EXECUTION_REPORT_SCHEMA_VERSION, EffectiveMemoryPolicyReport,
    EffectivePolicyReport, EffectiveRestartPolicyReport, ExecutionErrorReport, HostReport,
    InvocationReport, MemcordonReport, NativeArgument, NativeArgumentRaw, OptionEffectReport,
    PlanReport, PlanResolutionReport, PolicyEnvelopeReport, ReportModelError, ReportWritePhase,
    RequestedMemoryPolicyReport, RequestedPolicyReport, RequestedRestartPolicyReport,
    RequirementReport, SupervisionReport, SwapReport, ToolReport, UnavailableCapabilityReport,
    write_report_atomic, write_report_bytes_atomic,
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
    WindowsLoaderConsoleComparisonOutcomeV1, WindowsLoaderConsoleComparisonV1,
    WindowsLoaderDebugEventV1, WindowsLoaderDebugImagePathSourceV1,
    WindowsLoaderDebugObservationV1, WindowsLoaderMitigationObservationV1,
    WindowsLoaderMitigationPolicyObservationV1, WindowsLoaderNativeStatusV1,
    WindowsLoaderQualificationFailureV2, WindowsLoaderQualificationOutcomeV2,
    WindowsLoaderQualificationStageV2, WindowsLoaderReadyEvidenceV1, WorkloadFrontendEvidenceV1,
    boundary_evidence_is_consistent,
};
pub use windows_capability_owner_v2::{
    WINDOWS_CURRENT_CAPABILITY_OWNER_MANIFEST_SCHEMA_VERSION,
    WINDOWS_CURRENT_CAPABILITY_OWNER_ROLE_COUNT, WindowsCapabilityExtinctionProofV2,
    WindowsCapabilityOwnerEntryV2, WindowsCapabilityOwnerManifestV2, WindowsCapabilityOwnerRoleV2,
    WindowsJobClosureContractV2,
};
pub use windows_guardian_receipt::{
    WindowsGuardianCleanupTriggerV1, WindowsGuardianReceiptBinding, WindowsGuardianReceiptV2,
};
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
pub use windows_startup_diagnostic::{
    WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES, WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_MAX_AGE_MILLIS,
    WindowsLauncherStartupDiagnosticV1, WindowsLauncherStartupReasonV1,
    WindowsLauncherStartupStageV1,
};
