//! Versioned wire records for the private Windows sealed provider.
//!
//! These records deliberately contain native argument and environment arrays.
//! Neither endpoint accepts a shell command line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{BoundaryMechanismEvidence, ProviderRejectionEvidence, RestartSafetyProof, RunOutcome};

pub const WINDOWS_PUBLIC_PROTOCOL_VERSION: u32 = 1;
pub const WINDOWS_PRIVATE_PROTOCOL_VERSION: u32 = 1;
pub const WINDOWS_QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const WINDOWS_MAX_JOB_PROCESS_IDENTITIES: usize = 256;

pub const WINDOWS_CONTROL_SERVICE_NAME: &str = "MemCordonSealedControl";
pub const WINDOWS_LAUNCHER_SERVICE_NAME: &str = "MemCordonSealedLauncher";
pub const WINDOWS_CONTROL_PIPE: &str = r"\\.\pipe\memcordon-sealed-agent-v1";
pub const WINDOWS_LAUNCHER_PIPE: &str = r"\\.\pipe\memcordon-sealed-launcher-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsSealedFault {
    PublicPipeCreate,
    CallerPidLookup,
    CallerTokenImpersonation,
    PrimaryTokenDuplicate,
    PrivatePipeConnect,
    LauncherPeerVerify,
    TokenHandleDuplicate,
    JobCreate,
    JobConfigure,
    CompletionPort,
    GuardianCreate,
    GuardianKilledBeforeAuthorization,
    GuardianKilledAfterAuthorization,
    FrontendDisconnectedAfterAuthorization,
    FrontendKilledAfterAuthorization,
    ControlWorkerKilledAfterAuthorization,
    ControlServiceKilledAfterAuthorization,
    LauncherWorkerKilledAfterAuthorization,
    LauncherServiceKilledAfterAuthorization,
    AllJobOwnersClosedAfterAuthorization,
    StreamCreate,
    RelayHandleDuplicate,
    RelayReady,
    AttributeList,
    JobList,
    HandleList,
    CreateProcessAsUser,
    TargetTokenReadback,
    JobMembershipReadback,
    BeforeResume,
    Resume,
    TerminateJob,
    ActiveProcessQuery,
    RelayRetire,
    GuardianReap,
    FinalHandleClose,
    RecordRetire,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsSealedMutant {
    UseCreateProcessW,
    CreateUnderServiceToken,
    AssignJobAfterCreate,
    OmitJobList,
    OmitHandleList,
    PermitBreakaway,
    TrustClientToken,
    SkipTargetTokenReadback,
    SkipJobMembershipReadback,
    ResumeBeforeGuardian,
    ResumeBeforeRelays,
    LeakJobHandleToTarget,
    LeakLauncherPipe,
    AcceptRecursiveProvider,
    OmitGuardian,
    AcceptCompletionWithoutAccounting,
    SuccessBeforeActiveZero,
    SkipRelayAck,
    CloseJobBeforeEvidence,
    FallBackToStandard,
    OmitAgentFromArchive,
    AdvertiseWithoutCertificate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMutantObservationV1 {
    pub mutant: WindowsSealedMutant,
    pub mapped_test: String,
    pub native_observation: WindowsMutantNativeObservationV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "detector", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsMutantNativeObservationV1 {
    TargetTokenMismatch {
        creation_api: String,
        token_source: String,
        authenticated_envelope_sha256: String,
        target_envelope_sha256: String,
    },
    CreationManifest {
        used_create_process_as_user: bool,
        job_list_present: bool,
        handle_list_present: bool,
        post_create_job_assignment: bool,
        unexpected_handle_count: usize,
    },
    JobLimitReadback {
        breakaway_allowed: bool,
    },
    ExternalTargetTokenMismatch {
        authenticated_envelope_sha256: String,
        target_envelope_sha256: String,
    },
    ExternalJobMembershipMissing {
        process_in_any_job: bool,
    },
    PrematureAuthorization {
        guardian_ready: bool,
        relays_ready: bool,
        target_marker_observed: bool,
    },
    LeakedHandleObserved {
        kind: String,
    },
    RecursiveLaunchAccepted,
    GuardianMissing,
    CompletionAcceptedWithoutAccounting {
        completion_zero_observed: bool,
        active_process_query_performed: bool,
    },
    SuccessBeforeActiveZero {
        active_processes: u32,
    },
    RelayAckSkipped {
        target_retired_sent: bool,
        relays_retired_received: bool,
    },
    EvidenceAfterFinalHandleClose {
        final_handles_closed: bool,
        evidence_constructed_after_close: bool,
    },
    PlatformRouteFallback {
        ordinary_route_sealed: bool,
        mutant_route_standard: bool,
    },
    ArchiveInventoryOmission {
        sealed_agent_removed: bool,
        configuration_rejected: bool,
    },
    UnqualifiedAdvertisement {
        ordinary_advertised: bool,
        mutant_advertised: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMutantNativeReceiptV1 {
    pub schema_version: u32,
    pub mutant: WindowsSealedMutant,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub hook_observation: WindowsMutantHookObservationV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_observation_handle: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_candidate: Option<Box<WindowsTerminalReceiptV1>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "hook", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsMutantHookObservationV1 {
    Native {
        observation: WindowsMutantNativeObservationV1,
    },
    TargetTokenReadbackSkipped {
        child_pid: u32,
    },
    JobMembershipReadbackSkipped {
        child_pid: u32,
    },
}

impl WindowsMutantNativeReceiptV1 {
    pub fn binding_matches(&self, attempt_id: &str, nonce: &str, request_sha256: &str) -> bool {
        self.schema_version == 1
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
    }
}

impl WindowsMutantNativeObservationV1 {
    pub fn rejects(&self, mutant: WindowsSealedMutant) -> bool {
        match (mutant, self) {
            (
                WindowsSealedMutant::UseCreateProcessW,
                Self::TargetTokenMismatch {
                    creation_api,
                    token_source,
                    authenticated_envelope_sha256,
                    target_envelope_sha256,
                },
            ) => {
                creation_api == "create-process-w"
                    && token_source == "launcher-service"
                    && windows_sha256_text_is_valid(authenticated_envelope_sha256)
                    && windows_sha256_text_is_valid(target_envelope_sha256)
                    && authenticated_envelope_sha256 != target_envelope_sha256
            }
            (
                WindowsSealedMutant::CreateUnderServiceToken,
                Self::TargetTokenMismatch {
                    creation_api,
                    token_source,
                    authenticated_envelope_sha256,
                    target_envelope_sha256,
                },
            ) => {
                creation_api == "create-process-as-user-w"
                    && token_source == "launcher-service"
                    && windows_sha256_text_is_valid(authenticated_envelope_sha256)
                    && windows_sha256_text_is_valid(target_envelope_sha256)
                    && authenticated_envelope_sha256 != target_envelope_sha256
            }
            (
                WindowsSealedMutant::TrustClientToken,
                Self::TargetTokenMismatch {
                    creation_api,
                    token_source,
                    authenticated_envelope_sha256,
                    target_envelope_sha256,
                },
            ) => {
                creation_api == "create-process-as-user-w"
                    && token_source == "authenticated-handle-untrusted-envelope"
                    && windows_sha256_text_is_valid(authenticated_envelope_sha256)
                    && windows_sha256_text_is_valid(target_envelope_sha256)
                    && authenticated_envelope_sha256 != target_envelope_sha256
            }
            (
                WindowsSealedMutant::AssignJobAfterCreate,
                Self::CreationManifest {
                    used_create_process_as_user: true,
                    job_list_present: false,
                    handle_list_present: true,
                    post_create_job_assignment: true,
                    unexpected_handle_count: 0,
                },
            )
            | (
                WindowsSealedMutant::OmitHandleList,
                Self::CreationManifest {
                    used_create_process_as_user: true,
                    job_list_present: true,
                    handle_list_present: false,
                    post_create_job_assignment: false,
                    unexpected_handle_count: 0,
                },
            ) => true,
            (
                WindowsSealedMutant::OmitJobList,
                Self::CreationManifest {
                    used_create_process_as_user: true,
                    job_list_present: false,
                    handle_list_present: true,
                    post_create_job_assignment: false,
                    unexpected_handle_count: 0,
                },
            ) => true,
            (
                WindowsSealedMutant::SkipJobMembershipReadback,
                Self::ExternalJobMembershipMissing {
                    process_in_any_job: false,
                },
            ) => true,
            (
                WindowsSealedMutant::PermitBreakaway,
                Self::JobLimitReadback {
                    breakaway_allowed: true,
                },
            ) => true,
            (
                WindowsSealedMutant::SkipTargetTokenReadback,
                Self::ExternalTargetTokenMismatch {
                    authenticated_envelope_sha256,
                    target_envelope_sha256,
                },
            ) => {
                windows_sha256_text_is_valid(authenticated_envelope_sha256)
                    && windows_sha256_text_is_valid(target_envelope_sha256)
                    && authenticated_envelope_sha256 != target_envelope_sha256
            }
            (
                WindowsSealedMutant::ResumeBeforeGuardian,
                Self::PrematureAuthorization {
                    guardian_ready: false,
                    target_marker_observed: true,
                    ..
                },
            )
            | (
                WindowsSealedMutant::ResumeBeforeRelays,
                Self::PrematureAuthorization {
                    relays_ready: false,
                    target_marker_observed: true,
                    ..
                },
            ) => true,
            (WindowsSealedMutant::LeakJobHandleToTarget, Self::LeakedHandleObserved { kind }) => {
                kind == "job"
            }
            (WindowsSealedMutant::LeakLauncherPipe, Self::LeakedHandleObserved { kind }) => {
                kind == "pipe"
            }
            (WindowsSealedMutant::AcceptRecursiveProvider, Self::RecursiveLaunchAccepted)
            | (WindowsSealedMutant::OmitGuardian, Self::GuardianMissing) => true,
            (
                WindowsSealedMutant::AcceptCompletionWithoutAccounting,
                Self::CompletionAcceptedWithoutAccounting {
                    completion_zero_observed: true,
                    active_process_query_performed: false,
                },
            ) => true,
            (
                WindowsSealedMutant::SuccessBeforeActiveZero,
                Self::SuccessBeforeActiveZero { active_processes },
            ) => *active_processes != 0,
            (
                WindowsSealedMutant::SkipRelayAck,
                Self::RelayAckSkipped {
                    target_retired_sent: true,
                    relays_retired_received: false,
                },
            )
            | (
                WindowsSealedMutant::CloseJobBeforeEvidence,
                Self::EvidenceAfterFinalHandleClose {
                    final_handles_closed: true,
                    evidence_constructed_after_close: true,
                },
            ) => true,
            (
                WindowsSealedMutant::FallBackToStandard,
                Self::PlatformRouteFallback {
                    ordinary_route_sealed: true,
                    mutant_route_standard: true,
                },
            )
            | (
                WindowsSealedMutant::OmitAgentFromArchive,
                Self::ArchiveInventoryOmission {
                    sealed_agent_removed: true,
                    configuration_rejected: true,
                },
            )
            | (
                WindowsSealedMutant::AdvertiseWithoutCertificate,
                Self::UnqualifiedAdvertisement {
                    ordinary_advertised: false,
                    mutant_advertised: true,
                },
            ) => true,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsMutantKillEvidenceV1 {
    pub schema_version: u32,
    pub observations: Vec<WindowsMutantObservationV1>,
}

impl WindowsMutantKillEvidenceV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.observations.len() == WINDOWS_RELEASE_MUTANTS.len()
            && self.observations.iter().zip(WINDOWS_RELEASE_MUTANTS).all(
                |(observation, (mutant, mapped_test))| {
                    observation.mutant.as_str() == *mutant
                        && observation.mapped_test == *mapped_test
                        && observation.native_observation.rejects(observation.mutant)
                },
            )
    }
}

impl WindowsSealedMutant {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UseCreateProcessW => "use-create-process-w",
            Self::CreateUnderServiceToken => "create-under-service-token",
            Self::AssignJobAfterCreate => "assign-job-after-create",
            Self::OmitJobList => "omit-job-list",
            Self::OmitHandleList => "omit-handle-list",
            Self::PermitBreakaway => "permit-breakaway",
            Self::TrustClientToken => "trust-client-token",
            Self::SkipTargetTokenReadback => "skip-target-token-readback",
            Self::SkipJobMembershipReadback => "skip-job-membership-readback",
            Self::ResumeBeforeGuardian => "resume-before-guardian",
            Self::ResumeBeforeRelays => "resume-before-relays",
            Self::LeakJobHandleToTarget => "leak-job-handle-to-target",
            Self::LeakLauncherPipe => "leak-launcher-pipe",
            Self::AcceptRecursiveProvider => "accept-recursive-provider",
            Self::OmitGuardian => "omit-guardian",
            Self::AcceptCompletionWithoutAccounting => "accept-completion-without-accounting",
            Self::SuccessBeforeActiveZero => "success-before-active-zero",
            Self::SkipRelayAck => "skip-relay-ack",
            Self::CloseJobBeforeEvidence => "close-job-before-evidence",
            Self::FallBackToStandard => "fall-back-to-standard",
            Self::OmitAgentFromArchive => "omit-agent-from-archive",
            Self::AdvertiseWithoutCertificate => "advertise-without-certificate",
        }
    }
}

pub const WINDOWS_PREAUTHORIZATION_FAULTS: &[WindowsSealedFault] = &[
    WindowsSealedFault::PublicPipeCreate,
    WindowsSealedFault::CallerPidLookup,
    WindowsSealedFault::CallerTokenImpersonation,
    WindowsSealedFault::PrimaryTokenDuplicate,
    WindowsSealedFault::PrivatePipeConnect,
    WindowsSealedFault::LauncherPeerVerify,
    WindowsSealedFault::TokenHandleDuplicate,
    WindowsSealedFault::JobCreate,
    WindowsSealedFault::JobConfigure,
    WindowsSealedFault::CompletionPort,
    WindowsSealedFault::GuardianCreate,
    WindowsSealedFault::GuardianKilledBeforeAuthorization,
    WindowsSealedFault::StreamCreate,
    WindowsSealedFault::RelayHandleDuplicate,
    WindowsSealedFault::RelayReady,
    WindowsSealedFault::AttributeList,
    WindowsSealedFault::JobList,
    WindowsSealedFault::HandleList,
    WindowsSealedFault::CreateProcessAsUser,
    WindowsSealedFault::TargetTokenReadback,
    WindowsSealedFault::JobMembershipReadback,
    WindowsSealedFault::BeforeResume,
    WindowsSealedFault::Resume,
];

pub const WINDOWS_RETIREMENT_FAULTS: &[WindowsSealedFault] = &[
    WindowsSealedFault::GuardianKilledAfterAuthorization,
    WindowsSealedFault::TerminateJob,
    WindowsSealedFault::ActiveProcessQuery,
    WindowsSealedFault::RelayRetire,
    WindowsSealedFault::GuardianReap,
    WindowsSealedFault::FinalHandleClose,
    WindowsSealedFault::RecordRetire,
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAuthorityLossEvidenceV1 {
    pub schema_version: u32,
    pub frontend_killed: bool,
    pub frontend_disconnected: bool,
    pub control_worker_lost: bool,
    pub control_service_lost: bool,
    pub launcher_worker_lost: bool,
    pub launcher_service_lost: bool,
    pub guardian_killed_before_authorization: bool,
    pub guardian_killed_after_authorization: bool,
    pub all_job_owners_closed: bool,
    pub durable_service_restart_recovered: bool,
    pub machine_restart_recovery_exercised: bool,
    pub active_processes_zero_after_each: bool,
    pub relays_retired_after_each: bool,
    pub records_retired_after_each: bool,
}

impl WindowsAuthorityLossEvidenceV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.frontend_killed
            && self.frontend_disconnected
            && self.control_worker_lost
            && self.control_service_lost
            && self.launcher_worker_lost
            && self.launcher_service_lost
            && self.guardian_killed_before_authorization
            && self.guardian_killed_after_authorization
            && self.all_job_owners_closed
            && self.durable_service_restart_recovered
            && self.machine_restart_recovery_exercised
            && self.active_processes_zero_after_each
            && self.relays_retired_after_each
            && self.records_retired_after_each
    }
}

/// Release-required Windows sealed mutants and the native certification test
/// whose evidence must kill each one.
pub const WINDOWS_RELEASE_MUTANTS: &[(&str, &str)] = &[
    ("use-create-process-w", "windows_target_token_identity"),
    (
        "create-under-service-token",
        "windows_target_token_identity",
    ),
    ("assign-job-after-create", "windows_creation_time_job_list"),
    ("omit-job-list", "windows_creation_time_job_list"),
    ("omit-handle-list", "windows_exact_handle_manifest"),
    ("permit-breakaway", "windows_job_policy_readback"),
    ("trust-client-token", "windows_caller_token_authentication"),
    (
        "skip-target-token-readback",
        "windows_target_token_identity",
    ),
    (
        "skip-job-membership-readback",
        "windows_job_membership_readback",
    ),
    ("resume-before-guardian", "windows_preauthorization_gate"),
    ("resume-before-relays", "windows_preauthorization_gate"),
    ("leak-job-handle-to-target", "windows_exact_handle_manifest"),
    ("leak-launcher-pipe", "windows_exact_handle_manifest"),
    (
        "accept-recursive-provider",
        "windows_recursive_provider_rejection",
    ),
    ("omit-guardian", "windows_guardian_authority"),
    (
        "accept-completion-without-accounting",
        "windows_active_process_accounting",
    ),
    (
        "success-before-active-zero",
        "windows_active_process_accounting",
    ),
    ("skip-relay-ack", "windows_relay_retirement"),
    ("close-job-before-evidence", "windows_final_handle_ordering"),
    (
        "fall-back-to-standard",
        "windows_sealed_mechanism_selection",
    ),
    (
        "omit-agent-from-archive",
        "windows_native_archive_inventory",
    ),
    (
        "advertise-without-certificate",
        "windows_qualification_advertisement",
    ),
];

pub const WINDOWS_RELEASE_MUTANT_VARIANTS: &[WindowsSealedMutant] = &[
    WindowsSealedMutant::UseCreateProcessW,
    WindowsSealedMutant::CreateUnderServiceToken,
    WindowsSealedMutant::AssignJobAfterCreate,
    WindowsSealedMutant::OmitJobList,
    WindowsSealedMutant::OmitHandleList,
    WindowsSealedMutant::PermitBreakaway,
    WindowsSealedMutant::TrustClientToken,
    WindowsSealedMutant::SkipTargetTokenReadback,
    WindowsSealedMutant::SkipJobMembershipReadback,
    WindowsSealedMutant::ResumeBeforeGuardian,
    WindowsSealedMutant::ResumeBeforeRelays,
    WindowsSealedMutant::LeakJobHandleToTarget,
    WindowsSealedMutant::LeakLauncherPipe,
    WindowsSealedMutant::AcceptRecursiveProvider,
    WindowsSealedMutant::OmitGuardian,
    WindowsSealedMutant::AcceptCompletionWithoutAccounting,
    WindowsSealedMutant::SuccessBeforeActiveZero,
    WindowsSealedMutant::SkipRelayAck,
    WindowsSealedMutant::CloseJobBeforeEvidence,
    WindowsSealedMutant::FallBackToStandard,
    WindowsSealedMutant::OmitAgentFromArchive,
    WindowsSealedMutant::AdvertiseWithoutCertificate,
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreauthorizationFaultMatrixEvidenceV1 {
    pub schema_version: u32,
    pub faults: Vec<WindowsSealedFault>,
    pub first_instruction_markers_absent: bool,
    pub recovery_clear_after_each_fault: bool,
    pub rejections: Vec<WindowsFaultRejectionObservationV1>,
    pub terminal_frame_truncation_rejected: bool,
}

impl WindowsPreauthorizationFaultMatrixEvidenceV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.faults == WINDOWS_PREAUTHORIZATION_FAULTS
            && self.first_instruction_markers_absent
            && self.recovery_clear_after_each_fault
            && fault_rejections_are_complete(&self.faults, &self.rejections, false)
            && self.terminal_frame_truncation_rejected
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRetirementFaultMatrixEvidenceV1 {
    pub schema_version: u32,
    pub faults: Vec<WindowsSealedFault>,
    pub first_instruction_markers_observed: bool,
    pub recovery_clear_after_each_fault: bool,
    pub rejections: Vec<WindowsFaultRejectionObservationV1>,
}

impl WindowsRetirementFaultMatrixEvidenceV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.faults == WINDOWS_RETIREMENT_FAULTS
            && self.first_instruction_markers_observed
            && self.recovery_clear_after_each_fault
            && fault_rejections_are_complete(&self.faults, &self.rejections, true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFaultRejectionObservationV1 {
    pub fault: WindowsSealedFault,
    pub rejection: ProviderRejectionEvidence,
}

fn fault_rejections_are_complete(
    faults: &[WindowsSealedFault],
    observations: &[WindowsFaultRejectionObservationV1],
    target_released: bool,
) -> bool {
    observations.len() == faults.len()
        && observations
            .iter()
            .zip(faults)
            .all(|(observation, expected)| {
                observation.fault == *expected
                    && observation.rejection.code == "MCSEALED-WINDOWS-CERTIFICATION-FAULT"
                    && observation.rejection.target_released == target_released
                    && observation.rejection.is_consistent()
            })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationObservationsV1 {
    pub schema_version: u32,
    pub preauthorization: WindowsPreauthorizationFaultMatrixEvidenceV1,
    pub retirement: WindowsRetirementFaultMatrixEvidenceV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTokenScenarioEvidenceV1 {
    pub name: String,
    pub caller_envelope: WindowsCallerTokenEnvelopeV1,
    pub restricted_sid_count: u32,
    pub token_is_restricted: bool,
    pub enabled_sensitive_privilege_count: u32,
    pub administrator_deny_only: bool,
    pub initial_target_token_matches_caller: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTokenMatrixEvidenceV1 {
    pub schema_version: u32,
    pub scenarios: Vec<WindowsTokenScenarioEvidenceV1>,
    pub appcontainer_rejected_before_target: bool,
    pub different_session_supported: bool,
    pub different_session_verified: bool,
}

impl WindowsTokenMatrixEvidenceV1 {
    pub fn is_complete(&self) -> bool {
        const REQUIRED: [&str; 7] = [
            "elevated-admin",
            "ordinary-user",
            "restricted",
            "write-restricted",
            "disabled-privileges",
            "deny-only-admin",
            "low-integrity",
        ];
        self.schema_version == 1
            && self.scenarios.len() == REQUIRED.len()
            && self
                .scenarios
                .iter()
                .zip(REQUIRED)
                .all(|(scenario, required)| {
                    if scenario.name != required
                        || !scenario.initial_target_token_matches_caller
                        || scenario.caller_envelope.appcontainer
                    {
                        return false;
                    }
                    match required {
                        "elevated-admin" => scenario.caller_envelope.elevated,
                        "ordinary-user" => !scenario.caller_envelope.elevated,
                        "restricted" | "write-restricted" => {
                            scenario.token_is_restricted && scenario.restricted_sid_count != 0
                        }
                        "disabled-privileges" => scenario.enabled_sensitive_privilege_count == 0,
                        "deny-only-admin" => {
                            scenario.administrator_deny_only
                                && scenario.token_is_restricted
                                && scenario.restricted_sid_count != 0
                        }
                        "low-integrity" => {
                            scenario.caller_envelope.integrity_level == "S-1-16-4096"
                        }
                        _ => false,
                    }
                })
            && self.appcontainer_rejected_before_target
            && (!self.different_session_supported || self.different_session_verified)
    }
}

impl WindowsCertificationObservationsV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.preauthorization.is_complete()
            && self.retirement.is_complete()
    }
}

pub fn encode_windows_command_line(arguments: &[Vec<u16>]) -> Vec<u16> {
    let mut output = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if index != 0 {
            output.push(b' ' as u16);
        }
        encode_windows_argument(argument, &mut output);
    }
    output
}

/// Decodes the quoting subset produced by [`encode_windows_command_line`].
/// This is a platform-independent oracle for fixed-vector and fuzz round trips;
/// production launch still passes the encoded buffer directly to Windows.
pub fn decode_windows_command_line(command_line: &[u16]) -> Result<Vec<Vec<u16>>, &'static str> {
    if command_line.contains(&0) {
        return Err("Windows command line contains NUL");
    }
    let mut arguments = Vec::new();
    let mut cursor = 0_usize;
    while cursor < command_line.len() {
        while cursor < command_line.len()
            && matches!(command_line[cursor], value if value == b' ' as u16 || value == b'\t' as u16)
        {
            cursor += 1;
        }
        if cursor == command_line.len() {
            break;
        }
        let mut argument = Vec::new();
        let mut quoted = false;
        while cursor < command_line.len() {
            if !quoted
                && matches!(command_line[cursor], value if value == b' ' as u16 || value == b'\t' as u16)
            {
                break;
            }
            let mut backslashes = 0_usize;
            while cursor < command_line.len() && command_line[cursor] == b'\\' as u16 {
                backslashes += 1;
                cursor += 1;
            }
            if cursor < command_line.len() && command_line[cursor] == b'"' as u16 {
                argument.extend(std::iter::repeat_n(b'\\' as u16, backslashes / 2));
                if backslashes % 2 == 0 {
                    quoted = !quoted;
                } else {
                    argument.push(b'"' as u16);
                }
                cursor += 1;
            } else {
                argument.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                if cursor < command_line.len() {
                    argument.push(command_line[cursor]);
                    cursor += 1;
                }
            }
        }
        if quoted {
            return Err("Windows command line has an unterminated quote");
        }
        arguments.push(argument);
    }
    Ok(arguments)
}

fn encode_windows_argument(argument: &[u16], output: &mut Vec<u16>) {
    let quote = argument.is_empty()
        || argument
            .iter()
            .any(|value| *value == b' ' as u16 || *value == b'\t' as u16 || *value == b'"' as u16);
    if !quote {
        output.extend_from_slice(argument);
        return;
    }
    output.push(b'"' as u16);
    let mut backslashes = 0_usize;
    for value in argument {
        if *value == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if *value == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        backslashes = 0;
        output.push(*value);
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    output.push(b'"' as u16);
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWindowsCommandV1 {
    pub program: Vec<u16>,
    pub arguments: Vec<Vec<u16>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsEnvironmentEntryV1 {
    pub name: Vec<u16>,
    pub value: Vec<u16>,
}

pub fn encode_windows_environment_block(
    entries: &[WindowsEnvironmentEntryV1],
) -> Result<Vec<u16>, &'static str> {
    let mut entries = entries.to_vec();
    entries.sort_by_key(|entry| windows_environment_key(&entry.name));
    for pair in entries.windows(2) {
        if windows_environment_key(&pair[0].name) == windows_environment_key(&pair[1].name) {
            return Err("duplicate case-insensitive Windows environment name");
        }
    }
    let mut output = Vec::new();
    for entry in entries {
        if entry.name.is_empty()
            || entry.name.contains(&0)
            || entry.name.contains(&(b'=' as u16))
            || entry.value.contains(&0)
        {
            return Err("invalid Windows environment entry");
        }
        output.extend(entry.name);
        output.push(b'=' as u16);
        output.extend(entry.value);
        output.push(0);
    }
    output.push(0);
    if output.len() == 1 {
        output.push(0);
    }
    if output.len() > 32_767 {
        Err("Windows environment block exceeds the native UTF-16 limit")
    } else {
        Ok(output)
    }
}

fn windows_environment_key(name: &[u16]) -> Vec<u16> {
    String::from_utf16_lossy(name)
        .chars()
        .flat_map(char::to_uppercase)
        .collect::<String>()
        .encode_utf16()
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsAttemptStateV1 {
    BoundaryCreated,
    GuardianReady,
    TargetCreatedSuspended,
    Authorized,
    Terminating,
    Empty,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDurableCleanupStateV1 {
    pub termination_requested: bool,
    pub active_processes_zero: bool,
    pub guardian_reaped: bool,
    pub final_handles_closed: bool,
}

/// Platform-neutral wire image of one authenticated Windows attempt record.
///
/// The Windows service uses this parser before accepting durable recovery
/// state. Keeping the strict parser in core also lets the dedicated fuzz target
/// exercise the production authentication and state-invariant surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDurableAttemptRecordV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub boot_identity: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_sha256: String,
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub integrity_sha256: String,
}

pub fn parse_and_authenticate_windows_attempt_record(
    bytes: &[u8],
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<WindowsDurableAttemptRecordV1, &'static str> {
    if bytes.len() > WINDOWS_MAX_FRAME_BYTES
        || !windows_sha256_text_is_valid(expected_attempt_id)
        || expected_provider_generation.is_empty()
    {
        return Err("Windows attempt record identity is invalid");
    }
    let record: WindowsDurableAttemptRecordV1 =
        serde_json::from_slice(bytes).map_err(|_| "Windows attempt record JSON is invalid")?;
    let mut canonical = record.clone();
    canonical.integrity_sha256.clear();
    let canonical = serde_json::to_vec(&canonical)
        .map_err(|_| "Windows attempt record canonicalization failed")?;
    let expected_integrity = windows_sha256(&canonical);
    if record.schema_version != 1
        || record.attempt_id != expected_attempt_id
        || record.provider_generation != expected_provider_generation
        || record.integrity_sha256 != expected_integrity
        || !windows_sha256_text_is_valid(&record.attempt_id)
        || !windows_sha256_text_is_valid(&record.request_sha256)
        || !windows_sha256_text_is_valid(&record.caller_token_sha256)
        || !windows_sha256_text_is_valid(&record.job_identity_sha256)
        || record.boot_identity.is_empty()
        || !windows_process_identity_is_valid(&record.caller_process_identity)
        || !record
            .guardian_identity
            .as_ref()
            .is_none_or(windows_process_identity_is_valid)
        || !record
            .target_identity
            .as_ref()
            .is_none_or(windows_process_identity_is_valid)
        || !windows_durable_attempt_state_is_consistent(&record)
    {
        return Err("Windows attempt record authentication failed");
    }
    Ok(record)
}

fn windows_sha256_text_is_valid(value: &str) -> bool {
    let digest_length = windows_sha256(&[]).len();
    value.len() == digest_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn windows_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                char::from(HEX[usize::from(byte >> 4)]),
                char::from(HEX[usize::from(byte & 0x0f)]),
            ]
        })
        .collect()
}

const fn windows_process_identity_is_valid(identity: &WindowsProcessIdentityV1) -> bool {
    identity.process_id != 0 && identity.creation_time_100ns != 0
}

fn windows_durable_attempt_state_is_consistent(record: &WindowsDurableAttemptRecordV1) -> bool {
    let guardian_required = matches!(
        record.state,
        WindowsAttemptStateV1::GuardianReady
            | WindowsAttemptStateV1::TargetCreatedSuspended
            | WindowsAttemptStateV1::Authorized
    );
    let target_required = matches!(
        record.state,
        WindowsAttemptStateV1::TargetCreatedSuspended | WindowsAttemptStateV1::Authorized
    ) || record.resume_attempted
        || record.target_released;
    let authorization_permitted = matches!(
        record.state,
        WindowsAttemptStateV1::Authorized
            | WindowsAttemptStateV1::Terminating
            | WindowsAttemptStateV1::Empty
    );
    (!guardian_required || record.guardian_identity.is_some())
        && (!target_required || record.target_identity.is_some())
        && (!record.target_released || record.resume_attempted)
        && (!record.resume_attempted || record.authorization_unix_millis.is_some())
        && (record.state != WindowsAttemptStateV1::Authorized
            || record.authorization_unix_millis.is_some())
        && (record.authorization_unix_millis.is_none() || authorization_permitted)
        && (!record.cleanup_state.final_handles_closed
            || (record.cleanup_state.termination_requested
                && record.cleanup_state.active_processes_zero
                && record.cleanup_state.guardian_reaped
                && record.state == WindowsAttemptStateV1::Empty))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsCertificationPhaseV1 {
    Connected,
    CallerAuthenticated,
    LauncherAuthenticated,
    GuardianReady,
    RelaysReady,
    TargetCreatedSuspended,
    AssignmentVerified,
    Authorized,
    Running,
    Terminating,
    Empty,
    RelaysRetired,
    GuardianReaped,
    HandlesClosed,
    Retired,
}

pub const fn windows_certification_transition_allowed(
    from: WindowsCertificationPhaseV1,
    to: WindowsCertificationPhaseV1,
) -> bool {
    use WindowsCertificationPhaseV1 as Phase;
    matches!(
        (from, to),
        (
            Phase::Connected,
            Phase::CallerAuthenticated | Phase::Terminating
        ) | (
            Phase::CallerAuthenticated,
            Phase::LauncherAuthenticated | Phase::Terminating
        ) | (
            Phase::LauncherAuthenticated,
            Phase::GuardianReady | Phase::Terminating
        ) | (
            Phase::GuardianReady,
            Phase::RelaysReady | Phase::Terminating
        ) | (
            Phase::RelaysReady,
            Phase::TargetCreatedSuspended | Phase::Terminating
        ) | (
            Phase::TargetCreatedSuspended,
            Phase::AssignmentVerified | Phase::Terminating
        ) | (
            Phase::AssignmentVerified,
            Phase::Authorized | Phase::Terminating
        ) | (Phase::Authorized, Phase::Running | Phase::Terminating)
            | (Phase::Running, Phase::Terminating)
            | (Phase::Terminating, Phase::Empty)
            | (Phase::Empty, Phase::RelaysRetired)
            | (Phase::RelaysRetired, Phase::GuardianReaped)
            | (Phase::GuardianReaped, Phase::HandlesClosed)
            | (Phase::HandlesClosed, Phase::Retired)
    )
}

pub const fn windows_attempt_transition_allowed(
    from: WindowsAttemptStateV1,
    to: WindowsAttemptStateV1,
) -> bool {
    matches!(
        (from, to),
        (
            WindowsAttemptStateV1::BoundaryCreated,
            WindowsAttemptStateV1::GuardianReady | WindowsAttemptStateV1::Terminating
        ) | (
            WindowsAttemptStateV1::GuardianReady,
            WindowsAttemptStateV1::TargetCreatedSuspended | WindowsAttemptStateV1::Terminating
        ) | (
            WindowsAttemptStateV1::TargetCreatedSuspended,
            WindowsAttemptStateV1::Authorized | WindowsAttemptStateV1::Terminating
        ) | (
            WindowsAttemptStateV1::Authorized,
            WindowsAttemptStateV1::Terminating
        ) | (
            WindowsAttemptStateV1::Terminating,
            WindowsAttemptStateV1::Empty
        )
    )
}

pub fn validate_windows_security_descriptor_text(value: &str) -> Result<(), &'static str> {
    let dacl = if let Some(without_owner) = value.strip_prefix("O:") {
        let Some((owner, dacl)) = without_owner.split_once("D:") else {
            return Err("Windows security descriptor owner is missing a DACL");
        };
        if owner.is_empty() || owner.contains(['(', ')', ':']) {
            return Err("Windows security descriptor owner is malformed");
        }
        dacl
    } else if let Some(dacl) = value.strip_prefix("D:") {
        dacl
    } else {
        return Err("Windows security descriptor text has an invalid prefix or NUL");
    };
    if value.is_empty() || value.contains('\0') {
        return Err("Windows security descriptor text has an invalid prefix or NUL");
    }
    let mut depth = 0_u32;
    let mut ace_count = 0_u32;
    for character in dacl.chars() {
        match character {
            '(' => {
                if depth != 0 {
                    return Err("Windows security descriptor ACEs may not be nested");
                }
                depth = 1;
                ace_count += 1;
            }
            ')' => {
                if depth != 1 {
                    return Err("Windows security descriptor has an unmatched closing ACE");
                }
                depth = 0;
            }
            _ => {}
        }
    }
    if depth != 0 || ace_count == 0 {
        Err("Windows security descriptor has an incomplete or empty ACE inventory")
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLaunchPolicyV1 {
    pub memory_limit_bytes: Option<u64>,
    pub absolute_deadline_millis: Option<u64>,
    pub lifetime: WindowsLifetimeV1,
    pub poll_interval_millis: u64,
    pub signal_grace_millis: u64,
    pub command_exit_grace_millis: u64,
    pub limit_grace_millis: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsLifetimeV1 {
    Command,
    Workload,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProcessIdentityV1 {
    pub process_id: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCallerTokenEnvelopeV1 {
    pub user_sid: String,
    pub owner_sid: String,
    pub primary_group_sid: String,
    pub groups_sha256: String,
    pub privileges_sha256: String,
    pub restricted_sids_sha256: String,
    pub integrity_level: String,
    pub mandatory_policy: u32,
    pub session_id: u32,
    pub elevation_type: u32,
    pub elevated: bool,
    pub virtualization_allowed: bool,
    pub virtualization_enabled: bool,
    pub ui_access: bool,
    pub appcontainer: bool,
    pub authentication_id: u64,
    pub token_type: u32,
    pub impersonation_level: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLaunchRequestV1 {
    pub schema_version: u32,
    pub nonce: String,
    pub command: NativeWindowsCommandV1,
    pub environment: Vec<WindowsEnvironmentEntryV1>,
    pub current_directory: Vec<u16>,
    pub policy: WindowsLaunchPolicyV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLaunchBrokerRequestV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_envelope: WindowsCallerTokenEnvelopeV1,
    pub remote_primary_token_handle: u64,
    pub remote_frontend_process_handle: u64,
    /// Certification-only handles created by the authenticated frontend and
    /// duplicated into the launcher. They are absent from ordinary launches.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remote_frontend_canary_handles: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification_fault: Option<WindowsSealedFault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification_mutant: Option<WindowsSealedMutant>,
    pub launch: WindowsLaunchRequestV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsStreamRoleV1 {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRemoteStreamV1 {
    pub role: WindowsStreamRoleV1,
    pub remote_handle: u64,
}

pub fn validate_windows_stream_manifest(
    streams: &[WindowsRemoteStreamV1],
) -> Result<(), &'static str> {
    if streams.len() != 3 {
        return Err("stream manifest must contain exactly three entries");
    }
    let mut handles = std::collections::BTreeSet::new();
    let mut role_counts = [0_u8; 3];
    for stream in streams {
        if stream.remote_handle == 0 || !handles.insert(stream.remote_handle) {
            return Err("stream manifest contains a null or duplicate handle");
        }
        role_counts[match stream.role {
            WindowsStreamRoleV1::Stdin => 0,
            WindowsStreamRoleV1::Stdout => 1,
            WindowsStreamRoleV1::Stderr => 2,
        }] += 1;
    }
    if role_counts == [1, 1, 1] {
        Ok(())
    } else {
        Err("stream manifest contains duplicate or missing roles")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderRequestV1 {
    Probe {
        schema_version: u32,
    },
    RecoveryStatus {
        schema_version: u32,
    },
    PackageCleanup {
        schema_version: u32,
    },
    QualificationBegin {
        schema_version: u32,
        scope: String,
    },
    QualificationAuthorizeChild {
        schema_version: u32,
        child_process_identity: WindowsProcessIdentityV1,
    },
    QualificationAcquire {
        schema_version: u32,
    },
    QualificationEnd {
        schema_version: u32,
    },
    CertificationFault {
        schema_version: u32,
        fault: WindowsSealedFault,
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        launch: WindowsLaunchRequestV1,
    },
    CertificationMutant {
        schema_version: u32,
        mutant: WindowsSealedMutant,
        attempt_id: String,
        request_sha256: String,
        caller_process_identity: WindowsProcessIdentityV1,
        launch: WindowsLaunchRequestV1,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    Launch(WindowsLaunchRequestV1),
    RelaysReady {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    Cancel {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        signal: i32,
    },
    RelaysRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderResponseV1 {
    Probe {
        schema_version: u32,
        qualification: WindowsQualificationReceiptV1,
    },
    StreamsPrepared {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        streams: Vec<WindowsRemoteStreamV1>,
        relay_retired_event_handle: u64,
    },
    RecoveryStatus {
        schema_version: u32,
        attempts_empty: bool,
    },
    PackageCleanupReady {
        schema_version: u32,
    },
    QualificationReady {
        schema_version: u32,
    },
    QualificationAuthenticated {
        schema_version: u32,
    },
    QualificationChildAuthorized {
        schema_version: u32,
    },
    QualificationEnded {
        schema_version: u32,
    },
    CertificationMachineRestart {
        schema_version: u32,
        recovered: bool,
    },
    TargetAuthorized {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        child_pid: u32,
    },
    TargetRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    RelaysAbort {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    CertificationMutantHookObserved(WindowsMutantNativeReceiptV1),
    CertificationMutantObserved(WindowsMutantNativeReceiptV1),
    Terminal(WindowsTerminalReceiptV1),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: ProviderRejectionEvidence,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherRequestV1 {
    Probe {
        schema_version: u32,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    Membership {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        remote_process_handle: u64,
    },
    Launch(WindowsLaunchBrokerRequestV1),
    RelaysReady {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    Cancel {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        signal: i32,
    },
    RelaysRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherResponseV1 {
    Probe {
        schema_version: u32,
        process_identity: WindowsProcessIdentityV1,
    },
    CertificationMachineRestart {
        schema_version: u32,
        recovered: bool,
    },
    Membership {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        inside_active_job: bool,
    },
    StreamsPrepared {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        streams: Vec<WindowsRemoteStreamV1>,
        relay_retired_event_handle: u64,
    },
    TargetAuthorized {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        child_pid: u32,
    },
    TargetRetired {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    RelaysAbort {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
    },
    CertificationMutantHookObserved(WindowsMutantNativeReceiptV1),
    CertificationMutantObserved(WindowsMutantNativeReceiptV1),
    Terminal(WindowsTerminalReceiptV1),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: ProviderRejectionEvidence,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalReceiptV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub child_pid: u32,
    pub duration_millis: u64,
    pub authorization_offset_millis: u64,
    pub job_total_processes: u32,
    pub job_process_identities: Vec<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    pub outcome: RunOutcome,
    pub restart_safety: RestartSafetyProof,
    pub boundary_detail: BoundaryMechanismEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCleanupProcessCreationEvidenceV1 {
    pub schema_version: u32,
    pub attempted_after_terminating_transition: bool,
    pub child_created: bool,
    pub child_job_membership_verified: bool,
    pub total_processes_before: u32,
    pub total_processes_after: u32,
    pub final_active_processes_zero: bool,
}

impl WindowsCleanupProcessCreationEvidenceV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && self.attempted_after_terminating_transition
            && self.child_created
            && self.child_job_membership_verified
            && self.total_processes_after > self.total_processes_before
            && self.final_active_processes_zero
    }
}

impl WindowsTerminalReceiptV1 {
    pub fn process_identity_inventory_is_bounded(&self) -> bool {
        self.job_process_identities.len() <= WINDOWS_MAX_JOB_PROCESS_IDENTITIES
            && self
                .job_process_identities
                .iter()
                .all(|identity| identity.process_id != 0)
            && self
                .job_process_identities
                .iter()
                .enumerate()
                .all(|(index, identity)| !self.job_process_identities[..index].contains(identity))
            && self
                .cleanup_process_creation
                .as_ref()
                .is_none_or(WindowsCleanupProcessCreationEvidenceV1::is_consistent)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsQualificationReceiptV1 {
    pub schema_version: u32,
    pub provider_identity: String,
    pub control_service_identity: String,
    pub launcher_service_identity: String,
    pub package_verified: bool,
    pub public_pipe_security_verified: bool,
    pub private_pipe_security_verified: bool,
    pub control_service_privileges_verified: bool,
    pub launcher_service_privileges_verified: bool,
    pub caller_token_authentication_verified: bool,
    pub restricted_caller_token_verified: bool,
    pub primary_token_duplication_verified: bool,
    pub create_process_as_user_verified: bool,
    pub job_list_supported: bool,
    pub handle_list_supported: bool,
    pub nested_host_job_supported: bool,
    pub kill_on_close_verified: bool,
    pub breakaway_denied: bool,
    pub completion_port_verified: bool,
    pub guardian_verified: bool,
    pub frontend_loss_cleanup_verified: bool,
    pub alternate_token_child_contained: bool,
    pub nested_child_job_contained: bool,
    pub recursive_provider_request_denied: bool,
    pub exact_handle_inheritance_verified: bool,
    pub active_processes_zero_verified: bool,
    pub relays_retired_verified: bool,
    pub recovery_complete: bool,
    pub qualified: bool,
}

impl WindowsQualificationReceiptV1 {
    pub fn is_consistent_if_qualified(&self) -> bool {
        let mut candidate = self.clone();
        candidate.qualified = true;
        candidate.is_consistent()
    }

    pub fn is_consistent(&self) -> bool {
        self.schema_version == WINDOWS_QUALIFICATION_SCHEMA_VERSION
            && self.provider_identity
                == format!(
                    "memcordon-sealed-agent-windows-v1:{}",
                    env!("CARGO_PKG_VERSION")
                )
            && self.control_service_identity == "MemCordonSealedControl:LocalService:restricted"
            && self.launcher_service_identity == "MemCordonSealedLauncher:LocalSystem:restricted"
            && (!self.qualified
                || (self.package_verified
                    && self.public_pipe_security_verified
                    && self.private_pipe_security_verified
                    && self.control_service_privileges_verified
                    && self.launcher_service_privileges_verified
                    && self.caller_token_authentication_verified
                    && self.restricted_caller_token_verified
                    && self.primary_token_duplication_verified
                    && self.create_process_as_user_verified
                    && self.job_list_supported
                    && self.handle_list_supported
                    && self.nested_host_job_supported
                    && self.kill_on_close_verified
                    && self.breakaway_denied
                    && self.completion_port_verified
                    && self.guardian_verified
                    && self.frontend_loss_cleanup_verified
                    && self.alternate_token_child_contained
                    && self.nested_child_job_contained
                    && self.recursive_provider_request_denied
                    && self.exact_handle_inheritance_verified
                    && self.active_processes_zero_verified
                    && self.relays_retired_verified
                    && self.recovery_complete))
    }
}
