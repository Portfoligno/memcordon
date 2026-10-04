//! Versioned wire records for the private Windows sealed provider.
//!
//! These records deliberately contain native argument and environment arrays.
//! Neither endpoint accepts a shell command line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BoundaryMechanismEvidence, BoundaryRequirement, ChildTermination,
    CredentialTransitionDisposition, ProviderRejectionEvidence, RestartSafetyProof, RunOutcome,
    WindowsSealedEvidenceV2,
};

pub const WINDOWS_PUBLIC_PROTOCOL_VERSION: u32 = 3;
pub const WINDOWS_PRIVATE_PROTOCOL_VERSION: u32 = 3;
pub const WINDOWS_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const WINDOWS_MAX_JOB_PROCESS_IDENTITIES: usize = 256;
pub const WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS: usize = 4;

pub const WINDOWS_CONTROL_SERVICE_NAME: &str = "MemCordonSealedControl";
pub const WINDOWS_LAUNCHER_SERVICE_NAME: &str = "MemCordonSealedLauncher";
pub const WINDOWS_SESSION_BROKER_SERVICE_NAME: &str = "MemCordonSealedSessionBroker";
pub const WINDOWS_CONTROL_REQUIRED_PRIVILEGES: &[&str] = &["SeImpersonatePrivilege"];
pub const WINDOWS_LAUNCHER_REQUIRED_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeBackupPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeRestorePrivilege",
    "SeTcbPrivilege",
];
pub const WINDOWS_SESSION_BROKER_REQUIRED_PRIVILEGES: &[&str] = &[
    "SeAssignPrimaryTokenPrivilege",
    "SeIncreaseQuotaPrivilege",
    "SeImpersonatePrivilege",
    "SeSecurityPrivilege",
    "SeTcbPrivilege",
];
pub const WINDOWS_GUARDIAN_SERVICE_PREFIX: &str = "MemCordonSealedGuardian-";
pub const WINDOWS_GUARDIAN_SLOT_COUNT: usize = 8;
pub const WINDOWS_CONTROL_PIPE: &str = r"\\.\pipe\memcordon-sealed-agent-v1";
pub const WINDOWS_LAUNCHER_PIPE: &str = r"\\.\pipe\memcordon-sealed-launcher-v1";
pub const WINDOWS_SESSION_BROKER_PIPE: &str = r"\\.\pipe\memcordon-sealed-session-broker-v1";
pub const WINDOWS_GUARDIAN_PIPE_PREFIX: &str = r"\\.\pipe\memcordon-sealed-guardian-v1-";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRelayPhaseV1 {
    AwaitStreams,
    AwaitRelaysReady,
    AwaitAuthorizationOrAbort,
    Authorized,
    AwaitRelayAck,
    AwaitAbortRelayAck,
    AwaitTerminal,
    AwaitAbortRejection,
    Terminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsRelayEventV1 {
    StreamsPrepared,
    RelaysReady,
    TargetAuthorized,
    TargetRetired,
    RelaysAbort,
    RelaysRetired,
    Terminal,
    Reject,
    MutantHook,
    MutantTerminal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPublicFramePhaseV1 {
    Availability,
    Length,
    Payload,
    Decode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsPublicFrameFailureV1 {
    PeerClosed(WindowsPublicFramePhaseV1),
    Protocol(WindowsPublicFramePhaseV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsTerminalReplayDecisionV1 {
    ReplayOnce,
    FailClosed,
}

/// Transport-independent replay eligibility shared by every public frontend.
///
/// A transport loss is recoverable only after `StreamsPrepared` established an
/// exact attempt binding, and the reconnect budget is consumed before the
/// reconnect begins. Protocol/decode failures never cross a new trust boundary.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WindowsPublicTerminalRecoveryV1 {
    attempt_bound: bool,
    replay_consumed: bool,
    local_relays_retired: bool,
}

impl WindowsPublicTerminalRecoveryV1 {
    pub fn bind_attempt(&mut self) -> Result<(), &'static str> {
        if self.attempt_bound {
            return Err("Windows public terminal recovery binding is already active");
        }
        self.attempt_bound = true;
        Ok(())
    }

    pub fn observe_failure(
        &mut self,
        failure: WindowsPublicFrameFailureV1,
    ) -> WindowsTerminalReplayDecisionV1 {
        if matches!(failure, WindowsPublicFrameFailureV1::PeerClosed(_))
            && self.attempt_bound
            && !self.replay_consumed
        {
            self.replay_consumed = true;
            WindowsTerminalReplayDecisionV1::ReplayOnce
        } else {
            WindowsTerminalReplayDecisionV1::FailClosed
        }
    }

    pub fn begin_replay_after_bound_pending(&mut self) -> WindowsTerminalReplayDecisionV1 {
        if self.attempt_bound && !self.replay_consumed {
            self.replay_consumed = true;
            WindowsTerminalReplayDecisionV1::ReplayOnce
        } else {
            WindowsTerminalReplayDecisionV1::FailClosed
        }
    }

    pub const fn replay_consumed(self) -> bool {
        self.replay_consumed
    }

    /// Returns true exactly once, assigning local handle/event retirement to
    /// one owner even if recovery and Drop both try to retire the relays.
    pub fn retire_local_relays_once(&mut self) -> bool {
        if self.local_relays_retired {
            false
        } else {
            self.local_relays_retired = true;
            true
        }
    }
}

impl WindowsRelayPhaseV1 {
    pub fn advance(&mut self, event: WindowsRelayEventV1) -> Result<(), &'static str> {
        use WindowsRelayEventV1 as Event;
        use WindowsRelayPhaseV1 as Phase;

        *self = match (*self, event) {
            (Phase::AwaitStreams, Event::StreamsPrepared) => Phase::AwaitRelaysReady,
            (Phase::AwaitRelaysReady, Event::RelaysReady) => Phase::AwaitAuthorizationOrAbort,
            (Phase::AwaitAuthorizationOrAbort, Event::TargetAuthorized) => Phase::Authorized,
            (Phase::AwaitAuthorizationOrAbort, Event::RelaysAbort) => Phase::AwaitAbortRelayAck,
            (Phase::AwaitAuthorizationOrAbort, Event::MutantHook) => {
                Phase::AwaitAuthorizationOrAbort
            }
            (Phase::Authorized, Event::TargetRetired) => Phase::AwaitRelayAck,
            (Phase::AwaitRelayAck, Event::RelaysRetired) => Phase::AwaitTerminal,
            (Phase::AwaitAbortRelayAck, Event::RelaysRetired) => Phase::AwaitAbortRejection,
            (Phase::AwaitTerminal, Event::Terminal) => Phase::Terminal,
            (Phase::AwaitStreams, Event::Reject)
            | (Phase::AwaitRelaysReady, Event::Reject)
            | (Phase::AwaitAuthorizationOrAbort, Event::Reject)
            | (Phase::Authorized, Event::Reject)
            | (Phase::AwaitRelayAck, Event::Reject)
            | (Phase::AwaitAbortRelayAck, Event::Reject)
            | (Phase::AwaitTerminal, Event::Reject)
            | (Phase::AwaitAbortRejection, Event::Reject)
            | (Phase::AwaitStreams, Event::MutantTerminal)
            | (Phase::AwaitRelaysReady, Event::MutantTerminal)
            | (Phase::AwaitAuthorizationOrAbort, Event::MutantTerminal)
            | (Phase::Authorized, Event::MutantTerminal)
            | (Phase::AwaitRelayAck, Event::MutantTerminal)
            | (Phase::AwaitTerminal, Event::MutantTerminal) => Phase::Terminal,
            _ => return Err("invalid Windows relay protocol transition"),
        };
        Ok(())
    }
}

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
            && !self.nonce.is_empty()
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
pub struct WindowsPreauthorizationFaultMatrixEvidence<Rejection> {
    pub schema_version: u32,
    pub faults: Vec<WindowsSealedFault>,
    pub first_instruction_markers_absent: bool,
    pub recovery_clear_after_each_fault: bool,
    pub rejections: Vec<WindowsFaultRejectionObservation<Rejection>>,
    pub terminal_frame_truncation_rejected: bool,
}

pub type WindowsPreauthorizationFaultMatrixEvidenceV1 =
    WindowsPreauthorizationFaultMatrixEvidence<ProviderRejectionEvidence>;
pub type WindowsPreauthorizationFaultMatrixEvidenceV2 =
    WindowsPreauthorizationFaultMatrixEvidence<WindowsProviderRejectionV2>;

impl<Rejection: WindowsFaultRejection> WindowsPreauthorizationFaultMatrixEvidence<Rejection> {
    pub fn is_complete(&self) -> bool {
        self.schema_version == Rejection::MATRIX_SCHEMA_VERSION
            && self.faults == WINDOWS_PREAUTHORIZATION_FAULTS
            && self.first_instruction_markers_absent
            && self.recovery_clear_after_each_fault
            && fault_rejections_are_complete(&self.faults, &self.rejections, false)
            && self.terminal_frame_truncation_rejected
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRetirementFaultMatrixEvidence<Rejection> {
    pub schema_version: u32,
    pub faults: Vec<WindowsSealedFault>,
    pub first_instruction_markers_observed: bool,
    pub recovery_clear_after_each_fault: bool,
    pub rejections: Vec<WindowsFaultRejectionObservation<Rejection>>,
}

pub type WindowsRetirementFaultMatrixEvidenceV1 =
    WindowsRetirementFaultMatrixEvidence<ProviderRejectionEvidence>;
pub type WindowsRetirementFaultMatrixEvidenceV2 =
    WindowsRetirementFaultMatrixEvidence<WindowsProviderRejectionV2>;

impl<Rejection: WindowsFaultRejection> WindowsRetirementFaultMatrixEvidence<Rejection> {
    pub fn is_complete(&self) -> bool {
        self.schema_version == Rejection::MATRIX_SCHEMA_VERSION
            && self.faults == WINDOWS_RETIREMENT_FAULTS
            && self.first_instruction_markers_observed
            && self.recovery_clear_after_each_fault
            && fault_rejections_are_complete(&self.faults, &self.rejections, true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFaultRejectionObservation<Rejection> {
    pub fault: WindowsSealedFault,
    pub rejection: Rejection,
}

pub type WindowsFaultRejectionObservationV1 =
    WindowsFaultRejectionObservation<ProviderRejectionEvidence>;
pub type WindowsFaultRejectionObservationV2 =
    WindowsFaultRejectionObservation<WindowsProviderRejectionV2>;

pub trait WindowsFaultRejection {
    const MATRIX_SCHEMA_VERSION: u32;
    fn fault_code(&self) -> &str;
    fn target_released(&self) -> bool;
    fn is_consistent(&self) -> bool;
}

impl WindowsFaultRejection for ProviderRejectionEvidence {
    const MATRIX_SCHEMA_VERSION: u32 = 1;
    fn fault_code(&self) -> &str {
        &self.code
    }
    fn target_released(&self) -> bool {
        self.target_released
    }
    fn is_consistent(&self) -> bool {
        ProviderRejectionEvidence::is_consistent(self)
    }
}

impl WindowsFaultRejection for WindowsProviderRejectionV2 {
    const MATRIX_SCHEMA_VERSION: u32 = 2;
    fn fault_code(&self) -> &str {
        &self.code
    }
    fn target_released(&self) -> bool {
        self.target_released
    }
    fn is_consistent(&self) -> bool {
        WindowsProviderRejectionV2::is_consistent(self)
    }
}

fn fault_rejections_are_complete<Rejection: WindowsFaultRejection>(
    faults: &[WindowsSealedFault],
    observations: &[WindowsFaultRejectionObservation<Rejection>],
    target_released: bool,
) -> bool {
    observations.len() == faults.len()
        && observations
            .iter()
            .zip(faults)
            .all(|(observation, expected)| {
                observation.fault == *expected
                    && observation.rejection.fault_code() == "MCSEALED-WINDOWS-CERTIFICATION-FAULT"
                    && observation.rejection.target_released() == target_released
                    && observation.rejection.is_consistent()
            })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCertificationObservations<Rejection> {
    pub schema_version: u32,
    pub preauthorization: WindowsPreauthorizationFaultMatrixEvidence<Rejection>,
    pub retirement: WindowsRetirementFaultMatrixEvidence<Rejection>,
}

pub type WindowsCertificationObservationsV1 =
    WindowsCertificationObservations<ProviderRejectionEvidence>;
pub type WindowsCertificationObservationsV2 =
    WindowsCertificationObservations<WindowsProviderRejectionV2>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTokenScenarioEvidenceV1 {
    pub name: String,
    pub caller_envelope: WindowsCallerTokenEnvelopeV1,
    pub restricted_sid_count: u32,
    pub restricting_sids: Vec<String>,
    pub token_is_restricted: bool,
    pub write_restricted: bool,
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
        self.schema_version == 2
            && self.scenarios.len() == REQUIRED.len()
            && self
                .scenarios
                .iter()
                .zip(REQUIRED)
                .all(|(scenario, required)| {
                    let token_representation_valid = if required == "elevated-admin" {
                        scenario.caller_envelope.token_type == 1
                            && scenario.caller_envelope.impersonation_level == 0
                    } else {
                        scenario.caller_envelope.token_type == 2
                            && (2..=3).contains(&scenario.caller_envelope.impersonation_level)
                    };
                    if scenario.name != required
                        || !scenario.initial_target_token_matches_caller
                        || scenario.caller_envelope.appcontainer
                        || !token_representation_valid
                    {
                        return false;
                    }
                    match required {
                        "elevated-admin" => {
                            scenario.caller_envelope.elevated
                                && !scenario.token_is_restricted
                                && !scenario.write_restricted
                                && scenario.restricted_sid_count == 0
                                && scenario.restricting_sids.is_empty()
                        }
                        "ordinary-user" => {
                            !scenario.caller_envelope.elevated
                                && !scenario.write_restricted
                                && scenario.restricted_sid_count == 0
                                && scenario.restricting_sids.is_empty()
                        }
                        "restricted" => {
                            scenario.token_is_restricted
                                && !scenario.write_restricted
                                && scenario.restricted_sid_count == 1
                                && scenario.restricting_sids == ["S-1-5-12"]
                        }
                        "write-restricted" => {
                            scenario.token_is_restricted
                                && scenario.write_restricted
                                && scenario.restricted_sid_count == 1
                                && scenario.restricting_sids == ["S-1-5-33"]
                        }
                        "disabled-privileges" => {
                            scenario.enabled_sensitive_privilege_count == 0
                                && scenario.write_restricted
                                && scenario.restricted_sid_count == 1
                                && scenario.restricting_sids == ["S-1-5-33"]
                        }
                        "deny-only-admin" => {
                            scenario.administrator_deny_only
                                && scenario.token_is_restricted
                                && !scenario.write_restricted
                                && scenario.restricted_sid_count == 1
                                && scenario.restricting_sids == ["S-1-5-12"]
                        }
                        "low-integrity" => {
                            scenario.caller_envelope.integrity_level == "S-1-16-4096"
                                && scenario.token_is_restricted
                                && !scenario.write_restricted
                                && scenario.restricted_sid_count == 1
                                && scenario.restricting_sids == ["S-1-5-12"]
                        }
                        _ => false,
                    }
                })
            && self.appcontainer_rejected_before_target
            && (!self.different_session_supported || self.different_session_verified)
    }
}

impl<Rejection: WindowsFaultRejection> WindowsCertificationObservations<Rejection> {
    pub fn is_complete(&self) -> bool {
        self.schema_version == Rejection::MATRIX_SCHEMA_VERSION
            && self.preauthorization.is_complete()
            && self.retirement.is_complete()
    }
}

pub const WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT: usize = 6;

pub fn windows_certification_argument_prelude_len(mode: &[u16]) -> Option<usize> {
    if mode
        .iter()
        .copied()
        .eq("windows-certification-target".encode_utf16())
    {
        Some(3)
    } else if mode
        .iter()
        .copied()
        .eq("windows-certification-nested-target".encode_utf16())
    {
        Some(4)
    } else {
        None
    }
}

pub fn parse_windows_certification_frontend_handle_values(
    arguments: &[Vec<u16>],
) -> Result<Option<[u64; WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT]>, String> {
    let Some(mode) = arguments.first() else {
        return Ok(None);
    };
    String::from_utf16(mode).map_err(|error| error.to_string())?;
    let Some(prefix) = windows_certification_argument_prelude_len(mode) else {
        return Ok(None);
    };
    let values = arguments
        .get(prefix..)
        .ok_or_else(|| "frontend handle-canary arguments are absent".to_owned())?;
    if values.len() != WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT {
        return Err("frontend handle-canary inventory is not exact".to_owned());
    }
    let mut parsed = [0_u64; WINDOWS_CERTIFICATION_FRONTEND_CANARY_COUNT];
    for (index, value) in values.iter().enumerate() {
        parsed[index] = String::from_utf16(value)
            .map_err(|error| error.to_string())?
            .parse::<u64>()
            .map_err(|error| format!("frontend handle-canary value is invalid: {error}"))?;
    }
    Ok(Some(parsed))
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
                if cursor < command_line.len()
                    && !quoted
                    && matches!(command_line[cursor], value if value == b' ' as u16 || value == b'\t' as u16)
                {
                    break;
                }
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
        // CreateProcessW environment blocks retain the native =C: drive-directory
        // entries in addition to ordinary names, which cannot contain '='.
        let drive_directory = matches!(entry.name.as_slice(), [equals, drive, colon]
            if *equals == u16::from(b'=')
                && *colon == u16::from(b':')
                && ((u16::from(b'A')..=u16::from(b'Z')).contains(drive)
                    || (u16::from(b'a')..=u16::from(b'z')).contains(drive)));
        if entry.name.is_empty()
            || entry.name.contains(&0)
            || (entry.name.contains(&(b'=' as u16)) && !drive_directory)
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsAttemptTerminalDispositionV1 {
    PreauthorizationAbort,
    Posttarget,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDurableCleanupStateV1 {
    pub termination_requested: bool,
    pub active_processes_zero: bool,
    pub guardian_reaped: bool,
    pub final_handles_closed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsTerminalizationOwnerV1 {
    LauncherWorker,
    ControlService,
    StartupRecovery,
    GuardianRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsTerminalizationCheckpointV1 {
    Executing,
    CleanupRequested,
    CleanupProofReady,
    RejectionBuilding,
    OutboxStaging,
    OutboxStaged,
    AckRetiring,
    RetainedFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsTerminalizationErrorStageV1 {
    LaunchRelay,
    CleanupFinalize,
    ReceiptBuild,
    RejectionBuild,
    ResponseValidate,
    ResponseSerialize,
    RecordAuthenticate,
    AtomicStore,
    LiveDelivery,
    TerminalAck,
    OutboxRetirement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalizationErrorV1 {
    pub stage: WindowsTerminalizationErrorStageV1,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 128>")]
    pub error_code: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 2048>")]
    pub detail: String,
    pub native_code: Option<i32>,
    pub observed_unix_millis: Option<u64>,
}

impl WindowsTerminalizationErrorV1 {
    pub fn is_consistent(&self) -> bool {
        const MAX_CODE_BYTES: usize = 128;
        const MAX_DETAIL_BYTES: usize = 2 * 1024;
        !self.error_code.is_empty()
            && self.error_code.len() <= MAX_CODE_BYTES
            && self
                .error_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            && !self.detail.is_empty()
            && self.detail.len() <= MAX_DETAIL_BYTES
            && !self.detail.contains('\0')
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalizationStatusV1 {
    pub schema_version: u32,
    pub owner: WindowsTerminalizationOwnerV1,
    pub sequence: u64,
    pub checkpoint: WindowsTerminalizationCheckpointV1,
    /// The first causal terminalization failure. Later observers must not replace it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<WindowsTerminalizationErrorV1>,
    /// Later bounded observer/transport failures in durable causal order.
    #[serde(
        default,
        skip_serializing_if = "Vec::is_empty",
        deserialize_with = "deserialize_terminalization_errors"
    )]
    pub secondary_errors: Vec<WindowsTerminalizationErrorV1>,
}

fn deserialize_terminalization_errors<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<WindowsTerminalizationErrorV1>, D::Error> {
    crate::BoundedVec::<WindowsTerminalizationErrorV1, WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS>::deserialize(decoder)
        .map(|errors| errors.as_slice().to_vec())
}

impl WindowsTerminalizationStatusV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && self.sequence != 0
            && self
                .last_error
                .as_ref()
                .is_none_or(WindowsTerminalizationErrorV1::is_consistent)
            && self.secondary_errors.len() <= WINDOWS_MAX_TERMINALIZATION_SECONDARY_ERRORS
            && self
                .secondary_errors
                .iter()
                .all(WindowsTerminalizationErrorV1::is_consistent)
            && (self.checkpoint != WindowsTerminalizationCheckpointV1::RetainedFailure
                || self.last_error.is_some())
    }
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
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub attempt_id: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub provider_generation: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub boot_identity: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub caller_token_sha256: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::deserialize_record_outbox"
    )]
    pub terminal_response_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub diagnostic_retention: crate::DiagnosticRetentionV1,
    pub workload_admission: Option<crate::workload_registry::RuntimeAdmissionSnapshot>,
    pub workload_checkpoint: Option<(
        crate::workload_evidence::RuntimeAttemptBinding,
        crate::workload_evidence::VerifiedCheckpointV1,
    )>,
    pub record_revision: u64,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub provider_incarnation: String,
    #[serde(deserialize_with = "crate::deserialize_bounded_record_text::<_, 256>")]
    pub integrity_sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsTerminalLifecycleV1 {
    Executing,
    Retiring,
    ProofReady,
    OutboxStaged,
    AckCommitted,
    RetirementComplete,
    Retained,
    Quarantined,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalSeedV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub process_observation: crate::WindowsProcessObservationV2,
    pub primary_failure: Option<crate::ProviderFailureDiagnosticV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWorkerThreadIdentityV1 {
    pub thread_id: u32,
    pub creation_time_100ns: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsDurableAttemptRecordV4 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub provider_generation: String,
    pub boot_identity: String,
    pub launch_incarnation: String,
    pub nonce: String,
    pub request_sha256: String,
    pub caller_process_identity: WindowsProcessIdentityV1,
    pub caller_token_sha256: String,
    pub job_identity_sha256: String,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub worker_identity: Option<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_thread_identity: Option<WindowsWorkerThreadIdentityV1>,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub state: WindowsAttemptStateV1,
    pub lifecycle: WindowsTerminalLifecycleV1,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub owner_manifest: Option<crate::WindowsCapabilityOwnerManifestV1>,
    pub recovery_authorization: Option<crate::WindowsRecoveryAuthorizationV1>,
    pub terminal_publication_reserved: bool,
    pub terminal_seed: Option<WindowsTerminalSeedV2>,
    pub retirement_proof: Option<WindowsRetirementProofV2>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "crate::deserialize_record_outbox"
    )]
    pub terminal_response_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub diagnostic_retention: crate::DiagnosticRetentionV1,
    pub workload_admission: Option<crate::workload_registry::RuntimeAdmissionSnapshot>,
    pub workload_checkpoint: Option<(
        crate::workload_evidence::RuntimeAttemptBinding,
        crate::workload_evidence::VerifiedCheckpointV1,
    )>,
    pub record_revision: u64,
    pub provider_incarnation: String,
    pub integrity_sha256: String,
}

pub fn parse_and_authenticate_windows_attempt_record_v4(
    bytes: &[u8],
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<WindowsDurableAttemptRecordV4, &'static str> {
    if bytes.len() > WINDOWS_MAX_FRAME_BYTES
        || crate::validate_record_json_structure(bytes).is_err()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=structural-budget");
    }
    let mut record: WindowsDurableAttemptRecordV4 = serde_json::from_slice(bytes)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=json-invalid")?;
    authenticate_decoded_windows_attempt_record_v4(
        &mut record,
        expected_attempt_id,
        expected_provider_generation,
    )?;
    Ok(record)
}

pub fn authenticate_decoded_windows_attempt_record_v4(
    record: &mut WindowsDurableAttemptRecordV4,
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<(), &'static str> {
    if record.schema_version != 4
        || record.attempt_id != expected_attempt_id
        || record.provider_generation != expected_provider_generation
        || !windows_sha256_text_is_valid(&record.attempt_id)
        || !windows_sha256_text_is_valid(&record.request_sha256)
        || !windows_sha256_text_is_valid(&record.job_identity_sha256)
        || !windows_sha256_text_is_valid(&record.caller_token_sha256)
        || !windows_sha256_text_is_valid(&record.provider_incarnation)
        || record.boot_identity.is_empty()
        || record.launch_incarnation.is_empty()
        || record.nonce.is_empty()
        || record.record_revision == 0
        || !windows_process_identity_is_valid(&record.caller_process_identity)
        || record
            .guardian_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || record
            .worker_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || record
            .target_identity
            .as_ref()
            .is_some_and(|identity| !windows_process_identity_is_valid(identity))
        || !record.causal_diagnostics.is_consistent()
        || !record.diagnostic_retention.is_consistent()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=v4-binding");
    }
    if let Some(error) = windows_durable_attempt_v4_state_error(record) {
        return Err(error);
    }
    if let Some(manifest) = &record.owner_manifest {
        if manifest.validate().is_err()
            || manifest.attempt_id != record.attempt_id
            || manifest.provider_generation != record.provider_generation
            || manifest.launch_incarnation != record.launch_incarnation
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=owner-manifest");
        }
    }
    let preauthorization_abort_release = record.target_released
        && record.authorization_unix_millis.is_none()
        && !record.resume_attempted
        && record.terminal_disposition
            == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort);
    let authorized_intent = record.authorization_unix_millis.is_some()
        || record.resume_attempted
        || (record.target_released && !preauthorization_abort_release);
    if authorized_intent && record.owner_manifest.is_none() {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=owner-manifest-absent");
    }
    if record
        .recovery_authorization
        .as_ref()
        .is_some_and(|authorization| !authorization.is_consistent())
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=recovery-authorization");
    }
    if authorized_intent
        && (record.recovery_authorization.is_none()
            || !record.terminal_publication_reserved
            || record.worker_identity.is_none())
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=authorization-reservation");
    }
    if let Some(seed) = &record.terminal_seed {
        if seed.schema_version != 2
            || seed.attempt_id != record.attempt_id
            || seed.nonce != record.nonce
            || seed.request_sha256 != record.request_sha256
            || seed
                .process_observation
                .validate(&record.attempt_id, &record.nonce, &record.request_sha256)
                .is_err()
            || seed
                .primary_failure
                .as_ref()
                .is_some_and(|failure| !failure.is_consistent())
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-seed");
        }
    }
    if let Some(proof) = &record.retirement_proof {
        if proof.schema_version != 2
            || proof.attempt_id != record.attempt_id
            || proof.nonce != record.nonce
            || proof.request_sha256 != record.request_sha256
            || proof.provider_generation != record.provider_generation
            || proof.launch_incarnation != record.launch_incarnation
            || proof.original_boot_id != record.boot_identity
            || proof.job_identity != record.job_identity_sha256
            || record
                .owner_manifest
                .as_ref()
                .and_then(|manifest| manifest.canonical_sha256().ok())
                .as_deref()
                != Some(proof.owner_manifest_sha256.as_str())
        {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=retirement-proof");
        }
    }
    let has_complete_proof = record.terminal_seed.is_some() && record.retirement_proof.is_some();
    let proof_checkpoint_valid = match record.lifecycle {
        WindowsTerminalLifecycleV1::ProofReady => has_complete_proof,
        WindowsTerminalLifecycleV1::OutboxStaged
        | WindowsTerminalLifecycleV1::AckCommitted
        | WindowsTerminalLifecycleV1::RetirementComplete => {
            if record.terminal_disposition
                == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
            {
                record.terminal_seed.is_none() && record.retirement_proof.is_none()
            } else {
                has_complete_proof
            }
        }
        _ => true,
    };
    if !proof_checkpoint_valid {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=proof-checkpoint");
    }
    if matches!(
        record.lifecycle,
        WindowsTerminalLifecycleV1::OutboxStaged
            | WindowsTerminalLifecycleV1::AckCommitted
            | WindowsTerminalLifecycleV1::RetirementComplete
    ) && record.terminal_response_json.is_none()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-checkpoint");
    }
    if let Some(json) = &record.terminal_response_json {
        let response: WindowsLauncherResponseV3 = serde_json::from_str(json)
            .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-json")?;
        if !windows_terminal_outbox_is_bound_v3(record, &response) {
            return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=outbox-binding");
        }
    }
    let integrity = std::mem::take(&mut record.integrity_sha256);
    let mut canonical = crate::bounded_json_bytes(record, WINDOWS_MAX_FRAME_BYTES, false)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=canonicalization-failed")?;
    canonical.pop();
    let expected = windows_sha256(&canonical);
    record.integrity_sha256 = integrity;
    if record.integrity_sha256 != expected {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=integrity-digest");
    }
    Ok(())
}

fn windows_durable_attempt_v4_state_error(
    record: &WindowsDurableAttemptRecordV4,
) -> Option<&'static str> {
    let guardian_required = matches!(
        record.state,
        WindowsAttemptStateV1::GuardianReady
            | WindowsAttemptStateV1::TargetCreatedSuspended
            | WindowsAttemptStateV1::Authorized
    );
    let preauthorization_abort = !record.resume_attempted
        && record.authorization_unix_millis.is_none()
        && record.terminal_disposition
            == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
        && record.cleanup_state.termination_requested;
    let target_required = matches!(
        record.state,
        WindowsAttemptStateV1::TargetCreatedSuspended | WindowsAttemptStateV1::Authorized
    ) || record.resume_attempted
        || record.target_released;
    if guardian_required && record.guardian_identity.is_none() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-guardian-missing");
    }
    if target_required && record.target_identity.is_none() && !preauthorization_abort {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-target-missing");
    }
    if record.target_released && !record.resume_attempted && !preauthorization_abort {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-release-without-intent",
        );
    }
    if record.resume_attempted && record.authorization_unix_millis.is_none() {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-resume-without-authorization",
        );
    }
    if record.state == WindowsAttemptStateV1::Authorized
        && record.authorization_unix_millis.is_none()
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorized-without-timestamp",
        );
    }
    if record.authorization_unix_millis.is_some()
        && !matches!(
            record.state,
            WindowsAttemptStateV1::Authorized
                | WindowsAttemptStateV1::Terminating
                | WindowsAttemptStateV1::Empty
        )
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorization-before-state",
        );
    }
    if record.terminal_disposition
        == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && !matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-abort-before-termination",
        );
    }
    if record.cleanup_state.final_handles_closed
        && !(record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.state == WindowsAttemptStateV1::Empty)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-final-handles-before-empty",
        );
    }
    if !record.terminalization.is_consistent() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-status");
    }
    if record.terminal_response_json.is_some()
        != (record.terminalization.checkpoint == WindowsTerminalizationCheckpointV1::OutboxStaged)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-outbox-checkpoint",
        );
    }
    if matches!(
        record.terminalization.checkpoint,
        WindowsTerminalizationCheckpointV1::CleanupProofReady
            | WindowsTerminalizationCheckpointV1::RejectionBuilding
            | WindowsTerminalizationCheckpointV1::OutboxStaging
            | WindowsTerminalizationCheckpointV1::OutboxStaged
            | WindowsTerminalizationCheckpointV1::AckRetiring
    ) && record.state != WindowsAttemptStateV1::Empty
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-checkpoint-before-empty",
        );
    }
    if record.terminal_response_json.is_some()
        && (record.state != WindowsAttemptStateV1::Empty || record.terminal_disposition.is_none())
    {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-before-empty");
    }
    None
}

pub fn windows_terminal_outbox_is_bound_v3(
    record: &WindowsDurableAttemptRecordV4,
    response: &WindowsLauncherResponseV3,
) -> bool {
    let receipt_bound = |receipt: &WindowsTerminalReceiptV2| {
        receipt.attempt_id == record.attempt_id
            && receipt.nonce == record.nonce
            && receipt.request_sha256 == record.request_sha256
            && record.retirement_proof.as_ref() == Some(&receipt.retirement_proof)
            && receipt.validate_for_attempt().is_ok()
    };
    match response {
        WindowsLauncherResponseV3::Terminal(receipt) => {
            record.terminal_disposition == Some(WindowsAttemptTerminalDispositionV1::Posttarget)
                && receipt_bound(receipt)
        }
        WindowsLauncherResponseV3::Reject {
            attempt_id,
            nonce,
            request_sha256,
            rejection,
            ..
        } => {
            attempt_id == &record.attempt_id
                && nonce == &record.nonce
                && request_sha256 == &record.request_sha256
                && rejection.is_consistent()
                && match (record.terminal_disposition, &rejection.disposition) {
                    (
                        Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort),
                        WindowsProviderRejectionDispositionV2::Preauthorization { .. },
                    ) => true,
                    (
                        Some(WindowsAttemptTerminalDispositionV1::Posttarget),
                        WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt },
                    ) => receipt_bound(receipt),
                    _ => false,
                }
        }
        _ => false,
    }
}

pub fn parse_and_authenticate_windows_attempt_record(
    bytes: &[u8],
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<WindowsDurableAttemptRecordV1, &'static str> {
    if bytes.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=frame-too-large");
    }
    crate::validate_record_json_structure(bytes)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=structural-budget")?;
    if !windows_sha256_text_is_valid(expected_attempt_id) {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=expected-attempt-id-shape");
    }
    if expected_provider_generation.is_empty() {
        return Err(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=expected-provider-generation-empty",
        );
    }
    let mut record: WindowsDurableAttemptRecordV1 = serde_json::from_slice(bytes)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=json-invalid")?;
    authenticate_decoded_windows_attempt_record(
        &mut record,
        expected_attempt_id,
        expected_provider_generation,
    )?;
    Ok(record)
}

pub fn authenticate_decoded_windows_attempt_record(
    record: &mut WindowsDurableAttemptRecordV1,
    expected_attempt_id: &str,
    expected_provider_generation: &str,
) -> Result<(), &'static str> {
    if !windows_sha256_text_is_valid(expected_attempt_id) || expected_provider_generation.is_empty()
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=expected-binding-shape");
    }
    let integrity = std::mem::take(&mut record.integrity_sha256);
    struct CanonicalHash {
        digest: Sha256,
        remaining: usize,
    }
    impl std::io::Write for CanonicalHash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > self.remaining {
                return Err(std::io::Error::other("canonical record exceeds bound"));
            }
            self.remaining -= bytes.len();
            self.digest.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut canonical = CanonicalHash {
        digest: Sha256::new(),
        remaining: WINDOWS_MAX_FRAME_BYTES,
    };
    serde_json::to_writer(&mut canonical, &record)
        .map_err(|_| "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=canonicalization-failed")?;
    let expected_integrity = canonical
        .digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    record.integrity_sha256 = integrity;
    if record.schema_version != 3 {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=schema-version");
    }
    if !record.causal_diagnostics.is_consistent()
        || !record.diagnostic_retention.is_consistent()
        || record.workload_admission.as_ref().is_some_and(|snapshot| {
            snapshot.validate().is_err()
                || String::from(snapshot.private_invocation_digest.clone()) != record.request_sha256
                || !matches!(
                    snapshot.caller,
                    crate::workload_registry::CallerSelector::Windows { .. }
                )
        })
        || record
            .workload_checkpoint
            .as_ref()
            .is_some_and(|(binding, checkpoint)| {
                !record
                    .workload_admission
                    .as_ref()
                    .is_some_and(|snapshot| binding.matches_snapshot(snapshot))
                    || binding.attempt_id.as_str() != record.attempt_id
                    || !checkpoint.matches_binding(binding)
            })
        || !windows_sha256_text_is_valid(&record.provider_incarnation)
        || record.record_revision == 0
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=diagnostic-state");
    }
    if record.attempt_id != expected_attempt_id {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=attempt-id-binding");
    }
    if record.provider_generation != expected_provider_generation {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=provider-generation");
    }
    if record.integrity_sha256 != expected_integrity {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=integrity-digest");
    }
    if !windows_sha256_text_is_valid(&record.request_sha256) {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=request-digest-shape");
    }
    if !windows_sha256_text_is_valid(&record.caller_token_sha256) {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=caller-token-digest-shape");
    }
    if !windows_sha256_text_is_valid(&record.job_identity_sha256) {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=job-identity-digest-shape");
    }
    if record.boot_identity.is_empty() {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=boot-identity-empty");
    }
    if !windows_process_identity_is_valid(&record.caller_process_identity) {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=caller-process-identity");
    }
    if !record
        .guardian_identity
        .as_ref()
        .is_none_or(windows_process_identity_is_valid)
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=guardian-process-identity");
    }
    if !record
        .target_identity
        .as_ref()
        .is_none_or(windows_process_identity_is_valid)
    {
        return Err("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=target-process-identity");
    }
    if let Some(error) = windows_durable_attempt_state_error(record) {
        return Err(error);
    }
    Ok(())
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

fn windows_durable_attempt_state_error(
    record: &WindowsDurableAttemptRecordV1,
) -> Option<&'static str> {
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
    let preauthorization_abort = !record.resume_attempted
        && record.authorization_unix_millis.is_none()
        && record.terminal_disposition
            == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
        && record.cleanup_state.termination_requested;
    let preauthorization_abort_release = record.target_released && preauthorization_abort;
    if guardian_required && record.guardian_identity.is_none() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-guardian-missing");
    }
    if target_required && record.target_identity.is_none() && !preauthorization_abort {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-target-missing");
    }
    if record.target_released && !record.resume_attempted && !preauthorization_abort_release {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-release-without-intent",
        );
    }
    if record.resume_attempted && record.authorization_unix_millis.is_none() {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-resume-without-authorization",
        );
    }
    if record.state == WindowsAttemptStateV1::Authorized
        && record.authorization_unix_millis.is_none()
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorized-without-timestamp",
        );
    }
    if record.authorization_unix_millis.is_some() && !authorization_permitted {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-authorization-before-state",
        );
    }
    if record.terminal_disposition
        == Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort)
        && !matches!(
            record.state,
            WindowsAttemptStateV1::Terminating | WindowsAttemptStateV1::Empty
        )
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-abort-before-termination",
        );
    }
    if record.cleanup_state.final_handles_closed
        && !(record.cleanup_state.termination_requested
            && record.cleanup_state.active_processes_zero
            && record.cleanup_state.guardian_reaped
            && record.state == WindowsAttemptStateV1::Empty)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=lifecycle-final-handles-before-empty",
        );
    }
    if !record.terminalization.is_consistent() {
        return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-status");
    }
    let outbox_staged = record.terminal_response_json.is_some();
    if outbox_staged
        != (record.terminalization.checkpoint == WindowsTerminalizationCheckpointV1::OutboxStaged)
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-outbox-checkpoint",
        );
    }
    if matches!(
        record.terminalization.checkpoint,
        WindowsTerminalizationCheckpointV1::CleanupProofReady
            | WindowsTerminalizationCheckpointV1::RejectionBuilding
            | WindowsTerminalizationCheckpointV1::OutboxStaging
            | WindowsTerminalizationCheckpointV1::OutboxStaged
            | WindowsTerminalizationCheckpointV1::AckRetiring
    ) && record.state != WindowsAttemptStateV1::Empty
    {
        return Some(
            "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminalization-checkpoint-before-empty",
        );
    }
    if let Some(json) = record.terminal_response_json.as_ref() {
        if json.len() > WINDOWS_MAX_FRAME_BYTES / 2 {
            return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-size");
        }
        if crate::validate_record_json_structure(json.as_bytes()).is_err() {
            return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-structural-budget");
        }
        if record.state != WindowsAttemptStateV1::Empty {
            return Some(
                "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-before-empty",
            );
        }
        if record.terminal_disposition.is_none() {
            return Some(
                "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-without-disposition",
            );
        }
        if !serde_json::from_str::<WindowsLauncherResponseV1>(json).is_ok_and(|response| {
            !matches!(&response, WindowsLauncherResponseV1::Reject { rejection, .. } if rejection.provider_failure.is_some()) && windows_terminal_outbox_is_bound(
                &record.attempt_id,
                &record.request_sha256,
                record.terminal_disposition,
                &response,
            )
        }) {
            return Some("MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=terminal-outbox-binding");
        }
    }
    None
}

pub fn windows_terminal_outbox_is_bound(
    attempt_id: &str,
    request_sha256: &str,
    terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    response: &WindowsLauncherResponseV1,
) -> bool {
    match response {
        WindowsLauncherResponseV1::Terminal(receipt) => {
            terminal_disposition == Some(WindowsAttemptTerminalDispositionV1::Posttarget)
                && receipt.attempt_id == attempt_id
                && receipt.request_sha256 == request_sha256
                && receipt.process_identity_inventory_shape_is_bounded()
        }
        WindowsLauncherResponseV1::Reject {
            attempt_id: response_attempt_id,
            request_sha256: response_request_sha256,
            rejection,
            ..
        } => {
            let disposition_matches = match terminal_disposition {
                Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort) => {
                    rejection.terminal_ack_required && rejection.terminal_receipt.is_none()
                }
                Some(WindowsAttemptTerminalDispositionV1::Posttarget) => {
                    rejection.terminal_receipt.as_ref().is_some_and(|receipt| {
                        receipt.attempt_id == attempt_id && receipt.request_sha256 == request_sha256
                    })
                }
                None => false,
            };
            response_attempt_id == attempt_id
                && response_request_sha256 == request_sha256
                && rejection.is_consistent()
                && disposition_matches
        }
        _ => false,
    }
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
    if value.is_empty() || value.contains('\0') {
        return Err("Windows security descriptor text has an invalid prefix or NUL");
    }

    fn component<'a>(
        value: &'a str,
        following: &[&str],
        malformed: &'static str,
    ) -> Result<(&'a str, &'a str), &'static str> {
        let boundary = following
            .iter()
            .filter_map(|marker| value.find(marker))
            .min()
            .ok_or(malformed)?;
        let (component, remaining) = value.split_at(boundary);
        if component.is_empty() || component.contains(['(', ')', ':']) {
            return Err(malformed);
        }
        Ok((component, remaining))
    }

    let mut remaining = value;
    if let Some(without_owner) = remaining.strip_prefix("O:") {
        let (_, after_owner) = component(
            without_owner,
            &["G:", "D:"],
            "Windows security descriptor owner is malformed",
        )?;
        remaining = after_owner;
    }
    if let Some(without_group) = remaining.strip_prefix("G:") {
        let (_, after_group) = component(
            without_group,
            &["D:"],
            "Windows security descriptor group is malformed",
        )?;
        remaining = after_group;
    }
    let Some(mut dacl) = remaining.strip_prefix("D:") else {
        return Err("Windows security descriptor text is missing an ordered DACL");
    };
    if let Some((before_sacl, sacl)) = dacl.split_once("S:") {
        if sacl.contains(':') {
            return Err("Windows security descriptor SACL has a malformed component delimiter");
        }
        dacl = before_sacl;
    }
    if dacl.contains(':') {
        return Err("Windows security descriptor DACL has a malformed component delimiter");
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
pub struct WindowsServiceSelfAttestationV1 {
    pub schema_version: u32,
    pub challenge: String,
    pub service_name: String,
    pub process_identity: WindowsProcessIdentityV1,
    pub service_sid: String,
    pub service_sid_enabled: bool,
    pub service_sid_restricted: bool,
    pub token_session_id: u32,
    pub required_privileges: Vec<String>,
}

impl WindowsServiceSelfAttestationV1 {
    pub fn validate_for(
        &self,
        expected_challenge: &str,
        expected_service_name: &str,
        expected_process_identity: &WindowsProcessIdentityV1,
        expected_service_sid: &str,
        expected_privileges: &[&str],
    ) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("service attestation has the wrong schema version");
        }
        if !windows_sha256_text_is_valid(expected_challenge) || self.challenge != expected_challenge
        {
            return Err("service attestation challenge does not match");
        }
        if self.service_name != expected_service_name {
            return Err("service attestation service name does not match");
        }
        if self.process_identity != *expected_process_identity
            || !windows_process_identity_is_valid(&self.process_identity)
        {
            return Err("service attestation process identity does not match");
        }
        if self.service_sid != expected_service_sid {
            return Err("service attestation service SID does not match");
        }
        if !self.service_sid_enabled {
            return Err("service attestation lacks the enabled service SID");
        }
        if !self.service_sid_restricted {
            return Err("service attestation lacks the restricting service SID");
        }
        if self.required_privileges.len() != expected_privileges.len()
            || !self
                .required_privileges
                .iter()
                .zip(expected_privileges)
                .all(|(actual, expected)| actual == expected)
        {
            return Err("service attestation required privileges do not match");
        }
        Ok(())
    }
}

pub fn windows_service_attestation_challenge_is_valid(challenge: &str) -> bool {
    windows_sha256_text_is_valid(challenge)
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
    pub restart_attempt: u64,
    pub schema_version: u32,
    pub expected_provider_binding: crate::PublicProviderBindingV1,
    #[serde(default, deserialize_with = "deserialize_workload_contract")]
    pub workload_contract: Option<crate::workload_contract::WorkloadContractV1>,
    pub nonce: String,
    pub command: NativeWindowsCommandV1,
    pub environment: Vec<WindowsEnvironmentEntryV1>,
    pub current_directory: Vec<u16>,
    pub policy: WindowsLaunchPolicyV1,
}

fn deserialize_workload_contract<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<crate::workload_contract::WorkloadContractV1>, D::Error> {
    let contract =
        Option::<crate::workload_contract::WorkloadContractV1>::deserialize(deserializer)?;
    if let Some(contract) = &contract {
        contract.validate().map_err(serde::de::Error::custom)?;
    }
    Ok(contract)
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
    WorkloadDiscovery {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
    },
    WorkloadPlan {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
        contract: crate::workload_contract::WorkloadContractV1,
    },
    Probe {
        schema_version: u32,
    },
    RecoveryStatus {
        schema_version: u32,
        challenge: String,
    },
    PackageCleanup {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
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
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsReadOnlyQueryOperation {
    GuardianObservation,
    RecoveryConvergence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsReadOnlyQueryPhase {
    StateHardening,
    QueryHandler,
}

/// A failed authenticated query, never an association or permission to act.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReadOnlyQueryFailure {
    pub format: String,
    pub revision: u32,
    pub operation: WindowsReadOnlyQueryOperation,
    pub challenge: crate::BoundedText<128>,
    pub provider: crate::PublicProviderBindingV1,
    pub phase: WindowsReadOnlyQueryPhase,
    pub detail: crate::BoundedText<1024>,
    pub detail_truncated: bool,
}

impl WindowsReadOnlyQueryFailure {
    pub const MAX_FRAME_BYTES: usize = 16 * 1024;

    pub fn new(
        operation: WindowsReadOnlyQueryOperation,
        challenge: crate::BoundedText<128>,
        provider: crate::PublicProviderBindingV1,
        phase: WindowsReadOnlyQueryPhase,
        detail: &str,
    ) -> Result<Self, String> {
        let mut end = detail.len().min(1024);
        while !detail.is_char_boundary(end) {
            end -= 1;
        }
        let value = Self {
            format: "memcordon.windows-read-only-query-failure".into(),
            revision: 1,
            operation,
            challenge,
            provider,
            phase,
            detail: crate::BoundedText::new(&detail[..end]).map_err(str::to_owned)?,
            detail_truncated: end != detail.len(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.format != "memcordon.windows-read-only-query-failure"
            || self.revision != 1
            || self.challenge.as_str().is_empty()
            || self.detail.as_str().is_empty()
            || !self.provider.is_consistent()
        {
            return Err("read-only query failure namespace or binding is invalid".into());
        }
        Ok(())
    }

    pub fn error_for(
        &self,
        operation: WindowsReadOnlyQueryOperation,
        challenge: &str,
        provider: &crate::PublicProviderBindingV1,
    ) -> Result<String, String> {
        self.validate()?;
        if self.operation != operation
            || self.challenge.as_str() != challenge
            || self.provider != *provider
        {
            return Err("read-only query failure differs from authenticated query".into());
        }
        Ok(format!(
            "Windows read-only query failed at {:?}: {}{}",
            self.phase,
            self.detail.as_str(),
            if self.detail_truncated {
                " [detail truncated]"
            } else {
                ""
            },
        ))
    }
}

/// Read-only association of an actually held live guardian with its native attempt.
/// This observation neither authorizes execution nor changes the record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsGuardianAttemptObservation {
    pub format: String,
    pub revision: u32,
    pub challenge: crate::BoundedText<128>,
    pub guardian_identity: WindowsProcessIdentityV1,
    pub association: crate::result_v1::ProviderAttemptAssociationV1,
}

impl WindowsGuardianAttemptObservation {
    pub const MAX_FRAME_BYTES: usize = 16 * 1024;

    /// Join the authenticated launcher owner's facts to the exact public query.
    /// A private error reply cannot become a successful observation.
    pub fn from_launcher_query_response(
        response: WindowsLauncherResponseV3,
        challenge: &str,
        provider: &crate::PublicProviderBindingV1,
        guardian: &WindowsProcessIdentityV1,
    ) -> Result<Self, String> {
        match response {
            WindowsLauncherResponseV3::GuardianAttemptObservation(value) => {
                if !value.is_consistent()
                    || value.challenge.as_str() != challenge
                    || value.association.provider != *provider
                    || value.guardian_identity != *guardian
                {
                    return Err(
                        "launcher guardian observation differs from authenticated query".into(),
                    );
                }
                Ok(value)
            }
            WindowsLauncherResponseV3::ReadOnlyQueryFailure(value) => Err(value.error_for(
                WindowsReadOnlyQueryOperation::GuardianObservation,
                challenge,
                provider,
            )?),
            _ => Err("launcher did not return a guardian query response".into()),
        }
    }

    /// The dedicated query can return only an observation or a bound error.
    /// A failure is always propagated as Err, never accepted as an observation.
    pub fn from_query_wire_json(
        bytes: &[u8],
        challenge: &str,
        provider: &crate::PublicProviderBindingV1,
    ) -> Result<Self, String> {
        if bytes.len() > Self::MAX_FRAME_BYTES {
            return Err("live guardian observation frame exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Reply {
            Observation(WindowsGuardianAttemptObservation),
            Failure(WindowsReadOnlyQueryFailure),
        }
        match serde_json::from_slice::<Reply>(bytes).map_err(|error| error.to_string())? {
            Reply::Observation(value) => {
                if !value.is_consistent()
                    || value.challenge.as_str() != challenge
                    || value.association.provider != *provider
                {
                    return Err("live guardian observation differs from authenticated query".into());
                }
                Ok(value)
            }
            Reply::Failure(value) => Err(value.error_for(
                WindowsReadOnlyQueryOperation::GuardianObservation,
                challenge,
                provider,
            )?),
        }
    }

    /// Decode the dedicated observation wire shape, never a provider response enum.
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > Self::MAX_FRAME_BYTES {
            return Err("live guardian observation frame exceeds bound".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let observation: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if !observation.is_consistent() {
            return Err("live guardian observation is inconsistent".into());
        }
        Ok(observation)
    }

    pub fn is_consistent(&self) -> bool {
        self.format == "memcordon.windows-live-guardian-observation"
            && self.revision == 1
            && !self.challenge.as_str().is_empty()
            && self.guardian_identity.process_id != 0
            && self.guardian_identity.creation_time_100ns != 0
            && self.association.provider.is_consistent()
            && self.association.attempt_id != crate::DiagnosticSha256::from_bytes([0; 32])
            && self.association.request_sha256 != crate::DiagnosticSha256::from_bytes([0; 32])
    }
}

/// Live public protocol requests. V1 remains an explicit historical decoder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderRequestV3 {
    WorkloadDiscovery {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
    },
    WorkloadPlan {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
        contract: crate::workload_contract::WorkloadContractV1,
    },
    Probe {
        schema_version: u32,
    },
    ObserveGuardianAttempt {
        schema_version: u32,
        challenge: String,
        guardian_identity: WindowsProcessIdentityV1,
    },
    RecoveryStatus {
        schema_version: u32,
        challenge: String,
    },
    RecoverAttempt {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        challenge: String,
    },
    ConvergeRecovery {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
    },
    PackageCleanup {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
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
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsControlRequestStatusV1 {
    Ready,
    Active,
    Failed,
}

/// Authenticated launcher evidence retained across both package cleanup boundaries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPackageCleanupOutcomeV1 {
    pub status: WindowsControlRequestStatusV1,
    pub attempts_empty: Option<bool>,
    pub terminal_outboxes: Option<u32>,
    pub detail: String,
}

impl WindowsPackageCleanupOutcomeV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        match (self.status, self.attempts_empty, self.terminal_outboxes) {
            (WindowsControlRequestStatusV1::Ready, Some(true), Some(0))
            | (WindowsControlRequestStatusV1::Active, Some(false), Some(_)) => Ok(()),
            (_, Some(true), Some(count)) if count != 0 => {
                Err("empty attempts contradict authenticated terminal outboxes")
            }
            (WindowsControlRequestStatusV1::Failed, _, _) => Ok(()),
            _ => Err(
                "package cleanup requires consistent authenticated attempt and inventory evidence",
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsProviderReplacementQuiescenceV1 {
    ProviderJobsNotTerminated,
    ProviderJobStillActive,
    DurableRecoveryStillActive,
    ReadyForReplacement,
}

pub fn windows_provider_replacement_quiescence(
    provider_jobs_terminated: bool,
    provider_jobs_observed_empty: bool,
    durable_recovery_empty: bool,
) -> WindowsProviderReplacementQuiescenceV1 {
    match (
        provider_jobs_terminated,
        provider_jobs_observed_empty,
        durable_recovery_empty,
    ) {
        (false, _, _) => WindowsProviderReplacementQuiescenceV1::ProviderJobsNotTerminated,
        (true, false, _) => WindowsProviderReplacementQuiescenceV1::ProviderJobStillActive,
        (true, true, false) => WindowsProviderReplacementQuiescenceV1::DurableRecoveryStillActive,
        (true, true, true) => WindowsProviderReplacementQuiescenceV1::ReadyForReplacement,
    }
}

impl WindowsProviderReplacementQuiescenceV1 {
    pub fn phase(self) -> &'static str {
        match self {
            Self::ProviderJobsNotTerminated => "provider-jobs-not-terminated",
            Self::ProviderJobStillActive => "provider-job-still-active",
            Self::DurableRecoveryStillActive => "durable-recovery-still-active",
            Self::ReadyForReplacement => "ready-for-replacement",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttemptRetainedV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub relay_phase: WindowsRelayPhaseV1,
    pub durable_state: Option<WindowsAttemptStateV1>,
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub cleanup_complete: bool,
    pub terminal_replay_available: bool,
    pub authority_retained: bool,
    pub primary_detail: String,
    pub secondary_failures: Vec<String>,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub diagnostic_availability: crate::DiagnosticProjectionAvailabilityV1,
}

impl WindowsAttemptRetainedV1 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 2
            && self.provider_failure.is_some()
                == (self.diagnostic_availability
                    == crate::DiagnosticProjectionAvailabilityV1::Available)
            && self.causal_diagnostics.is_consistent()
            && self.provider_failure.as_ref().is_none_or(|failure| {
                failure.is_consistent()
                    && failure.projection_sha256 == failure.canonical_digest()
                    && failure.matches_journal(
                        &self.attempt_id,
                        &self.request_sha256,
                        &self.causal_diagnostics,
                    )
            })
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && !self.nonce.is_empty()
            && self.request_sha256 == request_sha256
            && self.relay_phase == relay_phase
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && self.authority_retained
            && !self.primary_detail.is_empty()
            && self
                .secondary_failures
                .iter()
                .all(|failure| !failure.is_empty())
            && (!self.cleanup_complete || self.durable_state == Some(WindowsAttemptStateV1::Empty))
            && (!self.terminal_replay_available
                || (self.cleanup_complete && self.terminal_disposition.is_some()))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsReplayOutboxStageV1 {
    NotAttempted,
    Attempting,
    Failed,
    Staged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReplayPendingV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub relay_phase: WindowsRelayPhaseV1,
    pub durable_state: WindowsAttemptStateV1,
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub authorization_present: bool,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub cleanup_complete: bool,
    pub outbox_stage: WindowsReplayOutboxStageV1,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub detail: String,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub diagnostic_availability: crate::DiagnosticProjectionAvailabilityV1,
}

impl WindowsReplayPendingV1 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 3
            && self.provider_failure.is_some()
                == (self.diagnostic_availability
                    == crate::DiagnosticProjectionAvailabilityV1::Available)
            && self.causal_diagnostics.is_consistent()
            && self.provider_failure.as_ref().is_none_or(|failure| {
                failure.is_consistent()
                    && failure.projection_sha256 == failure.canonical_digest()
                    && failure.matches_journal(
                        &self.attempt_id,
                        &self.request_sha256,
                        &self.causal_diagnostics,
                    )
            })
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.relay_phase == relay_phase
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && !self.detail.is_empty()
            && self.terminalization.is_consistent()
            && self.cleanup_complete
                == (self.durable_state == WindowsAttemptStateV1::Empty
                    && self.cleanup_state.termination_requested
                    && self.cleanup_state.active_processes_zero
                    && self.cleanup_state.guardian_reaped
                    && self.cleanup_state.final_handles_closed)
            && (!self.cleanup_complete || self.durable_state == WindowsAttemptStateV1::Empty)
    }
}

/// Explicitly unresolved retirement obligation; absence is never interpreted
/// as proof that the corresponding native action happened.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsMissingRetirementProofV1 {
    TerminalSeed,
    NativeJobEmpty,
    GuardianReceipt,
    RelayClosure,
    OwnerCapabilityClosure,
    RecoveryAuthorization,
    OwnerManifest,
    DurableOutbox,
    Ack,
    RetirementLedger,
}

fn missing_proofs_valid(proofs: &[WindowsMissingRetirementProofV1]) -> bool {
    proofs.len() <= 10
        && proofs
            .iter()
            .enumerate()
            .all(|(index, proof)| !proofs[..index].contains(proof))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRetainedRecordUnavailableReasonV1 {
    Preadmission,
    ReadFailure,
    ParseFailure,
    AuthenticationFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsRetainedRecordBindingV1 {
    Bound {
        provider_generation: String,
        launch_incarnation: String,
        boot_identity: String,
        job_identity: String,
        owner_manifest_sha256: Option<String>,
    },
    Unavailable {
        reason: WindowsRetainedRecordUnavailableReasonV1,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAttemptRetainedV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub record_binding: WindowsRetainedRecordBindingV1,
    pub relay_phase: WindowsRelayPhaseV1,
    pub durable_state: Option<WindowsAttemptStateV1>,
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub checkpoint: WindowsTerminalLifecycleV1,
    pub missing_proofs: Vec<WindowsMissingRetirementProofV1>,
    pub cleanup_complete: bool,
    pub terminal_replay_available: bool,
    pub authority_retained: bool,
    pub primary_detail: String,
    pub secondary_failures: Vec<String>,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub diagnostic_availability: crate::DiagnosticProjectionAvailabilityV1,
}

impl WindowsAttemptRetainedV2 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 3
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.relay_phase == relay_phase
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && !self.nonce.is_empty()
            && match &self.record_binding {
                WindowsRetainedRecordBindingV1::Bound {
                    provider_generation,
                    launch_incarnation,
                    boot_identity,
                    job_identity,
                    owner_manifest_sha256,
                } => {
                    !provider_generation.is_empty()
                        && !launch_incarnation.is_empty()
                        && !boot_identity.is_empty()
                        && windows_sha256_text_is_valid(job_identity)
                        && owner_manifest_sha256
                            .as_deref()
                            .is_none_or(windows_sha256_text_is_valid)
                }
                WindowsRetainedRecordBindingV1::Unavailable { .. } => {
                    self.durable_state.is_none()
                        && self.terminal_disposition.is_none()
                        && !self.cleanup_complete
                        && !self.terminal_replay_available
                        && self
                            .missing_proofs
                            .contains(&WindowsMissingRetirementProofV1::OwnerManifest)
                }
            }
            && missing_proofs_valid(&self.missing_proofs)
            && self.checkpoint != WindowsTerminalLifecycleV1::RetirementComplete
            && self.authority_retained
            && !self.primary_detail.is_empty()
            && self
                .secondary_failures
                .iter()
                .all(|failure| !failure.is_empty())
            && self.causal_diagnostics.is_consistent()
            && self.provider_failure.is_some()
                == (self.diagnostic_availability
                    == crate::DiagnosticProjectionAvailabilityV1::Available)
            && self.provider_failure.as_ref().is_none_or(|failure| {
                failure.is_consistent()
                    && failure.projection_sha256 == failure.canonical_digest()
                    && failure.matches_journal(
                        &self.attempt_id,
                        &self.request_sha256,
                        &self.causal_diagnostics,
                    )
            })
            && (!self.cleanup_complete || self.durable_state == Some(WindowsAttemptStateV1::Empty))
            && (!self.terminal_replay_available
                || (self.cleanup_complete && self.terminal_disposition.is_some()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsReplayPendingV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub boot_identity: String,
    pub job_identity: String,
    pub owner_manifest_sha256: Option<String>,
    pub relay_phase: WindowsRelayPhaseV1,
    pub durable_state: WindowsAttemptStateV1,
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
    pub checkpoint: WindowsTerminalLifecycleV1,
    pub missing_proofs: Vec<WindowsMissingRetirementProofV1>,
    pub authorization_present: bool,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub cleanup_complete: bool,
    pub outbox_stage: WindowsReplayOutboxStageV1,
    pub terminalization: WindowsTerminalizationStatusV1,
    pub detail: String,
    pub causal_diagnostics: crate::WindowsCausalDiagnosticsV1,
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub diagnostic_availability: crate::DiagnosticProjectionAvailabilityV1,
}

impl WindowsReplayPendingV2 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 4
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.relay_phase == relay_phase
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && !self.nonce.is_empty()
            && !self.provider_generation.is_empty()
            && !self.launch_incarnation.is_empty()
            && !self.boot_identity.is_empty()
            && windows_sha256_text_is_valid(&self.job_identity)
            && self
                .owner_manifest_sha256
                .as_deref()
                .is_none_or(windows_sha256_text_is_valid)
            && missing_proofs_valid(&self.missing_proofs)
            && self.checkpoint != WindowsTerminalLifecycleV1::RetirementComplete
            && !self.detail.is_empty()
            && self.terminalization.is_consistent()
            && self.causal_diagnostics.is_consistent()
            && self.provider_failure.is_some()
                == (self.diagnostic_availability
                    == crate::DiagnosticProjectionAvailabilityV1::Available)
            && self.provider_failure.as_ref().is_none_or(|failure| {
                failure.is_consistent()
                    && failure.projection_sha256 == failure.canonical_digest()
                    && failure.matches_journal(
                        &self.attempt_id,
                        &self.request_sha256,
                        &self.causal_diagnostics,
                    )
            })
            && self.cleanup_complete
                == (self.durable_state == WindowsAttemptStateV1::Empty
                    && self.cleanup_state.termination_requested
                    && self.cleanup_state.active_processes_zero
                    && self.cleanup_state.guardian_reaped
                    && self.cleanup_state.final_handles_closed)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalRetiredV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub terminal_response_sha256: String,
    pub disposition: WindowsAttemptTerminalDispositionV1,
}

impl WindowsTerminalRetiredV1 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        terminal_response_sha256: &str,
    ) -> bool {
        self.schema_version == 1
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.terminal_response_sha256 == terminal_response_sha256
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && windows_sha256_text_is_valid(&self.terminal_response_sha256)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRetirementLedgerCompletionV1 {
    RetirementComplete,
}

/// V3 live-wire confirmation issued only from an authenticated, completed
/// retirement-ledger tombstone. V1 remains an explicit historical decoder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalRetiredV2 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub terminal_response_sha256: String,
    pub disposition: WindowsAttemptTerminalDispositionV1,
    pub provider_generation: String,
    pub original_boot_id: String,
    pub launch_incarnation: String,
    pub job_identity: String,
    pub owner_manifest_sha256: String,
    pub retirement_proof_sha256: String,
    pub ledger_generation: String,
    pub completion: WindowsRetirementLedgerCompletionV1,
}

impl WindowsTerminalRetiredV2 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        terminal_response_sha256: &str,
    ) -> bool {
        self.schema_version == 2
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.terminal_response_sha256 == terminal_response_sha256
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && windows_sha256_text_is_valid(&self.terminal_response_sha256)
            && !self.provider_generation.is_empty()
            && !self.original_boot_id.is_empty()
            && !self.launch_incarnation.is_empty()
            && windows_sha256_text_is_valid(&self.job_identity)
            && windows_sha256_text_is_valid(&self.owner_manifest_sha256)
            && windows_sha256_text_is_valid(&self.retirement_proof_sha256)
            && windows_sha256_text_is_valid(&self.ledger_generation)
            && self.completion == WindowsRetirementLedgerCompletionV1::RetirementComplete
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRecoveryInventoryV1 {
    pub schema_version: u32,
    pub challenge: String,
    pub provider_generation: String,
    pub current_boot_identity: String,
    pub executing: u32,
    pub incomplete_proof: u32,
    pub unacknowledged_outboxes: u32,
    pub ack_retirement_in_progress: u32,
    pub completed_tombstones: u32,
    pub active_admissions: u32,
    pub quarantined: u32,
}

impl WindowsRecoveryInventoryV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && !self.challenge.is_empty()
            && !self.provider_generation.is_empty()
            && !self.current_boot_identity.is_empty()
            && (u64::from(self.executing)
                + u64::from(self.incomplete_proof)
                + u64::from(self.unacknowledged_outboxes)
                + u64::from(self.ack_retirement_in_progress)
                + u64::from(self.completed_tombstones)
                + u64::from(self.active_admissions)
                + u64::from(self.quarantined))
                <= u32::MAX as u64
    }

    pub fn authority_unsettled(&self) -> bool {
        self.executing != 0
            || self.incomplete_proof != 0
            || self.unacknowledged_outboxes != 0
            || self.ack_retirement_in_progress != 0
            || self.active_admissions != 0
            || self.quarantined != 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProviderProbeV1 {
    pub format: String,
    pub revision: u32,
    pub provider_identity: String,
    pub provider_binding: crate::PublicProviderBindingV1,
    pub launcher_authenticated: bool,
    pub recovery_clear: bool,
    pub attempts_empty: bool,
}

impl WindowsProviderProbeV1 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.format != "memcordon.windows-provider-probe"
            || self.revision != 1
            || self.provider_identity.is_empty()
            || self.provider_identity.len() > 256
            || !self.provider_binding.is_consistent()
            || !self
                .provider_binding
                .source_commit
                .as_str()
                .bytes()
                .any(|byte| byte != b'0')
            || self
                .provider_binding
                .runtime_manifest_sha256
                .bytes()
                .iter()
                .all(|byte| *byte == 0)
            || !self.launcher_authenticated
            || !self.recovery_clear
        {
            return Err("Windows provider probe identity or live observations differ");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderResponse<Terminal, Rejection> {
    WorkloadDiscovery {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
        discovery: crate::workload_discovery::WorkloadDiscovery,
    },
    WorkloadPlan {
        schema_version: u32,
        challenge: crate::workload_contract::Nonce128,
        resolution: crate::workload_evidence::RuntimeWorkloadResolution,
    },
    Probe {
        schema_version: u32,
        observation: WindowsProviderProbeV1,
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
        challenge: String,
        status: WindowsControlRequestStatusV1,
        attempts_empty: Option<bool>,
        detail: String,
    },
    RecoveryInventory(WindowsRecoveryInventoryV1),
    ReadOnlyQueryFailure(WindowsReadOnlyQueryFailure),
    RecoveryAttemptUnavailable {
        schema_version: u32,
        challenge: String,
        attempt_id: String,
        detail: String,
    },
    PackageCleanupResult {
        schema_version: u32,
        challenge: String,
        status: WindowsControlRequestStatusV1,
        attempts_empty: Option<bool>,
        terminal_outboxes: Option<u32>,
        detail: String,
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
    Terminal(Terminal),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: Rejection,
    },
    AttemptRetained(WindowsAttemptRetainedV1),
    AttemptRetainedV2(WindowsAttemptRetainedV2),
    ReplayPending(WindowsReplayPendingV1),
    ReplayPendingV2(WindowsReplayPendingV2),
    TerminalRetired(WindowsTerminalRetiredV1),
    TerminalRetiredV2(WindowsTerminalRetiredV2),
}

pub type WindowsProviderResponseV1 =
    WindowsProviderResponse<WindowsTerminalReceiptV1, ProviderRejectionEvidence>;
pub type WindowsProviderResponseV3 =
    WindowsProviderResponse<WindowsTerminalReceiptV2, WindowsProviderRejectionV2>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherRequestV1 {
    StartupAttestation {
        schema_version: u32,
        challenge: String,
    },
    Probe {
        schema_version: u32,
        challenge: String,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    PackageCleanup {
        schema_version: u32,
        deadline_millis: u64,
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
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
        caller_process_identity: WindowsProcessIdentityV1,
        caller_token_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminalization_error: Option<WindowsTerminalizationErrorV1>,
    },
}

/// Live private protocol requests. V1 remains an explicit historical decoder.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherRequestV3 {
    StartupAttestation {
        schema_version: u32,
        challenge: String,
    },
    Probe {
        schema_version: u32,
        challenge: String,
    },
    ObserveGuardianAttempt {
        schema_version: u32,
        challenge: crate::BoundedText<128>,
        guardian_identity: WindowsProcessIdentityV1,
    },
    CertificationMachineRestart {
        schema_version: u32,
    },
    PackageCleanup {
        schema_version: u32,
        deadline_millis: u64,
    },
    RecoverAttempt {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        challenge: String,
        caller: crate::WindowsRecoveryCallerEvidenceV1,
    },
    ConvergeRecovery {
        schema_version: u32,
        challenge: String,
        deadline_millis: u64,
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
    TerminalAcknowledged {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        terminal_response_sha256: String,
    },
    ReplayTerminal {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        relay_phase: WindowsRelayPhaseV1,
        caller_process_identity: WindowsProcessIdentityV1,
        caller_token_sha256: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        terminalization_error: Option<WindowsTerminalizationErrorV1>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherResponse<Terminal, Rejection> {
    StartupAttestation {
        schema_version: u32,
        attestation: WindowsServiceSelfAttestationV1,
    },
    Probe {
        schema_version: u32,
        attestation: WindowsServiceSelfAttestationV1,
        provider_binding: crate::PublicProviderBindingV1,
    },
    CertificationMachineRestart {
        schema_version: u32,
        recovered: bool,
    },
    PackageCleanup {
        schema_version: u32,
        status: WindowsControlRequestStatusV1,
        attempts_empty: Option<bool>,
        terminal_outboxes: Option<u32>,
        detail: String,
    },
    RecoveryInventory(WindowsRecoveryInventoryV1),
    GuardianAttemptObservation(WindowsGuardianAttemptObservation),
    ReadOnlyQueryFailure(WindowsReadOnlyQueryFailure),
    RecoveryAttemptUnavailable {
        schema_version: u32,
        challenge: String,
        attempt_id: String,
        detail: String,
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
    Terminal(Terminal),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: Rejection,
    },
    AttemptRetained(WindowsAttemptRetainedV1),
    AttemptRetainedV2(WindowsAttemptRetainedV2),
    ReplayPending(WindowsReplayPendingV1),
    ReplayPendingV2(WindowsReplayPendingV2),
    TerminalRetired(WindowsTerminalRetiredV1),
    TerminalRetiredV2(WindowsTerminalRetiredV2),
}

pub type WindowsLauncherResponseV1 =
    WindowsLauncherResponse<WindowsTerminalReceiptV1, ProviderRejectionEvidence>;
pub type WindowsLauncherResponseV3 =
    WindowsLauncherResponse<WindowsTerminalReceiptV2, WindowsProviderRejectionV2>;

macro_rules! terminal_authority_encoding {
    ($response:ty) => {
        impl $response {
            /// Expirable diagnostics are not immutable outbox or ACK authority.
            pub fn terminal_authority_json(&self) -> Result<String, serde_json::Error> {
                let mut authority = self.clone();
                if let Self::Reject { rejection, .. } = &mut authority {
                    rejection.provider_failure = None;
                }
                let mut bytes = crate::bounded_json_bytes(
                    &authority,
                    crate::WINDOWS_MAX_TERMINAL_FRAME_BYTES,
                    false,
                )?;
                bytes.pop();
                Ok(String::from_utf8(bytes).expect("JSON serialization emits UTF-8"))
            }
        }
    };
}
terminal_authority_encoding!(WindowsProviderResponseV1);
terminal_authority_encoding!(WindowsLauncherResponseV1);
terminal_authority_encoding!(WindowsProviderResponseV3);
terminal_authority_encoding!(WindowsLauncherResponseV3);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalReceiptV1 {
    pub policy_enforcement: crate::workload_evidence::RuntimePolicyEnforcement,
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

/// Version 2 intentionally carries only a bounded sample of Job identities.
/// Native retirement authority is represented separately from this observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsTerminalReceiptV2 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_enforcement: Option<crate::workload_evidence::RuntimePolicyEnforcement>,
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub payload: WindowsTerminalPayloadV2,
    pub process_observation: crate::WindowsProcessObservationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup_process_creation: Option<WindowsCleanupProcessCreationEvidenceV1>,
    pub restart_safety: RestartSafetyProof,
    pub retirement_proof: WindowsRetirementProofV2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsTerminalPayloadV2 {
    Execution {
        child_pid: u32,
        duration_millis: u64,
        authorization_offset_millis: u64,
        outcome: RunOutcome,
        boundary_detail: Box<BoundaryMechanismEvidence>,
    },
    RecoveredClosure {
        primary_failure: crate::OriginalFailureV1,
        target_creation_observed: bool,
        resume_attempted: bool,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRetirementProofSourceV2 {
    LiveNative,
    GuardianRecovery,
    PriorBoot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRetirementProofV2 {
    pub schema_version: u32,
    pub source: WindowsRetirementProofSourceV2,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub provider_generation: String,
    pub launch_incarnation: String,
    pub original_boot_id: String,
    pub job_identity: String,
    pub owner_manifest_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guardian_receipt_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_boot_id: Option<String>,
    pub target_completion_observed: bool,
    pub native_job_empty_observed: bool,
    pub relay_closure_observed: bool,
    pub guardian_completion_observed: bool,
    pub owner_capabilities_closed: bool,
    pub launch_gate_closed: bool,
    pub policy_reference_bound: bool,
}

impl WindowsTerminalReceiptV2 {
    pub fn execution(&self) -> Option<(u32, &RunOutcome, &BoundaryMechanismEvidence)> {
        match &self.payload {
            WindowsTerminalPayloadV2::Execution {
                child_pid,
                outcome,
                boundary_detail,
                ..
            } => Some((*child_pid, outcome, boundary_detail)),
            WindowsTerminalPayloadV2::RecoveredClosure { .. } => None,
        }
    }

    pub fn validate_for_attempt(&self) -> Result<(), &'static str> {
        if self.schema_version != 2 {
            return Err("schema_version");
        }
        if self.attempt_id.is_empty() || self.nonce.is_empty() || self.request_sha256.is_empty() {
            return Err("attempt_binding");
        }
        self.process_observation
            .validate(&self.attempt_id, &self.nonce, &self.request_sha256)?;
        let proof = &self.retirement_proof;
        if proof.schema_version != 2
            || proof.attempt_id != self.attempt_id
            || proof.nonce != self.nonce
            || proof.request_sha256 != self.request_sha256
            || proof.provider_generation.is_empty()
            || proof.launch_incarnation.is_empty()
            || proof.original_boot_id.is_empty()
            || proof.job_identity.is_empty()
            || proof.owner_manifest_sha256.is_empty()
            || !proof.owner_capabilities_closed
            || !proof.launch_gate_closed
            || !proof.policy_reference_bound
        {
            return Err("retirement_proof");
        }
        match (&self.payload, proof.source) {
            (
                WindowsTerminalPayloadV2::Execution { child_pid, .. },
                WindowsRetirementProofSourceV2::LiveNative,
            ) if proof.target_completion_observed
                && proof.native_job_empty_observed
                && proof.relay_closure_observed
                && proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof.current_boot_id.is_none()
                && *child_pid != 0
                && self
                    .process_observation
                    .root_identity
                    .as_ref()
                    .is_some_and(|root| root.process_id == *child_pid) => {}
            (
                WindowsTerminalPayloadV2::RecoveredClosure {
                    primary_failure, ..
                },
                WindowsRetirementProofSourceV2::GuardianRecovery,
            ) if match primary_failure {
                crate::OriginalFailureV1::Observed { event } => event.sequence != 0,
                crate::OriginalFailureV1::Unavailable { reason } => {
                    *reason != crate::OriginalUnavailableReasonV1::NoEarlierErrorObserved
                }
            } && proof.native_job_empty_observed
                && proof.guardian_completion_observed
                && proof
                    .guardian_receipt_sha256
                    .as_deref()
                    .is_some_and(windows_sha256_text_is_valid)
                && proof.current_boot_id.is_none()
                && self.cleanup_process_creation.is_none() => {}
            (
                WindowsTerminalPayloadV2::RecoveredClosure {
                    primary_failure, ..
                },
                WindowsRetirementProofSourceV2::PriorBoot,
            ) if match primary_failure {
                crate::OriginalFailureV1::Observed { event } => event.sequence != 0,
                crate::OriginalFailureV1::Unavailable { reason } => {
                    *reason != crate::OriginalUnavailableReasonV1::NoEarlierErrorObserved
                }
            } && !proof.target_completion_observed
                && !proof.native_job_empty_observed
                && !proof.relay_closure_observed
                && !proof.guardian_completion_observed
                && proof.guardian_receipt_sha256.is_none()
                && proof
                    .current_boot_id
                    .as_deref()
                    .is_some_and(|boot| !boot.is_empty() && boot != proof.original_boot_id)
                && self.cleanup_process_creation.is_none() => {}
            _ => return Err("retirement_proof.source"),
        }
        if let WindowsTerminalPayloadV2::Execution {
            boundary_detail, ..
        } = &self.payload
        {
            if let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = boundary_detail.as_ref()
            {
                if native.frontend_delivery.is_some() {
                    return Err("boundary_detail.frontend_delivery_before_ack");
                }
            }
        }
        if matches!(self.payload, WindowsTerminalPayloadV2::Execution { .. })
            && !self.restart_safety.is_safe_for(BoundaryRequirement::Sealed)
        {
            return Err("restart_safety");
        }
        if self
            .cleanup_process_creation
            .as_ref()
            .is_some_and(|cleanup| !cleanup.is_consistent())
        {
            return Err("cleanup_process_creation");
        }
        Ok(())
    }

    pub fn validate_for_certification(
        &self,
        expected_attempt_binding: &str,
        required_job_total_processes: u32,
    ) -> Result<ValidatedWindowsCertificationTerminal<'_>, String> {
        self.validate_for_attempt().map_err(str::to_owned)?;
        let Some((_, outcome, boundary_detail)) = self.execution() else {
            return Err("kind".to_owned());
        };
        let accounting = self
            .process_observation
            .final_accounting
            .as_ref()
            .ok_or_else(|| "process_observation.final_accounting".to_owned())?;
        if accounting.total_processes_native_u32 < required_job_total_processes
            || !accounting.observed_after_target_retirement
            || accounting.active_processes_native_u32 != 0
        {
            return Err("process_observation.final_accounting".to_owned());
        }
        let cleanup = self
            .cleanup_process_creation
            .as_ref()
            .ok_or_else(|| "cleanup_process_creation".to_owned())?;
        if !cleanup.is_consistent()
            || cleanup.attempt_binding != expected_attempt_binding
            || accounting.total_processes_native_u32 < cleanup.total_processes_after
        {
            return Err("cleanup_process_creation".to_owned());
        }
        if !matches!(
            outcome,
            RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 0 },
                ..
            }
        ) {
            return Err("outcome.child".to_owned());
        }
        let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = boundary_detail else {
            return Err("boundary_detail.variant".to_owned());
        };
        if !native.active_processes_zero
            || !native.direct_target_reaped
            || !native.guardian_reaped
            || !native.relays_retired
            || !native.final_job_handles_closed
        {
            return Err("boundary_detail.retirement".to_owned());
        }
        Ok(ValidatedWindowsCertificationTerminal { native })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsProviderRejectionDispositionV2 {
    Preauthorization {
        terminal_ack_required: bool,
    },
    PostauthorizationFailure {
        receipt: Box<WindowsTerminalReceiptV2>,
    },
    Retained {
        evidence: Box<WindowsAttemptRetainedV1>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsProviderRejectionV2 {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_admission: Option<crate::workload_evidence::WorkloadAdmissionRejectionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_failure: Option<crate::ProviderFailureDiagnosticV1>,
    pub code: String,
    pub phase: crate::BoundarySetupPhase,
    pub detail: String,
    pub os_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_qualification: Option<crate::WindowsLoaderQualificationOutcomeV2>,
    pub target_created: bool,
    pub target_released: bool,
    pub cleanup_attempted: bool,
    pub restart_safety: RestartSafetyProof,
    pub disposition: WindowsProviderRejectionDispositionV2,
}

impl WindowsProviderRejectionV2 {
    pub fn terminal_ack_required(&self) -> bool {
        match self.disposition {
            WindowsProviderRejectionDispositionV2::Preauthorization {
                terminal_ack_required,
            } => terminal_ack_required,
            WindowsProviderRejectionDispositionV2::PostauthorizationFailure { .. } => true,
            WindowsProviderRejectionDispositionV2::Retained { .. } => false,
        }
    }

    pub fn terminal_receipt(&self) -> Option<&WindowsTerminalReceiptV2> {
        match &self.disposition {
            WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } => {
                Some(receipt)
            }
            _ => None,
        }
    }

    pub fn is_consistent(&self) -> bool {
        if self.schema_version != 2
            || self.code.is_empty()
            || self.code.len() > 128
            || !self
                .code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            || self.detail.is_empty()
            || self.detail.len() > crate::PROVIDER_REJECTION_MAX_DETAIL_BYTES
            || self.detail.contains('\0')
            || (!self.target_created && self.target_released)
            || self
                .loader_qualification
                .as_ref()
                .is_some_and(|item| !item.is_consistent())
            || self.provider_failure.as_ref().is_some_and(|failure| {
                !failure.is_consistent() || failure.projection_sha256 != failure.canonical_digest()
            })
        {
            return false;
        }
        match &self.disposition {
            WindowsProviderRejectionDispositionV2::Preauthorization {
                terminal_ack_required,
            } => !self.target_released && (!terminal_ack_required || self.cleanup_attempted),
            WindowsProviderRejectionDispositionV2::PostauthorizationFailure { receipt } => {
                let matching_authority = match &receipt.payload {
                    WindowsTerminalPayloadV2::Execution {
                        boundary_detail, ..
                    } => matches!(
                        boundary_detail.as_ref(),
                        crate::BoundaryMechanismEvidence::WindowsJobObjectV2(native)
                            if native.target_released == self.target_released
                    ),
                    WindowsTerminalPayloadV2::RecoveredClosure {
                        target_creation_observed,
                        resume_attempted,
                        ..
                    } => {
                        *target_creation_observed == self.target_created
                            && (!self.target_released || *resume_attempted)
                    }
                };
                // Expirable diagnostics are omitted from the immutable terminal
                // outbox. When present, they must still match its primary cause.
                let matching_primary = match (&receipt.payload, self.provider_failure.as_ref()) {
                    (
                        WindowsTerminalPayloadV2::Execution {
                            outcome: RunOutcome::MonitorFailed { .. },
                            ..
                        },
                        Some(failure),
                    ) => matches!(
                        failure.original,
                        crate::OriginalFailureV1::Observed { ref event }
                            if event.sequence > 0
                    ),
                    (
                        WindowsTerminalPayloadV2::Execution {
                            outcome: RunOutcome::MonitorFailed { .. },
                            ..
                        },
                        None,
                    ) => true,
                    (
                        WindowsTerminalPayloadV2::RecoveredClosure {
                            primary_failure, ..
                        },
                        Some(failure),
                    ) => &failure.original == primary_failure,
                    (WindowsTerminalPayloadV2::RecoveredClosure { .. }, None) => true,
                    _ => false,
                };
                self.target_created
                    && self.cleanup_attempted
                    && receipt.validate_for_attempt().is_ok()
                    && receipt.restart_safety == self.restart_safety
                    && matching_authority
                    && matching_primary
            }
            WindowsProviderRejectionDispositionV2::Retained { evidence } => {
                evidence.authority_retained && !self.restart_safety.sealed_boundary_retired
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsCleanupProcessCreationEvidenceV1 {
    pub schema_version: u32,
    pub attempt_binding: String,
    pub attempted_after_terminating_transition: bool,
    pub child_created: bool,
    pub child_job_membership_verified: bool,
    pub child_identity: WindowsProcessIdentityV1,
    pub total_processes_before: u32,
    pub total_processes_after: u32,
    pub final_active_processes_zero: bool,
}

impl WindowsCleanupProcessCreationEvidenceV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && self
                .attempt_binding
                .strip_prefix("attempt-")
                .is_some_and(windows_sha256_text_is_valid)
            && self.attempted_after_terminating_transition
            && self.child_created
            && self.child_job_membership_verified
            && self.child_identity.process_id != 0
            && self.child_identity.creation_time_100ns != 0
            && self.total_processes_after > self.total_processes_before
            && self.final_active_processes_zero
    }
}

#[derive(Debug)]
pub struct ValidatedWindowsCertificationTerminal<'a> {
    pub native: &'a WindowsSealedEvidenceV2,
}

impl WindowsTerminalReceiptV1 {
    pub fn process_identity_inventory_shape_is_bounded(&self) -> bool {
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
    }

    pub fn process_identity_inventory_is_bounded(&self) -> bool {
        self.process_identity_inventory_shape_is_bounded()
            && self
                .cleanup_process_creation
                .as_ref()
                .is_none_or(WindowsCleanupProcessCreationEvidenceV1::is_consistent)
    }

    pub fn validate_for_certification(
        &self,
        expected_attempt_binding: &str,
        required_job_total_processes: u32,
    ) -> Result<ValidatedWindowsCertificationTerminal<'_>, String> {
        if self.schema_version != 1 {
            return Err("schema_version".to_owned());
        }
        if !self.process_identity_inventory_shape_is_bounded() {
            return Err("job_process_identities".to_owned());
        }
        if !self.restart_safety.is_safe_for(BoundaryRequirement::Sealed) {
            return Err("restart_safety".to_owned());
        }
        let cleanup = self
            .cleanup_process_creation
            .as_ref()
            .ok_or_else(|| "cleanup_process_creation".to_owned())?;
        if cleanup.attempt_binding != expected_attempt_binding {
            return Err("cleanup_process_creation.attempt_binding".to_owned());
        }
        for (complete, field) in [
            (
                cleanup.schema_version == 1,
                "cleanup_process_creation.schema_version",
            ),
            (
                cleanup.attempted_after_terminating_transition,
                "cleanup_process_creation.attempted_after_terminating_transition",
            ),
            (
                cleanup.child_created,
                "cleanup_process_creation.child_created",
            ),
            (
                cleanup.child_job_membership_verified,
                "cleanup_process_creation.child_job_membership_verified",
            ),
            (
                cleanup.child_identity.process_id != 0,
                "cleanup_process_creation.child_identity.process_id",
            ),
            (
                cleanup.child_identity.creation_time_100ns != 0,
                "cleanup_process_creation.child_identity.creation_time_100ns",
            ),
            (
                cleanup.total_processes_after > cleanup.total_processes_before,
                "cleanup_process_creation.total_processes_after",
            ),
            (
                cleanup.final_active_processes_zero,
                "cleanup_process_creation.final_active_processes_zero",
            ),
            (
                self.job_total_processes >= cleanup.total_processes_after,
                "job_total_processes.cleanup_floor",
            ),
            (
                self.job_total_processes >= required_job_total_processes,
                "job_total_processes.qualification_minimum",
            ),
        ] {
            if !complete {
                return Err(field.to_owned());
            }
        }
        if !matches!(
            self.outcome,
            RunOutcome::Exited {
                child: ChildTermination::ExitCode { code: 0 },
                ..
            }
        ) {
            return Err("outcome.child".to_owned());
        }
        let BoundaryMechanismEvidence::WindowsJobObjectV2(native) = &self.boundary_detail else {
            return Err("boundary_detail.variant".to_owned());
        };
        for (complete, field) in [
            (native.schema_version == 2, "boundary_detail.schema_version"),
            (
                native.service_identity == "MemCordonSealedControl+MemCordonSealedLauncher:v1",
                "boundary_detail.service_identity",
            ),
            (
                native.caller_token_authenticated,
                "boundary_detail.caller_token_authenticated",
            ),
            (
                native.initial_target_token_matches_caller,
                "boundary_detail.initial_target_token_matches_caller",
            ),
            (
                native.credential_transition_disposition
                    == CredentialTransitionDisposition::PreserveCallerEnvelope,
                "boundary_detail.credential_transition_disposition",
            ),
            (
                native.job_membership_independent_of_token,
                "boundary_detail.job_membership_independent_of_token",
            ),
            (native.job_created, "boundary_detail.job_created"),
            (
                native.job_limits_verified,
                "boundary_detail.job_limits_verified",
            ),
            (
                native.kill_on_close_verified,
                "boundary_detail.kill_on_close_verified",
            ),
            (native.breakaway_denied, "boundary_detail.breakaway_denied"),
            (
                native.completion_port_associated,
                "boundary_detail.completion_port_associated",
            ),
            (native.guardian_ready, "boundary_detail.guardian_ready"),
            (
                native.target_created_suspended,
                "boundary_detail.target_created_suspended",
            ),
            (
                native.job_list_applied_at_creation,
                "boundary_detail.job_list_applied_at_creation",
            ),
            (
                native.handle_list_applied_at_creation,
                "boundary_detail.handle_list_applied_at_creation",
            ),
            (
                native.target_job_membership_verified,
                "boundary_detail.target_job_membership_verified",
            ),
            (
                native.target_still_suspended_during_verification,
                "boundary_detail.target_still_suspended_during_verification",
            ),
            (
                native.inherited_handles_verified,
                "boundary_detail.inherited_handles_verified",
            ),
            (native.target_released, "boundary_detail.target_released"),
            (
                native.terminate_job_invoked,
                "boundary_detail.terminate_job_invoked",
            ),
            (
                native.active_processes_zero,
                "boundary_detail.active_processes_zero",
            ),
            (
                native.direct_target_reaped,
                "boundary_detail.direct_target_reaped",
            ),
            (native.relays_retired, "boundary_detail.relays_retired"),
            (native.guardian_reaped, "boundary_detail.guardian_reaped"),
            (
                native.final_job_handles_closed,
                "boundary_detail.final_job_handles_closed",
            ),
        ] {
            if !complete {
                return Err(field.to_owned());
            }
        }
        Ok(ValidatedWindowsCertificationTerminal { native })
    }
}
