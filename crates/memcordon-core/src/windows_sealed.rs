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

pub const WINDOWS_PUBLIC_PROTOCOL_VERSION: u32 = 1;
pub const WINDOWS_PRIVATE_PROTOCOL_VERSION: u32 = 1;
pub const WINDOWS_QUALIFICATION_SCHEMA_VERSION: u32 = 1;
pub const WINDOWS_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
pub const WINDOWS_MAX_JOB_PROCESS_IDENTITIES: usize = 256;

pub const WINDOWS_CONTROL_SERVICE_NAME: &str = "MemCordonSealedControl";
pub const WINDOWS_LAUNCHER_SERVICE_NAME: &str = "MemCordonSealedLauncher";
pub const WINDOWS_SESSION_BROKER_SERVICE_NAME: &str = "MemCordonSealedSessionBroker";
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

impl WindowsCertificationObservationsV1 {
    pub fn is_complete(&self) -> bool {
        self.schema_version == 1
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_response_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_disposition: Option<WindowsAttemptTerminalDispositionV1>,
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
        && record.terminal_response_json.as_ref().is_none_or(|json| {
            json.len() <= WINDOWS_MAX_FRAME_BYTES / 2
                && record.state == WindowsAttemptStateV1::Empty
                && record.terminal_disposition.is_some()
                && serde_json::from_str::<WindowsLauncherResponseV1>(json)
                    .is_ok_and(|response| windows_terminal_outbox_is_bound(record, &response))
        })
}

fn windows_terminal_outbox_is_bound(
    record: &WindowsDurableAttemptRecordV1,
    response: &WindowsLauncherResponseV1,
) -> bool {
    match response {
        WindowsLauncherResponseV1::Terminal(receipt) => {
            record.terminal_disposition == Some(WindowsAttemptTerminalDispositionV1::Posttarget)
                && receipt.attempt_id == record.attempt_id
                && receipt.request_sha256 == record.request_sha256
                && receipt.process_identity_inventory_shape_is_bounded()
        }
        WindowsLauncherResponseV1::Reject {
            attempt_id,
            request_sha256,
            rejection,
            ..
        } => {
            let disposition_matches = match record.terminal_disposition {
                Some(WindowsAttemptTerminalDispositionV1::PreauthorizationAbort) => {
                    rejection.terminal_ack_required && rejection.terminal_receipt.is_none()
                }
                Some(WindowsAttemptTerminalDispositionV1::Posttarget) => {
                    rejection.terminal_receipt.as_ref().is_some_and(|receipt| {
                        receipt.attempt_id == record.attempt_id
                            && receipt.request_sha256 == record.request_sha256
                    })
                }
                None => false,
            };
            attempt_id == &record.attempt_id
                && request_sha256 == &record.request_sha256
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
        challenge: String,
    },
    PackageCleanup {
        schema_version: u32,
        challenge: String,
    },
    QualificationBegin {
        schema_version: u32,
        scope: String,
        challenge: String,
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
}

impl WindowsAttemptRetainedV1 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 1
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
    NotStaged,
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
    pub cleanup_complete: bool,
    pub outbox_stage: WindowsReplayOutboxStageV1,
    pub detail: String,
}

impl WindowsReplayPendingV1 {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.schema_version == 1
            && self.attempt_id == attempt_id
            && self.nonce == nonce
            && self.request_sha256 == request_sha256
            && self.relay_phase == relay_phase
            && windows_sha256_text_is_valid(&self.attempt_id)
            && windows_sha256_text_is_valid(&self.request_sha256)
            && !self.detail.is_empty()
            && (!self.cleanup_complete || self.durable_state == WindowsAttemptStateV1::Empty)
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
        challenge: String,
        status: WindowsControlRequestStatusV1,
        attempts_empty: Option<bool>,
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
    QualificationReady {
        schema_version: u32,
    },
    QualificationAuthenticated {
        schema_version: u32,
        control_attestation: WindowsServiceSelfAttestationV1,
        launcher_attestation: WindowsServiceSelfAttestationV1,
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
    AttemptRetained(WindowsAttemptRetainedV1),
    ReplayPending(WindowsReplayPendingV1),
    TerminalRetired(WindowsTerminalRetiredV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "message", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherRequestV1 {
    Probe {
        schema_version: u32,
        challenge: String,
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
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherResponseV1 {
    Probe {
        schema_version: u32,
        attestation: WindowsServiceSelfAttestationV1,
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
    AttemptRetained(WindowsAttemptRetainedV1),
    ReplayPending(WindowsReplayPendingV1),
    TerminalRetired(WindowsTerminalRetiredV1),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsQualificationReceiptV1 {
    pub schema_version: u32,
    pub provider_identity: String,
    pub control_service_identity: String,
    pub launcher_service_identity: String,
    pub guardian_pool_identity: String,
    pub package_verified: bool,
    pub public_pipe_security_verified: bool,
    pub private_pipe_security_verified: bool,
    pub control_service_privileges_verified: bool,
    pub launcher_service_privileges_verified: bool,
    pub guardian_slot_tokens_verified: bool,
    pub guardian_slot_loader_verified: bool,
    pub guardian_capacity_verified: bool,
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
            && self.guardian_pool_identity
                == "MemCordonSealedGuardian-000..007:LocalSystem:restricted:demand"
            && (!self.qualified
                || (self.package_verified
                    && self.public_pipe_security_verified
                    && self.private_pipe_security_verified
                    && self.control_service_privileges_verified
                    && self.launcher_service_privileges_verified
                    && self.guardian_slot_tokens_verified
                    && self.guardian_slot_loader_verified
                    && self.guardian_capacity_verified
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
