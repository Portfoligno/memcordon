//! Versioned wire records for the private Windows sealed provider.
//!
//! These records deliberately contain native argument and environment arrays.
//! Neither endpoint accepts a shell command line.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    BoundaryMechanismEvidence, BoundaryRequirement, ChildTermination, RestartSafetyProof,
    RunOutcome,
};

pub const WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION: u32 = 4;
pub const WINDOWS_CURRENT_PRIVATE_PROTOCOL_VERSION: u32 = 4;
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
            | (Phase::AwaitAbortRejection, Event::MutantTerminal)
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

/// Actual observation of a selected invalid release ordering. This is failure
/// evidence, never execution authorization or successful boundary certification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPrematureReleaseWitnessV1 {
    pub schema_version: u32,
    pub mutant: WindowsSealedMutant,
    pub observation: WindowsMutantNativeObservationV1,
}

impl WindowsPrematureReleaseWitnessV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && matches!(
                self.mutant,
                WindowsSealedMutant::ResumeBeforeGuardian | WindowsSealedMutant::ResumeBeforeRelays
            )
            && matches!(
                self.observation,
                WindowsMutantNativeObservationV1::PrematureAuthorization {
                    target_marker_observed: true,
                    ..
                }
            )
            && self.observation.rejects(self.mutant)
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

pub trait WindowsFaultRejection {
    const MATRIX_SCHEMA_VERSION: u32;
    fn fault_code(&self) -> &str;
    fn target_released(&self) -> bool;
    fn is_consistent(&self) -> bool;
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
    PrematureReleaseFailure { mutant: WindowsSealedMutant },
}

impl WindowsAttemptTerminalDispositionV1 {
    pub fn premature_release_mutant(self) -> Option<WindowsSealedMutant> {
        match self {
            Self::PrematureReleaseFailure { mutant }
                if matches!(
                    mutant,
                    WindowsSealedMutant::ResumeBeforeGuardian
                        | WindowsSealedMutant::ResumeBeforeRelays
                ) =>
            {
                Some(mutant)
            }
            _ => None,
        }
    }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsWorkerThreadIdentityV1 {
    pub thread_id: u32,
    pub creation_time_100ns: u64,
}

/// Native support-site observations are diagnostic metadata, not authorization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsControlWorkerSiteV1 {
    pub format: String,
    pub revision: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub fault: WindowsSealedFault,
    pub process: WindowsProcessIdentityV1,
    pub thread: WindowsWorkerThreadIdentityV1,
    pub target_pid: u32,
    pub target_authorization_observed: bool,
}

impl WindowsControlWorkerSiteV1 {
    pub fn binds(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        fault: WindowsSealedFault,
        target_pid: u32,
    ) -> bool {
        self.format == "memcordon.windows-component-control-worker-site"
            && self.revision == 1
            && self.attempt_id == attempt_id
            && windows_sha256_text_is_valid(&self.attempt_id)
            && self.nonce == nonce
            && !self.nonce.is_empty()
            && self.request_sha256 == request_sha256
            && windows_sha256_text_is_valid(&self.request_sha256)
            && self.fault == fault
            && matches!(
                fault,
                WindowsSealedFault::ControlWorkerKilledAfterAuthorization
                    | WindowsSealedFault::ControlServiceKilledAfterAuthorization
            )
            && self.process.process_id != 0
            && self.process.creation_time_100ns != 0
            && self.thread.thread_id != 0
            && self.thread.creation_time_100ns != 0
            && self.target_pid == target_pid
            && target_pid != 0
            && self.target_authorization_observed
    }
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

/// A separate support experiment; this selection is never workload authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsLoaderDiagnosticKindV1 {
    OriginalRestrictedBootstrap,
    OriginalRestrictedBootstrapConsoleComparison,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsLoaderDiagnosticSelectionV1 {
    pub kind: WindowsLoaderDiagnosticKindV1,
    pub challenge: String,
    pub support_bootstrap_sha256: String,
    pub producer_deadline_sha256: String,
    pub work_deadline_unix_ms: u64,
    pub cleanup_deadline_unix_ms: u64,
}

impl WindowsLoaderDiagnosticSelectionV1 {
    pub fn validate_at(&self, now_unix_ms: u64) -> Result<(), &'static str> {
        if !windows_sha256_text_is_valid(&self.challenge)
            || self.challenge.bytes().all(|byte| byte == b'0')
            || !windows_sha256_text_is_valid(&self.support_bootstrap_sha256)
            || !windows_sha256_text_is_valid(&self.producer_deadline_sha256)
        {
            return Err("loader diagnostic challenge or selected image digest is invalid");
        }
        if self.work_deadline_unix_ms <= now_unix_ms
            || self.cleanup_deadline_unix_ms < self.work_deadline_unix_ms
        {
            return Err("loader diagnostic original cutoffs are expired or unordered");
        }
        Ok(())
    }
}

/// Native facts for the current-token profile. This contains no workload grant
/// or policy checkpoint and is never serialized under numeric execution 11.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsSealedEvidenceV3 {
    pub schema_version: u32,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub process_observation: Option<Box<crate::WindowsProcessObservationV2>>,
    pub service_identity: String,
    pub caller_token_authenticated: bool,
    pub initial_target_token_matches_caller: bool,
    pub credential_transition_disposition: crate::CredentialTransitionDisposition,
    pub job_membership_independent_of_token: bool,
    pub job_created: bool,
    pub job_limits_verified: bool,
    pub kill_on_close_verified: bool,
    pub breakaway_denied: bool,
    pub completion_port_associated: bool,
    pub guardian_ready: bool,
    pub target_created_suspended: bool,
    pub job_list_applied_at_creation: bool,
    pub handle_list_applied_at_creation: bool,
    pub target_job_membership_verified: bool,
    pub target_still_suspended_during_verification: bool,
    pub inherited_handles_verified: bool,
    pub target_released: bool,
    pub terminate_job_invoked: bool,
    pub active_processes_zero: bool,
    pub direct_target_reaped: bool,
    pub relays_retired: bool,
    pub guardian_reaped: bool,
    pub final_job_handles_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader_qualification: Option<crate::WindowsLoaderQualificationOutcomeV2>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_delivery: Option<WindowsFrontendDeliveryV3>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frontend_provider_association: Option<crate::execution_facts::ProviderAttemptAssociationV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retirement: Option<Box<WindowsRetirementProofV3>>,
}

impl WindowsSealedEvidenceV3 {
    pub fn prepared_boundary_is_verified(&self) -> bool {
        self.caller_token_authenticated
            && self.initial_target_token_matches_caller
            && self.credential_transition_disposition
                == crate::CredentialTransitionDisposition::PreserveCallerEnvelope
            && self.job_membership_independent_of_token
            && self.job_created
            && self.job_limits_verified
            && self.kill_on_close_verified
            && self.breakaway_denied
            && self.completion_port_associated
            && self.guardian_ready
            && self.target_created_suspended
            && self.job_list_applied_at_creation
            && self.handle_list_applied_at_creation
            && self.target_job_membership_verified
            && self.target_still_suspended_during_verification
            && self.inherited_handles_verified
    }

    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 3 || self.service_identity.is_empty() {
            return Err("native Windows evidence format");
        }
        if self
            .frontend_delivery
            .as_ref()
            .is_some_and(|delivery| !delivery.is_consistent() || self.process_observation.is_none())
        {
            return Err("native Windows frontend delivery binding");
        }
        if self.target_released && !self.prepared_boundary_is_verified() {
            return Err("native Windows release gate");
        }
        if self.target_released
            && (self.target_identity.is_none()
                || self
                    .process_observation
                    .as_ref()
                    .is_none_or(|observation| observation.root_identity != self.target_identity))
        {
            return Err("native Windows target process observation differs");
        }
        if let (Some(delivery), Some(observation)) =
            (&self.frontend_delivery, &self.process_observation)
        {
            observation.validate(
                &delivery.attempt_id,
                &delivery.nonce,
                &delivery.request_sha256,
            )?;
        }
        if let Some(proof) = &self.retirement {
            proof.validate()?;
            if proof.native_job_empty_observed != self.active_processes_zero
                || proof.target_completion_observed != self.direct_target_reaped
                || proof.relay_closure_observed != self.relays_retired
                || proof.guardian_completion_observed != self.guardian_reaped
                || proof.owner_capabilities_closed != self.final_job_handles_closed
            {
                return Err("native retirement observations disagree");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsFrontendDeliveryV3 {
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub terminal_sha256: String,
    pub retired_sha256: String,
    pub terminal_validated: bool,
    pub acknowledgement_observed: bool,
}

impl WindowsFrontendDeliveryV3 {
    pub fn is_consistent(&self) -> bool {
        windows_sha256_text_is_valid(&self.attempt_id)
            && !self.nonce.is_empty()
            && windows_sha256_text_is_valid(&self.request_sha256)
            && windows_sha256_text_is_valid(&self.terminal_sha256)
            && windows_sha256_text_is_valid(&self.retired_sha256)
            && self.terminal_validated
            && self.acknowledgement_observed
    }
}

/// Factual native retirement under the same-owner recovery access floor.
/// A terminal record cannot construct a live Job or a release gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsRetirementProofV3 {
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
    pub guardian_receipt_sha256: Option<String>,
    pub current_boot_id: Option<String>,
    pub capability_extinction: Option<crate::WindowsCapabilityExtinctionProofV2>,
    pub target_completion_observed: bool,
    pub native_job_empty_observed: bool,
    pub relay_closure_observed: bool,
    pub guardian_completion_observed: bool,
    pub owner_capabilities_closed: bool,
    pub launch_gate_closed: bool,
}

impl WindowsRetirementProofV3 {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != 3
            || self.attempt_id.is_empty()
            || self.nonce.is_empty()
            || !windows_sha256_text_is_valid(&self.request_sha256)
            || self.provider_generation.is_empty()
            || self.launch_incarnation.is_empty()
            || self.original_boot_id.is_empty()
            || self.job_identity.is_empty()
            || !windows_sha256_text_is_valid(&self.owner_manifest_sha256)
            || !self.owner_capabilities_closed
            || !self.launch_gate_closed
        {
            return Err("native retirement binding");
        }
        match self.source {
            WindowsRetirementProofSourceV2::LiveNative => {
                if !self.target_completion_observed
                    || !self.native_job_empty_observed
                    || !self.relay_closure_observed
                    || !self.guardian_completion_observed
                    || self.guardian_receipt_sha256.is_some()
                    || self.current_boot_id.is_some()
                    || self.capability_extinction.is_some()
                {
                    return Err("live native retirement");
                }
            }
            WindowsRetirementProofSourceV2::GuardianRecovery => {
                if !self.native_job_empty_observed
                    || !self.guardian_completion_observed
                    || !self
                        .guardian_receipt_sha256
                        .as_deref()
                        .is_some_and(windows_sha256_text_is_valid)
                    || self.current_boot_id.is_some()
                    || self.capability_extinction.is_some()
                {
                    return Err("guardian recovery retirement");
                }
            }
            WindowsRetirementProofSourceV2::PriorBoot => {
                if self.target_completion_observed
                    || self.native_job_empty_observed
                    || self.relay_closure_observed
                    || self.guardian_completion_observed
                    || self.guardian_receipt_sha256.is_some()
                    || self.capability_extinction.is_some()
                    || !self
                        .current_boot_id
                        .as_deref()
                        .is_some_and(|boot| !boot.is_empty() && boot != self.original_boot_id)
                {
                    return Err("prior boot retirement");
                }
            }
            WindowsRetirementProofSourceV2::CapabilityExtinction => {
                let extinction = self
                    .capability_extinction
                    .as_ref()
                    .ok_or("missing native capability extinction")?;
                extinction.validate()?;
                let contract = &extinction.contract;
                if self.target_completion_observed
                    || self.native_job_empty_observed
                    || self.relay_closure_observed
                    || self.guardian_completion_observed
                    || self.guardian_receipt_sha256.is_some()
                    || self.current_boot_id.is_some()
                    || contract.attempt_id != self.attempt_id
                    || contract.nonce != self.nonce
                    || contract.request_sha256 != self.request_sha256
                    || contract.provider_generation != self.provider_generation
                    || contract.launch_incarnation != self.launch_incarnation
                    || contract.original_boot_id != self.original_boot_id
                    || contract.job_identity != self.job_identity
                    || contract.owner_manifest_sha256 != self.owner_manifest_sha256
                {
                    return Err("native capability extinction binding");
                }
            }
        }
        Ok(())
    }
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
    pub association: crate::execution_facts::ProviderAttemptAssociationV1,
    /// Observation-only live control metadata, joined to the authenticated
    /// durable record. These fields grant no replay or terminal authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_target_identity: Option<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_process_identity: Option<WindowsProcessIdentityV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_thread_identity: Option<WindowsWorkerThreadIdentityV1>,
}

impl WindowsGuardianAttemptObservation {
    pub const MAX_FRAME_BYTES: usize = 16 * 1024;

    /// Join the authenticated launcher owner's facts to the exact public query.
    /// A private error reply cannot become a successful observation.
    pub fn from_launcher_query_response<Terminal, Rejection, Mutant>(
        response: WindowsLauncherResponse<Terminal, Rejection, Mutant>,
        challenge: &str,
        provider: &crate::PublicProviderBindingV1,
        guardian: &WindowsProcessIdentityV1,
    ) -> Result<Self, String> {
        match response {
            WindowsLauncherResponse::GuardianAttemptObservation(value) => {
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
            WindowsLauncherResponse::ReadOnlyQueryFailure(value) => Err(value.error_for(
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
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
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
        crate::canonical_json::reject_duplicate_json_keys(bytes)?;
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
            && match (
                &self.live_nonce,
                &self.worker_process_identity,
                &self.worker_thread_identity,
                &self.live_target_identity,
            ) {
                (None, None, None, None) => true,
                (Some(nonce), Some(process), Some(thread), Some(target)) => {
                    !nonce.is_empty()
                        && nonce.len() <= 128
                        && process.process_id != 0
                        && process.creation_time_100ns != 0
                        && target.process_id != 0
                        && target.creation_time_100ns != 0
                        && thread.thread_id != 0
                        && thread.creation_time_100ns != 0
                }
                _ => false,
            }
    }
}

/// Factual outcome of a current package cleanup request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsPackageCleanupOutcomeV1 {
    pub status: WindowsControlRequestStatusV1,
    pub attempts_empty: Option<bool>,
    pub terminal_outboxes: Option<u32>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsControlRequestStatusV1 {
    Ready,
    Active,
    Failed,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsRetainedMetadata {
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

impl WindowsRetainedMetadata {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.provider_failure.is_some()
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsReplayMetadata {
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

impl WindowsReplayMetadata {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        relay_phase: WindowsRelayPhaseV1,
    ) -> bool {
        self.provider_failure.is_some()
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
pub struct WindowsRetirementMetadata {
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub terminal_response_sha256: String,
    pub disposition: WindowsAttemptTerminalDispositionV1,
}

impl WindowsRetirementMetadata {
    pub fn is_consistent_for(
        &self,
        attempt_id: &str,
        nonce: &str,
        request_sha256: &str,
        terminal_response_sha256: &str,
    ) -> bool {
        self.attempt_id == attempt_id
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

/// Checked closure of an attempt that never acquired execution authorization.
/// This is distinct from a postauthorization Job retirement receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPreauthorizationRetirementProofV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub request_sha256: String,
    pub provider_generation: String,
    pub original_boot_id: String,
    pub launch_incarnation: String,
    pub job_identity: String,
    pub terminal_response_sha256: String,
    pub target_identity: Option<WindowsProcessIdentityV1>,
    pub guardian_identity: Option<WindowsProcessIdentityV1>,
    pub worker_identity: Option<WindowsProcessIdentityV1>,
    pub worker_thread_identity: Option<WindowsWorkerThreadIdentityV1>,
    pub frozen_owner_manifest_sha256: Option<String>,
    pub target_created: bool,
    pub authorization_unix_millis: Option<u64>,
    pub resume_attempted: bool,
    pub target_released: bool,
    pub cleanup_state: WindowsDurableCleanupStateV1,
    pub recorded_target_and_guardian_extinct: bool,
}

impl WindowsPreauthorizationRetirementProofV1 {
    pub fn is_consistent(&self) -> bool {
        self.schema_version == 1
            && windows_sha256_text_is_valid(&self.attempt_id)
            && !self.nonce.is_empty()
            && windows_sha256_text_is_valid(&self.request_sha256)
            && !self.provider_generation.is_empty()
            && !self.original_boot_id.is_empty()
            && !self.launch_incarnation.is_empty()
            && windows_sha256_text_is_valid(&self.job_identity)
            && windows_sha256_text_is_valid(&self.terminal_response_sha256)
            && self.target_created == self.target_identity.is_some()
            && self
                .frozen_owner_manifest_sha256
                .as_deref()
                .is_none_or(windows_sha256_text_is_valid)
            && [
                &self.target_identity,
                &self.guardian_identity,
                &self.worker_identity,
            ]
            .into_iter()
            .flatten()
            .all(|identity| identity.process_id != 0 && identity.creation_time_100ns != 0)
            && self
                .worker_thread_identity
                .as_ref()
                .is_none_or(|identity| identity.thread_id != 0 && identity.creation_time_100ns != 0)
            && self.authorization_unix_millis.is_none()
            && !self.resume_attempted
            && !self.target_released
            && self.cleanup_state.termination_requested
            && self.cleanup_state.active_processes_zero
            && self.cleanup_state.guardian_reaped
            && self.cleanup_state.final_handles_closed
            && self.recorded_target_and_guardian_extinct
    }

    pub fn canonical_sha256(&self) -> Result<String, serde_json::Error> {
        serde_json::to_vec(&(
            "memcordon.windows-preauthorization-retirement-proof-v1",
            self,
        ))
        .map(|bytes| windows_sha256(&bytes))
    }
}

/// Confirmation issued only from an authenticated, completed retirement ledger.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preauthorization_retirement_proof: Option<WindowsPreauthorizationRetirementProofV1>,
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
            && match (&self.disposition, &self.preauthorization_retirement_proof) {
                (
                    disposition @ WindowsAttemptTerminalDispositionV1::PrematureReleaseFailure {
                        ..
                    },
                    None,
                ) => {
                    disposition.premature_release_mutant().is_some()
                        && windows_sha256_text_is_valid(&self.owner_manifest_sha256)
                        && windows_sha256_text_is_valid(&self.retirement_proof_sha256)
                }
                (WindowsAttemptTerminalDispositionV1::Posttarget, None) => {
                    windows_sha256_text_is_valid(&self.owner_manifest_sha256)
                }
                (WindowsAttemptTerminalDispositionV1::PreauthorizationAbort, Some(proof)) => {
                    self.owner_manifest_sha256.is_empty()
                        && proof.is_consistent()
                        && proof.attempt_id == self.attempt_id
                        && proof.nonce == self.nonce
                        && proof.request_sha256 == self.request_sha256
                        && proof.provider_generation == self.provider_generation
                        && proof.original_boot_id == self.original_boot_id
                        && proof.launch_incarnation == self.launch_incarnation
                        && proof.job_identity == self.job_identity
                        && proof.terminal_response_sha256 == self.terminal_response_sha256
                        && proof
                            .canonical_sha256()
                            .is_ok_and(|digest| digest == self.retirement_proof_sha256)
                }
                _ => false,
            }
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
pub enum WindowsProviderResponse<Terminal, Rejection, Mutant = WindowsMutantNativeReceiptV2> {
    WorkloadAccepted(crate::WindowsWorkloadAcceptedV1),
    PreallocationCancelled(crate::WindowsPreallocationCancellationV1),
    WorkloadPrepared(crate::WindowsWorkloadPreparedV1),
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        control_site: Option<Box<WindowsControlWorkerSiteV1>>,
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
    CertificationMutantHookObserved(Mutant),
    CertificationMutantObserved(Mutant),
    Terminal(Terminal),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: Rejection,
    },
    AttemptRetainedV2(WindowsAttemptRetainedV2),
    ReplayPendingV2(WindowsReplayPendingV2),
    TerminalRetiredV2(WindowsTerminalRetiredV2),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)] // Preserve the direct, typed wire payload variants.
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WindowsLauncherResponse<Terminal, Rejection, Mutant = WindowsMutantNativeReceiptV2> {
    WorkloadPrepared(crate::WindowsWorkloadPreparedV1),
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
    CertificationMutantHookObserved(Mutant),
    CertificationMutantObserved(Mutant),
    Terminal(Terminal),
    Reject {
        schema_version: u32,
        attempt_id: String,
        nonce: String,
        request_sha256: String,
        rejection: Rejection,
    },
    AttemptRetainedV2(WindowsAttemptRetainedV2),
    ReplayPendingV2(WindowsReplayPendingV2),
    TerminalRetiredV2(WindowsTerminalRetiredV2),
}

trait ExpirableRejectionDiagnostics {
    fn clear_expirable_diagnostics(&mut self);
}

macro_rules! terminal_authority_encoding {
    ($response:ty) => {
        impl $response {
            /// Expirable diagnostics are not immutable outbox or ACK authority.
            pub fn terminal_authority_json(&self) -> Result<String, serde_json::Error> {
                let mut authority = self.clone();
                if let Self::Reject { rejection, .. } = &mut authority {
                    rejection.clear_expirable_diagnostics();
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

#[path = "windows_current.rs"]
mod current;
pub use current::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsRetirementProofSourceV2 {
    LiveNative,
    GuardianRecovery,
    PriorBoot,
    CapabilityExtinction,
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
