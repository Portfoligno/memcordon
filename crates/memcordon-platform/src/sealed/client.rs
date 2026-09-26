use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::digest::OutputSizeUser;
use sha2::{Digest, Sha256};

const ENDPOINT: &str = "/run/memcordon/sealed-agent.sock";
const VERSION: u16 = 3;
const PRIVATE_VERSION: u16 = 4;
const PRIVATE_LAUNCH_KIND: u16 = 10;
const PRIVATE_PLAN_KIND: u16 = 13;
const PRIVATE_TERMINAL_KIND: u16 = 105;
const PRIVATE_REJECTION_KIND: u16 = 106;
const PRIVATE_INDETERMINATE_KIND: u16 = 110;
const PRIVATE_PLAN_RECEIPT_KIND: u16 = 111;
const HEADER_LENGTH: usize = 72;
const MAX_FRAME: usize = 1024 * 1024;
const MAX_NATIVE_VALUE: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeReceipt {
    pub version: String,
    pub provider_identity: String,
    pub control_service_identity: String,
    pub launcher_service_identity: String,
    pub receipt_digest: String,
    pub setid_transition_certification_digest: String,
    pub sudo_transition_certification_digest: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct QualificationReceipt {
    schema_version: u32,
    workload_profile: memcordon_core::workload_contract::ProfileRef,
    workload_profile_probe_verified: bool,
    version: String,
    mechanism: String,
    provider_identity: String,
    control_service_identity: String,
    launcher_service_identity: String,
    receipt_digest: String,
    unified_cgroup_v2: bool,
    private_cgroup_subtree: bool,
    clone3: bool,
    clone3_into_cgroup: bool,
    pid_namespace: bool,
    mount_namespace: bool,
    cgroup_namespace: bool,
    pidfd: bool,
    close_range: bool,
    guardian_outside_boundary: bool,
    target_gated: bool,
    assignment_verified: bool,
    inherited_descriptors_verified: bool,
    spawn_error_reporting_verified: bool,
    frontend_loss_authority_verified: bool,
    cgroup_kill: bool,
    workload_empty: bool,
    helpers_reaped: bool,
    boundary_retired: bool,
    recovery_complete: bool,
    split_control_and_launcher_services: bool,
    launcher_no_new_privs_disabled: bool,
    caller_mount_namespace_reproduction_verified: bool,
    caller_no_new_privs_reproduction_verified: bool,
    caller_capability_bounding_set_reproduction_verified: bool,
    initial_provider_capabilities_absent: bool,
    credential_transition_disposition: String,
    setid_transition_certification_digest: String,
    sudo_transition_certification_digest: String,
    post_transition_cgroup_membership_verified: bool,
    post_transition_pid_namespace_verified: bool,
    post_transition_cleanup_verified: bool,
    recursive_provider_request_rejected: bool,
}

impl QualificationReceipt {
    fn is_complete(&self) -> bool {
        self.schema_version == 3
            && self.workload_profile
                == memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate.reference()
            && self.workload_profile_probe_verified
            && self.mechanism == "linux-pid-namespace-cgroup-v2"
            && self.provider_identity == "memcordon-sealed-agent-v2"
            && self.control_service_identity == "memcordon-sealed-agent.service:v2"
            && self.launcher_service_identity == "memcordon-sealed-launcher.service:v2"
            && valid_sha256(&self.receipt_digest)
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.spawn_error_reporting_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete
            && self.split_control_and_launcher_services
            && self.launcher_no_new_privs_disabled
            && self.caller_mount_namespace_reproduction_verified
            && self.caller_no_new_privs_reproduction_verified
            && self.caller_capability_bounding_set_reproduction_verified
            && self.initial_provider_capabilities_absent
            && self.credential_transition_disposition == "preserve-caller-envelope"
            && valid_sha256(&self.setid_transition_certification_digest)
            && valid_sha256(&self.sudo_transition_certification_digest)
            && self.post_transition_cgroup_membership_verified
            && self.post_transition_pid_namespace_verified
            && self.post_transition_cleanup_verified
            && self.recursive_provider_request_rejected
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == <Sha256 as OutputSizeUser>::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn parse_qualification(payload: &[u8]) -> Result<QualificationReceipt, String> {
    let receipt: QualificationReceipt =
        serde_json::from_slice(payload).map_err(|error| error.to_string())?;
    if receipt.is_complete() {
        Ok(receipt)
    } else {
        Err("provider qualification receipt is incomplete or incompatible".to_owned())
    }
}

#[allow(dead_code)]
pub struct TerminalReceipt {
    pub policy_enforcement: memcordon_core::workload_evidence::AttemptPolicyEnforcementV1,
    pub schema_version: u32,
    pub mechanism: String,
    pub status: Option<i32>,
    pub policy_revoked: bool,
    pub exec_status: TerminalExecStatus,
    pub spawn_error_reported: bool,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub target_initial_credentials_verified: bool,
    pub initial_provider_capabilities_absent: bool,
    pub caller_envelope_digest: String,
    pub caller_no_new_privs: bool,
    pub target_no_new_privs_matched: bool,
    pub caller_capability_bounding_set_digest: String,
    pub target_capability_bounding_set_matched: bool,
    pub caller_mount_namespace_digest: String,
    pub target_mount_context_derived_from_caller: bool,
    pub credential_transition_disposition: memcordon_core::CredentialTransitionDisposition,
    pub boundary_independent_of_credentials: bool,
    pub descriptors_verified: bool,
    pub writable_ancestor_cgroup_denied: bool,
    pub parent_namespace_handles_denied: bool,
    pub recursive_provider_request_denied: bool,
    pub guardian_ready: bool,
    pub frontend_loss_authority: bool,
    pub cgroup_kill: bool,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecStatus {
    Succeeded,
    Failed {
        class: TerminalExecFailureClass,
        os_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecFailureClass {
    NotFound,
    NotExecutable,
    Other,
}

#[derive(Debug)]
pub enum LaunchError {
    Transport(String),
    Rejected(Box<memcordon_core::ProviderRejectionEvidence>),
}

/// These are knowledge states, not a request to send another release byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateReleaseKnowledgeV2 {
    NotReleased,
    PossiblyReleased,
    Released,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateReplayDispositionV2 {
    /// The failed request allocated no target. A later launch needs fresh admission.
    NewAttemptWithFreshAdmission,
    /// Recover the historical receipt for this identity, never launch it again.
    QuerySameAttemptOnly,
    /// Neither automatic retry nor a second release is authorized.
    DoNotReplay,
}

/// Values must come from independent installed-runtime readback, not from the
/// report being decoded. The live provider socket supplies terminal authority.
pub struct PrivateExpectedResultV2<'a> {
    pub source_commit: &'a str,
    pub native_abi: memcordon_core::workload_evidence_v2::QualifiedNativeAbiV2,
    pub runtime_manifest_sha256: &'a memcordon_core::DiagnosticSha256,
    pub installed_qualification_sha256: &'a memcordon_core::DiagnosticSha256,
}

pub struct PrivateAuthenticatedTerminalV2 {
    report: memcordon_core::report_v11::PrivateExecutionReportV11,
    raw_response: Vec<u8>,
    restart_safety: memcordon_core::RestartSafetyProof,
}

impl PrivateAuthenticatedTerminalV2 {
    pub fn report(&self) -> &memcordon_core::report_v11::PrivateExecutionReportV11 {
        &self.report
    }

    pub fn raw_response(&self) -> &[u8] {
        &self.raw_response
    }

    pub fn restart_safety(&self) -> &memcordon_core::RestartSafetyProof {
        &self.restart_safety
    }
}

pub enum PrivateServiceResultV2 {
    Complete(Box<PrivateAuthenticatedTerminalV2>),
    Rejected {
        evidence: Box<memcordon_core::ProviderRejectionEvidence>,
        raw_response: Vec<u8>,
        release_knowledge: PrivateReleaseKnowledgeV2,
    },
    Indeterminate {
        attempt_id: [u8; 16],
        raw_response: Vec<u8>,
        reason_code: String,
    },
}

/// One authenticated, non-allocating public V2 plan exchange. The raw bytes
/// are the provider's exact response payload, retained for release evidence;
/// neither variant authorizes a later target release.
pub enum PrivatePlanExchangeV2 {
    Available {
        receipt: memcordon_core::workload_plan_v2::PrivatePlanReceiptV2,
        raw_response: Vec<u8>,
    },
    Rejected {
        evidence: Box<memcordon_core::ProviderRejectionEvidence>,
        raw_response: Vec<u8>,
    },
}

impl PrivateServiceResultV2 {
    pub fn release_knowledge(&self) -> PrivateReleaseKnowledgeV2 {
        match self {
            Self::Complete(_) => PrivateReleaseKnowledgeV2::Released,
            Self::Rejected {
                release_knowledge, ..
            } => *release_knowledge,
            Self::Indeterminate { .. } => PrivateReleaseKnowledgeV2::PossiblyReleased,
        }
    }

    pub fn replay_disposition(&self) -> PrivateReplayDispositionV2 {
        match self {
            Self::Complete(_) => PrivateReplayDispositionV2::QuerySameAttemptOnly,
            Self::Rejected {
                release_knowledge: PrivateReleaseKnowledgeV2::NotReleased,
                ..
            } => PrivateReplayDispositionV2::NewAttemptWithFreshAdmission,
            Self::Rejected { .. } | Self::Indeterminate { .. } => {
                PrivateReplayDispositionV2::DoNotReplay
            }
        }
    }
}

/// A failed read after request submission cannot establish that release did not
/// occur. Preserve the raw response if one was received but failed validation.
#[derive(Debug)]
pub struct PrivateResponseFailureV2 {
    pub detail: String,
    pub raw_response: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum PrivateLaunchErrorV2 {
    /// No request bytes were submitted to the provider.
    BeforeSubmission(String),
    /// Submission may have reached the provider; no release retry is safe.
    AfterSubmission(PrivateResponseFailureV2),
}

impl PrivateLaunchErrorV2 {
    pub fn release_knowledge(&self) -> PrivateReleaseKnowledgeV2 {
        match self {
            Self::BeforeSubmission(_) => PrivateReleaseKnowledgeV2::NotReleased,
            Self::AfterSubmission(failure) => failure.release_knowledge(),
        }
    }

    pub fn replay_disposition(&self) -> PrivateReplayDispositionV2 {
        match self {
            Self::BeforeSubmission(_) => PrivateReplayDispositionV2::NewAttemptWithFreshAdmission,
            Self::AfterSubmission(failure) => failure.replay_disposition(),
        }
    }
}

impl PrivateResponseFailureV2 {
    pub fn release_knowledge(&self) -> PrivateReleaseKnowledgeV2 {
        PrivateReleaseKnowledgeV2::PossiblyReleased
    }

    pub fn replay_disposition(&self) -> PrivateReplayDispositionV2 {
        PrivateReplayDispositionV2::DoNotReplay
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateIndeterminateV11 {
    schema_version: u32,
    attempt_id: String,
    release_knowledge: String,
    retirement_knowledge: String,
    replay_disposition: String,
    reason_code: String,
}

#[allow(
    clippy::result_large_err,
    reason = "the backend boundary preserves the public categorized Error contract"
)]
pub fn run(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
) -> Result<crate::backend::Execution, memcordon_core::Error> {
    let started = std::time::Instant::now();
    let qualification = probe().map_err(|error| {
        memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Setup,
            "MCSEALED-PROVIDER-QUALIFICATION",
            error,
        )
    })?;
    let terminal = launch(policy, command, context, started).map_err(|error| match error {
        LaunchError::Transport(detail) => memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Setup,
            "MCSEALED-PROVIDER-TRANSACTION",
            detail,
        ),
        LaunchError::Rejected(rejection) => {
            let rejection = *rejection;
            if rejection
                .workload_admission
                .as_ref()
                .is_some_and(|admission| {
                    policy.workload_contract().is_none_or(|contract| {
                        memcordon_core::workload_evidence::RequestBindingV1::from_contract(contract)
                            .as_ref()
                            != Ok(&admission.request)
                    })
                })
            {
                return memcordon_core::Error::new(
                    memcordon_core::ErrorCategory::Monitor,
                    "MCSEALED-WORKLOAD-REJECTION",
                    "provider admission rejection belongs to another request",
                );
            }
            let restart_safety = rejection.restart_safety.clone();
            let mut error = memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Setup,
                "MCSEALED-PROVIDER-REJECTION",
                format!(
                    "provider rejected launch [{}]: {}",
                    rejection.code, rejection.detail
                ),
            )
            .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
                requested: memcordon_core::BoundaryRequirement::Sealed,
                mechanism: Some("linux-pid-namespace-cgroup-v2".to_owned()),
                phase: rejection.phase,
                target_created: rejection.target_created,
                target_released: rejection.target_released,
                cleanup_attempted: rejection.cleanup_attempted,
                restart_safety,
            })
            .with_provider_rejection(rejection.clone());
            error.launch_phase = Some(boundary_phase_name(rejection.phase));
            error.workload_may_be_alive =
                rejection.target_created && rejection.restart_safety.workload_empty != Some(true);
            if matches!(
                rejection.phase,
                memcordon_core::BoundarySetupPhase::ResourceVerification
                    | memcordon_core::BoundarySetupPhase::Authorization
                    | memcordon_core::BoundarySetupPhase::Monitoring
                    | memcordon_core::BoundarySetupPhase::Retirement
            ) {
                error.cgroup_verified_before_release = true;
                error.guardian_ready_before_release = true;
            }
            error
        }
    })?;
    if !terminal
        .policy_enforcement
        .matches_terminal_request(policy.workload_contract())
    {
        return Err(memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Monitor,
            "MCSEALED-WORKLOAD-TERMINAL",
            "terminal workload binding differs from the exact request",
        ));
    }
    if let memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::Authorized {
        admission,
        ..
    } = &terminal.policy_enforcement
    {
        super::linux_runtime::verify(&admission.plan.provider).map_err(|detail| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-WORKLOAD-TERMINAL",
                detail,
            )
        })?;
    }
    let cleanup = memcordon_core::CleanupSummary {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        errors: Vec::new(),
        ..memcordon_core::CleanupSummary::default()
    };
    let restart_safety = terminal_restart_safety(&terminal);
    if terminal.policy_revoked {
        return Err(terminal_revocation_error(
            &terminal,
            cleanup,
            restart_safety,
        ));
    }
    if let TerminalExecStatus::Failed { class, os_code } = terminal.exec_status {
        return Err(terminal_spawn_error(
            &terminal,
            class,
            os_code,
            cleanup,
            restart_safety,
        ));
    }
    let child = memcordon_core::ChildTermination::ExitCode {
        code: terminal
            .status
            .expect("ordinary terminal status was validated"),
    };
    let outcome = if terminal.memory_limit_exceeded {
        let limit = policy.memory.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-MEMORY-EVIDENCE",
                "provider reported a memory limit without a configured limit",
            )
        })?;
        memcordon_core::RunOutcome::LimitExceeded {
            limit,
            observed: None,
            peak: None,
            evidence: memcordon_core::LimitEvidence {
                backend: "linux-pid-namespace-cgroup-v2".to_owned(),
                metric: "memory.current".to_owned(),
                detail: "memory.events oom_kill incremented".to_owned(),
            },
            child_after_termination: Some(child),
            cleanup,
        }
    } else if terminal.deadline_exceeded {
        let configured = policy.deadline.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider reported a deadline without a configured deadline",
            )
        })?;
        let duration_ms = configured.duration().as_millis() as u64;
        let deadline = memcordon_core::DeadlineEvidence::new(
            duration_ms,
            configured.scope(),
            "provider-absolute-deadline".to_owned(),
            duration_ms,
            duration_ms,
            policy.limit_grace.as_millis() as u64,
            0,
            None,
            Some("cgroup.kill".to_owned()),
        )
        .map_err(|_| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider deadline evidence was inconsistent",
            )
        })?;
        memcordon_core::RunOutcome::DeadlineExceeded {
            deadline,
            child_after_termination: Some(child),
            peak: None,
            cleanup,
        }
    } else {
        memcordon_core::RunOutcome::Exited {
            child,
            peak: None,
            cleanup,
        }
    };
    let evidence = memcordon_core::LinuxSealedEvidenceV2 {
        schema_version: 2,
        provider_identity: qualification.provider_identity.clone(),
        control_service_identity: qualification.control_service_identity.clone(),
        launcher_service_identity: qualification.launcher_service_identity.clone(),
        cgroup_identity_digest: qualification.receipt_digest.clone(),
        cgroup_created: true,
        cgroup_owned_by_provider: true,
        memory_configuration_verified: true,
        init_created_into_cgroup: terminal.assignment_verified,
        pid_namespace_created: terminal.namespaces_verified,
        mount_namespace_created: terminal.namespaces_verified,
        cgroup_namespace_created: terminal.namespaces_verified,
        target_pidfd_verified: true,
        target_cgroup_membership_verified: terminal.assignment_verified,
        target_pid_namespace_verified: terminal.namespaces_verified,
        target_initial_credentials_verified: terminal.target_initial_credentials_verified,
        initial_provider_capabilities_absent: terminal.initial_provider_capabilities_absent,
        caller_no_new_privs_reproduced: terminal.target_no_new_privs_matched,
        caller_capability_bounding_set_reproduced: terminal.target_capability_bounding_set_matched,
        caller_mount_context_reproduced: terminal.target_mount_context_derived_from_caller,
        credential_transition_disposition: terminal.credential_transition_disposition,
        boundary_independent_of_credentials: terminal.boundary_independent_of_credentials,
        inherited_descriptors_verified: terminal.descriptors_verified,
        writable_ancestor_cgroup_denied: terminal.writable_ancestor_cgroup_denied,
        parent_namespace_handles_denied: terminal.parent_namespace_handles_denied,
        recursive_provider_request_denied: terminal.recursive_provider_request_denied,
        guardian_ready: terminal.guardian_ready,
        target_released: true,
        cgroup_kill_invoked: terminal.cgroup_kill,
        cgroup_empty_verified: terminal.cgroup_empty,
        namespace_init_reaped: terminal.init_reaped,
        guardian_reaped: terminal.guardian_reaped,
        cgroup_removed: terminal.boundary_retired,
    };
    Ok(crate::backend::Execution {
        policy_enforcement: terminal.policy_enforcement.clone(),
        outcome,
        backend: crate::linux_cgroup::sealed_info(qualification),
        child_pid: std::num::NonZeroU32::new(terminal.target_pid),
        runtime: None,
        duration: started.elapsed(),
        authorization_offset: Some(Duration::from_millis(terminal.authorization_offset_millis)),
        launch: memcordon_core::LaunchEvidence {
            mechanism: "linux-pid-namespace-cgroup-v2".to_owned(),
            target_released: true,
            containment_verified_before_authorization: terminal.assignment_verified
                && terminal.namespaces_verified,
            guardian_started_before_authorization: terminal.guardian_ready,
            target_spawn_error_reported: terminal.spawn_error_reported,
            boundary_requested: memcordon_core::BoundaryRequirement::Sealed,
            boundary_effective: memcordon_core::BoundaryClass::Sealed,
            boundary_assignment_verified: terminal.assignment_verified,
            boundary_reconfiguration_denied: terminal.writable_ancestor_cgroup_denied,
            inherited_resources_restricted: terminal.descriptors_verified,
            frontend_loss_cleanup_authority_verified: terminal.frontend_loss_authority,
        },
        restart_safety,
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV2(
            evidence,
        ),
    })
}

pub(crate) fn terminal_restart_safety(
    terminal: &TerminalReceipt,
) -> memcordon_core::RestartSafetyProof {
    memcordon_core::RestartSafetyProof {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        helpers_reaped: terminal.init_reaped && terminal.guardian_reaped,
        containment_removed: terminal.boundary_retired,
        containment_incapable_of_live_members: terminal.cgroup_empty,
        sealed_boundary_retired: terminal.boundary_retired,
        errors: Vec::new(),
    }
}

pub(crate) fn terminal_revocation_error(
    terminal: &TerminalReceipt,
    cleanup: memcordon_core::CleanupSummary,
    restart_safety: memcordon_core::RestartSafetyProof,
) -> memcordon_core::Error {
    let mut error = memcordon_core::Error::new(
        memcordon_core::ErrorCategory::Monitor,
        "MCSEALED-POLICY-DRIFT",
        "active grant revoked; workload retired without an observed child exit status",
    )
    .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
        requested: memcordon_core::BoundaryRequirement::Sealed,
        mechanism: Some("linux-pid-namespace-cgroup-v2".to_owned()),
        phase: memcordon_core::BoundarySetupPhase::Retirement,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: restart_safety.clone(),
    });
    error.target_pid = Some(terminal.target_pid);
    error.launch_phase = Some("policy-revoked");
    error.target_released = true;
    error.authorization_offset = Some(Duration::from_millis(terminal.authorization_offset_millis));
    error.policy_enforcement = Some(terminal.policy_enforcement.clone());
    error.cgroup_verified_before_release = terminal.assignment_verified
        && terminal.namespaces_verified
        && terminal.target_initial_credentials_verified
        && terminal.initial_provider_capabilities_absent
        && terminal.target_no_new_privs_matched
        && terminal.target_capability_bounding_set_matched
        && terminal.target_mount_context_derived_from_caller
        && terminal.descriptors_verified
        && terminal.writable_ancestor_cgroup_denied;
    error.guardian_ready_before_release = terminal.guardian_ready;
    error.workload_may_be_alive =
        !restart_safety.is_safe_for(memcordon_core::BoundaryRequirement::Sealed);
    error.cleanup = cleanup;
    error.restart_safety = Some(restart_safety);
    error
}

pub(crate) fn terminal_spawn_error(
    terminal: &TerminalReceipt,
    class: TerminalExecFailureClass,
    os_code: i32,
    cleanup: memcordon_core::CleanupSummary,
    restart_safety: memcordon_core::RestartSafetyProof,
) -> memcordon_core::Error {
    let (code, initial_spawn_failure) = match class {
        TerminalExecFailureClass::NotFound => (
            "MCSPAWN-NOT-FOUND",
            Some(memcordon_core::InitialSpawnFailure::NotFound),
        ),
        TerminalExecFailureClass::NotExecutable => (
            "MCSPAWN-NOT-EXECUTABLE",
            Some(memcordon_core::InitialSpawnFailure::NotExecutable),
        ),
        TerminalExecFailureClass::Other => ("MCSPAWN-FAILED", None),
    };
    let detail = format!(
        "sealed provider reported a verified target exec failure with native OS code {os_code}"
    );
    let provider_rejection = memcordon_core::ProviderRejectionEvidence {
        workload_admission: None,
        provider_failure: None,
        schema_version: 1,
        code: code.to_owned(),
        phase: memcordon_core::BoundarySetupPhase::TargetCreation,
        detail: detail.clone(),
        os_code: Some(os_code),
        loader_qualification: None,
        target_created: true,
        target_released: true,
        cleanup_attempted: true,
        restart_safety: restart_safety.clone(),
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let mut error = memcordon_core::Error::new(memcordon_core::ErrorCategory::Spawn, code, detail)
        .with_provider_rejection(provider_rejection)
        .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
            requested: memcordon_core::BoundaryRequirement::Sealed,
            mechanism: Some("linux-pid-namespace-cgroup-v2".to_owned()),
            phase: memcordon_core::BoundarySetupPhase::TargetCreation,
            target_created: true,
            target_released: true,
            cleanup_attempted: true,
            restart_safety: restart_safety.clone(),
        });
    if let Some(failure) = initial_spawn_failure {
        error = error.with_initial_spawn_failure(failure);
    }
    error.os_code = Some(os_code);
    error.target_pid = Some(terminal.target_pid);
    error.launch_phase = Some("target-spawn-failed");
    error.target_released = true;
    error.authorization_offset = Some(Duration::from_millis(terminal.authorization_offset_millis));
    error.cgroup_verified_before_release = terminal.assignment_verified
        && terminal.namespaces_verified
        && terminal.target_initial_credentials_verified
        && terminal.initial_provider_capabilities_absent
        && terminal.target_no_new_privs_matched
        && terminal.target_capability_bounding_set_matched
        && terminal.target_mount_context_derived_from_caller
        && terminal.descriptors_verified
        && terminal.writable_ancestor_cgroup_denied;
    error.guardian_ready_before_release = terminal.guardian_ready;
    error.workload_may_be_alive =
        !restart_safety.is_safe_for(memcordon_core::BoundaryRequirement::Sealed);
    error.cleanup = cleanup;
    error.restart_safety = Some(restart_safety);
    error
}

pub(crate) fn launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    context: crate::supervisor::AttemptContext,
    started: std::time::Instant,
) -> Result<TerminalReceipt, LaunchError> {
    verify_endpoint().map_err(LaunchError::Transport)?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT))
        .map_err(|error| LaunchError::Transport(error.to_string()))?;
    verify_peer(&stream).map_err(LaunchError::Transport)?;
    let attempt = nonce().map_err(LaunchError::Transport)?;
    let nonce = nonce().map_err(LaunchError::Transport)?;
    let deadline_budget = effective_deadline_duration(policy, context, started.elapsed());
    let payload = encode_launch(policy, command, deadline_budget, context.restart_attempt)
        .map_err(LaunchError::Transport)?;
    let frame = encoded_frame(2, nonce, attempt, &payload).map_err(LaunchError::Transport)?;
    let cwd = fs::File::open(".").map_err(|error| LaunchError::Transport(error.to_string()))?;
    let frontend_pidfd = pidfd_self().map_err(LaunchError::Transport)?;
    let descriptors = [cwd.as_raw_fd(), 0, 1, 2, frontend_pidfd.as_raw_fd()];
    send_with_descriptors(&stream, &frame, &descriptors).map_err(LaunchError::Transport)?;
    let WireFrame {
        kind,
        nonce: returned_nonce,
        attempt: returned_attempt,
        payload,
    } = read_frame(&mut stream).map_err(LaunchError::Transport)?;
    if returned_nonce != nonce || returned_attempt != attempt {
        return Err(LaunchError::Transport(
            "provider terminal receipt identity mismatch".to_owned(),
        ));
    }
    if kind == 106 {
        return Err(LaunchError::Rejected(Box::new(
            parse_rejection(&payload).map_err(|error| {
                LaunchError::Transport(format!("invalid provider rejection: {error}"))
            })?,
        )));
    }
    if kind != 105 {
        return Err(LaunchError::Transport(
            "provider omitted terminal receipt".to_owned(),
        ));
    }
    let terminal = parse_terminal(&payload).map_err(LaunchError::Transport)?;
    let attempt_identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| LaunchError::Transport(error.to_string()))?;
    if !terminal.policy_enforcement.valid_native_terminal(
        policy.workload_contract(),
        memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate,
        &attempt_identity,
        context.restart_attempt,
        boot.trim(),
    ) {
        return Err(LaunchError::Transport(
            "terminal workload native attempt binding differs".into(),
        ));
    }
    Ok(terminal)
}

pub(crate) fn parse_rejection(
    payload: &[u8],
) -> Result<memcordon_core::ProviderRejectionEvidence, String> {
    memcordon_core::provider_rejection_wire::RejectionWireV1::parse_evidence(payload)
}

fn boundary_phase_name(phase: memcordon_core::BoundarySetupPhase) -> &'static str {
    match phase {
        memcordon_core::BoundarySetupPhase::RequestValidation => "request-validation",
        memcordon_core::BoundarySetupPhase::ProviderConnection => "provider-connection",
        memcordon_core::BoundarySetupPhase::ProviderIdentity => "provider-identity",
        memcordon_core::BoundarySetupPhase::CallerEnvelopeCapture => "caller-envelope-capture",
        memcordon_core::BoundarySetupPhase::LauncherServiceAuthentication => {
            "launcher-service-authentication"
        }
        memcordon_core::BoundarySetupPhase::CallerMountNamespaceAdoption => {
            "caller-mount-namespace-adoption"
        }
        memcordon_core::BoundarySetupPhase::CallerCapabilityEnvelope => {
            "caller-capability-envelope"
        }
        memcordon_core::BoundarySetupPhase::CredentialTransitionPolicy => {
            "credential-transition-policy"
        }
        memcordon_core::BoundarySetupPhase::BoundaryCreation => "boundary-creation",
        memcordon_core::BoundarySetupPhase::GuardianStartup => "guardian-startup",
        memcordon_core::BoundarySetupPhase::TargetCreation => "target-creation",
        memcordon_core::BoundarySetupPhase::AssignmentVerification => "assignment-verification",
        memcordon_core::BoundarySetupPhase::ResourceVerification => "resource-verification",
        memcordon_core::BoundarySetupPhase::Authorization => "authorization",
        memcordon_core::BoundarySetupPhase::Monitoring => "monitoring",
        memcordon_core::BoundarySetupPhase::Retirement => "retirement",
    }
}

pub fn workload_discovery()
-> Result<memcordon_core::workload_discovery::WorkloadDiscoveryV1, String> {
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let nonce = nonce()?;
    write_frame(&mut stream, 9, nonce, [0; 16], &[])?;
    let frame = read_frame(&mut stream)?;
    if frame.kind != 109
        || frame.nonce != nonce
        || frame.attempt != [0; 16]
        || frame.payload.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
    {
        return Err("discovery receipt identity or size differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&frame.payload)?;
    let discovery: memcordon_core::workload_discovery::WorkloadDiscoveryV1 =
        serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
    if !discovery.validate(memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate) {
        return Err("discovery profile differs".into());
    }
    super::linux_runtime::verify(&discovery.provider)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    if boot.trim() != discovery.boot_identity.as_str() {
        return Err("discovery boot differs".into());
    }
    Ok(discovery)
}

pub fn workload_plan(
    contract: &memcordon_core::workload_contract::WorkloadContractV1,
) -> Result<memcordon_core::workload_evidence::WorkloadResolutionReportV1, String> {
    use memcordon_core::workload_evidence::WorkloadResolutionReportV1;
    contract.validate()?;
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let nonce = nonce()?;
    let payload = serde_json::to_vec(contract).map_err(|error| error.to_string())?;
    if payload.len() > memcordon_core::workload_limits::CONTRACT_BYTES {
        return Err("encoded workload request exceeds limit".into());
    }
    write_frame(&mut stream, 8, nonce, [0; 16], &payload)?;
    let frame = read_frame(&mut stream)?;
    if frame.kind != 108
        || frame.nonce != nonce
        || frame.attempt != [0; 16]
        || frame.payload.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
    {
        return Err("workload plan receipt identity or size differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&frame.payload)?;
    let response: WorkloadResolutionReportV1 =
        serde_json::from_slice(&frame.payload).map_err(|error| error.to_string())?;
    if !response.valid_plan_response(
        contract,
        memcordon_core::workload_registry::BaselineProfile::LinuxUnixCreate,
    ) {
        return Err("workload plan request or effective binding differs".into());
    }
    match &response {
        WorkloadResolutionReportV1::Planned { binding, .. } => {
            super::linux_runtime::verify(&binding.provider)?;
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .map_err(|error| error.to_string())?;
            if boot.trim() != binding.boot_identity.as_str() {
                return Err("workload plan boot binding differs".into());
            }
        }
        WorkloadResolutionReportV1::Rejected { .. }
        | WorkloadResolutionReportV1::Unavailable { .. } => {}
        _ => return Err("workload plan returned an execution state".into()),
    }
    Ok(response)
}

pub fn probe() -> Result<ProbeReceipt, String> {
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT))
        .map_err(|error| provider_installation_error("provider connection failed", &error))?;
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let nonce = nonce()?;
    write_frame(&mut stream, 1, nonce, [0; 16], &[])?;
    let WireFrame {
        kind,
        nonce: returned_nonce,
        attempt,
        payload,
    } = read_frame(&mut stream)?;
    if kind != 101 || returned_nonce != nonce || attempt != [0; 16] {
        return Err("provider probe receipt identity mismatch".to_owned());
    }
    let receipt = parse_qualification(&payload)?;
    validate_exact_provider_pairing(
        env!("CARGO_PKG_VERSION"),
        &receipt.version,
        "CLI",
        "installed provider",
    )?;
    Ok(ProbeReceipt {
        version: receipt.version,
        provider_identity: receipt.provider_identity,
        control_service_identity: receipt.control_service_identity,
        launcher_service_identity: receipt.launcher_service_identity,
        receipt_digest: receipt.receipt_digest,
        setid_transition_certification_digest: receipt.setid_transition_certification_digest,
        sudo_transition_certification_digest: receipt.sudo_transition_certification_digest,
    })
}

pub(crate) fn validate_exact_provider_pairing(
    cli_version: &str,
    provider_version: &str,
    cli_channel: &str,
    provider_channel: &str,
) -> Result<(), String> {
    if provider_version != cli_version {
        return Err(format!(
            "sealed provider version mismatch before target authorization: {cli_channel} version {cli_version}; {provider_channel} version {provider_version}; install the matching memcordon package version and rerun package upgrade"
        ));
    }
    Ok(())
}

pub(crate) fn provider_installation_error(context: &str, error: &std::io::Error) -> String {
    let agent = invoked_executable_path()
        .and_then(|executable| executable.parent().map(Path::to_path_buf))
        .map(|directory| directory.join("memcordon-sealed-agent"))
        .unwrap_or_else(|| Path::new("memcordon-sealed-agent").to_path_buf());
    format!(
        "sealed provider is not installed or reachable: {context}: {error}\n\nCargo installation:\n  install the matching memcordon package version, then run:\n  {} package install\n\nNative archive:\n  run the memcordon-sealed-agent included beside this executable",
        agent.display()
    )
}

fn invoked_executable_path() -> Option<std::path::PathBuf> {
    let invoked = std::env::args_os().next().map(std::path::PathBuf::from)?;
    if invoked.components().count() > 1 {
        return fs::canonicalize(invoked).ok();
    }
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(&invoked))
            .find_map(|candidate| fs::canonicalize(candidate).ok())
    })
}

fn verify_endpoint() -> Result<(), String> {
    let metadata = fs::symlink_metadata(ENDPOINT)
        .map_err(|error| provider_installation_error("provider endpoint unavailable", &error))?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o007 != 0 {
        return Err("provider endpoint is not a root-owned socket identity".to_owned());
    }
    let launcher = fs::symlink_metadata("/run/memcordon/sealed-launcher.sock")
        .map_err(|error| provider_installation_error("launcher endpoint unavailable", &error))?;
    if !launcher.file_type().is_socket()
        || launcher.uid() != 0
        || launcher.gid() != 0
        || launcher.mode() & 0o777 != 0o600
    {
        return Err("launcher endpoint is not a root-only socket identity".to_owned());
    }
    let executable = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| provider_installation_error("provider executable unavailable", &error))?;
    if !executable.file_type().is_file() || executable.uid() != 0 || executable.mode() & 0o022 != 0
    {
        return Err("provider executable identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

fn verify_peer(stream: &UnixStream) -> Result<(), String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are initialized writable values of the exact
    // SO_PEERCRED ABI sizes; the borrowed stream fd remains open for the call.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    } == -1
        || credentials.uid != 0
    {
        return Err("connected provider peer is not root-owned".to_owned());
    }
    Ok(())
}

fn encode_launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    deadline_budget: Option<Duration>,
    restart_attempt: u64,
) -> Result<Vec<u8>, String> {
    if command.arguments().len() > MAX_ARGUMENTS {
        return Err("launch argument count exceeds protocol limit".to_owned());
    }
    let mut output = Vec::new();
    output.extend_from_slice(&3_u16.to_be_bytes());
    output.extend_from_slice(&restart_attempt.to_be_bytes());
    put_bytes(&mut output, command.program().as_bytes())?;
    put_count(&mut output, command.arguments().len())?;
    for argument in command.arguments() {
        put_bytes(&mut output, argument.as_bytes())?;
    }
    let environment: Vec<_> = std::env::vars_os().collect();
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("launch environment count exceeds protocol limit".to_owned());
    }
    put_count(&mut output, environment.len())?;
    for (name, value) in environment {
        put_bytes(&mut output, name.as_bytes())?;
        put_bytes(&mut output, value.as_bytes())?;
    }
    put_optional(
        &mut output,
        policy.memory.map(memcordon_core::ByteSize::bytes),
    );
    match policy.swap {
        memcordon_core::SwapPolicy::Bytes(bytes) => {
            output.push(1);
            output.extend_from_slice(&bytes.bytes().to_be_bytes());
        }
        memcordon_core::SwapPolicy::Unlimited => output.push(2),
        memcordon_core::SwapPolicy::Host => output.push(3),
    }
    let absolute_deadline_millis = match deadline_budget {
        Some(duration) => Some(
            monotonic_millis()?.saturating_add(
                u64::try_from(duration.as_millis())
                    .map_err(|_| "sealed deadline exceeds protocol range".to_owned())?,
            ),
        ),
        None => None,
    };
    put_optional(&mut output, absolute_deadline_millis);
    output.push(
        match policy
            .deadline
            .map(|value| value.scope())
            .unwrap_or(memcordon_core::DeadlineScope::Attempt)
        {
            memcordon_core::DeadlineScope::Attempt => 1,
            memcordon_core::DeadlineScope::Supervision => 2,
        },
    );
    output.push(match policy.lifetime {
        memcordon_core::Lifetime::Command => 1,
        memcordon_core::Lifetime::Workload => 2,
    });
    for duration in [
        policy.poll_interval,
        policy.signal_grace,
        policy.command_exit_grace,
        policy.limit_grace,
    ] {
        output.extend_from_slice(&(duration.as_millis() as u64).to_be_bytes());
    }
    put_count(&mut output, 5)?;
    output.extend_from_slice(&[1, 2, 3, 4, 5]);
    match policy.workload_contract() {
        None => output.push(0),
        Some(contract) => {
            contract.validate()?;
            output.push(1);
            put_bytes(
                &mut output,
                &serde_json::to_vec(contract).map_err(|error| error.to_string())?,
            )?;
        }
    }
    Ok(output)
}

fn put_count(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "launch count overflow".to_owned())?
            .to_be_bytes(),
    );
    Ok(())
}
fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_NATIVE_VALUE {
        return Err("launch native value exceeds protocol limit".to_owned());
    }
    put_count(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}
fn put_optional(output: &mut Vec<u8>, value: Option<u64>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn monotonic_millis() -> Result<u64, String> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is an initialized writable timespec of the exact ABI size;
    // CLOCK_MONOTONIC has no additional pointer, lifetime, or thread requirements.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) } != 0 {
        return Err(format!(
            "sealed monotonic clock unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err("sealed monotonic clock returned an invalid timespec".to_owned());
    }
    let seconds = u64::try_from(value.tv_sec)
        .map_err(|_| "sealed monotonic clock seconds are not representable".to_owned())?;
    let nanoseconds = u64::try_from(value.tv_nsec)
        .map_err(|_| "sealed monotonic clock nanoseconds are not representable".to_owned())?;
    Ok(seconds
        .saturating_mul(1000)
        .saturating_add(nanoseconds / 1_000_000))
}

pub(crate) fn effective_deadline_duration(
    policy: &memcordon_core::Policy,
    context: crate::supervisor::AttemptContext,
    setup_elapsed: Duration,
) -> Option<Duration> {
    policy.deadline.map(|deadline| match deadline.scope() {
        memcordon_core::DeadlineScope::Attempt => deadline.duration(),
        memcordon_core::DeadlineScope::Supervision => {
            context.supervision_deadline_remaining.map_or_else(
                || deadline.duration(),
                |remaining| remaining.saturating_sub(setup_elapsed),
            )
        }
    })
}

fn pidfd_self() -> Result<OwnedFd, String> {
    // SAFETY: getpid has no pointer arguments; pidfd_open receives the live caller pid and flags 0.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        // SAFETY: a nonnegative successful pidfd_open result is newly owned by this process.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn encoded_frame(
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    encoded_frame_for_version(VERSION, kind, nonce, attempt, payload)
}

fn encoded_frame_for_version(
    version: u16,
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame exceeds protocol limit".to_owned());
    }
    let total = u32::try_from(total).map_err(|_| "frame exceeds protocol limit".to_owned())?;
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&attempt);
    bytes.extend_from_slice(&Sha256::digest(payload));
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn send_with_descriptors(
    stream: &UnixStream,
    bytes: &[u8],
    descriptors: &[i32],
) -> Result<(), String> {
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: CMSG_SPACE is a pure ABI sizing macro and the descriptor byte count fits u32.
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) } as usize;
    let mut control = vec![0_u8; length];
    // SAFETY: an all-zero msghdr is the required empty initialization before assigning its buffers.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: message_control points at `control`, sized with CMSG_SPACE and alive below.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: `header` lies within `control`; CMSG_LEN bounds the exact descriptor copy and
    // descriptors are borrowed for the duration of sendmsg without transferring local ownership.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            descriptors.len(),
        );
    }
    // SAFETY: all iovec/control pointers refer to live immutable buffers through this synchronous call.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
    if sent != bytes.len() as isize {
        return Err("short provider launch transaction".to_owned());
    }
    Ok(())
}

pub(crate) fn parse_terminal(payload: &[u8]) -> Result<TerminalReceipt, String> {
    if payload.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
        return Err("terminal receipt exceeds limit".into());
    }
    let text = std::str::from_utf8(payload).map_err(|_| "terminal receipt encoding".to_owned())?;
    if !payload.ends_with(b"\n") {
        return Err("terminal receipt is not newline terminated".to_owned());
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| "terminal receipt field is malformed".to_owned())?;
        if name.is_empty() || fields.insert(name, value).is_some() {
            return Err("terminal receipt contains an empty or duplicate field".to_owned());
        }
    }
    let schema_version = take_terminal_field(&mut fields, "schema-version")?
        .parse::<u32>()
        .map_err(|_| "terminal schema version invalid".to_owned())?;
    let mechanism = take_terminal_field(&mut fields, "mechanism")?.to_owned();
    let policy_bytes = take_terminal_field(&mut fields, "policy-enforcement")?.as_bytes();
    memcordon_core::workload_contract::reject_duplicate_json_keys(policy_bytes)?;
    let policy_enforcement: memcordon_core::workload_evidence::AttemptPolicyEnforcementV1 =
        serde_json::from_slice(policy_bytes).map_err(|error| error.to_string())?;
    if !policy_enforcement.is_consistent() {
        return Err("terminal policy enforcement differs".into());
    }
    if schema_version != 2 || mechanism != "linux-pid-namespace-cgroup-v2" {
        return Err("terminal receipt schema or mechanism is incompatible".to_owned());
    }
    let status = match take_terminal_field(&mut fields, "status")? {
        "none" => None,
        value => Some(
            value
                .parse()
                .map_err(|_| "terminal status invalid".to_owned())?,
        ),
    };
    let policy_revoked = match fields.remove("policy-revoked") {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err("terminal revocation flag invalid".to_owned()),
    };
    if policy_revoked != status.is_none() {
        return Err("terminal revocation and observed child status disagree".to_owned());
    }
    let exec_name = take_terminal_field(&mut fields, "exec-status")?;
    let exec_os_code = match take_terminal_field(&mut fields, "exec-os-code")? {
        "none" => None,
        value => Some(
            value
                .parse::<i32>()
                .map_err(|_| "terminal exec OS code invalid".to_owned())?,
        ),
    };
    let spawn_error_reported = take_terminal_fact(&mut fields, "spawn-error-reported")?;
    if !spawn_error_reported {
        return Err("terminal receipt omitted verified spawn-error reporting".to_owned());
    }
    let exec_status = match (exec_name, exec_os_code) {
        ("success", None) => TerminalExecStatus::Succeeded,
        ("not-found", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotFound,
            os_code,
        },
        ("not-executable", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotExecutable,
            os_code,
        },
        ("failed", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::Other,
            os_code,
        },
        _ => return Err("terminal exec status and OS code are contradictory".to_owned()),
    };
    if let TerminalExecStatus::Failed { class, os_code } = exec_status {
        if os_code <= 0 || classify_terminal_exec_error(os_code) != class {
            return Err("terminal exec errno classification mismatch".to_owned());
        }
        let expected_status = match class {
            TerminalExecFailureClass::NotFound => 127,
            TerminalExecFailureClass::NotExecutable | TerminalExecFailureClass::Other => 126,
        };
        if status != Some(expected_status) {
            return Err("terminal exec failure and child status are contradictory".to_owned());
        }
    }
    let target_pid = take_terminal_field(&mut fields, "target-pid")?
        .parse()
        .map_err(|_| "terminal target pid invalid".to_owned())?;
    let authorization_offset_millis =
        take_terminal_field(&mut fields, "authorization-offset-millis")?
            .parse()
            .map_err(|_| "terminal authorization offset invalid".to_owned())?;
    let caller_envelope_digest =
        take_terminal_field(&mut fields, "caller-envelope-digest")?.to_owned();
    let caller_capability_bounding_set_digest =
        take_terminal_field(&mut fields, "caller-capability-bounding-set-digest")?.to_owned();
    let caller_mount_namespace_digest =
        take_terminal_field(&mut fields, "caller-mount-namespace-digest")?.to_owned();
    if !valid_sha256(&caller_envelope_digest)
        || !valid_sha256(&caller_capability_bounding_set_digest)
        || !valid_sha256(&caller_mount_namespace_digest)
    {
        return Err("terminal caller-envelope digest is invalid".to_owned());
    }
    let credential_transition_disposition =
        match take_terminal_field(&mut fields, "credential-transition-disposition")? {
            "preserve-caller-envelope" => {
                memcordon_core::CredentialTransitionDisposition::PreserveCallerEnvelope
            }
            _ => return Err("terminal credential-transition disposition is invalid".to_owned()),
        };
    let receipt = TerminalReceipt {
        policy_enforcement,
        schema_version,
        mechanism,
        status,
        policy_revoked,
        exec_status,
        spawn_error_reported,
        target_pid,
        authorization_offset_millis,
        assignment_verified: take_terminal_fact(&mut fields, "assignment-verified")?,
        namespaces_verified: take_terminal_fact(&mut fields, "namespaces-verified")?,
        target_initial_credentials_verified: take_terminal_fact(
            &mut fields,
            "target-initial-credentials-verified",
        )?,
        initial_provider_capabilities_absent: take_terminal_fact(
            &mut fields,
            "initial-provider-capabilities-absent",
        )?,
        caller_envelope_digest,
        caller_no_new_privs: take_terminal_fact(&mut fields, "caller-no-new-privs")?,
        target_no_new_privs_matched: take_terminal_fact(
            &mut fields,
            "target-no-new-privs-matched",
        )?,
        caller_capability_bounding_set_digest,
        target_capability_bounding_set_matched: take_terminal_fact(
            &mut fields,
            "target-capability-bounding-set-matched",
        )?,
        caller_mount_namespace_digest,
        target_mount_context_derived_from_caller: take_terminal_fact(
            &mut fields,
            "target-mount-context-derived-from-caller",
        )?,
        credential_transition_disposition,
        boundary_independent_of_credentials: take_terminal_fact(
            &mut fields,
            "boundary-independent-of-credentials",
        )?,
        descriptors_verified: take_terminal_fact(&mut fields, "descriptors-verified")?,
        writable_ancestor_cgroup_denied: take_terminal_fact(
            &mut fields,
            "writable-ancestor-cgroup-denied",
        )?,
        parent_namespace_handles_denied: take_terminal_fact(
            &mut fields,
            "parent-namespace-handles-denied",
        )?,
        recursive_provider_request_denied: take_terminal_fact(
            &mut fields,
            "recursive-provider-request-denied",
        )?,
        guardian_ready: take_terminal_fact(&mut fields, "guardian-ready-before-authorization")?,
        frontend_loss_authority: take_terminal_fact(
            &mut fields,
            "frontend-loss-authority-verified",
        )?,
        cgroup_kill: take_terminal_fact(&mut fields, "cgroup-kill-invoked")?,
        cgroup_empty: take_terminal_fact(&mut fields, "cgroup-empty")?,
        init_reaped: take_terminal_fact(&mut fields, "init-reaped")?,
        guardian_reaped: take_terminal_fact(&mut fields, "guardian-reaped")?,
        boundary_retired: take_terminal_fact(&mut fields, "boundary-retired")?,
        memory_limit_exceeded: take_terminal_fact(&mut fields, "memory-limit-exceeded")?,
        deadline_exceeded: take_terminal_fact(&mut fields, "deadline-exceeded")?,
    };
    if receipt.policy_revoked
        && (receipt.deadline_exceeded
            || !matches!(
                &receipt.policy_enforcement,
                memcordon_core::workload_evidence::AttemptPolicyEnforcementV1::Authorized {
                    terminal:
                        memcordon_core::workload_evidence::PolicyTerminalEvidenceV1::Retired {
                            controls_preserved: true,
                            provider_resources_closed: true,
                            ..
                        },
                    ..
                }
            )
            || !receipt.cgroup_empty
            || !receipt.init_reaped
            || !receipt.guardian_reaped
            || !receipt.boundary_retired)
    {
        return Err("terminal policy revocation lacks verified admission retirement".to_owned());
    }
    if fields.is_empty() {
        Ok(receipt)
    } else {
        Err("terminal receipt contains unknown fields".to_owned())
    }
}

fn take_terminal_field<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<&'a str, String> {
    fields
        .remove(name)
        .ok_or_else(|| format!("terminal field {name} missing"))
}

fn take_terminal_fact<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<bool, String> {
    match take_terminal_field(fields, name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("terminal fact {name} invalid")),
    }
}

fn classify_terminal_exec_error(os_code: i32) -> TerminalExecFailureClass {
    match os_code {
        libc::ENOENT | libc::ENOTDIR => TerminalExecFailureClass::NotFound,
        libc::EACCES | libc::EPERM | libc::ENOEXEC | libc::EISDIR => {
            TerminalExecFailureClass::NotExecutable
        }
        _ => TerminalExecFailureClass::Other,
    }
}

fn nonce() -> Result<[u8; 16], String> {
    let mut bytes = [0_u8; 16];
    let mut file = fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    file.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<(), String> {
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame length overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame too large".to_owned());
    }
    let digest = Sha256::digest(payload);
    stream
        .write_all(&VERSION.to_be_bytes())
        .and_then(|()| stream.write_all(&kind.to_be_bytes()))
        .and_then(|()| stream.write_all(&(total as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(&nonce))
        .and_then(|()| stream.write_all(&attempt))
        .and_then(|()| stream.write_all(&digest))
        .and_then(|()| stream.write_all(payload))
        .map_err(|error| error.to_string())
}

struct WireFrame {
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: Vec<u8>,
}

fn read_frame(stream: &mut UnixStream) -> Result<WireFrame, String> {
    read_frame_for_version(stream, VERSION)
}

fn read_frame_for_version(
    stream: &mut UnixStream,
    expected_version: u16,
) -> Result<WireFrame, String> {
    let mut header = [0_u8; HEADER_LENGTH];
    stream
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if u16::from_be_bytes([header[0], header[1]]) != expected_version {
        return Err("unsupported provider protocol".to_owned());
    }
    let kind = u16::from_be_bytes([header[2], header[3]]);
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(HEADER_LENGTH..=MAX_FRAME).contains(&total) {
        return Err("invalid provider frame length".to_owned());
    }
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&header[8..24]);
    let mut attempt = [0; 16];
    attempt.copy_from_slice(&header[24..40]);
    let mut payload = vec![0; total - HEADER_LENGTH];
    stream
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    if Sha256::digest(&payload).as_slice() != &header[40..72] {
        return Err("provider payload digest mismatch".to_owned());
    }
    Ok(WireFrame {
        kind,
        nonce,
        attempt,
        payload,
    })
}

/// Submit one already-encoded V4 private request to the fixed root-owned
/// service endpoint. The service remains authoritative for decoding,
/// admission, installed qualification and the single native release. This
/// transport never retries after a send attempt, including a short send.
pub fn run_private_v2(
    encoded_request: &[u8],
    expected: &PrivateExpectedResultV2<'_>,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    verify_endpoint().map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT))
        .map_err(|error| PrivateLaunchErrorV2::BeforeSubmission(error.to_string()))?;
    verify_peer(&stream).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let request_nonce = nonce().map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let attempt = nonce().map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if attempt == [0; 16] {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "private attempt identity is zero".into(),
        ));
    }
    let frame = encoded_frame_for_version(
        PRIVATE_VERSION,
        PRIVATE_LAUNCH_KIND,
        request_nonce,
        attempt,
        encoded_request,
    )
    .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let cwd = fs::File::open(".")
        .map_err(|error| PrivateLaunchErrorV2::BeforeSubmission(error.to_string()))?;
    let frontend_pidfd = pidfd_self().map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let descriptors = [cwd.as_raw_fd(), 0, 1, 2, frontend_pidfd.as_raw_fd()];
    send_with_descriptors(&stream, &frame, &descriptors).map_err(|detail| {
        PrivateLaunchErrorV2::AfterSubmission(PrivateResponseFailureV2 {
            detail,
            raw_response: None,
        })
    })?;
    receive_private_result(&mut stream, request_nonce, attempt, expected)
        .map_err(PrivateLaunchErrorV2::AfterSubmission)
}

/// Obtain a non-allocating V2 plan only from the authenticated root provider.
/// The receipt is a time-of-check snapshot; `run_private_v2` does not reuse it
/// as authority, and the service must repeat admission under its package and
/// policy leases before the release byte.
pub fn private_plan_v2(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
) -> Result<memcordon_core::workload_plan_v2::PrivatePlanReceiptV2, String> {
    match private_plan_exchange_v2(contract)? {
        PrivatePlanExchangeV2::Available { receipt, .. } => Ok(receipt),
        PrivatePlanExchangeV2::Rejected { evidence, .. } => Err(format!(
            "private plan unavailable [{}]: {}",
            evidence.code, evidence.detail
        )),
    }
}

/// The authenticated provider response is kept typed and byte-exact for the
/// final-public release verifier. A transport error is not a grant rejection.
pub fn private_plan_exchange_v2(
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
) -> Result<PrivatePlanExchangeV2, String> {
    contract.validate()?;
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    let nonce = nonce()?;
    let payload = serde_json::to_vec(contract).map_err(|error| error.to_string())?;
    let frame =
        encoded_frame_for_version(PRIVATE_VERSION, PRIVATE_PLAN_KIND, nonce, [0; 16], &payload)?;
    stream
        .write_all(&frame)
        .map_err(|error| error.to_string())?;
    let response = read_frame_for_version(&mut stream, PRIVATE_VERSION)?;
    if response.nonce != nonce || response.attempt != [0; 16] {
        return Err("private plan response identity differs".into());
    }
    match response.kind {
        PRIVATE_PLAN_RECEIPT_KIND => {
            let receipt =
                memcordon_core::workload_plan_v2::PrivatePlanReceiptV2::parse_for_contract(
                    &response.payload,
                    contract,
                )?;
            // The service obtains this from SO_PEERCRED; the local process
            // checks it before treating the receipt as its own plan.
            receipt.validate_for_caller(unsafe { libc::geteuid() })?;
            super::linux_runtime::verify_private(&receipt)?;
            Ok(PrivatePlanExchangeV2::Available {
                receipt,
                raw_response: response.payload,
            })
        }
        PRIVATE_REJECTION_KIND => {
            let rejection = parse_rejection(&response.payload)?;
            if rejection.phase != memcordon_core::BoundarySetupPhase::RequestValidation
                || rejection.target_created
                || rejection.target_released
                || rejection.cleanup_attempted
            {
                return Err("private plan rejection claims a native attempt".into());
            }
            Ok(PrivatePlanExchangeV2::Rejected {
                evidence: Box::new(rejection),
                raw_response: response.payload,
            })
        }
        _ => Err("provider omitted V2 private plan receipt".into()),
    }
}

/// Build the exact V4 private launch from a freshly authenticated plan. A
/// later package/policy mutation is still rejected by the service at launch;
/// this method cannot authorize a target from the plan alone.
pub fn execute_private_v2(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    execute_private_v2_with_expected_plan(policy, command, contract, context, None)
}

/// Compare a previously obtained public plan at the actual provider launch
/// boundary. A matching receipt never bypasses current admission.
pub fn execute_private_v2_with_expected_plan(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
    expected_plan: Option<&memcordon_core::workload_plan_v2::PrivatePlanReceiptV2>,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    execute_private_v2_plan_then_launch(
        policy,
        command,
        contract,
        contract,
        context,
        expected_plan,
        false,
    )
}

/// Deliberately plan the accepted contract, then submit one different
/// one-port contract with that exact authenticated plan as its V5 frozen
/// precondition. This is a negative release experiment, never an admission
/// shortcut: success is a preallocation provider rejection.
pub fn execute_private_v2_frozen_port_rejection(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    accepted_contract: &memcordon_core::workload_contract::WorkloadContractV2,
    tampered_contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
    expected_plan: &memcordon_core::workload_plan_v2::PrivatePlanReceiptV2,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    if !memcordon_core::private_release_branch_v1::one_policy_port_changed(
        accepted_contract,
        tampered_contract,
    ) {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "frozen private contract is not exactly one approved-plan port change".into(),
        ));
    }
    expected_plan
        .validate_for_contract(accepted_contract)
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    expected_plan
        .validate_for_caller(unsafe { libc::geteuid() })
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    execute_private_v2_plan_then_launch(
        policy,
        command,
        accepted_contract,
        tampered_contract,
        context,
        Some(expected_plan),
        true,
    )
}

fn execute_private_v2_plan_then_launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    plan_contract: &memcordon_core::workload_contract::WorkloadContractV2,
    launch_contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
    expected_plan: Option<&memcordon_core::workload_plan_v2::PrivatePlanReceiptV2>,
    frozen_port_case: bool,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    use memcordon_core::workload_contract::ExecutionIdentityRequestV2;

    plan_contract
        .validate()
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    launch_contract
        .validate()
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if policy.boundary() != memcordon_core::BoundaryRequirement::Sealed
        || policy.workload_contract().is_some()
        || plan_contract.authorized_profile.id.as_str() != "linux-tcp4-private-v1"
    {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "V2 private launch requires sealed boundary, private profile and no V1 contract".into(),
        ));
    }
    if !matches!(
        plan_contract.execution_identity,
        ExecutionIdentityRequestV2::AdministratorProfile { .. }
    ) {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "private preserve-caller execution identity is not available".into(),
        ));
    }
    let started = std::time::Instant::now();
    let plan = private_plan_v2(plan_contract).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if frozen_port_case && expected_plan != Some(&plan) {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "frozen private plan differs from freshly authenticated accepted plan".into(),
        ));
    }
    let precondition = expected_plan
        .map(|receipt| {
            memcordon_core::workload_plan_v2::PrivatePlanPreconditionV1::from_receipt(receipt)
                .map_err(PrivateLaunchErrorV2::BeforeSubmission)
        })
        .transpose()?;
    let encoded = encode_private_v2_with_plan(
        policy,
        command,
        launch_contract,
        context,
        started.elapsed(),
        &plan,
        precondition.as_ref(),
    )?;
    let expected = PrivateExpectedResultV2 {
        source_commit: &plan.source_commit,
        native_abi: plan.native_abi,
        runtime_manifest_sha256: &plan.runtime_manifest_sha256,
        installed_qualification_sha256: &plan.installed_qualification_sha256,
    };
    run_private_v2(&encoded, &expected)
}

fn encode_private_v2_with_plan(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    launch_contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
    setup_elapsed: Duration,
    plan: &memcordon_core::workload_plan_v2::PrivatePlanReceiptV2,
    precondition: Option<&memcordon_core::workload_plan_v2::PrivatePlanPreconditionV1>,
) -> Result<Vec<u8>, PrivateLaunchErrorV2> {
    let deadline_budget = effective_deadline_duration(policy, context, setup_elapsed);
    let launch = encode_launch(policy, command, deadline_budget, context.restart_attempt)
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let contract_bytes = serde_json::to_vec(launch_contract)
        .map_err(|error| PrivateLaunchErrorV2::BeforeSubmission(error.to_string()))?;
    let contract_digest = memcordon_core::workload_codec::contract_digest_v2(launch_contract)
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let mut encoded = Vec::new();
    let request_version: u16 = if precondition.is_some() {
        5
    } else {
        PRIVATE_VERSION
    };
    encoded.extend_from_slice(&request_version.to_be_bytes());
    encoded.extend_from_slice(plan.registry_digest.bytes());
    encoded.extend_from_slice(plan.installed_qualification_sha256.bytes());
    encoded.extend_from_slice(contract_digest.bytes());
    put_bytes(&mut encoded, &contract_bytes).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    put_bytes(&mut encoded, &launch).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if let Some(precondition) = precondition {
        encoded.extend_from_slice(precondition.contract_digest.bytes());
        encoded.extend_from_slice(precondition.generation_digest.bytes());
    }
    Ok(encoded)
}

/// A final-public reuse experiment, never an ordinary retry. One installed
/// nonroot CLI process obtains one authenticated plan and submits exactly two
/// fresh V5 launch exchanges under that plan. The first must report a real
/// postallocation CleanupIncomplete state; the second must be refused before
/// allocation. The root supervisor brackets those exchanges with FD4 so two
/// independent kernel intervals can be armed without changing actor PID.
pub fn execute_private_v2_reuse_pair(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
    contract: &memcordon_core::workload_contract::WorkloadContractV2,
    context: crate::AttemptContext,
    expected_plan: Option<&memcordon_core::workload_plan_v2::PrivatePlanReceiptV2>,
    barrier_fd: RawFd,
) -> Result<PrivateServiceResultV2, PrivateLaunchErrorV2> {
    use memcordon_core::provider_rejection_wire::{RejectionPhaseV1, RejectionWireV1};
    use memcordon_core::workload_contract::ExecutionIdentityRequestV2;

    if barrier_fd != 4 {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "reuse barrier must be inherited FD4".into(),
        ));
    }
    verify_reuse_barrier_peer(barrier_fd).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    contract
        .validate()
        .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if policy.boundary() != memcordon_core::BoundaryRequirement::Sealed
        || policy.workload_contract().is_some()
        || contract.authorized_profile.id.as_str() != "linux-tcp4-private-v1"
        || !matches!(
            contract.execution_identity,
            ExecutionIdentityRequestV2::AdministratorProfile { .. }
        )
    {
        return Err(PrivateLaunchErrorV2::BeforeSubmission(
            "reuse pair requires exact sealed private V2 contract".into(),
        ));
    }
    let started = std::time::Instant::now();
    let plan = private_plan_v2(contract).map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    if let Some(expected) = expected_plan {
        expected
            .validate_for_contract(contract)
            .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
        expected
            .validate_for_caller(unsafe { libc::geteuid() })
            .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
        if expected != &plan {
            return Err(PrivateLaunchErrorV2::BeforeSubmission(
                "reuse plan differs from protected expected plan".into(),
            ));
        }
    }
    let precondition =
        memcordon_core::workload_plan_v2::PrivatePlanPreconditionV1::from_receipt(&plan)
            .map_err(PrivateLaunchErrorV2::BeforeSubmission)?;
    let encoded = encode_private_v2_with_plan(
        policy,
        command,
        contract,
        context,
        started.elapsed(),
        &plan,
        Some(&precondition),
    )?;
    let expected = PrivateExpectedResultV2 {
        source_commit: &plan.source_commit,
        native_abi: plan.native_abi,
        runtime_manifest_sha256: &plan.runtime_manifest_sha256,
        installed_qualification_sha256: &plan.installed_qualification_sha256,
    };
    let first = run_private_v2(&encoded, &expected)?;
    let first_raw = match first {
        PrivateServiceResultV2::Rejected { raw_response, .. } => raw_response,
        PrivateServiceResultV2::Complete(terminal) => {
            return Err(reuse_after_submission(
                "reuse first launch unexpectedly completed",
                Some(terminal.raw_response().to_vec()),
            ));
        }
        PrivateServiceResultV2::Indeterminate { raw_response, .. } => {
            return Err(reuse_after_submission(
                "reuse first launch is indeterminate",
                Some(raw_response),
            ));
        }
    };
    let first_wire = RejectionWireV1::parse(&first_raw)
        .map_err(|detail| reuse_after_submission(&detail, Some(first_raw.clone())))?;
    if first_wire.code != "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE"
        || first_wire.phase != RejectionPhaseV1::Retirement
        || !first_wire.target_created
        || !first_wire.target_released
        || !first_wire.cleanup.attempted
        || first_wire.cleanup.sealed_boundary_retired
        || first_wire.cleanup.errors.is_empty()
    {
        return Err(reuse_after_submission(
            "reuse first launch lacks protected CleanupIncomplete result",
            Some(first_raw),
        ));
    }
    reuse_between_attempts_barrier(barrier_fd)
        .map_err(|detail| reuse_after_submission(&detail, None))?;
    let second_encoded = encode_private_v2_with_plan(
        policy,
        command,
        contract,
        context,
        started.elapsed(),
        &plan,
        Some(&precondition),
    )
    .map_err(|error| match error {
        PrivateLaunchErrorV2::BeforeSubmission(detail) => reuse_after_submission(&detail, None),
        PrivateLaunchErrorV2::AfterSubmission(failure) => {
            reuse_after_submission(&failure.detail, failure.raw_response)
        }
    })?;
    let second = run_private_v2(&second_encoded, &expected).map_err(|error| {
        let (detail, raw_response) = match error {
            PrivateLaunchErrorV2::BeforeSubmission(detail) => (detail, None),
            PrivateLaunchErrorV2::AfterSubmission(failure) => {
                (failure.detail, failure.raw_response)
            }
        };
        reuse_after_submission(&detail, raw_response)
    })?;
    let PrivateServiceResultV2::Rejected { raw_response, .. } = &second else {
        return Err(reuse_after_submission(
            "reuse second launch was not a typed rejection",
            match &second {
                PrivateServiceResultV2::Complete(terminal) => {
                    Some(terminal.raw_response().to_vec())
                }
                PrivateServiceResultV2::Indeterminate { raw_response, .. } => {
                    Some(raw_response.clone())
                }
                PrivateServiceResultV2::Rejected { .. } => None,
            },
        ));
    };
    let second_wire = RejectionWireV1::parse(raw_response)
        .map_err(|detail| reuse_after_submission(&detail, Some(raw_response.clone())))?;
    if second_wire.code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
        || second_wire.phase != RejectionPhaseV1::RequestValidation
        || second_wire.target_created
        || second_wire.target_released
        || second_wire.cleanup.attempted
    {
        return Err(reuse_after_submission(
            "reuse second launch did not prove preallocation block",
            Some(raw_response.clone()),
        ));
    }
    Ok(second)
}

fn reuse_after_submission(detail: &str, raw_response: Option<Vec<u8>>) -> PrivateLaunchErrorV2 {
    PrivateLaunchErrorV2::AfterSubmission(PrivateResponseFailureV2 {
        detail: detail.into(),
        raw_response,
    })
}

fn verify_reuse_barrier_peer(fd: RawFd) -> Result<(), String> {
    let mut socket_type: libc::c_int = 0;
    let mut type_length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&raw mut socket_type).cast(),
            &raw mut type_length,
        )
    } != 0
        || type_length as usize != std::mem::size_of::<libc::c_int>()
        || socket_type != libc::SOCK_STREAM
    {
        return Err("reuse barrier is not a Unix stream".into());
    }
    let mut peer = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut peer).cast(),
            &raw mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || peer.pid <= 0
        || peer.uid != 0
        || peer.pid == unsafe { libc::getpid() }
    {
        return Err("reuse barrier lacks root peer credentials".into());
    }
    Ok(())
}

fn reuse_between_attempts_barrier(fd: RawFd) -> Result<(), String> {
    verify_reuse_barrier_peer(fd)?;
    // SAFETY: CLI parsing fixed this inherited descriptor to FD4, and this
    // function takes sole ownership after the first provider exchange.
    let mut stream = unsafe { UnixStream::from_raw_fd(fd) };
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(120)))
        .map_err(|error| error.to_string())?;
    stream.write_all(b"R").map_err(|error| error.to_string())?;
    let mut release = [0_u8; 1];
    stream
        .read_exact(&mut release)
        .map_err(|error| error.to_string())?;
    if release != *b"G" {
        return Err("reuse barrier release byte differs".into());
    }
    Ok(())
}

/// Decode only a response read from the already-connected, authenticated
/// provider channel after the private request was sent. This function cannot
/// make a transport failure safe to replay, and does not perform a new launch.
pub fn receive_private_result(
    stream: &mut UnixStream,
    expected_nonce: [u8; 16],
    expected_attempt: [u8; 16],
    expected: &PrivateExpectedResultV2<'_>,
) -> Result<PrivateServiceResultV2, PrivateResponseFailureV2> {
    verify_peer(stream).map_err(|detail| PrivateResponseFailureV2 {
        detail,
        raw_response: None,
    })?;
    let frame = read_frame_for_version(stream, PRIVATE_VERSION).map_err(|detail| {
        PrivateResponseFailureV2 {
            detail,
            raw_response: None,
        }
    })?;
    decode_private_frame(frame, expected_nonce, expected_attempt, expected)
}

fn decode_private_frame(
    frame: WireFrame,
    expected_nonce: [u8; 16],
    expected_attempt: [u8; 16],
    expected: &PrivateExpectedResultV2<'_>,
) -> Result<PrivateServiceResultV2, PrivateResponseFailureV2> {
    let raw_response = frame.payload;
    let decode = || -> Result<PrivateServiceResultV2, String> {
        if frame.nonce != expected_nonce || frame.attempt != expected_attempt {
            return Err("private response nonce or attempt differs".into());
        }
        if raw_response.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
            return Err("private response exceeds byte bound".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&raw_response)?;
        match frame.kind {
            PRIVATE_TERMINAL_KIND => {
                let report: memcordon_core::report_v11::PrivateExecutionReportV11 =
                    serde_json::from_slice(&raw_response).map_err(|error| error.to_string())?;
                validate_private_service_report(&report, expected_attempt, expected)?;
                let restart_safety = private_terminal_restart_safety(&report);
                Ok(PrivateServiceResultV2::Complete(Box::new(
                    PrivateAuthenticatedTerminalV2 {
                        report,
                        raw_response: raw_response.clone(),
                        restart_safety,
                    },
                )))
            }
            PRIVATE_REJECTION_KIND => {
                let evidence = parse_rejection(&raw_response)?;
                // A target allocation may already have durable release intent.
                // Baseline rejection cleanup fields cannot prove private
                // namespace and policy-snapshot retirement.
                let release_knowledge = if evidence.target_created {
                    PrivateReleaseKnowledgeV2::PossiblyReleased
                } else {
                    PrivateReleaseKnowledgeV2::NotReleased
                };
                Ok(PrivateServiceResultV2::Rejected {
                    evidence: Box::new(evidence),
                    raw_response: raw_response.clone(),
                    release_knowledge,
                })
            }
            PRIVATE_INDETERMINATE_KIND => {
                let envelope: PrivateIndeterminateV11 =
                    serde_json::from_slice(&raw_response).map_err(|error| error.to_string())?;
                if envelope.schema_version != 11
                    || envelope.attempt_id != private_attempt_hex(expected_attempt)
                    || envelope.release_knowledge != "possibly-released"
                    || envelope.retirement_knowledge != "unverified"
                    || envelope.replay_disposition != "do-not-replay"
                    || envelope.reason_code != "MCSEALED-PRIVATE-TERMINAL-UNVERIFIED"
                {
                    return Err("private indeterminate envelope differs from protocol".into());
                }
                Ok(PrivateServiceResultV2::Indeterminate {
                    attempt_id: expected_attempt,
                    raw_response: raw_response.clone(),
                    reason_code: envelope.reason_code,
                })
            }
            _ => Err("private response kind differs from V4 protocol".into()),
        }
    };
    decode().map_err(|detail| PrivateResponseFailureV2 {
        detail,
        raw_response: Some(raw_response),
    })
}

fn private_attempt_hex(attempt: [u8; 16]) -> String {
    attempt.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn validate_private_service_report(
    report: &memcordon_core::report_v11::PrivateExecutionReportV11,
    expected_attempt: [u8; 16],
    expected: &PrivateExpectedResultV2<'_>,
) -> Result<(), String> {
    if report.schema_version != memcordon_core::report_v11::PRIVATE_EXECUTION_REPORT_SCHEMA_V11
        || report.source_commit != expected.source_commit
        || report.native_abi != expected.native_abi
        || report.runtime_manifest_sha256 != *expected.runtime_manifest_sha256
        || report.installed_qualification_sha256 != *expected.installed_qualification_sha256
        || report.attempt.attempt_id.as_str() != private_attempt_hex(expected_attempt)
    {
        return Err("private terminal differs from request or installed readback".into());
    }
    report.checkpoint.validate().map_err(str::to_owned)?;
    if report.checkpoint.native_abi != report.native_abi
        || report.checkpoint.attempt_binding != report.attempt.canonical_digest()?
        || !report.retirement.terminal_success(&report.checkpoint)
    {
        return Err("private terminal lacks bound checkpoint and retirement".into());
    }
    match &report.outcome {
        memcordon_core::report_v11::PrivateTerminalOutcomeV11::Exited { .. } => {}
        memcordon_core::report_v11::PrivateTerminalOutcomeV11::NativeFailure { phase, detail }
            if !phase.is_empty()
                && !detail.is_empty()
                && phase.len() <= 128
                && detail.len() <= 1024 => {}
        memcordon_core::report_v11::PrivateTerminalOutcomeV11::Interrupted { reason }
            if !reason.is_empty() && reason.len() <= 128 => {}
        _ => return Err("private terminal outcome violates V11 bound".into()),
    }
    Ok(())
}

fn private_terminal_restart_safety(
    report: &memcordon_core::report_v11::PrivateExecutionReportV11,
) -> memcordon_core::RestartSafetyProof {
    // This is reachable only after peer, frame, installed-readback and native
    // checkpoint/retirement joins. A bare report JSON cannot create this proof.
    debug_assert!(report.retirement.terminal_success(&report.checkpoint));
    memcordon_core::RestartSafetyProof {
        direct_child_reaped: true,
        workload_empty: Some(true),
        helpers_reaped: true,
        containment_removed: true,
        containment_incapable_of_live_members: true,
        sealed_boundary_retired: true,
        errors: Vec::new(),
    }
}

#[cfg(feature = "test-support")]
/// Exercises structural decoding only. Its boolean is not an authenticated
/// restart proof and must never be used by a production caller.
pub fn private_response_disposition_for_test(
    kind: u16,
    frame_nonce: [u8; 16],
    frame_attempt: [u8; 16],
    expected_nonce: [u8; 16],
    expected_attempt: [u8; 16],
    payload: &[u8],
    expected: &PrivateExpectedResultV2<'_>,
) -> Result<
    (
        PrivateReleaseKnowledgeV2,
        PrivateReplayDispositionV2,
        bool,
        Vec<u8>,
    ),
    PrivateResponseFailureV2,
> {
    let result = decode_private_frame(
        WireFrame {
            kind,
            nonce: frame_nonce,
            attempt: frame_attempt,
            payload: payload.to_vec(),
        },
        expected_nonce,
        expected_attempt,
        expected,
    )?;
    let restart_safe = matches!(
        &result,
        PrivateServiceResultV2::Complete(terminal)
            if terminal.restart_safety().is_safe_for(memcordon_core::BoundaryRequirement::Sealed)
    );
    let raw = match &result {
        PrivateServiceResultV2::Complete(terminal) => terminal.raw_response().to_vec(),
        PrivateServiceResultV2::Rejected { raw_response, .. }
        | PrivateServiceResultV2::Indeterminate { raw_response, .. } => raw_response.clone(),
    };
    Ok((
        result.release_knowledge(),
        result.replay_disposition(),
        restart_safe,
        raw,
    ))
}
