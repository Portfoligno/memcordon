//! Structural wire contract for the 25-case native release matrix.
//!
//! Parsing this record never authenticates its producer. A release verifier
//! must independently read each raw attachment, the protected native journal,
//! and the supervising CI job before constructing any qualification token.

use serde::{Deserialize, Serialize};

use crate::{DiagnosticSha256, workload_codec::hash_bytes};

pub const REQUIRED_PRIVATE_RELEASE_SELECTORS_V1: [&str; 25] = [
    "private_tcp::abi_alternate_entry_denied",
    "private_tcp::af_unix_abstract_and_pathname_denied",
    "private_tcp::af_unix_socketpair_denied",
    "private_tcp::authorization_uncertainty_retired",
    "private_tcp::caller_identity_and_epoch_bound",
    "private_tcp::checkpoint_persisted_before_release",
    "private_tcp::child_runtime_and_threads_retired",
    "private_tcp::descriptor_table_and_stdio_bound",
    "private_tcp::dual_attempt_namespace_isolation",
    "private_tcp::elf_ancestor_and_identity_pinned",
    "private_tcp::frontend_loss_retired",
    "private_tcp::guardian_loss_retired",
    "private_tcp::host_namespace_and_sysctl_unchanged",
    "private_tcp::io_uring_and_pidfd_import_denied",
    "private_tcp::namespace_reentry_denied",
    "private_tcp::native_filter_digest_and_abi_bound",
    "private_tcp::native_tcp_bind_listen_connect",
    "private_tcp::port_collision_same_namespace",
    "private_tcp::private_namespace_topology_exact",
    "private_tcp::release_checkpoint_terminal_joined",
    "private_tcp::retirement_failure_blocks_reuse",
    "private_tcp::scm_rights_and_precreated_socket_denied",
    "private_tcp::target_credentials_and_capabilities_dropped",
    "private_tcp::target_exec_and_fd_leak_observed",
    "private_tcp::wrong_grant_profile_and_port_rejected",
];

pub const MAX_PRIVATE_RELEASE_RESULT_BYTES_V1: usize = 64 * 1024;
pub const MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1: u64 = 1024 * 1024;
pub const PRIVATE_RELEASE_RESULT_ROOT_V1: &str = "/var/lib/memcordon/sealed/private-release-cases";

pub fn private_release_case_key_v1(
    stage: PrivateReleaseStageV1,
    selector: &str,
    challenge: &[u8; 32],
) -> Result<DiagnosticSha256, String> {
    if !REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.contains(&selector) || *challenge == [0; 32] {
        return Err("private release case identity differs".into());
    }
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"memcordon-private-release-case-v1\0");
    bytes.extend_from_slice(stage.as_str().as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(selector.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(challenge);
    Ok(hash_bytes(&bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateReleaseStageV1 {
    CandidateCapability,
    FinalPublic,
}

impl PrivateReleaseStageV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CandidateCapability => "candidate-capability",
            Self::FinalPublic => "final-public",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "stage", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivateReleaseInstalledBindingV1 {
    CandidateCapability {
        installation_epoch: DiagnosticSha256,
        candidate_manifest_sha256: DiagnosticSha256,
        installed_inspection_sha256: DiagnosticSha256,
    },
    FinalPublic {
        installation_epoch: DiagnosticSha256,
        qualified_manifest_sha256: DiagnosticSha256,
        release_qualification_sha256: DiagnosticSha256,
        active_host_receipt_sha256: DiagnosticSha256,
        public_plan_sha256: DiagnosticSha256,
        public_grant_sha256: DiagnosticSha256,
    },
}

impl PrivateReleaseInstalledBindingV1 {
    pub fn stage(&self) -> PrivateReleaseStageV1 {
        match self {
            Self::CandidateCapability { .. } => PrivateReleaseStageV1::CandidateCapability,
            Self::FinalPublic { .. } => PrivateReleaseStageV1::FinalPublic,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateReleaseKnowledgeV1 {
    NotReleased,
    PossiblyReleased,
    ExecObserved,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateReleaseExecV1 {
    NotObserved,
    Failed,
    Succeeded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateReleaseAllocatedOutcomeV1 {
    TargetCompleted,
    AuthorizationUncertain,
    FrontendLost,
    GuardianLost,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReleaseDualRetiredBranchV1 {
    pub attempt_id: String,
    pub checkpoint_sha256: DiagnosticSha256,
    pub terminal_sha256: DiagnosticSha256,
    pub retirement_sha256: DiagnosticSha256,
    pub release_knowledge: PrivateReleaseKnowledgeV1,
    pub exec: PrivateReleaseExecV1,
}

impl PrivateReleaseDualRetiredBranchV1 {
    fn valid_completed(&self) -> bool {
        valid_attempt_id(&self.attempt_id)
            && self.release_knowledge == PrivateReleaseKnowledgeV1::ExecObserved
            && self.exec == PrivateReleaseExecV1::Succeeded
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "phase", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PrivateReleaseObservationV1 {
    PreallocationRejected {
        rejection_code: String,
        observer_sha256: DiagnosticSha256,
    },
    AllocatedRetired {
        outcome: PrivateReleaseAllocatedOutcomeV1,
        attempt_id: String,
        checkpoint_sha256: DiagnosticSha256,
        terminal_sha256: DiagnosticSha256,
        retirement_sha256: DiagnosticSha256,
        release_knowledge: PrivateReleaseKnowledgeV1,
        exec: PrivateReleaseExecV1,
        native_observer_sha256: DiagnosticSha256,
    },
    DualAttemptsRetired {
        first: PrivateReleaseDualRetiredBranchV1,
        second: PrivateReleaseDualRetiredBranchV1,
        native_observer_sha256: DiagnosticSha256,
    },
    RetirementFailureBlockedReuse {
        attempt_id: String,
        checkpoint_sha256: DiagnosticSha256,
        terminal_sha256: DiagnosticSha256,
        cleanup_failure_sha256: DiagnosticSha256,
        reuse_rejection_sha256: DiagnosticSha256,
        release_knowledge: PrivateReleaseKnowledgeV1,
        exec: PrivateReleaseExecV1,
        native_observer_sha256: DiagnosticSha256,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivateReleaseAttachmentRoleV1 {
    Request,
    Report,
    Stdio,
    Observer,
    Cleanup,
}

impl PrivateReleaseAttachmentRoleV1 {
    pub const ALL: [Self; 5] = [
        Self::Request,
        Self::Report,
        Self::Stdio,
        Self::Observer,
        Self::Cleanup,
    ];

    pub fn leaf(self) -> &'static str {
        match self {
            Self::Request => "request.bin",
            Self::Report => "report.bin",
            Self::Stdio => "stdio.bin",
            Self::Observer => "observer.bin",
            Self::Cleanup => "cleanup.bin",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReleaseAttachmentV1 {
    pub role: PrivateReleaseAttachmentRoleV1,
    pub size: u64,
    pub sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateReleaseCaseResultV1 {
    pub schema_version: u8,
    pub selector: String,
    pub challenge: String,
    pub target: String,
    pub native_machine: String,
    pub installed: PrivateReleaseInstalledBindingV1,
    pub observation: PrivateReleaseObservationV1,
    pub attachments: Vec<PrivateReleaseAttachmentV1>,
}

impl PrivateReleaseCaseResultV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 {
            return Err("private release result byte bound differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let result: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        result.validate()?;
        Ok(result)
    }

    pub fn challenge_bytes(&self) -> Result<[u8; 32], String> {
        let mut challenge = [0_u8; 32];
        if self.challenge.len() != challenge.len() * 2
            || !self
                .challenge
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("private release challenge syntax differs".into());
        }
        for (index, byte) in challenge.iter_mut().enumerate() {
            let offset = index * 2;
            *byte = u8::from_str_radix(&self.challenge[offset..offset + 2], 16)
                .map_err(|_| "private release challenge syntax differs")?;
        }
        if challenge == [0; 32] {
            return Err("private release challenge is zero".into());
        }
        Ok(challenge)
    }

    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        let challenge = self.challenge_bytes()?;
        private_release_case_key_v1(self.installed.stage(), &self.selector, &challenge)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.contains(&self.selector.as_str())
        {
            return Err("private release selector or schema differs".into());
        }
        self.challenge_bytes()?;
        match (self.target.as_str(), self.native_machine.as_str()) {
            ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64") => {}
            _ => return Err("private release target or native machine differs".into()),
        }
        if self.attachments.len() != PrivateReleaseAttachmentRoleV1::ALL.len()
            || self
                .attachments
                .iter()
                .zip(PrivateReleaseAttachmentRoleV1::ALL)
                .any(|(actual, expected)| {
                    actual.role != expected || actual.size > MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
                })
        {
            return Err("private release raw attachment inventory differs".into());
        }
        let observer_hash = &self.attachments[3].sha256;
        let recorded_observer_hash = match &self.observation {
            PrivateReleaseObservationV1::PreallocationRejected {
                observer_sha256, ..
            } => observer_sha256,
            PrivateReleaseObservationV1::AllocatedRetired {
                native_observer_sha256,
                ..
            }
            | PrivateReleaseObservationV1::DualAttemptsRetired {
                native_observer_sha256,
                ..
            }
            | PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                native_observer_sha256,
                ..
            } => native_observer_sha256,
        };
        if observer_hash != recorded_observer_hash {
            return Err("private release observer attachment hash differs".into());
        }
        let expected = if self.selector == "private_tcp::wrong_grant_profile_and_port_rejected" {
            match self.installed.stage() {
                PrivateReleaseStageV1::CandidateCapability => "grant-rejected",
                PrivateReleaseStageV1::FinalPublic => "public-grant-rejected",
            }
        } else if self.selector == "private_tcp::retirement_failure_blocks_reuse" {
            "retirement-failure"
        } else if self.selector == "private_tcp::authorization_uncertainty_retired" {
            "authorization-uncertain"
        } else if self.selector == "private_tcp::frontend_loss_retired" {
            "frontend-lost"
        } else if self.selector == "private_tcp::guardian_loss_retired" {
            "guardian-lost"
        } else {
            "target-completed"
        };
        match (&self.observation, expected) {
            (
                PrivateReleaseObservationV1::DualAttemptsRetired { first, second, .. },
                "target-completed",
            ) if self.selector == "private_tcp::dual_attempt_namespace_isolation"
                && first.valid_completed()
                && second.valid_completed()
                && first.attempt_id != second.attempt_id
                && first.checkpoint_sha256 != second.checkpoint_sha256
                && first.terminal_sha256 != second.terminal_sha256
                && first.retirement_sha256 != second.retirement_sha256 => {}
            (
                PrivateReleaseObservationV1::PreallocationRejected { rejection_code, .. },
                "grant-rejected",
            )
            | (
                PrivateReleaseObservationV1::PreallocationRejected { rejection_code, .. },
                "public-grant-rejected",
            ) if !rejection_code.is_empty() && rejection_code.len() <= 128 => {}
            (
                PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                    attempt_id,
                    release_knowledge,
                    ..
                },
                "retirement-failure",
            ) if valid_attempt_id(attempt_id)
                && *release_knowledge != PrivateReleaseKnowledgeV1::NotReleased => {}
            (
                PrivateReleaseObservationV1::AllocatedRetired {
                    outcome,
                    attempt_id,
                    release_knowledge,
                    exec,
                    ..
                },
                expected,
            ) if valid_attempt_id(attempt_id)
                && allocated_outcome_name(*outcome) == expected
                && match outcome {
                    PrivateReleaseAllocatedOutcomeV1::TargetCompleted => {
                        *release_knowledge == PrivateReleaseKnowledgeV1::ExecObserved
                            && *exec == PrivateReleaseExecV1::Succeeded
                    }
                    PrivateReleaseAllocatedOutcomeV1::FrontendLost
                    | PrivateReleaseAllocatedOutcomeV1::GuardianLost => {
                        *release_knowledge == PrivateReleaseKnowledgeV1::ExecObserved
                    }
                    PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain => {
                        *release_knowledge != PrivateReleaseKnowledgeV1::NotReleased
                    }
                } => {}
            _ => return Err("private release case phase or outcome differs".into()),
        }
        Ok(())
    }
}

fn valid_attempt_id(value: &str) -> bool {
    value.len() == [0_u8; 16].len() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value.bytes().any(|byte| byte != b'0')
}

fn allocated_outcome_name(value: PrivateReleaseAllocatedOutcomeV1) -> &'static str {
    match value {
        PrivateReleaseAllocatedOutcomeV1::TargetCompleted => "target-completed",
        PrivateReleaseAllocatedOutcomeV1::AuthorizationUncertain => "authorization-uncertain",
        PrivateReleaseAllocatedOutcomeV1::FrontendLost => "frontend-lost",
        PrivateReleaseAllocatedOutcomeV1::GuardianLost => "guardian-lost",
    }
}
