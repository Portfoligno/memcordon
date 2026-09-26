//! Typed subbranch transcripts for the two preallocation release cases.
//! These structures describe claims only. Deserializing or structurally
//! validating one never grants admission or qualifies a native release; an
//! independent observer must join the exact request and allocation interval.

use serde::{Deserialize, Serialize};

use crate::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use crate::workload_admission_v2::ProviderAdmissionSnapshotV2;
use crate::workload_codec::contract_digest_v2;
use crate::workload_contract::{
    RequirementV1, TcpEndpoint, TcpPeerRequirement, WorkloadContractV2,
};
use crate::workload_registry_v2::AdmissionCodeV2;
use crate::{DiagnosticSha256, workload_codec::hash_bytes};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyBranchV1 {
    WrongGrant,
    WrongProfile,
    UnapprovedChangedPortPlan,
    CommittedPortTamper,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyOperationBranchV1 {
    AcceptedControl,
    WrongGrant,
    WrongProfile,
    UnapprovedChangedPortPlan,
    CommittedPortTamper,
}

impl PolicyOperationBranchV1 {
    pub const ALL: [Self; 5] = [
        Self::AcceptedControl,
        Self::WrongGrant,
        Self::WrongProfile,
        Self::UnapprovedChangedPortPlan,
        Self::CommittedPortTamper,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AcceptedControl => "accepted-control",
            Self::WrongGrant => "wrong-grant",
            Self::WrongProfile => "wrong-profile",
            Self::UnapprovedChangedPortPlan => "unapproved-changed-port-plan",
            Self::CommittedPortTamper => "committed-port-tamper",
        }
    }
}

pub fn policy_branch_challenge_v1(
    base_challenge: &[u8; 32],
    branch: PolicyOperationBranchV1,
) -> Result<[u8; 32], &'static str> {
    if base_challenge == &[0; 32] {
        return Err("policy base challenge absent");
    }
    let mut bytes = b"memcordon/private-release/policy-branch/v1\0".to_vec();
    bytes.extend_from_slice(base_challenge);
    bytes.extend_from_slice(branch.as_str().as_bytes());
    Ok(*hash_bytes(&bytes).bytes())
}

/// Independent reviewed release intent for the dynamic policy experiment.
/// Its exact canonical bytes must be pinned by the protected collector intent
/// and the workflow-scoped intent digest. It is not an activation or grant:
/// live H0/registry/caller admission and physical intervals are separate joins.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePolicyReleaseIntentV1 {
    pub schema_version: u8,
    pub target: String,
    pub candidate_build_sha256: DiagnosticSha256,
    pub installed_inspection_sha256: DiagnosticSha256,
    pub installation_epoch_sha256: DiagnosticSha256,
    pub registry_sha256: DiagnosticSha256,
    pub authenticated_caller_uid: u32,
    pub authenticated_caller_sha256: DiagnosticSha256,
    pub reviewed_topology_sha256: DiagnosticSha256,
    pub observer: PrivatePolicyObserverIntentV1,
    pub base_challenge: [u8; 32],
    pub accepted: WorkloadContractV2,
    pub changed_port: WorkloadContractV2,
    pub committed_tamper: WorkloadContractV2,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePolicyObserverIntentV1 {
    pub boot_id: String,
    pub kernel_release: String,
    pub btf_sha256: DiagnosticSha256,
    pub control_result_key: DiagnosticSha256,
    pub bpf_source_sha256: DiagnosticSha256,
    pub loader_source_sha256: DiagnosticSha256,
    pub object_sha256: DiagnosticSha256,
    pub loader_sha256: DiagnosticSha256,
    pub agent_sha256: DiagnosticSha256,
    pub agent_build_id: Vec<u8>,
    pub request_entry_offset: u64,
    pub request_exit_offset: u64,
    pub allocation_entry_offset: u64,
}

impl PrivatePolicyObserverIntentV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.boot_id.is_empty()
            || self.boot_id.len() > 64
            || self.kernel_release.is_empty()
            || self.kernel_release.len() > 128
            || !matches!(self.agent_build_id.len(), 20 | 32)
            || self.request_entry_offset == 0
            || self.request_exit_offset == 0
            || self.allocation_entry_offset == 0
            || self.request_entry_offset == self.request_exit_offset
            || self.request_entry_offset == self.allocation_entry_offset
            || self.request_exit_offset == self.allocation_entry_offset
            || [
                &self.btf_sha256,
                &self.control_result_key,
                &self.bpf_source_sha256,
                &self.loader_source_sha256,
                &self.object_sha256,
                &self.loader_sha256,
                &self.agent_sha256,
            ]
            .iter()
            .any(|digest| digest.bytes() == &[0; 32])
        {
            return Err("policy observer intent differs".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivatePolicyAgentFixtureV1 {
    pub schema_version: u8,
    pub selector: String,
    pub base_challenge: [u8; 32],
    pub authenticated_caller_uid: u32,
    pub accepted: WorkloadContractV2,
    pub changed_port: WorkloadContractV2,
    pub committed_tamper: WorkloadContractV2,
}

impl PrivatePolicyReleaseIntentV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || self.authenticated_caller_uid == 0
            || self.base_challenge == [0; 32]
            || [
                &self.candidate_build_sha256,
                &self.installed_inspection_sha256,
                &self.installation_epoch_sha256,
                &self.registry_sha256,
                &self.authenticated_caller_sha256,
                &self.reviewed_topology_sha256,
            ]
            .iter()
            .any(|digest| digest.bytes() == &[0; 32])
        {
            return Err("policy release intent identity differs".into());
        }
        self.observer.validate()?;
        self.agent_fixture().validate()
    }

    pub fn agent_fixture(&self) -> PrivatePolicyAgentFixtureV1 {
        PrivatePolicyAgentFixtureV1 {
            schema_version: 1,
            selector: "private_tcp::wrong_grant_profile_and_port_rejected".into(),
            base_challenge: self.base_challenge,
            authenticated_caller_uid: self.authenticated_caller_uid,
            accepted: self.accepted.clone(),
            changed_port: self.changed_port.clone(),
            committed_tamper: self.committed_tamper.clone(),
        }
    }

    pub fn canonical_agent_fixture_bytes(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        serde_json::to_vec(&self.agent_fixture()).map_err(|error| error.to_string())
    }
}

impl PrivatePolicyAgentFixtureV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.selector != "private_tcp::wrong_grant_profile_and_port_rejected"
            || self.base_challenge == [0; 32]
            || self.authenticated_caller_uid == 0
        {
            return Err("policy agent fixture identity differs".into());
        }
        self.accepted.validate()?;
        self.changed_port.validate()?;
        self.committed_tamper.validate()?;
        if !one_policy_port_changed(&self.accepted, &self.changed_port)
            || !one_policy_port_changed(&self.accepted, &self.committed_tamper)
            || contract_digest_v2(&self.changed_port)?
                == contract_digest_v2(&self.committed_tamper)?
        {
            return Err("policy changed-port branches differ".into());
        }
        Ok(())
    }
}

pub fn one_policy_port_changed(
    original: &WorkloadContractV2,
    changed: &WorkloadContractV2,
) -> bool {
    if original.requirements.as_slice().len() != changed.requirements.as_slice().len()
        || original.workload_plan_digest == changed.workload_plan_digest
        || original.authorization.grant_id != changed.authorization.grant_id
        || original.authorization.grant_revision != changed.authorization.grant_revision
        || original.authorized_profile != changed.authorized_profile
        || original.expected_epoch != changed.expected_epoch
        || original.execution_identity != changed.execution_identity
        || original.ceiling != changed.ceiling
        || original.endpoints != changed.endpoints
        || original.schema_version != changed.schema_version
    {
        return false;
    }
    let mut changed_ports = 0;
    for (left, right) in original
        .requirements
        .as_slice()
        .iter()
        .zip(changed.requirements.as_slice())
    {
        match (left, right) {
            (
                RequirementV1::Tcp {
                    id: lid,
                    family: lf,
                    operations: lo,
                    scope: ls,
                    local_ports: lp,
                    peer: lpeer,
                },
                RequirementV1::Tcp {
                    id: rid,
                    family: rf,
                    operations: ro,
                    scope: rs,
                    local_ports: rp,
                    peer: rpeer,
                },
            ) if lid == rid && lf == rf && lo == ro && ls == rs => {
                if lp != rp {
                    changed_ports += 1;
                }
                if lpeer != rpeer {
                    match (lpeer, rpeer) {
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: la,
                                        port: lp,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V4 {
                                        address: ra,
                                        port: rp,
                                    },
                            },
                        ) if la == ra && lp != rp => changed_ports += 1,
                        (
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: la,
                                        port: lp,
                                    },
                            },
                            TcpPeerRequirement::ExactAddress {
                                endpoint:
                                    TcpEndpoint::V6 {
                                        address: ra,
                                        port: rp,
                                    },
                            },
                        ) if la == ra && lp != rp => changed_ports += 1,
                        _ => return false,
                    }
                }
            }
            _ if left == right => {}
            _ => return false,
        }
    }
    changed_ports == 1
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "kind",
    content = "detail",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
pub enum PolicyOperationOutcomeV1 {
    AcceptedControl,
    Admission(AdmissionCodeV2),
    FrozenBindingMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPositiveNativeV1 {
    pub attempt_id: String,
    pub checkpoint_sha256: DiagnosticSha256,
    pub terminal_sha256: DiagnosticSha256,
    pub response_sha256: DiagnosticSha256,
    pub network_namespace_inode: u64,
    pub candidate_exit_code: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedPolicyBranchRawV1 {
    pub schema_version: u8,
    pub selector: String,
    pub branch: PolicyOperationBranchV1,
    pub base_challenge_sha256: DiagnosticSha256,
    pub result_key: DiagnosticSha256,
    pub challenge_sha256: DiagnosticSha256,
    pub fixture_sha256: DiagnosticSha256,
    pub reviewed_topology_sha256: DiagnosticSha256,
    pub installed_inspection_sha256: DiagnosticSha256,
    pub installation_epoch_sha256: DiagnosticSha256,
    pub registry_sha256: DiagnosticSha256,
    pub accepted_request_sha256: DiagnosticSha256,
    pub changed_request_sha256: DiagnosticSha256,
    pub committed_tamper_request_sha256: DiagnosticSha256,
    pub exact_branch_request_sha256: DiagnosticSha256,
    pub outcome: PolicyOperationOutcomeV1,
    pub frozen_snapshot_sha256: DiagnosticSha256,
    pub authenticated_caller_uid: u32,
    pub authenticated_caller_sha256: DiagnosticSha256,
    pub accepted: WorkloadContractV2,
    pub changed_port: WorkloadContractV2,
    pub committed_tamper: WorkloadContractV2,
    pub exact_branch_request: WorkloadContractV2,
    pub frozen: ProviderAdmissionSnapshotV2,
    pub positive_native: Option<PolicyPositiveNativeV1>,
}

impl ProtectedPolicyBranchRawV1 {
    pub fn parse(bytes: &[u8], base_challenge: &[u8; 32]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 512 * 1024 {
            return Err("policy branch raw bound differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let raw: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        raw.validate(base_challenge)?;
        if serde_json::to_vec(&raw).map_err(|error| error.to_string())? != bytes {
            return Err("policy branch raw canonical encoding differs".into());
        }
        Ok(raw)
    }

    pub fn validate(&self, base_challenge: &[u8; 32]) -> Result<(), String> {
        self.frozen.validate()?;
        let challenge =
            policy_branch_challenge_v1(base_challenge, self.branch).map_err(str::to_owned)?;
        let fixture = PrivatePolicyAgentFixtureV1 {
            schema_version: 1,
            selector: self.selector.clone(),
            base_challenge: *base_challenge,
            authenticated_caller_uid: self.authenticated_caller_uid,
            accepted: self.accepted.clone(),
            changed_port: self.changed_port.clone(),
            committed_tamper: self.committed_tamper.clone(),
        };
        fixture.validate()?;
        if self.schema_version != 1
            || self.authenticated_caller_uid == 0
            || self.base_challenge_sha256 != hash_bytes(base_challenge)
            || self.challenge_sha256 != hash_bytes(&challenge)
            || self.result_key
                != private_release_case_key_v1(
                    PrivateReleaseStageV1::CandidateCapability,
                    &self.selector,
                    &challenge,
                )?
            || self.fixture_sha256
                != hash_bytes(&serde_json::to_vec(&fixture).map_err(|error| error.to_string())?)
            || self.accepted_request_sha256 != contract_digest_v2(&self.accepted)?
            || self.changed_request_sha256 != contract_digest_v2(&self.changed_port)?
            || self.committed_tamper_request_sha256 != contract_digest_v2(&self.committed_tamper)?
            || self.exact_branch_request_sha256 != contract_digest_v2(&self.exact_branch_request)?
            || self.frozen_snapshot_sha256 != self.frozen.canonical_digest()?
            || self.frozen.request != self.accepted
            || self.frozen.registry_digest != self.registry_sha256
            || self.frozen.qualification_digest != self.installed_inspection_sha256
            || self.frozen.package_generation_digest != self.installation_epoch_sha256
            || self.frozen.caller_envelope_digest != self.authenticated_caller_sha256
            || self.frozen.native_invocation_digest != self.result_key
            || self.frozen.caller
                != (crate::workload_registry::CallerSelector::Linux {
                    uid: self.authenticated_caller_uid,
                })
            || self.authenticated_caller_sha256
                != hash_bytes(
                    &serde_json::to_vec(&crate::workload_registry::CallerSelector::Linux {
                        uid: self.authenticated_caller_uid,
                    })
                    .map_err(|error| error.to_string())?,
                )
            || self.reviewed_topology_sha256.bytes() == &[0; 32]
        {
            return Err("policy branch raw structural binding differs".into());
        }
        match self.branch {
            PolicyOperationBranchV1::AcceptedControl
                if self.outcome == PolicyOperationOutcomeV1::AcceptedControl
                    && self.exact_branch_request == self.accepted
                    && self.positive_native.is_none() => {}
            PolicyOperationBranchV1::UnapprovedChangedPortPlan
                if self.positive_native.is_none()
                    && self.exact_branch_request == self.changed_port
                    && self.outcome
                        == PolicyOperationOutcomeV1::Admission(
                            AdmissionCodeV2::PlanNotApproved,
                        ) => {}
            PolicyOperationBranchV1::CommittedPortTamper
                if self.positive_native.is_none()
                    && self.exact_branch_request == self.committed_tamper
                    && self.outcome == PolicyOperationOutcomeV1::FrozenBindingMismatch => {}
            PolicyOperationBranchV1::WrongGrant
                if self.positive_native.is_none()
                    && self.outcome
                        == PolicyOperationOutcomeV1::Admission(
                            AdmissionCodeV2::ProfileNotAuthorized,
                        )
                    && self.exact_branch_request != self.accepted => {}
            PolicyOperationBranchV1::WrongProfile
                if self.positive_native.is_none()
                    && self.outcome
                        == PolicyOperationOutcomeV1::Admission(
                            AdmissionCodeV2::ProfileDigestMismatch,
                        )
                    && self.exact_branch_request != self.accepted => {}
            _ => return Err("policy branch raw outcome differs".into()),
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyBranchOutcomeV1 {
    Admission(AdmissionCodeV2),
    FrozenBindingMismatch,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RejectedPolicyBranchV1 {
    pub branch: PolicyBranchV1,
    pub exact_request_sha256: DiagnosticSha256,
    pub exact_registry_sha256: DiagnosticSha256,
    pub authenticated_caller_sha256: DiagnosticSha256,
    pub outcome: PolicyBranchOutcomeV1,
    pub independent_interval_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFourBranchTranscriptV1 {
    pub schema_version: u8,
    pub challenge_sha256: DiagnosticSha256,
    pub accepted_control_request_sha256: DiagnosticSha256,
    pub accepted_control_registry_sha256: DiagnosticSha256,
    pub authenticated_caller_sha256: DiagnosticSha256,
    /// Stable order prevents a duplicated negative from replacing a missing
    /// branch. Each request must be an exact authenticated fixture, not an
    /// arbitrary syntactically invalid request.
    pub rejected: [RejectedPolicyBranchV1; 4],
}

impl PolicyFourBranchTranscriptV1 {
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.schema_version != 1 {
            return Err("policy branch schema differs");
        }
        let expected = [
            PolicyBranchV1::WrongGrant,
            PolicyBranchV1::WrongProfile,
            PolicyBranchV1::UnapprovedChangedPortPlan,
            PolicyBranchV1::CommittedPortTamper,
        ];
        for (index, branch) in self.rejected.iter().enumerate() {
            if branch.branch != expected[index]
                || branch.authenticated_caller_sha256 != self.authenticated_caller_sha256
                || branch.exact_registry_sha256 != self.accepted_control_registry_sha256
                || branch.exact_request_sha256 == self.accepted_control_request_sha256
                || branch.outcome
                    != match branch.branch {
                        PolicyBranchV1::WrongGrant => {
                            PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileNotAuthorized)
                        }
                        PolicyBranchV1::WrongProfile => {
                            PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::ProfileDigestMismatch)
                        }
                        PolicyBranchV1::UnapprovedChangedPortPlan => {
                            PolicyBranchOutcomeV1::Admission(AdmissionCodeV2::PlanNotApproved)
                        }
                        PolicyBranchV1::CommittedPortTamper => {
                            PolicyBranchOutcomeV1::FrozenBindingMismatch
                        }
                    }
                || self.rejected[..index]
                    .iter()
                    .any(|previous| previous.exact_request_sha256 == branch.exact_request_sha256)
            {
                return Err("policy branch inventory differs");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoricalEpochTranscriptV1 {
    pub schema_version: u8,
    pub challenge_sha256: DiagnosticSha256,
    pub e0_installation_epoch_sha256: DiagnosticSha256,
    pub e1_installation_epoch_sha256: DiagnosticSha256,
    pub e0_accepted_request_sha256: DiagnosticSha256,
    pub e0_accepted_result_sha256: DiagnosticSha256,
    pub package_mutation_journal_sha256: DiagnosticSha256,
    pub original_replay_request_sha256: DiagnosticSha256,
    pub stale_rejection_sha256: DiagnosticSha256,
    pub stale_interval_sha256: DiagnosticSha256,
    pub fresh_e1_request_sha256: DiagnosticSha256,
    pub fresh_e1_result_sha256: DiagnosticSha256,
    pub caller_rejection_sha256: DiagnosticSha256,
}

impl HistoricalEpochTranscriptV1 {
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        if self.schema_version != 1
            || self.e0_installation_epoch_sha256 == self.e1_installation_epoch_sha256
            || self.e0_accepted_request_sha256 != self.original_replay_request_sha256
            || self.fresh_e1_request_sha256 == self.original_replay_request_sha256
            || self.e0_accepted_result_sha256 == self.fresh_e1_result_sha256
        {
            return Err("historical epoch transcript differs");
        }
        Ok(())
    }
}
