//! Structural five-actor final-public policy case. This record is not release
//! authority: P must independently rejoin every protected provider leaf and
//! loss-free kernel interval before accepting its digests.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::private_public_case_v2::FinalPublicChildIdentityV2;
use crate::private_release_branch_v1::{PolicyOperationBranchV1, policy_branch_challenge_v1};
use crate::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use crate::workload_codec::hash_bytes;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::{BoundedText, DiagnosticSha256};

pub const PUBLIC_POLICY_SELECTOR_V1: &str = "private_tcp::wrong_grant_profile_and_port_rejected";
const MAX_PUBLIC_POLICY_COMPOSITE_BYTES_V1: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PublicPolicyBranchOutcomeV1 {
    AcceptedControl {
        attempt_id: String,
        target_identity_sha256: DiagnosticSha256,
        terminal_sha256: DiagnosticSha256,
        cleanup_sha256: DiagnosticSha256,
    },
    PlanDenied {
        admission_code: crate::workload_registry_v2::AdmissionCodeV2,
        rejection_sha256: DiagnosticSha256,
    },
    FrozenPlanDenied {
        rejection_sha256: DiagnosticSha256,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPolicyBranchEvidenceV1 {
    pub branch: PolicyOperationBranchV1,
    pub challenge: [u8; 32],
    pub result_key: DiagnosticSha256,
    pub child: FinalPublicChildIdentityV2,
    pub provider_record_sha256: DiagnosticSha256,
    pub plan_response_sha256: DiagnosticSha256,
    pub grant_decision_sha256: DiagnosticSha256,
    pub kernel_capture_sha256: DiagnosticSha256,
    pub report_sha256: DiagnosticSha256,
    pub stdio_sha256: DiagnosticSha256,
    pub raw_inventory_sha256: DiagnosticSha256,
    pub outcome: PublicPolicyBranchOutcomeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPolicyCompositeCaseV1 {
    pub schema_version: u8,
    pub selector: String,
    pub base_challenge: [u8; 32],
    pub source_commit: String,
    pub release_version: BoundedText<128>,
    pub target: String,
    pub native_machine: String,
    pub archive_sha256: DiagnosticSha256,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub active_h1_receipt_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub build_context_sha256: DiagnosticSha256,
    pub release_catalogue_sha256: DiagnosticSha256,
    pub provider_inventory_sha256: DiagnosticSha256,
    pub interval_inventory_sha256: DiagnosticSha256,
    pub branches: [PublicPolicyBranchEvidenceV1; 5],
}

impl PublicPolicyCompositeCaseV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_PUBLIC_POLICY_COMPOSITE_BYTES_V1 {
            return Err("public policy composite byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let value: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if serde_json::to_vec(&value).map_err(|error| error.to_string())? != bytes {
            return Err("public policy composite encoding is not canonical".into());
        }
        value.validate()?;
        Ok(value)
    }

    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            PUBLIC_POLICY_SELECTOR_V1,
            &self.base_challenge,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        if self.schema_version != 1
            || self.selector != PUBLIC_POLICY_SELECTOR_V1
            || self.base_challenge == [0; 32]
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.release_version.as_str().is_empty()
            || !matches!(
                (self.target.as_str(), self.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64")
            )
            || [
                &self.archive_sha256,
                &self.manifest_sha256,
                &self.qualification_sha256,
                &self.active_h1_receipt_sha256,
                &self.installation_epoch,
                &self.build_context_sha256,
                &self.release_catalogue_sha256,
                &self.provider_inventory_sha256,
                &self.interval_inventory_sha256,
            ]
            .contains(&&zero)
        {
            return Err("public policy composite release subject differs".into());
        }
        let mut keys = BTreeSet::new();
        let mut actors = BTreeSet::new();
        let mut captures = BTreeSet::new();
        let mut providers = BTreeSet::new();
        let boot = &self.branches[0].child.boot_identity;
        let actor = &self.branches[0].child;
        for (branch, item) in PolicyOperationBranchV1::ALL.into_iter().zip(&self.branches) {
            let derived = policy_branch_challenge_v1(&self.base_challenge, branch)?;
            let key = private_release_case_key_v1(
                PrivateReleaseStageV1::FinalPublic,
                PUBLIC_POLICY_SELECTOR_V1,
                &derived,
            )?;
            let expected_code = match branch {
                PolicyOperationBranchV1::WrongGrant => {
                    Some(crate::workload_registry_v2::AdmissionCodeV2::ProfileNotAuthorized)
                }
                PolicyOperationBranchV1::WrongProfile => {
                    Some(crate::workload_registry_v2::AdmissionCodeV2::ProfileDigestMismatch)
                }
                PolicyOperationBranchV1::UnapprovedChangedPortPlan => {
                    Some(crate::workload_registry_v2::AdmissionCodeV2::PlanNotApproved)
                }
                _ => None,
            };
            let outcome_valid = match (&item.outcome, branch) {
                (
                    PublicPolicyBranchOutcomeV1::AcceptedControl {
                        attempt_id,
                        target_identity_sha256,
                        terminal_sha256,
                        cleanup_sha256,
                    },
                    PolicyOperationBranchV1::AcceptedControl,
                ) => {
                    attempt_id.len() == 32
                        && attempt_id
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        && [target_identity_sha256, terminal_sha256, cleanup_sha256]
                            .iter()
                            .all(|digest| **digest != zero)
                }
                (
                    PublicPolicyBranchOutcomeV1::PlanDenied {
                        admission_code,
                        rejection_sha256,
                    },
                    _,
                ) => Some(*admission_code) == expected_code && *rejection_sha256 != zero,
                (
                    PublicPolicyBranchOutcomeV1::FrozenPlanDenied { rejection_sha256 },
                    PolicyOperationBranchV1::CommittedPortTamper,
                ) => *rejection_sha256 != zero,
                _ => false,
            };
            if item.branch != branch
                || item.challenge != derived
                || item.result_key != key
                || !keys.insert(*item.result_key.bytes())
                || !actors.insert((item.child.pid, item.child.start_time_ticks))
                || !captures.insert(*item.kernel_capture_sha256.bytes())
                || !providers.insert(*item.provider_record_sha256.bytes())
                || item.child.boot_identity != *boot
                || item.child.uid != actor.uid
                || item.child.gid != actor.gid
                || item.child.executable_sha256 != actor.executable_sha256
                || item.child.pid == 0
                || item.child.start_time_ticks == 0
                || item.child.uid == 0
                || item.child.gid == 0
                || !item.child.supplementary_groups_empty
                || [
                    &item.child.executable_sha256,
                    &item.child.argv_sha256,
                    &item.child.working_directory_sha256,
                    &item.provider_record_sha256,
                    &item.plan_response_sha256,
                    &item.grant_decision_sha256,
                    &item.kernel_capture_sha256,
                    &item.report_sha256,
                    &item.stdio_sha256,
                    &item.raw_inventory_sha256,
                ]
                .contains(&&zero)
                || !outcome_valid
            {
                return Err("public policy branch inventory or outcome differs".into());
            }
        }
        if self.result_key()? == hash_bytes(&[]) || keys.contains(self.result_key()?.bytes()) {
            return Err("public policy base result key aliases a derived branch".into());
        }
        Ok(())
    }
}
