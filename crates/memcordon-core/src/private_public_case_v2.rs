//! Structural final-public case evidence from an installed CLI invocation.
//!
//! The record binds the public child and raw observations to one final
//! installation. It does not authenticate the producer, process, protected
//! terminal or downloaded archive; the independent verifier must obtain those
//! facts separately and compare them before constructing P.

use serde::{Deserialize, Serialize};

use crate::private_public_report_v2::PublicCliReportEvidenceV2;
use crate::private_release_case_v1::{
    MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1, MAX_PRIVATE_RELEASE_RESULT_BYTES_V1,
    PrivateReleaseAllocatedOutcomeV1, PrivateReleaseAttachmentRoleV1, PrivateReleaseAttachmentV1,
    PrivateReleaseObservationV1, PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1,
    private_release_case_key_v1, validate_release_observation_v1,
};
use crate::workload_codec::hash_bytes;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::{BoundedText, DiagnosticSha256};

/// Final-public raw capture uses its reviewed fixed 100,000-event budget.
/// This is a transport bound, never permission to trust a capture.
pub const MAX_FINAL_PUBLIC_OBSERVER_BYTES_V3: u64 = 40 + 192 * 100_000;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalPublicInstalledBindingV2 {
    pub installation_epoch: DiagnosticSha256,
    pub archive_sha256: DiagnosticSha256,
    pub qualified_manifest_sha256: DiagnosticSha256,
    pub release_qualification_sha256: DiagnosticSha256,
    pub active_host_receipt_sha256: DiagnosticSha256,
    pub component_sha256: DiagnosticSha256,
    pub unit_sha256: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
    pub public_plan_sha256: DiagnosticSha256,
    pub public_grant_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalPublicChildIdentityV2 {
    pub pid: u32,
    pub start_time_ticks: u64,
    pub boot_identity: BoundedText<128>,
    pub uid: u32,
    pub gid: u32,
    pub supplementary_groups_empty: bool,
    pub executable_sha256: DiagnosticSha256,
    pub argv_sha256: DiagnosticSha256,
    pub working_directory_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalPublicCaseEvidenceV2 {
    pub schema_version: u8,
    pub selector: String,
    pub challenge: [u8; 32],
    pub source_commit: String,
    pub release_version: BoundedText<128>,
    pub target: String,
    pub native_machine: String,
    pub build_context_sha256: DiagnosticSha256,
    pub release_catalogue_sha256: DiagnosticSha256,
    pub installed: FinalPublicInstalledBindingV2,
    pub child: FinalPublicChildIdentityV2,
    pub observation: PrivateReleaseObservationV1,
    pub positive_control_terminal_sha256: Option<DiagnosticSha256>,
    pub report: PublicCliReportEvidenceV2,
    pub attachments: Vec<PrivateReleaseAttachmentV1>,
}

impl FinalPublicCaseEvidenceV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 {
            return Err("final-public case evidence byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let case: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        case.validate()?;
        Ok(case)
    }

    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            &self.selector,
            &self.challenge,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_version(2)
    }

    fn validate_version(&self, version: u8) -> Result<(), String> {
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        if self.schema_version != version
            || !matches!(version, 2 | 3)
            || !REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.contains(&self.selector.as_str())
            || self.challenge == [0; 32]
            || self.source_commit.len() != [0_u8; 20].len() * 2
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || self.release_version.as_str().is_empty()
            || !matches!(
                (self.target.as_str(), self.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64")
            )
        {
            return Err("final-public selector, challenge or source identity differs".into());
        }
        if [
            &self.installed.installation_epoch,
            &self.installed.archive_sha256,
            &self.installed.qualified_manifest_sha256,
            &self.installed.release_qualification_sha256,
            &self.installed.active_host_receipt_sha256,
            &self.installed.component_sha256,
            &self.installed.unit_sha256,
            &self.installed.filter_sha256,
            &self.installed.public_plan_sha256,
            &self.installed.public_grant_sha256,
            &self.build_context_sha256,
            &self.release_catalogue_sha256,
            &self.child.executable_sha256,
            &self.child.argv_sha256,
            &self.child.working_directory_sha256,
        ]
        .into_iter()
        .any(|digest| *digest == zero)
            || self.child.pid == 0
            || self.child.start_time_ticks == 0
            || self.child.uid == 0
            || self.child.gid == 0
            || !self.child.supplementary_groups_empty
            || self.child.boot_identity.as_str().is_empty()
        {
            return Err("final-public installed or nonroot child binding is incomplete".into());
        }
        validate_release_observation_v1(
            &self.selector,
            PrivateReleaseStageV1::FinalPublic,
            &self.observation,
        )?;
        let observation_digests: Vec<&DiagnosticSha256> = match &self.observation {
            PrivateReleaseObservationV1::PublicFaultRejectedRetiredV2 {
                checkpoint_file_sha256,
                original_rejection_sha256,
                fault_trigger_sha256,
                fault_failure_sha256,
                retirement_sha256,
                recovery_sha256,
                native_observer_sha256,
                ..
            } => {
                if version != 3 {
                    return Err(
                        "versioned nonterminal fault evidence requires public V3 transport".into(),
                    );
                }
                let mut digests = vec![
                    checkpoint_file_sha256,
                    original_rejection_sha256,
                    fault_trigger_sha256,
                    retirement_sha256,
                    native_observer_sha256,
                ];
                digests.extend(fault_failure_sha256.iter());
                digests.extend(recovery_sha256.iter());
                digests
            }
            PrivateReleaseObservationV1::PolicyComposite { .. }
            | PrivateReleaseObservationV1::AbiComposite { .. } => {
                return Err("candidate composite is not final-public evidence".into());
            }
            PrivateReleaseObservationV1::PreallocationRejected {
                observer_sha256, ..
            } => vec![observer_sha256],
            PrivateReleaseObservationV1::AllocatedRetired {
                checkpoint_sha256,
                terminal_sha256,
                retirement_sha256,
                native_observer_sha256,
                ..
            } => vec![
                checkpoint_sha256,
                terminal_sha256,
                retirement_sha256,
                native_observer_sha256,
            ],
            PrivateReleaseObservationV1::DualAttemptsRetired {
                first,
                second,
                native_observer_sha256,
            } => vec![
                &first.checkpoint_sha256,
                &first.terminal_sha256,
                &first.retirement_sha256,
                &second.checkpoint_sha256,
                &second.terminal_sha256,
                &second.retirement_sha256,
                native_observer_sha256,
            ],
            PrivateReleaseObservationV1::RetirementFailureBlockedReuse {
                checkpoint_sha256,
                terminal_sha256,
                cleanup_failure_sha256,
                reuse_rejection_sha256,
                native_observer_sha256,
                ..
            } => vec![
                checkpoint_sha256,
                terminal_sha256,
                cleanup_failure_sha256,
                reuse_rejection_sha256,
                native_observer_sha256,
            ],
        };
        if observation_digests
            .into_iter()
            .any(|digest| *digest == zero)
        {
            return Err("final-public protected observation digest is absent".into());
        }
        self.report.validate_structure()?;
        if let PublicCliReportEvidenceV2::AbsentFrontendRejectedV3 {
            original_rejection_sha256,
            ..
        } = &self.report
        {
            if version != 3
                || !matches!(&self.observation,PrivateReleaseObservationV1::PublicFaultRejectedRetiredV2 {outcome:PrivateReleaseAllocatedOutcomeV1::FrontendLost,original_rejection_sha256:original,..} if original==original_rejection_sha256)
            {
                return Err(
                    "V3 absent frontend report differs from actual nonterminal rejection".into(),
                );
            }
        }
        if matches!(
            self.report,
            PublicCliReportEvidenceV2::AbsentFrontendLoss { .. }
        ) && matches!(
            self.observation,
            PrivateReleaseObservationV1::PublicFaultRejectedRetiredV2 { .. }
        ) {
            return Err(
                "nonterminal frontend rejection cannot claim authenticated Terminal".into(),
            );
        }
        match (&self.observation, &self.positive_control_terminal_sha256) {
            (
                PrivateReleaseObservationV1::PreallocationRejected { rejection_code, .. },
                Some(control),
            ) if rejection_code == "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED" && *control != zero => {
            }
            (PrivateReleaseObservationV1::PreallocationRejected { .. }, _) => {
                return Err("final-public exact rejection or positive control is absent".into());
            }
            (_, None) => {}
            (_, Some(_)) => {
                return Err("final-public positive control belongs only to rejection".into());
            }
        }
        if matches!(
            self.report,
            PublicCliReportEvidenceV2::AbsentFrontendLoss { .. }
        ) && !matches!(
            self.observation,
            PrivateReleaseObservationV1::AllocatedRetired {
                outcome: PrivateReleaseAllocatedOutcomeV1::FrontendLost,
                ..
            }
        ) {
            return Err("absent public CLI report requires frontend loss".into());
        }
        if let (
            PublicCliReportEvidenceV2::AbsentFrontendLoss {
                authenticated_terminal_sha256,
                ..
            },
            PrivateReleaseObservationV1::AllocatedRetired {
                terminal_sha256, ..
            },
        ) = (&self.report, &self.observation)
        {
            if authenticated_terminal_sha256 != terminal_sha256 {
                return Err("frontend-loss terminal replacement differs".into());
            }
        }
        let expected_roles: &[PrivateReleaseAttachmentRoleV1] =
            if matches!(self.report, PublicCliReportEvidenceV2::Present { .. }) {
                &PrivateReleaseAttachmentRoleV1::ALL
            } else {
                &[
                    PrivateReleaseAttachmentRoleV1::Request,
                    PrivateReleaseAttachmentRoleV1::Stdio,
                    PrivateReleaseAttachmentRoleV1::Observer,
                    PrivateReleaseAttachmentRoleV1::Cleanup,
                ]
            };
        if self.attachments.len() != expected_roles.len()
            || self
                .attachments
                .iter()
                .zip(expected_roles)
                .any(|(actual, role)| {
                    actual.role != *role
                        || actual.size
                            > if version == 3
                                && actual.role == PrivateReleaseAttachmentRoleV1::Observer
                            {
                                MAX_FINAL_PUBLIC_OBSERVER_BYTES_V3
                            } else {
                                MAX_PRIVATE_RELEASE_ATTACHMENT_BYTES_V1
                            }
                        || actual.sha256 == zero
                })
        {
            return Err("final-public raw attachment inventory differs".into());
        }
        let observer = self
            .attachments
            .iter()
            .find(|attachment| attachment.role == PrivateReleaseAttachmentRoleV1::Observer)
            .expect("fixed attachment roles contain observer");
        let observed = match &self.observation {
            PrivateReleaseObservationV1::PublicFaultRejectedRetiredV2 {
                native_observer_sha256,
                ..
            } => native_observer_sha256,
            PrivateReleaseObservationV1::PolicyComposite { .. }
            | PrivateReleaseObservationV1::AbiComposite { .. } => {
                return Err("candidate composite is not final-public evidence".into());
            }
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
        if observer.sha256 != *observed {
            return Err("final-public observer attachment differs".into());
        }
        if let PublicCliReportEvidenceV2::Present { size, sha256 } = &self.report {
            let attachment = &self.attachments[1];
            if attachment.size != *size || attachment.sha256 != *sha256 {
                return Err("final-public CLI report attachment differs".into());
            }
        }
        Ok(())
    }

    pub fn validate_report_bytes(&self, report_bytes: Option<&[u8]>) -> Result<(), String> {
        self.validate()?;
        match &self.observation {
            PrivateReleaseObservationV1::AllocatedRetired { outcome, .. } => {
                self.report.validate_for_outcome(*outcome, report_bytes)
            }
            _ => match (&self.report, report_bytes) {
                (PublicCliReportEvidenceV2::Present { size, sha256 }, Some(bytes))
                    if *size == bytes.len() as u64 && *sha256 == hash_bytes(bytes) =>
                {
                    Ok(())
                }
                _ => Err("final-public CLI report bytes differ".into()),
            },
        }
    }
}

/// Versioned structural transport, not a proof constructor. The independent
/// public verifier must reconstruct every original response/wait/retirement.
/// Legacy V2 retains its rejection of nonterminal fault evidence.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct FinalPublicCaseEvidenceV3(pub FinalPublicCaseEvidenceV2);
impl FinalPublicCaseEvidenceV3 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_PRIVATE_RELEASE_RESULT_BYTES_V1 {
            return Err("public V3 case byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let case: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        case.validate()?;
        Ok(case)
    }
    pub fn validate(&self) -> Result<(), String> {
        self.0.validate_version(3)
    }
    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        self.0.result_key()
    }
    pub fn validate_report_bytes(&self, report_bytes: Option<&[u8]>) -> Result<(), String> {
        self.validate()?;
        match (&self.0.report, report_bytes) {
            (PublicCliReportEvidenceV2::Present { size, sha256 }, Some(bytes))
                if *size == bytes.len() as u64 && *sha256 == hash_bytes(bytes) =>
            {
                Ok(())
            }
            (
                PublicCliReportEvidenceV2::AbsentFrontendLoss { .. }
                | PublicCliReportEvidenceV2::AbsentFrontendRejectedV3 { .. },
                None,
            ) => Ok(()),
            _ => Err("public V3 original report presence differs".into()),
        }
    }
}
