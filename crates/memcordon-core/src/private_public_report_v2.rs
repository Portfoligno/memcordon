//! Final-public CLI report evidence for fault cases that can lose the frontend.
//!
//! This is a bounded wire record, not authentication of the hashes it holds.
//! The independent supervisor must obtain terminal, transport and recovery
//! evidence from protected sources before accepting an absent CLI report.

use serde::{Deserialize, Serialize};

use crate::DiagnosticSha256;
use crate::private_release_case_v1::PrivateReleaseAllocatedOutcomeV1;
use crate::workload_codec::hash_bytes;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::workload_limits::PUBLIC_OBJECT_BYTES;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum PublicCliReportEvidenceV2 {
    Present {
        size: u64,
        sha256: DiagnosticSha256,
    },
    AbsentFrontendLoss {
        authenticated_terminal_sha256: DiagnosticSha256,
        supervised_transport_sha256: DiagnosticSha256,
        independent_recovery_sha256: DiagnosticSha256,
    },
    /// V3 only. Preserve a real nonterminal rejection; never rename it a
    /// Terminal to satisfy the legacy frontend-loss envelope.
    AbsentFrontendRejectedV3 {
        original_rejection_sha256: DiagnosticSha256,
        supervised_transport_sha256: DiagnosticSha256,
        supervisor_wait_sha256: DiagnosticSha256,
        independent_recovery_sha256: DiagnosticSha256,
    },
}

impl PublicCliReportEvidenceV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > PUBLIC_OBJECT_BYTES {
            return Err("public CLI report evidence byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let evidence: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if matches!(evidence, Self::AbsentFrontendRejectedV3 { .. }) {
            return Err(
                "nonterminal frontend report replacement requires public V3 case transport".into(),
            );
        }
        evidence.validate_structure()?;
        Ok(evidence)
    }

    pub fn validate_structure(&self) -> Result<(), String> {
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        match self {
            Self::Present { size, sha256 } => {
                if *size == 0 || *size > PUBLIC_OBJECT_BYTES as u64 || *sha256 == zero {
                    return Err("present public CLI report evidence differs".into());
                }
            }
            Self::AbsentFrontendLoss {
                authenticated_terminal_sha256,
                supervised_transport_sha256,
                independent_recovery_sha256,
            } => {
                if [
                    authenticated_terminal_sha256,
                    supervised_transport_sha256,
                    independent_recovery_sha256,
                ]
                .into_iter()
                .any(|digest| *digest == zero)
                {
                    return Err("frontend-loss replacement evidence is incomplete".into());
                }
            }
            Self::AbsentFrontendRejectedV3 {
                original_rejection_sha256,
                supervised_transport_sha256,
                supervisor_wait_sha256,
                independent_recovery_sha256,
            } => {
                if [
                    original_rejection_sha256,
                    supervised_transport_sha256,
                    supervisor_wait_sha256,
                    independent_recovery_sha256,
                ]
                .into_iter()
                .any(|digest| *digest == zero)
                {
                    return Err("V3 nonterminal frontend replacement is incomplete".into());
                }
            }
        }
        Ok(())
    }

    pub fn validate_for_outcome(
        &self,
        outcome: PrivateReleaseAllocatedOutcomeV1,
        report_bytes: Option<&[u8]>,
    ) -> Result<(), String> {
        self.validate_structure()?;
        match (self, report_bytes) {
            (Self::Present { size, sha256 }, Some(bytes))
                if *size == bytes.len() as u64 && *sha256 == hash_bytes(bytes) =>
            {
                Ok(())
            }
            (Self::AbsentFrontendLoss { .. }, None)
                if outcome == PrivateReleaseAllocatedOutcomeV1::FrontendLost =>
            {
                Ok(())
            }
            _ => Err("public CLI report presence differs from observed outcome".into()),
        }
    }
}
