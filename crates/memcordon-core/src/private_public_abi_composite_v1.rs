//! Structural final-public ABI composite. The filtered public CLI target and
//! the sealed service's outer-only controls are distinct actors. This format
//! binds their immutable inventories; it is not a semantic verification token.

use serde::{Deserialize, Serialize};

use crate::private_public_case_v2::FinalPublicChildIdentityV2;
use crate::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use crate::workload_codec::hash_bytes;
use crate::workload_contract::reject_duplicate_json_keys;
use crate::{BoundedText, DiagnosticSha256};

pub const PUBLIC_ABI_SELECTOR_V1: &str = "private_tcp::abi_alternate_entry_denied";
const OUTER_DOMAIN: &[u8] = b"memcordon-public-abi-outer-v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicAbiCompositeCaseV1 {
    pub schema_version: u8,
    pub selector: String,
    pub challenge: [u8; 32],
    pub source_commit: String,
    pub release_version: BoundedText<128>,
    pub target: String,
    pub native_machine: String,
    pub archive_sha256: DiagnosticSha256,
    pub manifest_sha256: DiagnosticSha256,
    pub qualification_sha256: DiagnosticSha256,
    pub active_h1_receipt_sha256: DiagnosticSha256,
    pub installation_epoch: DiagnosticSha256,
    pub filtered_child: FinalPublicChildIdentityV2,
    pub filtered_provider_sha256: DiagnosticSha256,
    pub filtered_report_sha256: DiagnosticSha256,
    pub filtered_stdio_sha256: DiagnosticSha256,
    pub filtered_terminal_sha256: DiagnosticSha256,
    pub filtered_cleanup_sha256: DiagnosticSha256,
    /// Exact service-captured target stdout; still only a producer claim.
    pub filtered_target_report_sha256: DiagnosticSha256,
    /// Exact protected service wrapper joining stdout to the H1 attempt.
    pub filtered_service_journal_sha256: DiagnosticSha256,
    /// Exact protected durable checkpoint JSON retained before V4 removal.
    pub filtered_checkpoint_file_sha256: DiagnosticSha256,
    pub filtered_kernel_capture_sha256: DiagnosticSha256,
    pub outer_auxiliary_key: DiagnosticSha256,
    pub outer_request_sha256: DiagnosticSha256,
    pub outer_raw_sha256: DiagnosticSha256,
    pub outer_kernel_capture_sha256: DiagnosticSha256,
}

impl PublicAbiCompositeCaseV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 32 * 1024 {
            return Err("public ABI composite byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if serde_json::to_vec(&record).map_err(|error| error.to_string())? != bytes {
            return Err("public ABI composite encoding is not canonical".into());
        }
        record.validate()?;
        Ok(record)
    }

    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            PUBLIC_ABI_SELECTOR_V1,
            &self.challenge,
        )
    }

    pub fn expected_outer_auxiliary_key(&self) -> Result<DiagnosticSha256, String> {
        let mut bytes = OUTER_DOMAIN.to_vec();
        for digest in [
            &self.active_h1_receipt_sha256,
            &self.installation_epoch,
            &self.result_key()?,
            &DiagnosticSha256::from_bytes(self.challenge),
        ] {
            bytes.extend_from_slice(digest.bytes());
        }
        Ok(hash_bytes(&bytes))
    }

    pub fn validate(&self) -> Result<(), String> {
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        if self.schema_version != 1
            || self.selector != PUBLIC_ABI_SELECTOR_V1
            || self.challenge == [0; 32]
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
            || self.filtered_child.pid == 0
            || self.filtered_child.start_time_ticks == 0
            || self.filtered_child.uid == 0
            || self.filtered_child.gid == 0
            || !self.filtered_child.supplementary_groups_empty
            || self.filtered_child.boot_identity.as_str().is_empty()
            || [
                &self.archive_sha256,
                &self.manifest_sha256,
                &self.qualification_sha256,
                &self.active_h1_receipt_sha256,
                &self.installation_epoch,
                &self.filtered_provider_sha256,
                &self.filtered_report_sha256,
                &self.filtered_stdio_sha256,
                &self.filtered_terminal_sha256,
                &self.filtered_cleanup_sha256,
                &self.filtered_target_report_sha256,
                &self.filtered_service_journal_sha256,
                &self.filtered_checkpoint_file_sha256,
                &self.filtered_kernel_capture_sha256,
                &self.outer_request_sha256,
                &self.outer_raw_sha256,
                &self.outer_kernel_capture_sha256,
                &self.filtered_child.executable_sha256,
                &self.filtered_child.argv_sha256,
                &self.filtered_child.working_directory_sha256,
            ]
            .contains(&&zero)
            || self.outer_auxiliary_key != self.expected_outer_auxiliary_key()?
            || self.filtered_kernel_capture_sha256 == self.outer_kernel_capture_sha256
            || self.filtered_provider_sha256 == self.outer_raw_sha256
            || self.filtered_target_report_sha256 == self.filtered_service_journal_sha256
        {
            return Err("public ABI filtered/outer composite identity differs".into());
        }
        Ok(())
    }
}
