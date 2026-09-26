//! Final-public reuse has a postallocation cleanup failure, a distinct
//! preallocation refusal, and later recovery. It is not a Terminal case.
//! This record binds protected bytes but confers no semantic authority.

use serde::{Deserialize, Serialize};

use crate::private_public_case_v2::FinalPublicChildIdentityV2;
use crate::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use crate::workload_contract::reject_duplicate_json_keys;
use crate::{BoundedText, DiagnosticSha256};

pub const PUBLIC_REUSE_SELECTOR_V1: &str = "private_tcp::retirement_failure_blocks_reuse";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicReuseCompositeCaseV1 {
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
    pub child: FinalPublicChildIdentityV2,
    pub provider_sha256: DiagnosticSha256,
    pub report_sha256: DiagnosticSha256,
    pub stdio_sha256: DiagnosticSha256,
    pub first_failure_sha256: DiagnosticSha256,
    pub blocked_rejection_sha256: DiagnosticSha256,
    pub recovered_cleanup_sha256: DiagnosticSha256,
    pub durable_incomplete_snapshot_sha256: DiagnosticSha256,
    pub protected_reuse_transcript_sha256: DiagnosticSha256,
    pub semantic_join_sha256: DiagnosticSha256,
    pub first_kernel_capture_sha256: DiagnosticSha256,
    pub blocked_kernel_capture_sha256: DiagnosticSha256,
    pub recovery_kernel_capture_sha256: DiagnosticSha256,
}

impl PublicReuseCompositeCaseV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > 32 * 1024 {
            return Err("public reuse composite byte bound differs".into());
        }
        reject_duplicate_json_keys(bytes)?;
        let record: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if serde_json::to_vec(&record).map_err(|error| error.to_string())? != bytes {
            return Err("public reuse composite encoding is not canonical".into());
        }
        record.validate()?;
        Ok(record)
    }

    pub fn result_key(&self) -> Result<DiagnosticSha256, String> {
        private_release_case_key_v1(
            PrivateReleaseStageV1::FinalPublic,
            PUBLIC_REUSE_SELECTOR_V1,
            &self.challenge,
        )
    }

    pub fn validate(&self) -> Result<(), String> {
        let zero = DiagnosticSha256::from_bytes([0; 32]);
        let captures = [
            &self.first_kernel_capture_sha256,
            &self.blocked_kernel_capture_sha256,
            &self.recovery_kernel_capture_sha256,
        ];
        if self.schema_version != 1
            || self.selector != PUBLIC_REUSE_SELECTOR_V1
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
            || self.child.pid == 0
            || self.child.start_time_ticks == 0
            || self.child.uid == 0
            || self.child.gid == 0
            || !self.child.supplementary_groups_empty
            || self.child.boot_identity.as_str().is_empty()
            || [
                &self.archive_sha256,
                &self.manifest_sha256,
                &self.qualification_sha256,
                &self.active_h1_receipt_sha256,
                &self.installation_epoch,
                &self.provider_sha256,
                &self.report_sha256,
                &self.stdio_sha256,
                &self.first_failure_sha256,
                &self.blocked_rejection_sha256,
                &self.recovered_cleanup_sha256,
                &self.durable_incomplete_snapshot_sha256,
                &self.protected_reuse_transcript_sha256,
                &self.semantic_join_sha256,
                &self.child.executable_sha256,
                &self.child.argv_sha256,
                &self.child.working_directory_sha256,
            ]
            .contains(&&zero)
            || captures.contains(&&zero)
            || captures[0] == captures[1]
            || captures[0] == captures[2]
            || captures[1] == captures[2]
            || self.semantic_join_sha256 == self.protected_reuse_transcript_sha256
            || self.first_failure_sha256 == self.blocked_rejection_sha256
            || self.first_failure_sha256 == self.recovered_cleanup_sha256
        {
            return Err("public reuse failure/block/recovery identity differs".into());
        }
        self.result_key()?;
        Ok(())
    }
}
