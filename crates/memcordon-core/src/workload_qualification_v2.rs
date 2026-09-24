//! Structural V2 qualification verification against trusted native runner records.
//!
//! This module does not manufacture a qualification artifact or execute tests.
//! The caller must supply completion digests from an independently trusted
//! native runner and join the parsed bytes to a reviewed release inventory.

use crate::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, QualificationArtifactSchemaTwo,
};
use crate::workload_codec::{Encoder, hash_bytes};
use crate::workload_contract::ProfileRef;
use crate::workload_discovery_v2::profile_catalog_digest_v2;
use crate::workload_limits as limits;
use crate::workload_registry_v2::ProfileKindV2;
use crate::{BoundedText, BoundedVec, DiagnosticSha256};
use serde::{Deserialize, Serialize};

pub const NATIVE_TESTS_MAX: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NativeTestOutcomeV2 {
    Passed,
    Failed,
    Skipped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedNativeTestV2 {
    pub name: BoundedText<256>,
    pub target: BoundedText<128>,
    pub outcome: NativeTestOutcomeV2,
    pub runner_completion_digest: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualificationArtifactV2 {
    pub schema_version: QualificationArtifactSchemaTwo,
    pub source_commit: BoundedText<40>,
    pub target: BoundedText<128>,
    pub profile: ProfileRef,
    pub profile_catalog_digest: DiagnosticSha256,
    pub filter_digest: DiagnosticSha256,
    pub unit_digest: DiagnosticSha256,
    pub component_digest: DiagnosticSha256,
    pub test_inventory_digest: DiagnosticSha256,
    pub runner_run_digest: DiagnosticSha256,
    pub host_prerequisites_digest: DiagnosticSha256,
    pub observed_results: BoundedVec<ObservedNativeTestV2, NATIVE_TESTS_MAX>,
    pub tests_skipped: u32,
}

/// Each completion digest is obtained from an observed native runner record,
/// not reconstructed from an expected test name or an artifact's own flags.
pub struct TrustedNativeCompletionV2<'a> {
    pub name: &'a str,
    pub target: &'a str,
    pub native_executed: bool,
    pub completion_digest: &'a DiagnosticSha256,
}

/// This expectation is an independent input to verification. Its source must
/// be the checked-in required inventory plus trusted runner completion data.
pub struct TrustedQualificationExpectationV2<'a> {
    pub source_commit: &'a str,
    pub target: &'a str,
    pub profile: &'a ProfileRef,
    pub filter_digest: &'a DiagnosticSha256,
    pub unit_digest: &'a DiagnosticSha256,
    pub component_digest: &'a DiagnosticSha256,
    pub runner_run_digest: &'a DiagnosticSha256,
    pub host_prerequisites_digest: &'a DiagnosticSha256,
    pub completions: &'a [TrustedNativeCompletionV2<'a>],
}

impl QualificationArtifactV2 {
    pub fn parse_and_validate(
        bytes: &[u8],
        reference: &QualificationArtifactReferenceV2,
        expected: &TrustedQualificationExpectationV2<'_>,
    ) -> Result<Self, String> {
        if bytes.len() > limits::REGISTRY_BYTES {
            return Err("qualification artifact exceeds byte limit".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        let artifact: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if reference.artifact_sha256 != hash_bytes(bytes)
            || reference.qualified_target != artifact.target.as_str()
            || reference.source_commit != artifact.source_commit.as_str()
            || reference.profile != artifact.profile
        {
            return Err("qualification artifact reference does not bind actual bytes".into());
        }
        artifact.validate(expected)?;
        Ok(artifact)
    }

    pub fn validate(&self, expected: &TrustedQualificationExpectationV2<'_>) -> Result<(), String> {
        if self.source_commit.as_str() != expected.source_commit
            || self.target.as_str() != expected.target
            || &self.profile != expected.profile
            || self.profile != ProfileKindV2::LinuxTcp4PrivateV1.reference()
            || !matches!(
                self.target.as_str(),
                "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
            )
            || !valid_source_commit(self.source_commit.as_str())
            || self.profile_catalog_digest != profile_catalog_digest_v2()
            || &self.filter_digest != expected.filter_digest
            || &self.unit_digest != expected.unit_digest
            || &self.component_digest != expected.component_digest
            || &self.runner_run_digest != expected.runner_run_digest
            || &self.host_prerequisites_digest != expected.host_prerequisites_digest
            || self.tests_skipped != 0
            || self.observed_results.as_slice().len() != expected.completions.len()
            || expected.completions.is_empty()
            || expected.completions.len() > NATIVE_TESTS_MAX
        {
            return Err("V2 qualification identity, native target or result count differs".into());
        }
        let inventory_digest = inventory_digest(expected.completions)?;
        if self.test_inventory_digest != inventory_digest {
            return Err("V2 qualification test inventory digest differs".into());
        }
        for (observed, trusted) in self
            .observed_results
            .as_slice()
            .iter()
            .zip(expected.completions)
        {
            if observed.name.as_str() != trusted.name
                || observed.target.as_str() != expected.target
                || trusted.target != expected.target
                || !trusted.native_executed
                || observed.outcome != NativeTestOutcomeV2::Passed
                || &observed.runner_completion_digest != trusted.completion_digest
            {
                return Err("V2 qualification native test observation differs".into());
            }
        }
        Ok(())
    }
}

pub fn inventory_digest(
    expected: &[TrustedNativeCompletionV2<'_>],
) -> Result<DiagnosticSha256, String> {
    if expected.is_empty() || expected.len() > NATIVE_TESTS_MAX {
        return Err("V2 qualification inventory count differs".into());
    }
    let mut encoder = Encoder::new(b"qualification-test-inventory-v2", limits::REGISTRY_BYTES)?;
    encoder.count(expected.len())?;
    for (index, test) in expected.iter().enumerate() {
        if test.name.is_empty()
            || test.name.len() > 256
            || !test
                .name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b':'))
            || (index > 0 && expected[index - 1].name >= test.name)
        {
            return Err("V2 qualification test inventory is not sorted and unique".into());
        }
        encoder.count(test.name.len())?;
        encoder.raw(test.name.as_bytes())?;
    }
    Ok(hash_bytes(&encoder.finish()))
}

fn valid_source_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
