//! Q materialization and final-public gate behind non-deserializable native authority.
//!
//! These tokens have no constructor while the stage-specific 25-case native
//! endpoint is incomplete. Structural JSON/ZIP readback cannot inhabit them.

use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, QualificationArtifactSchemaTwo,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_qualification_v2::{
    NativeTestOutcomeV2, ObservedNativeTestV2, QualificationArtifactV2, TrustedNativeCompletionV2,
    TrustedQualificationExpectationV2, inventory_digest,
};
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

use crate::private_native::{
    ExpectedFinalPublicJoinV2, NativeRunEnvelopeV2, NativeRunStageV2,
    validate_final_public_structural_join,
};
use crate::private_suite::REQUIRED_CASES;
use crate::workload_qualification::PRIVATE_V2_ARTIFACTS;
use crate::{CiError, Result};

/// Only a future independently authenticated supervisor reader may construct
/// this token. In particular, `StructuralNativeArtifactV2` cannot convert.
pub struct IndependentlyVerifiedCandidateRunV2 {
    envelope: NativeRunEnvelopeV2,
    raw_run_digest: DiagnosticSha256,
    completion_digests: Vec<DiagnosticSha256>,
}

/// The final public pass must be distinct from candidate capability evidence.
pub struct IndependentlyVerifiedFinalPublicRunV2 {
    envelope: NativeRunEnvelopeV2,
}

pub struct IndependentBuildIdentityV2<'a> {
    pub version: &'a str,
    pub source_commit: &'a str,
    pub target: &'a str,
    pub component_sha256: &'a DiagnosticSha256,
    pub unit_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub host_prerequisites_sha256: &'a DiagnosticSha256,
}

pub struct ProducedPrivateQualificationV2 {
    pub bytes: Vec<u8>,
    pub reference: QualificationArtifactReferenceV2,
}

/// Serializes Q only from independent B and a protected, authenticated 25-case
/// native run. It does not consume M1, archive A, H1 or final-public P.
pub fn produce_private_qualification_v2(
    run: &IndependentlyVerifiedCandidateRunV2,
    build: &IndependentBuildIdentityV2<'_>,
) -> Result<ProducedPrivateQualificationV2> {
    let envelope = &run.envelope;
    if envelope.stage != NativeRunStageV2::CandidateCapability
        || envelope.version != build.version
        || envelope.source_commit != build.source_commit
        || envelope.target != build.target
        || envelope.component_sha256 != *build.component_sha256
        || envelope.unit_sha256 != *build.unit_sha256
        || envelope.filter_sha256 != *build.filter_sha256
        || envelope.host_prerequisites_sha256 != *build.host_prerequisites_sha256
        || run.completion_digests.len() != REQUIRED_CASES.len()
        || envelope.cases.len() != REQUIRED_CASES.len()
        || envelope
            .cases
            .iter()
            .zip(REQUIRED_CASES)
            .any(|(case, name)| case.name != name || !case.passed)
    {
        return Err(CiError::Message(
            "verified candidate run differs from independent B".into(),
        ));
    }
    let completions: Vec<_> = REQUIRED_CASES
        .iter()
        .zip(&run.completion_digests)
        .map(|(name, digest)| TrustedNativeCompletionV2 {
            name,
            target: build.target,
            native_executed: true,
            completion_digest: digest,
        })
        .collect();
    let mut observed_results = BoundedVec::default();
    for completion in &completions {
        observed_results
            .try_push(ObservedNativeTestV2 {
                name: BoundedText::new(completion.name)
                    .map_err(|error| CiError::Message(error.into()))?,
                target: BoundedText::new(completion.target)
                    .map_err(|error| CiError::Message(error.into()))?,
                outcome: NativeTestOutcomeV2::Passed,
                runner_completion_digest: completion.completion_digest.clone(),
            })
            .map_err(|_| CiError::Message("private completion inventory exceeds bound".into()))?;
    }
    let profile = ProfileKindV2::LinuxTcp4PrivateV1.reference();
    let artifact = QualificationArtifactV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        source_commit: BoundedText::new(build.source_commit)
            .map_err(|error| CiError::Message(error.into()))?,
        target: BoundedText::new(build.target).map_err(|error| CiError::Message(error.into()))?,
        profile: profile.clone(),
        profile_catalog_digest: profile_catalog_digest_v2(),
        filter_digest: build.filter_sha256.clone(),
        unit_digest: build.unit_sha256.clone(),
        component_digest: build.component_sha256.clone(),
        test_inventory_digest: inventory_digest(&completions).map_err(CiError::Message)?,
        runner_run_digest: run.raw_run_digest.clone(),
        host_prerequisites_digest: build.host_prerequisites_sha256.clone(),
        observed_results,
        tests_skipped: 0,
    };
    let bytes = serde_json::to_vec(&artifact)?;
    let (_, path) = PRIVATE_V2_ARTIFACTS
        .iter()
        .find(|(target, _)| *target == build.target)
        .ok_or_else(|| CiError::Message("private Q target is not required".into()))?;
    let reference = QualificationArtifactReferenceV2 {
        schema_version: QualificationArtifactSchemaTwo::default(),
        artifact: (*path).into(),
        artifact_sha256: hash_bytes(&bytes),
        qualified_target: build.target.into(),
        source_commit: build.source_commit.into(),
        profile: profile.clone(),
    };
    let expected = TrustedQualificationExpectationV2 {
        source_commit: build.source_commit,
        target: build.target,
        profile: &profile,
        filter_digest: build.filter_sha256,
        unit_digest: build.unit_sha256,
        component_digest: build.component_sha256,
        runner_run_digest: &run.raw_run_digest,
        host_prerequisites_digest: build.host_prerequisites_sha256,
        completions: &completions,
    };
    crate::workload_qualification::validate_private_v2_against_trusted_native_completions(
        &bytes, &reference, &expected,
    )?;
    Ok(ProducedPrivateQualificationV2 { bytes, reference })
}

/// A publication precondition, not a success flag from the final artifact.
/// Both tokens must ultimately come from separate authenticated supervisor
/// readbacks; the current structural run records cannot construct either.
pub fn require_final_public_private_gate(
    candidate: &IndependentlyVerifiedCandidateRunV2,
    final_public: &IndependentlyVerifiedFinalPublicRunV2,
    build: &IndependentBuildIdentityV2<'_>,
    qualification: &ProducedPrivateQualificationV2,
    expected: &ExpectedFinalPublicJoinV2<'_>,
) -> Result<()> {
    let reproduced = produce_private_qualification_v2(candidate, build)?;
    if reproduced.bytes != qualification.bytes
        || reproduced.reference != qualification.reference
        || build.source_commit != expected.source_commit
        || build.version != expected.version
        || build.target != expected.target
        || build.component_sha256 != expected.component_sha256
        || build.unit_sha256 != expected.unit_sha256
        || build.filter_sha256 != expected.filter_sha256
    {
        return Err(CiError::Message(
            "private Q differs from candidate native run and final B".into(),
        ));
    }
    validate_final_public_structural_join(&candidate.envelope, &final_public.envelope, expected)?;
    Ok(())
}
