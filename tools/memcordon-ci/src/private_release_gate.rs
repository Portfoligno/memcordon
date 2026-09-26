//! Q materialization and final-public gate behind non-deserializable native authority.
//!
//! These tokens have no constructor while the stage-specific 25-case native
//! endpoint is incomplete. Structural JSON/ZIP readback cannot inhabit them.

use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::release_trust::{
    ExpectedNativeQualificationV1, NativeQualificationCertificateV1, ReleaseSigningRoleV1,
    ReleaseTrustAnchorV1, SignedNativeQualificationCertificateV1, SignedReleaseTrustPolicyV1,
    TrustHighWaterV1,
};
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

use crate::private_completed_run::{AuthenticatedCandidateC3, AuthenticatedCompletedProducerV2};
use crate::private_native::{ExpectedFinalPublicJoinV2, NativeRunEnvelopeV2, NativeRunStageV2};
use crate::private_native_verify::VerifiedCandidateSemanticsV2;
use crate::private_suite::REQUIRED_CASES;
use crate::release_private::PrivateCandidateRecordV2;
use crate::workload_qualification::PRIVATE_V2_ARTIFACTS;
use crate::{CiError, Result};

/// Only a future independently authenticated supervisor reader may construct
/// this token. In particular, `StructuralNativeArtifactV2` cannot convert.
pub struct IndependentlyVerifiedCandidateRunV2 {
    envelope: NativeRunEnvelopeV2,
    raw_run_digest: DiagnosticSha256,
    completion_digests: Vec<DiagnosticSha256>,
    raw_index_sha256: DiagnosticSha256,
}

/// The final public pass must be distinct from candidate capability evidence.
pub struct IndependentlyVerifiedFinalPublicRunV2 {
    public_index: crate::private_public_completion::PublicEvidenceIndexV3,
    public_index_sha256: DiagnosticSha256,
}

/// Constructed only after the independently authenticated Actions upload and
/// origin-bound family replay agree. A parsed P or a successful job is not enough.
pub(crate) fn complete_final_public_run(
    completed: &crate::private_public_completion::AuthenticatedCompletedPublicEvidenceV2,
    verified: &crate::private_public_completion::VerifiedPublicSemanticsV3,
) -> Result<IndependentlyVerifiedFinalPublicRunV2> {
    use crate::private_observer_session::ObserverStageV1;
    let origin = completed.origin();
    let subject = &origin.descriptor().subject;
    let provenance = completed.provenance();
    let index = verified.index();
    let generation = origin.descriptor().generations.last().ok_or_else(|| {
        CiError::Message("final public origin lacks installation generation".into())
    })?;
    if subject.stage != ObserverStageV1::Public
        || index.schema_version != 3
        || index.source_commit != subject.source_commit
        || index.release_version != subject.release_version
        || index.target != subject.target
        || index.build_sha256 != subject.build_sha256
        || index.catalogue_sha256 != subject.catalogue_sha256
        || index.origin_commitment_sha256 != *origin.origin_commitment_sha256()
        || index.custody_receipt_sha256 != *origin.receipt_sha256()
        || index.payload_index_sha256 != *origin.payload_index_sha256()
        || index.generation_timeline_sha256 != *origin.generation_timeline_sha256()
        || index.raw_index_sha256 != *completed.raw_index_sha256()
        || index.completed_provenance_sha256 != *completed.provenance_sha256()
        || index.installation_epoch != generation.installation_epoch
        || index.manifest_sha256 != generation.installed_manifest_sha256
        || index.host_receipt_sha256 != generation.installed_receipt_sha256
        || index.boot_identity != origin.descriptor().boot_id
        || provenance.repository_id != subject.repository_id
        || provenance.run_id != subject.run_id
        || provenance.run_attempt != subject.run_attempt
        || provenance.producer_job_id != subject.job_id
        || provenance.runner_id != subject.runner_id
        || origin.upload().is_none_or(|upload| {
            upload.archive_sha256 != provenance.archive_sha256
                || upload.archive_size != provenance.archive_size
                || upload.artifact_id != provenance.artifact_id
                || upload.uploaded_job_id != provenance.producer_job_id
                || upload.uploaded_run_attempt != provenance.run_attempt
        })
    {
        return Err(CiError::Message(
            "final P differs from completed Actions custody/build/install subject".into(),
        ));
    }
    let bytes = verified.public_index_bytes()?;
    let parsed = crate::private_public_completion::PublicEvidenceIndexV3::parse(&bytes)?;
    if parsed != *index {
        return Err(CiError::Message(
            "final P canonical readback differs".into(),
        ));
    }
    Ok(IndependentlyVerifiedFinalPublicRunV2 {
        public_index: parsed,
        public_index_sha256: hash_bytes(&bytes),
    })
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

/// Binds the independent 25-case semantic token to the actual completed C3
/// artifact. The older V2 envelope reader cannot parse the C3-only upload.
fn verify_candidate_c3_semantics(
    semantics: &VerifiedCandidateSemanticsV2,
    completed: &AuthenticatedCandidateC3,
    build: &IndependentBuildIdentityV2<'_>,
) -> Result<()> {
    if semantics.result_digests.len() != REQUIRED_CASES.len()
        || !semantics.completed_origin
        || completed.index.cases.len() != REQUIRED_CASES.len()
        || completed.index.target != build.target
        || completed.index.source_commit != build.source_commit
        || completed.index.release_version != build.version
        || completed.raw_index_sha256 == hash_bytes(&[])
        || completed.provenance_sha256 == hash_bytes(&[])
    {
        return Err(CiError::Message(
            "completed C3 independent case subject differs from B".into(),
        ));
    }
    let origin = completed.observer_origin.as_ref().ok_or_else(|| {
        CiError::Message("candidate Q lacks completed authenticated custody".into())
    })?;
    if semantics.subject != origin.descriptor().subject
        || semantics.payload_index_sha256 != *origin.payload_index_sha256()
        || semantics.origin_commitment_sha256 != *origin.origin_commitment_sha256()
        || semantics.generation_timeline_sha256 != *origin.generation_timeline_sha256()
        || semantics.inventory_digests.len() != REQUIRED_CASES.len()
        || semantics.subject.source_commit != build.source_commit
        || semantics.subject.release_version != build.version
        || semantics.subject.target != build.target
    {
        return Err(CiError::Message(
            "candidate Q exact completed origin/replay subject differs".into(),
        ));
    }
    for ((case, selector), digest) in completed
        .index
        .cases
        .iter()
        .zip(REQUIRED_CASES)
        .zip(&semantics.result_digests)
    {
        let exact = completed
            .parsed
            .member(&case.result.path)
            .ok_or_else(|| CiError::Message("completed C3 exact protected result absent".into()))?;
        if case.selector != selector
            || case.result.sha256 != *digest
            || hash_bytes(exact) != *digest
        {
            return Err(CiError::Message(
                "completed C3 result differs from independent 25-case semantics".into(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn produce_private_qualification_c3(
    semantics: &VerifiedCandidateSemanticsV2,
    completed: &AuthenticatedCandidateC3,
    build: &IndependentBuildIdentityV2<'_>,
) -> Result<ProducedPrivateQualificationV2> {
    verify_candidate_c3_semantics(semantics, completed, build)?;
    let completions: Vec<_> = REQUIRED_CASES
        .iter()
        .zip(&semantics.result_digests)
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
            .map_err(|_| CiError::Message("C3 completion inventory exceeds bound".into()))?;
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
        runner_run_digest: completed.archive_sha256.clone(),
        host_prerequisites_digest: build.host_prerequisites_sha256.clone(),
        observed_results,
        tests_skipped: 0,
    };
    let bytes = serde_json::to_vec(&artifact)?;
    let (_, path) = PRIVATE_V2_ARTIFACTS
        .iter()
        .find(|(target, _)| *target == build.target)
        .ok_or_else(|| CiError::Message("C3 Q target is not required".into()))?;
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
        runner_run_digest: &completed.archive_sha256,
        host_prerequisites_digest: build.host_prerequisites_sha256,
        completions: &completions,
    };
    crate::workload_qualification::validate_private_v2_against_trusted_native_completions(
        &bytes, &reference, &expected,
    )?;
    Ok(ProducedPrivateQualificationV2 { bytes, reference })
}

/// The C3-native CQ issuer. It never accepts the old V2 ZIP envelope as a
/// substitute for the completed C3 raw index, and its only semantic input is
/// the non-deserializable 25-case verifier token.
pub(crate) fn sign_native_qualification_certificate_c3(
    semantics: &VerifiedCandidateSemanticsV2,
    completed: &AuthenticatedCandidateC3,
    build: &IndependentBuildIdentityV2<'_>,
    build_bytes: &[u8],
    qualification: &ProducedPrivateQualificationV2,
    intent: &NativeCertificateSigningIntentV1<'_>,
) -> Result<Vec<u8>> {
    let reproduced = produce_private_qualification_c3(semantics, completed, build)?;
    let policy = intent
        .signed_policy
        .verify(
            intent.trust_anchor,
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    let key = policy
        .policy()
        .delegated_keys
        .iter()
        .find(|key| key.key_id == intent.key_id)
        .ok_or_else(|| CiError::Message("C3 native Q signing key is not delegated".into()))?;
    if reproduced.bytes != qualification.bytes
        || reproduced.reference != qualification.reference
        || completed.repository_id != policy.policy().repository_id
        || intent.repository != policy.policy().repository
        || intent.workflow_path != policy.policy().workflow_path
        || intent.workflow_revision != policy.policy().workflow_revision
        || intent.verifier_sha256 != policy.policy().verifier_sha256
        || completed.index.collector_intent_sha256 != *intent.collector_intent_sha256
        || String::from(intent.release_catalogue_sha256.clone()) != policy.policy().catalogue_sha256
        || completed.index.target != build.target
        || completed.index.source_commit != build.source_commit
        || completed.index.release_version != build.version
        || !key.roles.contains(&ReleaseSigningRoleV1::NativeQ)
        || key.public_key_hex != key_bytes_hex(intent.signing_key.verifying_key().as_bytes())
        || intent.issued_at_unix < key.not_before_unix
        || intent.expires_at_unix > key.expires_at_unix
        || intent.release_sequence < policy.policy().minimum_release_sequence
        || intent.release_sequence < intent.high_water.release_sequence
        || intent.issued_at_unix >= intent.expires_at_unix
        || build_bytes.len() > 16 * 1024
        || completed.run_id == 0
        || completed.run_attempt == 0
    {
        return Err(CiError::Message(
            "C3 native Q signing authority differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(build_bytes)
        .map_err(CiError::Message)?;
    let submitted_build = PrivateCandidateRecordV2::parse(build_bytes).map_err(CiError::Message)?;
    if submitted_build.version != build.version
        || submitted_build.source_commit != build.source_commit
        || submitted_build.target != build.target
        || submitted_build.component_sha256 != *build.component_sha256
        || submitted_build.unit_sha256 != *build.unit_sha256
        || submitted_build.filter_sha256 != *build.filter_sha256
    {
        return Err(CiError::Message("C3 native Q signing B differs".into()));
    }
    let mut accepted_set = b"memcordon/private-accepted-case-set/v1\0".to_vec();
    for (case, digest) in completed.index.cases.iter().zip(&semantics.result_digests) {
        accepted_set.extend_from_slice(&(case.selector.len() as u32).to_be_bytes());
        accepted_set.extend_from_slice(case.selector.as_bytes());
        accepted_set.extend_from_slice(digest.bytes());
    }
    let native_machine = if build.target == "x86_64-unknown-linux-gnu" {
        "x86_64"
    } else if build.target == "aarch64-unknown-linux-gnu" {
        "aarch64"
    } else {
        return Err(CiError::Message("C3 native machine differs".into()));
    };
    let accepted_sha256 = hash_bytes(&accepted_set);
    let payload = NativeQualificationCertificateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        key_id: intent.key_id.into(),
        release_sequence: intent.release_sequence,
        build_sha256: String::from(hash_bytes(build_bytes)),
        build_context_sha256: String::from(intent.build_context_sha256.clone()),
        target: build.target.into(),
        native_machine: native_machine.into(),
        source_commit: build.source_commit.into(),
        release_version: build.version.into(),
        qualification_sha256: String::from(hash_bytes(&qualification.bytes)),
        qualification_size: qualification.bytes.len() as u64,
        raw_index_sha256: String::from(completed.raw_index_sha256.clone()),
        completed_provenance_sha256: String::from(completed.provenance_sha256.clone()),
        repository_id: completed.repository_id,
        repository: intent.repository.into(),
        workflow_path: intent.workflow_path.into(),
        workflow_revision: intent.workflow_revision.into(),
        run_id: completed.run_id,
        run_attempt: completed.run_attempt,
        producer_job_id: completed.producer_job_id,
        artifact_id: completed.artifact_id,
        verifier_sha256: intent.verifier_sha256.into(),
        verifier_source_commit: intent.verifier_source_commit.into(),
        verifier_policy_sha256: policy.policy().verifier_policy_sha256.clone(),
        catalogue_sha256: policy.policy().catalogue_sha256.clone(),
        accepted_case_set_sha256: String::from(accepted_sha256.clone()),
        issued_at_unix: intent.issued_at_unix,
        expires_at_unix: intent.expires_at_unix,
        decision: "Complete".into(),
    };
    let canonical = payload.canonical_bytes().map_err(CiError::Message)?;
    let signed = SignedNativeQualificationCertificateV1 {
        payload,
        signature_hex: key_bytes_hex(&intent.signing_key.sign(&canonical).to_bytes()),
    };
    signed
        .verify(
            &policy,
            &ExpectedNativeQualificationV1 {
                repository_id: completed.repository_id,
                repository: intent.repository,
                workflow_path: intent.workflow_path,
                workflow_revision: intent.workflow_revision,
                target: build.target,
                native_machine,
                verifier_sha256: intent.verifier_sha256,
                source_commit: build.source_commit,
                release_version: build.version,
                build_sha256: &String::from(hash_bytes(build_bytes)),
                build_context_sha256: &String::from(intent.build_context_sha256.clone()),
                qualification_bytes: &qualification.bytes,
                raw_index_sha256: &String::from(completed.raw_index_sha256.clone()),
                completed_provenance_sha256: &String::from(completed.provenance_sha256.clone()),
                accepted_case_set_sha256: &String::from(accepted_sha256),
            },
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    Ok(serde_json::to_vec(&signed)?)
}

/// Independently provisioned release decision inputs. The caller must not
/// derive these values from C, Q, CQ, or the candidate runner's environment.
pub struct NativeCertificateSigningIntentV1<'a> {
    pub trust_anchor: &'a ReleaseTrustAnchorV1,
    pub signed_policy: &'a SignedReleaseTrustPolicyV1,
    pub high_water: &'a TrustHighWaterV1,
    pub signing_key: &'a SigningKey,
    pub key_id: &'a str,
    pub release_sequence: u64,
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub workflow_revision: &'a str,
    pub verifier_sha256: &'a str,
    pub verifier_source_commit: &'a str,
    pub build_context_sha256: &'a DiagnosticSha256,
    pub collector_intent_sha256: &'a DiagnosticSha256,
    pub release_catalogue_sha256: &'a DiagnosticSha256,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

/// Only a verified 25-case capability plus a separately authenticated,
/// completed producer can authorize signing. There is no sign-JSON or
/// sign-digest entry point. The key belongs on the trusted verifier host.
pub(crate) fn sign_native_qualification_certificate(
    run: &IndependentlyVerifiedCandidateRunV2,
    completed: &AuthenticatedCompletedProducerV2,
    build: &IndependentBuildIdentityV2<'_>,
    build_bytes: &[u8],
    qualification: &ProducedPrivateQualificationV2,
    intent: &NativeCertificateSigningIntentV1<'_>,
) -> Result<Vec<u8>> {
    let reproduced = produce_private_qualification_v2(run, build)?;
    let policy = intent
        .signed_policy
        .verify(
            intent.trust_anchor,
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    let key = policy
        .policy()
        .delegated_keys
        .iter()
        .find(|key| key.key_id == intent.key_id)
        .ok_or_else(|| CiError::Message("native Q signing key is not delegated".into()))?;
    let signing_public_hex = key_bytes_hex(intent.signing_key.verifying_key().as_bytes());
    if reproduced.bytes != qualification.bytes
        || reproduced.reference != qualification.reference
        || completed.artifact.envelope != run.envelope
        || completed.artifact.producer.stage != NativeRunStageV2::CandidateCapability
        || completed.artifact.producer.target != build.target
        || completed.run_id.to_string() != run.envelope.workflow_run_id
        || completed.run_attempt != run.envelope.workflow_attempt
        || completed.repository_id != policy.policy().repository_id
        || intent.repository != policy.policy().repository
        || intent.workflow_path != policy.policy().workflow_path
        || intent.workflow_revision != policy.policy().workflow_revision
        || intent.verifier_sha256 != policy.policy().verifier_sha256
        || *intent.build_context_sha256 != run.envelope.build_context_sha256
        || *intent.collector_intent_sha256 == hash_bytes(&[])
        || *intent.release_catalogue_sha256 != run.envelope.release_catalogue_sha256
        || String::from(run.envelope.release_catalogue_sha256.clone())
            != policy.policy().catalogue_sha256
        || !key.roles.contains(&ReleaseSigningRoleV1::NativeQ)
        || key.public_key_hex != signing_public_hex
        || intent.issued_at_unix < key.not_before_unix
        || intent.expires_at_unix > key.expires_at_unix
        || intent.release_sequence < policy.policy().minimum_release_sequence
        || intent.release_sequence < intent.high_water.release_sequence
        || intent.issued_at_unix >= intent.expires_at_unix
        || build_bytes.len() > 16 * 1024
    {
        return Err(CiError::Message(
            "native Q signing authority differs".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(build_bytes)
        .map_err(CiError::Message)?;
    let submitted_build: PrivateCandidateRecordV2 = serde_json::from_slice(build_bytes)?;
    if submitted_build.schema_version != 2
        || submitted_build.version != build.version
        || submitted_build.source_commit != build.source_commit
        || submitted_build.target != build.target
        || submitted_build.component_sha256 != *build.component_sha256
        || submitted_build.unit_sha256 != *build.unit_sha256
        || submitted_build.filter_sha256 != *build.filter_sha256
    {
        return Err(CiError::Message("native Q signing B differs".into()));
    }
    let mut accepted_set = b"memcordon/private-accepted-case-set/v1\0".to_vec();
    for (case, digest) in run.envelope.cases.iter().zip(&run.completion_digests) {
        accepted_set.extend_from_slice(&(case.name.len() as u32).to_be_bytes());
        accepted_set.extend_from_slice(case.name.as_bytes());
        accepted_set.extend_from_slice(digest.bytes());
    }
    let payload = NativeQualificationCertificateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        key_id: intent.key_id.into(),
        release_sequence: intent.release_sequence,
        build_sha256: String::from(hash_bytes(build_bytes)),
        build_context_sha256: String::from(run.envelope.build_context_sha256.clone()),
        target: build.target.into(),
        native_machine: run.envelope.native_machine.clone(),
        source_commit: build.source_commit.into(),
        release_version: build.version.into(),
        qualification_sha256: String::from(hash_bytes(&qualification.bytes)),
        qualification_size: qualification.bytes.len() as u64,
        raw_index_sha256: String::from(run.raw_index_sha256.clone()),
        completed_provenance_sha256: String::from(completed.provenance_sha256.clone()),
        repository_id: completed.repository_id,
        repository: intent.repository.into(),
        workflow_path: intent.workflow_path.into(),
        workflow_revision: intent.workflow_revision.into(),
        run_id: completed.run_id,
        run_attempt: completed.run_attempt,
        producer_job_id: completed.producer_job_id,
        artifact_id: completed.artifact_id,
        verifier_sha256: intent.verifier_sha256.into(),
        verifier_source_commit: intent.verifier_source_commit.into(),
        verifier_policy_sha256: policy.policy().verifier_policy_sha256.clone(),
        catalogue_sha256: String::from(run.envelope.release_catalogue_sha256.clone()),
        accepted_case_set_sha256: String::from(hash_bytes(&accepted_set)),
        issued_at_unix: intent.issued_at_unix,
        expires_at_unix: intent.expires_at_unix,
        decision: "Complete".into(),
    };
    let canonical = payload.canonical_bytes().map_err(CiError::Message)?;
    let signed = SignedNativeQualificationCertificateV1 {
        payload,
        signature_hex: key_bytes_hex(&intent.signing_key.sign(&canonical).to_bytes()),
    };
    signed
        .verify(
            &policy,
            &ExpectedNativeQualificationV1 {
                repository_id: completed.repository_id,
                repository: intent.repository,
                workflow_path: intent.workflow_path,
                workflow_revision: intent.workflow_revision,
                target: build.target,
                native_machine: &run.envelope.native_machine,
                verifier_sha256: intent.verifier_sha256,
                source_commit: build.source_commit,
                release_version: build.version,
                build_sha256: &String::from(hash_bytes(build_bytes)),
                build_context_sha256: &String::from(intent.build_context_sha256.clone()),
                qualification_bytes: &qualification.bytes,
                raw_index_sha256: &String::from(run.raw_index_sha256.clone()),
                completed_provenance_sha256: &String::from(completed.provenance_sha256.clone()),
                accepted_case_set_sha256: &String::from(hash_bytes(&accepted_set)),
            },
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    Ok(serde_json::to_vec(&signed)?)
}

fn key_bytes_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
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
    let public = &final_public.public_index;
    if public.source_commit != expected.source_commit
        || public.release_version != expected.version
        || public.target != expected.target
        || public.qualification_sha256 != hash_bytes(&qualification.bytes)
        || public.archive_sha256 != *expected.archive_sha256
        || public.manifest_sha256 != *expected.runtime_manifest_sha256
        || public.host_receipt_sha256 != *expected.installed_receipt_sha256
        || final_public.public_index_sha256.bytes() == &[0; 32]
    {
        return Err(CiError::Message(
            "final public qualification differs from candidate Q/build".into(),
        ));
    }
    Ok(())
}
