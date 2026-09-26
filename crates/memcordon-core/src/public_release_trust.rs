//! Signed final-public P decision, outside the immutable release archive A.
//!
//! The trusted verifier signs this only after a completed P producer and
//! independent 25-case public semantics. Parsing is never authentication.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::release_trust::{ReleaseSigningRoleV1, TrustHighWaterV1, VerifiedReleaseTrustPolicyV1};
use crate::workload_codec::hash_bytes;

const DOMAIN: &[u8] = b"memcordon/public-qualification/v1\0";
const MAX_DOCUMENT: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicQualificationCertificateV1 {
    pub schema_version: u8,
    pub policy_version: u64,
    pub key_id: String,
    pub release_sequence: u64,
    pub build_sha256: String,
    pub qualification_sha256: String,
    pub qualification_certificate_sha256: String,
    pub archive_sha256: String,
    pub manifest_sha256: String,
    pub host_receipt_sha256: String,
    pub public_evidence_sha256: String,
    pub public_evidence_size: u64,
    pub raw_index_sha256: String,
    pub completed_provenance_sha256: String,
    pub target: String,
    pub native_machine: String,
    pub source_commit: String,
    pub release_version: String,
    pub repository_id: u64,
    pub repository: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub run_id: u64,
    pub run_attempt: u32,
    pub producer_job_id: u64,
    pub artifact_id: u64,
    pub verifier_sha256: String,
    pub verifier_source_commit: String,
    pub verifier_policy_sha256: String,
    pub catalogue_sha256: String,
    pub accepted_case_set_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub decision: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPublicQualificationCertificateV1 {
    pub payload: PublicQualificationCertificateV1,
    pub signature_hex: String,
}

pub struct ExpectedPublicQualificationV1<'a> {
    pub release_sequence: u64,
    pub repository_id: u64,
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub workflow_revision: &'a str,
    pub run_id: u64,
    pub run_attempt: u32,
    pub producer_job_id: u64,
    pub artifact_id: u64,
    pub target: &'a str,
    pub native_machine: &'a str,
    pub source_commit: &'a str,
    pub release_version: &'a str,
    pub verifier_sha256: &'a str,
    pub verifier_source_commit: &'a str,
    pub build_sha256: &'a str,
    pub qualification_sha256: &'a str,
    pub qualification_certificate_sha256: &'a str,
    pub archive_sha256: &'a str,
    pub manifest_sha256: &'a str,
    pub host_receipt_sha256: &'a str,
    pub public_evidence_bytes: &'a [u8],
    pub raw_index_sha256: &'a str,
    pub completed_provenance_sha256: &'a str,
    pub accepted_case_set_sha256: &'a str,
}

pub struct VerifiedPublicQualificationV1 {
    certificate_sha256: String,
    release_sequence: u64,
}

impl VerifiedPublicQualificationV1 {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }

    pub fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
}

fn text_field(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') {
        return Err("public certificate text field differs".into());
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn hex_digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("public certificate digest syntax differs".into());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("public certificate signature syntax differs".into());
    }
    let mut bytes = [0_u8; N];
    for (index, slot) in bytes.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "public certificate signature syntax differs")?;
    }
    Ok(bytes)
}

impl PublicQualificationCertificateV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.release_sequence == 0
            || self.public_evidence_size == 0
            || self.repository_id == 0
            || self.run_id == 0
            || self.run_attempt == 0
            || self.producer_job_id == 0
            || self.artifact_id == 0
            || self.issued_at_unix >= self.expires_at_unix
            || self.decision != "Complete"
        {
            return Err("public certificate identity differs".into());
        }
        for digest in [
            &self.build_sha256,
            &self.qualification_sha256,
            &self.qualification_certificate_sha256,
            &self.archive_sha256,
            &self.manifest_sha256,
            &self.host_receipt_sha256,
            &self.public_evidence_sha256,
            &self.raw_index_sha256,
            &self.completed_provenance_sha256,
            &self.verifier_sha256,
            &self.verifier_policy_sha256,
            &self.catalogue_sha256,
            &self.accepted_case_set_sha256,
        ] {
            hex_digest(digest)?;
        }
        let mut out = DOMAIN.to_vec();
        out.push(self.schema_version);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        text_field(&mut out, &self.key_id)?;
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        for value in [
            &self.build_sha256,
            &self.qualification_sha256,
            &self.qualification_certificate_sha256,
            &self.archive_sha256,
            &self.manifest_sha256,
            &self.host_receipt_sha256,
            &self.public_evidence_sha256,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.public_evidence_size.to_be_bytes());
        for value in [
            &self.raw_index_sha256,
            &self.completed_provenance_sha256,
            &self.target,
            &self.native_machine,
            &self.source_commit,
            &self.release_version,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.repository_id.to_be_bytes());
        for value in [
            &self.repository,
            &self.workflow_path,
            &self.workflow_revision,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.run_id.to_be_bytes());
        out.extend_from_slice(&self.run_attempt.to_be_bytes());
        out.extend_from_slice(&self.producer_job_id.to_be_bytes());
        out.extend_from_slice(&self.artifact_id.to_be_bytes());
        for value in [
            &self.verifier_sha256,
            &self.verifier_source_commit,
            &self.verifier_policy_sha256,
            &self.catalogue_sha256,
            &self.accepted_case_set_sha256,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        text_field(&mut out, &self.decision)?;
        Ok(out)
    }
}

fn validate_public_certificate_subject(
    payload: &PublicQualificationCertificateV1,
    policy: &VerifiedReleaseTrustPolicyV1,
    expected: &ExpectedPublicQualificationV1<'_>,
    high_water: &TrustHighWaterV1,
    now_unix: u64,
) -> Result<VerifyingKey, String> {
    payload.canonical_bytes()?;
    let trust = policy.policy();
    if payload.policy_version != trust.policy_version
        || payload.release_sequence != expected.release_sequence
        || payload.release_sequence < trust.minimum_release_sequence
        || payload.release_sequence < high_water.release_sequence
        || now_unix < high_water.last_accepted_wall_unix
        || now_unix < payload.issued_at_unix
        || now_unix >= payload.expires_at_unix
        || now_unix >= trust.expires_at_unix
        || payload.repository_id != trust.repository_id
        || payload.repository_id != expected.repository_id
        || payload.repository != trust.repository
        || payload.repository != expected.repository
        || payload.workflow_path != trust.workflow_path
        || payload.workflow_path != expected.workflow_path
        || payload.workflow_revision != trust.workflow_revision
        || payload.workflow_revision != expected.workflow_revision
        || payload.run_id != expected.run_id
        || payload.run_attempt != expected.run_attempt
        || payload.producer_job_id != expected.producer_job_id
        || payload.artifact_id != expected.artifact_id
        || payload.verifier_sha256 != trust.verifier_sha256
        || payload.verifier_sha256 != expected.verifier_sha256
        || payload.verifier_source_commit != expected.verifier_source_commit
        || payload.verifier_policy_sha256 != trust.verifier_policy_sha256
        || payload.catalogue_sha256 != trust.catalogue_sha256
        || payload.target != expected.target
        || payload.native_machine != expected.native_machine
        || payload.source_commit != expected.source_commit
        || payload.release_version != expected.release_version
        || payload.build_sha256 != expected.build_sha256
        || payload.qualification_sha256 != expected.qualification_sha256
        || payload.qualification_certificate_sha256 != expected.qualification_certificate_sha256
        || payload.archive_sha256 != expected.archive_sha256
        || payload.manifest_sha256 != expected.manifest_sha256
        || payload.host_receipt_sha256 != expected.host_receipt_sha256
        || payload.public_evidence_sha256
            != String::from(hash_bytes(expected.public_evidence_bytes))
        || payload.public_evidence_size != expected.public_evidence_bytes.len() as u64
        || payload.raw_index_sha256 != expected.raw_index_sha256
        || payload.completed_provenance_sha256 != expected.completed_provenance_sha256
        || payload.accepted_case_set_sha256 != expected.accepted_case_set_sha256
        || trust.revoked_key_ids.binary_search(&payload.key_id).is_ok()
        || trust
            .revoked_build_sha256
            .binary_search(&payload.build_sha256)
            .is_ok()
        || trust
            .revoked_qualification_sha256
            .binary_search(&payload.qualification_sha256)
            .is_ok()
    {
        return Err("public certificate subject or policy differs".into());
    }
    let key = trust
        .delegated_keys
        .iter()
        .find(|key| key.key_id == payload.key_id)
        .ok_or("public certificate key is not delegated")?;
    if !key.roles.contains(&ReleaseSigningRoleV1::PublicP)
        || payload.issued_at_unix < key.not_before_unix
        || payload.expires_at_unix > key.expires_at_unix
    {
        return Err("public certificate key role or validity differs".into());
    }
    let verifying = VerifyingKey::from_bytes(&decode_fixed::<32>(&key.public_key_hex)?)
        .map_err(|_| "public certificate key differs")?;
    Ok(verifying)
}

/// CP V2 keeps the existing PublicP subject/role contract and separately binds
/// physical payload, origin custody and the producer's installed timeline.
/// The inner V1 schema is an explicitly versioned subject, not a V1 signature.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicQualificationCertificateV2 {
    pub schema_version: u8,
    pub subject: PublicQualificationCertificateV1,
    pub payload_index_sha256: String,
    pub origin_commitment_sha256: String,
    pub custody_receipt_sha256: String,
    pub generation_timeline_sha256: String,
    pub qualification_certificate_file_sha256: String,
    pub semantics_sha256: String,
}

impl PublicQualificationCertificateV2 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 2 {
            return Err("public V2 certificate schema differs".into());
        }
        let subject = self.subject.canonical_bytes()?;
        let mut out = b"memcordon/public-qualification/v2\0".to_vec();
        out.extend_from_slice(&(subject.len() as u64).to_be_bytes());
        out.extend_from_slice(&subject);
        for digest in [
            &self.payload_index_sha256,
            &self.origin_commitment_sha256,
            &self.custody_receipt_sha256,
            &self.generation_timeline_sha256,
            &self.qualification_certificate_file_sha256,
            &self.semantics_sha256,
        ] {
            hex_digest(digest)?;
            if digest.bytes().all(|byte| byte == b'0') {
                return Err("public V2 certificate has an empty origin digest".into());
            }
            out.extend_from_slice(&decode_fixed::<32>(digest)?);
        }
        Ok(out)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPublicQualificationCertificateV2 {
    pub payload: PublicQualificationCertificateV2,
    pub signature_hex: String,
}

pub struct ExpectedPublicQualificationV2<'a> {
    pub subject: ExpectedPublicQualificationV1<'a>,
    pub payload_index_sha256: &'a str,
    pub origin_commitment_sha256: &'a str,
    pub custody_receipt_sha256: &'a str,
    pub generation_timeline_sha256: &'a str,
    pub qualification_certificate_file_sha256: &'a str,
    pub semantics_sha256: &'a str,
}

pub struct VerifiedPublicQualificationV2 {
    certificate_sha256: String,
    release_sequence: u64,
    payload_index_sha256: String,
    origin_commitment_sha256: String,
}

impl VerifiedPublicQualificationV2 {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
    pub fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
    pub fn payload_index_sha256(&self) -> &str {
        &self.payload_index_sha256
    }
    pub fn origin_commitment_sha256(&self) -> &str {
        &self.origin_commitment_sha256
    }
}

impl SignedPublicQualificationCertificateV2 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("public V2 certificate byte bound differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        policy: &VerifiedReleaseTrustPolicyV1,
        expected: &ExpectedPublicQualificationV2<'_>,
        high_water: &TrustHighWaterV1,
        now_unix: u64,
    ) -> Result<VerifiedPublicQualificationV2, String> {
        let payload = &self.payload;
        let canonical = payload.canonical_bytes()?;
        if payload.payload_index_sha256 != expected.payload_index_sha256
            || payload.origin_commitment_sha256 != expected.origin_commitment_sha256
            || payload.custody_receipt_sha256 != expected.custody_receipt_sha256
            || payload.generation_timeline_sha256 != expected.generation_timeline_sha256
            || payload.qualification_certificate_file_sha256
                != expected.qualification_certificate_file_sha256
            || payload.semantics_sha256 != expected.semantics_sha256
        {
            return Err("public V2 certificate physical provenance differs".into());
        }
        let verifying = validate_public_certificate_subject(
            &payload.subject,
            policy,
            &expected.subject,
            high_water,
            now_unix,
        )?;
        let signature = Signature::from_bytes(&decode_fixed::<64>(&self.signature_hex)?);
        verifying
            .verify_strict(&canonical, &signature)
            .map_err(|_| "public V2 certificate signature differs")?;
        let certificate_sha256 = String::from(hash_bytes(&canonical));
        if policy
            .policy()
            .revoked_certificate_sha256
            .binary_search(&certificate_sha256)
            .is_ok()
        {
            return Err("public V2 certificate is revoked".into());
        }
        Ok(VerifiedPublicQualificationV2 {
            certificate_sha256,
            release_sequence: payload.subject.release_sequence,
            payload_index_sha256: payload.payload_index_sha256.clone(),
            origin_commitment_sha256: payload.origin_commitment_sha256.clone(),
        })
    }
}

impl SignedPublicQualificationCertificateV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("public certificate byte bound differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        policy: &VerifiedReleaseTrustPolicyV1,
        expected: &ExpectedPublicQualificationV1<'_>,
        high_water: &TrustHighWaterV1,
        now_unix: u64,
    ) -> Result<VerifiedPublicQualificationV1, String> {
        let payload = &self.payload;
        let canonical = payload.canonical_bytes()?;
        let verifying =
            validate_public_certificate_subject(payload, policy, expected, high_water, now_unix)?;
        let trust = policy.policy();
        let signature = Signature::from_bytes(&decode_fixed::<64>(&self.signature_hex)?);
        verifying
            .verify_strict(&canonical, &signature)
            .map_err(|_| "public certificate signature differs")?;
        let certificate_sha256 = String::from(hash_bytes(&canonical));
        if trust
            .revoked_certificate_sha256
            .binary_search(&certificate_sha256)
            .is_ok()
        {
            return Err("public certificate is revoked".into());
        }
        Ok(VerifiedPublicQualificationV1 {
            certificate_sha256,
            release_sequence: payload.release_sequence,
        })
    }
}
