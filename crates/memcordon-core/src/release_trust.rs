//! Independently anchored release verifier certificates.
//!
//! JSON is a transport encoding. Signatures cover the explicit, length-prefixed
//! binary encoding below; an artifact cannot supply its own trust anchor.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::workload_codec::hash_bytes;

const MAX_DOCUMENT: usize = 64 * 1024;
const MAX_TEXT: usize = 512;
const POLICY_DOMAIN: &[u8] = b"memcordon/release-trust-policy/v1\0";
const Q_DOMAIN: &[u8] = b"memcordon/native-qualification/v1\0";
const ROLLBACK_DOMAIN: &[u8] = b"memcordon/release-rollback-exception/v1\0";
const ROOT_ROTATION_DOMAIN: &[u8] = b"memcordon/release-root-rotation/v1\0";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub enum ReleaseSigningRoleV1 {
    NativeQ,
    PublicP,
    ReleaseIndex,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedReleaseKeyV1 {
    pub key_id: String,
    pub public_key_hex: String,
    pub roles: Vec<ReleaseSigningRoleV1>,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTrustPolicyV1 {
    pub schema_version: u8,
    pub policy_version: u64,
    pub root_key_id: String,
    pub repository_id: u64,
    pub repository: String,
    pub workflow_path: String,
    pub workflow_revision: String,
    pub verifier_sha256: String,
    pub verifier_policy_sha256: String,
    pub catalogue_sha256: String,
    pub minimum_release_sequence: u64,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub delegated_keys: Vec<DelegatedReleaseKeyV1>,
    pub revoked_key_ids: Vec<String>,
    pub revoked_certificate_sha256: Vec<String>,
    pub revoked_qualification_sha256: Vec<String>,
    pub revoked_build_sha256: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseTrustPolicyV1 {
    pub payload: ReleaseTrustPolicyV1,
    pub signature_hex: String,
}

/// This key is supplied by administrator-controlled installation state, never
/// by the downloaded release bundle.
#[derive(Clone, Debug)]
pub struct ReleaseTrustAnchorV1 {
    pub root_key_id: String,
    pub public_key_hex: String,
}

#[derive(Clone, Debug)]
pub struct TrustHighWaterV1 {
    pub policy_version: u64,
    pub release_sequence: u64,
    pub last_accepted_wall_unix: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedReleaseTrustPolicyV1 {
    policy: ReleaseTrustPolicyV1,
    digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRollbackExceptionV1 {
    pub schema_version: u8,
    pub root_key_id: String,
    pub policy_version: u64,
    pub build_sha256: String,
    pub qualification_sha256: String,
    pub allowed_release_sequence: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseRollbackExceptionV1 {
    pub payload: ReleaseRollbackExceptionV1,
    pub signature_hex: String,
}

pub struct VerifiedReleaseRollbackExceptionV1 {
    build_sha256: String,
    qualification_sha256: String,
    allowed_release_sequence: u64,
    policy_version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRootRotationV1 {
    pub schema_version: u8,
    pub previous_root_key_id: String,
    pub previous_root_public_key_hex: String,
    pub next_root_key_id: String,
    pub next_root_public_key_hex: String,
    pub minimum_next_policy_version: u64,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedReleaseRootRotationV1 {
    pub payload: ReleaseRootRotationV1,
    pub previous_root_signature_hex: String,
    pub next_root_signature_hex: String,
}

pub struct VerifiedReleaseRootRotationV1 {
    minimum_next_policy_version: u64,
}

impl VerifiedReleaseRootRotationV1 {
    pub fn minimum_next_policy_version(&self) -> u64 {
        self.minimum_next_policy_version
    }
}

impl ReleaseRootRotationV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.previous_root_key_id == self.next_root_key_id
            || self.previous_root_public_key_hex == self.next_root_public_key_hex
            || self.minimum_next_policy_version == 0
            || self.issued_at_unix >= self.expires_at_unix
        {
            return Err("release root rotation identity differs".into());
        }
        decode_fixed::<32>(&self.previous_root_public_key_hex)?;
        decode_fixed::<32>(&self.next_root_public_key_hex)?;
        let mut out = ROOT_ROTATION_DOMAIN.to_vec();
        out.push(self.schema_version);
        for value in [
            &self.previous_root_key_id,
            &self.previous_root_public_key_hex,
            &self.next_root_key_id,
            &self.next_root_public_key_hex,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.minimum_next_policy_version.to_be_bytes());
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        Ok(out)
    }
}

impl SignedReleaseRootRotationV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("release root rotation size differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        previous: &ReleaseTrustAnchorV1,
        next: &ReleaseTrustAnchorV1,
        last_policy_version: u64,
        now_unix: u64,
    ) -> Result<VerifiedReleaseRootRotationV1, String> {
        let payload = &self.payload;
        let bytes = payload.canonical_bytes()?;
        if payload.previous_root_key_id != previous.root_key_id
            || payload.previous_root_public_key_hex != previous.public_key_hex
            || payload.next_root_key_id != next.root_key_id
            || payload.next_root_public_key_hex != next.public_key_hex
            || payload.minimum_next_policy_version <= last_policy_version
            || now_unix < payload.issued_at_unix
            || now_unix >= payload.expires_at_unix
        {
            return Err("release root rotation anchors or version differ".into());
        }
        verify_signature(
            &previous.public_key_hex,
            &self.previous_root_signature_hex,
            &bytes,
        )?;
        verify_signature(&next.public_key_hex, &self.next_root_signature_hex, &bytes)?;
        Ok(VerifiedReleaseRootRotationV1 {
            minimum_next_policy_version: payload.minimum_next_policy_version,
        })
    }
}

impl ReleaseRollbackExceptionV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.allowed_release_sequence == 0
            || self.issued_at_unix >= self.expires_at_unix
        {
            return Err("release rollback exception identity differs".into());
        }
        hex_digest(&self.build_sha256)?;
        hex_digest(&self.qualification_sha256)?;
        let mut out = ROLLBACK_DOMAIN.to_vec();
        out.push(self.schema_version);
        text_field(&mut out, &self.root_key_id)?;
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        text_field(&mut out, &self.build_sha256)?;
        text_field(&mut out, &self.qualification_sha256)?;
        out.extend_from_slice(&self.allowed_release_sequence.to_be_bytes());
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        Ok(out)
    }
}

impl SignedReleaseRollbackExceptionV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("release rollback exception size differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        anchor: &ReleaseTrustAnchorV1,
        policy: &VerifiedReleaseTrustPolicyV1,
        now_unix: u64,
    ) -> Result<VerifiedReleaseRollbackExceptionV1, String> {
        let payload = &self.payload;
        let bytes = payload.canonical_bytes()?;
        if payload.root_key_id != anchor.root_key_id
            || payload.policy_version != policy.policy.policy_version
            || now_unix < payload.issued_at_unix
            || now_unix >= payload.expires_at_unix
            || now_unix >= policy.policy.expires_at_unix
            || policy
                .policy
                .revoked_build_sha256
                .binary_search(&payload.build_sha256)
                .is_ok()
            || policy
                .policy
                .revoked_qualification_sha256
                .binary_search(&payload.qualification_sha256)
                .is_ok()
        {
            return Err("release rollback exception is stale or revoked".into());
        }
        verify_signature(&anchor.public_key_hex, &self.signature_hex, &bytes)?;
        Ok(VerifiedReleaseRollbackExceptionV1 {
            build_sha256: payload.build_sha256.clone(),
            qualification_sha256: payload.qualification_sha256.clone(),
            allowed_release_sequence: payload.allowed_release_sequence,
            policy_version: payload.policy_version,
        })
    }
}

impl VerifiedReleaseTrustPolicyV1 {
    pub fn policy(&self) -> &ReleaseTrustPolicyV1 {
        &self.policy
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeQualificationCertificateV1 {
    pub schema_version: u8,
    pub policy_version: u64,
    pub key_id: String,
    pub release_sequence: u64,
    pub build_sha256: String,
    pub build_context_sha256: String,
    pub target: String,
    pub native_machine: String,
    pub source_commit: String,
    pub release_version: String,
    pub qualification_sha256: String,
    pub qualification_size: u64,
    pub raw_index_sha256: String,
    pub completed_provenance_sha256: String,
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
pub struct SignedNativeQualificationCertificateV1 {
    pub payload: NativeQualificationCertificateV1,
    pub signature_hex: String,
}

/// Independent release intent and exact local bytes. Do not populate these
/// fields from the certificate being checked.
pub struct ExpectedNativeQualificationV1<'a> {
    pub repository_id: u64,
    pub repository: &'a str,
    pub workflow_path: &'a str,
    pub workflow_revision: &'a str,
    pub target: &'a str,
    pub native_machine: &'a str,
    pub verifier_sha256: &'a str,
    pub source_commit: &'a str,
    pub release_version: &'a str,
    pub build_sha256: &'a str,
    pub build_context_sha256: &'a str,
    pub qualification_bytes: &'a [u8],
    pub raw_index_sha256: &'a str,
    pub completed_provenance_sha256: &'a str,
    pub accepted_case_set_sha256: &'a str,
}

#[derive(Clone, Debug)]
pub struct VerifiedNativeQualificationV1 {
    certificate_sha256: String,
    policy_sha256: String,
    release_sequence: u64,
}

impl VerifiedNativeQualificationV1 {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }

    pub fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
}

fn text_field(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > MAX_TEXT || value.contains('\0') {
        return Err("release certificate text field is invalid".into());
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
        return Err("release certificate digest syntax differs".into());
    }
    Ok(())
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("release signature or key syntax differs".into());
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16);
            let low = (pair[1] as char).to_digit(16);
            high.zip(low).map(|(high, low)| ((high << 4) | low) as u8)
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("release signature or key syntax differs")?;
    bytes
        .try_into()
        .map_err(|_| "release signature or key length differs".into())
}

fn check_sorted_unique(values: &[String]) -> Result<(), String> {
    if values.len() > 256 || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("release trust policy set ordering differs".into());
    }
    for value in values {
        text_field(&mut Vec::new(), value)?;
    }
    Ok(())
}

fn append_set(out: &mut Vec<u8>, values: &[String]) -> Result<(), String> {
    check_sorted_unique(values)?;
    out.extend_from_slice(&(values.len() as u32).to_be_bytes());
    for value in values {
        text_field(out, value)?;
    }
    Ok(())
}

impl ReleaseTrustPolicyV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.repository_id == 0
            || self.minimum_release_sequence == 0
            || self.not_before_unix >= self.expires_at_unix
            || self.delegated_keys.is_empty()
            || self.delegated_keys.len() > 32
        {
            return Err("release trust policy identity differs".into());
        }
        hex_digest(&self.verifier_sha256)?;
        hex_digest(&self.verifier_policy_sha256)?;
        hex_digest(&self.catalogue_sha256)?;
        let mut out = POLICY_DOMAIN.to_vec();
        out.push(self.schema_version);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        text_field(&mut out, &self.root_key_id)?;
        out.extend_from_slice(&self.repository_id.to_be_bytes());
        for value in [
            &self.repository,
            &self.workflow_path,
            &self.workflow_revision,
            &self.verifier_sha256,
            &self.verifier_policy_sha256,
            &self.catalogue_sha256,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.minimum_release_sequence.to_be_bytes());
        out.extend_from_slice(&self.not_before_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        out.extend_from_slice(&(self.delegated_keys.len() as u32).to_be_bytes());
        let mut previous = "";
        for key in &self.delegated_keys {
            if key.key_id.as_str() <= previous
                || key.roles.is_empty()
                || key.roles.len() > 3
                || key.not_before_unix >= key.expires_at_unix
            {
                return Err("release trust delegated key ordering differs".into());
            }
            previous = &key.key_id;
            decode_fixed::<32>(&key.public_key_hex)?;
            text_field(&mut out, &key.key_id)?;
            text_field(&mut out, &key.public_key_hex)?;
            out.push(key.roles.len() as u8);
            let mut last = 0;
            for role in &key.roles {
                let ordinal = match role {
                    ReleaseSigningRoleV1::NativeQ => 1,
                    ReleaseSigningRoleV1::PublicP => 2,
                    ReleaseSigningRoleV1::ReleaseIndex => 3,
                };
                if ordinal <= last {
                    return Err("release trust key roles are not ordered".into());
                }
                out.push(ordinal);
                last = ordinal;
            }
            out.extend_from_slice(&key.not_before_unix.to_be_bytes());
            out.extend_from_slice(&key.expires_at_unix.to_be_bytes());
        }
        for set in [
            &self.revoked_key_ids,
            &self.revoked_certificate_sha256,
            &self.revoked_qualification_sha256,
            &self.revoked_build_sha256,
        ] {
            append_set(&mut out, set)?;
        }
        for digest in self
            .revoked_certificate_sha256
            .iter()
            .chain(&self.revoked_qualification_sha256)
            .chain(&self.revoked_build_sha256)
        {
            hex_digest(digest)?;
        }
        Ok(out)
    }
}

impl SignedReleaseTrustPolicyV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("release trust policy size differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        anchor: &ReleaseTrustAnchorV1,
        high_water: &TrustHighWaterV1,
        now_unix: u64,
    ) -> Result<VerifiedReleaseTrustPolicyV1, String> {
        let bytes = self.payload.canonical_bytes()?;
        if self.payload.root_key_id != anchor.root_key_id
            || self.payload.policy_version < high_water.policy_version
            || now_unix < high_water.last_accepted_wall_unix
            || now_unix < self.payload.not_before_unix
            || now_unix >= self.payload.expires_at_unix
        {
            return Err("release trust policy is stale or has wrong root".into());
        }
        verify_signature(&anchor.public_key_hex, &self.signature_hex, &bytes)?;
        Ok(VerifiedReleaseTrustPolicyV1 {
            policy: self.payload.clone(),
            digest: String::from(hash_bytes(&bytes)),
        })
    }
}

impl NativeQualificationCertificateV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.release_sequence == 0
            || self.qualification_size == 0
            || self.repository_id == 0
            || self.run_id == 0
            || self.run_attempt == 0
            || self.producer_job_id == 0
            || self.artifact_id == 0
            || self.issued_at_unix >= self.expires_at_unix
            || self.decision != "Complete"
        {
            return Err("native qualification certificate identity differs".into());
        }
        let mut out = Q_DOMAIN.to_vec();
        out.push(self.schema_version);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        text_field(&mut out, &self.key_id)?;
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        for value in [
            &self.build_sha256,
            &self.build_context_sha256,
            &self.target,
            &self.native_machine,
            &self.source_commit,
            &self.release_version,
            &self.qualification_sha256,
        ] {
            text_field(&mut out, value)?;
        }
        out.extend_from_slice(&self.qualification_size.to_be_bytes());
        for value in [&self.raw_index_sha256, &self.completed_provenance_sha256] {
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
        for digest in [
            &self.build_sha256,
            &self.build_context_sha256,
            &self.qualification_sha256,
            &self.raw_index_sha256,
            &self.completed_provenance_sha256,
            &self.verifier_sha256,
            &self.verifier_policy_sha256,
            &self.catalogue_sha256,
            &self.accepted_case_set_sha256,
        ] {
            hex_digest(digest)?;
        }
        Ok(out)
    }
}

impl SignedNativeQualificationCertificateV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
            return Err("native qualification certificate size differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        policy: &VerifiedReleaseTrustPolicyV1,
        expected: &ExpectedNativeQualificationV1<'_>,
        high_water: &TrustHighWaterV1,
        now_unix: u64,
    ) -> Result<VerifiedNativeQualificationV1, String> {
        self.verify_with_rollback(policy, expected, high_water, None, now_unix)
    }

    pub fn verify_with_rollback(
        &self,
        policy: &VerifiedReleaseTrustPolicyV1,
        expected: &ExpectedNativeQualificationV1<'_>,
        high_water: &TrustHighWaterV1,
        rollback: Option<&VerifiedReleaseRollbackExceptionV1>,
        now_unix: u64,
    ) -> Result<VerifiedNativeQualificationV1, String> {
        let p = &self.payload;
        let bytes = p.canonical_bytes()?;
        let certificate_sha256 = String::from(hash_bytes(&bytes));
        let trusted = policy.policy();
        if p.policy_version != trusted.policy_version
            || p.release_sequence < trusted.minimum_release_sequence
            || (p.release_sequence < high_water.release_sequence
                && !rollback.is_some_and(|exception| {
                    exception.policy_version == trusted.policy_version
                        && exception.allowed_release_sequence == p.release_sequence
                        && exception.build_sha256 == p.build_sha256
                        && exception.qualification_sha256 == p.qualification_sha256
                }))
            || now_unix < high_water.last_accepted_wall_unix
            || now_unix < p.issued_at_unix
            || now_unix >= p.expires_at_unix
            || p.issued_at_unix < trusted.not_before_unix
            || p.repository_id != expected.repository_id
            || p.repository_id != trusted.repository_id
            || p.repository != expected.repository
            || p.repository != trusted.repository
            || p.workflow_path != expected.workflow_path
            || p.workflow_path != trusted.workflow_path
            || p.workflow_revision != expected.workflow_revision
            || p.workflow_revision != trusted.workflow_revision
            || p.target != expected.target
            || p.native_machine != expected.native_machine
            || p.verifier_sha256 != expected.verifier_sha256
            || p.source_commit != expected.source_commit
            || p.release_version != expected.release_version
            || p.build_sha256 != expected.build_sha256
            || p.build_context_sha256 != expected.build_context_sha256
            || p.qualification_sha256 != String::from(hash_bytes(expected.qualification_bytes))
            || p.qualification_size != expected.qualification_bytes.len() as u64
            || p.raw_index_sha256 != expected.raw_index_sha256
            || p.completed_provenance_sha256 != expected.completed_provenance_sha256
            || p.accepted_case_set_sha256 != expected.accepted_case_set_sha256
            || p.verifier_policy_sha256 != trusted.verifier_policy_sha256
            || p.verifier_sha256 != trusted.verifier_sha256
            || p.catalogue_sha256 != trusted.catalogue_sha256
            || trusted.revoked_key_ids.binary_search(&p.key_id).is_ok()
            || trusted
                .revoked_certificate_sha256
                .binary_search(&certificate_sha256)
                .is_ok()
            || trusted
                .revoked_qualification_sha256
                .binary_search(&p.qualification_sha256)
                .is_ok()
            || trusted
                .revoked_build_sha256
                .binary_search(&p.build_sha256)
                .is_ok()
        {
            return Err("native qualification certificate subject or freshness differs".into());
        }
        let key = trusted
            .delegated_keys
            .iter()
            .find(|key| key.key_id == p.key_id)
            .ok_or("native qualification certificate signing key is not delegated")?;
        if !key.roles.contains(&ReleaseSigningRoleV1::NativeQ)
            || p.issued_at_unix < key.not_before_unix
            || p.issued_at_unix >= key.expires_at_unix
            || now_unix >= key.expires_at_unix
        {
            return Err(
                "native qualification certificate signing role or key validity differs".into(),
            );
        }
        verify_signature(&key.public_key_hex, &self.signature_hex, &bytes)?;
        Ok(VerifiedNativeQualificationV1 {
            certificate_sha256,
            policy_sha256: policy.digest().into(),
            release_sequence: p.release_sequence,
        })
    }
}

fn verify_signature(key_hex: &str, signature_hex: &str, message: &[u8]) -> Result<(), String> {
    let key = VerifyingKey::from_bytes(&decode_fixed::<32>(key_hex)?)
        .map_err(|_| "release signing public key is invalid")?;
    let signature = Signature::from_bytes(&decode_fixed::<64>(signature_hex)?);
    key.verify_strict(message, &signature)
        .map_err(|_| "release signature verification failed".into())
}
