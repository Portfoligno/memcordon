//! Detached, signer-authenticated seal of the exact final archive A.
//! This certificate is distributed beside A, never inside the bytes it signs.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::release_trust::{ReleaseSigningRoleV1, TrustHighWaterV1, VerifiedReleaseTrustPolicyV1};
use crate::workload_codec::hash_bytes;

const DOMAIN: &[u8] = b"memcordon/release-archive/v1\0";
const MAX_CERTIFICATE: usize = 256 * 1024;
const MAX_MEMBERS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveMemberV1 {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveCertificateV1 {
    pub schema_version: u8,
    pub policy_version: u64,
    pub key_id: String,
    pub release_sequence: u64,
    pub archive_sha256: String,
    pub archive_size: u64,
    pub members: Vec<ArchiveMemberV1>,
    pub build_sha256: String,
    pub manifest_sha256: String,
    pub qualification_sha256: String,
    pub native_certificate_sha256: String,
    pub source_commit: String,
    pub release_version: String,
    pub target: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedArchiveCertificateV1 {
    pub payload: ArchiveCertificateV1,
    pub signature_hex: String,
}

/// Independent expected values, never populated from the presented seal.
pub struct ExpectedArchiveSealV1<'a> {
    pub archive_bytes: &'a [u8],
    pub members: &'a [ArchiveMemberV1],
    pub build_sha256: &'a str,
    pub manifest_sha256: &'a str,
    pub qualification_sha256: &'a str,
    pub native_certificate_sha256: &'a str,
    pub source_commit: &'a str,
    pub release_version: &'a str,
    pub target: &'a str,
    pub release_sequence: u64,
}

#[derive(Clone, Debug)]
pub struct VerifiedArchiveSealV1 {
    certificate_sha256: String,
    archive_sha256: String,
    release_sequence: u64,
}

impl VerifiedArchiveSealV1 {
    pub fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }
    pub fn archive_sha256(&self) -> &str {
        &self.archive_sha256
    }
    pub fn release_sequence(&self) -> u64 {
        self.release_sequence
    }
}

fn text(out: &mut Vec<u8>, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.contains('\0') {
        return Err("archive certificate text field differs".into());
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn digest(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("archive certificate digest syntax differs".into());
    }
    Ok(())
}

fn fixed<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("archive certificate signature syntax differs".into());
    }
    let mut result = [0u8; N];
    for (output, pair) in result.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or("archive certificate signature digit differs")?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or("archive certificate signature digit differs")?;
        *output = ((high << 4) | low) as u8;
    }
    Ok(result)
}

impl ArchiveCertificateV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        if self.schema_version != 1
            || self.policy_version == 0
            || self.release_sequence == 0
            || self.archive_size == 0
            || self.members.is_empty()
            || self.members.len() > MAX_MEMBERS
            || self.issued_at_unix >= self.expires_at_unix
            || self.source_commit.len() != 40
            || !self
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err("archive certificate identity differs".into());
        }
        for value in [
            &self.archive_sha256,
            &self.build_sha256,
            &self.manifest_sha256,
            &self.qualification_sha256,
            &self.native_certificate_sha256,
        ] {
            digest(value)?;
        }
        let mut out = DOMAIN.to_vec();
        out.push(self.schema_version);
        out.extend_from_slice(&self.policy_version.to_be_bytes());
        text(&mut out, &self.key_id)?;
        out.extend_from_slice(&self.release_sequence.to_be_bytes());
        text(&mut out, &self.archive_sha256)?;
        out.extend_from_slice(&self.archive_size.to_be_bytes());
        out.extend_from_slice(&(self.members.len() as u32).to_be_bytes());
        let mut previous = "";
        for member in &self.members {
            if member.path.as_str() <= previous
                || member.path.starts_with('/')
                || member
                    .path
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
                || member.mode != 0o644 && member.mode != 0o755
            {
                return Err("archive certificate member inventory differs".into());
            }
            previous = &member.path;
            digest(&member.sha256)?;
            text(&mut out, &member.path)?;
            out.extend_from_slice(&member.size.to_be_bytes());
            out.extend_from_slice(&member.mode.to_be_bytes());
            text(&mut out, &member.sha256)?;
        }
        for value in [
            &self.build_sha256,
            &self.manifest_sha256,
            &self.qualification_sha256,
            &self.native_certificate_sha256,
            &self.source_commit,
            &self.release_version,
            &self.target,
        ] {
            text(&mut out, value)?;
        }
        out.extend_from_slice(&self.issued_at_unix.to_be_bytes());
        out.extend_from_slice(&self.expires_at_unix.to_be_bytes());
        Ok(out)
    }
}

impl SignedArchiveCertificateV1 {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE {
            return Err("archive certificate size differs".into());
        }
        crate::workload_contract::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn verify(
        &self,
        certificate_bytes: &[u8],
        policy: &VerifiedReleaseTrustPolicyV1,
        high_water: &TrustHighWaterV1,
        expected: &ExpectedArchiveSealV1<'_>,
        now_unix: u64,
    ) -> Result<VerifiedArchiveSealV1, String> {
        let payload = &self.payload;
        let canonical = payload.canonical_bytes()?;
        let policy_payload = policy.policy();
        let certificate_sha256 = String::from(hash_bytes(certificate_bytes));
        let archive_sha256 = String::from(hash_bytes(expected.archive_bytes));
        if certificate_bytes.len() > MAX_CERTIFICATE
            || serde_json::to_vec(self).map_err(|error| error.to_string())? != certificate_bytes
            || payload.policy_version != policy_payload.policy_version
            || payload.policy_version < high_water.policy_version
            || payload.release_sequence < high_water.release_sequence
            || payload.release_sequence < policy_payload.minimum_release_sequence
            || payload.release_sequence != expected.release_sequence
            || now_unix < payload.issued_at_unix
            || now_unix >= payload.expires_at_unix
            || now_unix < high_water.last_accepted_wall_unix
            || now_unix >= policy_payload.expires_at_unix
            || payload.archive_sha256 != archive_sha256
            || payload.archive_size != expected.archive_bytes.len() as u64
            || payload.members != expected.members
            || payload.build_sha256 != expected.build_sha256
            || payload.manifest_sha256 != expected.manifest_sha256
            || payload.qualification_sha256 != expected.qualification_sha256
            || payload.native_certificate_sha256 != expected.native_certificate_sha256
            || payload.source_commit != expected.source_commit
            || payload.release_version != expected.release_version
            || payload.target != expected.target
            || policy_payload
                .revoked_certificate_sha256
                .binary_search(&certificate_sha256)
                .is_ok()
            || policy_payload
                .revoked_certificate_sha256
                .binary_search(&payload.native_certificate_sha256)
                .is_ok()
            || policy_payload
                .revoked_build_sha256
                .binary_search(&payload.build_sha256)
                .is_ok()
            || policy_payload
                .revoked_qualification_sha256
                .binary_search(&payload.qualification_sha256)
                .is_ok()
        {
            return Err("archive certificate subject, freshness or revocation differs".into());
        }
        let delegated = policy_payload
            .delegated_keys
            .iter()
            .find(|key| key.key_id == payload.key_id)
            .ok_or("archive certificate key is not delegated")?;
        if !delegated
            .roles
            .contains(&ReleaseSigningRoleV1::ReleaseIndex)
            || policy_payload
                .revoked_key_ids
                .binary_search(&payload.key_id)
                .is_ok()
            || now_unix < delegated.not_before_unix
            || now_unix >= delegated.expires_at_unix
        {
            return Err("archive certificate key role or validity differs".into());
        }
        let key = VerifyingKey::from_bytes(&fixed::<32>(&delegated.public_key_hex)?)
            .map_err(|_| "archive certificate key differs")?;
        let signature = Signature::from_bytes(&fixed::<64>(&self.signature_hex)?);
        key.verify_strict(&canonical, &signature)
            .map_err(|_| "archive certificate signature differs")?;
        Ok(VerifiedArchiveSealV1 {
            certificate_sha256,
            archive_sha256,
            release_sequence: payload.release_sequence,
        })
    }
}
