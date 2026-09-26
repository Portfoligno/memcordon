//! Detached exact-A signer. A is reopened after seal and its tar headers and
//! member bytes are compared to independently reviewed B/M1/Q/CQ inputs.
//! The sidecar is not included in A, and this API requires a verified CQ token.

use std::io::{Cursor, Read};

use ed25519_dalek::{Signer, SigningKey};
use memcordon_core::release_archive_trust::{
    ArchiveCertificateV1, ArchiveMemberV1, ExpectedArchiveSealV1, SignedArchiveCertificateV1,
};
use memcordon_core::release_trust::{
    ExpectedNativeQualificationV1, ReleaseSigningRoleV1, ReleaseTrustAnchorV1,
    SignedNativeQualificationCertificateV1, SignedReleaseTrustPolicyV1, TrustHighWaterV1,
    VerifiedNativeQualificationV1,
};
use memcordon_core::workload_codec::hash_bytes;

use crate::release_private::{
    OfflinePrivateQualifiedResultV2, PrivateArchiveFormat, QualifiedArchiveExpectation,
    validate_qualified_archive,
};
use crate::{CiError, Result};

pub(crate) struct ArchiveCertificateSigningIntentV1<'a> {
    pub(crate) trust_anchor: &'a ReleaseTrustAnchorV1,
    pub(crate) signed_policy: &'a SignedReleaseTrustPolicyV1,
    pub(crate) high_water: &'a TrustHighWaterV1,
    pub(crate) signing_key: &'a SigningKey,
    pub(crate) key_id: &'a str,
    pub(crate) issued_at_unix: u64,
    pub(crate) expires_at_unix: u64,
}

fn exact_members(
    archive_bytes: &[u8],
    expected: &QualifiedArchiveExpectation<'_>,
) -> Result<Vec<ArchiveMemberV1>> {
    if expected.format != PrivateArchiveFormat::TarGz {
        return Err(CiError::Message(
            "detached A certificate requires tar.gz A".into(),
        ));
    }
    let manifest = expected.final_manifest.manifest();
    let root = format!("memcordon-v{}-{}", manifest.version, manifest.target);
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(archive_bytes)));
    let mut actual = Vec::with_capacity(expected.members.len());
    for entry in archive.entries()? {
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() || actual.len() >= 64 {
            return Err(CiError::Message(
                "sealed A member type/count differs".into(),
            ));
        }
        let path = entry
            .path()?
            .to_str()
            .ok_or_else(|| CiError::Message("sealed A member path is not UTF-8".into()))?
            .to_owned();
        let relative = path
            .strip_prefix(&format!("{root}/"))
            .ok_or_else(|| CiError::Message("sealed A member root differs".into()))?;
        let reviewed = expected
            .members
            .get(relative)
            .ok_or_else(|| CiError::Message("sealed A contains unreviewed member".into()))?;
        let mode = entry.header().mode()?;
        let expected_mode = manifest
            .components
            .iter()
            .find(|component| component.path == relative)
            .map_or(0o644, |component| component.mode);
        let size = entry.size();
        if mode != expected_mode || size != reviewed.len() as u64 || size > 128 * 1024 * 1024 {
            return Err(CiError::Message("sealed A member mode/size differs".into()));
        }
        let mut bytes = Vec::with_capacity(size as usize);
        (&mut entry).take(size + 1).read_to_end(&mut bytes)?;
        if bytes != *reviewed {
            return Err(CiError::Message(
                "sealed A member bytes differ from reviewed input".into(),
            ));
        }
        actual.push(ArchiveMemberV1 {
            path,
            size,
            mode,
            sha256: String::from(hash_bytes(&bytes)),
        });
    }
    if actual.len() != expected.members.len()
        || actual.windows(2).any(|pair| pair[0].path >= pair[1].path)
    {
        return Err(CiError::Message(
            "sealed A exact member order/inventory differs".into(),
        ));
    }
    Ok(actual)
}

pub(crate) fn sign_detached_archive_certificate(
    sealed: &OfflinePrivateQualifiedResultV2,
    expected: &QualifiedArchiveExpectation<'_>,
    verified_q: &VerifiedNativeQualificationV1,
    intent: &ArchiveCertificateSigningIntentV1<'_>,
) -> Result<Vec<u8>> {
    let archive_bytes = sealed.archive_bytes();
    let manifest = sealed.final_manifest().manifest();
    let policy = intent
        .signed_policy
        .verify(
            intent.trust_anchor,
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    let delegated = policy
        .policy()
        .delegated_keys
        .iter()
        .find(|key| key.key_id == intent.key_id)
        .ok_or_else(|| CiError::Message("A signing key is not delegated".into()))?;
    let signing_public = hex::encode(intent.signing_key.verifying_key().as_bytes());
    let q = SignedNativeQualificationCertificateV1::parse(expected.certificate_bytes)
        .map_err(CiError::Message)?;
    let q_canonical = q.payload.canonical_bytes().map_err(CiError::Message)?;
    let reverified_q = q
        .verify(
            &policy,
            &ExpectedNativeQualificationV1 {
                repository_id: policy.policy().repository_id,
                repository: &policy.policy().repository,
                workflow_path: &policy.policy().workflow_path,
                workflow_revision: &policy.policy().workflow_revision,
                target: &manifest.target,
                native_machine: &q.payload.native_machine,
                verifier_sha256: &policy.policy().verifier_sha256,
                source_commit: &manifest.source_commit,
                release_version: &manifest.version,
                build_sha256: &q.payload.build_sha256,
                build_context_sha256: &q.payload.build_context_sha256,
                qualification_bytes: expected.qualification_bytes,
                raw_index_sha256: &q.payload.raw_index_sha256,
                completed_provenance_sha256: &q.payload.completed_provenance_sha256,
                accepted_case_set_sha256: &q.payload.accepted_case_set_sha256,
            },
            intent.high_water,
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    if !delegated
        .roles
        .contains(&ReleaseSigningRoleV1::ReleaseIndex)
        || delegated.public_key_hex != signing_public
        || policy
            .policy()
            .revoked_key_ids
            .binary_search(&delegated.key_id)
            .is_ok()
        || intent.issued_at_unix < delegated.not_before_unix
        || intent.expires_at_unix > delegated.expires_at_unix
        || intent.issued_at_unix >= intent.expires_at_unix
        || verified_q.policy_sha256() != policy.digest()
        || verified_q.release_sequence() < policy.policy().minimum_release_sequence
        || verified_q.release_sequence() < intent.high_water.release_sequence
        || verified_q.certificate_sha256() != String::from(hash_bytes(&q_canonical))
        || reverified_q.certificate_sha256() != verified_q.certificate_sha256()
        || q.payload.target != manifest.target
        || q.payload.source_commit != manifest.source_commit
        || q.payload.release_version != manifest.version
        || q.payload.build_sha256 != String::from(hash_bytes(expected.candidate_record_bytes))
        || q.payload.qualification_sha256 != String::from(hash_bytes(expected.qualification_bytes))
        || sealed.archive_sha256() != &hash_bytes(archive_bytes)
        || validate_qualified_archive(archive_bytes, expected)? != *sealed.archive_sha256()
    {
        return Err(CiError::Message(
            "sealed A/Q/policy signing authority differs".into(),
        ));
    }
    let members = exact_members(archive_bytes, expected)?;
    let build_sha = String::from(hash_bytes(expected.candidate_record_bytes));
    let manifest_sha = String::from(hash_bytes(sealed.final_manifest().manifest_bytes()));
    let qualification_sha = String::from(hash_bytes(expected.qualification_bytes));
    let cq_file_sha = String::from(hash_bytes(expected.certificate_bytes));
    let payload = ArchiveCertificateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        key_id: intent.key_id.into(),
        release_sequence: verified_q.release_sequence(),
        archive_sha256: String::from(hash_bytes(archive_bytes)),
        archive_size: archive_bytes.len() as u64,
        members: members.clone(),
        build_sha256: build_sha.clone(),
        manifest_sha256: manifest_sha.clone(),
        qualification_sha256: qualification_sha.clone(),
        native_certificate_sha256: cq_file_sha.clone(),
        source_commit: manifest.source_commit.clone(),
        release_version: manifest.version.clone(),
        target: manifest.target.clone(),
        issued_at_unix: intent.issued_at_unix,
        expires_at_unix: intent.expires_at_unix,
    };
    let canonical = payload.canonical_bytes().map_err(CiError::Message)?;
    let signed = SignedArchiveCertificateV1 {
        payload,
        signature_hex: hex::encode(intent.signing_key.sign(&canonical).to_bytes()),
    };
    let bytes = serde_json::to_vec(&signed)?;
    signed
        .verify(
            &bytes,
            &policy,
            intent.high_water,
            &ExpectedArchiveSealV1 {
                archive_bytes,
                members: &members,
                build_sha256: &build_sha,
                manifest_sha256: &manifest_sha,
                qualification_sha256: &qualification_sha,
                native_certificate_sha256: &cq_file_sha,
                source_commit: &manifest.source_commit,
                release_version: &manifest.version,
                target: &manifest.target,
                release_sequence: verified_q.release_sequence(),
            },
            intent.issued_at_unix,
        )
        .map_err(CiError::Message)?;
    Ok(bytes)
}
