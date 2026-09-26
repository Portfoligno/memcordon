//! Protected local import of a root-authorized, completed-CI Q decision.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Cursor, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use memcordon_core::private_release_build_v2::{
    PrivateCandidateRecordV2, private_component_digest_v2,
};
use memcordon_core::release_archive_trust::{
    ArchiveMemberV1, ExpectedArchiveSealV1, SignedArchiveCertificateV1,
};
use memcordon_core::release_trust::{
    ExpectedNativeQualificationV1, ReleaseTrustAnchorV1, SignedNativeQualificationCertificateV1,
    SignedReleaseRollbackExceptionV1, SignedReleaseRootRotationV1, SignedReleaseTrustPolicyV1,
    TrustHighWaterV1,
};
use memcordon_core::runtime_manifest_v3::{RuntimeProfileAvailabilityV3, SealedRuntimeV3};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_qualification_v2::QualificationArtifactV2;
use serde::{Deserialize, Serialize};

use super::installed_release_qualification::{
    CandidateV3Readback, IndependentlyVerifiedNativeRunV2,
};

const TRUST_ROOT: &str = "/etc/memcordon/release-trust";
const TRUST_STATE: &str = "/var/lib/memcordon/sealed/release-trust";
const INSTALLED_ROOT: &str = "/usr/libexec/memcordon/certification/workload";
const MAX_BUILD_BYTES: u64 = 1024 * 1024;
const MAX_CERT_BYTES: u64 = 64 * 1024;
const STATE_LEAF: &str = "high-water.v1.json";
// CLOCK_REALTIME and CLOCK_BOOTTIME are sampled separately and NTP can slew
// realtime. Bound a rollback without rejecting ordinary sampling jitter.
const WALL_MONOTONIC_SKEW_NANOS: u128 = 5_000_000_000;

/// Before any H1 revocation or installation-epoch advance, authenticate the
/// detached exact-A seal under the independently provisioned root and policy.
/// A and its sidecar are never accepted through a world-writable ancestor.
pub(crate) fn verify_source_archive_seal(
    archive_path: &Path,
    certificate_path: &Path,
    source: &crate::package::LinuxSourceSnapshot,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 || source.qualification.is_none() {
        return Err("signed final A requires root and qualified M1 source".into());
    }
    let archive_bytes = super::installed_release_qualification::read_protected_absolute(
        archive_path,
        512 * 1024 * 1024,
        None,
    )?;
    let certificate_bytes = super::installed_release_qualification::read_protected_absolute(
        certificate_path,
        256 * 1024,
        None,
    )?;
    let signed = SignedArchiveCertificateV1::parse(&certificate_bytes)?;
    let manifest =
        memcordon_core::runtime_manifest_v3::RuntimeManifestV3::parse(&source.manifest_bytes)?;
    let archive_root = format!("memcordon-v{}-{}", manifest.version, manifest.target);
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(Cursor::new(&archive_bytes)));
    let mut inventory = Vec::new();
    let mut members = BTreeMap::new();
    let mut expanded = 0_u64;
    for entry in archive.entries().map_err(|error| error.to_string())? {
        let mut entry = entry.map_err(|error| error.to_string())?;
        if !entry.header().entry_type().is_file()
            || entry.size() > 128 * 1024 * 1024
            || inventory.len() >= 64
        {
            return Err("signed A member type or bound differs".into());
        }
        expanded = expanded
            .checked_add(entry.size())
            .ok_or("signed A expansion overflow")?;
        if expanded > 512 * 1024 * 1024 {
            return Err("signed A expansion bound differs".into());
        }
        let path = entry
            .path()
            .map_err(|error| error.to_string())?
            .into_owned();
        let path = path.to_str().ok_or("signed A path is not UTF-8")?;
        let relative = path
            .strip_prefix(&archive_root)
            .and_then(|suffix| suffix.strip_prefix('/'))
            .ok_or("signed A package root differs")?;
        if relative.is_empty()
            || relative.len() > 256
            || relative
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("signed A member path differs".into());
        }
        let mode = entry.header().mode().map_err(|error| error.to_string())?;
        if mode != 0o644 && mode != 0o755 {
            return Err("signed A member mode differs".into());
        }
        let size = entry.size();
        let mut bytes = Vec::new();
        (&mut entry)
            .take(size + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 != size
            || members
                .insert(relative.to_owned(), String::from(hash_bytes(&bytes)))
                .is_some()
        {
            return Err("signed A member is duplicate or incomplete".into());
        }
        inventory.push(ArchiveMemberV1 {
            path: path.to_owned(),
            size,
            mode,
            sha256: String::from(hash_bytes(&bytes)),
        });
    }
    inventory.sort_by(|a, b| a.path.cmp(&b.path));
    let required = [
        ("runtime-manifest.json", &source.manifest_bytes),
        ("memcordon-sealed-agent", &source.agent_bytes),
        (
            source
                .qualification
                .as_ref()
                .expect("checked")
                .0
                .to_str()
                .and_then(|p| p.strip_prefix("/usr/libexec/memcordon/"))
                .ok_or("Q source path differs")?,
            &source.qualification.as_ref().expect("checked").1,
        ),
        (
            source
                .release_build
                .as_ref()
                .ok_or("signed A source B absent")?
                .0
                .to_str()
                .and_then(|p| p.strip_prefix("/usr/libexec/memcordon/"))
                .ok_or("B source path differs")?,
            &source.release_build.as_ref().expect("checked").1,
        ),
        (
            source
                .release_certificate
                .as_ref()
                .ok_or("signed A source CQ absent")?
                .0
                .to_str()
                .and_then(|p| p.strip_prefix("/usr/libexec/memcordon/"))
                .ok_or("CQ source path differs")?,
            &source.release_certificate.as_ref().expect("checked").1,
        ),
    ];
    for (name, bytes) in required {
        if members.get(name).map(String::as_str) != Some(String::from(hash_bytes(bytes)).as_str()) {
            return Err(format!("signed A source member {name} differs"));
        }
    }
    let source_parent = std::env::current_exe()
        .map_err(|error| error.to_string())?
        .parent()
        .ok_or("signed A source agent has no parent")?
        .to_path_buf();
    let public_cli = super::installed_release_qualification::read_protected_absolute(
        &source_parent.join("memcordon"),
        128 * 1024 * 1024,
        None,
    )?;
    if members.get("memcordon").map(String::as_str)
        != Some(String::from(hash_bytes(&public_cli)).as_str())
    {
        return Err("signed A public CLI differs from staged source".into());
    }
    if let Some(helper) = &source.arm32_helper_bytes {
        if members
            .get("memcordon-arm32-abi-helper")
            .map(String::as_str)
            != Some(String::from(hash_bytes(helper)).as_str())
        {
            return Err("signed A ARM32 helper differs from staged source".into());
        }
    }
    let cq_bytes = &source.release_certificate.as_ref().expect("checked").1;
    let cq = SignedNativeQualificationCertificateV1::parse(cq_bytes)?;
    let root_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(TRUST_ROOT).join("root-anchor.v1.json"),
        MAX_CERT_BYTES,
        Some(0o600),
    )?;
    let policy_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(TRUST_ROOT).join("policy.v1.json"),
        MAX_CERT_BYTES,
        Some(0o600),
    )?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&root_bytes)?;
    let anchor_file: ReleaseTrustAnchorV1File =
        serde_json::from_slice(&root_bytes).map_err(|error| error.to_string())?;
    if anchor_file.schema_version != 1 {
        return Err("signed A root anchor schema differs".into());
    }
    let anchor = ReleaseTrustAnchorV1 {
        root_key_id: anchor_file.root_key_id,
        public_key_hex: anchor_file.public_key_hex,
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "signed A wall time unavailable")?;
    let now_unix = now.as_secs();
    let now_nanos = now.as_nanos();
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() || boot_id.len() > 64 {
        return Err("signed A boot identity differs".into());
    }
    let boottime_nanos = current_boottime_nanos()?;
    let state_dir = open_protected_directory(Path::new(TRUST_STATE))?;
    let _state_lock = lock_state(&state_dir)?;
    let prior = read_state(&state_dir)?;
    if prior.boot_id == boot_id {
        let elapsed = boottime_nanos
            .checked_sub(prior.last_accepted_boottime_nanos)
            .ok_or("signed A monotonic clock moved backward")?;
        let minimum_wall = prior
            .last_accepted_wall_nanos
            .checked_add(elapsed)
            .ok_or("signed A wall clock bound overflow")?;
        if now_nanos < minimum_wall.saturating_sub(WALL_MONOTONIC_SKEW_NANOS) {
            return Err("signed A wall clock fell behind boot monotonic time".into());
        }
    }
    let mut rotation_floor = None;
    if prior.policy_version != 0
        && (prior.root_key_id != anchor.root_key_id
            || prior.root_public_key_hex != anchor.public_key_hex)
    {
        let rotation_bytes = super::installed_release_qualification::read_protected_absolute(
            &Path::new(TRUST_ROOT).join("root-rotation.v1.json"),
            MAX_CERT_BYTES,
            Some(0o600),
        )?;
        let previous = ReleaseTrustAnchorV1 {
            root_key_id: prior.root_key_id.clone(),
            public_key_hex: prior.root_public_key_hex.clone(),
        };
        let rotation = SignedReleaseRootRotationV1::parse(&rotation_bytes)?.verify(
            &previous,
            &anchor,
            prior.policy_version,
            now_unix,
        )?;
        rotation_floor = Some(rotation.minimum_next_policy_version());
    }
    let policy = SignedReleaseTrustPolicyV1::parse(&policy_bytes)?.verify(
        &anchor,
        &prior.high_water(),
        now_unix,
    )?;
    if prior.policy_version == policy.policy().policy_version
        && prior.policy_version != 0
        && prior.policy_sha256 != policy.digest()
    {
        return Err("signed A trust policy changed without version advance".into());
    }
    if rotation_floor.is_some_and(|floor| policy.policy().policy_version < floor) {
        return Err("signed A rotated policy version is too low".into());
    }
    let accepted_policy = HighWaterStateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        policy_sha256: policy.digest().into(),
        release_sequence: prior.release_sequence,
        last_accepted_wall_unix: now_unix,
        last_accepted_wall_nanos: now_nanos,
        last_accepted_boottime_nanos: boottime_nanos,
        boot_id: boot_id.into(),
        root_key_id: anchor.root_key_id.clone(),
        root_public_key_hex: anchor.public_key_hex.clone(),
    };
    // A valid newer policy becomes the floor even if it revokes the presented A.
    persist_state(&state_dir, &accepted_policy)?;
    let q = &cq.payload;
    let native_machine = match manifest.target.as_str() {
        "x86_64-unknown-linux-gnu" => "x86_64",
        "aarch64-unknown-linux-gnu" => "aarch64",
        _ => return Err("signed A target is unsupported".into()),
    };
    let verified_q = cq.verify(
        &policy,
        &ExpectedNativeQualificationV1 {
            repository_id: policy.policy().repository_id,
            repository: &policy.policy().repository,
            workflow_path: &policy.policy().workflow_path,
            workflow_revision: &policy.policy().workflow_revision,
            target: &manifest.target,
            native_machine,
            verifier_sha256: &policy.policy().verifier_sha256,
            source_commit: &manifest.source_commit,
            release_version: &manifest.version,
            build_sha256: &String::from(hash_bytes(
                &source.release_build.as_ref().expect("checked").1,
            )),
            build_context_sha256: &q.build_context_sha256,
            qualification_bytes: &source.qualification.as_ref().expect("checked").1,
            raw_index_sha256: &q.raw_index_sha256,
            completed_provenance_sha256: &q.completed_provenance_sha256,
            accepted_case_set_sha256: &q.accepted_case_set_sha256,
        },
        &accepted_policy.high_water(),
        now_unix,
    )?;
    let expected = ExpectedArchiveSealV1 {
        archive_bytes: &archive_bytes,
        members: &inventory,
        build_sha256: &String::from(hash_bytes(
            &source.release_build.as_ref().expect("checked").1,
        )),
        manifest_sha256: &String::from(hash_bytes(&source.manifest_bytes)),
        qualification_sha256: &String::from(hash_bytes(
            &source.qualification.as_ref().expect("checked").1,
        )),
        native_certificate_sha256: &String::from(hash_bytes(cq_bytes)),
        source_commit: &manifest.source_commit,
        release_version: &manifest.version,
        target: &manifest.target,
        release_sequence: verified_q.release_sequence(),
    };
    let verified = signed.verify(
        &certificate_bytes,
        &policy,
        &accepted_policy.high_water(),
        &expected,
        now_unix,
    )?;
    let accepted_archive = HighWaterStateV1 {
        release_sequence: accepted_policy
            .release_sequence
            .max(verified.release_sequence()),
        ..accepted_policy
    };
    persist_state(&state_dir, &accepted_archive)?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HighWaterStateV1 {
    schema_version: u8,
    policy_version: u64,
    policy_sha256: String,
    release_sequence: u64,
    last_accepted_wall_unix: u64,
    last_accepted_wall_nanos: u128,
    last_accepted_boottime_nanos: u128,
    boot_id: String,
    root_key_id: String,
    root_public_key_hex: String,
}

impl HighWaterStateV1 {
    fn initial() -> Self {
        Self {
            schema_version: 1,
            policy_version: 0,
            policy_sha256: String::new(),
            release_sequence: 0,
            last_accepted_wall_unix: 0,
            last_accepted_wall_nanos: 0,
            last_accepted_boottime_nanos: 0,
            boot_id: String::new(),
            root_key_id: String::new(),
            root_public_key_hex: String::new(),
        }
    }

    fn high_water(&self) -> TrustHighWaterV1 {
        TrustHighWaterV1 {
            policy_version: self.policy_version,
            release_sequence: self.release_sequence,
            last_accepted_wall_unix: self.last_accepted_wall_unix,
        }
    }
}

pub(crate) fn verify_installed_native_q(
    candidate: &CandidateV3Readback,
) -> Result<IndependentlyVerifiedNativeRunV2, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("installed release trust verification requires root service".into());
    }
    let target = candidate.manifest.target.as_str();
    let short = match target {
        "x86_64-unknown-linux-gnu" => "x64",
        "aarch64-unknown-linux-gnu" => "arm64",
        _ => return Err("installed release certificate target is unsupported".into()),
    };
    let qualification_bytes = candidate
        .qualification_bytes()
        .ok_or("installed release Q bytes are absent")?;
    let root_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(TRUST_ROOT).join("root-anchor.v1.json"),
        MAX_CERT_BYTES,
        Some(0o600),
    )?;
    let policy_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(TRUST_ROOT).join("policy.v1.json"),
        MAX_CERT_BYTES,
        Some(0o600),
    )?;
    let build_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(INSTALLED_ROOT).join(format!("{short}-private-build-v1.json")),
        MAX_BUILD_BYTES,
        None,
    )?;
    let certificate_bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(INSTALLED_ROOT).join(format!("{short}-private-cq-v1.json")),
        MAX_CERT_BYTES,
        None,
    )?;
    let build = PrivateCandidateRecordV2::parse(&build_bytes)?;
    let qualification: QualificationArtifactV2 =
        serde_json::from_slice(qualification_bytes).map_err(|error| error.to_string())?;
    let mut unqualified_manifest = candidate.manifest.clone();
    let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &mut unqualified_manifest.sealed else {
        return Err("installed release M1 has no workload profile inventory".into());
    };
    let mut unqualified_profiles = memcordon_core::BoundedVec::default();
    for (index, profile) in profiles.as_slice().iter().enumerate() {
        let mut profile = profile.clone();
        if index == 0 {
            profile.availability = RuntimeProfileAvailabilityV3::Unqualified;
        }
        unqualified_profiles
            .try_push(profile)
            .map_err(|_| "installed release M0 profile inventory exceeds bound")?;
    }
    if unqualified_profiles.as_slice().is_empty() {
        return Err("installed release M1 has no private profile".into());
    }
    *profiles = unqualified_profiles;
    let m0_bytes = serde_json::to_vec(&unqualified_manifest).map_err(|error| error.to_string())?;
    let installed_components = private_component_digest_v2(
        &candidate.manifest.target,
        &candidate.manifest.source_commit,
        &candidate.manifest.version,
        &candidate.manifest.components,
    )?;
    if build.version != candidate.manifest.version
        || build.source_commit != candidate.manifest.source_commit
        || build.target != candidate.manifest.target
        || build.runtime_manifest_sha256 != hash_bytes(&m0_bytes)
        || build.component_sha256 != installed_components
        || build.component_sha256 != qualification.component_digest
        || build.unit_sha256 != qualification.unit_digest
        || build.filter_sha256 != qualification.filter_digest
    {
        return Err("installed release B, M0, M1 and Q identities differ".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&root_bytes)?;
    let anchor: ReleaseTrustAnchorV1File =
        serde_json::from_slice(&root_bytes).map_err(|error| error.to_string())?;
    if anchor.schema_version != 1 || anchor.root_key_id.is_empty() {
        return Err("installed release root anchor is invalid".into());
    }
    let signed_policy = SignedReleaseTrustPolicyV1::parse(&policy_bytes)?;
    let signed_certificate = SignedNativeQualificationCertificateV1::parse(&certificate_bytes)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "installed release trusted wall time is unavailable")?;
    let now_unix = now.as_secs();
    let now_nanos = now.as_nanos();
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| format!("installed release boot identity: {error}"))?;
    let boot_id = boot_id.trim();
    if boot_id.is_empty() || boot_id.len() > 64 {
        return Err("installed release boot identity differs".into());
    }
    let boottime_nanos = current_boottime_nanos()?;
    let state_dir = open_protected_directory(Path::new(TRUST_STATE))?;
    let _state_lock = lock_state(&state_dir)?;
    let prior = read_state(&state_dir)?;
    if prior.boot_id == boot_id {
        let elapsed = boottime_nanos
            .checked_sub(prior.last_accepted_boottime_nanos)
            .ok_or("installed release monotonic clock moved backward")?;
        let minimum_wall = prior
            .last_accepted_wall_nanos
            .checked_add(elapsed)
            .ok_or("installed release wall clock bound overflow")?;
        if now_nanos < minimum_wall.saturating_sub(WALL_MONOTONIC_SKEW_NANOS) {
            return Err("installed release wall clock fell behind boot monotonic time".into());
        }
    }
    let trusted_anchor = ReleaseTrustAnchorV1 {
        root_key_id: anchor.root_key_id,
        public_key_hex: anchor.public_key_hex,
    };
    let rotation = if prior.policy_version == 0 {
        None
    } else if prior.root_key_id == trusted_anchor.root_key_id
        && prior.root_public_key_hex == trusted_anchor.public_key_hex
    {
        None
    } else {
        let rotation_bytes = super::installed_release_qualification::read_protected_absolute(
            &Path::new(TRUST_ROOT).join("root-rotation.v1.json"),
            MAX_CERT_BYTES,
            Some(0o600),
        )?;
        let previous = ReleaseTrustAnchorV1 {
            root_key_id: prior.root_key_id.clone(),
            public_key_hex: prior.root_public_key_hex.clone(),
        };
        Some(SignedReleaseRootRotationV1::parse(&rotation_bytes)?.verify(
            &previous,
            &trusted_anchor,
            prior.policy_version,
            now_unix,
        )?)
    };
    let policy = signed_policy.verify(&trusted_anchor, &prior.high_water(), now_unix)?;
    if rotation
        .as_ref()
        .is_some_and(|proof| policy.policy().policy_version < proof.minimum_next_policy_version())
    {
        return Err("installed release rotated policy version is too low".into());
    }
    if prior.policy_version == policy.policy().policy_version
        && prior.policy_version != 0
        && prior.policy_sha256 != policy.digest()
    {
        return Err("installed release policy changed without version advance".into());
    }
    // A valid newer policy must remain the floor even when it revokes the
    // current CQ. Otherwise retrying an old policy could reopen admission.
    let accepted_policy = HighWaterStateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        policy_sha256: policy.digest().into(),
        release_sequence: prior.release_sequence,
        last_accepted_wall_unix: now_unix,
        last_accepted_wall_nanos: now_nanos,
        last_accepted_boottime_nanos: boottime_nanos,
        boot_id: boot_id.into(),
        root_key_id: trusted_anchor.root_key_id.clone(),
        root_public_key_hex: trusted_anchor.public_key_hex.clone(),
    };
    persist_state(&state_dir, &accepted_policy)?;
    let cert = &signed_certificate.payload;
    let expected = ExpectedNativeQualificationV1 {
        repository_id: policy.policy().repository_id,
        repository: &policy.policy().repository,
        workflow_path: &policy.policy().workflow_path,
        workflow_revision: &policy.policy().workflow_revision,
        target,
        native_machine: match target {
            "x86_64-unknown-linux-gnu" => "x86_64",
            "aarch64-unknown-linux-gnu" => "aarch64",
            _ => unreachable!("supported target selected above"),
        },
        verifier_sha256: &policy.policy().verifier_sha256,
        source_commit: &candidate.manifest.source_commit,
        release_version: &candidate.manifest.version,
        build_sha256: &String::from(hash_bytes(&build_bytes)),
        build_context_sha256: &cert.build_context_sha256,
        qualification_bytes,
        raw_index_sha256: &cert.raw_index_sha256,
        completed_provenance_sha256: &cert.completed_provenance_sha256,
        accepted_case_set_sha256: &cert.accepted_case_set_sha256,
    };
    let rollback_path = Path::new(TRUST_ROOT).join("rollback-exception.v1.json");
    let rollback = match std::fs::symlink_metadata(&rollback_path) {
        Ok(_) => {
            let bytes = super::installed_release_qualification::read_protected_absolute(
                &rollback_path,
                MAX_CERT_BYTES,
                Some(0o600),
            )?;
            Some(SignedReleaseRollbackExceptionV1::parse(&bytes)?.verify(
                &trusted_anchor,
                &policy,
                now_unix,
            )?)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!(
                "installed release rollback exception read: {error}"
            ));
        }
    };
    let verified = signed_certificate.verify_with_rollback(
        &policy,
        &expected,
        &accepted_policy.high_water(),
        rollback.as_ref(),
        now_unix,
    )?;
    match (target, cert.native_machine.as_str()) {
        ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64") => {}
        _ => return Err("installed release native machine differs".into()),
    }
    let next = HighWaterStateV1 {
        schema_version: 1,
        policy_version: policy.policy().policy_version,
        policy_sha256: policy.digest().into(),
        release_sequence: accepted_policy
            .release_sequence
            .max(verified.release_sequence()),
        last_accepted_wall_unix: now_unix,
        last_accepted_wall_nanos: now_nanos,
        last_accepted_boottime_nanos: boottime_nanos,
        boot_id: boot_id.into(),
        root_key_id: trusted_anchor.root_key_id.clone(),
        root_public_key_hex: trusted_anchor.public_key_hex.clone(),
    };
    persist_state(&state_dir, &next)?;
    Ok(super::installed_release_qualification::verified_native_run(
        hash_bytes(qualification_bytes),
        verified,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseTrustAnchorV1File {
    schema_version: u8,
    root_key_id: String,
    public_key_hex: String,
}

fn current_boottime_nanos() -> Result<u128, String> {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut stamp) } < 0 {
        return Err(format!(
            "installed release monotonic clock: {}",
            std::io::Error::last_os_error()
        ));
    }
    let seconds = u128::try_from(stamp.tv_sec)
        .map_err(|_| "installed release monotonic clock seconds differ")?;
    let nanos = u128::try_from(stamp.tv_nsec)
        .map_err(|_| "installed release monotonic clock nanoseconds differ")?;
    if nanos >= 1_000_000_000 {
        return Err("installed release monotonic clock nanos differ".into());
    }
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanos))
        .ok_or("installed release monotonic clock overflows".into())
}

fn open_protected_directory(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("release trust state path is not absolute".into());
    }
    let mut directory = File::open("/").map_err(|error| error.to_string())?;
    for component in path.components() {
        let Component::Normal(name) = component else {
            if component == Component::RootDir {
                continue;
            }
            return Err("release trust state path has unsafe component".into());
        };
        let name = CString::new(name.as_bytes()).map_err(|_| "release trust state path has NUL")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(format!(
                "release trust state directory open: {}",
                std::io::Error::last_os_error()
            ));
        }
        directory = unsafe { File::from_raw_fd(fd) };
        let meta = directory.metadata().map_err(|error| error.to_string())?;
        if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err("release trust state directory is not root protected".into());
        }
    }
    Ok(directory)
}

fn lock_state(directory: &File) -> Result<File, String> {
    let name = CString::new("state.lock").expect("fixed state lock name");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "release trust state lock open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
        return Err("release trust state lock protection differs".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } < 0 {
        return Err(format!(
            "release trust state lock: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(file)
}

fn read_state(directory: &File) -> Result<HighWaterStateV1, String> {
    let name = CString::new(STATE_LEAF).expect("fixed state name");
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        if std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            return Ok(HighWaterStateV1::initial());
        }
        return Err(format!(
            "release trust state open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let meta = file.metadata().map_err(|error| error.to_string())?;
    if !meta.is_file() || meta.uid() != 0 || meta.nlink() != 1 || meta.mode() & 0o777 != 0o600 {
        return Err("release trust high-water protection differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_CERT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CERT_BYTES {
        return Err("release trust high-water size differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let state: HighWaterStateV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if state.schema_version != 1
        || state.policy_version == 0
        || state.policy_sha256.len() != 64
        || !state
            .policy_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || state.last_accepted_wall_nanos / 1_000_000_000
            != u128::from(state.last_accepted_wall_unix)
        || state.last_accepted_boottime_nanos == 0
        || state.boot_id.is_empty()
        || state.boot_id.len() > 64
        || state.root_key_id.is_empty()
        || state.root_public_key_hex.len() != [0_u8; 32].len() * 2
        || !state
            .root_public_key_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("release trust high-water content differs".into());
    }
    Ok(state)
}

fn persist_state(directory: &File, state: &HighWaterStateV1) -> Result<(), String> {
    let bytes = serde_json::to_vec(state).map_err(|error| error.to_string())?;
    let temporary = format!(
        "high-water.{}.{}.new",
        std::process::id(),
        state.last_accepted_wall_unix
    );
    let name = CString::new(temporary).map_err(|_| "release trust temporary name has NUL")?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "release trust temporary open: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    let target = CString::new(STATE_LEAF).expect("fixed state leaf");
    if unsafe {
        libc::renameat(
            directory.as_raw_fd(),
            name.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
        )
    } < 0
    {
        return Err(format!(
            "release trust state rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    directory.sync_all().map_err(|error| error.to_string())?;
    Ok(())
}
