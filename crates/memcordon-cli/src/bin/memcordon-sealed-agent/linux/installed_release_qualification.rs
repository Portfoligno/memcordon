//! Installed M1 readback and independently anchored native Q provenance.

use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use memcordon_core::runtime_manifest::{RuntimeComponentRecord, RuntimeComponentRole};
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, RuntimeManifestV3, RuntimeProfileAvailabilityV3,
    SealedRuntimeV3,
};
use memcordon_core::workload_discovery_v2::profile_catalog_digest_v2;
use memcordon_core::workload_qualification_v2::QualificationArtifactV2;
use memcordon_core::workload_registry_v2::ProfileKindV2;
use memcordon_core::{BoundedVec, DiagnosticSha256, workload_codec::hash_bytes};

const Q_INSTALLED_ROOT: &str = "/usr/libexec/memcordon";

/// An exact installed generation with, at most, a structurally joined Q.
/// It is deliberately not convertible into a production or host capability.
pub(crate) struct CandidateV3Readback {
    pub(crate) manifest: RuntimeManifestV3,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) qualification_sha256: Option<DiagnosticSha256>,
    qualification_bytes: Option<Vec<u8>>,
}

impl CandidateV3Readback {
    pub(crate) fn qualification_bytes(&self) -> Option<&[u8]> {
        self.qualification_bytes.as_deref()
    }
}

pub(crate) struct IndependentlyVerifiedNativeRunV2 {
    qualification_sha256: DiagnosticSha256,
    certificate_sha256: String,
    policy_sha256: String,
    release_sequence: u64,
}

pub(crate) struct TrustedReleaseQualification {
    _reference: QualificationArtifactReferenceV2,
    certificate_sha256: String,
    policy_sha256: String,
    release_sequence: u64,
}

impl TrustedReleaseQualification {
    pub(crate) fn reference(&self) -> &QualificationArtifactReferenceV2 {
        &self._reference
    }

    pub(crate) fn certificate_sha256(&self) -> &str {
        &self.certificate_sha256
    }

    pub(crate) fn policy_sha256(&self) -> &str {
        &self.policy_sha256
    }

    pub(crate) fn release_sequence(&self) -> u64 {
        self.release_sequence
    }

    pub(crate) fn from_independently_verified_run(
        candidate: &CandidateV3Readback,
        provenance: IndependentlyVerifiedNativeRunV2,
    ) -> Result<Self, String> {
        let reference = qualified_reference(&candidate.manifest)?
            .ok_or("installed release M1 has no Q reference")?;
        if candidate.qualification_sha256.as_ref() != Some(&provenance.qualification_sha256)
            || candidate.qualification_bytes().is_none()
            || reference.artifact_sha256 != provenance.qualification_sha256
        {
            return Err("installed release Q differs from authenticated certificate".into());
        }
        Ok(Self {
            _reference: reference.clone(),
            certificate_sha256: provenance.certificate_sha256,
            policy_sha256: provenance.policy_sha256,
            release_sequence: provenance.release_sequence,
        })
    }
}

/// The installer and ordinary admission call this only with a retained shared
/// package-generation lock. It reads the independently provisioned trust root
/// and protected installed certificate afresh on every call.
pub(crate) fn verify_anchored_native_qualification(
    candidate: &CandidateV3Readback,
) -> Result<TrustedReleaseQualification, String> {
    let verified = super::installed_release_certificate::verify_installed_native_q(candidate)?;
    TrustedReleaseQualification::from_independently_verified_run(candidate, verified)
}

pub(super) fn verified_native_run(
    qualification_sha256: DiagnosticSha256,
    verified: memcordon_core::release_trust::VerifiedNativeQualificationV1,
) -> IndependentlyVerifiedNativeRunV2 {
    IndependentlyVerifiedNativeRunV2 {
        qualification_sha256,
        certificate_sha256: verified.certificate_sha256().into(),
        policy_sha256: verified.policy_sha256().into(),
        release_sequence: verified.release_sequence(),
    }
}

pub(crate) fn fixed_q_reference_path(target: &str) -> Result<&'static str, String> {
    match target {
        "x86_64-unknown-linux-gnu" => Ok("certification/workload/linux-x64-private-v2.json"),
        "aarch64-unknown-linux-gnu" => Ok("certification/workload/linux-arm64-private-v2.json"),
        _ => Err("installed release Q target is unsupported".into()),
    }
}

/// The caller must hold the shared package-generation lock across this entire
/// read. The Q path is a fixed archive-relative member below a reviewed
/// root-owned installed directory; it is never read from a manifest pathname.
pub(crate) fn read_candidate(
    manifest_bytes: Vec<u8>,
    agent_bytes: &[u8],
    public_bytes: &[u8],
    arm32_helper_bytes: Option<&[u8]>,
    installed: bool,
) -> Result<CandidateV3Readback, String> {
    let manifest = RuntimeManifestV3::parse(&manifest_bytes)?;
    let q_reference = qualified_reference(&manifest)?;
    let q_bytes = match q_reference {
        Some(reference) if installed => {
            let relative = fixed_q_reference_path(&manifest.target)?;
            if reference.artifact != relative {
                return Err("installed M1 Q archive-relative reference differs".into());
            }
            let path = Path::new(Q_INSTALLED_ROOT).join(relative);
            Some(read_protected_absolute(
                &path,
                memcordon_core::workload_limits::REGISTRY_BYTES as u64,
                None,
            )?)
        }
        Some(_) => {
            return Err("qualified V3 source requires installed protected Q readback".into());
        }
        None => None,
    };
    from_exact_bytes(
        manifest_bytes,
        agent_bytes,
        public_bytes,
        arm32_helper_bytes,
        q_bytes,
    )
}

/// Pure byte join used by tests and by the protected installed reader. This
/// does not validate native execution: a self-consistent forged Q remains only
/// a candidate until an independent run verifier supplies provenance.
pub(crate) fn from_exact_bytes(
    manifest_bytes: Vec<u8>,
    agent_bytes: &[u8],
    public_bytes: &[u8],
    arm32_helper_bytes: Option<&[u8]>,
    qualification_bytes: Option<Vec<u8>>,
) -> Result<CandidateV3Readback, String> {
    let manifest = RuntimeManifestV3::parse(&manifest_bytes)?;
    let q_reference = qualified_reference(&manifest)?;
    let mut normalized = manifest.clone();
    let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &mut normalized.sealed else {
        return Err("installed M1 requires Linux workload V2 protocol".into());
    };
    let mut unqualified = BoundedVec::default();
    for (index, record) in profiles.as_slice().iter().enumerate() {
        let mut record = record.clone();
        if index == 0 && q_reference.is_some() {
            record.availability = RuntimeProfileAvailabilityV3::Unqualified;
        }
        unqualified
            .try_push(record)
            .map_err(|_| "installed M1 profile inventory exceeds bound")?;
    }
    *profiles = unqualified;
    let component = |id: &str, path: &str, role, bytes: &[u8]| RuntimeComponentRecord {
        id: id.into(),
        path: path.into(),
        role,
        size: bytes.len() as u64,
        mode: 0o755,
        sha256: String::from(hash_bytes(bytes)),
    };
    let mut components = vec![
        component(
            "public-cli",
            "memcordon",
            RuntimeComponentRole::PublicCli,
            public_bytes,
        ),
        component(
            "sealed-agent",
            "memcordon-sealed-agent",
            RuntimeComponentRole::SealedAgent,
            agent_bytes,
        ),
    ];
    if manifest.target == "aarch64-unknown-linux-gnu" {
        let helper = arm32_helper_bytes.ok_or("installed ARM32 helper absent")?;
        components.push(component(
            "arm32-abi-helper",
            "memcordon-arm32-abi-helper",
            RuntimeComponentRole::Arm32AbiHelper,
            helper,
        ));
    } else if arm32_helper_bytes.is_some() {
        return Err("installed ARM32 helper supplied for other target".into());
    }
    let expected = RuntimeManifestV3::linux_unqualified(
        env!("CARGO_PKG_VERSION").into(),
        crate::SOURCE_COMMIT.into(),
        super::runtime_manifest::target()?.into(),
        components,
    )?;
    if normalized != expected {
        return Err("installed M1 static fields differ from exact executable images".into());
    }
    let qualification_sha256 = match (q_reference, qualification_bytes.as_deref()) {
        (None, None) => None,
        (Some(reference), Some(bytes)) => {
            if bytes.len() > memcordon_core::workload_limits::REGISTRY_BYTES
                || reference.artifact != fixed_q_reference_path(&manifest.target)?
                || reference.artifact_sha256 != hash_bytes(bytes)
            {
                return Err("installed M1 Q path, bound or byte hash differs".into());
            }
            memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
            let artifact: QualificationArtifactV2 =
                serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            if artifact.source_commit.as_str() != manifest.source_commit
                || artifact.target.as_str() != manifest.target
                || artifact.profile != ProfileKindV2::LinuxTcp4PrivateV1.reference()
                || artifact.profile_catalog_digest != profile_catalog_digest_v2()
            {
                return Err("installed M1 Q structural identity differs".into());
            }
            Some(hash_bytes(bytes))
        }
        _ => return Err("installed M1 Q presence differs from manifest availability".into()),
    };
    Ok(CandidateV3Readback {
        manifest,
        manifest_bytes,
        qualification_sha256,
        qualification_bytes,
    })
}

fn qualified_reference(
    manifest: &RuntimeManifestV3,
) -> Result<Option<&QualificationArtifactReferenceV2>, String> {
    let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &manifest.sealed else {
        return Err("installed V3 has no Linux workload protocol".into());
    };
    match &profiles
        .as_slice()
        .first()
        .ok_or("installed V3 private profile absent")?
        .availability
    {
        RuntimeProfileAvailabilityV3::Qualified { qualification } => Ok(Some(qualification)),
        RuntimeProfileAvailabilityV3::Unqualified => Ok(None),
        RuntimeProfileAvailabilityV3::Unsupported => {
            Err("installed V3 private profile unexpectedly unsupported".into())
        }
    }
}

pub(crate) fn read_protected_absolute(
    path: &Path,
    maximum: u64,
    exact_mode: Option<u32>,
) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("installed release path is not absolute".into());
    }
    let mut directory = File::open("/").map_err(|error| error.to_string())?;
    verify_directory(&directory)?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            if index == 0 && *component == Component::RootDir {
                continue;
            }
            return Err("installed release path has a nonnormal component".into());
        };
        let leaf = CString::new(name.as_bytes()).map_err(|_| "installed release path has NUL")?;
        let final_component = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if final_component {
                0
            } else {
                libc::O_DIRECTORY
            };
        // SAFETY: each exact component is opened relative to the retained
        // protected ancestor descriptor; no symlink is followed.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), leaf.as_ptr(), flags) };
        if fd == -1 {
            return Err(format!(
                "installed release open: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned descriptor.
        let opened = unsafe { File::from_raw_fd(fd) };
        if final_component {
            return read_protected_opened(opened, maximum, exact_mode);
        }
        verify_directory(&opened)?;
        directory = opened;
    }
    Err("installed release path has no file component".into())
}

fn verify_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("installed release ancestor is not root-protected".into());
    }
    Ok(())
}

fn read_protected_opened(
    mut file: File,
    maximum: u64,
    exact_mode: Option<u32>,
) -> Result<Vec<u8>, String> {
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || (exact_mode.is_none() && before.mode() & 0o111 != 0)
        || exact_mode.is_some_and(|mode| before.mode() & 0o7777 != mode)
        || before.len() > maximum
    {
        return Err("installed release file is not an exact protected regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        )
    {
        return Err("installed release file changed during pinned readback".into());
    }
    Ok(bytes)
}
