//! Exact Q -> final M1 -> installed V6 readback join for a Linux private release.
//!
//! The caller owns independent native-run, build and installed-host inputs.
//! This verifier never derives trusted expectations from the submitted JSON.

use memcordon_core::DiagnosticSha256;
use memcordon_core::package_inspection_v6::{
    LinuxInstalledInspectionV6, NetworkLauncherStateV6, TrustedLinuxInspectionV6,
};
pub use memcordon_core::private_release_build_v2::{
    PrivateCandidateRecordV2, PrivateCandidateStageV2,
};
use memcordon_core::release_trust::SignedNativeQualificationCertificateV1;
use memcordon_core::runtime_manifest::RuntimeComponentRecord;
use memcordon_core::runtime_manifest_v3::{
    QualificationArtifactReferenceV2, RuntimeManifestV3, RuntimeProfileAvailabilityV3,
    SealedRuntimeV3, ValidatedQualificationReferenceV2,
};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_qualification_v2::{
    QualificationArtifactV2, TrustedQualificationExpectationV2,
};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read, Write};
use std::path::Path;

use crate::private_native::FinalInstalledBindingV2;
use crate::workload_qualification::{
    private_component_digest_v2, private_unit_digest_v2, validate_private_v2_against_build,
};
use crate::{CiError, Result};

pub struct VerifiedPrivateReleaseReadbackV2 {
    pub qualification: QualificationArtifactV2,
    pub runtime_manifest: RuntimeManifestV3,
    pub installed_inspection: LinuxInstalledInspectionV6,
}

/// The immutable B/M0 candidate identity. None of these fields depends on Q,
/// an installed receipt, a final archive or public acceptance.
pub struct PreparedPrivateCandidateV2 {
    pub manifest: RuntimeManifestV3,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: DiagnosticSha256,
    pub component_sha256: DiagnosticSha256,
    pub unit_sha256: DiagnosticSha256,
    pub filter_sha256: DiagnosticSha256,
}

/// Prepared M1 from the unchanged executable B and independently verified Q.
/// The caller must obtain `expected` from trusted native/platform provenance;
/// this constructor does not authenticate those inputs by itself.
pub struct PreparedPrivateFinalManifestV2 {
    manifest: RuntimeManifestV3,
    manifest_bytes: Vec<u8>,
    manifest_sha256: DiagnosticSha256,
}

impl PreparedPrivateFinalManifestV2 {
    pub fn manifest(&self) -> &RuntimeManifestV3 {
        &self.manifest
    }

    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    pub fn manifest_sha256(&self) -> &DiagnosticSha256 {
        &self.manifest_sha256
    }
}

pub fn prepare_private_final_manifest(
    candidate: &PreparedPrivateCandidateV2,
    qualification_bytes: &[u8],
    reference: QualificationArtifactReferenceV2,
    expected: &TrustedQualificationExpectationV2<'_>,
) -> Result<PreparedPrivateFinalManifestV2> {
    let build = &candidate.manifest;
    if RuntimeManifestV3::parse(&candidate.manifest_bytes).map_err(CiError::Message)? != *build
        || hash_bytes(&candidate.manifest_bytes) != candidate.manifest_sha256
        || private_component_digest_v2(
            &build.target,
            &build.source_commit,
            &build.version,
            &build.components,
        )? != candidate.component_sha256
        || build.source_commit != expected.source_commit
        || build.target != expected.target
        || candidate.component_sha256 != *expected.component_digest
        || candidate.unit_sha256 != *expected.unit_digest
        || candidate.filter_sha256 != *expected.filter_digest
    {
        return Err(CiError::Message(
            "private final manifest qualification differs from candidate B".into(),
        ));
    }
    validate_private_v2_against_build(
        qualification_bytes,
        &reference,
        expected,
        &build.version,
        &build.components,
    )?;
    let validated = ValidatedQualificationReferenceV2::from_verified_artifact(
        qualification_bytes,
        reference,
        expected,
    )
    .map_err(CiError::Message)?;
    let manifest = RuntimeManifestV3::linux_with_qualifications(
        build.version.clone(),
        build.source_commit.clone(),
        build.target.clone(),
        build.components.clone(),
        Some(validated),
    )
    .map_err(CiError::Message)?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    Ok(PreparedPrivateFinalManifestV2 {
        manifest_sha256: hash_bytes(&manifest_bytes),
        manifest,
        manifest_bytes,
    })
}

impl PreparedPrivateCandidateV2 {
    pub fn record(&self) -> PrivateCandidateRecordV2 {
        PrivateCandidateRecordV2 {
            schema_version: 2,
            stage: PrivateCandidateStageV2::UnqualifiedCandidate,
            version: self.manifest.version.clone(),
            source_commit: self.manifest.source_commit.clone(),
            target: self.manifest.target.clone(),
            runtime_manifest_sha256: self.manifest_sha256.clone(),
            component_sha256: self.component_sha256.clone(),
            unit_sha256: self.unit_sha256.clone(),
            filter_sha256: self.filter_sha256.clone(),
        }
    }
}

/// Recompute `expected` from opened executable bytes and independently read
/// package V6 metadata; the submitted record is never its own expectation.
pub fn validate_private_candidate_record(
    record_bytes: &[u8],
    expected: &PreparedPrivateCandidateV2,
) -> Result<PrivateCandidateRecordV2> {
    if record_bytes.len() > 16 * 1024 {
        return Err(CiError::Message(
            "private candidate record exceeds bound".into(),
        ));
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(record_bytes)
        .map_err(CiError::Message)?;
    let actual = PrivateCandidateRecordV2::parse(record_bytes).map_err(CiError::Message)?;
    if actual != expected.record() {
        return Err(CiError::Message(
            "private candidate B/M0 record differs".into(),
        ));
    }
    Ok(actual)
}

pub struct PrivateCandidateInputs<'a> {
    pub version: &'a str,
    pub source_commit: &'a str,
    pub target: &'a str,
    pub components: &'a [RuntimeComponentRecord],
    pub component_bytes: &'a BTreeMap<String, Vec<u8>>,
    pub compiled_units: &'a memcordon_core::package_inspection_v6::LinuxUnitHashesV6,
    /// Filter digest from an independently read back, pinned agent B.
    pub filter_sha256: &'a DiagnosticSha256,
}

pub fn prepare_private_candidate(
    inputs: PrivateCandidateInputs<'_>,
) -> Result<PreparedPrivateCandidateV2> {
    if !matches!(
        inputs.target,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) || inputs.components.len() != inputs.component_bytes.len()
    {
        return Err(CiError::Message(
            "private candidate build inventory differs".into(),
        ));
    }
    let mut seen = BTreeSet::new();
    for component in inputs.components {
        let bytes = inputs.component_bytes.get(&component.path).ok_or_else(|| {
            CiError::Message("private candidate lacks executable component bytes".into())
        })?;
        if !seen.insert(component.path.as_str())
            || bytes.len() as u64 != component.size
            || String::from(hash_bytes(bytes)) != component.sha256
        {
            return Err(CiError::Message(
                "private candidate executable differs".into(),
            ));
        }
    }
    let component_sha256 = private_component_digest_v2(
        inputs.target,
        inputs.source_commit,
        inputs.version,
        inputs.components,
    )?;
    let manifest = RuntimeManifestV3::linux_unqualified(
        inputs.version.into(),
        inputs.source_commit.into(),
        inputs.target.into(),
        inputs.components.to_vec(),
    )
    .map_err(CiError::Message)?;
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    Ok(PreparedPrivateCandidateV2 {
        manifest_sha256: hash_bytes(&manifest_bytes),
        component_sha256,
        unit_sha256: private_unit_digest_v2(inputs.compiled_units),
        filter_sha256: inputs.filter_sha256.clone(),
        manifest,
        manifest_bytes,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivateArchiveFormat {
    TarGz,
    Zip,
}

/// Independently reviewed member bytes must include the exact executables,
/// M1 and Q; no archive member is allowed merely because the archive lists it.
pub struct QualifiedArchiveExpectation<'a> {
    pub format: PrivateArchiveFormat,
    pub members: &'a BTreeMap<String, Vec<u8>>,
    pub final_manifest: &'a PreparedPrivateFinalManifestV2,
    pub qualification_bytes: &'a [u8],
    /// Exact candidate B bytes authenticated by the completed-job collector.
    pub candidate_record_bytes: &'a [u8],
    /// Signed Q decision. Signature/role/trust-root validation is performed by
    /// the installed verifier, not by this archive format reader.
    pub certificate_bytes: &'a [u8],
}

fn release_build_and_certificate_paths(target: &str) -> Result<(String, String)> {
    let short = match target {
        "x86_64-unknown-linux-gnu" => "x64",
        "aarch64-unknown-linux-gnu" => "arm64",
        _ => return Err(CiError::Message("private release target differs".into())),
    };
    Ok((
        format!("certification/workload/{short}-private-build-v1.json"),
        format!("certification/workload/{short}-private-cq-v1.json"),
    ))
}

/// Seals the independently supplied fixed B/M1/Q/document inventory, then
/// reads it back before returning bytes. The caller still must authenticate Q,
/// the installed H1 readback, and the source of every member independently.
pub fn seal_qualified_archive(
    expected: &QualifiedArchiveExpectation<'_>,
) -> Result<(Vec<u8>, DiagnosticSha256)> {
    if expected.members.len() > 64
        || expected
            .members
            .values()
            .any(|member| member.len() > 256 * 1024 * 1024)
        || expected
            .members
            .values()
            .try_fold(0usize, |total, member| total.checked_add(member.len()))
            .is_none_or(|total| total > 512 * 1024 * 1024)
    {
        return Err(CiError::Message("private archive exceeds bound".into()));
    }
    let manifest = expected.final_manifest.manifest();
    let root = format!("memcordon-v{}-{}", manifest.version, manifest.target);
    let bytes = match expected.format {
        PrivateArchiveFormat::TarGz => {
            let encoder = flate2::GzBuilder::new()
                .mtime(0)
                .write(Vec::new(), flate2::Compression::default());
            let mut archive = tar::Builder::new(encoder);
            for (relative, member) in expected.members {
                let mut header = tar::Header::new_gnu();
                header.set_size(member.len() as u64);
                header.set_mode(
                    manifest
                        .components
                        .iter()
                        .find(|component| component.path == *relative)
                        .map_or(0o644, |component| component.mode),
                );
                header.set_cksum();
                archive.append_data(
                    &mut header,
                    Path::new(&root).join(relative),
                    member.as_slice(),
                )?;
            }
            archive.into_inner()?.finish()?
        }
        PrivateArchiveFormat::Zip => {
            let mut archive = zip::ZipWriter::new(Cursor::new(Vec::new()));
            for (relative, member) in expected.members {
                let mode = manifest
                    .components
                    .iter()
                    .find(|component| component.path == *relative)
                    .map_or(0o644, |component| component.mode);
                let options = zip::write::SimpleFileOptions::default()
                    .system(zip::System::Unix)
                    .unix_permissions(mode);
                let member_path = Path::new(&root).join(relative);
                archive.start_file(member_path.to_string_lossy().into_owned(), options)?;
                archive.write_all(member)?;
            }
            archive.finish()?.into_inner()
        }
    };
    let digest = validate_qualified_archive(&bytes, expected)?;
    Ok((bytes, digest))
}

pub fn validate_qualified_archive(
    archive_bytes: &[u8],
    expected: &QualifiedArchiveExpectation<'_>,
) -> Result<DiagnosticSha256> {
    const MAX_ARCHIVE_BYTES: usize = 512 * 1024 * 1024;
    const MAX_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
    if archive_bytes.len() > MAX_ARCHIVE_BYTES || expected.members.len() > 64 {
        return Err(CiError::Message("private archive exceeds bound".into()));
    }
    let manifest = expected.final_manifest.manifest();
    let qualification_reference = match &manifest.sealed {
        SealedRuntimeV3::WorkloadV2 { profiles, .. } => profiles
            .as_slice()
            .iter()
            .find_map(|profile| match &profile.availability {
                RuntimeProfileAvailabilityV3::Qualified { qualification } => Some(qualification),
                _ => None,
            })
            .ok_or_else(|| CiError::Message("qualified archive lacks Q reference".into()))?,
        _ => return Err(CiError::Message("qualified archive lacks Linux V3".into())),
    };
    let manifest_bytes = expected
        .members
        .get("runtime-manifest.json")
        .ok_or_else(|| CiError::Message("qualified archive lacks M1".into()))?;
    if manifest_bytes != expected.final_manifest.manifest_bytes()
        || RuntimeManifestV3::parse(manifest_bytes).map_err(CiError::Message)? != *manifest
        || hash_bytes(manifest_bytes) != *expected.final_manifest.manifest_sha256()
    {
        return Err(CiError::Message("qualified archive M1 differs".into()));
    }
    let qualification_bytes = expected
        .members
        .get(&qualification_reference.artifact)
        .ok_or_else(|| CiError::Message("qualified archive lacks Q".into()))?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(qualification_bytes)
        .map_err(CiError::Message)?;
    let parsed_q: QualificationArtifactV2 = serde_json::from_slice(qualification_bytes)?;
    if hash_bytes(qualification_bytes) != qualification_reference.artifact_sha256
        || qualification_bytes != expected.qualification_bytes
        || parsed_q.target.as_str() != manifest.target
        || parsed_q.source_commit.as_str() != manifest.source_commit
        || parsed_q.profile != qualification_reference.profile
        || qualification_reference.qualified_target != manifest.target
        || qualification_reference.source_commit != manifest.source_commit
    {
        return Err(CiError::Message("qualified archive Q differs".into()));
    }
    let (build_path, certificate_path) = release_build_and_certificate_paths(&manifest.target)?;
    let build_bytes = expected
        .members
        .get(&build_path)
        .ok_or_else(|| CiError::Message("qualified archive lacks exact candidate B".into()))?;
    let certificate_bytes = expected
        .members
        .get(&certificate_path)
        .ok_or_else(|| CiError::Message("qualified archive lacks signed Q certificate".into()))?;
    if build_bytes != expected.candidate_record_bytes
        || certificate_bytes != expected.certificate_bytes
        || build_bytes.len() > 16 * 1024
    {
        return Err(CiError::Message(
            "qualified archive B/CQ bytes differ".into(),
        ));
    }
    let build = PrivateCandidateRecordV2::parse(build_bytes).map_err(CiError::Message)?;
    let certificate = SignedNativeQualificationCertificateV1::parse(certificate_bytes)
        .map_err(CiError::Message)?;
    if build.schema_version != 2
        || build.stage != PrivateCandidateStageV2::UnqualifiedCandidate
        || build.version != manifest.version
        || build.source_commit != manifest.source_commit
        || build.target != manifest.target
        || build.component_sha256 != parsed_q.component_digest
        || build.unit_sha256 != parsed_q.unit_digest
        || build.filter_sha256 != parsed_q.filter_digest
        || certificate.payload.build_sha256 != String::from(hash_bytes(build_bytes))
        || certificate.payload.qualification_sha256 != String::from(hash_bytes(qualification_bytes))
        || certificate.payload.qualification_size != qualification_bytes.len() as u64
        || certificate.payload.target != manifest.target
        || certificate.payload.source_commit != manifest.source_commit
        || certificate.payload.release_version != manifest.version
        || certificate.payload.decision != "Complete"
        || certificate.payload.canonical_bytes().is_err()
    {
        return Err(CiError::Message(
            "qualified archive B/Q/CQ binding differs".into(),
        ));
    }
    let expected_root = format!("memcordon-v{}-{}", manifest.version, manifest.target);
    let mut expected_modes = BTreeMap::new();
    let mut required_members = BTreeSet::from([
        "runtime-manifest.json",
        qualification_reference.artifact.as_str(),
        build_path.as_str(),
        certificate_path.as_str(),
    ]);
    for component in &manifest.components {
        let bytes = expected
            .members
            .get(&component.path)
            .ok_or_else(|| CiError::Message("qualified archive lacks B component".into()))?;
        if bytes.len() as u64 != component.size
            || String::from(hash_bytes(bytes)) != component.sha256
        {
            return Err(CiError::Message("qualified archive B differs".into()));
        }
        if !required_members.insert(&component.path) {
            return Err(CiError::Message(
                "qualified archive member roles overlap".into(),
            ));
        }
        expected_modes.insert(component.path.as_str(), component.mode);
    }
    for path in crate::release_archive::NATIVE_ARCHIVE_STATIC_PATHS {
        if !required_members.insert(path) {
            return Err(CiError::Message(
                "qualified archive member roles overlap".into(),
            ));
        }
    }
    if expected
        .members
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != required_members
    {
        return Err(CiError::Message(
            "qualified archive member inventory differs from reviewed release inventory".into(),
        ));
    }
    for path in expected.members.keys() {
        let rooted = Path::new(&expected_root).join(path);
        if crate::release_archive::normalized_member_path(&rooted)? != Path::new(path) {
            return Err(CiError::Message(
                "private archive expectation path is unsafe".into(),
            ));
        }
    }
    let mut seen = BTreeSet::new();
    let mut expanded_bytes = 0usize;
    let mut check = |name: &str, mode: u32, bytes: &[u8]| -> Result<()> {
        expanded_bytes = expanded_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| CiError::Message("private archive expands beyond bound".into()))?;
        if expanded_bytes > MAX_ARCHIVE_BYTES {
            return Err(CiError::Message(
                "private archive expands beyond bound".into(),
            ));
        }
        let rooted = Path::new(name);
        if rooted.components().next().map(|part| part.as_os_str())
            != Some(std::ffi::OsStr::new(&expected_root))
        {
            return Err(CiError::Message("private archive has wrong root".into()));
        }
        let relative = crate::release_archive::normalized_member_path(rooted)?;
        let key = relative
            .to_str()
            .ok_or_else(|| CiError::Message("private archive path is not UTF-8".into()))?;
        if !seen.insert(key.to_owned())
            || expected.members.get(key).map(Vec::as_slice) != Some(bytes)
        {
            return Err(CiError::Message("private archive member differs".into()));
        }
        let required_mode = expected_modes.get(key).copied().unwrap_or(0o644);
        if mode & 0o777 != required_mode {
            return Err(CiError::Message(
                "private archive member mode differs".into(),
            ));
        }
        Ok(())
    };
    match expected.format {
        PrivateArchiveFormat::TarGz => {
            let decoder = flate2::read::GzDecoder::new(Cursor::new(archive_bytes));
            let mut archive = tar::Archive::new(decoder);
            for entry in archive.entries()? {
                let mut entry = entry?;
                if !entry.header().entry_type().is_file() || entry.size() > MAX_MEMBER_BYTES {
                    return Err(CiError::Message(
                        "private archive has non-file or oversized member".into(),
                    ));
                }
                let name = entry.path()?.to_string_lossy().into_owned();
                let mode = entry.header().mode()?;
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                check(&name, mode, &bytes)?;
            }
        }
        PrivateArchiveFormat::Zip => {
            let mut archive = zip::ZipArchive::new(Cursor::new(archive_bytes))?;
            for index in 0..archive.len() {
                let mut entry = archive.by_index(index)?;
                if !entry.is_file() || entry.size() > MAX_MEMBER_BYTES {
                    return Err(CiError::Message(
                        "private archive has non-file or oversized member".into(),
                    ));
                }
                let name = entry.name().to_owned();
                let mode = entry
                    .unix_mode()
                    .ok_or_else(|| CiError::Message("private archive lacks member mode".into()))?;
                if mode & 0o170000 != 0o100000 {
                    return Err(CiError::Message(
                        "private ZIP member is not a regular file".into(),
                    ));
                }
                let mut bytes = Vec::new();
                entry.read_to_end(&mut bytes)?;
                check(&name, mode, &bytes)?;
            }
        }
    }
    if seen.len() != expected.members.len() {
        return Err(CiError::Message(
            "private archive omits expected member".into(),
        ));
    }
    Ok(hash_bytes(archive_bytes))
}

pub struct QualifiedLinuxReadbackInputs<'a> {
    pub qualification_bytes: &'a [u8],
    pub qualification_reference: &'a QualificationArtifactReferenceV2,
    pub expected_qualification: &'a TrustedQualificationExpectationV2<'a>,
    pub version: &'a str,
    pub components: &'a [RuntimeComponentRecord],
    pub runtime_manifest_bytes: &'a [u8],
    pub installed_inspection_bytes: &'a [u8],
    pub trusted_installed: &'a TrustedLinuxInspectionV6<'a>,
}

pub fn validate_qualified_linux_readback(
    inputs: QualifiedLinuxReadbackInputs<'_>,
) -> Result<VerifiedPrivateReleaseReadbackV2> {
    let QualifiedLinuxReadbackInputs {
        qualification_bytes,
        qualification_reference,
        expected_qualification,
        version,
        components,
        runtime_manifest_bytes,
        installed_inspection_bytes,
        trusted_installed,
    } = inputs;
    let qualification = validate_private_v2_against_build(
        qualification_bytes,
        qualification_reference,
        expected_qualification,
        version,
        components,
    )?;
    if qualification.unit_digest != private_unit_digest_v2(trusted_installed.unit_hashes)
        || qualification.filter_digest != *trusted_installed.filter_sha256
    {
        return Err(CiError::Message(
            "private qualification units or filter differ from installed readback".into(),
        ));
    }
    let validated_reference = ValidatedQualificationReferenceV2::from_verified_artifact(
        qualification_bytes,
        qualification_reference.clone(),
        expected_qualification,
    )
    .map_err(CiError::Message)?;
    let expected_manifest = RuntimeManifestV3::linux_with_qualifications(
        version.into(),
        expected_qualification.source_commit.into(),
        expected_qualification.target.into(),
        components.to_vec(),
        Some(validated_reference),
    )
    .map_err(CiError::Message)?;
    let manifest = RuntimeManifestV3::parse(runtime_manifest_bytes).map_err(CiError::Message)?;
    if manifest != expected_manifest {
        return Err(CiError::Message(
            "final Linux V3 manifest differs from verified Q and build B".into(),
        ));
    }
    let inspection = LinuxInstalledInspectionV6::parse_and_validate(
        installed_inspection_bytes,
        runtime_manifest_bytes,
        trusted_installed,
    )
    .map_err(CiError::Message)?;
    if inspection.network_launcher_state != NetworkLauncherStateV6::EnabledQualified
        || inspection.private_qualification.as_ref() != Some(qualification_reference)
        || inspection.installed_qualification_sha256.is_none()
        || !inspection.provider_reachable
    {
        return Err(CiError::Message(
            "final Linux V6 readback lacks qualified installed host".into(),
        ));
    }
    Ok(VerifiedPrivateReleaseReadbackV2 {
        qualification,
        runtime_manifest: manifest,
        installed_inspection: inspection,
    })
}

/// Offline qualified asset assembly. The native Q expectation, static source
/// members, and installed H1 expectation must be obtained independently by the
/// caller; this API cannot turn caller-supplied values into release authority.
#[derive(Clone)]
pub struct OfflinePrivateQualifiedInputs<'a> {
    pub candidate: &'a PreparedPrivateCandidateV2,
    pub qualification_bytes: &'a [u8],
    pub candidate_record_bytes: &'a [u8],
    pub certificate_bytes: &'a [u8],
    pub qualification_reference: QualificationArtifactReferenceV2,
    pub expected_qualification: &'a TrustedQualificationExpectationV2<'a>,
    pub component_bytes: &'a BTreeMap<String, Vec<u8>>,
    pub static_bytes: &'a BTreeMap<String, Vec<u8>>,
    pub archive_format: PrivateArchiveFormat,
    pub installed_inspection_bytes: &'a [u8],
    pub trusted_installed: &'a TrustedLinuxInspectionV6<'a>,
}

pub struct OfflinePrivateQualifiedResultV2 {
    final_manifest: PreparedPrivateFinalManifestV2,
    archive_bytes: Vec<u8>,
    archive_sha256: DiagnosticSha256,
    installed_readback: VerifiedPrivateReleaseReadbackV2,
}

impl OfflinePrivateQualifiedResultV2 {
    pub fn final_manifest(&self) -> &PreparedPrivateFinalManifestV2 {
        &self.final_manifest
    }

    pub fn archive_bytes(&self) -> &[u8] {
        &self.archive_bytes
    }

    pub fn archive_sha256(&self) -> &DiagnosticSha256 {
        &self.archive_sha256
    }

    pub fn installed_readback(&self) -> &VerifiedPrivateReleaseReadbackV2 {
        &self.installed_readback
    }

    /// Values for the later P stage, projected from sealed A, exact M1 and
    /// separately validated installed H1; never copied from a P envelope.
    pub fn expected_final_public_binding(&self) -> Result<FinalInstalledBindingV2> {
        let installed_receipt_sha256 = self
            .installed_readback
            .installed_inspection
            .installed_qualification_sha256
            .as_ref()
            .ok_or_else(|| CiError::Message("qualified H1 lacks installed receipt".into()))?;
        Ok(FinalInstalledBindingV2 {
            archive_sha256: self.archive_sha256.clone(),
            runtime_manifest_sha256: self.final_manifest.manifest_sha256().clone(),
            installed_receipt_sha256: installed_receipt_sha256.clone(),
        })
    }
}

pub fn prepare_private_qualified_offline(
    inputs: OfflinePrivateQualifiedInputs<'_>,
) -> Result<OfflinePrivateQualifiedResultV2> {
    let final_manifest = prepare_private_final_manifest(
        inputs.candidate,
        inputs.qualification_bytes,
        inputs.qualification_reference.clone(),
        inputs.expected_qualification,
    )?;
    let mut members = BTreeMap::new();
    for component in &final_manifest.manifest().components {
        let bytes = inputs.component_bytes.get(&component.path).ok_or_else(|| {
            CiError::Message("offline qualified asset lacks candidate B component".into())
        })?;
        members.insert(component.path.clone(), bytes.clone());
    }
    if inputs.component_bytes.len() != final_manifest.manifest().components.len() {
        return Err(CiError::Message(
            "offline qualified asset has surplus B component".into(),
        ));
    }
    for path in crate::release_archive::NATIVE_ARCHIVE_STATIC_PATHS {
        let bytes = inputs.static_bytes.get(*path).ok_or_else(|| {
            CiError::Message("offline qualified asset lacks reviewed static member".into())
        })?;
        if members.insert((*path).into(), bytes.clone()).is_some() {
            return Err(CiError::Message(
                "offline qualified asset member roles overlap".into(),
            ));
        }
    }
    if inputs.static_bytes.len() != crate::release_archive::NATIVE_ARCHIVE_STATIC_PATHS.len()
        || members
            .insert(
                inputs.qualification_reference.artifact.clone(),
                inputs.qualification_bytes.to_vec(),
            )
            .is_some()
        || members
            .insert(
                "runtime-manifest.json".into(),
                final_manifest.manifest_bytes().to_vec(),
            )
            .is_some()
    {
        return Err(CiError::Message(
            "offline qualified asset inventory differs".into(),
        ));
    }
    validate_private_candidate_record(inputs.candidate_record_bytes, inputs.candidate)?;
    let (build_path, certificate_path) =
        release_build_and_certificate_paths(&final_manifest.manifest().target)?;
    if members
        .insert(build_path, inputs.candidate_record_bytes.to_vec())
        .is_some()
        || members
            .insert(certificate_path, inputs.certificate_bytes.to_vec())
            .is_some()
    {
        return Err(CiError::Message(
            "offline qualified asset member roles overlap".into(),
        ));
    }
    let (archive_bytes, archive_sha256) = seal_qualified_archive(&QualifiedArchiveExpectation {
        format: inputs.archive_format,
        members: &members,
        final_manifest: &final_manifest,
        qualification_bytes: inputs.qualification_bytes,
        candidate_record_bytes: inputs.candidate_record_bytes,
        certificate_bytes: inputs.certificate_bytes,
    })?;
    let installed_readback = validate_qualified_linux_readback(QualifiedLinuxReadbackInputs {
        qualification_bytes: inputs.qualification_bytes,
        qualification_reference: &inputs.qualification_reference,
        expected_qualification: inputs.expected_qualification,
        version: &final_manifest.manifest().version,
        components: &final_manifest.manifest().components,
        runtime_manifest_bytes: final_manifest.manifest_bytes(),
        installed_inspection_bytes: inputs.installed_inspection_bytes,
        trusted_installed: inputs.trusted_installed,
    })?;
    Ok(OfflinePrivateQualifiedResultV2 {
        final_manifest,
        archive_bytes,
        archive_sha256,
        installed_readback,
    })
}
