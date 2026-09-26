//! Same-host final A installation, H1 activation and readback boundary.
//!
//! The expected A/M1/B/Q/CQ digests are root-protected release intent, not
//! values accepted from the downloaded archive. P must run on this host.

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::Deserialize;

use crate::{CiError, Result};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalHostReadbackV1 {
    schema_version: u8,
    source_commit: String,
    version: String,
    target: String,
    native_machine: String,
    boot_id: String,
    installation_epoch: DiagnosticSha256,
    installed_runtime_manifest_sha256: DiagnosticSha256,
    qualification_file_sha256: DiagnosticSha256,
    build_file_sha256: DiagnosticSha256,
    certificate_file_sha256: DiagnosticSha256,
    certificate_payload_sha256: DiagnosticSha256,
    public_cli_sha256: DiagnosticSha256,
    agent_sha256: DiagnosticSha256,
    arm32_helper_sha256: Option<DiagnosticSha256>,
    component_sha256: DiagnosticSha256,
    unit_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    policy_sha256: DiagnosticSha256,
    policy_version: u64,
    release_sequence: u64,
    active_h1_receipt_sha256: DiagnosticSha256,
    active_run_nonce: String,
    native_run_digest: DiagnosticSha256,
    host_prerequisites_digest: DiagnosticSha256,
}

impl FinalHostReadbackV1 {
    pub fn parse_bounded(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 64 * 1024 {
            return Err(CiError::Message(
                "final H1 readback is absent or unbounded".into(),
            ));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)
            .map_err(CiError::Message)?;
        let actual: Self = serde_json::from_slice(bytes)?;
        if actual.schema_version != 1
            || actual.active_h1_receipt_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || actual.native_run_digest == DiagnosticSha256::from_bytes([0; 32])
            || actual.active_run_nonce.len() != 64
            || !actual
                .active_run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(CiError::Message(
                "final H1 readback core identity differs".into(),
            ));
        }
        Ok(actual)
    }
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }
    pub fn target(&self) -> &str {
        &self.target
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn native_machine(&self) -> &str {
        &self.native_machine
    }
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }
    pub fn installation_epoch(&self) -> &DiagnosticSha256 {
        &self.installation_epoch
    }
    pub fn manifest_sha256(&self) -> &DiagnosticSha256 {
        &self.installed_runtime_manifest_sha256
    }
    pub fn qualification_sha256(&self) -> &DiagnosticSha256 {
        &self.qualification_file_sha256
    }
    pub fn public_cli_sha256(&self) -> &DiagnosticSha256 {
        &self.public_cli_sha256
    }
    pub fn agent_sha256(&self) -> &DiagnosticSha256 {
        &self.agent_sha256
    }
    pub fn arm32_helper_sha256(&self) -> Option<&DiagnosticSha256> {
        self.arm32_helper_sha256.as_ref()
    }
    pub fn active_h1_receipt_sha256(&self) -> &DiagnosticSha256 {
        &self.active_h1_receipt_sha256
    }
    pub fn component_sha256(&self) -> &DiagnosticSha256 {
        &self.component_sha256
    }
    pub fn unit_sha256(&self) -> &DiagnosticSha256 {
        &self.unit_sha256
    }
    pub fn filter_sha256(&self) -> &DiagnosticSha256 {
        &self.filter_sha256
    }
}

/// Expectations are obtained from the protected final-install intent, exact
/// archive component bytes, and the local boot, never from H1 JSON itself.
pub struct ExpectedFinalHostReadbackV1<'a> {
    pub source_commit: &'a str,
    pub version: &'a str,
    pub target: &'a str,
    pub native_machine: &'a str,
    pub boot_id: &'a str,
    pub installation_epoch: Option<&'a DiagnosticSha256>,
    pub manifest_sha256: &'a DiagnosticSha256,
    pub qualification_sha256: &'a DiagnosticSha256,
    pub build_sha256: &'a DiagnosticSha256,
    pub certificate_file_sha256: &'a DiagnosticSha256,
    pub certificate_payload_sha256: &'a DiagnosticSha256,
    pub public_cli_bytes: &'a [u8],
    pub agent_bytes: &'a [u8],
    pub arm32_helper_bytes: Option<&'a [u8]>,
    pub component_sha256: &'a DiagnosticSha256,
    pub unit_sha256: &'a DiagnosticSha256,
    pub filter_sha256: &'a DiagnosticSha256,
    pub policy_sha256: &'a DiagnosticSha256,
    pub policy_version: u64,
    pub release_sequence: u64,
}

/// Pure readback join shared by the same-host installer and portable tests.
/// The caller must authenticate the installed agent and protected H1 source.
pub fn validate_final_host_readback(
    bytes: &[u8],
    expected: &ExpectedFinalHostReadbackV1<'_>,
) -> Result<FinalHostReadbackV1> {
    let actual = FinalHostReadbackV1::parse_bounded(bytes)?;
    let zero = DiagnosticSha256::from_bytes([0; 32]);
    if actual.schema_version != 1
        || actual.source_commit != expected.source_commit
        || actual.version != expected.version
        || actual.target != expected.target
        || actual.native_machine != expected.native_machine
        || actual.boot_id != expected.boot_id
        || actual.installation_epoch == zero
        || expected
            .installation_epoch
            .is_some_and(|epoch| actual.installation_epoch != *epoch)
        || actual.installed_runtime_manifest_sha256 != *expected.manifest_sha256
        || actual.qualification_file_sha256 != *expected.qualification_sha256
        || actual.build_file_sha256 != *expected.build_sha256
        || actual.certificate_file_sha256 != *expected.certificate_file_sha256
        || actual.certificate_payload_sha256 != *expected.certificate_payload_sha256
        || actual.public_cli_sha256 != hash_bytes(expected.public_cli_bytes)
        || actual.agent_sha256 != hash_bytes(expected.agent_bytes)
        || actual.arm32_helper_sha256 != expected.arm32_helper_bytes.map(hash_bytes)
        || actual.component_sha256 != *expected.component_sha256
        || actual.unit_sha256 != *expected.unit_sha256
        || actual.filter_sha256 != *expected.filter_sha256
        || actual.policy_sha256 != *expected.policy_sha256
        || actual.policy_version != expected.policy_version
        || actual.release_sequence != expected.release_sequence
        || actual.active_h1_receipt_sha256 == zero
        || actual.native_run_digest == zero
        || actual.host_prerequisites_digest == zero
        || actual.active_run_nonce.len() != 64
        || !actual
            .active_run_nonce
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(CiError::Message(
            "final H1 readback release subject differs".into(),
        ));
    }
    Ok(actual)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use flate2::read::GzDecoder;
    use memcordon_core::DiagnosticSha256;
    use memcordon_core::private_release_build_v2::PrivateCandidateRecordV2;
    use memcordon_core::release_trust::SignedNativeQualificationCertificateV1;
    use memcordon_core::runtime_manifest_v3::{
        RuntimeManifestV3, RuntimeProfileAvailabilityV3, SealedRuntimeV3,
    };
    use memcordon_core::workload_codec::hash_bytes;
    use serde::Deserialize;

    use crate::command::CommandSpec;
    use crate::release_archive::{NATIVE_ARCHIVE_STATIC_PATHS, normalized_member_path};
    use crate::{CiError, Result};

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ProtectedFinalInstallIntentV1 {
        schema_version: u8,
        target: String,
        native_machine: String,
        source_commit: String,
        release_version: String,
        archive_sha256: DiagnosticSha256,
        archive_certificate_sha256: DiagnosticSha256,
        manifest_sha256: DiagnosticSha256,
        build_sha256: DiagnosticSha256,
        qualification_sha256: DiagnosticSha256,
        certificate_file_sha256: DiagnosticSha256,
        certificate_canonical_sha256: DiagnosticSha256,
        policy_sha256: DiagnosticSha256,
        policy_version: u64,
        release_sequence: u64,
    }

    fn fixed_paths(target: &str) -> Result<(&'static str, &'static str, &'static str)> {
        match target {
            "x86_64-unknown-linux-gnu" => Ok((
                "certification/workload/x64-private-build-v1.json",
                "certification/workload/x64-private-cq-v1.json",
                "certification/workload/linux-x64-private-v2.json",
            )),
            "aarch64-unknown-linux-gnu" => Ok((
                "certification/workload/arm64-private-build-v1.json",
                "certification/workload/arm64-private-cq-v1.json",
                "certification/workload/linux-arm64-private-v2.json",
            )),
            _ => Err(CiError::Message("final install target differs".into())),
        }
    }

    fn read_intent(path: &Path) -> Result<ProtectedFinalInstallIntentV1> {
        let bytes = crate::private_protected_readback::read_protected_raw_case_file(path)?;
        if bytes.len() > 16 * 1024 {
            return Err(CiError::Message(
                "final install intent exceeds bound".into(),
            ));
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)
            .map_err(CiError::Message)?;
        let intent: ProtectedFinalInstallIntentV1 = serde_json::from_slice(&bytes)?;
        if intent.schema_version != 1
            || intent.source_commit.len() != 40
            || !intent
                .source_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            || intent.release_version.is_empty()
            || intent.release_version.len() > 64
            || intent.policy_version == 0
            || intent.release_sequence == 0
            || intent.archive_certificate_sha256 == DiagnosticSha256::from_bytes([0; 32])
            || !matches!(
                (intent.target.as_str(), intent.native_machine.as_str()),
                ("x86_64-unknown-linux-gnu", "x86_64") | ("aarch64-unknown-linux-gnu", "aarch64")
            )
        {
            return Err(CiError::Message(
                "final install intent identity differs".into(),
            ));
        }
        Ok(intent)
    }

    fn archive_members(bytes: &[u8], root: &str) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut archive = tar::Archive::new(GzDecoder::new(Cursor::new(bytes)));
        let mut members = BTreeMap::new();
        let mut expanded = 0_u64;
        for entry in archive.entries()? {
            let mut entry = entry?;
            if !entry.header().entry_type().is_file() {
                return Err(CiError::Message(
                    "final A contains nonregular member".into(),
                ));
            }
            let full = entry.path()?.into_owned();
            if full
                .components()
                .next()
                .and_then(|part| part.as_os_str().to_str())
                != Some(root)
            {
                return Err(CiError::Message("final A package root differs".into()));
            }
            let relative = normalized_member_path(&full)?;
            let name = relative
                .to_str()
                .ok_or_else(|| CiError::Message("final A path is not UTF-8".into()))?;
            if name.is_empty() || name.len() > 256 || entry.size() > 128 * 1024 * 1024 {
                return Err(CiError::Message("final A member bound differs".into()));
            }
            expanded = expanded
                .checked_add(entry.size())
                .ok_or_else(|| CiError::Message("final A expansion overflow".into()))?;
            if expanded > 512 * 1024 * 1024 || members.len() >= 64 {
                return Err(CiError::Message(
                    "final A expanded inventory exceeds bound".into(),
                ));
            }
            let size = entry.size();
            let mut member = Vec::new();
            (&mut entry).take(size + 1).read_to_end(&mut member)?;
            if member.len() as u64 != size || members.insert(name.into(), member).is_some() {
                return Err(CiError::Message(
                    "final A duplicate or incomplete member".into(),
                ));
            }
        }
        Ok(members)
    }

    fn validate_members(
        members: &BTreeMap<String, Vec<u8>>,
        intent: &ProtectedFinalInstallIntentV1,
    ) -> Result<RuntimeManifestV3> {
        let get = |name: &str| {
            members
                .get(name)
                .ok_or_else(|| CiError::Message(format!("final A lacks {name}")))
        };
        let manifest_bytes = get("runtime-manifest.json")?;
        let manifest = RuntimeManifestV3::parse(manifest_bytes).map_err(CiError::Message)?;
        let (build_path, cq_path, q_path) = fixed_paths(&intent.target)?;
        let build_bytes = get(build_path)?;
        let cq_bytes = get(cq_path)?;
        let q_bytes = get(q_path)?;
        let build = PrivateCandidateRecordV2::parse(build_bytes).map_err(CiError::Message)?;
        let cq =
            SignedNativeQualificationCertificateV1::parse(cq_bytes).map_err(CiError::Message)?;
        let cq_canonical = cq.payload.canonical_bytes().map_err(CiError::Message)?;
        if manifest.version != intent.release_version
            || manifest.source_commit != intent.source_commit
            || manifest.target != intent.target
            || build.version != intent.release_version
            || build.source_commit != intent.source_commit
            || build.target != intent.target
            || hash_bytes(manifest_bytes) != intent.manifest_sha256
            || hash_bytes(build_bytes) != intent.build_sha256
            || hash_bytes(q_bytes) != intent.qualification_sha256
            || hash_bytes(cq_bytes) != intent.certificate_file_sha256
            || hash_bytes(&cq_canonical) != intent.certificate_canonical_sha256
            || cq.payload.build_sha256 != String::from(intent.build_sha256.clone())
            || cq.payload.qualification_sha256 != String::from(intent.qualification_sha256.clone())
            || cq.payload.target != intent.target
            || cq.payload.source_commit != intent.source_commit
            || cq.payload.release_version != intent.release_version
        {
            return Err(CiError::Message(
                "final A differs from protected release intent".into(),
            ));
        }
        let q_reference = match &manifest.sealed {
            SealedRuntimeV3::WorkloadV2 { profiles, .. } => {
                profiles.as_slice().iter().find_map(|profile| {
                    if let RuntimeProfileAvailabilityV3::Qualified { qualification } =
                        &profile.availability
                    {
                        Some(qualification)
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
        .ok_or_else(|| CiError::Message("final A M1 lacks private Q reference".into()))?;
        if q_reference.artifact != q_path
            || q_reference.artifact_sha256 != intent.qualification_sha256
        {
            return Err(CiError::Message("final A Q reference differs".into()));
        }
        let mut required = BTreeSet::from([
            "runtime-manifest.json".to_owned(),
            build_path.to_owned(),
            cq_path.to_owned(),
            q_path.to_owned(),
        ]);
        for path in NATIVE_ARCHIVE_STATIC_PATHS {
            required.insert((*path).into());
        }
        for component in &manifest.components {
            let bytes = get(&component.path)?;
            if bytes.len() as u64 != component.size
                || String::from(hash_bytes(bytes)) != component.sha256
                || component.mode != 0o755
                || !required.insert(component.path.clone())
            {
                return Err(CiError::Message("final A component differs".into()));
            }
        }
        if members.keys().cloned().collect::<BTreeSet<_>>() != required {
            return Err(CiError::Message("final A member inventory differs".into()));
        }
        Ok(manifest)
    }

    fn stage_members(
        directory: &Path,
        members: &BTreeMap<String, Vec<u8>>,
        manifest: &RuntimeManifestV3,
    ) -> Result<PathBuf> {
        for (name, bytes) in members {
            let relative = Path::new(name);
            if relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(CiError::Message("final A stage path differs".into()));
            }
            let path = directory.join(relative);
            fs::create_dir_all(
                path.parent()
                    .ok_or_else(|| CiError::Message("final A parent absent".into()))?,
            )?;
            let mode = if manifest
                .components
                .iter()
                .any(|component| component.path == *name)
            {
                0o755
            } else {
                0o644
            };
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        }
        Ok(directory.join("memcordon-sealed-agent"))
    }

    fn apply_final_same_host(
        root: &Path,
        intent_path: &Path,
        archive_path: &Path,
        operation: &str,
        prior_epoch: Option<&DiagnosticSha256>,
    ) -> Result<super::FinalHostReadbackV1> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(CiError::Message("final A install requires root".into()));
        }
        if let Some(epoch) = prior_epoch {
            let before = CommandSpec::new(
                "/usr/libexec/memcordon-sealed-agent",
                root,
                Duration::from_secs(30),
            )
            .remove_github_token()
            .args(["package", "verify-private-host", "--json"])
            .run()?;
            if super::FinalHostReadbackV1::parse_bounded(&before)?.installation_epoch() != epoch {
                return Err(CiError::Message("final upgrade E0 H1 epoch differs".into()));
            }
        }
        let intent = read_intent(intent_path)?;
        let metadata = fs::symlink_metadata(archive_path)?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 512 * 1024 * 1024 {
            return Err(CiError::Message(
                "final A archive size or type differs".into(),
            ));
        }
        let bytes = fs::read(archive_path)?;
        if bytes.len() as u64 != metadata.len() || hash_bytes(&bytes) != intent.archive_sha256 {
            return Err(CiError::Message(
                "final A archive digest differs from protected intent".into(),
            ));
        }
        let certificate_source = Path::new("/etc/memcordon/release-trust/archive-cert-v1.json");
        let certificate_bytes =
            crate::private_protected_readback::read_protected_raw_case_file(certificate_source)?;
        if certificate_bytes.len() > 128 * 1024
            || hash_bytes(&certificate_bytes) != intent.archive_certificate_sha256
        {
            return Err(CiError::Message(
                "detached A certificate differs from protected install intent".into(),
            ));
        }
        let archive_root = format!("memcordon-v{}-{}", intent.release_version, intent.target);
        let members = archive_members(&bytes, &archive_root)?;
        let manifest = validate_members(&members, &intent)?;
        let (build_path, _, _) = fixed_paths(&intent.target)?;
        let build =
            PrivateCandidateRecordV2::parse(members.get(build_path).expect("validated B member"))
                .map_err(CiError::Message)?;
        let protected_root = Path::new("/run/memcordon-final-install");
        if matches!(fs::symlink_metadata(protected_root), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
        {
            fs::create_dir(protected_root)?;
            fs::set_permissions(protected_root, fs::Permissions::from_mode(0o700))?;
        }
        let root_meta = fs::symlink_metadata(protected_root)?;
        if !root_meta.is_dir() || root_meta.uid() != 0 || root_meta.mode() & 0o7777 != 0o700 {
            return Err(CiError::Message(
                "final A staging root custody differs".into(),
            ));
        }
        let staging = tempfile::Builder::new()
            .prefix("memcordon-final-a-")
            .tempdir_in(protected_root)?;
        let stage_leaf = |name: &str, value: &[u8]| -> Result<std::path::PathBuf> {
            let path = staging.path().join(name);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(value)?;
            file.sync_all()?;
            Ok(path)
        };
        let sealed_archive = stage_leaf("archive.tar.gz", &bytes)?;
        let sealed_certificate = stage_leaf("archive-cert-v1.json", &certificate_bytes)?;
        let agent = stage_members(staging.path(), &members, &manifest)?;
        CommandSpec::new(&agent, root, Duration::from_secs(180))
            .remove_github_token()
            .args(["package", operation, "--ephemeral-ci", "--archive-path"])
            .arg(sealed_archive.as_os_str())
            .arg("--archive-certificate")
            .arg(sealed_certificate.as_os_str())
            .run()?;
        CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            root,
            Duration::from_secs(180),
        )
        .remove_github_token()
        .args(["package", "qualify-private"])
        .run()?;
        // The final readback command revalidates current M1/B/Q/CQ and H1
        // under the package lock. An absent or stale H1 is a hard failure.
        let readback = CommandSpec::new(
            "/usr/libexec/memcordon-sealed-agent",
            root,
            Duration::from_secs(30),
        )
        .remove_github_token()
        .args(["package", "verify-private-host", "--json"])
        .run()?;
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let host = super::validate_final_host_readback(
            &readback,
            &super::ExpectedFinalHostReadbackV1 {
                source_commit: &intent.source_commit,
                version: &intent.release_version,
                target: &intent.target,
                native_machine: &intent.native_machine,
                boot_id: boot.trim(),
                installation_epoch: None,
                manifest_sha256: &intent.manifest_sha256,
                qualification_sha256: &intent.qualification_sha256,
                build_sha256: &intent.build_sha256,
                certificate_file_sha256: &intent.certificate_file_sha256,
                certificate_payload_sha256: &intent.certificate_canonical_sha256,
                public_cli_bytes: members.get("memcordon").expect("required CLI"),
                agent_bytes: members
                    .get("memcordon-sealed-agent")
                    .expect("required agent"),
                arm32_helper_bytes: members.get("memcordon-arm32-abi-helper").map(Vec::as_slice),
                component_sha256: &build.component_sha256,
                unit_sha256: &build.unit_sha256,
                filter_sha256: &build.filter_sha256,
                policy_sha256: &intent.policy_sha256,
                policy_version: intent.policy_version,
                release_sequence: intent.release_sequence,
            },
        )?;
        if prior_epoch.is_some_and(|epoch| host.installation_epoch() == epoch) {
            return Err(CiError::Message(
                "final upgrade did not advance installation epoch".into(),
            ));
        }
        Ok(host)
    }

    pub fn install_final_same_host(
        root: &Path,
        intent_path: &Path,
        archive_path: &Path,
    ) -> Result<()> {
        apply_final_same_host(root, intent_path, archive_path, "install", None).map(|_| ())
    }

    pub fn upgrade_final_same_host(
        root: &Path,
        intent_path: &Path,
        archive_path: &Path,
        prior_epoch: &DiagnosticSha256,
    ) -> Result<super::FinalHostReadbackV1> {
        apply_final_same_host(
            root,
            intent_path,
            archive_path,
            "upgrade",
            Some(prior_epoch),
        )
    }
}

#[cfg(target_os = "linux")]
pub use linux::{install_final_same_host, upgrade_final_same_host};

#[cfg(not(target_os = "linux"))]
pub fn install_final_same_host(
    _root: &std::path::Path,
    _intent: &std::path::Path,
    _archive: &std::path::Path,
) -> crate::Result<()> {
    Err(crate::CiError::Message(
        "final private install requires a native Linux host".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn upgrade_final_same_host(
    _root: &std::path::Path,
    _intent_path: &std::path::Path,
    _archive_path: &std::path::Path,
    _prior_epoch: &DiagnosticSha256,
) -> Result<FinalHostReadbackV1> {
    Err(CiError::Message("final A upgrade requires Linux".into()))
}
