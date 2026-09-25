//! Independent static installed-H0 readback for an unqualified Linux candidate.
//!
//! This measures fixed installed files instead of taking hashes from the
//! native case report. It does not establish service reachability, kernel
//! observation, or authority to produce a qualification artifact.

#[cfg(target_os = "linux")]
use std::path::Path;

use memcordon_core::DiagnosticSha256;
use memcordon_core::package_inspection_v6::{
    LinuxInstalledInspectionV6, LinuxUnitHashesV6, NetworkLauncherStateV6,
};
use memcordon_core::runtime_manifest::RuntimeComponentRole;
use memcordon_core::runtime_manifest_v3::{RuntimeManifestV3, SealedRuntimeV3};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;

use crate::private_protected_readback::ProtectedCandidateReleaseRequestV1;
use crate::release_private::PreparedPrivateCandidateV2;
use crate::workload_qualification::private_unit_digest_v2;
use crate::{CiError, Result};

#[cfg(target_os = "linux")]
const MANIFEST: &str = "/usr/libexec/memcordon-runtime-manifest.json";
#[cfg(target_os = "linux")]
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";
#[cfg(target_os = "linux")]
const INSTALLATION_EPOCH: &str = "/usr/libexec/.memcordon-installation-epoch.json";
#[cfg(target_os = "linux")]
const PACKAGE_JOURNAL: &str = "/usr/libexec/.memcordon-package-transaction.json";
#[cfg(target_os = "linux")]
const UNIT_PATHS: [&str; 7] = [
    "/usr/lib/systemd/system/memcordon-sealed-agent.service",
    "/usr/lib/systemd/system/memcordon-sealed-agent.socket",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.service",
    "/usr/lib/systemd/system/memcordon-sealed-launcher.socket",
    "/usr/lib/tmpfiles.d/memcordon.conf",
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service",
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket",
];

pub struct InstalledH0StaticBytes {
    pub manifest: Vec<u8>,
    pub agent: Vec<u8>,
    pub units: [Vec<u8>; 7],
}

/// Independent installed image identity for target-side `/proc/self/exe`
/// comparison. This reopens the fixed image rather than accepting a dev/ino
/// from the native result. It is structural, not pinned native owner custody.
#[cfg(target_os = "linux")]
pub fn read_fixed_agent_identity(expected_bytes: &[u8]) -> Result<(u64, u64)> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if expected_bytes.is_empty() || expected_bytes.len() > 128 * 1024 * 1024 {
        return Err(CiError::Message(
            "installed candidate agent size differs".into(),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(AGENT)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.mode() & 0o111 == 0
        || before.dev() == 0
        || before.ino() == 0
        || before.len() != expected_bytes.len() as u64
    {
        return Err(CiError::Message(
            "installed candidate agent protection differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(expected_bytes.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path = std::fs::symlink_metadata(AGENT)?;
    if bytes != expected_bytes
        || (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || (after.dev(), after.ino()) != (path.dev(), path.ino())
        || !path.is_file()
    {
        return Err(CiError::Message(
            "installed candidate agent changed during identity readback".into(),
        ));
    }
    Ok((before.dev(), before.ino()))
}

#[cfg(not(target_os = "linux"))]
pub fn read_fixed_agent_identity(_expected_bytes: &[u8]) -> Result<(u64, u64)> {
    Err(CiError::Message(
        "installed candidate agent identity requires Linux".into(),
    ))
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct InstallationEpochV1 {
    schema_version: u8,
    counter: u64,
    nonce_digest: DiagnosticSha256,
}

/// Canonical epoch bytes are independent of component or manifest hashes, so
/// a byte-identical reinstall cannot reuse a previous candidate run. This
/// checks the record's form, not package-lock ownership or host freshness.
pub fn validate_installation_epoch_bytes(bytes: &[u8]) -> Result<DiagnosticSha256> {
    if bytes.is_empty() || bytes.len() > 4096 {
        return Err(CiError::Message("installed H0 epoch size differs".into()));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let epoch: InstallationEpochV1 = serde_json::from_slice(bytes)?;
    if epoch.schema_version != 1
        || epoch.counter == 0
        || epoch.nonce_digest == DiagnosticSha256::from_bytes([0; 32])
        || serde_json::to_vec(&epoch)? != bytes
    {
        return Err(CiError::Message("installed H0 epoch differs".into()));
    }
    Ok(hash_bytes(bytes))
}

/// The caller must hold a package-generation lease across this read and the
/// native run. This result is a structural equality input, never Q authority.
#[cfg(target_os = "linux")]
pub fn read_fixed_installation_epoch() -> Result<DiagnosticSha256> {
    match std::fs::symlink_metadata(PACKAGE_JOURNAL) {
        Ok(_) => {
            return Err(CiError::Message(
                "installed H0 has a pending package transaction".into(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let bytes = read_root_owned_regular(Path::new(INSTALLATION_EPOCH), 4096, 0o600)?;
    validate_installation_epoch_bytes(&bytes)
}

#[cfg(not(target_os = "linux"))]
pub fn read_fixed_installation_epoch() -> Result<DiagnosticSha256> {
    Err(CiError::Message(
        "installed H0 epoch requires a native Linux host".into(),
    ))
}

pub fn join_installed_epoch_to_candidate_request(
    request: &ProtectedCandidateReleaseRequestV1,
    independently_read_epoch: &DiagnosticSha256,
) -> Result<()> {
    if &request.installation_epoch != independently_read_epoch {
        return Err(CiError::Message(
            "candidate request installation epoch differs from installed H0".into(),
        ));
    }
    Ok(())
}

/// Reads only the fixed installed image inventory. Files and ancestors must
/// be root-owned and not writable by an unprivileged user. This is a snapshot,
/// not a package-generation lease: callers must separately bind the epoch.
#[cfg(target_os = "linux")]
pub fn read_fixed_installed_h0() -> Result<InstalledH0StaticBytes> {
    let manifest = read_root_owned_regular(Path::new(MANIFEST), 1024 * 1024, 0o644)?;
    let agent = read_root_owned_regular(Path::new(AGENT), 128 * 1024 * 1024, 0o755)?;
    let units = UNIT_PATHS
        .map(|path| read_root_owned_regular(Path::new(path), 128 * 1024, 0o644))
        .into_iter()
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| CiError::Message("installed H0 unit inventory differs".into()))?;
    Ok(InstalledH0StaticBytes {
        manifest,
        agent,
        units,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn read_fixed_installed_h0() -> Result<InstalledH0StaticBytes> {
    Err(CiError::Message(
        "installed H0 requires a native Linux host".into(),
    ))
}

/// Returns a digest for a structural raw-attachment join only. The expected
/// unit/filter values must come from the earlier B build inventory, never the
/// V6 inspection or native result being checked.
pub fn validate_installed_h0_static(
    candidate: &PreparedPrivateCandidateV2,
    expected_units: &LinuxUnitHashesV6,
    installed: &InstalledH0StaticBytes,
    inspection_bytes: &[u8],
) -> Result<DiagnosticSha256> {
    if inspection_bytes.is_empty() || inspection_bytes.len() > 128 * 1024 {
        return Err(CiError::Message(
            "installed H0 inspection size differs".into(),
        ));
    }
    reject_duplicate_json_keys(inspection_bytes).map_err(CiError::Message)?;
    let inspection: LinuxInstalledInspectionV6 = serde_json::from_slice(inspection_bytes)?;
    let manifest = RuntimeManifestV3::parse(&installed.manifest).map_err(CiError::Message)?;
    let SealedRuntimeV3::WorkloadV2 {
        native_protocols,
        profile_catalog_sha256,
        ..
    } = &candidate.manifest.sealed
    else {
        return Err(CiError::Message(
            "installed H0 requires workload-V2 M0".into(),
        ));
    };
    let agent = candidate
        .manifest
        .components
        .iter()
        .find(|component| component.role == RuntimeComponentRole::SealedAgent)
        .ok_or_else(|| CiError::Message("candidate B lacks sealed agent".into()))?;
    let installed_units = LinuxUnitHashesV6 {
        control_service: hash_bytes(&installed.units[0]),
        control_socket: hash_bytes(&installed.units[1]),
        launcher_service: hash_bytes(&installed.units[2]),
        launcher_socket: hash_bytes(&installed.units[3]),
        tmpfiles: hash_bytes(&installed.units[4]),
        network_launcher_service: hash_bytes(&installed.units[5]),
        network_launcher_socket: hash_bytes(&installed.units[6]),
    };
    if manifest != candidate.manifest
        || installed.manifest != candidate.manifest_bytes
        || hash_bytes(&installed.manifest) != candidate.manifest_sha256
        || private_unit_digest_v2(expected_units) != candidate.unit_sha256
        || installed_units != *expected_units
        || String::from(hash_bytes(&installed.agent)) != agent.sha256
        || inspection.package.version.as_str() != candidate.manifest.version
        || inspection.package.source_commit.as_str() != candidate.manifest.source_commit
        || inspection.package.target.as_str() != candidate.manifest.target
        || inspection.package.runtime_manifest_sha256 != candidate.manifest_sha256
        || inspection.package.components != candidate.manifest.components
        || inspection.package.native_protocols != *native_protocols
        || inspection.package.profile_catalog_sha256 != *profile_catalog_sha256
        || inspection.package.private_filter_sha256 != candidate.filter_sha256
        || inspection.package.compiled_units != *expected_units
        || inspection.installed_units != installed_units
        || String::from(inspection.installed_agent_sha256.clone()) != agent.sha256
        || inspection.network_launcher_state != NetworkLauncherStateV6::InstalledDisabled
        || inspection.baseline_qualification.is_some()
        || inspection.private_qualification.is_some()
        || inspection.installed_qualification_sha256.is_some()
        || !inspection.package.compiled_metadata_valid
        || !inspection.installed_artifacts_valid
    {
        return Err(CiError::Message(
            "installed H0 static image differs from independently prepared B/M0".into(),
        ));
    }
    // `provider_reachable` and service state remain self-reported here. Their
    // independent OS observations are prerequisites to any trusted Q token.
    Ok(hash_bytes(inspection_bytes))
}

#[cfg(target_os = "linux")]
fn read_root_owned_regular(path: &Path, max: u64, mode: u32) -> Result<Vec<u8>> {
    use std::fs::OpenOptions;
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Component;

    let mut ancestor = std::path::PathBuf::from("/");
    let parent = path
        .parent()
        .ok_or_else(|| CiError::Message("installed H0 parent absent".into()))?;
    for component in parent.components() {
        if let Component::Normal(leaf) = component {
            ancestor.push(leaf);
            let metadata = std::fs::symlink_metadata(&ancestor)?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CiError::Message(
                    "installed H0 ancestor is not root-protected".into(),
                ));
            }
        }
    }
    let parent_before = std::fs::symlink_metadata(parent)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file()
        || before.uid() != 0
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() == 0
        || before.len() > max
    {
        return Err(CiError::Message(
            "installed H0 file protection differs".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(max + 1).read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    let path_after = std::fs::symlink_metadata(path)?;
    let parent_after = std::fs::symlink_metadata(parent)?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
        || (path_after.dev(), path_after.ino()) != (before.dev(), before.ino())
        || (parent_after.dev(), parent_after.ino()) != (parent_before.dev(), parent_before.ino())
    {
        return Err(CiError::Message(
            "installed H0 changed during readback".into(),
        ));
    }
    Ok(bytes)
}
