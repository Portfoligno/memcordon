use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

#[cfg(not(target_os = "windows"))]
use crate::inspection_schema::ProviderPackageMetadataV4;
use crate::inspection_schema::{
    AgentPackageInspectionV5 as AgentPackageInspectionV4,
    InstalledProviderInspectionV5 as InstalledProviderInspectionV4,
};
#[cfg(target_os = "linux")]
use memcordon_core::package_inspection_v6::{
    InspectionVersionSix, LinuxInstalledInspectionV6, LinuxPackageInspectionV6, LinuxUnitHashesV6,
    NetworkLauncherStateV6, TrustedLinuxInspectionV6,
};
#[cfg(target_os = "linux")]
use memcordon_core::{BoundedText, DiagnosticSha256};

/// The private launcher accepts this only after installed V3/V6 and a fresh
/// native V4 host receipt have been independently read back and joined.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct VerifiedInstalledPrivateAuthority {
    source_commit: String,
    runtime_manifest_sha256: DiagnosticSha256,
    generation_digest: DiagnosticSha256,
    qualification_digest: DiagnosticSha256,
    filter_abi: crate::linux::network_filter::NativeAbi,
    filter_digest: DiagnosticSha256,
    active_host_receipt_sha256: DiagnosticSha256,
    certificate_sha256: String,
    trust_policy_sha256: String,
    release_sequence: u64,
}

#[cfg(target_os = "linux")]
/// A shared package lock couples readback to the generation used at the
/// checkpoint/release boundary. Package mutation takes the exclusive lock.
/// Callers must acquire this before the policy lease and hold it until the
/// release packet is sent or the attempt is rejected.
#[derive(Debug)]
pub(crate) struct VerifiedInstalledPrivateAuthorityLease {
    _package_lease: std::fs::File,
    authority: VerifiedInstalledPrivateAuthority,
}

/// A candidate package readback for the administrator's fixed native canary.
/// This is intentionally separate from the qualified production authority;
/// it cannot be converted into `VerifiedInstalledPrivateAuthorityLease`.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct VerifiedProbePackageLease {
    _package_lease: std::fs::File,
    _agent_file: std::fs::File,
    pub(crate) runtime_manifest_sha256: DiagnosticSha256,
    pub(crate) release_qualification_sha256: DiagnosticSha256,
    pub(crate) agent_sha256: DiagnosticSha256,
    pub(crate) units: LinuxUnitHashesV6,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) source_commit: String,
    pub(crate) target: String,
}

/// Candidate-capability release tests run against installed M0 before any Q
/// exists. This non-convertible lease must never be built through the H1 probe
/// lease, which intentionally requires M1 plus installed Q bytes.
#[cfg(target_os = "linux")]
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct VerifiedReleaseCandidatePackageLease {
    _package_lease: std::fs::File,
    _agent_file: std::fs::File,
    pub(crate) runtime_manifest_sha256: DiagnosticSha256,
    pub(crate) installation_epoch: DiagnosticSha256,
    pub(crate) agent_sha256: DiagnosticSha256,
    pub(crate) units: LinuxUnitHashesV6,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) source_commit: String,
    pub(crate) target: String,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
impl VerifiedReleaseCandidatePackageLease {
    pub(crate) fn agent_installation_path(&self) -> &'static Path {
        Path::new(BINARY)
    }

    pub(crate) fn agent_file_identity(&self) -> Result<(u64, u64), String> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self
            ._agent_file
            .metadata()
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: pinned image identity: {error}"))?;
        if !metadata.is_file() || metadata.dev() == 0 || metadata.ino() == 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: pinned image identity differs".into());
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    /// Read a fresh V6 installed inspection under this M0 package lock. The
    /// bytes are diagnostic release evidence, not a Q or H1 authority.
    pub(crate) fn installed_inspection_bytes(&self) -> Result<Vec<u8>, String> {
        let inspection = linux_installed_inspection_v6()?
            .ok_or("MCSEALED-PRIVATE-RELEASE: installed V6 inspection absent")?;
        if inspection.package.runtime_manifest_sha256 != self.runtime_manifest_sha256
            || inspection.installed_agent_sha256 != self.agent_sha256
            || inspection.installed_units != self.units
            || inspection.private_qualification.is_some()
            || inspection.installed_qualification_sha256.is_some()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: installed M0 inspection differs".into());
        }
        serde_json::to_vec(&inspection).map_err(|error| error.to_string())
    }

    pub(crate) fn pinned_fixture_entrypoint(
        &self,
    ) -> Result<crate::linux::entrypoint::VerifiedEntrypoint, String> {
        let file = self
            ._agent_file
            .try_clone()
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: clone pinned image: {error}"))?;
        crate::linux::entrypoint::VerifiedEntrypoint::from_probe_package_image(
            file,
            &self.agent_sha256,
        )
    }
}

#[cfg(target_os = "linux")]
impl VerifiedProbePackageLease {
    pub(crate) fn pinned_fixture_entrypoint(
        &self,
    ) -> Result<crate::linux::entrypoint::VerifiedEntrypoint, String> {
        let file = self
            ._agent_file
            .try_clone()
            .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: clone pinned image: {error}"))?;
        crate::linux::entrypoint::VerifiedEntrypoint::from_probe_package_image(
            file,
            &self.agent_sha256,
        )
    }
}

/// Launch-generation evidence retained after the package lease is consumed.
/// This is report input only: it cannot authorize a workload or renew host
/// qualification after the installed generation changes.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct VerifiedInstalledPrivateReportBinding {
    source_commit: String,
    runtime_manifest_sha256: DiagnosticSha256,
    generation_digest: DiagnosticSha256,
    qualification_digest: DiagnosticSha256,
    filter_abi: crate::linux::network_filter::NativeAbi,
    filter_digest: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // Accessors become live when the routed V4 checkpoint producer is integrated.
impl VerifiedInstalledPrivateAuthorityLease {
    /// Called immediately before the durable release decision, while this
    /// package-generation guard is still retained. A policy refresh or
    /// revocation between admission and release closes the attempt.
    pub(crate) fn revalidate_release_boundary(&self) -> Result<(), String> {
        let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
            .ok_or("MCSEALED-PRIVATE-QUALIFICATION: M1 disappeared before release")?;
        let release =
            crate::linux::installed_release_qualification::verify_anchored_native_qualification(
                &candidate,
            )?;
        if release.certificate_sha256() != self.authority.certificate_sha256
            || release.policy_sha256() != self.authority.trust_policy_sha256
            || release.release_sequence() != self.authority.release_sequence
            || candidate.qualification_sha256.as_ref() != Some(&self.authority.qualification_digest)
            || memcordon_core::workload_codec::hash_bytes(&candidate.manifest_bytes)
                != self.authority.runtime_manifest_sha256
        {
            return Err(
                "MCSEALED-PRIVATE-QUALIFICATION: release trust changed before release".into(),
            );
        }
        let host = crate::linux::private_host_receipt::read_current_active(&release)?
            .ok_or("MCSEALED-PRIVATE-QUALIFICATION: H1 disappeared before release")?;
        if host.receipt_sha256() != &self.authority.active_host_receipt_sha256 {
            return Err("MCSEALED-PRIVATE-QUALIFICATION: H1 changed before release".into());
        }
        Ok(())
    }

    pub(crate) fn source_commit(&self) -> &str {
        &self.authority.source_commit
    }

    pub(crate) fn runtime_manifest_sha256(&self) -> &DiagnosticSha256 {
        &self.authority.runtime_manifest_sha256
    }

    pub(crate) fn generation_digest(&self) -> &DiagnosticSha256 {
        &self.authority.generation_digest
    }

    pub(crate) fn qualification_digest(&self) -> &DiagnosticSha256 {
        &self.authority.qualification_digest
    }

    pub(crate) fn filter_abi(&self) -> crate::linux::network_filter::NativeAbi {
        self.authority.filter_abi
    }

    pub(crate) fn filter_digest(&self) -> &DiagnosticSha256 {
        &self.authority.filter_digest
    }

    pub(crate) fn active_host_receipt_sha256(&self) -> &DiagnosticSha256 {
        &self.authority.active_host_receipt_sha256
    }

    /// Consume the lock-bound authority after the release decision. The
    /// returned value is evidence for terminal projection, not a reusable
    /// admission or package-verification token.
    pub(crate) fn into_report_binding(self) -> VerifiedInstalledPrivateReportBinding {
        let authority = self.authority;
        VerifiedInstalledPrivateReportBinding {
            source_commit: authority.source_commit,
            runtime_manifest_sha256: authority.runtime_manifest_sha256,
            generation_digest: authority.generation_digest,
            qualification_digest: authority.qualification_digest,
            filter_abi: authority.filter_abi,
            filter_digest: authority.filter_digest,
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(dead_code)] // Terminal V11 projection is not routed until native host qualification exists.
impl VerifiedInstalledPrivateReportBinding {
    pub(crate) fn source_commit(&self) -> &str {
        &self.source_commit
    }

    pub(crate) fn runtime_manifest_sha256(&self) -> &DiagnosticSha256 {
        &self.runtime_manifest_sha256
    }

    pub(crate) fn generation_digest(&self) -> &DiagnosticSha256 {
        &self.generation_digest
    }

    pub(crate) fn qualification_digest(&self) -> &DiagnosticSha256 {
        &self.qualification_digest
    }

    pub(crate) fn filter_abi(&self) -> crate::linux::network_filter::NativeAbi {
        self.filter_abi
    }

    pub(crate) fn filter_digest(&self) -> &DiagnosticSha256 {
        &self.filter_digest
    }
}

const SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision control provider\nRequires=memcordon-sealed-agent.socket memcordon-sealed-launcher.socket\nAfter=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent serve\nUser=root\nGroup=memcordon\nKillMode=process\nStateDirectory=memcordon/sealed memcordon/policy\nStateDirectoryMode=0700\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /var/lib/memcordon/policy\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision control socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-agent.sock\nDirectoryMode=0755\nSocketMode=0660\nSocketUser=root\nSocketGroup=memcordon\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker\nRequires=memcordon-sealed-launcher.socket\nAfter=local-fs.target\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nRestrictAddressFamilies=AF_UNIX\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed supervision launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
// Installed as an unavailable, disabled package component until native V2
// admission and qualification are implemented. Installation must not activate
// this privileged broker or advertise the private profile.
const NETWORK_LAUNCHER_SERVICE: &str = "[Unit]\nDescription=MemCordon sealed private IPv4 launch broker\nRequires=memcordon-sealed-network-launcher.socket\nAfter=local-fs.target\nRefuseManualStart=yes\n\n[Service]\nType=simple\nExecStart=/usr/libexec/memcordon-sealed-agent network-launch-broker\nUser=root\nGroup=root\nDelegate=yes\nKillMode=process\nStateDirectory=memcordon/sealed\nStateDirectoryMode=0700\nNoNewPrivileges=no\nAmbientCapabilities=\nCapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN\nRestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK\nLockPersonality=yes\n\n[Install]\nWantedBy=multi-user.target\n";
const NETWORK_LAUNCHER_SOCKET: &str = "[Unit]\nDescription=MemCordon sealed private IPv4 launch broker socket\nAfter=systemd-tmpfiles-setup.service\n\n[Socket]\nListenStream=/run/memcordon/sealed-network-launcher.sock\nDirectoryMode=0750\nSocketMode=0600\nSocketUser=root\nSocketGroup=root\nRemoveOnStop=yes\n\n[Install]\nWantedBy=sockets.target\n";
const TMPFILES: &str = "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n";
#[cfg(target_os = "linux")]
const BINARY: &str = "/usr/libexec/memcordon-sealed-agent";
#[cfg(target_os = "linux")]
const UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.service";
#[cfg(target_os = "linux")]
const SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-agent.socket";
#[cfg(target_os = "linux")]
const LAUNCHER_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.service";
#[cfg(target_os = "linux")]
const LAUNCHER_SOCKET_UNIT: &str = "/usr/lib/systemd/system/memcordon-sealed-launcher.socket";
#[cfg(target_os = "linux")]
const NETWORK_LAUNCHER_UNIT: &str =
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.service";
#[cfg(target_os = "linux")]
const NETWORK_LAUNCHER_SOCKET_UNIT: &str =
    "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket";
#[cfg(target_os = "linux")]
const TMPFILES_FILE: &str = "/usr/lib/tmpfiles.d/memcordon.conf";
#[cfg(target_os = "linux")]
const LEGACY_PACKAGE_LEASE: &str = "/run/memcordon/sealed-package.lock";
#[cfg(target_os = "linux")]
const RUNTIME_DIRECTORY: &str = "/run/memcordon";
#[cfg(target_os = "linux")]
const INSTALLED_QUALIFICATION_ROOT: &str = "/usr/libexec/memcordon";
#[cfg(target_os = "linux")]
const PACKAGE_TRANSACTION_JOURNAL: &str = "/usr/libexec/.memcordon-package-transaction.json";
#[cfg(target_os = "linux")]
const PACKAGE_INSTALLATION_EPOCH: &str = "/usr/libexec/.memcordon-installation-epoch.json";

#[cfg(target_os = "linux")]
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageInstallationEpochV1 {
    pub(crate) schema_version: u8,
    pub(crate) counter: u64,
    pub(crate) nonce_digest: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxSourceSnapshot {
    pub(crate) agent_bytes: Vec<u8>,
    pub(crate) arm32_helper_bytes: Option<Vec<u8>>,
    pub(crate) manifest_bytes: Vec<u8>,
    pub(crate) qualification: Option<(std::path::PathBuf, Vec<u8>)>,
    pub(crate) release_build: Option<(std::path::PathBuf, Vec<u8>)>,
    pub(crate) release_certificate: Option<(std::path::PathBuf, Vec<u8>)>,
    pub(crate) v3: bool,
}

#[cfg(target_os = "linux")]
fn release_proof_paths(target: &str) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
    let short = match target {
        "x86_64-unknown-linux-gnu" => "x64",
        "aarch64-unknown-linux-gnu" => "arm64",
        _ => return Err("package release proof target differs".into()),
    };
    let root = Path::new("certification/workload");
    Ok((
        root.join(format!("{short}-private-build-v1.json")),
        root.join(format!("{short}-private-cq-v1.json")),
    ))
}

#[cfg(target_os = "linux")]
fn read_source_release_proofs(
    root: &Path,
    target: &str,
    qualified: bool,
) -> Result<
    (
        Option<(std::path::PathBuf, Vec<u8>)>,
        Option<(std::path::PathBuf, Vec<u8>)>,
    ),
    String,
> {
    if !qualified {
        return Ok((None, None));
    }
    let (build, certificate) = release_proof_paths(target)?;
    let build_bytes = read_source_regular(&root.join(&build), 1024 * 1024, 0o644)?;
    let certificate_bytes = read_source_regular(&root.join(&certificate), 64 * 1024, 0o644)?;
    if build_bytes.is_empty() || certificate_bytes.is_empty() {
        return Err("package release proof bytes absent".into());
    }
    let installed_root = Path::new(INSTALLED_QUALIFICATION_ROOT);
    Ok((
        Some((installed_root.join(build), build_bytes)),
        Some((installed_root.join(certificate), certificate_bytes)),
    ))
}

#[cfg(target_os = "linux")]
fn read_source_regular(path: &Path, maximum: u64, mode: u32) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| format!("package source open {}: {error}", path.display()))?;
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.mode() & 0o7777 != mode
        || before.len() > maximum
    {
        return Err("package source is not an exact regular artifact".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        )
    {
        return Err("package source changed during pinned readback".into());
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_source_snapshot(source: &Path) -> Result<LinuxSourceSnapshot, String> {
    use memcordon_core::runtime_manifest_v3::{
        RuntimeProfileAvailabilityV3, SealedRuntimeV3, VersionedRuntimeManifest,
    };
    let parent = source.parent().ok_or("package source has no parent")?;
    let agent_bytes = read_source_regular(source, 128 * 1024 * 1024, 0o755)?;
    if source == Path::new(BINARY) {
        if let Some(candidate) = crate::linux::runtime_manifest::source_v3_candidate(source)? {
            let qualification = match candidate.qualification_bytes() {
                Some(bytes) => {
                    let relative =
                        crate::linux::installed_release_qualification::fixed_q_reference_path(
                            &candidate.manifest.target,
                        )?;
                    Some((
                        Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative),
                        bytes.to_vec(),
                    ))
                }
                None => None,
            };
            let (release_build, release_certificate) = read_source_release_proofs(
                Path::new(INSTALLED_QUALIFICATION_ROOT),
                &candidate.manifest.target,
                qualification.is_some(),
            )?;
            return Ok(LinuxSourceSnapshot {
                agent_bytes,
                arm32_helper_bytes: (candidate.manifest.target == "aarch64-unknown-linux-gnu")
                    .then(|| {
                        read_source_regular(
                            Path::new(crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER),
                            1024 * 1024,
                            0o755,
                        )
                    })
                    .transpose()?,
                manifest_bytes: candidate.manifest_bytes,
                qualification,
                release_build,
                release_certificate,
                v3: true,
            });
        }
    }
    let manifest_path = parent.join("runtime-manifest.json");
    let manifest_bytes = match std::fs::symlink_metadata(&manifest_path) {
        Ok(_) => Some(read_source_regular(
            &manifest_path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            0o644,
        )?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.to_string()),
    };
    if let Some(bytes) = manifest_bytes {
        if let VersionedRuntimeManifest::V3(manifest) = VersionedRuntimeManifest::parse(&bytes)? {
            let public = read_source_regular(&parent.join("memcordon"), 128 * 1024 * 1024, 0o755)?;
            let arm32_helper_bytes = (manifest.target == "aarch64-unknown-linux-gnu")
                .then(|| {
                    read_source_regular(
                        &parent.join("memcordon-arm32-abi-helper"),
                        1024 * 1024,
                        0o755,
                    )
                })
                .transpose()?;
            let SealedRuntimeV3::WorkloadV2 { profiles, .. } = &manifest.sealed else {
                return Err("package V3 source lacks workload protocol".into());
            };
            let qualification = match &profiles
                .as_slice()
                .first()
                .ok_or("package V3 source lacks private profile")?
                .availability
            {
                RuntimeProfileAvailabilityV3::Qualified { qualification } => {
                    let relative =
                        crate::linux::installed_release_qualification::fixed_q_reference_path(
                            &manifest.target,
                        )?;
                    if qualification.artifact != relative {
                        return Err("package M1 Q reference is not the fixed archive member".into());
                    }
                    let source_q = parent.join(relative);
                    let q_bytes = read_source_regular(
                        &source_q,
                        memcordon_core::workload_limits::REGISTRY_BYTES as u64,
                        0o644,
                    )?;
                    Some((
                        Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative),
                        q_bytes,
                    ))
                }
                RuntimeProfileAvailabilityV3::Unqualified => None,
                RuntimeProfileAvailabilityV3::Unsupported => {
                    return Err("package V3 private profile is unsupported".into());
                }
            };
            let (release_build, release_certificate) =
                read_source_release_proofs(parent, &manifest.target, qualification.is_some())?;
            crate::linux::installed_release_qualification::from_exact_bytes(
                bytes.clone(),
                &agent_bytes,
                &public,
                arm32_helper_bytes.as_deref(),
                qualification.as_ref().map(|(_, bytes)| bytes.clone()),
            )?;
            return Ok(LinuxSourceSnapshot {
                agent_bytes,
                arm32_helper_bytes,
                manifest_bytes: bytes,
                qualification,
                release_build,
                release_certificate,
                v3: true,
            });
        }
    }
    let legacy_manifest = crate::linux::runtime_manifest::source(source, &agent_bytes)?;
    Ok(LinuxSourceSnapshot {
        agent_bytes,
        arm32_helper_bytes: None,
        manifest_bytes: legacy_manifest,
        qualification: None,
        release_build: None,
        release_certificate: None,
        v3: false,
    })
}

pub fn run(
    operation: &OsStr,
    json: bool,
    ephemeral_ci: bool,
    qualification_artifact_directory: Option<&Path>,
) -> Result<(), String> {
    run_with_archive(
        operation,
        json,
        ephemeral_ci,
        qualification_artifact_directory,
        None,
    )
}

pub fn run_with_archive(
    operation: &OsStr,
    json: bool,
    ephemeral_ci: bool,
    qualification_artifact_directory: Option<&Path>,
    archive: Option<(&Path, &Path)>,
) -> Result<(), String> {
    if archive.is_some() && (operation != "install" && operation != "upgrade" || !ephemeral_ci) {
        return Err("signed A is valid only for ephemeral final install or upgrade".into());
    }
    if operation == "inspect" {
        if ephemeral_ci {
            return Err("--ephemeral-ci is valid only for package mutations".to_owned());
        }
        #[cfg(target_os = "linux")]
        if let Some(inspection) = linux_package_inspection_v6()? {
            return render_v6_package_inspection(&inspection, json);
        }
        return render_inspection(&inspect()?, json);
    }
    if operation == "verify" {
        if ephemeral_ci {
            return Err("--ephemeral-ci is valid only for package mutations".to_owned());
        }
        verify()?;
        #[cfg(target_os = "linux")]
        if let Some(inspection) = linux_installed_inspection_v6()? {
            return render_v6_installed_inspection(&inspection, json);
        }
        return render_installed_inspection(&installed_inspection()?, json);
    }
    #[cfg(target_os = "linux")]
    if operation == "verify-private-host" {
        if !json || ephemeral_ci || qualification_artifact_directory.is_some() {
            return Err("verify-private-host requires only --json".into());
        }
        return verify_private_host_json();
    }
    #[cfg(target_os = "linux")]
    if operation == "qualify-private" {
        if json || ephemeral_ci || qualification_artifact_directory.is_some() {
            return Err("qualify-private accepts no modifiers or external artifacts".into());
        }
        return qualify_private_host();
    }
    if json {
        return Err("--json is valid only for package inspect and package verify".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        if qualification_artifact_directory.is_some() {
            return Err(
                "external qualification artifacts are available only on Windows".to_owned(),
            );
        }
        linux_mutation(operation, ephemeral_ci, archive)
    }
    #[cfg(target_os = "windows")]
    {
        if archive.is_some() {
            return Err("signed A is Linux-only".into());
        }
        crate::windows::package::mutate(operation, ephemeral_ci, qualification_artifact_directory)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (ephemeral_ci, qualification_artifact_directory, archive);
        Err("provider package mutation is unavailable on this platform".to_owned())
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn register_public_release_case(
    selector: &std::ffi::OsStr,
    challenge: &std::ffi::OsStr,
    pid: &std::ffi::OsStr,
    start_time_ticks: &std::ffi::OsStr,
) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("final-public selector is not UTF-8")?;
    let challenge = challenge
        .to_str()
        .ok_or("final-public challenge is not UTF-8")?;
    let pid = pid
        .to_str()
        .ok_or("final-public child pid is not UTF-8")?
        .parse::<libc::pid_t>()
        .map_err(|_| "final-public child pid syntax differs")?;
    let start_time_ticks = start_time_ticks
        .to_str()
        .ok_or("final-public child start time is not UTF-8")?
        .parse::<u64>()
        .map_err(|_| "final-public child start time syntax differs")?;
    crate::linux::private_public_provider::register(selector, challenge, pid, start_time_ticks)
}

#[cfg(target_os = "linux")]
pub(crate) fn public_abi_outer_control(
    selector: &std::ffi::OsStr,
    challenge: &std::ffi::OsStr,
    dispatch_key: &std::ffi::OsStr,
) -> Result<(), String> {
    crate::linux::private_public_abi_control::request_control(
        selector
            .to_str()
            .ok_or("public ABI selector is not UTF-8")?,
        challenge
            .to_str()
            .ok_or("public ABI challenge is not UTF-8")?,
        dispatch_key.to_str().ok_or("public ABI key is not UTF-8")?,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn public_reuse_operation(
    operation: &std::ffi::OsStr,
    selector: &std::ffi::OsStr,
    challenge: &std::ffi::OsStr,
    dispatch_key: &std::ffi::OsStr,
) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("public reuse selector is not UTF-8")?;
    let challenge = challenge
        .to_str()
        .ok_or("public reuse challenge is not UTF-8")?;
    let key = dispatch_key
        .to_str()
        .ok_or("public reuse key is not UTF-8")?;
    match operation.to_str() {
        Some("public-reuse-hold") => {
            crate::linux::private_public_reuse::hold(selector, challenge, key)
        }
        Some("public-reuse-release") => {
            crate::linux::private_public_reuse::release(selector, challenge, key)
        }
        Some("public-reuse-recover") => {
            crate::linux::private_public_reuse::recover(selector, challenge, key)
        }
        Some("public-reuse-release-and-recover") => {
            crate::linux::private_public_reuse::release_and_recover(selector, challenge, key)
        }
        Some("public-reuse-verify") => {
            println!(
                "{}",
                crate::linux::private_public_reuse::verify_completed(selector, challenge, key)?
            );
            Ok(())
        }
        _ => Err("public reuse operation differs".into()),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_public_release_provider(
    selector: &std::ffi::OsStr,
    challenge: &std::ffi::OsStr,
) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("final-public selector is not UTF-8")?;
    let challenge = challenge
        .to_str()
        .ok_or("final-public challenge is not UTF-8")?;
    println!(
        "{}",
        crate::linux::private_public_provider::verify_completed(selector, challenge)?
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn public_preparation_context_v2() -> Result<(), String> {
    println!(
        "{}",
        crate::linux::private_public_provider::preparation_context_v2()?
    );
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn verify_public_spoof(
    selector: &std::ffi::OsStr,
    challenge: &std::ffi::OsStr,
) -> Result<(), String> {
    let selector = selector
        .to_str()
        .ok_or("final-public spoof selector is not UTF-8")?;
    let challenge = challenge
        .to_str()
        .ok_or("final-public spoof challenge is not UTF-8")?;
    println!(
        "{}",
        crate::linux::private_public_provider::verify_public_spoof(selector, challenge)?
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn qualify_private_host() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-PROBE: root administrator required".into());
    }
    let current = std::fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(BINARY).map_err(|error| error.to_string())?;
    if !installed.is_file() || current.dev() != installed.dev() || current.ino() != installed.ino()
    {
        return Err("MCSEALED-PRIVATE-PROBE: invoke the installed agent image".into());
    }
    // Starting the socket only activates the protected launcher service for
    // this administrator operation. It does not publish or enable a profile.
    let status = std::process::Command::new("systemctl")
        .arg("start")
        .arg("memcordon-sealed-network-launcher.socket")
        .status()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: start socket: {error}"))?;
    if !status.success() {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE: start socket exited {status}"
        ));
    }
    crate::linux::service::request_private_host_qualification()
}

#[cfg(target_os = "linux")]
fn verify_private_host_json() -> Result<(), String> {
    use memcordon_core::release_trust::SignedNativeQualificationCertificateV1;
    use memcordon_core::workload_codec::hash_bytes;
    use memcordon_core::workload_qualification_v2::QualificationArtifactV2;
    use std::os::unix::fs::MetadataExt;

    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-HOST: root readback required".into());
    }
    let current = std::fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = std::fs::symlink_metadata(BINARY).map_err(|error| error.to_string())?;
    if !installed.is_file() || current.dev() != installed.dev() || current.ino() != installed.ino()
    {
        return Err("MCSEALED-PRIVATE-HOST: invoke the installed agent image".into());
    }
    // The lease retains the shared package-generation lock and proves current
    // M1/Q/CQ/policy, active H1, epoch and enabled launcher before projection.
    let lease = acquire_verified_private_qualification_lease()?;
    let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
        .ok_or("MCSEALED-PRIVATE-HOST: installed M1 absent")?;
    let release =
        crate::linux::installed_release_qualification::verify_anchored_native_qualification(
            &candidate,
        )?;
    let active = crate::linux::private_host_receipt::read_current_active(&release)?
        .ok_or("MCSEALED-PRIVATE-HOST: active H1 absent")?;
    let snapshot = linux_source_snapshot(Path::new(BINARY))?;
    let qualification_bytes = candidate
        .qualification_bytes()
        .ok_or("MCSEALED-PRIVATE-HOST: Q absent")?;
    let qualification: QualificationArtifactV2 =
        serde_json::from_slice(qualification_bytes).map_err(|error| error.to_string())?;
    let build_bytes = snapshot
        .release_build
        .as_ref()
        .ok_or("MCSEALED-PRIVATE-HOST: B absent")?
        .1
        .as_slice();
    let certificate_bytes = snapshot
        .release_certificate
        .as_ref()
        .ok_or("MCSEALED-PRIVATE-HOST: CQ absent")?
        .1
        .as_slice();
    let certificate = SignedNativeQualificationCertificateV1::parse(certificate_bytes)?;
    if String::from(hash_bytes(&certificate.payload.canonical_bytes()?))
        != release.certificate_sha256()
        || certificate.payload.build_sha256 != String::from(hash_bytes(build_bytes))
        || certificate.payload.qualification_sha256 != String::from(hash_bytes(qualification_bytes))
        || active.receipt_sha256() != lease.active_host_receipt_sha256()
        || active.installation_epoch() != lease.generation_digest()
        || active.release_qualification_sha256() != lease.qualification_digest()
    {
        return Err("MCSEALED-PRIVATE-HOST: readback changed after trust verification".into());
    }
    let target = candidate.manifest.target.as_str();
    let native_machine = match target {
        "x86_64-unknown-linux-gnu" => "x86_64",
        "aarch64-unknown-linux-gnu" => "aarch64",
        _ => return Err("MCSEALED-PRIVATE-HOST: unsupported target".into()),
    };
    let component_hash = |id: &str| {
        candidate
            .manifest
            .components
            .iter()
            .find(|component| component.id == id)
            .map(|component| component.sha256.clone())
    };
    let public_cli_sha256 =
        component_hash("public-cli").ok_or("MCSEALED-PRIVATE-HOST: public CLI absent")?;
    let agent_sha256 =
        component_hash("sealed-agent").ok_or("MCSEALED-PRIVATE-HOST: agent absent")?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    if boot_id.trim().is_empty() || boot_id.trim().len() > 64 {
        return Err("MCSEALED-PRIVATE-HOST: boot identity differs".into());
    }
    lease.revalidate_release_boundary()?;
    let final_active = crate::linux::private_host_receipt::read_current_active(&release)?
        .ok_or("MCSEALED-PRIVATE-HOST: active H1 disappeared")?;
    if final_active.run_nonce() != active.run_nonce()
        || final_active.native_run_digest() != active.native_run_digest()
        || final_active.host_prerequisites_digest() != active.host_prerequisites_digest()
        || final_active.receipt_sha256() != active.receipt_sha256()
    {
        return Err("MCSEALED-PRIVATE-HOST: active H1 changed during readback".into());
    }
    let output = serde_json::json!({
        "schema_version": 1,
        "source_commit": candidate.manifest.source_commit,
        "version": candidate.manifest.version,
        "target": target,
        "native_machine": native_machine,
        "boot_id": boot_id.trim(),
        "installation_epoch": String::from(lease.generation_digest().clone()),
        "installed_runtime_manifest_sha256": String::from(hash_bytes(&candidate.manifest_bytes)),
        "qualification_file_sha256": String::from(hash_bytes(qualification_bytes)),
        "build_file_sha256": String::from(hash_bytes(build_bytes)),
        "certificate_file_sha256": String::from(hash_bytes(certificate_bytes)),
        "certificate_payload_sha256": release.certificate_sha256(),
        "public_cli_sha256": public_cli_sha256,
        "agent_sha256": agent_sha256,
        "arm32_helper_sha256": component_hash("arm32-abi-helper"),
        "component_sha256": String::from(qualification.component_digest),
        "unit_sha256": String::from(qualification.unit_digest),
        "filter_sha256": String::from(qualification.filter_digest),
        "policy_sha256": release.policy_sha256(),
        "policy_version": certificate.payload.policy_version,
        "release_sequence": release.release_sequence(),
        "active_h1_receipt_sha256": String::from(active.receipt_sha256().clone()),
        "active_run_nonce": active.run_nonce(),
        "native_run_digest": String::from(active.native_run_digest().clone()),
        "host_prerequisites_digest": String::from(active.host_prerequisites_digest().clone()),
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_v6_package_inspection(
    inspection: &LinuxPackageInspectionV6,
    json: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "Linux sealed package V6: {} ({})",
            inspection.version.as_str(),
            inspection.source_commit.as_str()
        );
        println!("compiled package metadata: valid");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn render_v6_installed_inspection(
    inspection: &LinuxInstalledInspectionV6,
    json: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!("Linux installed provider V6: artifacts valid");
        println!("provider reachable: {}", inspection.provider_reachable);
        println!(
            "network launcher state: {:?}",
            inspection.network_launcher_state
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn compiled_unit_hashes_v6() -> LinuxUnitHashesV6 {
    let digest = |bytes: &[u8]| memcordon_core::workload_codec::hash_bytes(bytes);
    LinuxUnitHashesV6 {
        control_service: digest(SERVICE.as_bytes()),
        control_socket: digest(SOCKET.as_bytes()),
        launcher_service: digest(LAUNCHER_SERVICE.as_bytes()),
        launcher_socket: digest(LAUNCHER_SOCKET.as_bytes()),
        tmpfiles: digest(TMPFILES.as_bytes()),
        network_launcher_service: digest(NETWORK_LAUNCHER_SERVICE.as_bytes()),
        network_launcher_socket: digest(NETWORK_LAUNCHER_SOCKET.as_bytes()),
    }
}

#[cfg(target_os = "linux")]
fn installed_unit_hashes_v6() -> Result<LinuxUnitHashesV6, String> {
    let digest = |path: &str| -> Result<DiagnosticSha256, String> {
        DiagnosticSha256::try_from(
            BoundedText::<64>::new(&sha256_regular_no_follow(Path::new(path))?)
                .map_err(str::to_owned)?,
        )
        .map_err(str::to_owned)
    };
    Ok(LinuxUnitHashesV6 {
        control_service: digest(UNIT)?,
        control_socket: digest(SOCKET_UNIT)?,
        launcher_service: digest(LAUNCHER_UNIT)?,
        launcher_socket: digest(LAUNCHER_SOCKET_UNIT)?,
        tmpfiles: digest(TMPFILES_FILE)?,
        network_launcher_service: digest(NETWORK_LAUNCHER_UNIT)?,
        network_launcher_socket: digest(NETWORK_LAUNCHER_SOCKET_UNIT)?,
    })
}

#[cfg(target_os = "linux")]
fn compiled_filter_digest_v6() -> Result<DiagnosticSha256, String> {
    use crate::linux::network_filter::{
        NativeAbi, compile_initial_closed_filter, filter_instruction_digest,
    };
    let abi = match crate::linux::runtime_manifest::target()? {
        "x86_64-unknown-linux-gnu" => NativeAbi::X86_64,
        "aarch64-unknown-linux-gnu" => NativeAbi::Aarch64,
        _ => return Err("V6 inspection requires a supported GNU Linux ABI".into()),
    };
    let instructions = compile_initial_closed_filter(abi);
    Ok(DiagnosticSha256::from_bytes(
        filter_instruction_digest(&instructions).map_err(str::to_owned)?,
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn package_inspection_v6_from_verified_manifest(
    manifest: &memcordon_core::runtime_manifest_v3::RuntimeManifestV3,
    manifest_bytes: &[u8],
) -> Result<LinuxPackageInspectionV6, String> {
    if memcordon_core::runtime_manifest_v3::RuntimeManifestV3::parse(manifest_bytes)? != *manifest {
        return Err("V6 package manifest differs from pinned bytes".into());
    }
    verify_compiled_metadata()?;
    let memcordon_core::runtime_manifest_v3::SealedRuntimeV3::WorkloadV2 {
        native_protocols,
        profile_catalog_sha256,
        ..
    } = &manifest.sealed
    else {
        return Err("V6 inspection requires Linux workload-V2 manifest".into());
    };
    Ok(LinuxPackageInspectionV6 {
        schema_version: InspectionVersionSix,
        version: BoundedText::new(&manifest.version).map_err(str::to_owned)?,
        source_commit: BoundedText::new(&manifest.source_commit).map_err(str::to_owned)?,
        target: BoundedText::new(&manifest.target).map_err(str::to_owned)?,
        runtime_manifest_sha256: memcordon_core::workload_codec::hash_bytes(manifest_bytes),
        components: manifest.components.clone(),
        native_protocols: native_protocols.clone(),
        profile_catalog_sha256: profile_catalog_sha256.clone(),
        private_filter_sha256: compiled_filter_digest_v6()?,
        compiled_units: compiled_unit_hashes_v6(),
        compiled_metadata_valid: true,
    })
}

#[cfg(target_os = "linux")]
fn linux_package_inspection_v6() -> Result<Option<LinuxPackageInspectionV6>, String> {
    let source = std::env::current_exe().map_err(|error| error.to_string())?;
    let (manifest, bytes) = if source == Path::new(BINARY) {
        let Some(candidate) = crate::linux::runtime_manifest::source_v3_candidate(&source)? else {
            return Ok(None);
        };
        (candidate.manifest, candidate.manifest_bytes)
    } else {
        let snapshot = linux_source_snapshot(&source)?;
        if !snapshot.v3 {
            return Ok(None);
        }
        let manifest = memcordon_core::runtime_manifest_v3::RuntimeManifestV3::parse(
            &snapshot.manifest_bytes,
        )?;
        (manifest, snapshot.manifest_bytes)
    };
    Ok(Some(package_inspection_v6_from_verified_manifest(
        &manifest, &bytes,
    )?))
}

#[cfg(target_os = "linux")]
fn linux_installed_inspection_v6() -> Result<Option<LinuxInstalledInspectionV6>, String> {
    let Some(candidate) = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
    else {
        return Ok(None);
    };
    let manifest = candidate.manifest;
    let manifest_bytes = candidate.manifest_bytes;
    let binding = manifest.public_binding(&manifest_bytes)?;
    if binding.runtime_manifest_sha256
        != memcordon_core::workload_codec::hash_bytes(&manifest_bytes)
    {
        return Err("V6 installed generation changed during binding readback".into());
    }
    let network_launcher_state = observed_network_launcher_state()?;
    let package = package_inspection_v6_from_verified_manifest(&manifest, &manifest_bytes)?;
    let installed_agent_sha256 = DiagnosticSha256::try_from(
        BoundedText::<64>::new(&sha256_regular_no_follow(Path::new(BINARY))?)
            .map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    let provider_reachable = probe_provider().is_ok();
    let inspection = LinuxInstalledInspectionV6 {
        schema_version: InspectionVersionSix,
        package: package.clone(),
        installed_units: installed_unit_hashes_v6()?,
        installed_agent_sha256: installed_agent_sha256.clone(),
        installed_artifacts_valid: true,
        provider_reachable,
        network_launcher_state,
        baseline_qualification: None,
        private_qualification: None,
        installed_qualification_sha256: None,
    };
    let serialized = serde_json::to_vec(&inspection).map_err(|error| error.to_string())?;
    LinuxInstalledInspectionV6::parse_and_validate(
        &serialized,
        &manifest_bytes,
        &TrustedLinuxInspectionV6 {
            runtime_manifest_sha256: &package.runtime_manifest_sha256,
            filter_sha256: &package.private_filter_sha256,
            unit_hashes: &package.compiled_units,
            installed_agent_sha256: &installed_agent_sha256,
            provider_reachable,
            network_launcher_state,
            baseline_qualification: None,
            private_qualification: None,
            installed_qualification_sha256: None,
        },
    )?;
    Ok(Some(inspection))
}

/// The package lock stays held across authenticated Q and current H1 readback,
/// and through the caller's checkpoint and release decision.
#[cfg(target_os = "linux")]
pub(crate) fn acquire_verified_private_qualification_lease()
-> Result<VerifiedInstalledPrivateAuthorityLease, String> {
    let package_lease = crate::linux::service::acquire_shared_package_lease()?;
    verify()?;
    let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
        .ok_or("MCSEALED-PRIVATE-QUALIFICATION: installed M1 absent")?;
    let release =
        crate::linux::installed_release_qualification::verify_anchored_native_qualification(
            &candidate,
        )?;
    acquire_verified_private_qualification_lease_with_guard(package_lease, candidate, &release)
}

/// An internal caller with already authenticated release Q may enter this
/// route; it still rechecks the exact installed generation under one guard.
#[cfg(target_os = "linux")]
pub(crate) fn acquire_verified_private_qualification_lease_with_release(
    release: &crate::linux::installed_release_qualification::TrustedReleaseQualification,
) -> Result<VerifiedInstalledPrivateAuthorityLease, String> {
    let package_lease = crate::linux::service::acquire_shared_package_lease()?;
    verify()?;
    let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
        .ok_or("MCSEALED-PRIVATE-QUALIFICATION: installed M1 absent")?;
    let current =
        crate::linux::installed_release_qualification::verify_anchored_native_qualification(
            &candidate,
        )?;
    if current.certificate_sha256() != release.certificate_sha256()
        || current.policy_sha256() != release.policy_sha256()
        || current.release_sequence() != release.release_sequence()
    {
        return Err("MCSEALED-PRIVATE-QUALIFICATION: release trust changed".into());
    }
    acquire_verified_private_qualification_lease_with_guard(package_lease, candidate, &current)
}

#[cfg(target_os = "linux")]
fn acquire_verified_private_qualification_lease_with_guard(
    package_lease: std::fs::File,
    candidate: crate::linux::installed_release_qualification::CandidateV3Readback,
    release: &crate::linux::installed_release_qualification::TrustedReleaseQualification,
) -> Result<VerifiedInstalledPrivateAuthorityLease, String> {
    use crate::linux::network_filter::NativeAbi;

    let q_digest = candidate
        .qualification_sha256
        .as_ref()
        .ok_or("MCSEALED-PRIVATE-QUALIFICATION: installed release Q absent")?;
    if release.reference().artifact_sha256 != *q_digest {
        return Err("MCSEALED-PRIVATE-QUALIFICATION: trusted release Q differs from M1".into());
    }
    if observed_network_launcher_state()? != NetworkLauncherStateV6::EnabledUnqualified {
        return Err("MCSEALED-PRIVATE-QUALIFICATION: network launcher is not active".into());
    }
    let host = crate::linux::private_host_receipt::read_current_active(release)?
        .ok_or("MCSEALED-PRIVATE-QUALIFICATION: current active H1 absent")?;
    let epoch = installed_generation_epoch()?;
    let manifest_sha256 = memcordon_core::workload_codec::hash_bytes(&candidate.manifest_bytes);
    if host.installation_epoch() != &epoch
        || host.release_qualification_sha256() != q_digest
        || host.receipt().installed_runtime_manifest_sha256 != manifest_sha256
        || host.receipt().source_commit != candidate.manifest.source_commit
        || host.receipt().target != candidate.manifest.target
    {
        return Err("MCSEALED-PRIVATE-QUALIFICATION: active H1 differs from current M1/Q".into());
    }
    let filter_abi = match candidate.manifest.target.as_str() {
        "x86_64-unknown-linux-gnu" => NativeAbi::X86_64,
        "aarch64-unknown-linux-gnu" => NativeAbi::Aarch64,
        _ => return Err("MCSEALED-PRIVATE-QUALIFICATION: unsupported native ABI".into()),
    };
    let filter_digest = compiled_filter_digest_v6()?;
    if host.receipt().filter_instruction_sha256 != filter_digest {
        return Err("MCSEALED-PRIVATE-QUALIFICATION: active H1 filter differs".into());
    }
    Ok(VerifiedInstalledPrivateAuthorityLease {
        _package_lease: package_lease,
        authority: VerifiedInstalledPrivateAuthority {
            source_commit: candidate.manifest.source_commit,
            runtime_manifest_sha256: manifest_sha256,
            generation_digest: epoch,
            qualification_digest: q_digest.clone(),
            filter_abi,
            filter_digest,
            active_host_receipt_sha256: host.receipt_sha256().clone(),
            certificate_sha256: release.certificate_sha256().into(),
            trust_policy_sha256: release.policy_sha256().into(),
            release_sequence: release.release_sequence(),
        },
    })
}

/// Qualification bootstrap verifies installed candidate bytes under the
/// package lock without asking for an already qualified host lease.
#[cfg(target_os = "linux")]
pub(crate) fn acquire_verified_release_candidate_package_lease()
-> Result<VerifiedReleaseCandidatePackageLease, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // SAFETY: geteuid has no pointers and returns the kernel effective UID.
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: root candidate supervisor required".into());
    }
    let package_lease = crate::linux::service::acquire_shared_package_lease()?;
    verify()?;
    let (manifest, manifest_bytes) = crate::linux::runtime_manifest::source_v3(Path::new(BINARY))?
        .ok_or("MCSEALED-PRIVATE-RELEASE: installed unqualified M0 absent")?;
    let installation_epoch = installed_generation_epoch()?;
    let units = installed_unit_hashes_v6()?;
    if units != compiled_unit_hashes_v6() {
        return Err("MCSEALED-PRIVATE-RELEASE: installed unit bytes differ".into());
    }
    let mut agent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(BINARY)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: pinned image open: {error}"))?;
    let metadata = agent_file
        .metadata()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: pinned image metadata: {error}"))?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
        || metadata.nlink() != 1
    {
        return Err("MCSEALED-PRIVATE-RELEASE: pinned image protection differs".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = agent_file
            .read(&mut buffer)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: pinned image read: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let agent_sha256 = DiagnosticSha256::from_bytes(hash.finalize().into());
    let expected_agent = DiagnosticSha256::try_from(
        BoundedText::<64>::new(&inspect()?.executable_sha256).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    if agent_sha256 != expected_agent {
        return Err("MCSEALED-PRIVATE-RELEASE: pinned image digest differs".into());
    }
    let path_metadata = std::fs::symlink_metadata(BINARY)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: installed image path: {error}"))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err("MCSEALED-PRIVATE-RELEASE: installed image changed during pinning".into());
    }
    Ok(VerifiedReleaseCandidatePackageLease {
        _package_lease: package_lease,
        _agent_file: agent_file,
        runtime_manifest_sha256: memcordon_core::workload_codec::hash_bytes(&manifest_bytes),
        installation_epoch,
        agent_sha256,
        units,
        filter_sha256: compiled_filter_digest_v6()?,
        source_commit: manifest.source_commit,
        target: manifest.target,
    })
}

/// Installed H1 canaries require a structurally bound M1/Q candidate but
/// still cannot construct a production private qualification lease.
#[cfg(target_os = "linux")]
pub(crate) fn acquire_verified_probe_package_lease() -> Result<VerifiedProbePackageLease, String> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    // SAFETY: geteuid has no pointers and returns the kernel's effective UID.
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-PROBE: root coordinator required".into());
    }
    let package_lease = crate::linux::service::acquire_shared_package_lease()?;
    verify()?;
    let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
        .ok_or("MCSEALED-PRIVATE-PROBE: installed V3 candidate absent")?;
    let release_qualification_sha256 = candidate
        .qualification_sha256
        .clone()
        .ok_or("MCSEALED-PRIVATE-PROBE: installed M1 Q bytes absent")?;
    let units = installed_unit_hashes_v6()?;
    if units != compiled_unit_hashes_v6() {
        return Err("MCSEALED-PRIVATE-PROBE: installed unit bytes differ".into());
    }
    let mut agent_file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(BINARY)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: pinned image open: {error}"))?;
    let metadata = agent_file
        .metadata()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: pinned image metadata: {error}"))?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o755 {
        return Err("MCSEALED-PRIVATE-PROBE: pinned image protection differs".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = agent_file
            .read(&mut buffer)
            .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: pinned image read: {error}"))?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let agent_sha256 = DiagnosticSha256::from_bytes(hash.finalize().into());
    let expected_agent = DiagnosticSha256::try_from(
        BoundedText::<64>::new(&inspect()?.executable_sha256).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)?;
    if agent_sha256 != expected_agent {
        return Err("MCSEALED-PRIVATE-PROBE: pinned image digest differs".into());
    }
    let path_metadata = std::fs::symlink_metadata(BINARY)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE: installed image path: {error}"))?;
    if metadata.dev() != path_metadata.dev() || metadata.ino() != path_metadata.ino() {
        return Err("MCSEALED-PRIVATE-PROBE: installed image changed during pinning".into());
    }
    Ok(VerifiedProbePackageLease {
        _package_lease: package_lease,
        _agent_file: agent_file,
        runtime_manifest_sha256: memcordon_core::workload_codec::hash_bytes(
            &candidate.manifest_bytes,
        ),
        release_qualification_sha256,
        agent_sha256,
        units,
        filter_sha256: compiled_filter_digest_v6()?,
        source_commit: candidate.manifest.source_commit,
        target: candidate.manifest.target,
    })
}

#[cfg(target_os = "linux")]
fn observed_network_launcher_state() -> Result<NetworkLauncherStateV6, String> {
    let mut all_disabled = true;
    for unit in [
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
    ] {
        let output = std::process::Command::new("/usr/bin/systemctl")
            .args(["show", "--property=ActiveState,UnitFileState", unit])
            .output()
            .map_err(|error| format!("V6 network launcher state readback: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "V6 network launcher state readback failed for {unit}: {}",
                output.status
            ));
        }
        let values = std::str::from_utf8(&output.stdout).map_err(|error| error.to_string())?;
        let mut active = None;
        let mut enabled = None;
        for line in values.lines() {
            if let Some(value) = line.strip_prefix("ActiveState=") {
                if active.replace(value).is_some() {
                    return Err("V6 network launcher has duplicate active state".into());
                }
            } else if let Some(value) = line.strip_prefix("UnitFileState=") {
                if enabled.replace(value).is_some() {
                    return Err("V6 network launcher has duplicate unit state".into());
                }
            } else {
                return Err("V6 network launcher has an unknown state field".into());
            }
        }
        let (Some(active), Some(enabled)) = (active, enabled) else {
            return Err("V6 network launcher state readback is incomplete".into());
        };
        if !matches!(active, "inactive" | "failed" | "active" | "activating")
            || !matches!(enabled, "disabled" | "enabled" | "static")
        {
            return Err("V6 network launcher has an unsupported state".into());
        }
        all_disabled &= matches!(active, "inactive" | "failed") && enabled == "disabled";
    }
    Ok(if all_disabled {
        NetworkLauncherStateV6::InstalledDisabled
    } else {
        NetworkLauncherStateV6::EnabledUnqualified
    })
}

pub(crate) fn verify() -> Result<(), String> {
    verify_compiled_metadata()?;
    #[cfg(target_os = "linux")]
    match std::fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL) {
        Ok(_) => return Err("package generation has an unrecovered transaction journal".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    #[cfg(target_os = "linux")]
    verify_installed_package()?;
    #[cfg(target_os = "windows")]
    crate::windows::package::verify_installed()?;
    Ok(())
}

fn render_inspection(inspection: &AgentPackageInspectionV4, json: bool) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!(
            "memcordon-sealed-agent {} ({})",
            inspection.version, inspection.source_commit
        );
        println!("executable sha256: {}", inspection.executable_sha256);
        println!("compiled package metadata: valid");
    }
    Ok(())
}

fn render_installed_inspection(
    inspection: &InstalledProviderInspectionV4,
    json: bool,
) -> Result<(), String> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(inspection).map_err(|error| error.to_string())?
        );
    } else {
        println!("installed provider artifacts: valid");
        println!(
            "provider reachable: {}",
            if inspection.provider_reachable {
                "yes"
            } else {
                "no"
            }
        );
        println!(
            "qualification complete: {}",
            if inspection.qualification_complete {
                "yes"
            } else {
                "no"
            }
        );
    }
    Ok(())
}

pub(crate) fn inspect() -> Result<AgentPackageInspectionV4, String> {
    verify_compiled_metadata()?;
    let executable = std::env::current_exe()
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: current executable: {error}"))?;
    let executable_sha256 = sha256_regular_no_follow(&executable)?;
    #[cfg(not(target_os = "windows"))]
    let (mechanism, platform) = (
        "linux-pid-namespace-cgroup-v2".to_owned(),
        ProviderPackageMetadataV4::LinuxSystemd {
            control_service_sha256: sha256_bytes(SERVICE.as_bytes()),
            control_socket_sha256: sha256_bytes(SOCKET.as_bytes()),
            launcher_service_sha256: sha256_bytes(LAUNCHER_SERVICE.as_bytes()),
            launcher_socket_sha256: sha256_bytes(LAUNCHER_SOCKET.as_bytes()),
            tmpfiles_sha256: sha256_bytes(TMPFILES.as_bytes()),
        },
    );
    #[cfg(target_os = "windows")]
    let (mechanism, platform) = (
        "windows-job-object-v2".to_owned(),
        crate::windows::package::compiled_metadata()?,
    );
    Ok(AgentPackageInspectionV4 {
        schema_version: 5,
        native_protocols: if cfg!(target_os = "windows") {
            memcordon_core::runtime_manifest::NativeProviderProtocols::Windows {
                provider_contract: 3,
                public_wire: 2,
                private_wire: 2,
            }
        } else {
            memcordon_core::runtime_manifest::NativeProviderProtocols::Linux {
                provider_contract: 3,
                launch_wire: 3,
            }
        },
        runtime_manifest_schema: 2,
        workload_contract_schema: 1,
        profile_catalog_sha256: memcordon_core::runtime_manifest::baseline_catalog_digest(cfg!(
            target_os = "windows"
        )),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        source_commit: crate::SOURCE_COMMIT.to_owned(),
        executable_sha256,
        provider_protocol: if cfg!(target_os = "windows") {
            memcordon_core::WINDOWS_PUBLIC_PROTOCOL_VERSION
        } else {
            u32::from(crate::protocol::PROTOCOL_VERSION)
        },
        mechanism,
        execution_report_schema: memcordon_core::EXECUTION_REPORT_SCHEMA_VERSION,
        plan_report_schema: memcordon_core::PLAN_REPORT_SCHEMA_VERSION,
        doctor_report_schema: memcordon_core::DOCTOR_REPORT_SCHEMA_VERSION,
        platform,
        compiled_metadata_valid: true,
    })
}

fn installed_inspection() -> Result<InstalledProviderInspectionV4, String> {
    let agent = inspect()?;
    #[cfg(target_os = "linux")]
    {
        let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
        verify_installed_executable_digest(&agent.executable_sha256, &installed_executable_sha256)?;
        let qualification = probe_provider().ok();
        let provider_reachable = qualification.is_some();
        let qualification_complete = qualification.as_ref().is_some_and(|value| value.complete());
        let provider_identity = qualification.map(|value| value.provider_identity);
        let policy = match crate::policy_registry::native::Lease::acquire()
            .and_then(|lease| lease.read())
        {
            Ok(Some(activation)) => activation.inspection()?,
            Ok(None) => {
                memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unconfigured
            }
            Err(_) => memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unavailable,
        };
        Ok(InstalledProviderInspectionV4 {
            schema_version: 5,
            agent,
            installed_executable_sha256,
            installed_artifacts_valid: true,
            provider_identity,
            provider_reachable,
            qualification_complete,
            policy,
            profile_qualification:
                memcordon_core::runtime_manifest::profile_qualification_reference(
                    crate::linux::runtime_manifest::target()?,
                ),
            diagnostic_qualification: None,
        })
    }
    #[cfg(target_os = "windows")]
    {
        crate::windows::package::installed_inspection(agent)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Ok(InstalledProviderInspectionV4 {
            schema_version: 5,
            agent,
            installed_executable_sha256: String::new(),
            installed_artifacts_valid: false,
            provider_identity: None,
            provider_reachable: false,
            qualification_complete: false,
            policy: memcordon_core::runtime_manifest::InstalledPolicyObservationV1::Unavailable,
            profile_qualification:
                memcordon_core::runtime_manifest::profile_qualification_reference("unsupported"),
            diagnostic_qualification: None,
        })
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", test))]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn verify_installed_executable_digest(
    packaged_executable_sha256: &str,
    installed_executable_sha256: &str,
) -> Result<(), String> {
    if installed_executable_sha256 != packaged_executable_sha256 {
        return Err(
            "MCSEALED-PACKAGE-VERSION-MISMATCH: installed provider executable differs from the invoked memcordon package; rerun package upgrade with the matching memcordon-sealed-agent"
                .to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn sha256_bytes(bytes: &[u8]) -> String {
    hex_digest(Sha256::digest(bytes))
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn sha256_regular_no_follow(path: &std::path::Path) -> Result<String, String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(windows)]
    use std::os::windows::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    #[cfg(windows)]
    options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = options
        .open(path)
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "MCSEALED-PACKAGE-INSPECT: {} is not a no-follow regular file",
            path.display()
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("MCSEALED-PACKAGE-INSPECT: {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex_digest(digest.finalize()))
}

fn verify_compiled_metadata() -> Result<(), String> {
    const CONTROL_CAPABILITY_BOUNDING_SET: &str =
        "CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_SYS_PTRACE";
    const CONTROL_READ_WRITE_PATHS: &str =
        "ReadWritePaths=/run/memcordon /var/lib/memcordon/sealed /var/lib/memcordon/policy";
    let control_capabilities = SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let control_ambient = SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    let control_read_write_paths = SERVICE
        .lines()
        .filter(|line| line.starts_with("ReadWritePaths="))
        .collect::<Vec<_>>();
    let launcher_capabilities = LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let launcher_ambient = LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    let network_launcher_capabilities = NETWORK_LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("CapabilityBoundingSet="))
        .collect::<Vec<_>>();
    let network_launcher_ambient = NETWORK_LAUNCHER_SERVICE
        .lines()
        .filter(|line| line.starts_with("AmbientCapabilities="))
        .collect::<Vec<_>>();
    let launcher_forbidden = [
        "PrivateTmp=",
        "ProtectSystem=",
        "ReadWritePaths=",
        "ReadOnlyPaths=",
        "InaccessiblePaths=",
        "RestrictSUIDSGID=",
    ];
    let launcher_changes_target_mounts = LAUNCHER_SERVICE.lines().any(|line| {
        launcher_forbidden
            .iter()
            .any(|prefix| line.starts_with(prefix))
    });
    if SERVICE.contains("Description=MemCordon sealed supervision control provider")
        && SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent serve")
        && SERVICE.contains("User=root")
        && SERVICE.contains("Group=memcordon")
        && SERVICE.contains("NoNewPrivileges=yes")
        && SERVICE.contains("PrivateTmp=yes")
        && SERVICE.contains("ProtectSystem=strict")
        && SERVICE.contains(
            "After=local-fs.target systemd-tmpfiles-setup.service memcordon-sealed-launcher.socket",
        )
        && !SERVICE.contains("RuntimeDirectory=")
        && !SERVICE.contains("RuntimeDirectoryMode=")
        && control_capabilities == [CONTROL_CAPABILITY_BOUNDING_SET]
        && control_ambient == ["AmbientCapabilities="]
        && control_read_write_paths == [CONTROL_READ_WRITE_PATHS]
        && SOCKET.contains("ListenStream=/run/memcordon/sealed-agent.sock")
        && SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && SOCKET.contains("SocketMode=0660")
        && SOCKET.contains("SocketGroup=memcordon")
        && LAUNCHER_SERVICE.contains("Description=MemCordon sealed supervision launch broker")
        && LAUNCHER_SERVICE.contains("ExecStart=/usr/libexec/memcordon-sealed-agent launch-broker")
        && LAUNCHER_SERVICE.contains("User=root")
        && LAUNCHER_SERVICE.contains("Group=root")
        && LAUNCHER_SERVICE.contains("NoNewPrivileges=no")
        && !LAUNCHER_SERVICE.contains("RuntimeDirectory=")
        && !LAUNCHER_SERVICE.contains("RuntimeDirectoryMode=")
        && launcher_capabilities.is_empty()
        && launcher_ambient == ["AmbientCapabilities="]
        && !launcher_changes_target_mounts
        && LAUNCHER_SOCKET.contains("ListenStream=/run/memcordon/sealed-launcher.sock")
        && LAUNCHER_SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && LAUNCHER_SOCKET.contains("DirectoryMode=0750")
        && LAUNCHER_SOCKET.contains("SocketMode=0600")
        && LAUNCHER_SOCKET.contains("SocketUser=root")
        && LAUNCHER_SOCKET.contains("SocketGroup=root")
        && NETWORK_LAUNCHER_SERVICE
            .contains("Description=MemCordon sealed private IPv4 launch broker")
        && NETWORK_LAUNCHER_SERVICE
            .contains("ExecStart=/usr/libexec/memcordon-sealed-agent network-launch-broker")
        && NETWORK_LAUNCHER_SERVICE.contains("Requires=memcordon-sealed-network-launcher.socket")
        && NETWORK_LAUNCHER_SERVICE.contains("RefuseManualStart=yes")
        && NETWORK_LAUNCHER_SERVICE.contains("User=root")
        && NETWORK_LAUNCHER_SERVICE.contains("Group=root")
        && NETWORK_LAUNCHER_SERVICE.contains("Delegate=yes")
        && NETWORK_LAUNCHER_SERVICE.contains("NoNewPrivileges=no")
        && NETWORK_LAUNCHER_SERVICE.contains("RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK")
        && !NETWORK_LAUNCHER_SERVICE.contains("CAP_NET_RAW")
        && !NETWORK_LAUNCHER_SERVICE.contains("RuntimeDirectory=")
        && !NETWORK_LAUNCHER_SERVICE.contains("RuntimeDirectoryMode=")
        && network_launcher_capabilities
            == [
                "CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_CHROOT CAP_SETUID CAP_SETGID CAP_SETPCAP CAP_DAC_OVERRIDE CAP_SYS_PTRACE CAP_KILL CAP_NET_ADMIN",
            ]
        && network_launcher_ambient == ["AmbientCapabilities="]
        && NETWORK_LAUNCHER_SOCKET
            .contains("ListenStream=/run/memcordon/sealed-network-launcher.sock")
        && NETWORK_LAUNCHER_SOCKET.contains("After=systemd-tmpfiles-setup.service")
        && NETWORK_LAUNCHER_SOCKET.contains("DirectoryMode=0750")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketMode=0600")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketUser=root")
        && NETWORK_LAUNCHER_SOCKET.contains("SocketGroup=root")
        && TMPFILES
            == "d /run/memcordon 0750 root memcordon -\nf /run/memcordon-sealed-package.lock 0600 root root -\n"
    {
        Ok(())
    } else {
        Err("compiled split-service metadata is inconsistent".to_owned())
    }
}

#[cfg(test)]
pub(crate) fn network_launcher_templates_for_test() -> (&'static str, &'static str) {
    (NETWORK_LAUNCHER_SERVICE, NETWORK_LAUNCHER_SOCKET)
}

#[cfg(test)]
pub(crate) fn verify_compiled_metadata_for_test() -> Result<(), String> {
    verify_compiled_metadata()
}

#[cfg(target_os = "linux")]
fn prepare_runtime_directory() -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    match std::fs::symlink_metadata("/run/memcordon") {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Err("provider runtime path is not a real directory".to_owned()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir("/run/memcordon").map_err(|error| error.to_string())?;
        }
        Err(error) => return Err(error.to_string()),
    }
    std::fs::set_permissions("/run/memcordon", std::fs::Permissions::from_mode(0o750))
        .map_err(|error| error.to_string())?;
    let metadata = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o7777 != 0o750 {
        return Err("provider runtime directory identity or mode is unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_runtime_directory_owner(service_gid: libc::gid_t) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != 0
        || metadata.gid() != service_gid
        || metadata.mode() & 0o7777 != 0o750
    {
        return Err("provider runtime directory identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum ArtifactAccess {
    MetadataOnly,
    Readable,
}

#[cfg(target_os = "linux")]
fn open_artifact_descriptor(
    path: &std::path::Path,
    access: ArtifactAccess,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt;

    let access_flag = match access {
        ArtifactAccess::MetadataOnly => libc::O_PATH,
        ArtifactAccess::Readable => 0,
    };
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(access_flag | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err("MCSEALED-PACKAGE-VERIFY: installed package is incomplete".to_owned())
        }
        Err(error) => Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {}: {error}",
            path.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn verify_open_artifact(
    file: &mut std::fs::File,
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} is not a no-follow regular file",
            path.display()
        ));
    }
    if metadata.uid() != expected_uid || metadata.gid() != expected_gid {
        let expected_owner = if expected_uid == 0 && expected_gid == 0 {
            "root:root".to_owned()
        } else {
            format!("{expected_uid}:{expected_gid}")
        };
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} is not owned by {expected_owner}",
            path.display(),
        ));
    }
    if metadata.mode() & 0o7777 != expected_mode {
        return Err(format!(
            "MCSEALED-PACKAGE-VERIFY: {} mode is not {expected_mode:04o}",
            path.display()
        ));
    }
    if let Some(expected_bytes) = expected_bytes {
        let mut actual = Vec::with_capacity(expected_bytes.len() + 1);
        file.by_ref()
            .take((expected_bytes.len() + 1) as u64)
            .read_to_end(&mut actual)
            .map_err(|error| format!("MCSEALED-PACKAGE-VERIFY: {}: {error}", path.display()))?;
        if actual != expected_bytes {
            return Err(format!(
                "MCSEALED-PACKAGE-VERIFY: {} content differs from the packaged artifact",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_metadata_artifact(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), String> {
    let mut file = open_artifact_descriptor(path, ArtifactAccess::MetadataOnly)?;
    verify_open_artifact(
        &mut file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        None,
    )
}

#[cfg(target_os = "linux")]
fn verify_readable_artifact(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    let mut file = open_artifact_descriptor(path, ArtifactAccess::Readable)?;
    verify_open_artifact(
        &mut file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_metadata_artifact_for_test(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), String> {
    verify_metadata_artifact(path, expected_uid, expected_gid, expected_mode)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_readable_artifact_for_test(
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    verify_readable_artifact(
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn open_metadata_artifact_for_test(path: &std::path::Path) -> Result<std::fs::File, String> {
    open_artifact_descriptor(path, ArtifactAccess::MetadataOnly)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn open_readable_artifact_for_test(path: &std::path::Path) -> Result<std::fs::File, String> {
    open_artifact_descriptor(path, ArtifactAccess::Readable)
}

#[cfg(all(target_os = "linux", feature = "test-support"))]
pub fn verify_open_artifact_for_test(
    file: &mut std::fs::File,
    path: &std::path::Path,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
    expected_bytes: Option<&[u8]>,
) -> Result<(), String> {
    verify_open_artifact(
        file,
        path,
        expected_uid,
        expected_gid,
        expected_mode,
        expected_bytes,
    )
}

#[cfg(target_os = "linux")]
fn verify_installed_package() -> Result<(), String> {
    let packaged_executable = inspect()?;
    verify_installed_package_against(&packaged_executable.executable_sha256)
}

#[cfg(target_os = "linux")]
fn verify_installed_package_against(packaged_executable_sha256: &str) -> Result<(), String> {
    verify_metadata_artifact(
        std::path::Path::new(crate::linux::service::PACKAGE_LEASE),
        0,
        0,
        0o600,
    )?;

    let installed_executable_sha256 = sha256_regular_no_follow(std::path::Path::new(BINARY))?;
    verify_installed_executable_digest(packaged_executable_sha256, &installed_executable_sha256)?;

    let artifacts = [
        (BINARY, 0o755, None),
        (UNIT, 0o644, Some(SERVICE.as_bytes())),
        (SOCKET_UNIT, 0o644, Some(SOCKET.as_bytes())),
        (LAUNCHER_UNIT, 0o644, Some(LAUNCHER_SERVICE.as_bytes())),
        (
            LAUNCHER_SOCKET_UNIT,
            0o644,
            Some(LAUNCHER_SOCKET.as_bytes()),
        ),
        (
            NETWORK_LAUNCHER_UNIT,
            0o644,
            Some(NETWORK_LAUNCHER_SERVICE.as_bytes()),
        ),
        (
            NETWORK_LAUNCHER_SOCKET_UNIT,
            0o644,
            Some(NETWORK_LAUNCHER_SOCKET.as_bytes()),
        ),
        (TMPFILES_FILE, 0o644, Some(TMPFILES.as_bytes())),
    ];
    for (path, expected_mode, expected_bytes) in artifacts {
        verify_readable_artifact(
            std::path::Path::new(path),
            0,
            0,
            expected_mode,
            expected_bytes,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct PackageFileChange {
    path: std::path::PathBuf,
    bytes: Option<Vec<u8>>,
    mode: u32,
}

#[cfg(target_os = "linux")]
struct AppliedPackageFileChange {
    path: std::path::PathBuf,
    backup: Option<tempfile::TempPath>,
}

#[cfg(target_os = "linux")]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournalEntry {
    pub(crate) path: std::path::PathBuf,
    pub(crate) backup: Option<std::path::PathBuf>,
    pub(crate) old_sha256: Option<DiagnosticSha256>,
    pub(crate) old_device: Option<u64>,
    pub(crate) old_inode: Option<u64>,
}

#[cfg(target_os = "linux")]
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackageJournal {
    pub(crate) schema_version: u8,
    pub(crate) entries: Vec<PackageJournalEntry>,
}

#[cfg(target_os = "linux")]
struct PackageFileTransaction {
    applied: Vec<AppliedPackageFileChange>,
    directories: CreatedPackageDirectories,
}

#[cfg(target_os = "linux")]
#[derive(Default)]
struct CreatedPackageDirectories {
    paths: Vec<std::path::PathBuf>,
    keep: bool,
}

#[cfg(target_os = "linux")]
impl CreatedPackageDirectories {
    fn cleanup(&mut self) -> Result<(), String> {
        while let Some(path) = self.paths.pop() {
            if let Err(error) = std::fs::remove_dir(&path) {
                self.paths.push(path);
                return Err(error.to_string());
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for CreatedPackageDirectories {
    fn drop(&mut self) {
        if !self.keep {
            for path in self.paths.drain(..).rev() {
                let _ = std::fs::remove_dir(path);
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn ensure_protected_package_parent(
    path: &Path,
    directories: &mut CreatedPackageDirectories,
) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let parent = path.parent().ok_or("package artifact has no parent")?;
    let mut current = std::path::PathBuf::from("/");
    for component in parent.components() {
        let std::path::Component::Normal(name) = component else {
            continue;
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return Err(format!(
                        "package artifact parent is not root-protected: {}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o755)
                    .create(&current)
                    .map_err(|error| error.to_string())?;
                directories.paths.push(current.clone());
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
                if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o755 {
                    return Err("created package directory protection differs".into());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sync_package_parent(path: &Path) -> Result<(), String> {
    std::fs::File::open(path.parent().ok_or("package artifact has no parent")?)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn allowed_journal_target(path: &Path) -> bool {
    [
        BINARY,
        UNIT,
        SOCKET_UNIT,
        LAUNCHER_UNIT,
        LAUNCHER_SOCKET_UNIT,
        NETWORK_LAUNCHER_UNIT,
        NETWORK_LAUNCHER_SOCKET_UNIT,
        TMPFILES_FILE,
        crate::linux::runtime_manifest::INSTALLED,
        "/usr/libexec/memcordon/certification/workload/linux-x64-private-v2.json",
        "/usr/libexec/memcordon/certification/workload/linux-arm64-private-v2.json",
    ]
    .into_iter()
    .any(|expected| path == Path::new(expected))
}

#[cfg(target_os = "linux")]
fn protected_file_digest(path: &Path) -> Result<DiagnosticSha256, String> {
    DiagnosticSha256::try_from(
        BoundedText::<64>::new(&sha256_regular_no_follow(path)?).map_err(str::to_owned)?,
    )
    .map_err(str::to_owned)
}

#[cfg(target_os = "linux")]
pub(crate) fn validate_package_journal(journal: &PackageJournal) -> Result<(), String> {
    let mut seen = std::collections::BTreeSet::new();
    if journal.schema_version != 1 || journal.entries.is_empty() || journal.entries.len() > 11 {
        return Err("package transaction journal inventory differs".into());
    }
    for entry in &journal.entries {
        if !allowed_journal_target(&entry.path)
            || !seen.insert(&entry.path)
            || entry.backup.is_some() != entry.old_sha256.is_some()
            || entry.backup.is_some() != entry.old_device.is_some()
            || entry.backup.is_some() != entry.old_inode.is_some()
        {
            return Err("package transaction journal target differs".into());
        }
        if let Some(backup) = &entry.backup {
            if backup.parent() != entry.path.parent()
                || !backup
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(".memcordon-backup-"))
            {
                return Err("package transaction journal backup path differs".into());
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn write_package_journal(journal: &PackageJournal) -> Result<(), String> {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;
    validate_package_journal(journal)?;
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    match std::fs::symlink_metadata(path) {
        Ok(_) => return Err("unrecovered package transaction journal exists".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let bytes = serde_json::to_vec(journal).map_err(|error| error.to_string())?;
    if bytes.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES {
        return Err("package transaction journal exceeds byte bound".into());
    }
    let mut stage = tempfile::Builder::new()
        .prefix(".memcordon-journal-")
        .tempfile_in(path.parent().expect("fixed journal parent"))
        .map_err(|error| error.to_string())?;
    // SAFETY: the open staging file is exclusively owned by this root installer.
    if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    stage.write_all(&bytes).map_err(|error| error.to_string())?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    stage
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    std::fs::rename(stage.path(), path).map_err(|error| error.to_string())?;
    sync_package_parent(path)
}

#[cfg(target_os = "linux")]
fn clear_package_journal() -> Result<(), String> {
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    crate::linux::installed_release_qualification::read_protected_absolute(
        path,
        memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
        Some(0o600),
    )?;
    std::fs::remove_file(path).map_err(|error| error.to_string())?;
    sync_package_parent(path)
}

#[cfg(target_os = "linux")]
fn read_installation_epoch() -> Result<Option<(PackageInstallationEpochV1, Vec<u8>)>, String> {
    let path = Path::new(PACKAGE_INSTALLATION_EPOCH);
    let bytes = match std::fs::symlink_metadata(path) {
        Ok(_) => crate::linux::installed_release_qualification::read_protected_absolute(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            Some(0o600),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let epoch: PackageInstallationEpochV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if epoch.schema_version != 1
        || epoch.counter == 0
        || epoch.nonce_digest == DiagnosticSha256::from_bytes([0; 32])
        || serde_json::to_vec(&epoch).map_err(|error| error.to_string())? != bytes
    {
        return Err("package installation epoch differs from canonical record".into());
    }
    Ok(Some((epoch, bytes)))
}

#[cfg(target_os = "linux")]
pub(crate) fn next_installation_epoch(
    previous: Option<&PackageInstallationEpochV1>,
    nonce: [u8; 32],
) -> Result<PackageInstallationEpochV1, String> {
    let counter = previous.map_or(Ok(1), |epoch| {
        epoch.counter.checked_add(1).ok_or("package epoch overflow")
    })?;
    Ok(PackageInstallationEpochV1 {
        schema_version: 1,
        counter,
        nonce_digest: memcordon_core::workload_codec::hash_bytes(&nonce),
    })
}

/// A package-generation identity independent of M1/Q bytes. Callers must
/// retain a shared or exclusive package lease across this read and admission.
#[cfg(target_os = "linux")]
pub(crate) fn installed_generation_epoch() -> Result<DiagnosticSha256, String> {
    let (_, bytes) = read_installation_epoch()?
        .ok_or("protected package installation epoch is absent; re-install or upgrade")?;
    Ok(memcordon_core::workload_codec::hash_bytes(&bytes))
}

#[cfg(target_os = "linux")]
fn advance_installation_epoch() -> Result<DiagnosticSha256, String> {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::PermissionsExt;

    let previous = read_installation_epoch()?;
    let mut nonce = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut nonce))
        .map_err(|error| format!("package epoch entropy unavailable: {error}"))?;
    let epoch = next_installation_epoch(previous.as_ref().map(|(epoch, _)| epoch), nonce)?;
    let bytes = serde_json::to_vec(&epoch).map_err(|error| error.to_string())?;
    let path = Path::new(PACKAGE_INSTALLATION_EPOCH);
    let mut directories = CreatedPackageDirectories::default();
    ensure_protected_package_parent(path, &mut directories)?;
    let mut stage = tempfile::Builder::new()
        .prefix(".memcordon-epoch-")
        .tempfile_in(path.parent().expect("fixed epoch parent"))
        .map_err(|error| error.to_string())?;
    // SAFETY: the staged epoch descriptor remains live in this root installer.
    if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    stage.write_all(&bytes).map_err(|error| error.to_string())?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|error| error.to_string())?;
    stage
        .as_file()
        .sync_all()
        .map_err(|error| error.to_string())?;
    std::fs::rename(stage.path(), path).map_err(|error| error.to_string())?;
    sync_package_parent(path)?;
    directories.keep = true;
    let (_, readback) = read_installation_epoch()?.ok_or("package epoch vanished after write")?;
    if readback != bytes {
        return Err("package epoch changed during protected readback".into());
    }
    Ok(memcordon_core::workload_codec::hash_bytes(&bytes))
}

#[cfg(target_os = "linux")]
fn recover_package_journal() -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let path = Path::new(PACKAGE_TRANSACTION_JOURNAL);
    let bytes = match std::fs::symlink_metadata(path) {
        Ok(_) => crate::linux::installed_release_qualification::read_protected_absolute(
            path,
            memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64,
            Some(0o600),
        )?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let journal: PackageJournal =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    validate_package_journal(&journal)?;
    for unit in [
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
        "memcordon-sealed-agent.service",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.socket",
    ] {
        stop_unit(unit)?;
    }
    ensure_recovery_idle("recover package transaction")?;
    for entry in journal.entries.iter().rev() {
        if let (Some(backup), Some(old_sha256)) = (&entry.backup, &entry.old_sha256) {
            let original_matches = |path: &Path| -> Result<bool, String> {
                let metadata = match std::fs::symlink_metadata(path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
                    Err(error) => return Err(error.to_string()),
                };
                Ok(metadata.is_file()
                    && metadata.uid() == 0
                    && metadata.nlink() == 1
                    && Some(metadata.dev()) == entry.old_device
                    && Some(metadata.ino()) == entry.old_inode
                    && protected_file_digest(path)? == *old_sha256)
            };
            let backup_present = match std::fs::symlink_metadata(backup) {
                Ok(_) => true,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.to_string()),
            };
            if original_matches(backup)? {
                std::fs::rename(backup, &entry.path).map_err(|error| error.to_string())?;
            } else if original_matches(&entry.path)? {
                if backup_present {
                    std::fs::remove_file(backup).map_err(|error| error.to_string())?;
                }
            } else {
                return Err("package transaction backup and old artifact both differ".into());
            }
        } else {
            match std::fs::remove_file(&entry.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
        }
        sync_package_parent(&entry.path)?;
    }
    systemctl(["daemon-reload"])?;
    clear_package_journal()
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_install_is_new(operation: &OsStr, installed: bool) -> Result<(), String> {
    if operation == "install" && installed {
        return Err(
            "provider is already installed; use package upgrade for a quiesced replacement".into(),
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn ensure_install_preflight(
    operation: &OsStr,
    journal_pending: bool,
    installed: bool,
) -> Result<(), String> {
    if operation != "install" {
        return Ok(());
    }
    if journal_pending {
        return Err("package install requires recovery of a pending transaction first".into());
    }
    ensure_install_is_new(operation, installed)
}

#[cfg(target_os = "linux")]
impl PackageFileTransaction {
    fn apply(changes: Vec<PackageFileChange>) -> Result<Self, String> {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let mut staged = Vec::with_capacity(changes.len());
        let mut directories = CreatedPackageDirectories::default();
        for change in changes {
            ensure_protected_package_parent(&change.path, &mut directories)?;
            let stage = if let Some(bytes) = &change.bytes {
                let parent = change.path.parent().expect("protected parent");
                let mut stage =
                    tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
                // SAFETY: the temporary file descriptor remains live, and the
                // installer is root under the exclusive package-generation lock.
                if unsafe { libc::fchown(stage.as_file().as_raw_fd(), 0, 0) } == -1 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                stage.write_all(bytes).map_err(|error| error.to_string())?;
                stage
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(change.mode))
                    .map_err(|error| error.to_string())?;
                stage
                    .as_file()
                    .sync_all()
                    .map_err(|error| error.to_string())?;
                Some(stage)
            } else {
                None
            };
            staged.push((change.path, stage));
        }
        let mut prepared = Vec::with_capacity(staged.len());
        let mut journal_entries = Vec::with_capacity(staged.len());
        for (path, stage) in staged {
            let parent = path.parent().expect("protected parent");
            let (backup, old_sha256, old_device, old_inode) = match std::fs::symlink_metadata(&path)
            {
                Ok(metadata) => {
                    if !metadata.is_file()
                        || metadata.uid() != 0
                        || metadata.nlink() != 1
                        || metadata.mode() & 0o022 != 0
                    {
                        return Err("existing package artifact is not root-protected".into());
                    }
                    let old_sha256 = protected_file_digest(&path)?;
                    let backup = tempfile::Builder::new()
                        .prefix(".memcordon-backup-")
                        .tempfile_in(parent)
                        .map_err(|error| error.to_string())?
                        .into_temp_path();
                    (
                        Some(backup),
                        Some(old_sha256),
                        Some(metadata.dev()),
                        Some(metadata.ino()),
                    )
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    (None, None, None, None)
                }
                Err(error) => return Err(error.to_string()),
            };
            journal_entries.push(PackageJournalEntry {
                path: path.clone(),
                backup: backup.as_ref().map(|value| value.to_path_buf()),
                old_sha256,
                old_device,
                old_inode,
            });
            prepared.push((path, stage, backup));
        }
        if let Err(error) = write_package_journal(&PackageJournal {
            schema_version: 1,
            entries: journal_entries,
        }) {
            // A directory fsync can fail after the journal rename. In that
            // state its recorded backup names must outlive these TempPaths so
            // the next locked mutation can inspect/recover the transaction.
            if std::fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL).is_ok() {
                for (_, _, backup) in &mut prepared {
                    if let Some(backup) = backup.take() {
                        backup.keep().map_err(|keep_error| {
                            format!("journal write failed: {error}; backup retain: {keep_error}")
                        })?;
                    }
                }
                directories.keep = true;
            }
            return Err(error);
        }
        let mut transaction = Self {
            applied: Vec::with_capacity(prepared.len()),
            directories,
        };
        for (path, stage, backup) in prepared {
            let result = (|| {
                if let Some(backup) = &backup {
                    std::fs::rename(&path, backup).map_err(|error| error.to_string())?;
                }
                transaction.applied.push(AppliedPackageFileChange {
                    path: path.clone(),
                    backup,
                });
                if let Some(stage) = stage {
                    std::fs::rename(stage.path(), &path).map_err(|error| error.to_string())?;
                }
                sync_package_parent(&path)
            })();
            if let Err(error) = result {
                return match transaction.rollback() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(format!("{error}; package rollback failed: {rollback}")),
                };
            }
        }
        Ok(transaction)
    }

    fn rollback(mut self) -> Result<(), String> {
        let mut failures = Vec::new();
        for applied in self.applied.drain(..).rev() {
            match std::fs::remove_file(&applied.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => failures.push(error.to_string()),
            }
            if let Some(backup) = applied.backup {
                if let Err(error) = std::fs::rename(&backup, &applied.path) {
                    failures.push(error.to_string());
                    if let Err(keep_error) = backup.keep() {
                        failures.push(format!("could not retain rollback backup: {keep_error}"));
                    }
                }
            }
            if let Err(error) = sync_package_parent(&applied.path) {
                failures.push(error);
            }
        }
        if failures.is_empty() {
            self.directories.cleanup()?;
            clear_package_journal()
        } else {
            Err(failures.join("; "))
        }
    }

    fn commit(mut self) -> Result<(), String> {
        if let Err(error) = clear_package_journal() {
            for applied in &mut self.applied {
                if let Some(backup) = applied.backup.take() {
                    backup.keep().map_err(|keep_error| {
                        format!("journal commit failed: {error}; backup retain: {keep_error}")
                    })?;
                }
            }
            self.directories.keep = true;
            return Err(error);
        }
        self.directories.keep = true;
        for applied in self.applied.drain(..) {
            drop(applied.backup);
            sync_package_parent(&applied.path)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn linux_mutation(
    operation: &OsStr,
    ephemeral_ci: bool,
    archive: Option<(&Path, &Path)>,
) -> Result<(), String> {
    use std::fs;
    use std::path::Path;

    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    if unsafe { libc::geteuid() } != 0 {
        return Err("package mutation requires root".to_owned());
    }
    if operation != "install" && operation != "upgrade" && operation != "uninstall" {
        return Err("unknown package operation".to_owned());
    }
    let _package_lease = crate::linux::service::acquire_package_lease().map_err(|error| {
        format!("refusing package mutation while a sealed provider attempt is active: {error}")
    })?;
    prepare_runtime_directory()?;
    let _legacy_package_lease = crate::linux::service::acquire_legacy_package_lease().map_err(
        |error| {
            format!(
                "refusing package mutation while a legacy sealed provider attempt is active: {error}"
            )
        },
    )?;
    // An already installed generation must not lose its active H1 or epoch
    // merely because a caller used install instead of the quiesced upgrade.
    // A pending journal is a separate fail-closed state for install; upgrade
    // and uninstall retain the locked recovery path below.
    let journal_pending = match fs::symlink_metadata(PACKAGE_TRANSACTION_JOURNAL) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    let installed_before_mutation = match fs::symlink_metadata(BINARY) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    ensure_install_preflight(operation, journal_pending, installed_before_mutation)?;
    let preflight_source = if operation == "uninstall" {
        None
    } else {
        Some(linux_source_snapshot(
            &std::env::current_exe().map_err(|error| error.to_string())?,
        )?)
    };
    if let Some(snapshot) = &preflight_source {
        if snapshot.qualification.is_some() {
            let (archive_path, certificate_path) = archive.ok_or(
                "qualified M1 installation requires exact signed A and detached certificate",
            )?;
            crate::linux::installed_release_certificate::verify_source_archive_seal(
                archive_path,
                certificate_path,
                snapshot,
            )?;
        } else if archive.is_some() {
            return Err("unqualified M0 cannot claim a signed final A".into());
        }
    }
    let _public_provider_mutation_guard = if installed_before_mutation || operation != "install" {
        Some(crate::linux::private_public_provider::require_idle_for_package_mutation()?)
    } else {
        None
    };
    // Revocation precedes crash recovery and any byte replacement, including
    // byte-identical upgrades. Restoring old package files never restores H1.
    crate::linux::private_host_receipt::revoke_active()?;
    recover_package_journal()?;
    // This is intentionally outside the rollback set: an interrupted or
    // byte-identical replacement may never resurrect an older detached run.
    advance_installation_epoch()?;
    let existing_installation = match fs::symlink_metadata(BINARY) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(error.to_string()),
    };
    ensure_install_is_new(operation, existing_installation)?;
    let source_snapshot = preflight_source;
    if operation == "uninstall" {
        ensure_recovery_idle("uninstall")?;
        stop_unit("memcordon-sealed-network-launcher.service")?;
        stop_unit("memcordon-sealed-network-launcher.socket")?;
        disable_optional_network_launcher()?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket")?;
        ensure_recovery_idle("uninstall")?;
        // Refuse a substituted Q path before removing any installed package
        // file; the later unlink repeats the protected readback under the lock.
        for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
            let relative =
                crate::linux::installed_release_qualification::fixed_q_reference_path(target)?;
            let path = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    crate::linux::installed_release_qualification::read_protected_absolute(
                        &path,
                        memcordon_core::workload_limits::REGISTRY_BYTES as u64,
                        None,
                    )?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
            let (build, certificate) = release_proof_paths(target)?;
            for (relative, limit) in [(build, 1024 * 1024), (certificate, 64 * 1024)] {
                let proof = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
                match fs::symlink_metadata(&proof) {
                    Ok(_) => {
                        crate::linux::installed_release_qualification::read_protected_absolute(
                            &proof, limit, None,
                        )?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        let mut removals = Vec::new();
        for path in [
            SOCKET_UNIT,
            UNIT,
            LAUNCHER_SOCKET_UNIT,
            LAUNCHER_UNIT,
            NETWORK_LAUNCHER_SOCKET_UNIT,
            NETWORK_LAUNCHER_UNIT,
            TMPFILES_FILE,
            BINARY,
            crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER,
            crate::linux::runtime_manifest::INSTALLED,
        ] {
            match fs::symlink_metadata(path) {
                Ok(_) => removals.push(PackageFileChange {
                    path: Path::new(path).to_path_buf(),
                    bytes: None,
                    mode: 0,
                }),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(format!("could not inspect {path}: {error}")),
            }
        }
        for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
            let relative =
                crate::linux::installed_release_qualification::fixed_q_reference_path(target)?;
            let path = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
            match fs::symlink_metadata(&path) {
                Ok(_) => {
                    crate::linux::installed_release_qualification::read_protected_absolute(
                        &path,
                        memcordon_core::workload_limits::REGISTRY_BYTES as u64,
                        None,
                    )?;
                    removals.push(PackageFileChange {
                        path,
                        bytes: None,
                        mode: 0,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.to_string()),
            }
            let (build, certificate) = release_proof_paths(target)?;
            for (relative, limit) in [(build, 1024 * 1024), (certificate, 64 * 1024)] {
                let proof = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
                match fs::symlink_metadata(&proof) {
                    Ok(_) => {
                        crate::linux::installed_release_qualification::read_protected_absolute(
                            &proof, limit, None,
                        )?;
                        removals.push(PackageFileChange {
                            path: proof,
                            bytes: None,
                            mode: 0,
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        if !removals.is_empty() {
            let transaction = PackageFileTransaction::apply(removals)?;
            if let Err(error) = systemctl(["daemon-reload"]) {
                return match transaction.rollback() {
                    Ok(()) => Err(error),
                    Err(rollback) => Err(format!(
                        "{error}; package uninstall rollback failed: {rollback}"
                    )),
                };
            }
            transaction.commit()?;
        } else {
            systemctl(["daemon-reload"])?;
        }
        for path in [
            "/usr/libexec/memcordon/certification/workload",
            "/usr/libexec/memcordon/certification",
            INSTALLED_QUALIFICATION_ROOT,
        ] {
            remove_uninstalled_directory(path)?;
        }
        remove_uninstalled_file(LEGACY_PACKAGE_LEASE)?;
        // Startup diagnostics are package-owned and may be cleared after stop
        // proofs. Protected completed native/H1 evidence is different: retain
        // it for audit after revoking active admission, never erase it merely
        // to make the state directory appear empty.
        crate::linux::startup::clear()?;
        let retained_private_evidence =
            match fs::read_dir(crate::linux::private_qualification::PROBE_ROOT) {
                Ok(mut entries) => entries
                    .next()
                    .transpose()
                    .map_err(|error| error.to_string())?
                    .is_some(),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.to_string()),
            };
        if !retained_private_evidence {
            remove_uninstalled_directory(crate::linux::private_qualification::PROBE_ROOT)?;
        }
        for path in [
            crate::linux::CGROUP_ROOT,
            crate::linux::private_qualification::PROBE_WORKING_DIRECTORY,
            RUNTIME_DIRECTORY,
        ] {
            remove_uninstalled_directory(path)?;
        }
        let retained_release_trust =
            match fs::symlink_metadata("/var/lib/memcordon/sealed/release-trust") {
                Ok(metadata) if metadata.is_dir() => true,
                Ok(_) => return Err("release trust state is not a directory".into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.to_string()),
            };
        if retained_private_evidence {
            eprintln!(
                "provider uninstall retained protected completed qualification evidence in {}",
                crate::linux::private_qualification::PROBE_ROOT
            );
        }
        if retained_release_trust {
            eprintln!(
                "provider uninstall retained release trust high-water state in /var/lib/memcordon/sealed/release-trust"
            );
        }
        if !retained_private_evidence && !retained_release_trust {
            remove_uninstalled_directory(crate::linux::STATE_ROOT)?;
        }
        // This is the final uninstall mutation. The open exclusive lease remains locked until
        // return, while unlinking prevents the package lock itself becoming residual state.
        remove_uninstalled_file(crate::linux::service::PACKAGE_LEASE)?;
        return Ok(());
    }
    if operation == "upgrade" {
        ensure_recovery_idle("upgrade")?;
        stop_unit("memcordon-sealed-network-launcher.service")?;
        stop_unit("memcordon-sealed-network-launcher.socket")?;
        disable_optional_network_launcher()?;
        stop_unit("memcordon-sealed-agent.service")?;
        stop_unit("memcordon-sealed-launcher.service")?;
        stop_unit("memcordon-sealed-agent.socket")?;
        stop_unit("memcordon-sealed-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-agent.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-agent.socket")?;
        ensure_unit_inactive("memcordon-sealed-launcher.socket")?;
        ensure_recovery_idle("upgrade")?;
    }
    verify_compiled_metadata()?;
    let service_gid = ensure_service_group()?;
    ensure_probe_account()?;
    ensure_probe_working_directory()?;
    // Already-loaded pre-transition units can remove their shared RuntimeDirectory while upgrade
    // quiesces both services. Re-establish the tmpfiles contract after all stop/recovery checks and
    // immediately before assigning the reviewed ownership. Successful uninstall returns above.
    prepare_runtime_directory()?;
    let runtime_directory =
        std::ffi::CString::new("/run/memcordon").expect("static runtime path has no NUL");
    // SAFETY: runtime_directory is a live NUL-terminated path and service_gid came from the
    // system group database. The public socket group needs traversal through this 0750 parent.
    if unsafe { libc::chown(runtime_directory.as_ptr(), 0, service_gid) } == -1 {
        return Err(format!(
            "could not assign /run/memcordon to root:memcordon: {}",
            std::io::Error::last_os_error()
        ));
    }
    verify_runtime_directory_owner(service_gid)?;
    let source_snapshot = source_snapshot.expect("uninstall returned before installation");
    let source_digest = sha256_bytes(&source_snapshot.agent_bytes);
    let mut changes = Vec::new();
    for target in ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"] {
        let relative =
            crate::linux::installed_release_qualification::fixed_q_reference_path(target)?;
        let path = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
        let bytes = source_snapshot
            .qualification
            .as_ref()
            .and_then(|(source_path, bytes)| (source_path == &path).then(|| bytes.clone()));
        let q_present = if bytes.is_some() {
            true
        } else {
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => return Err(error.to_string()),
                Ok(_) => true,
            }
        };
        if q_present {
            changes.push(PackageFileChange {
                path,
                bytes,
                mode: 0o644,
            });
        }
        let (build_relative, certificate_relative) = release_proof_paths(target)?;
        for (relative, supplied) in [
            (build_relative, source_snapshot.release_build.as_ref()),
            (
                certificate_relative,
                source_snapshot.release_certificate.as_ref(),
            ),
        ] {
            let path = Path::new(INSTALLED_QUALIFICATION_ROOT).join(relative);
            let bytes = supplied
                .and_then(|(source_path, bytes)| (source_path == &path).then(|| bytes.clone()));
            if bytes.is_none() {
                match fs::symlink_metadata(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.to_string()),
                    Ok(_) => {}
                }
            }
            changes.push(PackageFileChange {
                path,
                bytes,
                mode: 0o644,
            });
        }
    }
    let helper_path = Path::new(crate::linux::runtime_manifest::INSTALLED_ARM32_HELPER);
    if source_snapshot.arm32_helper_bytes.is_some() || fs::symlink_metadata(helper_path).is_ok() {
        changes.push(PackageFileChange {
            path: helper_path.to_path_buf(),
            bytes: source_snapshot.arm32_helper_bytes.clone(),
            mode: 0o755,
        });
    }
    for (path, bytes, mode) in [
        (BINARY, source_snapshot.agent_bytes, 0o755),
        (UNIT, SERVICE.as_bytes().to_vec(), 0o644),
        (SOCKET_UNIT, SOCKET.as_bytes().to_vec(), 0o644),
        (LAUNCHER_UNIT, LAUNCHER_SERVICE.as_bytes().to_vec(), 0o644),
        (
            LAUNCHER_SOCKET_UNIT,
            LAUNCHER_SOCKET.as_bytes().to_vec(),
            0o644,
        ),
        (
            NETWORK_LAUNCHER_UNIT,
            NETWORK_LAUNCHER_SERVICE.as_bytes().to_vec(),
            0o644,
        ),
        (
            NETWORK_LAUNCHER_SOCKET_UNIT,
            NETWORK_LAUNCHER_SOCKET.as_bytes().to_vec(),
            0o644,
        ),
        (TMPFILES_FILE, TMPFILES.as_bytes().to_vec(), 0o644),
        (
            crate::linux::runtime_manifest::INSTALLED,
            source_snapshot.manifest_bytes.clone(),
            0o644,
        ),
    ] {
        changes.push(PackageFileChange {
            path: Path::new(path).to_path_buf(),
            bytes: Some(bytes),
            mode,
        });
    }
    let transaction = PackageFileTransaction::apply(changes)?;
    let installed = (|| {
        verify_installed_package_against(&source_digest)?;
        if source_snapshot.v3 {
            let candidate = crate::linux::runtime_manifest::source_v3_candidate(Path::new(BINARY))?
                .ok_or("installed V3 candidate disappeared")?;
            if candidate.manifest_bytes != source_snapshot.manifest_bytes
                || candidate.qualification_sha256
                    != source_snapshot
                        .qualification
                        .as_ref()
                        .map(|(_, bytes)| memcordon_core::workload_codec::hash_bytes(bytes))
            {
                return Err("installed V3/Q candidate differs from snapshotted source".into());
            }
            let installed_snapshot = linux_source_snapshot(Path::new(BINARY))?;
            if installed_snapshot.arm32_helper_bytes != source_snapshot.arm32_helper_bytes
                || installed_snapshot.release_build != source_snapshot.release_build
                || installed_snapshot.release_certificate != source_snapshot.release_certificate
            {
                return Err("installed ARM32 helper or signed release proof changed".into());
            }
            if candidate.qualification_sha256.is_some() {
                // Admission of a qualified M1 requires the independently
                // provisioned root and a live, signed CQ before any service
                // or optional network launcher is activated. The later H1
                // operation revalidates this under the installed generation.
                crate::linux::installed_release_qualification::verify_anchored_native_qualification(
                    &candidate,
                )?;
            }
        }
        systemctl(["daemon-reload"])?;
        disable_optional_network_launcher()?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.service")?;
        ensure_unit_inactive("memcordon-sealed-network-launcher.socket")?;
        if ephemeral_ci {
            systemctl(["start", "memcordon-sealed-launcher.socket"])?;
            systemctl(["start", "memcordon-sealed-agent.socket"])?;
        } else {
            systemctl(["enable", "--now", "memcordon-sealed-launcher.socket"])?;
            systemctl(["enable", "--now", "memcordon-sealed-agent.socket"])?;
        }
        systemctl(["restart", "memcordon-sealed-launcher.service"])?;
        systemctl(["restart", "memcordon-sealed-agent.service"])?;
        wait_provider_ready()?;
        // Root deliberately bypasses ordinary directory and socket ACL checks.
        verify_client_access_configuration()
    })();
    if let Err(error) = installed {
        let _ = stop_unit("memcordon-sealed-agent.service");
        let _ = stop_unit("memcordon-sealed-launcher.service");
        let _ = stop_unit("memcordon-sealed-agent.socket");
        let _ = stop_unit("memcordon-sealed-launcher.socket");
        let rollback = transaction.rollback();
        let reload = systemctl(["daemon-reload"]);
        return Err(format!(
            "package install/upgrade failed: {error}; rollback: {rollback:?}; daemon reload: {reload:?}"
        ));
    }
    transaction.commit()
}

#[cfg(target_os = "linux")]
fn remove_uninstalled_file(path: &str) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "provider uninstall could not remove residual file {path}: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn remove_uninstalled_directory(path: &str) -> Result<(), String> {
    match std::fs::remove_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "provider uninstall found residual state in {path}: {error}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn ensure_recovery_idle(operation: &str) -> Result<(), String> {
    let ambiguous = crate::linux::recovery::recover()?;
    if !ambiguous.is_empty() {
        return Err(format!(
            "refusing to {operation} while sealed recovery is ambiguous: {}",
            ambiguous.join(",")
        ));
    }
    if live_attempt_exists()? {
        return Err(format!(
            "refusing to {operation} while an authenticated attempt record exists"
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_client_access_configuration() -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let allowed_gid = service_group_gid()?;
    let directory = std::fs::symlink_metadata("/run/memcordon")
        .map_err(|error| format!("provider runtime directory unavailable: {error}"))?;
    if !directory.file_type().is_dir()
        || directory.uid() != 0
        || directory.gid() != allowed_gid
        || directory.mode() & 0o777 != 0o750
    {
        return Err("provider runtime directory identity or permissions are unsafe".to_owned());
    }
    let socket = std::fs::symlink_metadata("/run/memcordon/sealed-agent.sock")
        .map_err(|error| format!("provider endpoint unavailable: {error}"))?;
    if !socket.file_type().is_socket()
        || socket.uid() != 0
        || socket.gid() != allowed_gid
        || socket.mode() & 0o777 != 0o660
    {
        return Err("provider endpoint identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn service_group_gid() -> Result<libc::gid_t, String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: package mutation is single-threaded; `name` is NUL-terminated and live for the
    // lookup, and the returned libc database pointer is read immediately without retention.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Err("memcordon service group is unavailable".to_owned());
    }
    // SAFETY: the null case was rejected and the group database entry remains valid until the
    // next group lookup in this single-threaded process.
    Ok(unsafe { (*group).gr_gid })
}

#[cfg(target_os = "linux")]
pub fn probe_provider() -> Result<crate::linux::qualification::QualificationReceipt, String> {
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    use crate::protocol::{Frame, MessageKind, read_frame, write_frame};

    let mut stream = UnixStream::connect("/run/memcordon/sealed-agent.sock")
        .map_err(|error| readiness_error(&error.to_string()))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| readiness_error(&error.to_string()))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(60)))
        .map_err(|error| readiness_error(&error.to_string()))?;
    let nonce = [0x52; 16];
    write_frame(
        &mut stream,
        &Frame {
            kind: MessageKind::Probe,
            nonce,
            attempt_id: [0; 16],
            payload: Vec::new(),
        },
    )
    .map_err(|error| readiness_error(&error.to_string()))?;
    let receipt = read_frame(&mut stream).map_err(|error| readiness_error(&error.to_string()))?;
    if receipt.nonce != nonce || receipt.attempt_id != [0; 16] {
        return Err(readiness_error("response identity mismatch"));
    }
    if receipt.kind == MessageKind::Rejected {
        let reason = std::str::from_utf8(&receipt.payload)
            .map_err(|error| readiness_error(&format!("invalid rejection payload: {error}")))?;
        return Err(readiness_error(&format!(
            "provider rejected probe: {reason}"
        )));
    }
    if receipt.kind != MessageKind::ProbeReceipt {
        return Err(readiness_error("unexpected response kind"));
    }
    let qualification: crate::linux::qualification::QualificationReceipt =
        serde_json::from_slice(&receipt.payload)
            .map_err(|error| readiness_error(&error.to_string()))?;
    if qualification.schema_version != 3
        || qualification.mechanism != "linux-pid-namespace-cgroup-v2"
        || qualification.provider_identity.is_empty()
        || qualification.receipt_digest.is_empty()
        || !qualification.complete()
    {
        return Err(readiness_error("incomplete qualification"));
    }
    Ok(qualification)
}

#[cfg(target_os = "linux")]
fn wait_provider_ready() -> Result<(), String> {
    let _qualification = probe_provider()?;
    if live_attempt_exists()? {
        return Err(readiness_error("provider is not idle"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn live_attempt_exists() -> Result<bool, String> {
    let state_root = std::path::Path::new("/var/lib/memcordon/sealed");
    if !state_root.exists() {
        return Ok(false);
    }
    for entry in std::fs::read_dir(state_root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.file_name() != crate::linux::private_qualification::PROBE_DIRECTORY_NAME {
            return Ok(true);
        }
        if !crate::linux::private_qualification::pending_records(&entry.path())?.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
fn ensure_service_group() -> Result<libc::gid_t, String> {
    let name = std::ffi::CString::new("memcordon").expect("static group name has no NUL");
    // SAFETY: libc receives initialized scalar arguments and pointers into live owned buffers or handles; the return value governs ownership and error cleanup.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if !group.is_null() {
        // SAFETY: getgrnam returned a live libc-managed group record.
        return Ok(unsafe { (*group).gr_gid });
    }
    let status = std::process::Command::new("/usr/sbin/groupadd")
        .args(["--system", "memcordon"])
        .status()
        .map_err(|error| format!("could not create service group: {error}"))?;
    if !status.success() {
        return Err(format!("service group creation failed with {status}"));
    }
    // SAFETY: groupadd succeeded and name remains a live NUL-terminated lookup key.
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Err("service group was not visible after successful creation".to_owned());
    }
    // SAFETY: getgrnam returned a live libc-managed group record.
    Ok(unsafe { (*group).gr_gid })
}

#[cfg(target_os = "linux")]
fn ensure_probe_account() -> Result<(), String> {
    let name = std::ffi::CString::new("memcordon-qualify")
        .expect("static qualification account has no NUL");
    // SAFETY: this package mutation runs single-threaded and reads the returned
    // entry before any other account database lookup can invalidate it.
    let existing = unsafe { libc::getpwnam(name.as_ptr()) };
    if existing.is_null() {
        let status = std::process::Command::new("/usr/sbin/useradd")
            .args([
                "--system",
                "--user-group",
                "--no-create-home",
                "--home-dir",
                "/nonexistent",
                "--shell",
                "/usr/sbin/nologin",
                "memcordon-qualify",
            ])
            .status()
            .map_err(|error| format!("could not create qualification account: {error}"))?;
        if !status.success() {
            return Err(format!(
                "qualification account creation failed with {status}"
            ));
        }
    }
    let _numeric_identity = crate::linux::private_qualification::fixed_probe_account()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_probe_working_directory() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let path = Path::new(crate::linux::private_qualification::PROBE_WORKING_DIRECTORY);
    let parent = path.parent().ok_or("qualification workdir parent absent")?;
    std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err("qualification workdir parent is not protected".into());
    }
    match std::fs::create_dir(path) {
        Ok(()) => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o555))
            .map_err(|error| error.to_string())?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(format!("qualification workdir creation: {error}")),
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o555
        || std::fs::read_dir(path)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
    {
        return Err("qualification workdir identity, mode or emptiness differs".into());
    }
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "linux")]
fn systemctl<const N: usize>(arguments: [&str; N]) -> Result<(), String> {
    let status = std::process::Command::new("/usr/bin/systemctl")
        .args(arguments)
        .status()
        .map_err(|error| error.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("systemctl failed with {status}"))
    }
}

#[cfg(target_os = "linux")]
fn disable_optional_network_launcher() -> Result<(), String> {
    for (unit, path) in [
        (
            "memcordon-sealed-network-launcher.socket",
            NETWORK_LAUNCHER_SOCKET_UNIT,
        ),
        (
            "memcordon-sealed-network-launcher.service",
            NETWORK_LAUNCHER_UNIT,
        ),
    ] {
        if std::path::Path::new(path)
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            systemctl(["disable", "--now", unit])?;
            ensure_unit_inactive(unit)?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_unit_inactive(unit: &str) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=ActiveState", "--value", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    if !output.status.success() {
        if unit_load_state(unit)? == "not-found" {
            return Ok(());
        }
        return Err(format!(
            "MCSEALED-PACKAGE-STOP-PROOF: systemctl show failed with {}",
            output.status
        ));
    }
    let state = std::str::from_utf8(&output.stdout)
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?
        .trim();
    if matches!(state, "inactive" | "failed") {
        Ok(())
    } else {
        Err(format!(
            "MCSEALED-PACKAGE-STOP-PROOF: {unit} remained {state}"
        ))
    }
}

#[cfg(target_os = "linux")]
fn stop_unit(unit: &str) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["stop", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP: unit={unit}; invocation-error={error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let diagnostic = systemctl_output_diagnostic(&output);
    match unit_load_state(unit) {
        Ok(state) if state == "not-found" => Ok(()),
        Ok(state) => Err(format!(
            "MCSEALED-PACKAGE-STOP: unit={unit}; load-state={state}; systemctl-output={diagnostic}"
        )),
        Err(error) => Err(format!(
            "MCSEALED-PACKAGE-STOP: unit={unit}; load-state-error={error}; systemctl-output={diagnostic}"
        )),
    }
}

#[cfg(target_os = "linux")]
fn systemctl_output_diagnostic(output: &std::process::Output) -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1,
        "program": "/usr/bin/systemctl",
        "status": output.status.to_string(),
        "status_code": output.status.code(),
        "stdout": bounded_systemctl_stream(&output.stdout),
        "stderr": bounded_systemctl_stream(&output.stderr),
    })
}

#[cfg(target_os = "linux")]
fn bounded_systemctl_stream(bytes: &[u8]) -> serde_json::Value {
    use std::fmt::Write as _;

    const MAXIMUM_BYTES: usize = 4 * 1024;
    let retained = &bytes[..bytes.len().min(MAXIMUM_BYTES)];
    let truncated = retained.len() != bytes.len();
    match std::str::from_utf8(retained) {
        Ok(data) => serde_json::json!({
            "encoding": "utf-8",
            "data": data,
            "original_bytes": bytes.len(),
            "truncated": truncated,
        }),
        Err(_) => {
            let mut data = String::new();
            for byte in retained {
                write!(&mut data, "{byte:02x}").expect("writing hexadecimal to a string succeeds");
            }
            serde_json::json!({
                "encoding": "hex",
                "data": data,
                "original_bytes": bytes.len(),
                "truncated": truncated,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn unit_load_state(unit: &str) -> Result<String, String> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["show", "--property=LoadState", "--value", unit])
        .output()
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))?;
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("MCSEALED-PACKAGE-STOP-PROOF: {error}"))
}

#[cfg(target_os = "linux")]
fn readiness_error(cause: &str) -> String {
    const MAX_SYSTEMD_BYTES: usize = 16 * 1024;
    const MAX_JOURNAL_BYTES: usize = 32 * 1024;
    let systemd = bounded_command_diagnostic(
        "/usr/bin/systemctl",
        &[
            "show",
            "--no-pager",
            "--property=LoadState",
            "--property=ActiveState",
            "--property=SubState",
            "--property=Result",
            "--property=ExecMainStatus",
            "memcordon-sealed-agent.service",
        ],
        MAX_SYSTEMD_BYTES,
        false,
    );
    let journal = bounded_command_diagnostic(
        "/usr/bin/journalctl",
        &[
            "--unit",
            "memcordon-sealed-agent.service",
            "--boot",
            "--no-pager",
            "--output=json",
            "--lines=50",
        ],
        MAX_JOURNAL_BYTES,
        true,
    );
    let startup = match crate::linux::startup::read() {
        Ok(Some(record)) => serde_json::to_value(record)
            .unwrap_or_else(|error| serde_json::json!({"query_error": error.to_string()})),
        Ok(None) => serde_json::Value::Null,
        Err(error) => serde_json::json!({"query_error": error}),
    };
    let diagnostics = serde_json::json!({
        "systemd": systemd,
        "startup_failure": startup,
        "journal": journal,
    });
    format!("MCSEALED-PROVIDER-READINESS: {cause}; diagnostics={diagnostics}")
}

#[cfg(target_os = "linux")]
fn bounded_command_diagnostic(
    program: &str,
    arguments: &[&str],
    maximum_bytes: usize,
    parse_json_lines: bool,
) -> serde_json::Value {
    let output = std::process::Command::new(program).args(arguments).output();
    match output {
        Ok(output) if output.stdout.len().saturating_add(output.stderr.len()) <= maximum_bytes => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            let content = if parse_json_lines {
                let mut entries = Vec::new();
                for line in stdout.lines() {
                    match serde_json::from_str::<serde_json::Value>(line) {
                        Ok(entry) => entries.push(entry),
                        Err(error) => {
                            return serde_json::json!({
                                "status": output.status.code(),
                                "parse_error": error.to_string(),
                                "stderr": stderr,
                            });
                        }
                    }
                }
                serde_json::json!({"entries": entries})
            } else {
                serde_json::json!({"lines": stdout.lines().collect::<Vec<_>>()})
            };
            serde_json::json!({
                "status": output.status.code(),
                "content": content,
                "stderr": stderr,
                "truncated": false,
            })
        }
        Ok(output) => serde_json::json!({
            "status": output.status.code(),
            "error": "diagnostic exceeded bounded payload",
            "truncated": true,
        }),
        Err(error) => serde_json::json!({
            "error": error.to_string(),
            "truncated": false,
        }),
    }
}
