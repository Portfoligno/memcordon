//! Protected installed-host receipt storage. Candidate package bytes and a
//! completed native canary are not, by themselves, release-Q provenance.

use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_qualification::PROBE_ROOT;

const ACTIVE: &str = "active";
const MAX_ACTIVE_BYTES: usize = 1024;
const PUBLICATION_LOCK: &str = "publication.lock";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ActiveHostReferenceV1 {
    schema_version: u8,
    run_nonce: String,
    receipt_sha256: DiagnosticSha256,
    native_run_digest: DiagnosticSha256,
    host_prerequisites_digest: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    release_qualification_sha256: DiagnosticSha256,
}

impl ActiveHostReferenceV1 {
    fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.is_empty() || bytes.len() > MAX_ACTIVE_BYTES {
            return Err("MCSEALED-PRIVATE-HOST: active reference bound differs".into());
        }
        memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
        let active: Self = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if active.schema_version != 1
            || active.run_nonce.len() != [0_u8; 32].len() * 2
            || !active
                .run_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || active.run_nonce.bytes().all(|byte| byte == b'0')
        {
            return Err("MCSEALED-PRIVATE-HOST: active run identity differs".into());
        }
        Ok(active)
    }
}

#[allow(dead_code)]
pub(crate) struct VerifiedActiveHostV1 {
    _package: crate::package::VerifiedProbePackageLease,
    active: ActiveHostReferenceV1,
    receipt: super::qualification_schema::QualificationReceiptV4,
}

pub(crate) struct VerifiedDetachedCandidateV1 {
    _package: crate::package::VerifiedProbePackageLease,
    run: super::private_qualification::VerifiedHostRunV1,
    nonce: [u8; 32],
}

impl VerifiedDetachedCandidateV1 {
    #[allow(dead_code)]
    pub(crate) fn run(&self) -> &super::private_qualification::VerifiedHostRunV1 {
        &self.run
    }
}

/// Builds only candidate bytes. Durable receipt/active publication requires a
/// separately authenticated detached coordinator outcome and is intentionally
/// not exposed by this function.
#[allow(dead_code)]
pub(crate) fn encode_candidate_receipt(
    package: &crate::package::VerifiedProbePackageLease,
    release: &super::installed_release_qualification::TrustedReleaseQualification,
    run: &super::private_qualification::VerifiedHostRunV1,
) -> Result<Vec<u8>, String> {
    require_coordinator_exited(run.coordinator())?;
    if release.reference().artifact_sha256 != package.release_qualification_sha256 {
        return Err("MCSEALED-PRIVATE-HOST: trusted release Q differs from installed Q".into());
    }
    let prerequisites = super::private_host_prerequisites::observe_host_prerequisites(package)?;
    if &prerequisites.digest()? != run.host_prerequisites_digest()
        || prerequisites.installation_epoch() != run.installation_epoch()
    {
        return Err("MCSEALED-PRIVATE-HOST: current prerequisites differ from native run".into());
    }
    let filter_abi = match package.target.as_str() {
        "x86_64-unknown-linux-gnu" => "x86_64",
        "aarch64-unknown-linux-gnu" => "aarch64",
        _ => return Err("MCSEALED-PRIVATE-HOST: installed target ABI differs".into()),
    };
    let mut receipt = super::qualification_schema::QualificationReceiptV4 {
        schema_version: 4,
        version: env!("CARGO_PKG_VERSION").into(),
        source_commit: package.source_commit.clone(),
        target: package.target.clone(),
        boot_id: prerequisites.boot_id().into(),
        installed_runtime_manifest_sha256: package.runtime_manifest_sha256.clone(),
        installed_agent_sha256: package.agent_sha256.clone(),
        installed_units: package.units.clone(),
        filter_abi: filter_abi.into(),
        filter_instruction_sha256: package.filter_sha256.clone(),
        profile_catalog_sha256: memcordon_core::workload_discovery_v2::profile_catalog_digest_v2(),
        host_prerequisites_digest: run.host_prerequisites_digest().clone(),
        native_run_digest: run.native_run_digest().clone(),
        probes: run.probes().to_vec(),
        receipt_digest: DiagnosticSha256::from_bytes([0; 32]),
    };
    receipt.receipt_digest = receipt.canonical_digest()?;
    let bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
    let digest = hash_bytes(&bytes);
    let probes: Vec<_> = run
        .probes()
        .iter()
        .map(
            |probe| super::qualification_schema::TrustedQualificationProbeV4 {
                profile: &probe.profile,
                name: &probe.name,
                native_executed: probe.native_executed,
                completion_digest: &probe.completion_digest,
            },
        )
        .collect();
    let trusted = super::qualification_schema::TrustedQualificationReceiptV4 {
        source_commit: &package.source_commit,
        target: &package.target,
        boot_id: prerequisites.boot_id(),
        installed_runtime_manifest_sha256: &package.runtime_manifest_sha256,
        installed_agent_sha256: &package.agent_sha256,
        installed_units: &package.units,
        filter_instruction_sha256: &package.filter_sha256,
        host_prerequisites_digest: run.host_prerequisites_digest(),
        native_run_digest: run.native_run_digest(),
        probes: &probes,
        receipt_sha256: &digest,
    };
    super::qualification_schema::QualificationReceiptV4::parse_and_validate(&bytes, &trusted)?;
    Ok(bytes)
}

impl VerifiedActiveHostV1 {
    #[allow(dead_code)]
    pub(crate) fn receipt(&self) -> &super::qualification_schema::QualificationReceiptV4 {
        &self.receipt
    }

    pub(crate) fn receipt_sha256(&self) -> &DiagnosticSha256 {
        &self.active.receipt_sha256
    }

    pub(crate) fn installation_epoch(&self) -> &DiagnosticSha256 {
        &self.active.installation_epoch
    }

    pub(crate) fn release_qualification_sha256(&self) -> &DiagnosticSha256 {
        &self.active.release_qualification_sha256
    }
}

fn open_root() -> Result<Option<File>, String> {
    let directory = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PROBE_ROOT)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("MCSEALED-PRIVATE-HOST: root open: {error}")),
    };
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-HOST: protected root differs".into());
    }
    Ok(Some(directory))
}

fn open_protected_leaf(directory: &File, name: &str) -> Result<Option<File>, String> {
    let name = CString::new(name).map_err(|_| "MCSEALED-PRIVATE-HOST: unsafe leaf")?;
    // SAFETY: openat is rooted at the pinned protected directory and rejects
    // leaf symlinks; a missing active reference means not qualified.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.kind() == std::io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(format!("MCSEALED-PRIVATE-HOST: leaf open: {error}"));
    }
    // SAFETY: successful openat transferred one unique descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let owner = directory
        .metadata()
        .map_err(|error| error.to_string())?
        .uid();
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("MCSEALED-PRIVATE-HOST: protected leaf differs".into());
    }
    Ok(Some(file))
}

fn read_protected_bytes(
    directory: &File,
    name: &str,
    limit: usize,
) -> Result<Option<Vec<u8>>, String> {
    let Some(file) = open_protected_leaf(directory, name)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > limit {
        return Err("MCSEALED-PRIVATE-HOST: protected leaf byte bound differs".into());
    }
    Ok(Some(bytes))
}

fn open_publication_lock(root: &File) -> Result<File, String> {
    let name = CString::new(PUBLICATION_LOCK).expect("fixed publication lock name");
    // SAFETY: the fixed leaf is opened relative to the protected root; the
    // descriptor, not the pathname, is then locked for the entire publication.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: publication lock open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let lock = unsafe { File::from_raw_fd(fd) };
    let metadata = lock.metadata().map_err(|error| error.to_string())?;
    let owner = root.metadata().map_err(|error| error.to_string())?.uid();
    if !metadata.is_file()
        || metadata.uid() != owner
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err("MCSEALED-PRIVATE-HOST: publication lock protection differs".into());
    }
    // SAFETY: flock applies to the retained descriptor and waits only for a
    // concurrent protected publisher, not for a caller-selected resource.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: publication lock acquire: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(lock)
}

fn write_new_or_matching(
    root: &File,
    name: &str,
    bytes: &[u8],
    limit: usize,
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err("MCSEALED-PRIVATE-HOST: publication byte bound differs".into());
    }
    let leaf = CString::new(name).map_err(|_| "MCSEALED-PRIVATE-HOST: unsafe publication leaf")?;
    // SAFETY: the name is fixed or derived from a checked nonce, and O_EXCL
    // never overwrites prior evidence after a crash or concurrent invocation.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(format!(
                "MCSEALED-PRIVATE-HOST: publication create: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else {
        // SAFETY: successful openat returned one owned descriptor.
        let mut file = unsafe { File::from_raw_fd(fd) };
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| error.to_string())?;
        root.sync_all().map_err(|error| error.to_string())?;
    }
    if read_protected_bytes(root, name, limit)?.as_deref() != Some(bytes) {
        return Err("MCSEALED-PRIVATE-HOST: publication readback differs".into());
    }
    Ok(())
}

fn persist_receipt(root: &File, name: &str, bytes: &[u8]) -> Result<(), String> {
    let limit = memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES;
    if let Some(existing) = read_protected_bytes(root, name, limit)? {
        return if existing == bytes {
            Ok(())
        } else {
            Err("MCSEALED-PRIVATE-HOST: existing receipt bytes differ".into())
        };
    }
    let temporary = format!("{name}.new");
    write_new_or_matching(root, &temporary, bytes, limit)?;
    let from = CString::new(temporary).map_err(|_| "MCSEALED-PRIVATE-HOST: unsafe receipt temp")?;
    let to = CString::new(name).map_err(|_| "MCSEALED-PRIVATE-HOST: unsafe receipt leaf")?;
    // SAFETY: fixed nonce-derived leaves remain below one protected directory.
    // RENAME_NOREPLACE prevents replacing existing native evidence.
    let status = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            root.as_raw_fd(),
            from.as_ptr(),
            root.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if status == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: receipt rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all().map_err(|error| error.to_string())?;
    if read_protected_bytes(root, name, limit)?.as_deref() != Some(bytes) {
        return Err("MCSEALED-PRIVATE-HOST: receipt readback differs".into());
    }
    Ok(())
}

fn publish_receipt_then_active(
    root: &File,
    nonce: &str,
    receipt_bytes: &[u8],
    active_bytes: &[u8],
) -> Result<ActiveHostReferenceV1, String> {
    let active = ActiveHostReferenceV1::parse(active_bytes)?;
    if active.run_nonce != nonce || active.receipt_sha256 != hash_bytes(receipt_bytes) {
        return Err("MCSEALED-PRIVATE-HOST: publication identity differs".into());
    }
    let receipt_name = format!("receipt-{nonce}.json");
    persist_receipt(root, &receipt_name, receipt_bytes)?;
    if let Some(existing) = read_protected_bytes(root, ACTIVE, MAX_ACTIVE_BYTES)? {
        ActiveHostReferenceV1::parse(&existing)?;
        if existing == active_bytes {
            return Ok(active);
        }
    }
    let temporary = format!("active.{nonce}.new");
    write_new_or_matching(root, &temporary, active_bytes, MAX_ACTIVE_BYTES)?;
    let from = CString::new(temporary).expect("lower-hex nonce has no NUL");
    let to = CString::new(ACTIVE).expect("fixed active leaf has no NUL");
    // SAFETY: both names are fixed/protected leaves below the retained root.
    // Receipt bytes have been fsynced and read back before this single rename.
    if unsafe {
        libc::renameat(
            root.as_raw_fd(),
            from.as_ptr(),
            root.as_raw_fd(),
            to.as_ptr(),
        )
    } == -1
    {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: active rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all().map_err(|error| error.to_string())?;
    if read_protected_bytes(root, ACTIVE, MAX_ACTIVE_BYTES)?.as_deref() != Some(active_bytes) {
        return Err("MCSEALED-PRIVATE-HOST: active publication readback differs".into());
    }
    Ok(active)
}

/// Persist the candidate receipt before atomically replacing the active
/// reference. The only caller must possess independently verified release Q;
/// installed M1/Q bytes and a host run alone cannot enter this function.
#[allow(dead_code)]
pub(crate) fn publish_verified_active(
    release: &super::installed_release_qualification::TrustedReleaseQualification,
    candidate: VerifiedDetachedCandidateV1,
) -> Result<VerifiedActiveHostV1, String> {
    let root = open_root()?.ok_or("MCSEALED-PRIVATE-HOST: protected root absent")?;
    let _publication_lock = open_publication_lock(&root)?;
    let name = candidate
        .nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let run_directory = open_run_directory(&root, &name)?;
    let current = super::private_qualification::verify_completed_run_after_exit(
        &candidate.nonce,
        &run_directory,
        &candidate._package,
    )?;
    require_coordinator_exited(current.coordinator())?;
    if current.native_run_digest() != candidate.run.native_run_digest()
        || current.host_prerequisites_digest() != candidate.run.host_prerequisites_digest()
        || current.installation_epoch() != candidate.run.installation_epoch()
        || current.probes() != candidate.run.probes()
    {
        return Err("MCSEALED-PRIVATE-HOST: detached candidate changed before publication".into());
    }
    let receipt_bytes = encode_candidate_receipt(&candidate._package, release, &current)?;
    let receipt_sha256 = hash_bytes(&receipt_bytes);
    let active = ActiveHostReferenceV1 {
        schema_version: 1,
        run_nonce: name.clone(),
        receipt_sha256,
        native_run_digest: current.native_run_digest().clone(),
        host_prerequisites_digest: current.host_prerequisites_digest().clone(),
        installation_epoch: current.installation_epoch().clone(),
        release_qualification_sha256: candidate._package.release_qualification_sha256.clone(),
    };
    let active_bytes = serde_json::to_vec(&active).map_err(|error| error.to_string())?;
    if publish_receipt_then_active(&root, &name, &receipt_bytes, &active_bytes)? != active {
        return Err("MCSEALED-PRIVATE-HOST: active publication readback differs".into());
    }
    drop(candidate);
    let verified = read_current_active(release)?
        .ok_or("MCSEALED-PRIVATE-HOST: active readback disappeared")?;
    if verified.active != active {
        return Err("MCSEALED-PRIVATE-HOST: active readback changed".into());
    }
    Ok(verified)
}

/// Invoked under the package transaction's exclusive generation lock before
/// any installation mutation. Missing active state is already unavailable.
#[allow(dead_code)]
pub(crate) fn revoke_active() -> Result<(), String> {
    let Some(root) = open_root()? else {
        return Ok(());
    };
    let Some(_active) = open_protected_leaf(&root, ACTIVE)? else {
        return Ok(());
    };
    let name = CString::new(ACTIVE).expect("fixed active leaf");
    // SAFETY: unlinkat targets only the fixed active leaf under the retained
    // protected root. No user-selected path or recursive deletion is used.
    if unsafe { libc::unlinkat(root.as_raw_fd(), name.as_ptr(), 0) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: active revoke: {}",
            std::io::Error::last_os_error()
        ));
    }
    root.sync_all().map_err(|error| error.to_string())
}

#[allow(dead_code)]
pub(crate) fn read_active() -> Result<Option<ActiveHostReferenceV1>, String> {
    let Some(root) = open_root()? else {
        return Ok(None);
    };
    let Some(file) = open_protected_leaf(&root, ACTIVE)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_ACTIVE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    ActiveHostReferenceV1::parse(&bytes).map(Some)
}

fn decode_nonce(value: &str) -> Result<[u8; 32], String> {
    let mut nonce = [0_u8; 32];
    if value.len() != nonce.len() * 2 {
        return Err("MCSEALED-PRIVATE-HOST: run nonce length differs".into());
    }
    for (index, byte) in nonce.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "MCSEALED-PRIVATE-HOST: run nonce syntax differs")?;
    }
    Ok(nonce)
}

fn open_run_directory(root: &File, nonce: &str) -> Result<File, String> {
    let name = CString::new(nonce).map_err(|_| "MCSEALED-PRIVATE-HOST: unsafe run name")?;
    // SAFETY: the run name has already passed strict fixed-width lower-hex
    // validation and openat rejects a symlink or non-directory leaf.
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-HOST: run directory open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned directory descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-HOST: run directory protection differs".into());
    }
    Ok(directory)
}

fn require_coordinator_exited(
    recorded: &super::private_attempt::ProcessIdentityV4,
) -> Result<(), String> {
    let pid = recorded.pid as libc::pid_t;
    // SAFETY: pidfd_open observes only the positive PID found in the protected
    // native ledger. An absent PID proves that coordinator cannot still run.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if raw == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(format!("MCSEALED-PRIVATE-HOST: coordinator pidfd: {error}"));
    }
    // SAFETY: successful pidfd_open transferred a unique owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let current = super::private_attempt::ProcessIdentityV4::observe(pid, pidfd.as_fd())?;
    if current != *recorded {
        return Ok(());
    }
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the retained coordinator pidfd.
    if unsafe { libc::poll(&raw mut pollfd, 1, 0) } == 1 && pollfd.revents & libc::POLLIN != 0 {
        return Ok(());
    }
    Err("MCSEALED-PRIVATE-HOST: coordinator is still live".into())
}

#[cfg(feature = "test-support")]
pub(crate) fn require_coordinator_exited_for_test(
    recorded: &super::private_attempt::ProcessIdentityV4,
) -> Result<(), String> {
    require_coordinator_exited(recorded)
}

/// Second-stage root-only readback. The first coordinator must have exited;
/// an administrator-supplied nonce is only a selector, never trusted facts.
pub(crate) fn verify_detached_candidate(
    nonce: &[u8; 32],
) -> Result<VerifiedDetachedCandidateV1, String> {
    if *nonce == [0; 32] || unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-HOST: detached finalizer authority differs".into());
    }
    let package = crate::package::acquire_verified_probe_package_lease()?;
    let root = open_root()?.ok_or("MCSEALED-PRIVATE-HOST: protected root absent")?;
    let name = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let directory = open_run_directory(&root, &name)?;
    let run =
        super::private_qualification::verify_completed_run_after_exit(nonce, &directory, &package)?;
    require_coordinator_exited(run.coordinator())?;
    Ok(VerifiedDetachedCandidateV1 {
        _package: package,
        run,
        nonce: *nonce,
    })
}

/// Reconstructs expected receipt facts from the installed candidate package,
/// current kernel/service prerequisites and every protected native completion.
/// The trusted Q token is intentionally unconstructible until independent
/// release-run provenance exists; candidate M1/Q cannot call this route.
#[allow(dead_code)]
pub(crate) fn read_current_active(
    release: &super::installed_release_qualification::TrustedReleaseQualification,
) -> Result<Option<VerifiedActiveHostV1>, String> {
    let package = crate::package::acquire_verified_probe_package_lease()?;
    if release.reference().artifact_sha256 != package.release_qualification_sha256 {
        return Err("MCSEALED-PRIVATE-HOST: trusted release Q differs from installed Q".into());
    }
    let Some(root) = open_root()? else {
        return Ok(None);
    };
    let Some(active_file) = open_protected_leaf(&root, ACTIVE)? else {
        return Ok(None);
    };
    let mut active_bytes = Vec::new();
    active_file
        .take(MAX_ACTIVE_BYTES as u64 + 1)
        .read_to_end(&mut active_bytes)
        .map_err(|error| error.to_string())?;
    let active = ActiveHostReferenceV1::parse(&active_bytes)?;
    let nonce = decode_nonce(&active.run_nonce)?;
    let run_directory = open_run_directory(&root, &active.run_nonce)?;
    let verified = super::private_qualification::verify_completed_run_after_exit(
        &nonce,
        &run_directory,
        &package,
    )?;
    require_coordinator_exited(verified.coordinator())?;
    if verified.native_run_digest() != &active.native_run_digest
        || verified.host_prerequisites_digest() != &active.host_prerequisites_digest
        || verified.installation_epoch() != &active.installation_epoch
        || package.release_qualification_sha256 != active.release_qualification_sha256
    {
        return Err("MCSEALED-PRIVATE-HOST: active native run or prerequisites differ".into());
    }
    let receipt_name = format!("receipt-{}.json", active.run_nonce);
    let Some(receipt_file) = open_protected_leaf(&root, &receipt_name)? else {
        return Err("MCSEALED-PRIVATE-HOST: active receipt absent".into());
    };
    let mut receipt_bytes = Vec::new();
    receipt_file
        .take(memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES as u64 + 1)
        .read_to_end(&mut receipt_bytes)
        .map_err(|error| error.to_string())?;
    if hash_bytes(&receipt_bytes) != active.receipt_sha256 {
        return Err("MCSEALED-PRIVATE-HOST: protected receipt bytes differ".into());
    }
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| error.to_string())?;
    let boot_id = boot_id.trim();
    let probes: Vec<_> = verified
        .probes()
        .iter()
        .map(
            |probe| super::qualification_schema::TrustedQualificationProbeV4 {
                profile: &probe.profile,
                name: &probe.name,
                native_executed: probe.native_executed,
                completion_digest: &probe.completion_digest,
            },
        )
        .collect();
    let trusted = super::qualification_schema::TrustedQualificationReceiptV4 {
        source_commit: &package.source_commit,
        target: &package.target,
        boot_id,
        installed_runtime_manifest_sha256: &package.runtime_manifest_sha256,
        installed_agent_sha256: &package.agent_sha256,
        installed_units: &package.units,
        filter_instruction_sha256: &package.filter_sha256,
        host_prerequisites_digest: verified.host_prerequisites_digest(),
        native_run_digest: verified.native_run_digest(),
        probes: &probes,
        receipt_sha256: &active.receipt_sha256,
    };
    let receipt = super::qualification_schema::QualificationReceiptV4::parse_and_validate(
        &receipt_bytes,
        &trusted,
    )?;
    let Some(current_file) = open_protected_leaf(&root, ACTIVE)? else {
        return Err("MCSEALED-PRIVATE-HOST: active reference changed during readback".into());
    };
    let mut current_bytes = Vec::new();
    current_file
        .take(MAX_ACTIVE_BYTES as u64 + 1)
        .read_to_end(&mut current_bytes)
        .map_err(|error| error.to_string())?;
    let Some(current_root) = open_root()? else {
        return Err("MCSEALED-PRIVATE-HOST: protected root changed during readback".into());
    };
    let initial_root = root.metadata().map_err(|error| error.to_string())?;
    let final_root = current_root.metadata().map_err(|error| error.to_string())?;
    if current_bytes != active_bytes
        || initial_root.dev() != final_root.dev()
        || initial_root.ino() != final_root.ino()
    {
        return Err("MCSEALED-PRIVATE-HOST: active reference changed during readback".into());
    }
    Ok(Some(VerifiedActiveHostV1 {
        _package: package,
        active,
        receipt,
    }))
}

#[cfg(feature = "test-support")]
pub(crate) fn parse_active_for_test(bytes: &[u8]) -> Result<(), String> {
    ActiveHostReferenceV1::parse(bytes).map(|_| ())
}

#[cfg(feature = "test-support")]
pub(crate) fn persist_receipt_for_test(
    root: &File,
    nonce: &str,
    bytes: &[u8],
) -> Result<(), String> {
    persist_receipt(root, &format!("receipt-{nonce}.json"), bytes)
}

#[cfg(feature = "test-support")]
pub(crate) fn publish_storage_for_test(
    root: &File,
    nonce: &str,
    receipt_bytes: &[u8],
    active_bytes: &[u8],
) -> Result<(), String> {
    publish_receipt_then_active(root, nonce, receipt_bytes, active_bytes).map(|_| ())
}
