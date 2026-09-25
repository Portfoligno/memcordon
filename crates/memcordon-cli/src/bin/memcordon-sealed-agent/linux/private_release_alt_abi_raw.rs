//! Protected, nonpublishable raw custody for the x86 alternate-ABI half.
//! This does not construct a release-case completion or satisfy the ARM64 half.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_alt_abi::{SELECTOR, X32AlternateAbiSubwitnessV1};
use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

const RAW_LEAF: &str = "x32-alternate.raw.json";
const TEMP_LEAF: &str = "x32-alternate.raw.json.new";
const MAX_RAW_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedX32RawV1 {
    schema: u32,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    installed_inspection_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
    worker: ProcessIdentityV4,
    witness: X32AlternateAbiSubwitnessV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DetachedX32RawReadbackV1 {
    pub(crate) raw_sha256: DiagnosticSha256,
    pub(crate) worker: ProcessIdentityV4,
    pub(crate) witness: X32AlternateAbiSubwitnessV1,
}

/// The retained M0 authority owns this fixed directory. A crash can leave a
/// `.new` file, which detached readback treats as incomplete, never success.
#[allow(dead_code)] // No composite 25th-case dispatcher exists.
pub(crate) fn persist_closed_x32_raw(
    case: &ReleaseCandidateRunAuthorityV1,
    worker: &ProcessIdentityV4,
    witness: &X32AlternateAbiSubwitnessV1,
) -> Result<DiagnosticSha256, String> {
    if case.selector() != SELECTOR || worker.pid == 0 || worker.start_time == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 raw authority differs".into());
    }
    case.revalidate()?;
    witness.verify_binding(&case.challenge_bytes(), case.filter_digest())?;
    let record = ProtectedX32RawV1 {
        schema: 1,
        selector: SELECTOR.into(),
        result_key: case.protected_result_key()?.clone(),
        challenge_sha256: hash_bytes(&case.challenge_bytes()),
        installed_inspection_sha256: hash_bytes(&case.installed_inspection_bytes()?),
        filter_sha256: case.filter_digest().clone(),
        worker: worker.clone(),
        witness: witness.clone(),
    };
    let bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_RAW_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 raw exceeds bound".into());
    }
    let directory = case.protected_case_directory()?;
    write_immutable(directory, &bytes)?;
    case.revalidate()?;
    Ok(hash_bytes(&bytes))
}

/// Detached caller must provide independently captured worker/coordinator
/// identities, current installed inspection and reviewed filter digest. A
/// self-asserted JSON file cannot supply any of those expected values.
#[allow(dead_code)] // No composite 25th-case dispatcher exists.
pub(crate) fn readback_closed_x32_raw(
    directory: &File,
    request: &ReleaseCaseRequestV1,
    expected_filter: &DiagnosticSha256,
    expected_installed_inspection: &DiagnosticSha256,
    expected_worker: &ProcessIdentityV4,
    expected_coordinator: &ProcessIdentityV4,
) -> Result<DetachedX32RawReadbackV1, String> {
    if !cfg!(target_arch = "x86_64")
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != SELECTOR
    {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 detached selector differs".into());
    }
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 detached directory differs".into());
    }
    let bytes = read_immutable(directory)?;
    let record: ProtectedX32RawV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&record).map_err(|error| error.to_string())? != bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 raw is not canonical".into());
    }
    record
        .witness
        .verify_binding(&request.challenge, expected_filter)?;
    if record.schema != 1
        || record.selector != SELECTOR
        || record.result_key != request.result_key()
        || record.challenge_sha256 != hash_bytes(&request.challenge)
        || record.installed_inspection_sha256 != *expected_installed_inspection
        || record.filter_sha256 != *expected_filter
        || record.worker != *expected_worker
        || expected_worker == expected_coordinator
        || expected_worker == &record.witness.native
        || expected_worker == &record.witness.alternate
        || expected_coordinator == &record.witness.native
        || expected_coordinator == &record.witness.alternate
    {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 detached raw binding differs".into());
    }
    super::private_release_run::require_recorded_process_exited(expected_worker)?;
    super::private_release_run::require_recorded_process_exited(expected_coordinator)?;
    Ok(DetachedX32RawReadbackV1 {
        raw_sha256: hash_bytes(&bytes),
        worker: record.worker,
        witness: record.witness,
    })
}

fn fixed_name(name: &'static str) -> CString {
    CString::new(name).expect("fixed x32 raw leaf has no NUL")
}

fn write_immutable(directory: &File, bytes: &[u8]) -> Result<(), String> {
    let temporary = fixed_name(TEMP_LEAF);
    let final_name = fixed_name(RAW_LEAF);
    // SAFETY: fixed leaf, pinned directory and O_EXCL create exactly one
    // root-owned temporary file without following a link.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: x32 raw create: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: x32 raw write: {error}"))?;
    // SAFETY: RENAME_NOREPLACE atomically seals one fixed leaf. The temporary
    // remains after a failure, causing subsequent detached readback to fail.
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            temporary.as_ptr(),
            directory.as_raw_fd(),
            final_name.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: x32 raw rename: {}",
            std::io::Error::last_os_error()
        ));
    }
    directory
        .sync_all()
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: x32 raw fsync: {error}"))
}

fn read_immutable(directory: &File) -> Result<Vec<u8>, String> {
    let temporary = fixed_name(TEMP_LEAF);
    // SAFETY: fstatat with NOFOLLOW only checks the fixed temporary leaf.
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let found = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if found == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 interrupted raw write exists".into());
    }
    let final_name = fixed_name(RAW_LEAF);
    // SAFETY: one fixed leaf under pinned directory; O_NOFOLLOW excludes a
    // symlink substitution even if the directory is unexpectedly writable.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            final_name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: x32 raw open: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat returned one owned descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > MAX_RAW_BYTES as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 raw file identity differs".into());
    }
    let mut bytes = Vec::new();
    file.take((MAX_RAW_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_RAW_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 raw length differs".into());
    }
    Ok(bytes)
}
