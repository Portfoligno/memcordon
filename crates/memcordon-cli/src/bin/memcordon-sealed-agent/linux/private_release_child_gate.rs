//! A protected synchronization barrier for independent live-descendant OS
//! observation. The CI acknowledgment is never native completion or Q proof.

use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_release_child_owner::LiveDescendantWitnessV1;

const GATE_LEAF: &str = "live-gate.json";
const GATE_TEMP: &str = "live-gate.pending";
const ACK_LEAF: &str = "live-ack.json";
const MAX_BYTES: usize = 8192;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    live: LiveDescendantWitnessV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LiveAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    live_gate_sha256: DiagnosticSha256,
}

pub(crate) fn persist_gate(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    live: &LiveDescendantWitnessV1,
) -> Result<DiagnosticSha256, String> {
    if unsafe { libc::geteuid() } != 0
        || live.schema_version != 1
        || live.challenge_sha256 != hash_bytes(challenge)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate authority differs".into());
    }
    protected_directory(directory)?;
    let bytes = serde_json::to_vec(&LiveGateV1 {
        schema_version: 1,
        selector: super::private_release_children::SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        live: live.clone(),
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, GATE_TEMP, GATE_LEAF, &bytes)?;
    if read_leaf(directory, GATE_LEAF, false)?.as_deref() != Some(bytes.as_slice()) {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate readback differs".into());
    }
    Ok(hash_bytes(&bytes))
}

pub(crate) fn wait_for_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
    deadline: Instant,
) -> Result<(), String> {
    protected_directory(directory)?;
    loop {
        if let Some(bytes) = read_leaf(directory, ACK_LEAF, true)? {
            return verify_ack_bytes(&bytes, result_key, challenge, gate_sha256);
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: child CI live acknowledgment timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn readback_gate_and_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    live: &LiveDescendantWitnessV1,
) -> Result<DiagnosticSha256, String> {
    protected_directory(directory)?;
    let bytes = read_leaf(directory, GATE_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: child live gate absent")?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let gate: LiveGateV1 = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if gate.schema_version != 1
        || gate.selector != super::private_release_children::SELECTOR
        || &gate.result_key != result_key
        || gate.challenge_sha256 != hash_bytes(challenge)
        || &gate.live != live
        || serde_json::to_vec(&gate).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child live gate differs".into());
    }
    let digest = hash_bytes(&bytes);
    let ack = read_leaf(directory, ACK_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: child live acknowledgment absent")?;
    verify_ack_bytes(&ack, result_key, challenge, &digest)?;
    Ok(digest)
}

fn verify_ack_bytes(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let ack: LiveAckV1 = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if ack.schema_version != 1
        || ack.selector != super::private_release_children::SELECTOR
        || &ack.result_key != result_key
        || ack.challenge_sha256 != hash_bytes(challenge)
        || &ack.live_gate_sha256 != gate_sha256
        || serde_json::to_vec(&ack).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child live acknowledgment differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn ack_bytes_for_test(
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Vec<u8> {
    serde_json::to_vec(&LiveAckV1 {
        schema_version: 1,
        selector: super::private_release_children::SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        live_gate_sha256: gate_sha256.clone(),
    })
    .expect("fixed child ack serialization")
}

#[cfg(feature = "test-support")]
pub(crate) fn verify_ack_for_test(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    verify_ack_bytes(bytes, result_key, challenge, gate_sha256)
}

pub(crate) fn protected_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate directory differs".into());
    }
    Ok(())
}

pub(crate) fn read_leaf(
    directory: &File,
    leaf: &str,
    ack_staging_allowed: bool,
) -> Result<Option<Vec<u8>>, String> {
    let name = CString::new(leaf).expect("fixed child gate leaf");
    // SAFETY: one fixed leaf is resolved below a retained protected directory.
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
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child gate open: {error}"
        ));
    }
    // SAFETY: successful openat transferred one unique descriptor.
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() == 0
        || metadata.len() > MAX_BYTES as u64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate leaf protection differs".into());
    }
    // CI's safe hard-link/no-replace publication briefly has two links while
    // it unlinks its fsynced fixed pending leaf. Do not release on that state.
    if ack_staging_allowed && metadata.nlink() == 2 {
        return Ok(None);
    }
    if metadata.nlink() != 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate link count differs".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES || bytes.len() as u64 != metadata.len() {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate leaf byte bound differs".into());
    }
    Ok(Some(bytes))
}

pub(crate) fn persist_atomic(
    directory: &File,
    temp: &str,
    leaf: &str,
    bytes: &[u8],
) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: child gate byte bound differs".into());
    }
    let temporary = CString::new(temp).expect("fixed child gate temp");
    let canonical = CString::new(leaf).expect("fixed child gate canonical");
    // SAFETY: O_EXCL creates a new protected fixed temporary leaf only.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child gate create: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful openat transferred one unique descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    // SAFETY: RENAME_NOREPLACE cannot overwrite a prior canonical witness.
    let renamed = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory.as_raw_fd(),
            temporary.as_ptr(),
            directory.as_raw_fd(),
            canonical.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if renamed == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child gate publish: {}",
            std::io::Error::last_os_error()
        ));
    }
    directory.sync_all().map_err(|error| error.to_string())?;
    Ok(())
}
