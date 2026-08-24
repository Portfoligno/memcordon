use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const STARTUP_FAILURE_PATH: &str = "/run/memcordon/sealed-startup-failure.json";
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_DETAIL_BYTES: usize = 8 * 1024;
const MAX_CODE_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartupPhase {
    Qualification,
    SocketActivation,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StartupFailureV1 {
    pub schema_version: u32,
    pub phase: StartupPhase,
    pub code: String,
    pub detail: String,
    pub provider_pid: u32,
}

pub fn record(phase: StartupPhase, error: &str) -> Result<(), String> {
    record_at(Path::new(STARTUP_FAILURE_PATH), phase, error)
}

pub fn read() -> Result<Option<StartupFailureV1>, String> {
    read_at(Path::new(STARTUP_FAILURE_PATH), true)
}

pub fn clear() -> Result<(), String> {
    clear_at(Path::new(STARTUP_FAILURE_PATH))
}

#[cfg(feature = "test-support")]
pub fn record_for_test(path: &Path, phase: StartupPhase, error: &str) -> Result<(), String> {
    record_at(path, phase, error)
}

#[cfg(feature = "test-support")]
pub fn read_for_test(path: &Path) -> Result<Option<StartupFailureV1>, String> {
    read_at(path, false)
}

#[cfg(feature = "test-support")]
pub fn clear_for_test(path: &Path) -> Result<(), String> {
    clear_at(path)
}

fn record_at(path: &Path, phase: StartupPhase, error: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "MCSEALED-STARTUP-EVIDENCE: path has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    let code = error
        .split_once(':')
        .map_or(error, |(candidate, _)| candidate);
    if code.is_empty()
        || code.len() > MAX_CODE_BYTES
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("MCSEALED-STARTUP-EVIDENCE: invalid stable error code".to_owned());
    }
    let detail = bounded_detail(error);
    let record = StartupFailureV1 {
        schema_version: 1,
        phase,
        code: code.to_owned(),
        detail,
        provider_pid: std::process::id(),
    };
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("MCSEALED-STARTUP-EVIDENCE: record exceeds size bound".to_owned());
    }
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    let persist = file
        .write_all(&bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temporary, path))
        .and_then(|()| File::open(parent)?.sync_all());
    if let Err(error) = persist {
        drop(file);
        let _ = fs::remove_file(&temporary);
        return Err(format!("MCSEALED-STARTUP-EVIDENCE: {error}"));
    }
    Ok(())
}

fn read_at(path: &Path, require_root: bool) -> Result<Option<StartupFailureV1>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("MCSEALED-STARTUP-EVIDENCE: {error}")),
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    if !metadata.file_type().is_file()
        || (require_root && metadata.uid() != 0)
        || metadata.mode() & 0o077 != 0
    {
        return Err("MCSEALED-STARTUP-EVIDENCE: unsafe record identity or mode".to_owned());
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err("MCSEALED-STARTUP-EVIDENCE: record exceeds size bound".to_owned());
    }
    let record: StartupFailureV1 = serde_json::from_slice(&bytes)
        .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))?;
    validate(&record)?;
    Ok(Some(record))
}

fn clear_at(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => {
            let parent = path
                .parent()
                .ok_or_else(|| "MCSEALED-STARTUP-EVIDENCE: path has no parent".to_owned())?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| format!("MCSEALED-STARTUP-EVIDENCE: {error}"))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("MCSEALED-STARTUP-EVIDENCE: {error}")),
    }
}

fn validate(record: &StartupFailureV1) -> Result<(), String> {
    if record.schema_version != 1
        || record.code.is_empty()
        || record.code.len() > MAX_CODE_BYTES
        || !record
            .code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
        || record.detail.len() > MAX_DETAIL_BYTES
        || record.provider_pid == 0
    {
        return Err("MCSEALED-STARTUP-EVIDENCE: invalid typed record".to_owned());
    }
    Ok(())
}

fn bounded_detail(error: &str) -> String {
    const SUFFIX: &str = "...[truncated]";
    if error.len() <= MAX_DETAIL_BYTES {
        return error.to_owned();
    }
    let mut boundary = MAX_DETAIL_BYTES - SUFFIX.len();
    while !error.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}{SUFFIX}", &error[..boundary])
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{}.new", std::process::id()));
    PathBuf::from(name)
}
