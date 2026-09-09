use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};

pub(super) const FILE_NAME: &str = "control-startup-failure.json";
const DETAIL_BYTES: usize = 4096;
const RECORD_BYTES: usize = DETAIL_BYTES * 6 + 1024;

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    process_id: u32,
    service_exit: u32,
    unix_millis: u128,
    detail: String,
    truncated: bool,
}

fn path() -> Result<std::path::PathBuf, String> {
    let root = super::policy_registry::root();
    super::package::reject_reparse_components(&root)?;
    super::security::SecurityDescriptor::from_sddl(&super::security::state_bootstrap_sddl()?)?
        .verify_path(&root)?;
    Ok(root.join(FILE_NAME))
}

pub(super) fn clear() -> Result<(), String> {
    match std::fs::remove_file(path()?) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn encode_failure(service_exit: u32, detail: &str, unix_millis: u128) -> Result<Vec<u8>, String> {
    let boundary = detail
        .char_indices()
        .map(|(index, character)| index + character.len_utf8())
        .take_while(|end| *end <= DETAIL_BYTES)
        .last()
        .unwrap_or(0);
    let failure = Failure {
        process_id: std::process::id(),
        service_exit,
        unix_millis,
        detail: detail[..boundary].to_owned(),
        truncated: boundary != detail.len(),
    };
    let mut bytes = serde_json::to_vec(&failure).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    if bytes.len() > RECORD_BYTES {
        return Err("startup diagnostic exceeds bounded record size".into());
    }
    Ok(bytes)
}

pub(super) fn record(service_exit: u32, detail: &str) -> Result<(), String> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    let bytes = encode_failure(service_exit, detail, now)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path()?)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("startup diagnostic is not a regular file".into());
    }
    file.set_len(0)
        .and_then(|()| file.write_all(&bytes))
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())
}

pub(super) fn read(service_exit: u32, elapsed_millis: u128) -> Result<Option<String>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path()?)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("startup diagnostic is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_millis();
    decode_failure(&bytes, service_exit, elapsed_millis, now).map(Some)
}

fn decode_failure(
    bytes: &[u8],
    service_exit: u32,
    elapsed_millis: u128,
    now: u128,
) -> Result<String, String> {
    if bytes.len() > RECORD_BYTES {
        return Err("startup diagnostic exceeds bounded record size".into());
    }
    let failure: Failure = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if failure.service_exit != service_exit
        || failure.process_id == 0
        || failure.detail.len() > DETAIL_BYTES
        || failure.unix_millis > now
        || now - failure.unix_millis > elapsed_millis.saturating_add(1000)
    {
        return Err("startup diagnostic identity or freshness differs".into());
    }
    serde_json::to_string(&failure).map_err(|error| error.to_string())
}

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_startup_diagnostics.rs"]
mod tests;
