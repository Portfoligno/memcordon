use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};

pub(super) const FILE_NAME: &str = "control-startup-failure.json";
const DETAIL_BYTES: usize = 4096;
const RECORD_BYTES: usize = DETAIL_BYTES * 6 + 1024;

use memcordon_core::{
    WindowsLauncherStartupReasonV1 as Reason, WindowsLauncherStartupStageV1 as Stage,
};

const LAUNCHER_FILE_NAME: &str = "launcher-startup-failure.json";
static LAUNCHER_PROGRESS: std::sync::LazyLock<std::sync::Mutex<(Stage, Option<(Stage, Reason)>)>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new((Stage::ProcessProtection, None)));

pub(super) fn launcher_stage(stage: Stage) {
    let mut progress = LAUNCHER_PROGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    progress.0 = stage;
    if stage == Stage::ServiceLoop {
        progress.1 = None;
    }
}

pub(super) fn launcher_blocker(reason: Reason) {
    let mut progress = LAUNCHER_PROGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if progress.1.is_none() {
        progress.1 = Some((progress.0, reason));
    }
}

fn launcher_path() -> Result<std::path::PathBuf, String> {
    Ok(path()?.with_file_name(LAUNCHER_FILE_NAME))
}

pub(super) fn clear_launcher() -> Result<(), String> {
    *LAUNCHER_PROGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = (Stage::ProcessProtection, None);
    let destination = launcher_path()?;
    match std::fs::remove_file(destination.with_extension("json.new")) {
        Ok(()) => (),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.to_string()),
    }
    match std::fs::remove_file(destination) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

pub(super) fn record_launcher(service_exit: u32) -> Result<(), String> {
    let progress = LAUNCHER_PROGRESS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (stage, reason) = progress.1.unwrap_or((progress.0, Reason::OperationFailed));
    let failure = memcordon_core::WindowsLauncherStartupDiagnosticV1 {
        schema_version: 1,
        provider: super::package::installed_public_provider_binding()?,
        startup_process: super::process::process_identity(unsafe {
            windows_sys::Win32::System::Threading::GetCurrentProcess()
        })?,
        boot_identity: super::record::boot_identity()?,
        recorded_tick_millis: unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        },
        service_exit,
        stage,
        reason,
        native_code: None,
    };
    drop(progress);
    let bytes = failure.to_bounded_json().map_err(str::to_owned)?;
    let destination = launcher_path()?;
    let staged = destination.with_extension("json.new");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&staged)
        .map_err(|error| error.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| error.to_string())?;
    drop(file);
    super::record::replace_atomically(&staged, &destination)
}

pub(super) fn read_launcher(
    service_exit: u32,
    expected_process: Option<&memcordon_core::WindowsProcessIdentityV1>,
    minimum_tick: u64,
) -> Result<Option<String>, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_STANDARD_INFO, FileStandardInfo, GetFileInformationByHandleEx,
    };
    let file = match OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(launcher_path()?)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err("launcher startup diagnostic is not a regular file".into());
    }
    let mut standard = FILE_STANDARD_INFO::default();
    // Inspect the held file object rather than resolving its pathname again.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as _,
            FileStandardInfo,
            (&raw mut standard).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if standard.NumberOfLinks != 1 {
        return Err("launcher startup diagnostic has multiple links".into());
    }
    let mut bytes = Vec::new();
    file.take(memcordon_core::WINDOWS_LAUNCHER_STARTUP_DIAGNOSTIC_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let failure = memcordon_core::WindowsLauncherStartupDiagnosticV1::from_json_for(
        &bytes,
        &super::package::installed_public_provider_binding()?,
        &super::record::boot_identity()?,
        unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() },
        service_exit,
        expected_process,
    )
    .map_err(str::to_owned)?;
    failure
        .validate_since(minimum_tick)
        .map_err(str::to_owned)?;
    serde_json::to_string(&failure)
        .map(Some)
        .map_err(|error| error.to_string())
}

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
