//! Caller-owned current prepared observations. These paths never cross the
//! provider boundary and cannot authorize another native attempt.
use memcordon_core::{WindowsProviderRequestV4, WindowsWorkloadPreparedV1};
use std::{cell::RefCell, fs::File, marker::PhantomData, path::PathBuf, rc::Rc};

struct Observer {
    path: PathBuf,
    _directory: File,
}

thread_local! {
    static ACTIVE: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

pub struct WindowsPreparedObservationScope {
    _thread: PhantomData<Rc<()>>,
}

fn open_observation_file(path: &std::path::Path) -> std::io::Result<File> {
    use std::os::windows::{fs::MetadataExt, fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "current observation is not a regular non-reparse file",
        ));
    }
    Ok(file)
}

impl WindowsPreparedObservationScope {
    pub fn begin(path: &std::path::Path) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        let path = std::path::absolute(path).map_err(|error| error.to_string())?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|error| error.to_string())?;
        use std::os::windows::fs::MetadataExt;
        let metadata = directory.metadata().map_err(|error| error.to_string())?;
        if !metadata.is_dir() || metadata.file_attributes() & 0x400 != 0 {
            return Err("prepared observation requires an existing non-reparse directory".into());
        }
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() {
                return Err("prepared observation scope already active".into());
            }
            *active = Some(Observer {
                path,
                _directory: directory,
            });
            Ok(Self {
                _thread: PhantomData,
            })
        })
    }
}

impl Drop for WindowsPreparedObservationScope {
    fn drop(&mut self) {
        ACTIVE.with(|active| {
            active.borrow_mut().take();
        });
    }
}

pub(super) fn current_process_identity() -> Result<memcordon_core::WindowsProcessIdentityV1, String>
{
    use windows_sys::Win32::{
        Foundation::FILETIME,
        System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes},
    };
    let (mut birth, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: the current-process pseudo handle and distinct native outputs remain live.
    if unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &mut birth,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(memcordon_core::WindowsProcessIdentityV1 {
        process_id: unsafe { GetCurrentProcessId() },
        creation_time_100ns: u64::from(birth.dwLowDateTime)
            | (u64::from(birth.dwHighDateTime) << 32),
    })
}

pub(super) fn publish_accepted(
    accepted: &memcordon_core::WindowsWorkloadAcceptedV1,
    request_bytes: &[u8],
) -> Result<bool, String> {
    accepted.validate().map_err(str::to_owned)?;
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(true);
        };
        if request_bytes.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES
            || String::from(memcordon_core::hash_bytes(request_bytes)) != accepted.request_sha256
        {
            return Err("accepted original native request differs".into());
        }
        let native_path = observer
            .path
            .join(format!("{}.request.json", accepted.attempt_id));
        if native_path
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            return Err("accepted native request destination already exists".into());
        }
        memcordon_core::write_report_bytes_atomic(&native_path, request_bytes)
            .map_err(|error| error.to_string())?;
        let path = observer
            .path
            .join(format!("{}.accepted.json", accepted.attempt_id));
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err("accepted observation already exists".into());
        }
        memcordon_core::write_report_bytes_atomic(
            &path,
            &serde_json::to_vec(accepted).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(false)
    })
}

pub(super) fn preparation_acknowledged(
    accepted: &memcordon_core::WindowsWorkloadAcceptedV1,
) -> Result<bool, String> {
    use std::io::Read;
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(true);
        };
        let path = observer
            .path
            .join(format!("{}.accepted-ack.json", accepted.attempt_id));
        let file = match open_observation_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("preparation acknowledgement exceeds bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        match serde_json::from_slice::<WindowsProviderRequestV4>(&bytes)
            .map_err(|error| error.to_string())?
        {
            WindowsProviderRequestV4::PreparationAcknowledged {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
                accepted_sha256,
            } if schema_version == memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
                && attempt_id == accepted.attempt_id
                && nonce == accepted.nonce
                && request_sha256 == accepted.request_sha256
                && accepted_sha256 == accepted.canonical_sha256()? =>
            {
                Ok(true)
            }
            _ => Err("preparation acknowledgement differs from original accepted request".into()),
        }
    })
}

pub(super) fn accepted_cancel_signal(
    accepted: &memcordon_core::WindowsWorkloadAcceptedV1,
) -> Result<Option<i32>, String> {
    cancel_signal_bound(
        &accepted.attempt_id,
        &accepted.nonce,
        &accepted.request_sha256,
    )
}

pub(super) fn publish_cancel_sent(
    prepared: &WindowsWorkloadPreparedV1,
    signal: i32,
) -> Result<(), String> {
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(());
        };
        let path = observer
            .path
            .join(format!("{}.cancel-sent.json", prepared.attempt_id));
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err("caller cancellation write observation exists".into());
        }
        let message = WindowsProviderRequestV4::Cancel {
            schema_version: memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
            attempt_id: prepared.attempt_id.clone(),
            nonce: prepared.nonce.clone(),
            request_sha256: prepared.request_sha256.clone(),
            signal,
        };
        let bytes = serde_json::to_vec(&message).map_err(|error| error.to_string())?;
        memcordon_core::write_report_bytes_atomic(&path, &bytes).map_err(|error| error.to_string())
    })
}

pub(super) fn publish_cancellation(
    cancellation: &memcordon_core::WindowsPreallocationCancellationV1,
    raw: &[u8],
) -> Result<(), String> {
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(());
        };
        let path = observer.path.join(format!(
            "{}.cancelled.json",
            cancellation.accepted.attempt_id
        ));
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err("preallocation cancellation observation exists".into());
        }
        memcordon_core::write_report_bytes_atomic(&path, raw).map_err(|error| error.to_string())
    })
}

pub(super) fn publish(
    prepared: &WindowsWorkloadPreparedV1,
    request_bytes: &[u8],
) -> Result<bool, String> {
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(true);
        };
        prepared.validate().map_err(str::to_owned)?;
        if request_bytes.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES
            || String::from(memcordon_core::hash_bytes(request_bytes)) != prepared.request_sha256
        {
            return Err("prepared native request bytes differ from original request".into());
        }
        let request_path = observer
            .path
            .join(format!("{}.request.json", prepared.attempt_id));
        if request_path
            .try_exists()
            .map_err(|error| error.to_string())?
        {
            use std::io::Read;
            let mut observed = Vec::new();
            open_observation_file(&request_path)
                .map_err(|error| error.to_string())?
                .take(memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64 + 1)
                .read_to_end(&mut observed)
                .map_err(|error| error.to_string())?;
            if observed != request_bytes {
                return Err("prepared request changed after accepted observation".into());
            }
        } else {
            memcordon_core::write_report_bytes_atomic(&request_path, request_bytes)
                .map_err(|error| error.to_string())?;
        }
        let path = observer
            .path
            .join(format!("{}.prepared.json", prepared.attempt_id));
        let bytes = serde_json::to_vec(prepared).map_err(|error| error.to_string())?;
        if path.try_exists().map_err(|error| error.to_string())? {
            return Err("prepared observation destination already exists".into());
        }
        memcordon_core::write_report_bytes_atomic(&path, &bytes)
            .map_err(|error| error.to_string())?;
        if std::fs::read(&path).map_err(|error| error.to_string())? != bytes {
            return Err("prepared observation named readback differs".into());
        }
        Ok(false)
    })
}

pub(super) fn acknowledged(prepared: &WindowsWorkloadPreparedV1) -> Result<bool, String> {
    use std::io::Read;
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(true);
        };
        let path = observer
            .path
            .join(format!("{}.prepared-ack.json", prepared.attempt_id));
        let file = match open_observation_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("prepared acknowledgment exceeds bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let acknowledgment: WindowsProviderRequestV4 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        match acknowledgment {
            WindowsProviderRequestV4::PreparedAcknowledged {
                schema_version,
                attempt_id,
                nonce,
                request_sha256,
                prepared_sha256,
            } if schema_version == memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
                && attempt_id == prepared.attempt_id
                && nonce == prepared.nonce
                && request_sha256 == prepared.request_sha256
                && prepared_sha256 == prepared.canonical_sha256()? =>
            {
                Ok(true)
            }
            _ => Err("caller acknowledgment differs from original prepared observation".into()),
        }
    })
}

pub(super) fn cancel_signal(prepared: &WindowsWorkloadPreparedV1) -> Result<Option<i32>, String> {
    cancel_signal_bound(
        &prepared.attempt_id,
        &prepared.nonce,
        &prepared.request_sha256,
    )
}

fn cancel_signal_bound(attempt: &str, nonce: &str, request: &str) -> Result<Option<i32>, String> {
    use std::io::Read;
    ACTIVE.with(|active| {
        let active = active.borrow();
        let Some(observer) = active.as_ref() else {
            return Ok(None);
        };
        let path = observer.path.join(format!("{attempt}.cancel.json"));
        let file = match open_observation_file(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let mut bytes = Vec::new();
        file.take(64 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() > 64 * 1024 {
            return Err("prepared cancellation exceeds bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)?;
        let cancellation: WindowsProviderRequestV4 =
            serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        match cancellation {
            WindowsProviderRequestV4::Cancel {
                schema_version,
                attempt_id,
                nonce: actual_nonce,
                request_sha256,
                signal,
            } if schema_version == memcordon_core::WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION
                && attempt_id == attempt
                && actual_nonce == nonce
                && request_sha256 == request =>
            {
                Ok(Some(signal))
            }
            _ => Err("caller cancellation differs from original prepared observation".into()),
        }
    })
}
