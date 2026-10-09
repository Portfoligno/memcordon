//! Optional owned evidence directory for a native observer's pre-release barrier.
use memcordon_core::mixed_observation::MixedPreparedObservationV2;
use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

thread_local! {static OBSERVER:RefCell<Option<Rc<File>>>=const{RefCell::new(None)};}
pub struct MixedObservationScope {
    previous: Option<Rc<File>>,
}
impl MixedObservationScope {
    /// Preserve the local filesystem error independently of the provider's
    /// authenticated terminal. The submitted bytes cannot attest persistence.
    pub fn record_report_delivery_failure(
        path: &Path,
        submitted: &[u8],
        error: &memcordon_core::Error,
    ) -> Result<(), String> {
        let scope = OBSERVER.with(|scope| scope.borrow().clone());
        let Some(directory) = scope else {
            return Ok(());
        };
        if submitted.len() > 16 * 1024 * 1024 {
            return Err("native report delivery observation exceeds bound".into());
        }
        let destination = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|error| error.to_string())?;
        let metadata = destination.metadata().map_err(|error| error.to_string())?;
        let receipt = serde_json::json!({"format":"memcordon.linux-native-report-delivery-failure","revision":1,
            "report_path":path.as_os_str().as_encoded_bytes(),"submitted_report":submitted,"native_errno":error.os_code,
            "native_error_code":error.code,"destination":{"device":metadata.dev(),"inode":metadata.ino(),"uid":metadata.uid(),
                "gid":metadata.gid(),"mode":metadata.mode(),"is_directory":metadata.is_dir()},
            "frontend_pid":std::process::id()});
        let bytes = serde_json::to_vec(&receipt).map_err(|error| error.to_string())?;
        let mut file = member(&directory, "report-delivery-failure.json", true)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .and_then(|()| directory.sync_all())
            .map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn install(directory: &Path) -> Result<Self, String> {
        if !directory.is_absolute() {
            return Err("mixed observation directory must be absolute".into());
        }
        let held = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
            .open(directory)
            .map_err(|error| error.to_string())?;
        let metadata = held.metadata().map_err(|error| error.to_string())?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            return Err("mixed observation directory is not exclusively owned".into());
        }
        let previous = OBSERVER.with(|scope| scope.replace(Some(Rc::new(held))));
        Ok(Self { previous })
    }
}
impl Drop for MixedObservationScope {
    fn drop(&mut self) {
        OBSERVER.with(|scope| scope.replace(self.previous.take()));
    }
}

fn member(root: &File, name: &str, write: bool) -> Result<File, std::io::Error> {
    let name = std::ffi::CString::new(name).expect("fixed validated attempt filename");
    let flags = libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if write {
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL
        } else {
            libc::O_RDONLY
        };
    let fd = unsafe { libc::openat(root.as_raw_fd(), name.as_ptr(), flags, 0o600) };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

/// Persist exactly the bytes sent to the authenticated provider, before send.
/// This receipt records an invocation; it grants no admission authority.
pub(super) fn record_request(attempt: [u8; 16], bytes: &[u8]) -> Result<(), String> {
    record_member(attempt, "provider-request.bin", bytes)
}

/// Retain the authenticated provider's original terminal bytes before local
/// report delivery. This observation does not certify report persistence.
pub(super) fn record_terminal(attempt: [u8; 16], bytes: &[u8]) -> Result<(), String> {
    record_member(attempt, "provider-terminal.json", bytes)
}
pub(super) fn record_legacy_frame(
    attempt: [u8; 16],
    terminal: bool,
    bytes: &[u8],
) -> Result<(), String> {
    record_member(
        attempt,
        if terminal {
            "legacy-provider-terminal.bin"
        } else {
            "legacy-provider-request.bin"
        },
        bytes,
    )
}

fn record_member(attempt: [u8; 16], suffix: &str, bytes: &[u8]) -> Result<(), String> {
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    let identity = attempt
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let mut file = member(&directory, &format!("{identity}.{suffix}"), true)
        .map_err(|error| error.to_string())?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|error| error.to_string())?;
    let mut readback = member(&directory, &format!("{identity}.{suffix}"), false)
        .map_err(|error| error.to_string())?;
    let metadata = readback.metadata().map_err(|error| error.to_string())?;
    if metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != bytes.len() as u64
    {
        return Err("mixed provider request receipt custody differs".into());
    }
    let mut persisted = Vec::new();
    readback
        .read_to_end(&mut persisted)
        .map_err(|error| error.to_string())?;
    if persisted != bytes {
        return Err("mixed provider request receipt readback differs".into());
    }
    Ok(())
}

pub(super) fn observe(
    bytes: &[u8],
    value: &MixedPreparedObservationV2,
    deadline: Instant,
) -> Result<(), String> {
    observe_phase(
        bytes,
        value,
        deadline,
        "prepared.json",
        "observer-ack.json",
        "memcordon.mixed-observer-acknowledgment",
    )
}

/// Opt-in final-policy-check observation under the same exclusively held scope.
pub(super) fn observe_release(
    bytes: &[u8],
    value: &memcordon_core::mixed_observation::MixedReleaseObservationV2,
    deadline: Instant,
) -> Result<(), String> {
    value.validate()?;
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    let mut configuration = match member(&directory, "release-observer.json", false) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    let metadata = configuration
        .metadata()
        .map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > 1024
    {
        return Err("mixed release observer configuration custody differs".into());
    }
    let mut selected = Vec::new();
    Read::by_ref(&mut configuration)
        .take(1025)
        .read_to_end(&mut selected)
        .map_err(|error| error.to_string())?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&selected)?;
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Configuration {
        format: String,
        revision: u32,
    }
    let configuration: Configuration =
        serde_json::from_slice(&selected).map_err(|error| error.to_string())?;
    if configuration.format != "memcordon.mixed-release-observer" || configuration.revision != 2 {
        return Err("mixed release observer configuration format differs".into());
    }
    observe_phase(
        bytes,
        &value.prepared,
        deadline,
        "release-prepared.json",
        "release-observer-ack.json",
        "memcordon.mixed-release-observer-acknowledgment",
    )
}

fn observe_phase(
    bytes: &[u8],
    value: &MixedPreparedObservationV2,
    deadline: Instant,
    observation_name: &str,
    acknowledgment_name: &str,
    acknowledgment_format: &str,
) -> Result<(), String> {
    let scope = OBSERVER.with(|scope| scope.borrow().clone());
    let Some(directory) = scope else {
        return Ok(());
    };
    value.validate()?;
    let attempt = value.admission.attempt_id.as_str();
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("mixed observation attempt filename differs".into());
    }
    let mut output = member(&directory, &format!("{attempt}.{observation_name}"), true)
        .map_err(|error| error.to_string())?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .and_then(|()| directory.sync_all())
        .map_err(|error| error.to_string())?;
    loop {
        if Instant::now() >= deadline {
            return Err("mixed native observer barrier deadline expired".into());
        }
        match member(
            &directory,
            &format!("{attempt}.{acknowledgment_name}"),
            false,
        ) {
            Ok(mut file) => {
                let metadata = file.metadata().map_err(|error| error.to_string())?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.nlink() != 1
                    || metadata.mode() & 0o7777 != 0o600
                    || metadata.len() > 8192
                {
                    return Err("mixed observer acknowledgement custody differs".into());
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut file)
                    .take(8193)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
                let ack: memcordon_core::mixed_observation::MixedObserverAcknowledgmentV2 =
                    serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
                if ack.format != acknowledgment_format
                    || ack.revision != 2
                    || ack.attempt_id != value.admission.attempt_id
                    || ack.admission_nonce != value.admission.admission_nonce
                    || ack.target != value.target
                    || ack.observer.pid == 0
                    || ack.observer.birth == 0
                {
                    return Err("mixed observer acknowledgement association differs".into());
                }
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::thread::sleep(Duration::from_millis(10))
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}
