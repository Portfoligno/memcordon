//! Explicit frontend-local custody of an already authenticated terminal receipt.
//! This adds no provider authority and does not change existing result formats.
use memcordon_core::{
    PublicProviderBindingV1, WindowsFrontendDeliveryV3, WindowsTerminalReceiptV3,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

pub const MAX_TERMINAL_OBSERVATION_BYTES: usize =
    memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES * 3;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedWindowsTerminalObservation {
    pub format: String,
    pub revision: u32,
    pub provider: PublicProviderBindingV1,
    pub terminal: WindowsTerminalReceiptV3,
    pub frontend_delivery: WindowsFrontendDeliveryV3,
    /// Exact frontend-local serialization hashed by the authenticated protocol.
    pub provider_request: Vec<u8>,
    /// Exact immutable authority serialization acknowledged by this frontend.
    pub terminal_authority_json: String,
}

struct Active {
    observation: Option<AuthenticatedWindowsTerminalObservation>,
    multiple_terminals: bool,
    provider_request: Option<Vec<u8>>,
    request_publication: Option<(std::path::PathBuf, std::fs::File)>,
    accepted_publication: Option<(std::path::PathBuf, std::fs::File)>,
    accepted_published: bool,
    first_probe_failure: Option<String>,
    client_destination: Option<(std::path::PathBuf, std::fs::File)>,
    client_record: Option<super::client_input::Record>,
    client_cutoff: Option<std::time::Instant>,
    client_publication_attempted: bool,
    client_issue_reported: bool,
}

thread_local! {
    static ACTIVE: RefCell<Option<Active>> = const { RefCell::new(None) };
}

/// One explicitly requested observation on the invoking frontend thread. A scope
/// cannot move between threads or silently reuse a preceding run's terminal.
pub struct WindowsTerminalObservationScope {
    active: bool,
    _thread: PhantomData<Rc<()>>,
}

impl WindowsTerminalObservationScope {
    /// Eager accepted custody is part of the requested terminal observation,
    /// with no file-based acknowledgement or additional protocol dependency.
    pub fn begin_with_terminal_path(path: &std::path::Path) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        let path = std::path::absolute(path).map_err(|error| error.to_string())?;
        let scope = Self::begin_with_request_path(&path.with_extension("provider-request.bin"))?;
        let accepted_path = path.with_extension("accepted-observation.json");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ)
            .open(&accepted_path)
            .map_err(|error| error.to_string())?;
        ACTIVE.with(|active| {
            active
                .borrow_mut()
                .as_mut()
                .expect("scope owns accepted destination")
                .accepted_publication = Some((accepted_path, file));
        });
        // This optional diagnostic has its own owned fixed destination. Failure
        // is reported separately and cannot reject or change the launch.
        let client_path = path.with_extension("client-input-observation.json");
        let client_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ)
            .open(&client_path);
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            let active = active.as_mut().expect("scope owns client destination");
            match client_file {
                Ok(file) => active.client_destination = Some((client_path, file)),
                Err(error) => client_issue(active, "create", error.raw_os_error()),
            }
        });
        Ok(scope)
    }
    pub fn begin_with_request_path(path: &std::path::Path) -> Result<Self, String> {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        if !path.is_absolute() {
            return Err("Windows request observation path must be absolute".into());
        }
        let scope = Self::begin()?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .map_err(|error| error.to_string())?;
        ACTIVE.with(|active| {
            active
                .borrow_mut()
                .as_mut()
                .expect("scope owns active request")
                .request_publication = Some((path.to_owned(), file))
        });
        Ok(scope)
    }
    pub fn begin() -> Result<Self, String> {
        ACTIVE.with(|active| {
            let mut active = active.borrow_mut();
            if active.is_some() {
                return Err("a Windows terminal observation scope is already live".into());
            }
            *active = Some(Active {
                observation: None,
                multiple_terminals: false,
                provider_request: None,
                request_publication: None,
                accepted_publication: None,
                accepted_published: false,
                first_probe_failure: None,
                client_destination: None,
                client_record: None,
                client_cutoff: None,
                client_publication_attempted: false,
                client_issue_reported: false,
            });
            Ok(Self {
                active: true,
                _thread: PhantomData,
            })
        })
    }

    pub fn finish(mut self) -> Result<AuthenticatedWindowsTerminalObservation, String> {
        client_finish();
        let captured = ACTIVE.with(|active| active.borrow_mut().take());
        self.active = false;
        let captured =
            captured.ok_or_else(|| "Windows terminal observation ownership was lost".to_owned())?;
        if captured.multiple_terminals {
            return Err("Windows observation requires exactly one authenticated terminal".into());
        }
        captured.observation.ok_or_else(|| {
            unavailable(
                "requested authenticated Windows terminal observation is unavailable",
                captured.first_probe_failure.as_deref(),
            )
        })
    }

    /// A request-only capture preserves a preauthorization refusal without
    /// requiring or manufacturing an authenticated terminal receipt.
    pub fn finish_request(mut self) -> Result<Vec<u8>, String> {
        client_finish();
        let captured = ACTIVE.with(|active| active.borrow_mut().take());
        self.active = false;
        let captured =
            captured.ok_or_else(|| "Windows request observation ownership was lost".to_owned())?;
        if captured.multiple_terminals {
            return Err("Windows request observation requires exactly one request".into());
        }
        let bytes = captured.provider_request.ok_or_else(|| {
            unavailable(
                "requested Windows launch request observation is unavailable",
                captured.first_probe_failure.as_deref(),
            )
        })?;
        let (path, file) = captured
            .request_publication
            .ok_or_else(|| "Windows request observation has no owned destination".to_owned())?;
        use std::{
            io::Read,
            os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        };
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE, GetFileInformationByHandle,
        };
        let named = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .map_err(|error| error.to_string())?;
        let identity = |file: &std::fs::File| -> Result<(u32, u32, u32), String> {
            let mut information = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: both files own live handles and the exact writable API buffer.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if information.dwFileAttributes & 0x400 != 0 || information.nNumberOfLinks != 1 {
                return Err(
                    "Windows request observation is not an ordinary singly named file".into(),
                );
            }
            Ok((
                information.dwVolumeSerialNumber,
                information.nFileIndexHigh,
                information.nFileIndexLow,
            ))
        };
        let mut observed = Vec::new();
        (&named)
            .take(memcordon_core::WINDOWS_MAX_FRAME_BYTES as u64 + 1)
            .read_to_end(&mut observed)
            .map_err(|error| error.to_string())?;
        if identity(&file)? != identity(&named)? || observed != bytes {
            return Err("Windows request observation named custody differs".into());
        }
        Ok(bytes)
    }
}

fn unavailable(message: &str, failure: Option<&str>) -> String {
    match failure {
        Some(failure) => format!("{message}; first local provider probe failure: {failure}"),
        None => message.to_owned(),
    }
}

pub(super) fn retain_accepted(
    accepted: &memcordon_core::WindowsWorkloadAcceptedV1,
    request: &[u8],
    provider: &PublicProviderBindingV1,
    frontend: &memcordon_core::WindowsProcessIdentityV1,
) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle,
    };
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        let Some(active) = active.as_mut() else {
            return Ok(());
        };
        let Some((path, file)) = active.accepted_publication.as_mut() else {
            return Ok(());
        };
        if active.accepted_published {
            return Err("multiple Windows accepted observations".into());
        }
        if active.provider_request.as_deref() != Some(request) {
            return Err("accepted observation original request custody differs".into());
        }
        memcordon_core::validate_windows_accepted_observation(
            accepted, request, provider, frontend,
        )?;
        let bytes = memcordon_core::bounded_json_bytes(
            accepted,
            memcordon_core::MAX_WINDOWS_ACCEPTED_OBSERVATION_BYTES,
            false,
        )
        .map_err(|error| error.to_string())?;
        // Mark before writing: a partial publication can never be retried as a
        // second accepted receipt in this scope.
        active.accepted_published = true;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| error.to_string())?;
        let named = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .map_err(|error| error.to_string())?;
        let identity = |file: &std::fs::File| -> Result<(u32, u32, u32), String> {
            let mut information = BY_HANDLE_FILE_INFORMATION::default();
            // SAFETY: both files own live handles and information is writable.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) } == 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            if information.dwFileAttributes & (0x400 | 0x10 | 0x40) != 0
                || information.nNumberOfLinks != 1
            {
                return Err(
                    "Windows accepted observation is not an ordinary single-link file".into(),
                );
            }
            Ok((
                information.dwVolumeSerialNumber,
                information.nFileIndexHigh,
                information.nFileIndexLow,
            ))
        };
        let mut readback = Vec::new();
        (&named)
            .take((bytes.len() + 1) as u64)
            .read_to_end(&mut readback)
            .map_err(|error| error.to_string())?;
        if identity(file)? != identity(&named)? || readback != bytes {
            return Err("Windows accepted observation named custody differs".into());
        }
        client_accept(active, accepted);
        Ok(())
    })
}

fn client_issue(active: &mut Active, stage: &'static str, native_error: Option<i32>) {
    use std::io::Write;
    if !active.client_issue_reported {
        active.client_issue_reported = true;
        // Diagnostic stderr failure must not unwind across the frozen I/O result.
        let _ = writeln!(
            std::io::stderr().lock(),
            "warning[MCCLI-WINDOWS-CLIENT-INPUT-RETENTION]: stage={stage}; native_win32_error={native_error:?}"
        );
    }
}

pub(super) fn client_begin(provider: &PublicProviderBindingV1, cutoff: std::time::Instant) {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        let Some(active) = slot
            .as_mut()
            .filter(|active| active.client_destination.is_some())
        else {
            return;
        };
        if active.client_record.is_some() {
            client_issue(active, "multiple-launches", None);
            return;
        }
        active.client_record = Some(super::client_input::Record::new(provider.clone()));
        active.client_cutoff = Some(cutoff);
    });
}
pub(super) fn client_enabled() -> bool {
    ACTIVE.with(|slot| {
        slot.try_borrow().ok().is_some_and(|slot| {
            slot.as_ref().is_some_and(|active| {
                active.client_destination.is_some()
                    && active.client_record.is_some()
                    && !active.client_publication_attempted
            })
        })
    })
}
pub(super) fn client_connected(connection: super::client_input::Connection) {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        if let Some(record) = slot
            .as_mut()
            .and_then(|active| active.client_record.as_mut())
        {
            if record.connection.is_none() {
                record.connection = Some(connection);
            }
        }
    });
}
pub(super) fn client_request(nonce: &str, digest: &str) {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        let Some(active) = slot.as_mut() else { return };
        let custody = active
            .provider_request
            .as_ref()
            .is_some_and(|bytes| String::from(memcordon_core::hash_bytes(bytes)) == digest);
        if let Some(record) = active.client_record.as_mut() {
            if !custody || record.request.is_some() {
                record.binding_error =
                    Some(super::client_input::BindingError::RequestCustodyUnavailable);
                client_issue(active, "request-binding", None);
                return;
            }
            record.request = Some(super::client_input::Request {
                nonce: nonce.to_owned(),
                request_sha256: digest.to_owned(),
            });
            record.binding = super::client_input::Binding::AcceptedMissing;
        }
    });
}
pub(super) fn client_before_write(sample: super::client_input::Sample) {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        if let Some(record) = slot
            .as_mut()
            .and_then(|active| active.client_record.as_mut())
        {
            if matches!(
                record.before_launch_frame_call,
                super::client_input::Sample::Missing {}
            ) {
                record.before_launch_frame_call = sample;
            }
        }
    });
}
pub(super) fn client_after_write(
    result: super::client_input::FrameResult,
    sample: super::client_input::Sample,
) {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        let Some(active) = slot.as_mut() else { return };
        if let Some(record) = active.client_record.as_mut() {
            if record.frame_result == super::client_input::FrameResult::NotReached {
                record.frame_result = result;
                record.after_launch_frame_call = sample;
            }
        }
        if result == super::client_input::FrameResult::ReturnedError {
            client_publish(active);
        }
    });
}
fn client_accept(active: &mut Active, accepted: &memcordon_core::WindowsWorkloadAcceptedV1) {
    if active.client_publication_attempted {
        return;
    }
    if let Some(record) = active.client_record.as_ref() {
        let mut bound = record.clone();
        bound.accepted = Some(accepted.clone());
        bound.binding = super::client_input::Binding::AcceptedReceipt;
        if bound.validate().is_ok() {
            active.client_record = Some(bound);
        } else {
            if let Some(record) = active.client_record.as_mut() {
                record.binding_error = Some(super::client_input::BindingError::ReceiptMismatch);
            }
            client_issue(active, "accepted-binding", None);
        }
        client_publish(active);
    }
}
fn client_publish(active: &mut Active) {
    use std::{
        io::{Read, Write},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle,
    };
    if active.client_publication_attempted || active.client_record.is_none() {
        return;
    }
    active.client_publication_attempted = true;
    let Some(cutoff) = active.client_cutoff else {
        client_issue(active, "missing-cutoff", None);
        return;
    };
    let live = || {
        if std::time::Instant::now() < cutoff {
            Ok(())
        } else {
            Err(("cutoff", None))
        }
    };
    let Ok(()) = live() else {
        client_issue(active, "cutoff", None);
        return;
    };
    let timer = match crate::WindowsSynchronousIoDeadline::start(cutoff) {
        Ok(timer) => timer,
        Err(_) => {
            client_issue(active, "deadline-owner", None);
            return;
        }
    };
    let result = (|| -> Result<(), (&'static str, Option<i32>)> {
        let bytes = active
            .client_record
            .as_ref()
            .expect("checked client record")
            .encode()
            .map_err(|_| ("encoding", None))?;
        let (path, file) = active
            .client_destination
            .as_mut()
            .ok_or(("missing-destination", None))?;
        live()?;
        file.write_all(&bytes)
            .map_err(|error| ("write", error.raw_os_error()))?;
        live()?;
        file.sync_all()
            .map_err(|error| ("sync", error.raw_os_error()))?;
        live()?;
        let named = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .map_err(|error| ("named-open", error.raw_os_error()))?;
        let identity =
            |file: &std::fs::File| -> Result<(u32, u32, u32), (&'static str, Option<i32>)> {
                let mut info = BY_HANDLE_FILE_INFORMATION::default();
                // SAFETY: the owned file handle and SDK-sized output remain live.
                if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
                    return Err(("identity", std::io::Error::last_os_error().raw_os_error()));
                }
                if info.dwFileAttributes & (0x400 | 0x10 | 0x40) != 0 || info.nNumberOfLinks != 1 {
                    return Err(("file-kind", None));
                }
                Ok((
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                ))
            };
        let mut readback = Vec::new();
        (&named)
            .take((bytes.len() + 1) as u64)
            .read_to_end(&mut readback)
            .map_err(|error| ("readback", error.raw_os_error()))?;
        live()?;
        if identity(file)? != identity(&named)? || readback != bytes {
            return Err(("named-custody", None));
        }
        live()
    })();
    let settled = timer.finish();
    match result {
        Err((stage, error)) => client_issue(active, stage, error),
        Ok(()) if settled.is_err() => client_issue(active, "deadline-settlement", None),
        Ok(()) => {}
    }
}
fn client_finish() {
    ACTIVE.with(|slot| {
        let Ok(mut slot) = slot.try_borrow_mut() else {
            return;
        };
        if let Some(active) = slot.as_mut() {
            client_publish(active);
        }
    });
}

/// Local failure context only: never a request, authenticated receipt, or proof.
/// Preserve the original failure within the explicit thread-owned scope.
pub(super) fn retain_probe_failure(detail: &str) {
    ACTIVE.with(|active| {
        if let Some(active) = active.borrow_mut().as_mut() {
            if active.first_probe_failure.is_none() {
                const LIMIT: usize = 2048;
                let mut end = detail.len().min(LIMIT);
                while !detail.is_char_boundary(end) {
                    end -= 1;
                }
                active.first_probe_failure = Some(detail[..end].to_owned());
            }
        }
    });
}

pub(super) fn retain_request(bytes: &[u8]) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE, GetFileInformationByHandle,
    };
    ACTIVE.with(|active| {
        if let Some(active) = active.borrow_mut().as_mut() {
            if active.provider_request.is_some() {
                active.multiple_terminals = true;
                return Err("multiple Windows request observations".into());
            }
            if bytes.len() > memcordon_core::WINDOWS_MAX_FRAME_BYTES {
                return Err("Windows request observation exceeds native frame bound".into());
            }
            if let Some((path, file)) = active.request_publication.as_mut() {
                file.write_all(bytes).map_err(|error| error.to_string())?;
                file.sync_all().map_err(|error| error.to_string())?;
                let named = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                    .open(path)
                    .map_err(|error| error.to_string())?;
                let identity = |file: &std::fs::File| -> Result<(u32, u32, u32), String> {
                    let mut information = BY_HANDLE_FILE_INFORMATION::default();
                    // SAFETY: file owns this live handle and information is a writable native structure.
                    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) }
                        == 0
                    {
                        return Err(std::io::Error::last_os_error().to_string());
                    }
                    Ok((
                        information.dwVolumeSerialNumber,
                        information.nFileIndexHigh,
                        information.nFileIndexLow,
                    ))
                };
                if identity(file)? != identity(&named)? {
                    return Err("Windows named request observation identity differs".into());
                }
                let mut readback = Vec::new();
                named
                    .take((bytes.len() + 1) as u64)
                    .read_to_end(&mut readback)
                    .map_err(|error| error.to_string())?;
                if readback != bytes {
                    return Err("Windows named request observation bytes differ".into());
                }
            }
            active.provider_request = Some(bytes.to_vec());
        }
        Ok(())
    })
}

impl Drop for WindowsTerminalObservationScope {
    fn drop(&mut self) {
        if self.active {
            client_finish();
            ACTIVE.with(|active| {
                active.borrow_mut().take();
            });
        }
    }
}

pub(super) fn retain(
    provider: &PublicProviderBindingV1,
    terminal: &WindowsTerminalReceiptV3,
    delivery: &WindowsFrontendDeliveryV3,
    authority_json: Result<String, String>,
) {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        if let Some(active) = active.as_mut() {
            let authority_json = match authority_json {
                Ok(value) => value,
                Err(error) => {
                    active.first_probe_failure.get_or_insert(error);
                    return;
                }
            };
            if active.observation.is_some() {
                active.multiple_terminals = true;
                return;
            }
            let Some(provider_request) = active.provider_request.take() else {
                active.multiple_terminals = true;
                return;
            };
            active.observation = Some(AuthenticatedWindowsTerminalObservation {
                format: "memcordon.windows-terminal-observation".into(),
                revision: 2,
                provider: provider.clone(),
                terminal: terminal.clone(),
                frontend_delivery: delivery.clone(),
                provider_request,
                terminal_authority_json: authority_json,
            });
        }
    });
}
