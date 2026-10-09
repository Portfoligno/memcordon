//! Explicit frontend-local custody of an already authenticated terminal receipt.
//! This adds no provider authority and does not change existing result formats.
use memcordon_core::{
    PublicProviderBindingV1, WindowsTerminalDeliveryEvidenceV1, WindowsTerminalReceiptV2,
};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::marker::PhantomData;
use std::rc::Rc;

pub const MAX_TERMINAL_OBSERVATION_BYTES: usize =
    memcordon_core::WINDOWS_MAX_TERMINAL_FRAME_BYTES * 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedWindowsTerminalObservation {
    pub format: String,
    pub revision: u32,
    pub provider: PublicProviderBindingV1,
    pub terminal: WindowsTerminalReceiptV2,
    pub frontend_delivery: WindowsTerminalDeliveryEvidenceV1,
    /// Exact frontend-local serialization hashed by the authenticated protocol.
    pub provider_request: Vec<u8>,
}

struct Active {
    observation: Option<AuthenticatedWindowsTerminalObservation>,
    multiple_terminals: bool,
    provider_request: Option<Vec<u8>>,
    request_publication: Option<(std::path::PathBuf, std::fs::File)>,
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
            });
            Ok(Self {
                active: true,
                _thread: PhantomData,
            })
        })
    }

    pub fn finish(mut self) -> Result<AuthenticatedWindowsTerminalObservation, String> {
        let captured = ACTIVE.with(|active| active.borrow_mut().take());
        self.active = false;
        let captured =
            captured.ok_or_else(|| "Windows terminal observation ownership was lost".to_owned())?;
        if captured.multiple_terminals {
            return Err("Windows observation requires exactly one authenticated terminal".into());
        }
        captured.observation.ok_or_else(|| {
            "requested authenticated Windows terminal observation is unavailable".into()
        })
    }

    /// A request-only capture preserves a preauthorization refusal without
    /// requiring or manufacturing an authenticated terminal receipt.
    pub fn finish_request(mut self) -> Result<Vec<u8>, String> {
        let captured = ACTIVE.with(|active| active.borrow_mut().take());
        self.active = false;
        let captured =
            captured.ok_or_else(|| "Windows request observation ownership was lost".to_owned())?;
        if captured.multiple_terminals {
            return Err("Windows request observation requires exactly one request".into());
        }
        let bytes = captured.provider_request.ok_or_else(|| {
            "requested Windows launch request observation is unavailable".to_owned()
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
                let mut named = std::fs::OpenOptions::new()
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
            ACTIVE.with(|active| {
                active.borrow_mut().take();
            });
        }
    }
}

pub(super) fn retain(
    provider: &PublicProviderBindingV1,
    terminal: &WindowsTerminalReceiptV2,
    delivery: &WindowsTerminalDeliveryEvidenceV1,
) {
    ACTIVE.with(|active| {
        let mut active = active.borrow_mut();
        if let Some(active) = active.as_mut() {
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
                revision: 1,
                provider: provider.clone(),
                terminal: terminal.clone(),
                frontend_delivery: delivery.clone(),
                provider_request,
            });
        }
    });
}
