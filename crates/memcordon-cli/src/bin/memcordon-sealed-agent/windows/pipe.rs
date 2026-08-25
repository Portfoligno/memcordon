use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};

use memcordon_core::{WINDOWS_MAX_FRAME_BYTES, WindowsSealedFault};

use super::security::SecurityDescriptor;

const PIPE_CLIENT_READ_WRITE: u32 = 0x0012_019b;

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn new(handle: HANDLE) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }

    pub const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this type owns one valid kernel handle and closes it once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn connect(name: &str) -> Result<OwnedHandle, String> {
    connect_with_fault(name, None)
}

pub fn connect_with_fault(
    name: &str,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<OwnedHandle, String> {
    let name = wide_null(name);
    for _ in 0..100 {
        if certification_fault == Some(WindowsSealedFault::PrivatePipeConnect) {
            return Err(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected PrivatePipeConnect".to_owned(),
            );
        }
        // SAFETY: every pointer references a live, NUL-terminated UTF-16 buffer;
        // the returned handle is transferred into OwnedHandle.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                PIPE_CLIENT_READ_WRITE,
                FILE_SHARE_NONE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return OwnedHandle::new(handle);
        }
        let error = io::Error::last_os_error();
        let code = error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok());
        if !matches!(code, Some(ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND)) {
            return Err(error.to_string());
        }
        if code == Some(ERROR_FILE_NOT_FOUND) {
            std::thread::sleep(Duration::from_millis(10));
        } else {
            // SAFETY: name remains NUL-terminated for the call.
            unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
        }
    }
    Err("timed out waiting for the sealed provider pipe".to_owned())
}

pub fn endpoint_exists(name: &str) -> Result<bool, String> {
    let name = wide_null(name);
    // SAFETY: name is a live NUL-terminated pipe path; a successful handle is
    // immediately adopted and closed.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            PIPE_CLIENT_READ_WRITE,
            FILE_SHARE_NONE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle != INVALID_HANDLE_VALUE {
        drop(OwnedHandle::new(handle)?);
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    let code = error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok());
    if code == Some(ERROR_FILE_NOT_FOUND) {
        Ok(false)
    } else if code == Some(ERROR_PIPE_BUSY) {
        Ok(true)
    } else {
        Err(error.to_string())
    }
}

pub struct PipeListener {
    name: Vec<u16>,
    security: SecurityDescriptor,
    first_instance: AtomicBool,
}

impl PipeListener {
    pub fn new(name: &str, security: SecurityDescriptor) -> Self {
        Self {
            name: wide_null(name),
            security,
            first_instance: AtomicBool::new(true),
        }
    }

    pub fn accept(&self) -> Result<OwnedHandle, String> {
        self.accept_prepared(self.prepare()?)
    }

    pub fn prepare(&self) -> Result<OwnedHandle, String> {
        self.prepare_with_fault(None)
    }

    pub fn prepare_with_fault(
        &self,
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<OwnedHandle, String> {
        let attributes = self.security.attributes(false);
        // SAFETY: name and security descriptor remain live for creation; the
        // pipe handle is transferred into OwnedHandle.
        let first_instance = self.first_instance.swap(false, Ordering::AcqRel);
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first_instance {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        if certification_fault == Some(WindowsSealedFault::PublicPipeCreate) {
            return Err(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected PublicPipeCreate".to_owned(),
            );
        }
        let pipe = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16,
                64 * 1024,
                64 * 1024,
                0,
                &raw const attributes,
            )
        };
        let pipe = OwnedHandle::new(pipe)?;
        self.security.verify_kernel_object(pipe.raw())?;
        Ok(pipe)
    }

    pub fn accept_prepared(&self, pipe: OwnedHandle) -> Result<OwnedHandle, String> {
        // SAFETY: pipe is a fresh listening named-pipe instance and no
        // OVERLAPPED pointer is required for synchronous operation.
        if unsafe { ConnectNamedPipe(pipe.raw(), ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok())
                != Some(ERROR_PIPE_CONNECTED)
            {
                return Err(error.to_string());
            }
        }
        Ok(pipe)
    }
}

pub fn disconnect(handle: HANDLE) {
    // SAFETY: caller provides a connected named-pipe server handle; failure is
    // harmless during terminal cleanup.
    unsafe { DisconnectNamedPipe(handle) };
}

pub fn write_frame<T: Serialize>(handle: HANDLE, value: &T) -> Result<(), String> {
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if payload.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err("Windows provider frame exceeds the protocol bound".to_owned());
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| "Windows provider frame length is not representable".to_owned())?;
    write_all(handle, &length.to_le_bytes())?;
    write_all(handle, &payload)
}

pub fn read_frame<T: DeserializeOwned>(handle: HANDLE) -> Result<T, String> {
    let mut length = [0_u8; 4];
    read_exact(handle, &mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > WINDOWS_MAX_FRAME_BYTES {
        return Err("Windows provider frame exceeds the protocol bound".to_owned());
    }
    let mut payload = vec![0_u8; length];
    read_exact(handle, &mut payload)?;
    serde_json::from_slice(&payload).map_err(|error| error.to_string())
}

pub fn frame_available(handle: HANDLE) -> Result<bool, String> {
    let mut available = 0_u32;
    // SAFETY: available points to initialized storage and no data buffer is
    // requested. The named-pipe handle remains owned by the caller.
    if unsafe {
        PeekNamedPipe(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &raw mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(ERROR_BROKEN_PIPE)
        {
            return Err("named-pipe peer disconnected".to_owned());
        }
        return Err(error.to_string());
    }
    Ok(available >= 4)
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let requested = u32::try_from(bytes.len().min(u32::MAX as usize))
            .expect("bounded write length is representable");
        let mut written = 0_u32;
        // SAFETY: bytes and written remain valid for the synchronous call; no
        // OVERLAPPED storage is used.
        if unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                requested,
                &raw mut written,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if written == 0 {
            return Err("zero-byte named-pipe write".to_owned());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_exact(handle: HANDLE, mut bytes: &mut [u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let requested = u32::try_from(bytes.len().min(u32::MAX as usize))
            .expect("bounded read length is representable");
        let mut read = 0_u32;
        // SAFETY: bytes and read remain valid for the synchronous call; no
        // OVERLAPPED storage is used.
        if unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                requested,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if read == 0 {
            return Err("unexpected end of Windows provider frame".to_owned());
        }
        let (_, rest) = bytes.split_at_mut(read as usize);
        bytes = rest;
    }
    Ok(())
}

pub fn wait_poll_interval() {
    std::thread::sleep(Duration::from_millis(10));
}
