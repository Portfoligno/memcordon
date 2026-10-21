//! Read-only image authority delegated to the exact restricted Probe process.
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_NAME_OPENED, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_READ, FILE_STANDARD_INFO, FILE_TYPE_DISK, FileStandardInfo,
    GetFileInformationByHandle, GetFileInformationByHandleEx, GetFileType,
    GetFinalPathNameByHandleW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, QueryFullProcessImageNameW};

use super::pipe::OwnedHandle;

const IMAGE_ACCESS: u32 = FILE_READ_DATA | FILE_READ_ATTRIBUTES | 0x0010_0000; // SYNCHRONIZE
const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImageFileIdentity {
    pub(crate) volume_serial: u32,
    pub(crate) file_id: u64,
    pub(crate) size: u64,
}

pub(crate) struct BootstrapImageFile {
    file: File,
    identity: ImageFileIdentity,
    sha256: String,
    receiver: bool,
}

fn live(deadline: Instant) -> Result<(), String> {
    if Instant::now() >= deadline {
        Err("bootstrap image verification exceeded original cutoff".into())
    } else {
        Ok(())
    }
}

fn native_error(api: &str) -> String {
    let error = std::io::Error::last_os_error();
    format!(
        "bootstrap image api={api} native_code={:?}: {error}",
        error.raw_os_error()
    )
}

fn open_read_pin(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .access_mode(IMAGE_ACCESS)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| format!("bootstrap image readonly pin: {error}"))
}

fn native_identity(file: &File) -> Result<ImageFileIdentity, String> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut flags = 0;
    // SAFETY: the file owns the live handle and flags is one writable scalar.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        return Err(native_error("GetHandleInformation"));
    }
    if flags & HANDLE_FLAG_INHERIT != 0
        || super::token::granted_handle_access(handle)? != IMAGE_ACCESS
        // SAFETY: GetFileType only queries the live object.
        || unsafe { GetFileType(handle) } != FILE_TYPE_DISK
    {
        return Err("bootstrap image capability rights, inheritance or object type differ".into());
    }
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: both APIs query this same owned file into exact initialized buffers.
    if unsafe { GetFileInformationByHandle(handle, &raw mut information) } == 0 {
        return Err(native_error("GetFileInformationByHandle"));
    }
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast(),
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(native_error(
            "GetFileInformationByHandleEx(FileStandardInfo)",
        ));
    }
    if information.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0
        || standard.Directory
        || standard.DeletePending
        || standard.NumberOfLinks != 1
        || standard.EndOfFile <= 0
        || standard.EndOfFile as u64 > MAX_IMAGE_BYTES
    {
        return Err("bootstrap image is not a bounded single-link immutable regular file".into());
    }
    Ok(ImageFileIdentity {
        volume_serial: information.dwVolumeSerialNumber,
        file_id: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
        size: standard.EndOfFile as u64,
    })
}

fn path_matches(actual: &[u16], expected: &Path) -> bool {
    let actual = String::from_utf16(actual);
    let expected = expected.to_str();
    match (actual, expected) {
        (Ok(actual), Some(expected)) => actual
            .strip_prefix(r"\\?\")
            .unwrap_or(&actual)
            .eq_ignore_ascii_case(expected.strip_prefix(r"\\?\").unwrap_or(expected)),
        _ => false,
    }
}

fn verify_file_path(file: &File, expected: &Path) -> Result<(), String> {
    let mut buffer = vec![0_u16; 32 * 1024];
    // FILE_NAME_OPENED queries the held object's opened name without asking the
    // restricted receiver to normalize inaccessible ancestor directories.
    // SAFETY: buffer supplies its declared writable UTF-16 capacity.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as HANDLE,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_OPENED,
        )
    };
    if length == 0 {
        return Err(native_error("GetFinalPathNameByHandleW(FILE_NAME_OPENED)"));
    }
    if length as usize >= buffer.len() || !path_matches(&buffer[..length as usize], expected) {
        return Err("bootstrap image capability has a foreign installed path".into());
    }
    Ok(())
}

fn verify_self_path(expected: &Path) -> Result<(), String> {
    let mut buffer = vec![0_u16; 32 * 1024];
    let mut length = buffer.len() as u32;
    // SAFETY: current-process pseudo handle is borrowed and buffer is writable.
    if unsafe {
        QueryFullProcessImageNameW(GetCurrentProcess(), 0, buffer.as_mut_ptr(), &raw mut length)
    } == 0
    {
        return Err(native_error("QueryFullProcessImageNameW(current)"));
    }
    if length as usize > buffer.len() || !path_matches(&buffer[..length as usize], expected) {
        return Err("bootstrap image capability does not match the executing process image".into());
    }
    Ok(())
}

fn read_bytes(
    file: &File,
    expected: &ImageFileIdentity,
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    live(deadline)?;
    if native_identity(file)? != *expected {
        return Err("bootstrap image native identity changed before readback".into());
    }
    // DuplicateHandle shares the file cursor. Rewind on every measurement;
    // issuer must not read concurrently once the receiver owns its duplicate.
    let mut reader = file;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("bootstrap image held-file rewind: {error}"))?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        live(deadline)?;
        let count = reader
            .read(&mut chunk)
            .map_err(|error| format!("bootstrap image held-file read: {error}"))?;
        if count == 0 {
            break;
        }
        if bytes.len() as u64 + count as u64 > MAX_IMAGE_BYTES {
            return Err("bootstrap image readback exceeds byte bound".into());
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    live(deadline)?;
    if bytes.len() as u64 != expected.size || native_identity(file)? != *expected {
        return Err("bootstrap image native identity or length changed during readback".into());
    }
    Ok(bytes)
}

impl BootstrapImageFile {
    pub(crate) fn open_installed(deadline: Instant) -> Result<Self, String> {
        live(deadline)?;
        let path = super::package::installed_target_desktop_bootstrap();
        super::package::reject_reparse_components(&path)?;
        let file = open_read_pin(&path)?;
        verify_file_path(&file, &path)?;
        let identity = native_identity(&file)?;
        let bytes = read_bytes(&file, &identity, deadline)?;
        super::package::verify_native_target_desktop_bootstrap_pe(&bytes)?;
        live(deadline)?;
        Ok(Self {
            file,
            identity,
            sha256: crate::package::sha256_bytes(&bytes),
            receiver: false,
        })
    }

    pub(crate) fn adopt_probe(
        handle: OwnedHandle,
        expected: &ImageFileIdentity,
        expected_sha256: &str,
        deadline: Instant,
    ) -> Result<Self, String> {
        // SAFETY: ownership is transferred exactly once, with no second closer.
        let file = unsafe { File::from_raw_handle(handle.raw()) };
        std::mem::forget(handle);
        let owner = Self {
            file,
            identity: expected.clone(),
            sha256: expected_sha256.to_owned(),
            receiver: true,
        };
        owner.verify(deadline)?;
        Ok(owner)
    }

    pub(crate) fn identity(&self) -> &ImageFileIdentity {
        &self.identity
    }

    pub(crate) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(crate) fn raw(&self) -> HANDLE {
        self.file.as_raw_handle() as HANDLE
    }

    pub(crate) fn duplicate_into(&self, process: HANDLE) -> Result<u64, String> {
        let mut remote = std::ptr::null_mut();
        // SAFETY: source file stays owned, process is the authenticated held
        // Probe, inheritance is false and only the exact measured mask is copied.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                self.raw(),
                process,
                &raw mut remote,
                IMAGE_ACCESS,
                0,
                0,
            )
        } == 0
        {
            return Err(native_error("DuplicateHandle(readonly image)"));
        }
        Ok(remote as usize as u64)
    }

    pub(crate) fn verify(&self, deadline: Instant) -> Result<String, String> {
        live(deadline)?;
        let path = super::package::installed_target_desktop_bootstrap();
        verify_file_path(&self.file, &path)?;
        if self.receiver {
            verify_self_path(&path)?;
        }
        let bytes = read_bytes(&self.file, &self.identity, deadline)?;
        super::package::verify_native_target_desktop_bootstrap_pe(&bytes)?;
        let hash = crate::package::sha256_bytes(&bytes);
        live(deadline)?;
        if hash != self.sha256 {
            return Err("bootstrap image capability content hash differs".into());
        }
        Ok(hash)
    }
}

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_bootstrap_image.rs"]
mod tests;
