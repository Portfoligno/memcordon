//! Finite anonymous standard streams for the direct measurement process.
use super::matched_control_process::live;
#[path = "matched_control_io_diagnostic.rs"]
mod diagnostic;
#[path = "matched_control_security.rs"]
pub(super) mod security;
pub(super) use diagnostic::StreamRole;
use std::{
    fs::File,
    io::{self, Read},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    thread::JoinHandle,
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{HANDLE, HANDLE_FLAG_INHERIT, SetHandleInformation},
    Security::{
        ACL, InitializeSecurityDescriptor, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SetSecurityDescriptorDacl,
    },
    System::{Pipes::CreatePipe, Threading::WaitForSingleObject},
};

pub(super) const CAPTURE_BYTES: usize = 64 * 1024;
pub(super) struct Pipe {
    pub read: File,
    pub write: File,
}
impl Pipe {
    fn make(sd: *mut std::ffi::c_void, inherit_read: bool, cutoff: Instant) -> io::Result<Self> {
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 1,
        };
        let mut read = std::ptr::null_mut();
        let mut write = std::ptr::null_mut();
        live(cutoff)?;
        if unsafe { CreatePipe(&mut read, &mut write, &attributes, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let read = unsafe { File::from_raw_handle(read) };
        let write = unsafe { File::from_raw_handle(write) };
        let local = if inherit_read {
            write.as_raw_handle()
        } else {
            read.as_raw_handle()
        };
        live(cutoff)?;
        if unsafe { SetHandleInformation(local, HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        live(cutoff)?;
        Ok(Self { read, write })
    }
    pub fn like_original(handle: HANDLE, role: StreamRole, cutoff: Instant) -> io::Result<Self> {
        use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
        live(cutoff)?;
        if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
            return Err(io::Error::other(
                "matched original output stream is not a pipe",
            ));
        }
        let descriptor = security::capture(handle, role, cutoff)?;
        Self::make(descriptor.as_ptr(), false, cutoff)
    }
    /// Use the selected caller's actual prepared default ACL, not the broker's
    /// ambient default. No token is impersonated and no ACL is enlarged here.
    pub fn create(default_acl: &[u8], inherit_read: bool, cutoff: Instant) -> io::Result<Self> {
        if default_acl.is_empty() || default_acl.len() > 64 * 1024 {
            return Err(io::Error::other(
                "matched pipe default ACL unavailable or oversize",
            ));
        }
        let mut acl = vec![0u32; default_acl.len().div_ceil(std::mem::size_of::<u32>())];
        unsafe {
            std::ptr::copy_nonoverlapping(
                default_acl.as_ptr(),
                acl.as_mut_ptr().cast(),
                default_acl.len(),
            )
        };
        let mut sd = SECURITY_DESCRIPTOR::default();
        live(cutoff)?;
        if unsafe { InitializeSecurityDescriptor((&mut sd as *mut SECURITY_DESCRIPTOR).cast(), 1) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        live(cutoff)?;
        if unsafe {
            SetSecurityDescriptorDacl(
                (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
                1,
                acl.as_mut_ptr().cast::<ACL>(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Self::make(
            (&mut sd as *mut SECURITY_DESCRIPTOR).cast(),
            inherit_read,
            cutoff,
        )
    }
}

pub(super) fn duplicate_inheritable(handle: HANDLE, cutoff: Instant) -> io::Result<OwnedHandle> {
    use windows_sys::Win32::{
        Foundation::{DUPLICATE_SAME_ACCESS, DuplicateHandle, INVALID_HANDLE_VALUE},
        System::Threading::GetCurrentProcess,
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other("matched inherited stream missing"));
    }
    let mut copy = std::ptr::null_mut();
    live(cutoff)?;
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut copy,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let copy = unsafe { OwnedHandle::from_raw_handle(copy) };
    live(cutoff)?;
    Ok(copy)
}

pub(super) struct Capture {
    reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
}
impl Drop for Capture {
    fn drop(&mut self) {
        if let Some(reader) = self.reader.take() {
            std::mem::forget(reader)
        }
    }
}
impl Capture {
    pub fn start(mut file: File, work: Instant) -> Self {
        let reader = std::thread::spawn(move || {
            let timer = memcordon_platform::WindowsSynchronousIoDeadline::start(work)
                .map_err(io::Error::other)?;
            let read = (|| {
                let mut captured = Vec::new();
                let mut buffer = [0u8; 4096];
                loop {
                    live(work)?;
                    let amount = file.read(&mut buffer)?;
                    live(work)?;
                    if amount == 0 {
                        return Ok(captured);
                    }
                    if amount > CAPTURE_BYTES - captured.len() {
                        return Err(io::Error::other("matched direct stream exceeds64KiB"));
                    }
                    captured.extend_from_slice(&buffer[..amount]);
                }
            })();
            let finished = timer.finish().map_err(io::Error::other);
            match read {
                Err(primary) => Err(super::matched_control_process::combine(primary, finished)),
                Ok(bytes) => {
                    finished?;
                    live(work)?;
                    Ok(bytes)
                }
            }
        });
        Self {
            reader: Some(reader),
        }
    }
    pub fn finish(&mut self, cutoff: Instant) -> io::Result<Vec<u8>> {
        let reader = self
            .reader
            .as_ref()
            .ok_or_else(|| io::Error::other("matched capture already consumed"))?;
        loop {
            live(cutoff)?;
            let status = unsafe { WaitForSingleObject(reader.as_raw_handle(), 0) };
            match status {
                windows_sys::Win32::Foundation::WAIT_OBJECT_0 => {
                    live(cutoff)?;
                    break;
                }
                windows_sys::Win32::Foundation::WAIT_TIMEOUT => {
                    std::thread::sleep(std::time::Duration::from_millis(1))
                }
                _ => return Err(io::Error::last_os_error()),
            }
        }
        let bytes = self
            .reader
            .take()
            .expect("held capture thread")
            .join()
            .map_err(|_| io::Error::other("matched capture thread panicked"))??;
        live(cutoff)?;
        Ok(bytes)
    }
}
