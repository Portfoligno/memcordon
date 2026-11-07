//! Fixed-right object transfer through already-owned process references.
use super::{ProcessIdentity, WindowsImageProcess, windows_held_file_metadata};
use crate::windows_private_fixture_binding::MAX_DIRECTORY_REFERENCES;
use std::{
    fs::File,
    io,
    os::windows::{
        ffi::OsStringExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    process::Child,
    sync::{Arc, Mutex},
    time::Instant,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, FILETIME},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_READ_ATTRIBUTES,
    },
    System::Threading::{
        GetCurrentProcess, GetProcessId, GetProcessTimes, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
    },
};

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original private object-transfer cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}

fn directory_reference(
    source: &File,
    recipient: windows_sys::Win32::Foundation::HANDLE,
    deadline: Instant,
    duplicated: &mut u32,
) -> io::Result<u64> {
    metadata_reference(source, recipient, deadline, duplicated, false)
}
fn metadata_reference(
    source: &File,
    recipient: windows_sys::Win32::Foundation::HANDLE,
    deadline: Instant,
    duplicated: &mut u32,
    marker: bool,
) -> io::Result<u64> {
    live(deadline)?;
    if *duplicated as usize >= MAX_DIRECTORY_REFERENCES {
        return Err(io::Error::other(
            "private directory transfer exceeds finite role bound",
        ));
    }
    let metadata = windows_held_file_metadata(source)?;
    live(deadline)?;
    let valid = if marker {
        metadata.attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | 0x40) == 0
            && metadata.links == 1
            && metadata.length == 0
    } else {
        metadata.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && metadata.attributes & FILE_ATTRIBUTE_REPARSE_POINT == 0
    };
    if !valid {
        return Err(io::Error::other(if marker {
            "private metadata source kind or marker empty extent differs"
        } else {
            "private metadata source is not a no-reparse directory"
        }));
    }
    let mut transferred = std::ptr::null_mut();
    // SAFETY: caller owns both objects; explicit read-attributes only, no
    // inheritable reference, same-access fallback or remote-close operation.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source.as_raw_handle(),
            recipient,
            &mut transferred,
            FILE_READ_ATTRIBUTES,
            0,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Charge successful native duplication BEFORE any fallible cutoff check.
    // The recipient's exact process owner settles even an unpublished slot.
    *duplicated += 1;
    live(deadline)?;
    Ok(transferred as usize as u64)
}

pub fn duplicate_directory_metadata_into_child(
    child: &Child,
    source: &File,
    deadline: Instant,
    duplicated: &mut u32,
) -> io::Result<u64> {
    directory_reference(source, child.as_raw_handle(), deadline, duplicated)
}

pub fn duplicate_marker_metadata_into_child(
    child: &Child,
    source: &File,
    deadline: Instant,
    duplicated: &mut u32,
) -> io::Result<u64> {
    metadata_reference(source, child.as_raw_handle(), deadline, duplicated, true)
}

/// A successful remote duplicate is immediately owned, even if later admission
/// fails. The controller must retain this owner before calling `admit`.
pub struct WindowsPendingChildProcess {
    handle: Arc<OwnedHandle>,
    source: ProcessIdentity,
    observed: Mutex<Option<ProcessIdentity>>,
}

impl WindowsImageProcess {
    pub fn same_object_reference(&self, other: &Self) -> bool {
        self.identity == other.identity && Arc::ptr_eq(&self._handle, &other._handle)
    }
    pub fn duplicate_directory_metadata(
        &self,
        source: &File,
        deadline: Instant,
        duplicated: &mut u32,
    ) -> io::Result<u64> {
        live(deadline)?;
        if self.has_exited()? {
            return Err(io::Error::other("private metadata recipient has retired"));
        }
        directory_reference(source, self._handle.as_raw_handle(), deadline, duplicated)
    }
    pub fn duplicate_marker_metadata(
        &self,
        source: &File,
        deadline: Instant,
        duplicated: &mut u32,
    ) -> io::Result<u64> {
        live(deadline)?;
        if self.has_exited()? {
            return Err(io::Error::other("private metadata recipient has retired"));
        }
        metadata_reference(
            source,
            self._handle.as_raw_handle(),
            deadline,
            duplicated,
            true,
        )
    }

    /// Duplicate a root-local Child reference FROM this retained root object.
    /// No PID is opened. No metadata capability may be delivered until native
    /// admission and insertion of this actual owner precede the authenticated ACK.
    pub fn duplicate_pending_child(
        &self,
        root_local_handle: u64,
        deadline: Instant,
    ) -> io::Result<WindowsPendingChildProcess> {
        live(deadline)?;
        let slot = isize::try_from(root_local_handle).map_err(io::Error::other)?;
        if slot <= 0 || self.has_exited()? {
            return Err(io::Error::other(
                "pending peer source/handle is unavailable",
            ));
        }
        live(deadline)?;
        let mut transferred = std::ptr::null_mut();
        // SAFETY: source root object is retained with PROCESS_DUP_HANDLE; the
        // scalar is interpreted only in that process. The local result requests
        // query/retirement rights, never terminate, duplicate or arbitrary rights.
        if unsafe {
            DuplicateHandle(
                self._handle.as_raw_handle(),
                slot as usize as _,
                GetCurrentProcess(),
                &mut transferred,
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful DuplicateHandle creates one local reference. Own it
        // before any later native query/cutoff failure; caller retains this owner.
        let handle = unsafe { OwnedHandle::from_raw_handle(transferred) };
        Ok(WindowsPendingChildProcess {
            handle: Arc::new(handle),
            source: self.identity,
            observed: Mutex::new(None),
        })
    }
}

impl WindowsPendingChildProcess {
    pub fn admit(
        &self,
        root: &WindowsImageProcess,
        expected: ProcessIdentity,
        fixture: &Path,
        deadline: Instant,
    ) -> io::Result<WindowsImageProcess> {
        live(deadline)?;
        let timer =
            crate::WindowsSynchronousIoDeadline::start(deadline).map_err(io::Error::other)?;
        let primary = self.admit_inner(root, expected, fixture, deadline);
        let settled = timer.finish().map_err(io::Error::other);
        match (primary, settled) {
            (Err(primary), Err(settlement)) => Err(io::Error::new(
                primary.kind(),
                AdmissionDeadlineFailure {
                    primary,
                    settlement,
                },
            )),
            (Err(primary), Ok(())) => Err(primary),
            (Ok(_), Err(settlement)) => Err(settlement),
            (Ok(process), Ok(())) => {
                live(deadline)?;
                Ok(process)
            }
        }
    }

    fn admit_inner(
        &self,
        root: &WindowsImageProcess,
        expected: ProcessIdentity,
        fixture: &Path,
        deadline: Instant,
    ) -> io::Result<WindowsImageProcess> {
        live(deadline)?;
        if self.source != root.identity || expected.pid == 0 || expected.birth == 0 {
            return Err(io::Error::other(
                "pending peer source/expected identity differs",
            ));
        }
        let raw = self.handle.as_raw_handle();
        // SAFETY: this exact locally-owned object is queried; an unrelated
        // object type fails rather than being treated as a process identity.
        let pid = unsafe { GetProcessId(raw) };
        if pid == 0 {
            return Err(io::Error::last_os_error());
        }
        live(deadline)?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessTimes(raw, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let identity = ProcessIdentity {
            pid,
            birth: (u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime),
        };
        *self
            .observed
            .lock()
            .map_err(|_| io::Error::other("pending peer identity ownership poisoned"))? =
            Some(identity);
        live(deadline)?;
        if identity != expected || identity.birth < root.identity.birth {
            return Err(io::Error::other(
                "duplicated pending peer native identity differs",
            ));
        }
        let process = WindowsImageProcess {
            identity,
            _handle: Arc::clone(&self.handle),
        };
        if root.has_exited()? {
            return Err(io::Error::other(
                "duplicated pending peer source has retired",
            ));
        }
        live(deadline)?;
        if process.has_exited()? {
            return Err(io::Error::other("duplicated pending peer has retired"));
        }
        live(deadline)?;
        if process.native_parent_process_id()? != root.identity.pid {
            return Err(io::Error::other(
                "duplicated pending peer live native parent differs",
            ));
        }
        live(deadline)?;
        let mut image = [0u16; 32768];
        let mut units = image.len() as u32;
        if unsafe { QueryFullProcessImageNameW(raw, 0, image.as_mut_ptr(), &mut units) } == 0 {
            return Err(io::Error::last_os_error());
        }
        live(deadline)?;
        let count = usize::try_from(units).map_err(io::Error::other)?;
        if count == 0 || count >= image.len() || image[..count].contains(&0) {
            return Err(io::Error::other("pending peer native image extent differs"));
        }
        let observed = std::ffi::OsString::from_wide(&image[..count]);
        if std::fs::canonicalize(Path::new(&observed))? != std::fs::canonicalize(fixture)? {
            return Err(io::Error::other(
                "duplicated pending peer image differs from held fixture",
            ));
        }
        live(deadline)?;
        if process.original_token_envelope(deadline)? != root.original_token_envelope(deadline)? {
            return Err(io::Error::other(
                "duplicated pending peer original token differs",
            ));
        }
        live(deadline)?;
        Ok(process)
    }

    pub fn has_exited(&self) -> io::Result<bool> {
        let identity = self
            .observed
            .lock()
            .map_err(|_| io::Error::other("pending peer identity ownership poisoned"))?
            .ok_or_else(|| {
                io::Error::other("pending object native process identity is unproved")
            })?;
        WindowsImageProcess {
            identity,
            _handle: Arc::clone(&self.handle),
        }
        .has_exited()
    }
}

#[derive(Debug)]
struct AdmissionDeadlineFailure {
    primary: io::Error,
    settlement: io::Error,
}
impl std::fmt::Display for AdmissionDeadlineFailure {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "{}; private admission deadline settlement: {}",
            self.primary, self.settlement
        )
    }
}
impl std::error::Error for AdmissionDeadlineFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.primary)
    }
}
