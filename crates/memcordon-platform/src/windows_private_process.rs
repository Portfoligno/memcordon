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
        GetCurrentProcess, GetProcessId, GetProcessTimes, PROCESS_DUP_HANDLE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, QueryFullProcessImageNameW,
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
    /// Retain the actual spawned broker object, never a numeric PID lookup.
    pub fn from_original_child(
        child: &Child,
        expected: ProcessIdentity,
        deadline: Instant,
    ) -> io::Result<Self> {
        live(deadline)?;
        if child.id() != expected.pid || expected.pid == 0 || expected.birth == 0 {
            return Err(io::Error::other("original broker Child binding differs"));
        }
        let mut raw = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                child.as_raw_handle(),
                GetCurrentProcess(),
                &mut raw,
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_DUP_HANDLE,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        if unsafe { GetProcessId(handle.as_raw_handle()) } != expected.pid {
            return Err(io::Error::other("original broker native PID differs"));
        }
        if unsafe {
            GetProcessTimes(
                handle.as_raw_handle(),
                &mut creation,
                &mut exit,
                &mut kernel,
                &mut user,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if ((u128::from(creation.dwHighDateTime) << 32) | u128::from(creation.dwLowDateTime))
            != expected.birth
        {
            return Err(io::Error::other("original broker native birth differs"));
        }
        let owner = Self {
            identity: expected,
            _handle: Arc::new(handle),
        };
        if owner.has_exited()? {
            return Err(io::Error::other("original broker already retired"));
        }
        live(deadline)?;
        Ok(owner)
    }

    /// Duplicate only the original direct-root process reference, with the
    /// additional duplicate right required for its fixed metadata delivery.
    pub fn duplicate_pending_direct_root(
        &self,
        raw: u64,
        deadline: Instant,
    ) -> io::Result<WindowsPendingChildProcess> {
        live(deadline)?;
        let slot = isize::try_from(raw).map_err(io::Error::other)?;
        if slot <= 0 || self.has_exited()? {
            return Err(io::Error::other(
                "original direct source or reference unavailable",
            ));
        }
        let mut target = std::ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                self._handle.as_raw_handle(),
                slot as usize as _,
                GetCurrentProcess(),
                &mut target,
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_DUP_HANDLE,
                0,
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let handle = unsafe { OwnedHandle::from_raw_handle(target) };
        Ok(WindowsPendingChildProcess {
            handle: Arc::new(handle),
            source: self.identity,
            observed: Mutex::new(None),
        })
    }
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
    pub fn admit_selected_direct_root(
        &self,
        broker: &WindowsImageProcess,
        expected: ProcessIdentity,
        fixture: &File,
        selected: &[u8; 32],
        deadline: Instant,
    ) -> io::Result<WindowsImageProcess> {
        live(deadline)?;
        let timer =
            crate::WindowsSynchronousIoDeadline::start(deadline).map_err(io::Error::other)?;
        let primary = self.admit_inner(
            broker,
            expected,
            AdmissionIdentity::Direct { fixture, selected },
            deadline,
        );
        let settled = timer.finish().map_err(io::Error::other);
        match (primary, settled) {
            (Err(primary), Err(settlement)) => Err(io::Error::new(
                primary.kind(),
                AdmissionDeadlineFailure {
                    primary,
                    settlement,
                },
            )),
            (Err(primary), _) => Err(primary),
            (_, Err(settlement)) => Err(settlement),
            (Ok(owner), Ok(())) => {
                live(deadline)?;
                Ok(owner)
            }
        }
    }
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
        let primary = self.admit_inner(root, expected, AdmissionIdentity::Peer(fixture), deadline);
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
        admission: AdmissionIdentity<'_>,
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
        match admission {
            AdmissionIdentity::Peer(fixture) => {
                if std::fs::canonicalize(Path::new(&observed))? != std::fs::canonicalize(fixture)? {
                    return Err(io::Error::other(
                        "duplicated pending peer image differs from held fixture",
                    ));
                }
                live(deadline)?;
                if process.original_token_envelope(deadline)?
                    != root.original_token_envelope(deadline)?
                {
                    return Err(io::Error::other(
                        "duplicated pending peer original token differs",
                    ));
                }
            }
            AdmissionIdentity::Direct { fixture, selected } => {
                use std::os::windows::fs::OpenOptionsExt;
                use windows_sys::Win32::Storage::FileSystem::{
                    FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
                    FILE_SHARE_WRITE,
                };
                let named = std::fs::OpenOptions::new()
                    .access_mode(FILE_READ_ATTRIBUTES)
                    .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(Path::new(&observed))?;
                let actual = windows_held_file_metadata(&named)?;
                let expected = windows_held_file_metadata(fixture)?;
                if (
                    actual.volume_serial,
                    actual.file_index,
                    actual.length,
                    actual.links,
                ) != (
                    expected.volume_serial,
                    expected.file_index,
                    expected.length,
                    expected.links,
                ) || actual.attributes
                    & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    != 0
                    || actual.links != 1
                {
                    return Err(io::Error::other(
                        "original direct image differs from same held immutable fixture",
                    ));
                }
                live(deadline)?;
                use sha2::{Digest, Sha256};
                let observed: [u8; 32] = Sha256::digest(
                    serde_json::to_vec(&process.original_token_envelope(deadline)?)
                        .map_err(io::Error::other)?,
                )
                .into();
                if observed != *selected {
                    return Err(io::Error::other("original direct selected token differs"));
                }
            }
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

enum AdmissionIdentity<'a> {
    Peer(&'a Path),
    Direct {
        fixture: &'a File,
        selected: &'a [u8; 32],
    },
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
