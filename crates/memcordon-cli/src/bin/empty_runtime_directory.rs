//! Descriptor-pinned, empty-only retirement; callers retain package authority.
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    time::Instant,
};

pub(crate) fn retire(
    parent: &File,
    name: &OsStr,
    held: &File,
    expected_uid: u32,
    cutoff: Instant,
) -> io::Result<()> {
    let check_cutoff = || {
        if Instant::now() >= cutoff {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original empty-root retirement cutoff exhausted",
            ))
        } else {
            Ok(())
        }
    };
    check_cutoff()?;
    if std::path::Path::new(name).file_name() != Some(name)
        || !matches!(
            (
                std::path::Path::new(name).components().next(),
                std::path::Path::new(name).components().count()
            ),
            (Some(std::path::Component::Normal(_)), 1)
        )
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "retirement requires one exact directory name",
        ));
    }
    let protected = |metadata: &std::fs::Metadata| {
        if !metadata.is_dir() || metadata.uid() != expected_uid || metadata.mode() & 0o022 != 0 {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "empty-root directory custody differs",
            ))
        } else {
            Ok(())
        }
    };
    protected(&parent.metadata()?)?;
    let original = held.metadata()?;
    protected(&original)?;
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory name contains NUL"))?;
    // SAFETY: parent is a live directory descriptor and name is NUL-terminated.
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound && original.nlink() == 0 {
            return Ok(());
        }
        return Err(error);
    }
    // SAFETY: successful openat returned a new uniquely owned descriptor.
    let named = unsafe { File::from_raw_fd(raw) };
    let current = named.metadata()?;
    protected(&current)?;
    if (original.dev(), original.ino()) != (current.dev(), current.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty-root directory identity substituted",
        ));
    }
    check_cutoff()?;
    // SAFETY: both descriptors remain held; AT_REMOVEDIR atomically rejects
    // any nonempty root, including an entry created after identity readback.
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if held.metadata()?.nlink() != 0 {
        return Err(io::Error::other("retired empty root remains linked"));
    }
    parent.sync_all()
}
