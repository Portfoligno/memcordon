//! Complete anonymous inodes become visible exactly once, without replacement.
use std::ffi::{CString, OsStr};
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Created,
    Synced,
    Published,
}

#[derive(Debug)]
pub struct PublicationError {
    pub committed: bool,
    pub source: io::Error,
}
impl std::fmt::Display for PublicationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "atomic initial publication committed={}: {}",
            self.committed, self.source
        )
    }
}
impl std::error::Error for PublicationError {}

pub fn publish(
    directory: &File,
    name: &OsStr,
    bytes: &[u8],
    mode: u32,
    bound: usize,
) -> Result<(), PublicationError> {
    publish_observed(directory, name, bytes, mode, bound, |_| Ok(()))
}

pub fn publish_observed(
    directory: &File,
    name: &OsStr,
    bytes: &[u8],
    mode: u32,
    bound: usize,
    mut checkpoint: impl FnMut(Phase) -> io::Result<()>,
) -> Result<(), PublicationError> {
    let mut committed = false;
    let result = (|| {
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || bytes.len() > bound
            || !directory.metadata()?.is_dir()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "publication requires one basename and bounded bytes",
            ));
        }
        let name = CString::new(name.as_bytes()).map_err(io::Error::other)?;
        // SAFETY: the held directory and constant path remain live. No pathname
        // exists for this inode until all bytes and file metadata are durable.
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c".".as_ptr(),
                libc::O_TMPFILE | libc::O_WRONLY | libc::O_CLOEXEC,
                mode as libc::mode_t,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat transfers the unique owned descriptor.
        let mut file = unsafe { File::from_raw_fd(raw) };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 0 || metadata.mode() & 0o777 != mode & 0o777 {
            return Err(io::Error::other(
                "anonymous publication inode metadata differs",
            ));
        }
        checkpoint(Phase::Created)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        checkpoint(Phase::Synced)?;
        // The documented procfd link route needs no CAP_DAC_READ_SEARCH. The
        // descriptor remains held, and linkat refuses any existing destination.
        let source = Path::new("/proc/self/fd").join(file.as_raw_fd().to_string());
        let source = CString::new(source.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: both strings and original owned descriptors remain live.
        if unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                source.as_ptr(),
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        committed = true;
        checkpoint(Phase::Published)?;
        directory.sync_all()
    })();
    result.map_err(|source| PublicationError { committed, source })
}
