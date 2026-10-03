//! Bounded, pinned no-follow reads of root-owned installed files.
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

pub(crate) fn read_protected_absolute(
    path: &Path,
    maximum: u64,
    exact_mode: Option<u32>,
) -> Result<Vec<u8>, String> {
    if !path.is_absolute() {
        return Err("installed artifact path is not absolute".into());
    }
    let mut directory = File::open("/").map_err(|error| error.to_string())?;
    verify_directory(&directory)?;
    let components: Vec<_> = path.components().collect();
    for (index, component) in components.iter().enumerate() {
        let Component::Normal(name) = component else {
            if index == 0 && *component == Component::RootDir {
                continue;
            }
            return Err("installed artifact path has a nonnormal component".into());
        };
        let leaf = CString::new(name.as_bytes()).map_err(|_| "installed artifact path has NUL")?;
        let final_component = index + 1 == components.len();
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | if final_component {
                0
            } else {
                libc::O_DIRECTORY
            };
        // SAFETY: exact native component relative to a retained protected ancestor.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), leaf.as_ptr(), flags) };
        if fd == -1 {
            return Err(format!(
                "installed artifact open: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat returned one owned descriptor.
        let opened = unsafe { File::from_raw_fd(fd) };
        if final_component {
            return read_protected_opened(opened, maximum, exact_mode);
        }
        verify_directory(&opened)?;
        directory = opened;
    }
    Err("installed artifact path has no file component".into())
}
fn verify_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("installed artifact ancestor is not root-protected".into());
    }
    Ok(())
}
fn read_protected_opened(
    mut file: File,
    maximum: u64,
    exact_mode: Option<u32>,
) -> Result<Vec<u8>, String> {
    let before = file.metadata().map_err(|error| error.to_string())?;
    if !before.is_file()
        || before.nlink() != 1
        || before.uid() != 0
        || before.mode() & 0o022 != 0
        || (exact_mode.is_none() && before.mode() & 0o111 != 0)
        || exact_mode.is_some_and(|mode| before.mode() & 0o7777 != mode)
        || before.len() > maximum
    {
        return Err("installed artifact file is not an exact protected regular file".into());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    let after = file.metadata().map_err(|error| error.to_string())?;
    if bytes.len() as u64 != before.len()
        || (
            after.dev(),
            after.ino(),
            after.len(),
            after.mtime(),
            after.mtime_nsec(),
            after.ctime(),
            after.ctime_nsec(),
        ) != (
            before.dev(),
            before.ino(),
            before.len(),
            before.mtime(),
            before.mtime_nsec(),
            before.ctime(),
            before.ctime_nsec(),
        )
    {
        return Err("installed artifact file changed during pinned readback".into());
    }
    Ok(bytes)
}
