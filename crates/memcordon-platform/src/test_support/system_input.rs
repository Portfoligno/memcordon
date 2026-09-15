//! Descriptor-backed identity checks for native CI system inputs.
use std::ffi::{CStr, OsStr};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// Return the actual descriptor path only when its filesystem is read-only.
pub fn macos_read_only_descriptor_path(file: &File) -> io::Result<PathBuf> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: the live descriptor and correctly sized output pointer satisfy fstatfs.
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatfs initialized the structure.
    if unsafe { filesystem.assume_init() }.f_flags & (libc::MNT_RDONLY as u32) == 0 {
        return Err(io::Error::other(
            "system digest requires a read-only native filesystem",
        ));
    }
    let mut descriptor_path = [0 as libc::c_char; libc::PATH_MAX as usize];
    // SAFETY: F_GETPATH writes at most PATH_MAX bytes to this live buffer.
    if unsafe {
        libc::fcntl(
            file.as_raw_fd(),
            libc::F_GETPATH,
            descriptor_path.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful F_GETPATH returns a NUL-terminated path in the buffer.
    let path = unsafe { CStr::from_ptr(descriptor_path.as_ptr()) };
    Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
}
