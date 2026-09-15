//! Effective filesystem access used by the native CI input inventory.
use std::fs::Metadata;
use std::io;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;

pub struct UnsearchableDirectory {
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub effective_uid: u32,
    pub effective_gid: u32,
    pub supplementary_groups: Vec<u32>,
}

/// Prove that the current compilation principal cannot search this directory.
/// A denied enumeration alone is insufficient: known child names may be usable.
pub fn unsearchable_directory(
    path: &Path,
    metadata: &Metadata,
) -> io::Result<Option<UnsearchableDirectory>> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: path is a live NUL-terminated pathname; scalar arguments match
    // faccessat2. AT_EACCESS checks effective credentials and the kernel checks
    // ACLs, unlike older libc faccessat emulation.
    #[cfg(target_os = "linux")]
    let status = unsafe {
        libc::syscall(
            libc::SYS_faccessat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            libc::X_OK,
            libc::AT_EACCESS,
        )
    };
    // SAFETY: path is a live NUL-terminated pathname. Darwin's native faccessat
    // checks effective credentials, including ACLs, when AT_EACCESS is supplied.
    #[cfg(target_os = "macos")]
    let status =
        unsafe { libc::faccessat(libc::AT_FDCWD, path.as_ptr(), libc::X_OK, libc::AT_EACCESS) };
    if status == 0 {
        return Ok(None);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::EACCES) {
        return Err(io::Error::other(format!(
            "checking effective directory search access: {error}"
        )));
    }
    // SAFETY: a zero-length getgroups call permits a null buffer.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: the buffer has capacity for count group ids.
    let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
    if actual < 0 {
        return Err(io::Error::last_os_error());
    }
    groups.truncate(actual as usize);
    groups.sort_unstable();
    // SAFETY: credential getters have no preconditions.
    let (effective_uid, effective_gid) = unsafe { (libc::geteuid(), libc::getegid()) };
    Ok(Some(UnsearchableDirectory {
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        effective_uid,
        effective_gid,
        supplementary_groups: groups,
    }))
}
