//! Removal evidence obtained from the original held cgroup, without path lookup.
#![cfg(target_os = "linux")]

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;

#[derive(Debug, serde::Serialize)]
pub struct LinuxCgroupRetirement {
    pub device: u64,
    pub inode: u64,
    pub native_links: u64,
    pub filesystem: &'static str,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle_retirement: Option<KernfsHandleRetirement>,
}

#[derive(Debug, serde::Serialize)]
pub struct KernfsHandleRetirement {
    pub handle_type: i32,
    pub handle_bytes: u32,
    pub handle_id: u64,
    pub mount_id: i32,
    pub open_errno: i32,
}

// Linux exportfs FILEID_KERNFS is one native u64 kernfs id. This fixed
// representation refuses any future/unsupported handle format or larger size.
#[repr(C)]
struct KernfsHandle {
    handle_bytes: u32,
    handle_type: i32,
    id: u64,
}

/// Observe removal of the exact retained cgroup2 inode.
///
/// Kernfs through Linux 6.17 reports subdirs+2 links even after removal. For
/// these kernels, obtain the kernel's handle from this fd with AT_EMPTY_PATH
/// and ask that same filesystem to resolve it. ESTALE proves this exact node
/// is no longer active; no pathname disappearance is accepted. Resolving a
/// still-live handle requires CAP_DAC_READ_SEARCH; capability and all other
/// errors remain errors. Callers separately prove extinction of held processes.
pub fn linux_cgroup_retirement(group: &File) -> io::Result<Option<LinuxCgroupRetirement>> {
    let metadata = group.metadata()?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: group remains borrowed and the output has the native statfs layout.
    if unsafe { libc::fstatfs(group.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful fstatfs call initialized the complete output.
    let filesystem = unsafe { filesystem.assume_init() };
    if !metadata.is_dir() || filesystem.f_type != libc::CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other(
            "retirement owner is not a cgroup2 directory",
        ));
    }
    let mut observation = LinuxCgroupRetirement {
        device: metadata.dev(),
        inode: metadata.ino(),
        native_links: metadata.nlink(),
        filesystem: "cgroup2",
        kind: "removed-held-inode",
        handle_retirement: None,
    };
    if metadata.nlink() == 0 {
        return Ok(Some(observation));
    }
    let mut handle = KernfsHandle {
        handle_bytes: std::mem::size_of::<u64>() as u32,
        handle_type: 0,
        id: 0,
    };
    let mut mount_id = 0;
    // SAFETY: repr(C) supplies file_handle's two scalar header fields followed
    // by exactly the advertised writable payload. Empty path targets group.
    if unsafe {
        libc::name_to_handle_at(
            group.as_raw_fd(),
            c"".as_ptr(),
            (&raw mut handle).cast::<libc::file_handle>(),
            &raw mut mount_id,
            libc::AT_EMPTY_PATH,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if handle.handle_type != 0xfe
        || handle.handle_bytes != std::mem::size_of::<u64>() as u32
        || handle.id != metadata.ino()
        || mount_id <= 0
    {
        return Err(io::Error::other(
            "held cgroup kernfs handle identity differs",
        ));
    }
    // SAFETY: the kernel generated this validated handle from group itself;
    // the same borrowed descriptor pins the mount used to resolve the handle.
    let reopened = unsafe {
        libc::open_by_handle_at(
            group.as_raw_fd(),
            (&raw mut handle).cast::<libc::file_handle>(),
            libc::O_PATH | libc::O_CLOEXEC,
        )
    };
    if reopened < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESTALE) {
            return Err(error);
        }
        observation.handle_retirement = Some(KernfsHandleRetirement {
            handle_type: handle.handle_type,
            handle_bytes: handle.handle_bytes,
            handle_id: handle.id,
            mount_id,
            open_errno: libc::ESTALE,
        });
        return Ok(Some(observation));
    }
    // SAFETY: successful open_by_handle_at returned one new owned descriptor.
    let reopened = File::from(unsafe { OwnedFd::from_raw_fd(reopened) });
    let actual = reopened.metadata();
    let closed = crate::linux_checked_close(reopened.into());
    let actual = actual?;
    closed?;
    if !actual.is_dir() || (actual.dev(), actual.ino()) != (metadata.dev(), metadata.ino()) {
        return Err(io::Error::other("reopened cgroup handle identity differs"));
    }
    Ok(None)
}
