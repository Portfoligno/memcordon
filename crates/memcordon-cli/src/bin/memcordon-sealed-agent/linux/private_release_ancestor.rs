//! Protected installed executable ancestor-chain witness. Every component is
//! opened relative to the preceding pinned directory with O_NOFOLLOW; the
//! final object must match the retained package image descriptor.

use std::ffi::{CStr, CString};
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Component;

use serde::{Deserialize, Serialize};

pub(crate) const SELECTOR: &str = "private_tcp::elf_ancestor_and_identity_pinned";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtectedPathNodeV1 {
    component: String,
    device: u64,
    inode: u64,
    owner_uid: u32,
    mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProtectedAgentPathV1 {
    schema_version: u8,
    nodes: Vec<ProtectedPathNodeV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentPathPreservationV1 {
    schema_version: u8,
    before: ProtectedAgentPathV1,
    after: ProtectedAgentPathV1,
}

impl ProtectedAgentPathV1 {
    pub(crate) fn capture(
        package: &crate::package::VerifiedReleaseCandidatePackageLease,
    ) -> Result<Self, String> {
        let path = package.agent_installation_path();
        if !path.is_absolute() {
            return Err("MCSEALED-PRIVATE-RELEASE: installed agent path is not absolute".into());
        }
        let components: Vec<_> = path.components().collect();
        if components.len() < 3 || !matches!(components.first(), Some(Component::RootDir)) {
            return Err("MCSEALED-PRIVATE-RELEASE: installed agent ancestor chain differs".into());
        }
        let mut directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: open root: {error}"))?;
        let mut nodes = vec![node("/", &directory, true)?];
        for (index, component) in components.iter().enumerate().skip(1) {
            let Component::Normal(name) = component else {
                return Err("MCSEALED-PRIVATE-RELEASE: installed path component differs".into());
            };
            let name_bytes = name.as_bytes();
            let name_c = CString::new(name_bytes)
                .map_err(|_| "MCSEALED-PRIVATE-RELEASE: NUL in installed path")?;
            let is_directory = index + 1 != components.len();
            let flags = libc::O_RDONLY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if is_directory { libc::O_DIRECTORY } else { 0 };
            // SAFETY: directory is retained, name_c is one NUL-terminated
            // component and O_NOFOLLOW forbids a substituted symlink.
            let raw = unsafe { libc::openat(directory.as_raw_fd(), name_c.as_ptr(), flags) };
            if raw < 0 {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELEASE: open protected agent component: {}",
                    std::io::Error::last_os_error()
                ));
            }
            // SAFETY: successful openat returned one owned fd.
            let opened = unsafe { File::from_raw_fd(raw) };
            let label = name
                .to_str()
                .ok_or("MCSEALED-PRIVATE-RELEASE: non-UTF-8 installed path")?;
            nodes.push(node(label, &opened, is_directory)?);
            directory = opened;
        }
        let final_node = nodes
            .last()
            .ok_or("MCSEALED-PRIVATE-RELEASE: installed image node absent")?;
        let pinned = package.agent_file_identity()?;
        if (final_node.device, final_node.inode) != pinned {
            return Err(
                "MCSEALED-PRIVATE-RELEASE: installed image path differs from pinned fd".into(),
            );
        }
        Ok(Self {
            schema_version: 1,
            nodes,
        })
    }
}

impl AgentPathPreservationV1 {
    pub(crate) fn complete(
        before: ProtectedAgentPathV1,
        after: ProtectedAgentPathV1,
    ) -> Result<Self, String> {
        let proof = Self {
            schema_version: 1,
            before,
            after,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.before.schema_version != 1
            || self.after.schema_version != 1
            || self.before.nodes.len() < 3
            || self.before != self.after
        {
            return Err("MCSEALED-PRIVATE-RELEASE: protected ancestor chain changed".into());
        }
        Ok(())
    }

    pub(crate) fn verify_current(&self, current: &ProtectedAgentPathV1) -> Result<(), String> {
        self.validate()?;
        if &self.after != current {
            return Err("MCSEALED-PRIVATE-RELEASE: current ancestor chain changed".into());
        }
        Ok(())
    }
}

fn node(component: &str, file: &File, directory: bool) -> Result<ProtectedPathNodeV1, String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if (directory && !metadata.is_dir())
        || (!directory && !metadata.is_file())
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.dev() == 0
        || metadata.ino() == 0
        || (!directory
            && (metadata.nlink() != 1
                || metadata.mode() & (libc::S_ISUID | libc::S_ISGID) != 0
                || metadata.mode() & 0o111 == 0))
    {
        return Err("MCSEALED-PRIVATE-RELEASE: protected path node differs".into());
    }
    reject_xattr(file, c"system.posix_acl_access")?;
    if directory {
        reject_xattr(file, c"system.posix_acl_default")?;
    } else {
        reject_xattr(file, c"security.capability")?;
    }
    Ok(ProtectedPathNodeV1 {
        component: component.into(),
        device: metadata.dev(),
        inode: metadata.ino(),
        owner_uid: metadata.uid(),
        mode: metadata.mode(),
    })
}

fn reject_xattr(file: &File, name: &CStr) -> Result<(), String> {
    // SAFETY: file is live and name is NUL terminated; a null output buffer
    // queries presence without reading or changing the attribute.
    let status =
        unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if status >= 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: forbidden path xattr present".into());
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(code) if code == libc::ENODATA || code == libc::ENOTSUP => Ok(()),
        _ => Err("MCSEALED-PRIVATE-RELEASE: protected path xattr readback failed".into()),
    }
}
