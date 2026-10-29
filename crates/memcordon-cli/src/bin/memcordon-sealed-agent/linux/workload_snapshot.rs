//! Fresh per-attempt snapshot custody. No installed-image store or administrator references.
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_bundle::{ImageEntryV1, SnapshotManifestV1};
use memcordon_core::workload_files::RootRelativePath;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};
use std::os::unix::fs::MetadataExt;

pub struct HeldSnapshot {
    manifest: SnapshotManifestV1,
    digest: DiagnosticSha256,
    root: File,
    root_identity: (u64, u64),
    objects: BTreeMap<RootRelativePath, File>,
    validation_cutoff: std::time::Instant,
}

impl HeldSnapshot {
    pub fn from_received_snapshot(
        manifest: SnapshotManifestV1,
        root: File,
        validation_cutoff: std::time::Instant,
    ) -> Result<Self, String> {
        manifest.validate()?;
        protected_directory(&root)?;
        let metadata = root.metadata().map_err(io)?;
        let digest = manifest.digest()?;
        let mut objects = BTreeMap::new();
        for entry in manifest.entries.as_slice() {
            if matches!(entry, ImageEntryV1::Regular { .. }) {
                let file = open_relative(root.as_fd(), entry.path(), false)?;
                verify_regular_until(&file, entry, true, validation_cutoff)?;
                objects.insert(entry.path().clone(), file);
            }
        }
        let value = Self {
            manifest,
            digest,
            root,
            root_identity: (metadata.dev(), metadata.ino()),
            objects,
            validation_cutoff,
        };
        value.revalidate()?;
        Ok(value)
    }

    pub fn definition(&self) -> &SnapshotManifestV1 {
        &self.manifest
    }
    pub fn digest(&self) -> &DiagnosticSha256 {
        &self.digest
    }
    pub fn validation_cutoff(&self) -> std::time::Instant {
        self.validation_cutoff
    }
    pub fn object(&self, path: &RootRelativePath) -> Result<BorrowedFd<'_>, String> {
        self.objects
            .get(path)
            .map(AsFd::as_fd)
            .ok_or_else(|| "snapshot regular member absent".into())
    }
    pub fn revalidate(&self) -> Result<(), String> {
        check_validation_cutoff(self.validation_cutoff)?;
        protected_directory(&self.root)?;
        let metadata = self.root.metadata().map_err(io)?;
        if (metadata.dev(), metadata.ino()) != self.root_identity
            || self.manifest.digest()? != self.digest
        {
            return Err("held snapshot root or manifest changed".into());
        }
        for entry in self.manifest.entries.as_slice() {
            check_validation_cutoff(self.validation_cutoff)?;
            match entry {
                ImageEntryV1::Regular { path, .. } => {
                    let held = self
                        .objects
                        .get(path)
                        .ok_or("snapshot member pin missing")?;
                    let named = open_relative(self.root.as_fd(), path, false)?;
                    verify_regular_until(held, entry, true, self.validation_cutoff)?;
                    verify_regular_until(&named, entry, true, self.validation_cutoff)?;
                    let a = held.metadata().map_err(io)?;
                    let b = named.metadata().map_err(io)?;
                    if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                        return Err("snapshot named member replaced".into());
                    }
                }
                ImageEntryV1::Symlink { path, target } => {
                    let (parent, name) = parent_at(self.root.as_fd(), path, false)?;
                    let mut bytes = vec![0_u8; 4096];
                    // SAFETY: initialized output buffer and held parent descriptor.
                    let count = unsafe {
                        libc::readlinkat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            bytes.as_mut_ptr().cast(),
                            bytes.len(),
                        )
                    };
                    if count < 0 {
                        return Err(io(std::io::Error::last_os_error()));
                    }
                    bytes.truncate(usize::try_from(count).map_err(|_| "link length invalid")?);
                    use std::os::unix::ffi::OsStrExt;
                    if bytes != relative_link(path, target).as_os_str().as_bytes() {
                        return Err("snapshot symlink changed".into());
                    }
                }
            }
        }
        Ok(())
    }
}

use std::path::{Path, PathBuf};
fn io(error: std::io::Error) -> String {
    error.to_string()
}
fn cstr(text: &str) -> Result<CString, String> {
    CString::new(text).map_err(|_| "native path contains NUL".into())
}
fn native(raw: i32) -> Result<File, String> {
    if raw < 0 {
        Err(io(std::io::Error::last_os_error()))
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

pub(crate) fn directory_at(
    parent: BorrowedFd<'_>,
    name: &str,
    create: bool,
) -> Result<File, String> {
    let name = cstr(name)?;
    if create && unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(io(error));
        }
    }
    native(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })
}

pub(crate) fn parent_at(
    root: BorrowedFd<'_>,
    path: &RootRelativePath,
    create: bool,
) -> Result<(File, CString), String> {
    let mut components = path.as_str().split('/').peekable();
    let mut parent = native(unsafe { libc::fcntl(root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
    while let Some(component) = components.next() {
        if components.peek().is_none() {
            return Ok((parent, cstr(component)?));
        }
        parent = directory_at(parent.as_fd(), component, create)?;
    }
    Err("empty image path".into())
}

pub(crate) fn open_relative(
    root: BorrowedFd<'_>,
    path: &RootRelativePath,
    create: bool,
) -> Result<File, String> {
    let (parent, name) = parent_at(root, path, create)?;
    let flags = if create {
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
    } else {
        libc::O_RDONLY
    };
    native(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    })
}

pub(crate) fn protected_directory(directory: &File) -> Result<(), String> {
    let metadata = directory.metadata().map_err(io)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err("image directory is not root-owned protected custody".into());
    }
    Ok(())
}

fn no_file_capability(file: &File) -> Result<(), String> {
    let name = c"security.capability";
    let size = unsafe { libc::fgetxattr(file.as_raw_fd(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size >= 0 {
        return Err("image file has capability metadata".into());
    }
    let error = std::io::Error::last_os_error();
    if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::ENOTSUP)) {
        Ok(())
    } else {
        Err(io(error))
    }
}

pub(crate) fn check_validation_cutoff(cutoff: std::time::Instant) -> Result<(), String> {
    if std::time::Instant::now() >= cutoff {
        Err("original snapshot validation cutoff exhausted".into())
    } else {
        Ok(())
    }
}
pub(crate) fn verify_regular_until(
    file: &File,
    entry: &ImageEntryV1,
    protected: bool,
    cutoff: std::time::Instant,
) -> Result<(), String> {
    check_validation_cutoff(cutoff)?;
    let ImageEntryV1::Regular {
        sha256,
        size,
        executable,
        ..
    } = entry
    else {
        return Err("regular object expected".into());
    };
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() != *size
        || metadata.mode() & 0o6000 != 0
        || (*executable && metadata.mode() & 0o111 == 0)
        || (protected && (metadata.uid() != 0 || metadata.mode() & 0o222 != 0))
    {
        return Err("image member type/size/mode/alias differs".into());
    }
    no_file_capability(file)?;
    let mut hash = Sha256::new();
    let mut offset = 0_u64;
    let mut bytes = [0_u8; 64 * 1024];
    use std::os::unix::fs::FileExt;
    loop {
        check_validation_cutoff(cutoff)?;
        let count = file.read_at(&mut bytes, offset).map_err(io)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| "image byte count exceeds u64")?)
            .ok_or("image byte count overflow")?;
        if offset > *size {
            return Err("image grew during verification".into());
        }
        hash.update(&bytes[..count]);
    }
    if offset != *size || DiagnosticSha256::from_bytes(hash.finalize().into()) != *sha256 {
        return Err("image content digest differs".into());
    }
    Ok(())
}

fn relative_link(path: &RootRelativePath, target: &RootRelativePath) -> PathBuf {
    let parent = Path::new(path.as_str())
        .parent()
        .expect("relative path has parent");
    let mut result = PathBuf::new();
    for _ in parent.components() {
        result.push("..");
    }
    result.push(target.as_str());
    result
}
