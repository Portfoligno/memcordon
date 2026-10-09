use crate::{Artifact, MAX_ARTIFACT_BYTES, VerificationResult, sha256};
use std::collections::BTreeMap;
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path};

pub(crate) struct Custody {
    bytes: BTreeMap<String, Vec<u8>>,
    hashes: BTreeMap<String, String>,
}

impl Custody {
    pub(crate) fn new(root: &Path, artifacts: &[Artifact]) -> VerificationResult<Self> {
        let mut bytes = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        let mut total = 0u64;
        for artifact in artifacts {
            validate_path(&artifact.path)?;
            if bytes.contains_key(&artifact.path) {
                return Err("duplicate evidence artifact path".into());
            }
            if artifact.length > MAX_ARTIFACT_BYTES {
                return Err("artifact exceeds per-file bound".into());
            }
            total = total
                .checked_add(artifact.length)
                .ok_or("artifact total overflow")?;
            if total > 4 * 1024 * 1024 * 1024 {
                return Err("artifact total exceeds bounded evidence index".into());
            }
            let collected = read_confined(root, &artifact.path, artifact.length)?;
            let hash = sha256(&collected);
            if collected.len() as u64 != artifact.length || hash != artifact.sha256 {
                return Err(format!(
                    "persisted artifact custody differs: {}",
                    artifact.path
                ));
            }
            hashes.insert(artifact.path.clone(), hash);
            bytes.insert(artifact.path.clone(), collected);
        }
        Ok(Self { bytes, hashes })
    }
    pub(crate) fn bytes(&self, path: &str) -> VerificationResult<&[u8]> {
        validate_path(path)?;
        self.bytes
            .get(path)
            .map(Vec::as_slice)
            .ok_or_else(|| format!("artifact not bound in evidence index: {path}"))
    }
    pub(crate) fn hash(&self, path: &str) -> VerificationResult<&str> {
        validate_path(path)?;
        self.hashes
            .get(path)
            .map(String::as_str)
            .ok_or_else(|| format!("artifact digest not bound in evidence index: {path}"))
    }
}

pub fn validate_path(path: &str) -> VerificationResult<()> {
    if path.is_empty()
        || path.len() > 1024
        || path.contains('\\')
        || path.contains(':')
        || path.contains('\0')
        || path.starts_with('/')
        || path.ends_with('/')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || !Path::new(path)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
    {
        return Err("artifact reference is not a finite relative ordinary path".into());
    }
    Ok(())
}

fn bounded_read(mut file: File, limit: u64) -> VerificationResult<Vec<u8>> {
    let before = file.metadata().map_err(|e| e.to_string())?;
    if !before.is_file() || before.len() > limit {
        return Err("evidence is not a bounded regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.nlink() != 1 {
            return Err("hard-linked evidence is not exclusive collected custody".into());
        }
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit
        || before.len() != after.len()
        || before.len() != bytes.len() as u64
        || before.modified().map_err(|e| e.to_string())?
            != after.modified().map_err(|e| e.to_string())?
    {
        return Err("evidence changed during bounded collection".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return Err("native evidence identity changed during collection".into());
        }
    }
    Ok(bytes)
}

#[cfg(unix)]
fn read_confined(root: &Path, relative: &str, limit: u64) -> VerificationResult<Vec<u8>> {
    use rustix::fs::{Mode, OFlags, open, openat};
    let mut ancestors = vec![File::from(
        open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    )];
    let parts: Vec<_> = relative.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        let child = openat(
            ancestors.last().ok_or("held ancestor absent")?,
            *part,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?;
        ancestors.push(File::from(child));
    }
    let parent = ancestors.last().ok_or("held parent absent")?;
    let file = openat(
        parent,
        parts[parts.len() - 1],
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| e.to_string())?;
    use std::os::unix::fs::MetadataExt;
    let file = File::from(file);
    let expected = file.metadata().map_err(|e| e.to_string())?;
    let bytes = bounded_read(file.try_clone().map_err(|e| e.to_string())?, limit)?;
    let named = File::from(
        openat(
            parent,
            parts[parts.len() - 1],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    let current = named.metadata().map_err(|e| e.to_string())?;
    if !current.is_file()
        || current.nlink() != 1
        || (current.dev(), current.ino()) != (expected.dev(), expected.ino())
    {
        return Err("persisted named evidence was replaced/unlinked during collection".into());
    }
    if bounded_read(named, limit)? != bytes {
        return Err("persisted named evidence readback differs".into());
    }
    let mut current = File::from(
        open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    for (index, held) in ancestors.iter().enumerate() {
        let expected = held.metadata().map_err(|e| e.to_string())?;
        let observed = current.metadata().map_err(|e| e.to_string())?;
        if (expected.dev(), expected.ino()) != (observed.dev(), observed.ino()) {
            return Err("named evidence ancestor detached or replaced".into());
        }
        if index < parts.len() - 1 {
            current = File::from(
                openat(
                    &current,
                    parts[index],
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| e.to_string())?,
            );
        }
    }
    let final_named = File::from(
        openat(
            &current,
            parts[parts.len() - 1],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    let final_identity = final_named.metadata().map_err(|e| e.to_string())?;
    if (expected.dev(), expected.ino()) != (final_identity.dev(), final_identity.ino())
        || bounded_read(final_named, limit)? != bytes
    {
        return Err("bundle-root named evidence identity/readback differs".into());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn read_confined(root: &Path, relative: &str, limit: u64) -> VerificationResult<Vec<u8>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    };
    let identity = |file: &File| -> VerificationResult<(u32, u32, u32)> {
        let mut information = std::mem::MaybeUninit::<
            windows_sys::Win32::Storage::FileSystem::BY_HANDLE_FILE_INFORMATION,
        >::zeroed();
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::GetFileInformationByHandle(
                file.as_raw_handle().cast(),
                information.as_mut_ptr(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let information = unsafe { information.assume_init() };
        if information.nNumberOfLinks != 1 {
            return Err("hard-linked Windows evidence lacks exclusive named custody".into());
        }
        Ok((
            information.dwVolumeSerialNumber,
            information.nFileIndexHigh,
            information.nFileIndexLow,
        ))
    };
    let mut held = Vec::new();
    let mut current = root.to_path_buf();
    let parts: Vec<_> = relative.split('/').collect();
    for part in std::iter::once(None).chain(parts[..parts.len() - 1].iter().map(|p| Some(*p))) {
        if let Some(part) = part {
            current.push(part);
        }
        let directory = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&current)
            .map_err(|e| e.to_string())?;
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("evidence ancestor is not a held ordinary directory".into());
        }
        held.push(directory);
    }
    current.push(parts[parts.len() - 1]);
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|e| e.to_string())?;
    if file
        .metadata()
        .map_err(|e| e.to_string())?
        .file_attributes()
        & FILE_ATTRIBUTE_REPARSE_POINT
        != 0
    {
        return Err("reparse evidence is forbidden".into());
    }
    let expected = identity(&file)?;
    let bytes = bounded_read(file.try_clone().map_err(|e| e.to_string())?, limit)?;
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|e| e.to_string())?;
    if identity(&named)? != expected
        || named
            .metadata()
            .map_err(|e| e.to_string())?
            .file_attributes()
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || bounded_read(named, limit)? != bytes
    {
        return Err("Windows named evidence identity/readback differs".into());
    }
    drop(file);
    drop(held);
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn read_confined(_: &Path, _: &str, _: u64) -> VerificationResult<Vec<u8>> {
    Err("native file custody unavailable on this host".into())
}

pub(crate) fn read_external(path: &Path, limit: u64) -> VerificationResult<Vec<u8>> {
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    let parent = absolute.parent().ok_or("file has no parent")?;
    let name = absolute
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("external metadata filename is not UTF-8")?;
    // Manifest/index are externally trusted selections, but their final member
    // still cannot be a link/reparse object or change while being decoded.
    read_confined(parent, name, limit)
}

pub(crate) fn executable_target(bytes: &[u8], target: &str) -> VerificationResult<()> {
    if target.ends_with("linux-gnu") {
        if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
            return Err("selected executable is not native 64-bit little-endian ELF".into());
        }
        let machine = u16::from_le_bytes([bytes[18], bytes[19]]);
        let required = if target.starts_with("x86_64-") {
            62
        } else {
            183
        };
        if machine != required {
            return Err("ELF executable architecture differs".into());
        }
    } else {
        if bytes.len() < 64 || &bytes[..2] != b"MZ" {
            return Err("selected executable is not a PE image".into());
        }
        let pe = u32::from_le_bytes(
            bytes[60..64]
                .try_into()
                .map_err(|_| "truncated PE offset")?,
        ) as usize;
        let header = bytes
            .get(pe..pe.checked_add(26).ok_or("PE offset overflow")?)
            .ok_or("truncated PE header")?;
        if &header[..4] != b"PE\0\0" {
            return Err("invalid PE signature".into());
        }
        let machine = u16::from_le_bytes([header[4], header[5]]);
        let required = if target.starts_with("x86_64-") {
            0x8664
        } else {
            0xaa64
        };
        if machine != required || u16::from_le_bytes([header[24], header[25]]) != 0x20b {
            return Err("PE executable architecture/optional header differs".into());
        }
    }
    Ok(())
}
