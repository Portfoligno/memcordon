use crate::{Artifact, MAX_ARTIFACT_BYTES, MAX_PRODUCER_BYTES, ProducerOrigin, VerificationResult};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::io::{Read, Seek};
use std::path::{Component, Path, PathBuf};

pub(crate) struct Custody {
    bytes: BTreeMap<String, std::sync::Arc<[u8]>>,
    hashes: BTreeMap<String, String>,
    archives: BTreeMap<String, Collected>,
    root: PathBuf,
}

impl Custody {
    pub(crate) fn for_storage(
        root: &Path,
        artifacts: &[Artifact],
        origins: &[ProducerOrigin],
        plan: &crate::storage::StoragePlan,
        metadata_bytes: u64,
    ) -> VerificationResult<Self> {
        plan.check_budget(metadata_bytes)?;
        plan.validate_directory(root)?;
        let physical: Vec<_> = plan.physical_artifacts().cloned().collect();
        let mut held = Self::for_evidence(root, &physical, origins)?;
        let mut bytes = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        for logical in artifacts {
            let object = plan.resolve(&logical.path)?;
            if logical.length != object.length || logical.sha256 != object.sha256 {
                return Err("logical evidence differs from held storage object".into());
            }
            hashes.insert(logical.path.clone(), logical.sha256.clone());
            if let Some(value) = held.bytes.get(&object.path) {
                bytes.insert(logical.path.clone(), value.clone());
            }
        }
        held.bytes = bytes;
        held.hashes = hashes;
        Ok(held)
    }
    pub(crate) fn new(root: &Path, artifacts: &[Artifact]) -> VerificationResult<Self> {
        Self::for_evidence(root, artifacts, &[])
    }
    pub(crate) fn for_evidence(
        root: &Path,
        artifacts: &[Artifact],
        origins: &[ProducerOrigin],
    ) -> VerificationResult<Self> {
        Self::with_limits(
            root,
            artifacts,
            origins,
            MAX_ARTIFACT_BYTES,
            MAX_PRODUCER_BYTES,
        )
    }
    fn with_limits(
        root: &Path,
        artifacts: &[Artifact],
        origins: &[ProducerOrigin],
        raw_limit: u64,
        total_limit: u64,
    ) -> VerificationResult<Self> {
        let mut archive_names = BTreeSet::new();
        for origin in origins {
            validate_path(&origin.bundle_artifact)?;
            if !archive_names.insert(origin.bundle_artifact.as_str()) {
                return Err("duplicate producer archive custody role".into());
            }
            let mut matches = artifacts
                .iter()
                .filter(|artifact| artifact.path == origin.bundle_artifact);
            let artifact = matches
                .next()
                .ok_or("producer archive lacks indexed custody")?;
            if matches.next().is_some() {
                return Err("producer archive role digest/index differs".into());
            }
            if artifact.sha256 != origin.artifact_sha256 {
                return Err("actual downloaded producer archive digest differs".into());
            }
        }
        let mut bytes = BTreeMap::new();
        let mut hashes = BTreeMap::new();
        let mut archives = BTreeMap::new();
        let mut total = 0u64;
        for artifact in artifacts {
            validate_path(&artifact.path)?;
            if hashes.contains_key(&artifact.path) {
                return Err("duplicate evidence artifact path".into());
            }
            let archive = archive_names.contains(artifact.path.as_str());
            if artifact.length > if archive { total_limit } else { raw_limit } {
                return Err("artifact exceeds per-file bound".into());
            }
            total = total
                .checked_add(artifact.length)
                .ok_or("artifact total overflow")?;
            if total > total_limit {
                return Err("artifact total exceeds bounded evidence index".into());
            }
            let collected = collect_confined(root, &artifact.path, artifact.length, !archive)?;
            if collected.length != artifact.length || collected.hash != artifact.sha256 {
                return Err(format!(
                    "persisted artifact custody differs: {}",
                    artifact.path
                ));
            }
            hashes.insert(artifact.path.clone(), collected.hash.clone());
            if archive {
                archives.insert(artifact.path.clone(), collected);
            } else {
                bytes.insert(
                    artifact.path.clone(),
                    std::sync::Arc::from(collected.bytes.ok_or("raw artifact buffer absent")?),
                );
            }
        }
        Ok(Self {
            bytes,
            hashes,
            archives,
            root: root.into(),
        })
    }
    pub(crate) fn archive(&self, path: &str) -> VerificationResult<File> {
        validate_path(path)?;
        let held = self
            .archives
            .get(path)
            .ok_or("archive is not a declared producer origin")?;
        let collected = bounded_collect(
            held.file.try_clone().map_err(|e| e.to_string())?,
            held.length,
            false,
        )?;
        if collected != *held {
            return Err("held producer archive changed after collection".into());
        }
        if collect_confined(&self.root, path, held.length, false)? != *held {
            return Err("named producer archive changed after collection".into());
        }
        let mut file = collected.file;
        file.rewind().map_err(|e| e.to_string())?;
        Ok(file)
    }
    pub(crate) fn bytes(&self, path: &str) -> VerificationResult<&[u8]> {
        validate_path(path)?;
        self.bytes
            .get(path)
            .map(|bytes| bytes.as_ref())
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

#[cfg(test)]
#[path = "../tests/private/archive_custody.rs"]
mod archive_tests;

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

/// Exclusively publish one physical member, then independently collect its named bytes.
pub(crate) fn retain_bytes(
    root: &Path,
    artifact: &Artifact,
    bytes: &[u8],
    existing: bool,
) -> VerificationResult<()> {
    validate_path(&artifact.path)?;
    if bytes.len() as u64 != artifact.length || crate::sha256(bytes) != artifact.sha256 {
        return Err("retained evidence differs from actual capture".into());
    }
    if !existing {
        write_confined(root, &artifact.path, bytes)?;
    }
    let held = collect_confined(root, &artifact.path, artifact.length, true)?;
    if held.length != artifact.length
        || held.hash != artifact.sha256
        || held.bytes.as_deref() != Some(bytes)
    {
        return Err("equal evidence digest key has unequal retained bytes".into());
    }
    Ok(())
}

#[cfg(unix)]
fn write_confined(root: &Path, relative: &str, bytes: &[u8]) -> VerificationResult<()> {
    use rustix::fs::{Mode, OFlags, mkdirat, open, openat};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    let mut parents = vec![File::from(
        open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    )];
    let parts: Vec<_> = relative.split('/').collect();
    for part in &parts[..parts.len() - 1] {
        let parent = parents.last().ok_or("held publication parent absent")?;
        match mkdirat(parent, *part, Mode::from_bits_truncate(0o755)) {
            Ok(()) => (),
            Err(rustix::io::Errno::EXIST) => (),
            Err(e) => return Err(e.to_string()),
        }
        parents.push(File::from(
            openat(
                parent,
                *part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|e| e.to_string())?,
        ));
    }
    let parent = parents.last().ok_or("held publication parent absent")?;
    let mut file = File::from(
        openat(
            parent,
            parts[parts.len() - 1],
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::from_bits_truncate(0o644),
        )
        .map_err(|e| e.to_string())?,
    );
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    parent.sync_all().map_err(|e| e.to_string())?;
    let named = File::from(
        openat(
            parent,
            parts[parts.len() - 1],
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| e.to_string())?,
    );
    let original = file.metadata().map_err(|e| e.to_string())?;
    let current = named.metadata().map_err(|e| e.to_string())?;
    if original.nlink() != 1 || (original.dev(), original.ino()) != (current.dev(), current.ino()) {
        return Err("new evidence member named identity changed".into());
    }
    let collected = collect_confined(root, relative, bytes.len() as u64, false)?;
    if collected.identity != (original.dev(), original.ino()) {
        return Err("new evidence publication ancestor changed".into());
    }
    Ok(())
}

#[cfg(windows)]
fn write_confined(root: &Path, relative: &str, bytes: &[u8]) -> VerificationResult<()> {
    use std::io::Write;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
    };
    let mut parents = Vec::new();
    let mut current = root.to_path_buf();
    let parts: Vec<_> = relative.split('/').collect();
    for part in std::iter::once(None).chain(parts[..parts.len() - 1].iter().map(|p| Some(*p))) {
        if let Some(part) = part {
            current.push(part);
            match std::fs::create_dir(&current) {
                Ok(()) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.to_string()),
            }
        }
        let directory = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&current)
            .map_err(|e| e.to_string())?;
        let metadata = directory.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("publication ancestor is not held ordinary directory".into());
        }
        parents.push(directory);
    }
    current.push(parts[parts.len() - 1]);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&current)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    let identity = windows_identity(&file)?;
    drop(file);
    if collect_confined(root, relative, bytes.len() as u64, false)?.identity != identity {
        return Err("new evidence member named identity changed".into());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_confined(_: &Path, _: &str, _: &[u8]) -> VerificationResult<()> {
    Err("native evidence custody unavailable on this host".into())
}

struct Collected {
    file: File,
    bytes: Option<Vec<u8>>,
    hash: String,
    length: u64,
    #[cfg(unix)]
    identity: (u64, u64),
    #[cfg(windows)]
    identity: (u32, u32, u32),
}

impl PartialEq for Collected {
    fn eq(&self, other: &Self) -> bool {
        #[cfg(any(unix, windows))]
        if self.identity != other.identity {
            return false;
        }
        self.length == other.length && self.hash == other.hash && self.bytes == other.bytes
    }
}

fn bounded_collect(mut file: File, limit: u64, buffered: bool) -> VerificationResult<Collected> {
    file.rewind().map_err(|e| e.to_string())?;
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
    let mut bytes = buffered.then(Vec::new);
    let mut digest = Sha256::new();
    let mut length = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let remaining = limit
            .checked_sub(length)
            .ok_or("evidence exceeds collection limit")?;
        let capacity = usize::try_from(remaining.min(buffer.len() as u64 - 1) + 1)
            .map_err(|e| e.to_string())?;
        let count = file
            .read(&mut buffer[..capacity])
            .map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(count as u64)
            .ok_or("evidence length overflow")?;
        if length > limit {
            return Err("evidence exceeds collection limit".into());
        }
        digest.update(&buffer[..count]);
        if let Some(bytes) = &mut bytes {
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    let after = file.metadata().map_err(|e| e.to_string())?;
    if length > limit
        || before.len() != after.len()
        || before.len() != length
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
    #[cfg(windows)]
    let identity = windows_identity(&file)?;
    Ok(Collected {
        file,
        bytes,
        hash: hex::encode(digest.finalize()),
        length,
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (before.dev(), before.ino())
        },
        #[cfg(windows)]
        identity,
    })
}

#[cfg(windows)]
fn windows_identity(file: &File) -> VerificationResult<(u32, u32, u32)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), information.as_mut_ptr()) }
        == 0
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
}

#[cfg(unix)]
fn collect_confined(
    root: &Path,
    relative: &str,
    limit: u64,
    buffered: bool,
) -> VerificationResult<Collected> {
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
    let bytes = bounded_collect(
        file.try_clone().map_err(|e| e.to_string())?,
        limit,
        buffered,
    )?;
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
    if bounded_collect(named, limit, buffered)? != bytes {
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
        || bounded_collect(final_named, limit, buffered)? != bytes
    {
        return Err("bundle-root named evidence identity/readback differs".into());
    }
    Ok(bytes)
}

#[cfg(windows)]
fn collect_confined(
    root: &Path,
    relative: &str,
    limit: u64,
    buffered: bool,
) -> VerificationResult<Collected> {
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
    let bytes = bounded_collect(
        file.try_clone().map_err(|e| e.to_string())?,
        limit,
        buffered,
    )?;
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
        || bounded_collect(named, limit, buffered)? != bytes
    {
        return Err("Windows named evidence identity/readback differs".into());
    }
    drop(file);
    drop(held);
    Ok(bytes)
}

#[cfg(not(any(unix, windows)))]
fn collect_confined(_: &Path, _: &str, _: u64, _: bool) -> VerificationResult<Collected> {
    Err("native file custody unavailable on this host".into())
}

fn read_confined(root: &Path, relative: &str, limit: u64) -> VerificationResult<Vec<u8>> {
    collect_confined(root, relative, limit, true)?
        .bytes
        .ok_or("external evidence buffer absent".into())
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
