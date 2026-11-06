//! Native handle ownership for files consumed by current Windows tests.
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
pub struct HeldWindowsArtifact {
    pub bytes: Vec<u8>,
    pub sha256: String,
    _file: std::fs::File,
    _ancestors: Vec<std::fs::File>,
}

/// A borrowed catalog-selected source. Positive links are observations, not
/// exclusive ownership; only an independent strict destination is launched.
#[cfg(windows)]
pub struct HeldProviderSource {
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub metadata: crate::windows_provider_source_record::Metadata,
    path: std::path::PathBuf,
    file: std::fs::File,
    _ancestors: Vec<std::fs::File>,
}

#[cfg(windows)]
fn provider_live(work: std::time::Instant) -> crate::Result<()> {
    if std::time::Instant::now() >= work {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "borrowed provider original cutoff exhausted",
        )
        .into())
    } else {
        Ok(())
    }
}

#[cfg(windows)]
fn open_provider(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(windows)]
#[allow(unsafe_code)] // Query-only metadata of the already held borrowed provider.
fn provider_metadata(
    file: &std::fs::File,
) -> crate::Result<crate::windows_provider_source_record::Metadata> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns this live handle and info is a correctly sized output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let metadata = crate::windows_provider_source_record::Metadata {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
        bytes: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    };
    metadata.validate().map_err(crate::CiError::Message)?;
    Ok(metadata)
}

#[cfg(windows)]
fn read_provider(file: &std::fs::File, work: std::time::Instant) -> crate::Result<Vec<u8>> {
    use std::io::{Read, Seek};
    provider_live(work)?;
    let mut reader = file;
    reader.seek(std::io::SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        provider_live(work)?;
        let remaining = (crate::windows_provider_source_record::SOURCE_BYTES - bytes.len() as u64
            + 1)
        .min(chunk.len() as u64) as usize;
        let read = reader.read(&mut chunk[..remaining])?;
        provider_live(work)?;
        if read == 0 {
            break;
        }
        if bytes.len().checked_add(read).is_none_or(|length| {
            length as u64 > crate::windows_provider_source_record::SOURCE_BYTES
        }) {
            return Err(crate::CiError::Message(
                "borrowed provider byte bound exceeded".into(),
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    Ok(bytes)
}

#[cfg(windows)]
impl HeldProviderSource {
    pub fn hold(path: &Path, work: std::time::Instant) -> crate::Result<Self> {
        provider_live(work)?;
        if !path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
        {
            return Err(crate::CiError::Message(
                "borrowed provider requires exact absolute source".into(),
            ));
        }
        let ancestors =
            hold_ancestors(path.parent().ok_or_else(|| {
                crate::CiError::Message("borrowed provider parent absent".into())
            })?)?;
        provider_live(work)?;
        let file = open_provider(path)?;
        provider_live(work)?;
        let metadata = provider_metadata(&file)?;
        let bytes = read_provider(&file, work)?;
        provider_live(work)?;
        let sha256 = crate::windows_causal_acceptance::sha256(&bytes);
        provider_live(work)?;
        let held = Self {
            bytes,
            sha256,
            metadata,
            path: path.to_path_buf(),
            file,
            _ancestors: ancestors,
        };
        held.verify(work)?;
        Ok(held)
    }

    pub fn verify(&self, work: std::time::Instant) -> crate::Result<()> {
        provider_live(work)?;
        let named = open_provider(&self.path)?;
        provider_live(work)?;
        let named_metadata = provider_metadata(&named)?;
        let named_bytes = read_provider(&named, work)?;
        provider_live(work)?;
        self.metadata
            .verify(&named_metadata, &named_bytes, &self.sha256)
            .map_err(crate::CiError::Message)?;
        provider_live(work)?;
        let original_metadata = provider_metadata(&self.file)?;
        let original_bytes = read_provider(&self.file, work)?;
        provider_live(work)?;
        self.metadata
            .verify(&original_metadata, &original_bytes, &self.sha256)
            .map_err(crate::CiError::Message)?;
        if named_bytes != self.bytes || original_bytes != self.bytes {
            return Err(crate::CiError::Message(
                "borrowed provider exact held bytes differ".into(),
            ));
        }
        provider_live(work)?;
        if provider_metadata(&self.file)? != self.metadata {
            return Err(crate::CiError::Message(
                "borrowed provider held metadata changed after readback".into(),
            ));
        }
        provider_live(work)?;
        if provider_metadata(&named)? != self.metadata {
            return Err(crate::CiError::Message(
                "borrowed provider named metadata changed after readback".into(),
            ));
        }
        provider_live(work)
    }

    pub fn publish(
        &self,
        destination: &Path,
        work: std::time::Instant,
    ) -> crate::Result<HeldWindowsArtifact> {
        self.verify(work)?;
        let _parents = hold_ancestors(destination.parent().ok_or_else(|| {
            crate::CiError::Message("private provider destination parent absent".into())
        })?)?;
        provider_live(work)?;
        let _published = publish_owned_file(destination, &self.bytes)?;
        provider_live(work)?;
        let copied = hold_artifact(
            destination,
            Some(&self.sha256),
            crate::windows_provider_source_record::SOURCE_BYTES,
        )?;
        provider_live(work)?;
        let destination_identity = copied.identity(destination)?;
        if destination_identity == (self.metadata.volume_serial, self.metadata.file_index)
            || copied.bytes != self.bytes
        {
            return Err(crate::CiError::Message(
                "private provider is not an independent exact owned copy".into(),
            ));
        }
        self.verify(work)?;
        provider_live(work)?;
        verify_named_artifact(&copied, destination)?;
        provider_live(work)?;
        Ok(copied)
    }
}

#[cfg(windows)]
impl HeldWindowsArtifact {
    /// Declaration from the original live file and directory guards, never a
    /// later named-file snapshot. The caller keeps this owner through execution.
    pub fn private_fixture_binding(
        &self,
        path: &Path,
        local_directory: memcordon_platform::windows_private_fixture_binding::PrivateFixtureAncestor,
        output_ancestors: Vec<
            memcordon_platform::windows_private_fixture_binding::PrivateFixtureAncestor,
        >,
        work: std::time::Instant,
    ) -> crate::Result<memcordon_platform::windows_private_fixture_binding::PrivateFixtureBinding>
    {
        use memcordon_platform::{
            test_support::windows_held_file_metadata,
            windows_private_fixture_binding::{PrivateFixtureAncestor, PrivateFixtureBinding},
        };
        provider_live(work)?;
        let metadata = windows_held_file_metadata(&self._file)?;
        native_file_identity(&self._file, false, path)?;
        if metadata.length != self.bytes.len() as u64
            || crate::windows_causal_acceptance::sha256(&self.bytes) != self.sha256
        {
            return Err(crate::CiError::Message("held fixture bytes differ".into()));
        }
        let paths = path
            .parent()
            .ok_or_else(|| crate::CiError::Message("held fixture parent absent".into()))?
            .ancestors()
            .filter(|path| !path.as_os_str().is_empty())
            .collect::<Vec<_>>();
        if paths.len() != self._ancestors.len() || paths.len() > 64 {
            return Err(crate::CiError::Message(
                "held fixture ancestry extent differs".into(),
            ));
        }
        let mut ancestors = Vec::new();
        for (path, file) in paths.into_iter().rev().zip(&self._ancestors) {
            provider_live(work)?;
            let identity = native_file_identity(file, true, path)?;
            let metadata = windows_held_file_metadata(file)?;
            ancestors.push(PrivateFixtureAncestor {
                path: path.to_owned(),
                volume_serial: identity.0,
                file_index: identity.1,
                attributes: metadata.attributes,
            });
        }
        provider_live(work)?;
        let binding = PrivateFixtureBinding {
            revision: 2,
            fixture: path.to_owned(),
            volume_serial: metadata.volume_serial,
            file_index: metadata.file_index,
            attributes: metadata.attributes,
            links: metadata.links,
            bytes: metadata.length,
            sha256: self.sha256.clone(),
            native_path_utf16: self.native_path()?,
            ancestors,
            local_directory,
            output_ancestors,
        };
        provider_live(work)?;
        Ok(binding)
    }

    pub(crate) fn private_ancestor_files(&self) -> &[std::fs::File] {
        &self._ancestors
    }

    /// Query the same continuously held regular file, not a fresh path identity.
    pub fn identity(&self, path: &Path) -> std::io::Result<(u32, u64)> {
        native_file_identity(&self._file, false, path)
    }

    #[allow(unsafe_code)] // Bounded backing filename from this exact retained file handle.
    pub fn native_path(&self) -> std::io::Result<Vec<u16>> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_NT};
        let mut path = [0u16; 2048];
        // SAFETY: owned live handle, fixed writable buffer with exact capacity.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                self._file.as_raw_handle().cast(),
                path.as_mut_ptr(),
                path.len() as u32,
                VOLUME_NAME_NT,
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if length as usize >= path.len()
            || path[length as usize] != 0
            || path[..length as usize].contains(&0)
        {
            return Err(std::io::Error::other(
                "held private native backing path is truncated or malformed",
            ));
        }
        Ok(path[..length as usize].to_vec())
    }
}

/// Compare the named leaf and every retained directory to the original native
/// handles; equal bytes alone do not authorize replacement of a custody record.
#[cfg(windows)]
pub fn verify_named_artifact(held: &HeldWindowsArtifact, path: &Path) -> crate::Result<()> {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    let parent = path
        .parent()
        .ok_or_else(|| crate::CiError::Message("held artifact parent absent".into()))?;
    let ancestors = hold_ancestors(parent)?;
    if ancestors.len() != held._ancestors.len() {
        return Err(crate::CiError::Message(
            "held artifact ancestor count changed".into(),
        ));
    }
    let ancestor_paths: Vec<_> = parent
        .ancestors()
        .filter(|ancestor| !ancestor.as_os_str().is_empty())
        .collect();
    for ((before, current), ancestor) in held
        ._ancestors
        .iter()
        .zip(&ancestors)
        .zip(ancestor_paths.into_iter().rev())
    {
        if native_file_identity(before, true, ancestor)?
            != native_file_identity(current, true, ancestor)?
        {
            return Err(crate::CiError::Message(
                "held artifact named ancestor native identity changed".into(),
            ));
        }
    }
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut bytes = Vec::new();
    (&named)
        .take(held.bytes.len() as u64 + 1)
        .read_to_end(&mut bytes)?;
    if native_file_identity(&held._file, false, path)? != native_file_identity(&named, false, path)?
        || bytes != held.bytes
    {
        return Err(crate::CiError::Message(
            "held artifact named native identity or exact bytes changed".into(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn hold_artifact(
    path: &Path,
    expected: Option<&str>,
    maximum: u64,
) -> crate::Result<HeldWindowsArtifact> {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    if !path.is_absolute() || maximum > 512 * 1024 * 1024 {
        return Err(crate::CiError::Message(
            "Windows native artifact custody requires bounded absolute input".into(),
        ));
    }
    let ancestors = hold_ancestors(path.parent().ok_or_else(|| {
        crate::CiError::Message("Windows native artifact parent missing".into())
    })?)?;
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let identity = native_file_identity(&file, false, path)?;
    let mut bytes = Vec::new();
    (&file).take(maximum + 1).read_to_end(&mut bytes)?;
    let digest = crate::windows_causal_acceptance::sha256(&bytes);
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut named_bytes = Vec::new();
    (&named).take(maximum + 1).read_to_end(&mut named_bytes)?;
    if bytes.len() as u64 > maximum
        || file.metadata()?.len() != bytes.len() as u64
        || native_file_identity(&file, false, path)? != identity
        || native_file_identity(&named, false, path)? != identity
        || named_bytes != bytes
        || expected.is_some_and(|expected| expected != digest)
    {
        return Err(crate::CiError::Message(
            "Windows native artifact named custody or measured bytes differ".into(),
        ));
    }
    Ok(HeldWindowsArtifact {
        bytes,
        sha256: digest,
        _file: file,
        _ancestors: ancestors,
    })
}

/// Keep source file/ancestry custody live through synchronous publication.
#[cfg(windows)]
pub fn retain_captured_artifact(
    source: &Path,
    destination: &Path,
    maximum: u64,
) -> crate::Result<Vec<u8>> {
    let held = hold_artifact(source, None, maximum)?;
    drop(publish_owned_file(destination, &held.bytes)?);
    Ok(held.bytes)
}

#[cfg(windows)]
pub fn copy_owned_artifact(
    source: &Path,
    destination: &Path,
    expected: &str,
) -> crate::Result<HeldWindowsArtifact> {
    let source = hold_artifact(source, Some(expected), 512 * 1024 * 1024)?;
    let _ancestors = hold_ancestors(destination.parent().ok_or_else(|| {
        crate::CiError::Message("Windows owned artifact destination parent missing".into())
    })?)?;
    let _published = publish_owned_file(destination, &source.bytes)?;
    hold_artifact(destination, Some(expected), 512 * 1024 * 1024)
}

/// Materialize actual Cargo output into independent receipt custody. The held
/// source may have Cargo aliases; no alias becomes an authoritative image.
#[cfg(windows)]
pub fn copy_compiler_artifact(
    source: &Path,
    build_root: &Path,
    destination: &Path,
    expected: &str,
) -> crate::Result<HeldWindowsArtifact> {
    copy_compiler_artifact_bounded(source, build_root, destination, expected, 512 * 1024 * 1024)
}

#[cfg(windows)]
fn copy_compiler_artifact_bounded(
    source: &Path,
    build_root: &Path,
    destination: &Path,
    expected: &str,
    bound: u64,
) -> crate::Result<HeldWindowsArtifact> {
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};
    if !source.is_absolute()
        || !build_root.is_absolute()
        || !source.starts_with(build_root)
        || source == build_root
        || source
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
        || source.strip_prefix(build_root).is_ok_and(|relative| {
            relative
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        })
    {
        return Err(crate::CiError::Message(
            "compiler artifact crosses original build root".into(),
        ));
    }
    let _source_ancestors = hold_ancestors(
        source
            .parent()
            .ok_or_else(|| crate::CiError::Message("compiler source parent absent".into()))?,
    )?;
    let open = || {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(source)
    };
    let identity = |file: &std::fs::File| native_compiler_source_identity(file, source);
    let file = open()?;
    let before = identity(&file)?;
    if before.4 == 0 || before.4 > bound {
        return Err(crate::CiError::Message(
            "compiler source exceeds executable byte bound".into(),
        ));
    }
    let mut bytes = Vec::new();
    (&file).take(bound + 1).read_to_end(&mut bytes)?;
    let named = open()?;
    let mut named_bytes = Vec::new();
    (&named).take(bound + 1).read_to_end(&mut named_bytes)?;
    if before.4 != bytes.len() as u64
        || identity(&file)? != before
        || identity(&named)? != before
        || named_bytes != bytes
        || crate::windows_causal_acceptance::sha256(&bytes) != expected
    {
        return Err(crate::CiError::Message(
            "held compiler source identity, links or bytes changed".into(),
        ));
    }
    let _destination_ancestors =
        hold_ancestors(destination.parent().ok_or_else(|| {
            crate::CiError::Message("compiler destination parent absent".into())
        })?)?;
    let _published = publish_owned_file(destination, &bytes)?;
    let copied = hold_artifact(destination, Some(expected), bound)?;
    if identity(&file)? != before || identity(&named)? != before {
        return Err(crate::CiError::Message(
            "compiler source changed during independent publication".into(),
        ));
    }
    Ok(copied)
}
#[cfg(windows)]
#[allow(unsafe_code)] // Query-only metadata of the held compiler byte source.
fn native_compiler_source_identity(
    file: &std::fs::File,
    path: &Path,
) -> std::io::Result<(u32, u64, u32, u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: File owns the live handle and info is a correctly sized output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::windows_receipt_identity::validate_compiler_source(
        path,
        info.dwFileAttributes,
        info.nNumberOfLinks,
    )?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        info.dwFileAttributes,
        info.nNumberOfLinks,
        (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
    ))
}

#[cfg(windows)]
#[allow(unsafe_code)] // Query-only identity of an exact held native file handle.
pub(crate) fn native_file_identity(
    file: &std::fs::File,
    directory: bool,
    path: &Path,
) -> std::io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: held File owns the live handle and info is a correctly sized output.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    crate::windows_receipt_identity::validate(
        path,
        directory,
        info.dwFileAttributes,
        info.nNumberOfLinks,
    )?;
    Ok((
        info.dwVolumeSerialNumber,
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(windows)]
pub(crate) fn hold_ancestors(path: &Path) -> std::io::Result<Vec<std::fs::File>> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    if path.components().any(|part| {
        matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err(std::io::Error::other(
            "Windows receipt ancestry must be normalized",
        ));
    }
    let mut held = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(ancestor)?;
        native_file_identity(&file, true, ancestor)?;
        held.push(file);
    }
    Ok(held)
}

#[cfg(windows)]
#[allow(unsafe_code)] // Native checked same-directory WRITE_THROUGH publication.
pub(crate) fn publish_owned_file(path: &Path, bytes: &[u8]) -> std::io::Result<std::fs::File> {
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };
    let pending = path.with_extension("pending");
    let mut held = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&pending)?;
    held.write_all(bytes)?;
    held.sync_all()?;
    let identity = native_file_identity(&held, false, &pending)?;
    let source: Vec<_> = pending.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    if source[..source.len() - 1].contains(&0) || destination[..destination.len() - 1].contains(&0)
    {
        return Err(std::io::Error::other("Windows receipt path contains NUL"));
    }
    // SAFETY: terminated owned UTF16 paths; no overwrite flag, owned same directory.
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let named = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if native_file_identity(&held, false, path)? != identity
        || native_file_identity(&named, false, path)? != identity
    {
        return Err(std::io::Error::other(
            "Windows receipt named native identity differs",
        ));
    }
    let mut observed = Vec::new();
    (&named)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut observed)?;
    if observed != bytes {
        return Err(std::io::Error::other(
            "Windows receipt named native readback differs",
        ));
    }
    drop(held);
    let protected = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    if native_file_identity(&protected, false, path)? != identity {
        return Err(std::io::Error::other(
            "Windows protected receipt identity differs",
        ));
    }
    let mut protected_bytes = Vec::new();
    (&protected)
        .take(bytes.len() as u64 + 1)
        .read_to_end(&mut protected_bytes)?;
    if protected_bytes != bytes {
        return Err(std::io::Error::other(
            "Windows protected receipt readback differs",
        ));
    }
    Ok(protected)
}
