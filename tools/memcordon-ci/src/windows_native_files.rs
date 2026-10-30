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
fn hold_ancestors(path: &Path) -> std::io::Result<Vec<std::fs::File>> {
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
