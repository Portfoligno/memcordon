//! Same held-directory facts used by the measurement producer and broker.
use super::{Directory, DirectoryRole};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::{Component, Path},
    time::Instant,
};
use windows_sys::Win32::{
    Security::GetKernelObjectSecurity,
    Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};

fn live(cutoff: Instant) -> io::Result<()> {
    if Instant::now() >= cutoff {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original matched directory cutoff expired",
        ));
    }
    Ok(())
}

#[allow(unsafe_code)] // One bounded query of this already owned native file handle.
fn security_extent(file: &File, storage: &mut [u64; 1024]) -> io::Result<u32> {
    let capacity = u32::try_from(std::mem::size_of_val(storage)).map_err(io::Error::other)?;
    let mut required = 0;
    // SAFETY: File owns the live handle, the aligned array covers capacity bytes,
    // and required is a writable native output for this synchronous query.
    if unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle(),
            23,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut required,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(required)
}

#[allow(unsafe_code)] // One disposition on the caller's identity-checked held leaf.
fn mark_empty_directory(file: &File) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: File owns the live handle; the fixed native input remains valid
    // throughout the synchronous call. The OS rejects a nonempty directory.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[allow(unsafe_code)] // Consume exactly one owned handle only on observed native close success.
fn close_file(file: File) -> Result<(), (io::Error, File)> {
    // SAFETY: File exclusively owns this live handle. Success is followed by
    // forget so Rust cannot close it again; failure returns the original owner.
    if unsafe { windows_sys::Win32::Foundation::CloseHandle(file.as_raw_handle()) } == 0 {
        return Err((io::Error::last_os_error(), file));
    }
    std::mem::forget(file);
    Ok(())
}

pub fn hold_chain(path: &Path, cutoff: Instant) -> io::Result<Vec<File>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
        || path.as_os_str().to_string_lossy().contains('\0')
    {
        return Err(io::Error::other(
            "matched directory path is not an absolute native input",
        ));
    }
    let mut paths: Vec<_> = path.ancestors().collect();
    if paths.len() > 64 {
        return Err(io::Error::other("matched directory ancestry exceeds64"));
    }
    paths.reverse();
    let mut held = Vec::with_capacity(paths.len());
    for directory in paths {
        live(cutoff)?;
        let file = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | 0x20000)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)?;
        live(cutoff)?;
        let info = memcordon_platform::test_support::windows_held_file_metadata(&file)?;
        live(cutoff)?;
        if info.attributes & 0x10 == 0 || info.attributes & (0x400 | 0x40) != 0 {
            return Err(io::Error::other(
                "matched directory ancestor is reparse, device or not a directory",
            ));
        }
        held.push(file);
    }
    Ok(held)
}

pub fn observe_directory(
    role: DirectoryRole,
    path: &Path,
    file: &File,
    cutoff: Instant,
) -> io::Result<Directory> {
    live(cutoff)?;
    let info = memcordon_platform::test_support::windows_held_file_metadata(file)?;
    live(cutoff)?;
    if info.attributes & 0x10 == 0 || info.attributes & (0x400 | 0x40) != 0 {
        return Err(io::Error::other(
            "matched directory witness is not an ordinary directory",
        ));
    }
    let mut storage = [0u64; 1024];
    let required = security_extent(file, &mut storage)?;
    live(cutoff)?;
    if required == 0 || required as usize > std::mem::size_of_val(&storage) {
        return Err(io::Error::other(
            "matched directory security extent is unavailable or oversized",
        ));
    }
    let bytes: Vec<u8> = storage
        .iter()
        .flat_map(|word| word.to_ne_bytes())
        .take(required as usize)
        .collect();
    use sha2::{Digest, Sha256};
    let security_sha256 = Sha256::digest(&bytes).into();
    live(cutoff)?;
    Ok(Directory {
        role,
        path: path.to_owned(),
        volume_serial: u64::from(info.volume_serial),
        file_index: info.file_index,
        attributes: info.attributes,
        security_information: 23,
        security_bytes: required,
        security_sha256,
    })
}

pub fn remove_empty_directory(
    path: &Path,
    expected: (u32, u64),
    cutoff: Instant,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("matched probe parent absent"))?;
    let parents = hold_chain(parent, cutoff)?;
    live(cutoff)?;
    let owned = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES | 0x0001_0000)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let info = memcordon_platform::test_support::windows_held_file_metadata(&owned)?;
    live(cutoff)?;
    if (info.volume_serial, info.file_index) != expected
        || info.attributes & 0x10 == 0
        || info.attributes & (0x400 | 0x40) != 0
    {
        return Err(io::Error::other(
            "matched original probe deletion identity/type differs",
        ));
    }
    let mut owned = Some(owned);
    let mut attempted = false;
    let removed = (|| {
        live(cutoff)?;
        attempted = true;
        mark_empty_directory(owned.as_ref().expect("held probe"))?;
        live(cutoff)?;
        if let Err((error, file)) = close_file(owned.take().expect("held deletion owner")) {
            owned = Some(file);
            return Err(error);
        }
        live(cutoff)?;
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(io::Error::other(
                    "matched probe namespace remains after native deletion",
                ));
            }
        }
        live(cutoff)
    })();
    match removed {
        Err(error) if attempted => {
            // Failed disposition/close or uncertain named removal is not cleanup
            // proof. Retain any actual leaf and its parents for this controller.
            let _retained = Box::leak(Box::new((owned, parents)));
            Err(error)
        }
        result => result,
    }
}
