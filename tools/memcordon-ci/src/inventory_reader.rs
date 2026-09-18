//! Bounded sequential reads for complete native-input content measurement.
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::Path;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::inventory_progress::InventoryProgress;

/// One heap buffer is reused throughout each root, including recursive descent.
pub const BUFFER_SIZE: usize = 1024 * 1024;

pub fn open_sequential(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_SEQUENTIAL_SCAN;
        options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
    }
    options.open(path)
}

/// Rendezvous points in the native file validation protocol. Callbacks are
/// synchronous observations; they do not replace any filesystem validation.
#[cfg(any(windows, unix))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFilePhase {
    BeforeOpen,
    Prechecked,
    ReadComplete,
    BeforeReopen,
}

/// Validate a regular Unix file around an EOF read. Device/inode bind
/// the descriptor and path; content and permission stamps reject concurrent
/// changes. Access time is excluded because this read can update it itself.
#[cfg(unix)]
pub fn digest_unix_file(
    path: &Path,
    expected: &std::fs::Metadata,
    buffer: &mut [u8],
    progress: &InventoryProgress,
    mut observe: impl FnMut(NativeFilePhase) -> crate::Result<()>,
) -> crate::Result<crate::inventory_pipeline::ValidatedDigest> {
    use crate::inventory_progress::Operation;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // Do not follow a substituted link or wait for a substituted FIFO's writer.
    // The metadata checks below still require the enumerated regular file.
    let open = || {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    };
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.nlink(),
            metadata.uid(),
            metadata.gid(),
            metadata.size(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    let cancellation = progress.cancellation();
    cancellation.check()?;
    observe(NativeFilePhase::BeforeOpen)?;
    cancellation.check()?;
    let mut file = progress.run(Operation::Open, path, open)?;
    cancellation.check()?;
    let before = progress.run(Operation::Precheck, path, || file.metadata())?;
    if !expected.is_file() || stamp(expected) != stamp(&before) {
        return Err(crate::CiError::Message(format!(
            "native input changed before read: {path:?}"
        )));
    }
    observe(NativeFilePhase::Prechecked)?;
    cancellation.check()?;
    // Unix virtual regular files can report length zero while exposing bytes.
    // Preserve EOF reads instead of treating st_size as authoritative content.
    let (digest, bytes) = progress.run(Operation::ReadHash, path, || {
        digest_reader_with_length(&mut file, buffer, progress, None)
    })?;
    observe(NativeFilePhase::ReadComplete)?;
    cancellation.check()?;
    let after = progress.run(Operation::PostMetadata, path, || file.metadata())?;
    observe(NativeFilePhase::BeforeReopen)?;
    cancellation.check()?;
    let current = progress.run(Operation::Reopen, path, open)?;
    cancellation.check()?;
    let path_metadata = progress.run(Operation::PathMetadata, path, || {
        std::fs::symlink_metadata(path)
    })?;
    let current_metadata = progress.run(Operation::PathIdentity, path, || current.metadata())?;
    if stamp(expected) != stamp(&after)
        || stamp(expected) != stamp(&path_metadata)
        || stamp(expected) != stamp(&current_metadata)
    {
        return Err(crate::CiError::Message(format!(
            "native input changed during read: {path:?}"
        )));
    }
    cancellation.check()?;
    progress.file_validated(bytes);
    Ok(crate::inventory_pipeline::ValidatedDigest { digest, bytes })
}

/// Read and validate the original enumerated file, including the current path's
/// stamp and file id. The callback permits deterministic mutation/cancel tests.
#[cfg(windows)]
pub fn digest_native_file(
    path: &Path,
    expected: &std::fs::Metadata,
    buffer: &mut [u8],
    progress: &InventoryProgress,
    mut observe: impl FnMut(NativeFilePhase) -> crate::Result<()>,
) -> crate::Result<crate::inventory_pipeline::ValidatedDigest> {
    use crate::inventory_progress::Operation;
    use std::os::windows::fs::MetadataExt;
    let stamp = |metadata: &std::fs::Metadata| {
        (
            metadata.file_attributes(),
            metadata.creation_time(),
            metadata.last_write_time(),
            metadata.file_size(),
        )
    };
    let cancellation = progress.cancellation();
    cancellation.check()?;
    observe(NativeFilePhase::BeforeOpen)?;
    cancellation.check()?;
    let mut file = progress.run(Operation::Open, path, || open_sequential(path))?;
    cancellation.check()?;
    let before = progress.run(Operation::Precheck, path, || file.metadata())?;
    if stamp(expected) != stamp(&before) {
        return Err(crate::CiError::Message(format!(
            "native input changed before read: {path:?}"
        )));
    }
    observe(NativeFilePhase::Prechecked)?;
    cancellation.check()?;
    let identity = progress.run(Operation::Identity, path, || {
        memcordon_testkit::windows_file_identity(&file)
    })?;
    let digest = progress.run(Operation::ReadHash, path, || {
        digest_reader_exact(&mut file, buffer, progress, expected.len())
    })?;
    observe(NativeFilePhase::ReadComplete)?;
    cancellation.check()?;
    let after = progress.run(Operation::PostMetadata, path, || file.metadata())?;
    observe(NativeFilePhase::BeforeReopen)?;
    cancellation.check()?;
    let current = progress.run(Operation::Reopen, path, || open_sequential(path))?;
    cancellation.check()?;
    if stamp(expected) != stamp(&after)
        || stamp(expected)
            != stamp(&progress.run(Operation::PathMetadata, path, || {
                std::fs::symlink_metadata(path)
            })?)
        || identity
            != progress.run(Operation::PathIdentity, path, || {
                memcordon_testkit::windows_file_identity(&current)
            })?
    {
        return Err(crate::CiError::Message(format!(
            "native input changed during read: {path:?}"
        )));
    }
    cancellation.check()?;
    progress.file_validated(expected.len());
    Ok(crate::inventory_pipeline::ValidatedDigest {
        digest,
        bytes: expected.len(),
    })
}

/// Hash until EOF, including short reads, and preserve the original read error.
pub fn digest_reader(
    reader: &mut impl Read,
    buffer: &mut [u8],
    progress: &InventoryProgress,
) -> io::Result<String> {
    digest_reader_with_length(reader, buffer, progress, None).map(|(digest, _)| digest)
}

/// Hash exactly a verified file length without a redundant EOF read. Callers
/// must verify file metadata and identity afterward to reject concurrent growth
/// or replacement; a premature EOF is always an error.
pub fn digest_reader_exact(
    reader: &mut impl Read,
    buffer: &mut [u8],
    progress: &InventoryProgress,
    length: u64,
) -> io::Result<String> {
    digest_reader_with_length(reader, buffer, progress, Some(length)).map(|(digest, _)| digest)
}

fn digest_reader_with_length(
    reader: &mut impl Read,
    buffer: &mut [u8],
    progress: &InventoryProgress,
    mut remaining: Option<u64>,
) -> io::Result<(String, u64)> {
    assert!(
        !buffer.is_empty(),
        "inventory read buffer must not be empty"
    );
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let cancellation = progress.cancellation();
    loop {
        cancellation.check()?;
        if remaining == Some(0) {
            break;
        }
        let capacity = remaining.map_or(buffer.len(), |remaining| {
            remaining.min(buffer.len() as u64) as usize
        });
        let read_started = Instant::now();
        let result = reader.read(&mut buffer[..capacity]);
        let read_elapsed = read_started.elapsed();
        let count = match result {
            Ok(count) => count,
            Err(error) => {
                progress.record_chunk(read_elapsed, Duration::ZERO, 0);
                return Err(error);
            }
        };
        let hash_started = Instant::now();
        digest.update(&buffer[..count]);
        progress.record_chunk(read_elapsed, hash_started.elapsed(), count as u64);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("native input byte count overflow"))?;
        if count == 0 {
            if remaining.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "native input ended before its verified length",
                ));
            }
            break;
        }
        if let Some(remaining) = &mut remaining {
            *remaining -= count as u64;
        }
    }
    cancellation.check()?;
    Ok((hex::encode(digest.finalize()), bytes))
}
