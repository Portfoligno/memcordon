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

/// Hash until EOF, including short reads, and preserve the original read error.
pub fn digest_reader(
    reader: &mut impl Read,
    buffer: &mut [u8],
    progress: &InventoryProgress,
) -> io::Result<String> {
    digest_reader_with_length(reader, buffer, progress, None)
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
    digest_reader_with_length(reader, buffer, progress, Some(length))
}

fn digest_reader_with_length(
    reader: &mut impl Read,
    buffer: &mut [u8],
    progress: &InventoryProgress,
    mut remaining: Option<u64>,
) -> io::Result<String> {
    assert!(
        !buffer.is_empty(),
        "inventory read buffer must not be empty"
    );
    let mut digest = Sha256::new();
    loop {
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
    Ok(hex::encode(digest.finalize()))
}
