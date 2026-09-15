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
    assert!(
        !buffer.is_empty(),
        "inventory read buffer must not be empty"
    );
    let mut digest = Sha256::new();
    loop {
        let read_started = Instant::now();
        let result = reader.read(buffer);
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
            break;
        }
    }
    Ok(hex::encode(digest.finalize()))
}
