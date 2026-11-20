//! Stage the fixture's selected Rust text sources under its held compiled parent.
use std::fs::OpenOptions;
use std::io::{self, Read, Seek, Write};
use std::path::Path;
use std::time::Instant;

pub(super) const MAX_SOURCE_BYTES: u64 = 1024 * 1024;

pub(super) fn stage(source: &Path, destination: &Path, deadline: Instant) -> io::Result<()> {
    let check = || {
        if Instant::now() >= deadline {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original toolchain source staging cutoff expired",
            ))
        } else {
            Ok(())
        }
    };
    check()?;
    let mut input = held_file_options().open(source)?;
    check()?;
    let metadata = input.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selected toolchain source is not a regular file",
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "selected toolchain source is a reparse point",
            ));
        }
    }
    check()?;
    let mut expected = Vec::new();
    (&mut input)
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut expected)?;
    if expected.len() as u64 > MAX_SOURCE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "selected toolchain source exceeds the staging byte bound",
        ));
    }
    check()?;
    let mut output = held_file_options()
        .write(true)
        .create_new(true)
        .open(destination)?;
    check()?;
    output.write_all(&expected)?;
    check()?;
    output.rewind()?;
    check()?;
    let mut actual = Vec::new();
    (&mut output)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut actual)?;
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged toolchain source owned readback differs",
        ));
    }
    check()
}

fn held_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        };
        options
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options
}
