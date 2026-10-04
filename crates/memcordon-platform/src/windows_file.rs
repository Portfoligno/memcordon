//! Durable same-directory file replacement on Windows.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows_sys::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

/// Replace a file in the same directory and request a write-through move.
///
/// The caller must flush the source file before calling this function. A
/// different parent is rejected so the move cannot fall back to a copy across
/// volumes. Windows reports any failure through the returned I/O error.
pub fn replace_file_write_through(source: &Path, destination: &Path) -> io::Result<()> {
    if source.parent().is_none() || source.parent() != destination.parent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "write-through replacement requires one directory",
        ));
    }
    let mut source_wide: Vec<u16> = source.as_os_str().encode_wide().collect();
    let mut destination_wide: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if source_wide.contains(&0) || destination_wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "write-through replacement path contains NUL",
        ));
    }
    source_wide.push(0);
    destination_wide.push(0);
    // SAFETY: both path buffers are live NUL-terminated UTF-16 strings. The
    // flags request replacement and completion of the on-disk move.
    if unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
