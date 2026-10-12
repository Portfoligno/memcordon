//! Transfer executable identity custody without retaining write access at exec.
use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(crate) fn pin_install_image(path: &Path) -> io::Result<File> {
    let image = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = image.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o7777 != 0o755 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native install source is not an exact regular artifact",
        ));
    }
    Ok(image)
}

pub(crate) fn retain_readonly(path: &Path, writer: File) -> io::Result<File> {
    let original = writer.metadata()?;
    let retained = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let reopened = retained.metadata()?;
    if (original.dev(), original.ino()) != (reopened.dev(), reopened.ino()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "native executable read-only handoff identity differs",
        ));
    }
    // Linux refuses exec while a writable file description remains open,
    // including one marked close-on-exec or chmodded to a read-only mode.
    drop(writer);
    Ok(retained)
}
