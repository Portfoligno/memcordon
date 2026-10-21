use std::{fs::OpenOptions, io::Write, path::Path};

pub(crate) fn publish(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut writer = OpenOptions::new().write(true).create_new(true).open(path)?;
    writer.write_all(bytes)?;
    writer.sync_all()?;
    // Immutable custody must not overlap a writable publication handle.
    drop(writer);
    Ok(())
}
