//! Copy held image bytes without changing the shared open-file-description offset.
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::fs::FileExt;

pub(crate) fn copy_exact(source: &File, destination: &mut File, size: u64) -> io::Result<()> {
    let bound = size
        .checked_add(1)
        .ok_or_else(|| io::Error::other("image copy bound overflow"))?;
    let mut offset = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = bound - offset;
        let length = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("image copy buffer length fits usize");
        let count = source.read_at(&mut buffer[..length], offset)?;
        if count == 0 {
            break;
        }
        offset += count as u64;
        if offset > size {
            return Err(io::Error::other("held image changed during root copy"));
        }
        destination.write_all(&buffer[..count])?;
    }
    if offset != size {
        return Err(io::Error::other("held image changed during root copy"));
    }
    Ok(())
}
