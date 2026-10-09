use std::{io, path::Path};

pub(crate) fn validate(
    path: &Path,
    directory: bool,
    attributes: u32,
    links: u32,
) -> io::Result<()> {
    const DIRECTORY: u32 = 0x10;
    const REPARSE_POINT: u32 = 0x400;
    if attributes & REPARSE_POINT != 0
        || (attributes & DIRECTORY != 0) != directory
        || (!directory && links != 1)
    {
        let bytes = path.as_os_str().as_encoded_bytes();
        let bounded = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]);
        return Err(io::Error::other(format!(
            "Windows receipt custody rejects reparse, type or link alias; path={bounded:?}; path-truncated={}; expected-directory={directory}; attributes=0x{attributes:08x}; links={links}",
            bytes.len() > 512,
        )));
    }
    Ok(())
}
