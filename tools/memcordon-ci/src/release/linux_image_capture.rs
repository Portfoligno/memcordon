//! Constant-memory, exact-length image evidence transfer.
use std::io::{self, Read, Write};
use std::time::Instant;

use sha2::{Digest, Sha256};

/// Validate lexical containment without resolving a filesystem name or
/// accepting a normalized alias of the caller's original artifact path.
pub fn normalized_descendant(root: &std::path::Path, path: &std::path::Path) -> io::Result<()> {
    use std::path::{Component, PathBuf};
    for operand in [root, path] {
        let normalized: PathBuf = operand.components().collect();
        if !operand.is_absolute()
            || operand
                .components()
                .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
            || normalized.as_os_str() != operand.as_os_str()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "image evidence containment requires absolute normalized paths",
            ));
        }
    }
    if path
        .strip_prefix(root)
        .is_ok_and(|relative| !relative.as_os_str().is_empty())
    {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "image evidence must be a strict descendant of its original output root",
        ))
    }
}

pub fn transfer(
    reader: &mut impl Read,
    writer: &mut impl Write,
    expected: u64,
    deadline: Instant,
) -> io::Result<[u8; 32]> {
    let mut count = 0u64;
    let mut hash = Sha256::new();
    let mut scratch = [0u8; 64 * 1024];
    loop {
        live(deadline)?;
        let read = reader.read(&mut scratch)?;
        if read == 0 {
            break;
        }
        count = count
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("image byte count overflow"))?;
        if count > expected {
            return Err(io::Error::other(format!(
                "image grew: expected-bytes={expected} observed-bytes={count}"
            )));
        }
        hash.update(&scratch[..read]);
        writer.write_all(&scratch[..read])?;
    }
    live(deadline)?;
    if count != expected {
        return Err(io::Error::other(format!(
            "image shortened: expected-bytes={expected} observed-bytes={count}"
        )));
    }
    Ok(hash.finalize().into())
}

fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original image capture cutoff exhausted",
        ))
    } else {
        Ok(())
    }
}
