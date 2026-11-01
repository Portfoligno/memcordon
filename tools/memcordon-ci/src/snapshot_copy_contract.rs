use crate::{CiError, Result};

pub fn mutation_extent(position: u64, offset: u64, length: u64, source_length: u64) -> Result<()> {
    if position > offset
        || offset
            .checked_add(length)
            .is_none_or(|end| end > source_length)
    {
        return Err(CiError::Message(
            "source mutation extent is not wholly unread in the original held source".into(),
        ));
    }
    Ok(())
}

pub fn mutation_gate(bytes: [u8; 2], changed: bool) -> Result<bool> {
    match (bytes, changed) {
        ([b'A', b'\n'], _) => Ok(false),
        ([b'W', b'\n'], false) | ([b'D', b'\n'], true) => Ok(true),
        _ => Err(CiError::Message(
            "snapshot retained alias phase gate differs".into(),
        )),
    }
}

pub fn publication_event(
    expected_watch: i32,
    watch: i32,
    mask: u32,
    name: &[u8],
    expected: &[u8],
) -> Result<bool> {
    // Linux inotify ABI flags; this portable classifier performs no observation.
    if mask & (0x4000 | 0x8000 | 0x400 | 0x800 | 0x2000) != 0 || watch != expected_watch {
        return Err(CiError::Message(
            "protected journal publication watch overflowed, retired, or drifted".into(),
        ));
    }
    if name != expected {
        return Ok(false);
    }
    if mask & (0x200 | 0x40 | 0x40000000) != 0 {
        return Err(CiError::Message(
            "exact protected journal publication was removed or has wrong type".into(),
        ));
    }
    Ok(mask & (0x100 | 0x80) != 0)
}
