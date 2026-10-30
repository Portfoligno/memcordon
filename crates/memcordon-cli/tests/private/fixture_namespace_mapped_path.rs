//! Pure parsing only: trust comes from full Windows ordinal comparisons to the
//! separately held native System32 root, never from a parsed device name.
use std::io;

pub const PROFILE_LEAF: &str = "kernelbase.dll";
pub const PATH_LIMIT: usize = 32768;
pub const INITIAL_CAPACITY: usize = 256;
const NT_PREFIX: &str = "\\Device\\";

#[derive(Debug, PartialEq, Eq)]
pub enum Query {
    Complete(Vec<u16>),
    Grow(usize),
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// K32GetMappedFileNameW returns the capacity on truncation, rather than the
/// required capacity. The adapter preserves a zero result's native error.
pub fn query(buffer: &[u16], returned: usize) -> io::Result<Query> {
    let capacity = buffer.len();
    if !(INITIAL_CAPACITY..=PATH_LIMIT).contains(&capacity) || !capacity.is_power_of_two() {
        return Err(invalid("mapped-name buffer capacity"));
    }
    if returned == 0 {
        return Err(invalid("mapped-name query returned zero"));
    }
    if returned >= capacity {
        return capacity
            .checked_mul(2)
            .filter(|next| *next <= PATH_LIMIT)
            .map(Query::Grow)
            .ok_or_else(|| invalid("mapped-name path bound"));
    }
    let units = &buffer[..returned];
    if buffer[returned] != 0 || units.contains(&0) || String::from_utf16(units).is_err() {
        return Err(invalid("mapped-name incomplete or malformed UTF16"));
    }
    Ok(Query::Complete(units.to_vec()))
}

/// Return full parent and one leaf, with no rewriting, normalization, or case
/// folding. A syntactically valid device path is not an admitted system path.
pub fn nt_parts(path: &[u16]) -> io::Result<(&[u16], &[u16])> {
    if path.is_empty() || path.len() > PATH_LIMIT || String::from_utf16(path).is_err() {
        return Err(invalid("NT path length or UTF16"));
    }
    let prefix: Vec<u16> = NT_PREFIX.encode_utf16().collect();
    let remainder = path
        .strip_prefix(prefix.as_slice())
        .ok_or_else(|| invalid("absolute NT device path required"))?;
    let mut count = 0;
    for component in remainder.split(|unit| *unit == u16::from(b'\\')) {
        if component.is_empty()
            || component == [u16::from(b'.')]
            || component == [u16::from(b'.'), u16::from(b'.')]
            || component.iter().any(|unit| matches!(*unit, 0 | 47 | 58))
        {
            return Err(invalid("noncanonical NT path component"));
        }
        count += 1;
    }
    if count < 2 {
        return Err(invalid("NT device path lacks a file component"));
    }
    let separator = path
        .iter()
        .rposition(|unit| *unit == u16::from(b'\\'))
        .ok_or_else(|| invalid("NT path separator"))?;
    Ok((&path[..separator], &path[separator + 1..]))
}

/// These are public CompareStringOrdinal results, not BOOL values. The adapter
/// captures GetLastError immediately for zero before calling this pure gate.
pub fn ordinal_result(result: i32) -> io::Result<bool> {
    match result {
        1 | 3 => Ok(false),
        2 => Ok(true),
        _ => Err(invalid("Windows ordinal comparison unavailable")),
    }
}

/// The adapter must compute parent_result using nt_parts(mapped).0 and the
/// complete held root, and leaf_result using nt_parts(mapped).1 and PROFILE_LEAF.
/// No prefix of a logged path, arbitrary basename, or ASCII fold can qualify.
pub fn bind(
    mapped: &[u16],
    root: &[u16],
    parent_result: i32,
    leaf_result: i32,
) -> io::Result<bool> {
    nt_parts(mapped)?;
    nt_parts(root)?;
    let parent = ordinal_result(parent_result)?;
    let leaf = ordinal_result(leaf_result)?;
    Ok(parent && leaf)
}

/// Full mapped-name/final-held-name comparison, again supplied by Windows.
pub fn same_path(first: &[u16], second: &[u16], result: i32) -> io::Result<bool> {
    nt_parts(first)?;
    nt_parts(second)?;
    ordinal_result(result)
}
