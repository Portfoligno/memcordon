//! Bounded native reparse diagnostics, never authorization for an input/cache.
use sha2::{Digest, Sha256};
use std::io;

const MAXIMUM_REPARSE_DATA_BUFFER_SIZE: usize = 16 * 1024;
const APP_EXEC_LINK: u32 = 0x8000_001b;

pub fn describe(data: &[u8]) -> io::Result<String> {
    fn invalid() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed native reparse evidence",
        )
    }
    let mut remaining = data;
    fn take<const N: usize>(input: &mut &[u8]) -> Option<[u8; N]> {
        let (value, rest) = input.split_at_checked(N)?;
        *input = rest;
        value.try_into().ok()
    }
    if data.len() > MAXIMUM_REPARSE_DATA_BUFFER_SIZE {
        return Err(invalid());
    }
    let tag = u32::from_le_bytes(take(&mut remaining).ok_or_else(invalid)?);
    let length = u16::from_le_bytes(take(&mut remaining).ok_or_else(invalid)?) as usize;
    let reserved = u16::from_le_bytes(take(&mut remaining).ok_or_else(invalid)?);
    if length != remaining.len() {
        return Err(invalid());
    }
    let mut description = format!(
        "tag=0x{tag:08x} data_len={length} reserved={reserved} payload_sha256={} payload_hex={}",
        hex::encode(Sha256::digest(remaining)),
        hex::encode(remaining)
    );
    if tag == APP_EXEC_LINK {
        // These fields aid investigation only. Even a well-formed payload does
        // not prove package registration, dependency closure or executable bytes.
        let version = u32::from_le_bytes(take(&mut remaining).ok_or_else(invalid)?);
        let mut chunks = remaining.chunks_exact(size_of::<u16>());
        let units: Vec<_> = chunks
            .by_ref()
            .map(|chunk| u16::from_le_bytes(chunk.try_into().expect("UTF-16 unit size")))
            .collect();
        if !chunks.remainder().is_empty() || units.last() != Some(&0) {
            return Err(invalid());
        }
        let fields: Result<Vec<_>, _> = units
            .split(|unit| *unit == 0)
            .map(String::from_utf16)
            .collect();
        description.push_str(&format!(" app_exec_version={version}"));
        match fields {
            Ok(fields) => description.push_str(&format!(" fields={fields:?}")),
            Err(_) => description.push_str(&format!(" fields_utf16={units:?}")),
        }
    }
    Ok(description)
}
