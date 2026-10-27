//! Controller-observed diagnostic path metadata; never fixture object authority.
use serde::{Deserialize, Serialize};
use std::io;

pub const MAX_COMPONENTS: usize = 17;
pub const MAX_PATH_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub revision: u32,
    pub components: Vec<Vec<u16>>,
    pub path_sha256: String,
    pub challenge_sha256: String,
    pub name_utf16_sha256: String,
    pub descriptor_sha256: String,
    pub work_cutoff_qpc: u64,
    pub qpc_frequency: u64,
    pub controller_same_original: bool,
    pub controller_absolute_same_original: bool,
    pub complete: bool,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "gate namespace diagnostic proof or native buffer differs",
    )
}

pub fn component(value: &[u16]) -> io::Result<()> {
    if value.is_empty()
        || value.iter().any(|unit| matches!(*unit, 0 | 0x2f | 0x5c))
        || value.iter().copied().eq(".".encode_utf16())
        || value.iter().copied().eq("..".encode_utf16())
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn rooted_path(components: &[Vec<u16>]) -> io::Result<Vec<u16>> {
    if components.is_empty() || components.len() > MAX_COMPONENTS {
        return Err(invalid());
    }
    let mut units = 1usize; // Account for the eventual native NUL before allocating.
    for value in components {
        component(value)?;
        units = units
            .checked_add(1)
            .and_then(|units| units.checked_add(value.len()))
            .ok_or_else(invalid)?;
        if units
            .checked_mul(size_of::<u16>())
            .is_none_or(|bytes| bytes > MAX_PATH_BYTES)
        {
            return Err(invalid());
        }
    }
    let mut path = Vec::with_capacity(units);
    for value in components {
        path.push(u16::from(b'\\'));
        path.extend_from_slice(value);
    }
    Ok(path)
}

pub fn path_sha256(components: &[Vec<u16>]) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    let mut digest = Sha256::new();
    for unit in rooted_path(components)? {
        digest.update(unit.to_le_bytes());
    }
    let mut output = String::new();
    for byte in digest.finalize() {
        write!(&mut output, "{byte:02x}").expect("String write is infallible");
    }
    Ok(output)
}

impl Proof {
    pub fn event_leaf(&self) -> io::Result<&[u16]> {
        let leaf = self.components.last().ok_or_else(invalid)?.as_slice();
        component(leaf)?;
        if leaf
            .len()
            .checked_add(1)
            .and_then(|units| units.checked_mul(size_of::<u16>()))
            .is_none_or(|bytes| bytes > MAX_PATH_BYTES)
        {
            return Err(invalid());
        }
        Ok(leaf)
    }
    pub fn validate(
        &self,
        name: &[u16],
        challenge: &[u8],
        descriptor_sha256: &str,
        cutoff: u64,
        frequency: u64,
    ) -> io::Result<()> {
        let local_prefix: Vec<u16> = "Local\\".encode_utf16().collect();
        let leaf = name
            .strip_prefix(local_prefix.as_slice())
            .ok_or_else(invalid)?;
        if self.revision != 1
            || !self.complete
            || !self.controller_same_original
            || !self.controller_absolute_same_original
            || cutoff == 0
            || frequency == 0
            || self.work_cutoff_qpc != cutoff
            || self.qpc_frequency != frequency
            || self.path_sha256 != path_sha256(&self.components)?
            || self.challenge_sha256 != super::sha256(challenge)
            || self.name_utf16_sha256 != super::name_sha256(name)
            || self.descriptor_sha256 != descriptor_sha256
            || self.event_leaf()? != leaf
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[cfg(windows)]
#[path = "controller_gate_namespace.rs"]
pub mod native;
