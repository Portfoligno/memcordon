//! A bounded diagnostic snapshot, never permission to open or release an event.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt::Write, io};
pub const DESCRIPTOR_BOUND: usize = 64 * 1024;
const ACE_BOUND: usize = 64;
#[path = "controller_gate_namespace_input.rs"]
pub mod namespace;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub revision: u32,
    pub descriptor: Vec<u8>,
    pub descriptor_sha256: String,
    pub name_utf16_sha256: String,
    pub challenge_sha256: String,
    pub work_cutoff_qpc: u64,
    pub qpc_frequency: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<namespace::Proof>,
}
pub fn sha256(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in Sha256::digest(bytes) {
        write!(&mut text, "{byte:02x}").expect("String formatting is infallible");
    }
    text
}
pub fn name_sha256(name: &[u16]) -> String {
    let mut digest = Sha256::new();
    for unit in name {
        digest.update(unit.to_le_bytes());
    }
    let mut text = String::new();
    for byte in digest.finalize() {
        write!(&mut text, "{byte:02x}").expect("String formatting is infallible");
    }
    text
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "gate access diagnostic snapshot differs",
    )
}
fn dword_aligned(value: usize) -> bool {
    value & (size_of::<u32>() - 1) == 0
}
fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u16>())?)?
            .try_into()
            .ok()?,
    ))
}
fn dword(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes
            .get(offset..offset.checked_add(size_of::<u32>())?)?
            .try_into()
            .ok()?,
    ))
}
fn sid(bytes: &[u8]) -> Option<usize> {
    let prefix = 8;
    if bytes.len() < prefix || bytes[0] != 1 || bytes[1] > 15 {
        return None;
    }
    let size = prefix + usize::from(bytes[1]) * size_of::<u32>();
    (size <= bytes.len()).then_some(size)
}
fn layout(bytes: &[u8]) -> Option<()> {
    let header = 20;
    if bytes.len() < header || bytes.len() > DESCRIPTOR_BOUND || bytes[0] != 1 || bytes[1] != 0 {
        return None;
    }
    let control = word(bytes, 2)?;
    if control & 0x8004 != 0x8004 || dword(bytes, 12)? != 0 {
        return None;
    }
    for offset in [4, 8] {
        let at = dword(bytes, offset)? as usize;
        if at < header || !dword_aligned(at) {
            return None;
        }
        sid(bytes.get(at..)?)?;
    }
    let at = dword(bytes, 16)? as usize;
    if at < header || !dword_aligned(at) {
        return None;
    }
    let acl = bytes.get(at..)?;
    if acl.len() < 8 || !matches!(acl[0], 2 | 4) || acl[1] != 0 || word(acl, 6)? != 0 {
        return None;
    }
    let length = usize::from(word(acl, 2)?);
    let count = usize::from(word(acl, 4)?);
    if length < 8 || length > acl.len() || !dword_aligned(length) || count > ACE_BOUND {
        return None;
    }
    let mut cursor = 8_usize;
    for _ in 0..count {
        let entry = acl.get(cursor..length)?;
        if entry.len() < 8 || !matches!(entry[0], 0 | 1) {
            return None;
        }
        let size = usize::from(word(entry, 2)?);
        if size < 8
            || size > entry.len()
            || !dword_aligned(size)
            || sid(entry.get(8..size)?)? != size - 8
        {
            return None;
        }
        cursor = cursor.checked_add(size)?;
    }
    Some(())
}
impl Input {
    pub fn validate(&self, name: &[u16], challenge: &[u8]) -> io::Result<()> {
        if self.descriptor.len() > DESCRIPTOR_BOUND {
            return Err(invalid());
        }
        if self.revision != 1
            || self.qpc_frequency == 0
            || self.work_cutoff_qpc == 0
            || name.is_empty()
            || name.contains(&0)
            || self.descriptor_sha256 != sha256(&self.descriptor)
            || self.name_utf16_sha256 != name_sha256(name)
            || self.challenge_sha256 != sha256(challenge)
            || layout(&self.descriptor).is_none()
        {
            return Err(invalid());
        }
        if let Some(proof) = &self.namespace {
            proof.validate(
                name,
                challenge,
                &self.descriptor_sha256,
                self.work_cutoff_qpc,
                self.qpc_frequency,
            )?;
        }
        Ok(())
    }
}
