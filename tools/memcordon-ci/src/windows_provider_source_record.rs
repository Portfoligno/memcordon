//! Borrowed provider bytes, not owned-receipt or source-authenticity authority.
use serde::{Deserialize, Serialize};

pub const SOURCE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub volume_serial: u32,
    pub file_index: u64,
    pub attributes: u32,
    pub links: u32,
    pub bytes: u64,
}

impl Metadata {
    pub fn validate(&self) -> Result<(), String> {
        if self.attributes & (0x10 | 0x400) != 0
            || self.links == 0
            || self.bytes == 0
            || self.bytes > SOURCE_BYTES
        {
            return Err(
                "borrowed provider requires bounded regular non-reparse bytes and positive links"
                    .into(),
            );
        }
        Ok(())
    }

    pub fn verify(&self, observed: &Self, bytes: &[u8], expected: &str) -> Result<(), String> {
        self.validate()?;
        observed.validate()?;
        if self != observed
            || self.bytes != bytes.len() as u64
            || crate::windows_causal_acceptance::sha256(bytes) != expected
        {
            return Err("borrowed provider metadata, length or measured content changed".into());
        }
        Ok(())
    }
}
