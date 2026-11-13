//! Closed preparation-child protocol. Wire scalars alone confer no native authority.
use crate::windows_registry_manifest::Declaration;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;

pub const FRAME_BYTES: usize = 128 * 1024;
pub fn digest(value: &impl Serialize) -> io::Result<String> {
    Ok(
        Sha256::digest(serde_json::to_vec(value).map_err(io::Error::other)?)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub version: u32,
    pub declaration: Declaration,
    pub declaration_sha256: String,
    pub challenge_sha256: String,
    pub cutoff_qpc: u64,
    pub frequency: u64,
}
impl Spec {
    pub fn validate(&self) -> io::Result<()> {
        self.declaration.validate().map_err(io::Error::other)?;
        if self.version != 1
            || self.cutoff_qpc == 0
            || self.frequency == 0
            || self.declaration_sha256 != digest(&self.declaration)?
            || self.challenge_sha256.len() != 64
            || !self
                .challenge_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::other(
                "catalog preparation spec is malformed or unbound",
            ));
        }
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub version: u32,
    pub pid: u32,
    pub birth: u64,
    pub spec_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transfer {
    pub version: u32,
    pub spec_sha256: String,
    pub handle: u64,
}
