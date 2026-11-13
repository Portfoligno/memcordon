//! Bounded original-listener wire facts. Decoding never grants native authority.
//! The runtime producer obtains the result only from its frozen original witness.
use serde::{Deserialize, Serialize};
use std::io;

pub const FORMAT: &str = "memcordon.original-listener-observation";
pub const LEAF: &str = "original-listener-observation.json";
pub const REVISION: u32 = 1;
pub const MAX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    TcpListenerBind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorDomain {
    RustIoRawOsErrorOnWindows,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub pid: u32,
    pub birth: u64,
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub token_sha256: [u8; 32],
    pub thread: u32,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub cutoff_qpc: u64,
    pub frequency: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expected {
    pub pid: u32,
    pub birth: u64,
    pub descriptor_sha256: [u8; 32],
    pub challenge_sha256: [u8; 32],
    pub token_sha256: [u8; 32],
    pub cutoff_qpc: u64,
    pub frequency: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub format: String,
    pub revision: u32,
    pub operation: Operation,
    pub domain: ErrorDomain,
    pub raw_os_error: i32,
    pub binding: Binding,
    pub ipv4: [u8; 4],
    pub port: u16,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "original listener observation shape or binding differs",
    )
}

fn validate_shape(value: &Observation) -> io::Result<()> {
    let binding = &value.binding;
    if value.format != FORMAT
        || value.revision != REVISION
        || value.ipv4 != [127, 0, 0, 1]
        || value.port != 0
        || binding.pid == 0
        || binding.birth == 0
        || binding.thread == 0
        || binding.frequency == 0
        || binding.started_qpc == 0
        || binding.finished_qpc < binding.started_qpc
        || binding.finished_qpc >= binding.cutoff_qpc
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn validate(value: &Observation, expected: &Expected) -> io::Result<()> {
    validate_shape(value)?;
    let binding = &value.binding;
    if binding.pid != expected.pid
        || binding.birth != expected.birth
        || binding.descriptor_sha256 != expected.descriptor_sha256
        || binding.challenge_sha256 != expected.challenge_sha256
        || binding.token_sha256 != expected.token_sha256
        || binding.cutoff_qpc != expected.cutoff_qpc
        || binding.frequency != expected.frequency
    {
        return Err(invalid());
    }
    Ok(())
}

pub fn encode(value: &Observation) -> io::Result<Vec<u8>> {
    validate_shape(value)?;
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8], expected: &Expected) -> io::Result<Observation> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(io::Error::other)?;
    let value = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    validate(&value, expected)?;
    Ok(value)
}
