//! Bounded original Rust spawn failure. It has no process-retirement authority.
use super::original_listener_observation::{Binding, Expected};
use serde::{Deserialize, Serialize};
use std::io;

pub const FORMAT: &str = "memcordon.original-peer-spawn-observation";
pub const LEAF: &str = "original-peer-spawn-observation.json";
pub const MAX_BYTES: usize = 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub intent_sequence: u32,
    pub intent_sha256: [u8; 32],
}

impl Grant {
    pub fn identity(self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(self.intent_sequence.to_le_bytes());
        hash.update(self.intent_sha256);
        hash.finalize().into()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Operation {
    CommandSpawn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ErrorDomain {
    RustIoRawOsErrorOnWindows,
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
    pub grant: Grant,
}

/// Preserve the application error only when the callback reported that same
/// error. Optional observations of APIs called inside spawn are irrelevant.
pub fn original_raw_error(
    actual: Option<&io::Error>,
    callback_raw_error: Option<i32>,
) -> Option<i32> {
    let raw = actual?.raw_os_error()?;
    (raw != 0 && callback_raw_error == Some(raw)).then_some(raw)
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "original peer spawn observation shape or binding differs",
    )
}

fn validate_shape(value: &Observation) -> io::Result<()> {
    let binding = &value.binding;
    if value.format != FORMAT
        || value.revision != 1
        || value.raw_os_error == 0
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

pub fn encode(value: &Observation) -> io::Result<Vec<u8>> {
    validate_shape(value)?;
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    Ok(bytes)
}

pub fn decode(bytes: &[u8], expected: &Expected, grant: Grant) -> io::Result<Observation> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(io::Error::other)?;
    let value: Observation = serde_json::from_slice(bytes).map_err(io::Error::other)?;
    validate_shape(&value)?;
    let binding = &value.binding;
    if binding.pid != expected.pid
        || binding.birth != expected.birth
        || binding.descriptor_sha256 != expected.descriptor_sha256
        || binding.challenge_sha256 != expected.challenge_sha256
        || binding.token_sha256 != expected.token_sha256
        || binding.cutoff_qpc != expected.cutoff_qpc
        || binding.frequency != expected.frequency
        || value.grant != grant
    {
        return Err(invalid());
    }
    Ok(value)
}
