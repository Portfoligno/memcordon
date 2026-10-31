//! Private read-only fixture comparison; this is never gate or launch authority.
use serde::{Deserialize, Serialize};

pub const RECORD_BYTES: usize = 64 * 1024;

pub fn sha256(bytes: &[u8]) -> String {
    use sha2::Digest;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = sha2::Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push(HEX[usize::from(byte >> 4)] as char);
        text.push(HEX[usize::from(byte & 15)] as char);
    }
    text
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenObservation {
    pub user_sid: Vec<u8>,
    pub restricted: bool,
    pub integrity_rid: u32,
    pub elevated: bool,
    pub restricting_sids: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub revision: u32,
    pub expected_token: TokenObservation,
    pub work_cutoff_qpc: u64,
    pub qpc_frequency: u64,
}

impl Input {
    pub fn validate(&self) -> Result<(), String> {
        if self.revision != 1
            || self.work_cutoff_qpc == 0
            || self.qpc_frequency == 0
            || !self.expected_token.restricted
            || self.expected_token.user_sid.is_empty()
            || self.expected_token.user_sid.len() > 256
            || self.expected_token.restricting_sids.is_empty()
            || self.expected_token.restricting_sids.len() > 64
            || self
                .expected_token
                .restricting_sids
                .iter()
                .any(|sid| sid.is_empty() || sid.len() > 256)
        {
            return Err("invalid bounded selected-caller gate control input".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub format: String,
    pub revision: u32,
    pub diagnostic_only: bool,
    pub case: serde_json::Value,
    pub challenge_sha256: String,
    pub gate_name_utf16_sha256: String,
    pub operation: String,
    pub desired_access: u32,
    pub attempted: bool,
    pub opened: bool,
    pub native_error: Option<i32>,
    pub token: TokenObservation,
    pub token_envelope: memcordon_core::WindowsCallerTokenEnvelopeV1,
    pub same_original_event_identity_proved: bool,
    pub acceptance_authority: bool,
}

impl Observation {
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > RECORD_BYTES {
            return Err("gate control record exceeds bound".into());
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes)?;
        serde_json::from_slice(bytes).map_err(|error| error.to_string())
    }

    pub fn validate(
        &self,
        input: &Input,
        case: &serde_json::Value,
        challenge: &str,
        name: &str,
        envelope: &memcordon_core::WindowsCallerTokenEnvelopeV1,
    ) -> Result<(), String> {
        input.validate()?;
        if self.format != "memcordon.fixture-gate-precondition"
            || self.revision != 1
            || !self.diagnostic_only
            || self.case != *case
            || self.challenge_sha256 != challenge
            || self.gate_name_utf16_sha256 != name
            || self.operation != "OpenEventW-pre-handoff-control"
            || self.desired_access != 0x0010_0000
            || !self.attempted
            || self.opened != self.native_error.is_none()
            || self.native_error.is_some_and(|code| code <= 0)
            || self.token != input.expected_token
            || self.token_envelope != *envelope
            || self.same_original_event_identity_proved
            || self.acceptance_authority
        {
            return Err("gate precondition comparison is unavailable or inconsistent".into());
        }
        Ok(())
    }
}
