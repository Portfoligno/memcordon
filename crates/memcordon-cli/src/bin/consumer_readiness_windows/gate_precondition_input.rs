//! Private read-only fixture comparison; this is never gate or launch authority.
use serde::{Deserialize, Serialize};

pub const RECORD_BYTES: usize = 64 * 1024;

pub const REDUCED_COMPILER_SENTINEL: &str = "reduced-compiler-sentinel.bin";
pub const REDUCED_COMPILER_OUTPUT: &str = "reduced-compiler-output.bin";
pub const COMPILER_ADMINISTRATORS_SID: &[u8] = &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0];
pub const COMPILER_AUTHORITY_MEMBERS: usize = 128;
pub const COMPILER_AUTHORITY_PROBE_BYTES: usize = 15 * 1024;
#[allow(
    dead_code,
    reason = "used by the controller receiving the fixture report"
)]
pub const COMPILER_QUALIFICATION_FAILURE_BYTES: usize = 1024;
const ENABLED_BY_DEFAULT: u32 = 2;
const ENABLED: u32 = 4;
const DENY_ONLY: u32 = 16;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CompilerQualificationStage {
    SourceSnapshot,
    SourceToken,
    SourceInventory,
    SourceValidation,
    AdministratorsSid,
    CreateRestrictedToken,
    ReducedDefaultDacl,
    ReducedInventory,
    AuthorityReduction,
    FrontendSetup,
    CreateSuspendedFrontend,
    SuspendedToken,
    ResumeFrontend,
    ReadFrontendStatus,
    EffectiveSnapshot,
    EffectiveValidation,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerQualificationFailure {
    pub stage: CompilerQualificationStage,
    pub win32: Option<i32>,
    pub premise: Option<String>,
}

#[allow(
    dead_code,
    reason = "parsing is used on the controller side of the fixture report"
)]
impl CompilerQualificationFailure {
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() > COMPILER_QUALIFICATION_FAILURE_BYTES {
            return None;
        }
        memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).ok()?;
        let failure: Self = serde_json::from_slice(bytes).ok()?;
        if failure.premise.as_ref().is_some_and(|premise| {
            premise.is_empty()
                || premise.len() > 170
                || !premise
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'-' | b'_'))
        }) {
            return None;
        }
        Some(failure)
    }

    pub fn held_child_status(bytes: &[u8], wrapper_status: Option<i32>) -> Option<i32> {
        if bytes.len() > 64 {
            return None;
        }
        let status = std::str::from_utf8(bytes)
            .ok()?
            .strip_prefix("reduced-compiler-child-exit=")?
            .strip_suffix('\n')?
            .parse::<i32>()
            .ok()?;
        (Some(status) == wrapper_status && status != 0).then_some(status)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerGroup {
    pub sid: Vec<u8>,
    pub attributes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerPrivilege {
    pub luid: [u32; 2],
    pub attributes: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerAuthoritySnapshot {
    pub token: TokenObservation,
    pub authentication_id: [u32; 2],
    pub session_id: u32,
    pub primary: bool,
    pub administrators_attributes: u32,
    pub groups: Vec<CompilerGroup>,
    pub privileges: Vec<CompilerPrivilege>,
    pub traversal_luid: [u32; 2],
}

impl CompilerAuthoritySnapshot {
    fn bounded(&self) -> bool {
        self.primary
            && !self.token.user_sid.is_empty()
            && self.token.user_sid.len() <= 68
            && !self.token.restricted
            && self.token.restricting_sids.is_empty()
            && self.authentication_id != [0; 2]
            && self.traversal_luid != [0; 2]
            && self.groups.len() <= COMPILER_AUTHORITY_MEMBERS
            && self.privileges.len() <= COMPILER_AUTHORITY_MEMBERS
            && self
                .groups
                .iter()
                .all(|group| !group.sid.is_empty() && group.sid.len() <= 68)
            && self
                .groups
                .windows(2)
                .all(|entries| entries[0].sid < entries[1].sid)
            && self
                .privileges
                .windows(2)
                .all(|entries| entries[0].luid < entries[1].luid)
            && self
                .groups
                .iter()
                .find(|group| group.sid == COMPILER_ADMINISTRATORS_SID)
                .is_some_and(|group| group.attributes == self.administrators_attributes)
    }

    pub fn validate_source(&self) -> Result<(), &'static str> {
        if !self.bounded() {
            return Err("reduced compiler source has invalid token shape or inventory");
        }
        if self.administrators_attributes & ENABLED == 0
            || self.administrators_attributes & DENY_ONLY != 0
        {
            return Err("reduced compiler source lacks enabled Administrators");
        }
        if !self
            .privileges
            .iter()
            .any(|privilege| privilege.luid != self.traversal_luid)
        {
            return Err("reduced compiler source lacks removable privileges");
        }
        Ok(())
    }

    pub fn validate_reduced(&self) -> Result<(), &'static str> {
        if !self.bounded() {
            return Err("reduced compiler target has invalid token shape or inventory");
        }
        if self.administrators_attributes & DENY_ONLY == 0
            || self.administrators_attributes & (ENABLED | ENABLED_BY_DEFAULT) != 0
        {
            return Err("reduced compiler target lacks exclusive deny-only Administrators");
        }
        if self
            .privileges
            .iter()
            .any(|privilege| privilege.luid != self.traversal_luid)
        {
            return Err("reduced compiler target retains deleted privileges");
        }
        Ok(())
    }
}

pub fn validate_compiler_authority_reduction(
    source: &CompilerAuthoritySnapshot,
    reduced: &CompilerAuthoritySnapshot,
) -> Result<(), &'static str> {
    source.validate_source()?;
    reduced.validate_reduced()?;
    if source.token.user_sid != reduced.token.user_sid
        || source.token.integrity_rid != reduced.token.integrity_rid
        || source.authentication_id != reduced.authentication_id
        || source.session_id != reduced.session_id
        || source.traversal_luid != reduced.traversal_luid
        || source.groups.len() != reduced.groups.len()
    {
        return Err("reduced compiler token source identity differs");
    }
    for (ordinary, actual) in source.groups.iter().zip(&reduced.groups) {
        // The disabled SID is checked above against the three flags Windows specifies.
        if ordinary.sid != actual.sid
            || (ordinary.sid != COMPILER_ADMINISTRATORS_SID
                && ordinary.attributes != actual.attributes)
        {
            return Err("reduced compiler group inventories differ outside the expected reduction");
        }
    }
    if !source
        .privileges
        .iter()
        .filter(|entry| entry.luid == source.traversal_luid)
        .eq(&reduced.privileges)
    {
        return Err("reduced compiler traversal privilege does not match its source");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerAuthorityFileIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerAuthorityProbes {
    pub challenge_sha256: String,
    pub effective_token_sha256: String,
    pub protected: CompilerAuthorityFileIdentity,
    pub protected_write_win32: u32,
    pub output_write_verified: bool,
    pub authority: CompilerAuthoritySnapshot,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompilerAuthorityOrdinaryControl {
    pub challenge_sha256: String,
    pub effective_token_sha256: String,
    pub protected: CompilerAuthorityFileIdentity,
    pub protected_write_verified: bool,
    pub token: TokenObservation,
    pub authority: CompilerAuthoritySnapshot,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub original_call_trace: Option<serde_json::Value>,
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
        let trace_invalid = match &self.original_call_trace {
            None => false,
            Some(trace) => {
                serde_json::to_vec(trace)
                    .map_err(|error| error.to_string())?
                    .len()
                    > 24 * 1024
                    || trace["context"] != "pre-handoff-control-child"
                    || trace["diagnostic_only"] != true
                    || trace["acceptance_authority"] != false
                    || trace["target_identity_proved"] != false
                    || trace["called"].as_u64() != Some(1)
                    || trace["outer_opened"].as_u64() != Some(u64::from(self.opened))
                    || self.native_error.is_some_and(|error| {
                        trace["outer_error"].as_u64() != u64::try_from(error).ok()
                    })
            }
        };
        if trace_invalid {
            return Err("optional control trace exceeds its diagnostic contract".into());
        }
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
