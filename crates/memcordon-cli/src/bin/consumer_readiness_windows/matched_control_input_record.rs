//! Complete Stage1 input readbacks, checked against the held caller and plan.
use super::descriptor::matched::Binding;
use memcordon_core::{WindowsCallerTokenEnvelopeV1, WindowsEnvironmentEntryV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenDetails {
    pub envelope: WindowsCallerTokenEnvelopeV1,
    pub token_id: u64,
    pub expiration: i64,
    pub group_count: u32,
    pub privilege_count: u32,
    pub modified_id: u64,
    pub default_acl_bytes: usize,
    pub default_acl_sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CwdIdentity {
    pub volume_serial: u64,
    pub file_index: u64,
    pub attributes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Security {
    pub security_information: u32,
    pub bytes: u32,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub role: u32,
    pub file_type: u32,
    pub security: Security,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Readback {
    pub revision: u32,
    pub binding: Binding,
    pub descriptor_sha256: [u8; 32],
    pub pid: u32,
    pub birth: u64,
    pub token_sha256: [u8; 32],
    pub partial_token_sha256: [u8; 32],
    pub token: TokenDetails,
    pub cwd_utf16: Vec<u16>,
    pub cwd_identity: CwdIdentity,
    pub environment: Vec<WindowsEnvironmentEntryV1>,
    pub streams: Vec<Stream>,
    pub started_qpc: u64,
    pub finished_qpc: u64,
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
}

pub struct Expected {
    pub binding: Binding,
    pub descriptor_sha256: [u8; 32],
    pub token_sha256: [u8; 32],
    pub default_acl_bytes: usize,
    pub default_acl_sha256: [u8; 32],
    pub qpc_frequency: u64,
    pub cutoff_qpc: u64,
    pub identity: Option<(u32, u64)>,
}

pub fn decode(bytes: &[u8]) -> Result<Readback, String> {
    if bytes.len() > MAX_BYTES {
        return Err("matched input readback exceeds64KiB".into());
    }
    let value: Readback = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let wire: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if wire != serde_json::to_value(&value).map_err(|error| error.to_string())? {
        return Err("matched input readback has an unexpected or missing field".into());
    }
    shape(&value)?;
    Ok(value)
}

fn shape(value: &Readback) -> Result<(), String> {
    if value.revision != 1
        || value.pid == 0
        || value.birth == 0
        || value.qpc_frequency == 0
        || value.started_qpc == 0
        || value.finished_qpc < value.started_qpc
        || value.finished_qpc >= value.cutoff_qpc
    {
        return Err("matched input identity/revision/clock unavailable or expired".into());
    }
    if value.cwd_utf16.is_empty()
        || value.cwd_utf16.len() > 32767
        || value.cwd_utf16.contains(&0)
        || value.cwd_identity.attributes & 0x10 == 0
        || value.cwd_identity.attributes & (0x400 | 0x40) != 0
    {
        return Err("matched input cwd is not a complete ordinary directory".into());
    }
    if value.environment.is_empty() || value.environment.len() > 128 {
        return Err("matched input environment count invalid".into());
    }
    memcordon_core::encode_windows_environment_block(&value.environment).map_err(str::to_owned)?;
    let roles = [(-10i32) as u32, (-11i32) as u32, (-12i32) as u32];
    if value.streams.len() != roles.len()
        || value.streams.iter().zip(roles).any(|(stream, role)| {
            stream.role != role
                || stream.file_type != 3
                || stream.security.security_information != 23
                || stream.security.bytes == 0
                || stream.security.bytes > 8192
        })
    {
        return Err(
            "matched input standard streams are incomplete or differ from pipe/security contract"
                .into(),
        );
    }
    if value.token.default_acl_bytes == 0 || value.token.default_acl_bytes > MAX_BYTES {
        return Err("matched input default ACL unavailable or oversized".into());
    }
    let token_bytes =
        serde_json::to_vec(&value.token.envelope).map_err(|error| error.to_string())?;
    let actual: [u8; 32] = Sha256::digest(&token_bytes).into();
    if actual != value.token_sha256 {
        return Err("matched input token envelope does not match its hash".into());
    }
    Ok(())
}

pub fn validate(value: &Readback, expected: &Expected) -> Result<(), String> {
    shape(value)?;
    if value.binding != expected.binding
        || value.descriptor_sha256 != expected.descriptor_sha256
        || value.token_sha256 != expected.token_sha256
        || value.token.default_acl_bytes != expected.default_acl_bytes
        || value.token.default_acl_sha256 != expected.default_acl_sha256
        || value.qpc_frequency != expected.qpc_frequency
        || value.cutoff_qpc != expected.cutoff_qpc
        || expected
            .identity
            .is_some_and(|identity| identity != (value.pid, value.birth))
    {
        return Err(
            "matched input differs from held caller, original identity or declared plan".into(),
        );
    }
    Ok(())
}

pub fn compare_inputs(left: &Readback, right: &Readback) -> Result<(), String> {
    shape(left)?;
    shape(right)?;
    let mut left_environment = left.environment.clone();
    let mut right_environment = right.environment.clone();
    left_environment.sort_by(|a, b| a.name.cmp(&b.name));
    right_environment.sort_by(|a, b| a.name.cmp(&b.name));
    if left.cwd_identity != right.cwd_identity
        || left_environment != right_environment
        || left.streams != right.streams
        || left.token.envelope != right.token.envelope
        || left.token.expiration != right.token.expiration
        || left.token.group_count != right.token.group_count
        || left.token.privilege_count != right.token.privilege_count
        || left.token.default_acl_bytes != right.token.default_acl_bytes
        || left.token.default_acl_sha256 != right.token.default_acl_sha256
    {
        return Err(
            "matched actual cwd, environment, streams or stable token inputs differ".into(),
        );
    }
    Ok(())
}
