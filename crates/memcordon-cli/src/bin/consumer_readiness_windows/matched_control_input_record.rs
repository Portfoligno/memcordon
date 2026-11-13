//! Complete Stage1 input readbacks, checked against the held caller and plan.
use super::descriptor::matched::{Binding, Lane, Scope};
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

#[derive(Clone, Debug, Serialize)]
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
    if validation_predicates(value, expected)
        .iter()
        .any(|(_, matches)| !matches)
    {
        return Err(
            "matched input differs from held caller, original identity or declared plan".into(),
        );
    }
    Ok(())
}

fn validation_predicates(value: &Readback, expected: &Expected) -> [(&'static str, bool); 8] {
    [
        ("binding", value.binding == expected.binding),
        (
            "descriptor_sha256",
            value.descriptor_sha256 == expected.descriptor_sha256,
        ),
        (
            "selected_token_sha256",
            value.token_sha256 == expected.token_sha256,
        ),
        (
            "default_acl_bytes",
            value.token.default_acl_bytes == expected.default_acl_bytes,
        ),
        (
            "default_acl_sha256",
            value.token.default_acl_sha256 == expected.default_acl_sha256,
        ),
        (
            "qpc_frequency",
            value.qpc_frequency == expected.qpc_frequency,
        ),
        ("cutoff_qpc", value.cutoff_qpc == expected.cutoff_qpc),
        (
            "identity",
            expected
                .identity
                .is_none_or(|identity| identity == (value.pid, value.birth)),
        ),
    ]
}

fn summary(value: &Readback) -> serde_json::Value {
    serde_json::json!({"binding":value.binding,"descriptor_sha256":value.descriptor_sha256,
        "pid":value.pid,"birth":value.birth,"token_sha256":value.token_sha256,
        "partial_token_sha256":value.partial_token_sha256,"token":value.token,
        "cwd_identity":value.cwd_identity,"streams":value.streams,
        "started_qpc":value.started_qpc,"finished_qpc":value.finished_qpc,
        "qpc_frequency":value.qpc_frequency,"cutoff_qpc":value.cutoff_qpc})
}

/// Bounded diagnostic values only; callers still apply the original validator.
/// Environment values and raw security bytes are intentionally not duplicated.
pub fn validation_diagnostic(value: &Readback, expected: &Expected) -> serde_json::Value {
    let predicates = validation_predicates(value, expected);
    let shape_error = shape(value).err();
    let first_failed = if shape_error.is_some() {
        Some("shape")
    } else {
        predicates
            .iter()
            .find(|(_, matches)| !matches)
            .map(|(name, _)| *name)
    };
    serde_json::json!({"format":"memcordon.matched-input-failure","revision":1,
        "stage":"validate","lane":expected.binding.lane,"expected":expected,"actual":summary(value),
        "shape_error":shape_error,
        "first_failed_predicate":first_failed,
        "predicates":predicates.into_iter().map(|(name,matches)| serde_json::json!({"predicate":name,"matches":matches})).collect::<Vec<_>>()})
}

pub fn encode_diagnostic(value: &serde_json::Value) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("matched input diagnostic exceeds64KiB".into());
    }
    Ok(bytes)
}

pub fn compare_inputs(left: &Readback, right: &Readback) -> Result<(), String> {
    shape(left)?;
    shape(right)?;
    if comparison_predicates(left, right)
        .iter()
        .any(|(_, matches)| !matches)
    {
        return Err(
            "matched actual cwd, environment, streams or stable token inputs differ".into(),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub scope: Scope,
    pub physical_stream_security_equal: bool,
}

/// Eligibility for owned-file operations and selected-token comparison only.
/// Physical pipe security remains measured data; paired stdio is not assessed.
pub fn assess_inputs(
    scope: Scope,
    left: &Readback,
    right: &Readback,
) -> Result<Assessment, String> {
    match scope {
        Scope::BinaryFiles
        | Scope::Envelope
        | Scope::JointListenerPrefix
        | Scope::ProviderListenerSelection => {}
    }
    shape(left)?;
    shape(right)?;
    if scoped_predicates(scope, left, right)
        .iter()
        .any(|(_, matches)| !matches)
    {
        return Err("matched owned-file or selected-token inputs differ".into());
    }
    Ok(Assessment {
        scope,
        physical_stream_security_equal: compare_inputs(left, right).is_ok(),
    })
}

fn scoped_predicates(scope: Scope, left: &Readback, right: &Readback) -> Vec<(&'static str, bool)> {
    let mut predicates = vec![
        (
            "scope_binding",
            left.binding.scope == scope && right.binding.scope == scope,
        ),
        (
            "pair_binding",
            left.binding.pair_sha256 == right.binding.pair_sha256
                && left.binding.input_sha256 == right.binding.input_sha256,
        ),
        (
            "lane_binding",
            left.binding.lane == Lane::Direct && right.binding.lane == Lane::Installed,
        ),
        (
            "distinct_identity",
            (left.pid, left.birth) != (right.pid, right.birth),
        ),
        (
            "work_clock",
            left.qpc_frequency == right.qpc_frequency && left.cutoff_qpc == right.cutoff_qpc,
        ),
        ("cwd_utf16", left.cwd_utf16 == right.cwd_utf16),
    ];
    predicates.extend(
        comparison_predicates(left, right)
            .into_iter()
            .filter(|(name, _)| *name != "streams"),
    );
    predicates
}

fn comparison_predicates(left: &Readback, right: &Readback) -> [(&'static str, bool); 9] {
    let mut left_environment = left.environment.clone();
    let mut right_environment = right.environment.clone();
    left_environment.sort_by(|a, b| a.name.cmp(&b.name));
    right_environment.sort_by(|a, b| a.name.cmp(&b.name));
    [
        ("cwd_identity", left.cwd_identity == right.cwd_identity),
        ("environment", left_environment == right_environment),
        ("streams", left.streams == right.streams),
        (
            "token_envelope",
            left.token.envelope == right.token.envelope,
        ),
        (
            "expiration",
            left.token.expiration == right.token.expiration,
        ),
        (
            "group_count",
            left.token.group_count == right.token.group_count,
        ),
        (
            "privilege_count",
            left.token.privilege_count == right.token.privilege_count,
        ),
        (
            "default_acl_bytes",
            left.token.default_acl_bytes == right.token.default_acl_bytes,
        ),
        (
            "default_acl_sha256",
            left.token.default_acl_sha256 == right.token.default_acl_sha256,
        ),
    ]
}

pub fn comparison_diagnostic(left: &Readback, right: &Readback) -> serde_json::Value {
    let predicates = scoped_predicates(left.binding.scope, left, right);
    let direct_shape_error = shape(left).err();
    let installed_shape_error = shape(right).err();
    let first_failed = if direct_shape_error.is_some() {
        Some("direct_shape")
    } else if installed_shape_error.is_some() {
        Some("installed_shape")
    } else {
        predicates
            .iter()
            .find(|(_, matches)| !matches)
            .map(|(name, _)| *name)
    };
    serde_json::json!({"format":"memcordon.matched-input-failure","revision":2,"stage":"compare",
        "comparison_scope":"owned-file-operations-and-selected-token",
        "physical_stream_security_equal":left.streams == right.streams,
        "direct":summary(left),"installed":summary(right),
        "direct_shape_error":direct_shape_error,"installed_shape_error":installed_shape_error,
        "first_failed_predicate":first_failed,
        "predicates":predicates.into_iter().map(|(name,matches)|serde_json::json!({"predicate":name,"matches":matches})).collect::<Vec<_>>()})
}
