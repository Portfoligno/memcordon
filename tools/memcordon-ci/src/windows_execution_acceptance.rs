//! Named installed Windows execution cases and bounded native identity streams.

use crate::windows_causal_acceptance::FixtureProcessIdentityV1;
use crate::{CiError, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const IDENTITY_STREAM_BYTES: usize = 2 * 1024 * 1024;
pub const CASE_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WindowsExecutionCaseV2 {
    Concurrent257,
    SequentialChurn4096,
    ShortLivedBursts,
    IdentityAccessDenied,
    ReplayAckLoss,
}
impl WindowsExecutionCaseV2 {
    pub const ALL: [Self; CASE_COUNT] = [
        Self::Concurrent257,
        Self::SequentialChurn4096,
        Self::ShortLivedBursts,
        Self::IdentityAccessDenied,
        Self::ReplayAckLoss,
    ];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Concurrent257 => "concurrent-257",
            Self::SequentialChurn4096 => "sequential-churn-4096",
            Self::ShortLivedBursts => "short-lived-bursts",
            Self::IdentityAccessDenied => "identity-access-denied",
            Self::ReplayAckLoss => "replay-ack-loss",
        }
    }
    pub const fn fixture_mode(self) -> &'static str {
        match self {
            Self::Concurrent257 => "windows-concurrent-257",
            Self::SequentialChurn4096 => "windows-sequential-churn-4096",
            Self::ShortLivedBursts => "windows-short-lived-bursts",
            Self::IdentityAccessDenied => "windows-identity-access-denied",
            Self::ReplayAckLoss => "windows-replay-ack-loss",
        }
    }
    pub const fn is_success(self) -> bool {
        !matches!(self, Self::IdentityAccessDenied)
    }
    pub const fn family_size(self) -> usize {
        match self {
            Self::Concurrent257 => 257,
            Self::SequentialChurn4096 => 4097,
            Self::ShortLivedBursts => 1025,
            Self::IdentityAccessDenied => 2,
            Self::ReplayAckLoss => 1,
        }
    }
}
fn error(message: impl Into<String>) -> CiError {
    CiError::Message(message.into())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureReadiness {
    kind: String,
    ordinal: Option<usize>,
    pid: u32,
    birth: u128,
}

pub fn validate_identity_stream(case: WindowsExecutionCaseV2, bytes: &[u8]) -> Result<()> {
    if bytes.len() > IDENTITY_STREAM_BYTES || !bytes.ends_with(b"\n") {
        return Err(error("identity stream is oversized or unterminated"));
    }
    let mut root_seen = false;
    let mut ordinals = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut count = 0usize;
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if count == case.family_size() {
            return Err(error("identity stream exceeds scenario count"));
        }
        let identity: FixtureProcessIdentityV1 = serde_json::from_slice(line)?;
        if identity.pid == 0
            || identity.birth == 0
            || !identities.insert((identity.pid, identity.birth))
        {
            return Err(error(
                "identity stream has invalid or repeated process identity",
            ));
        }
        match identity.ordinal {
            Some(ordinal) if ordinal < case.family_size() - 1 => {
                if !ordinals.insert(ordinal) {
                    return Err(error("identity stream repeats a child ordinal"));
                }
            }
            None if !root_seen => root_seen = true,
            _ => return Err(error("identity stream has invalid ordinal")),
        }
        count += 1;
    }
    if !root_seen || count != case.family_size() || ordinals.len() + 1 != count {
        return Err(error("identity stream is incomplete"));
    }
    Ok(())
}
/// Extract independent fixture identities without projecting provider observations.
pub fn identity_stream_from_stdout(case: WindowsExecutionCaseV2, stdout: &[u8]) -> Result<Vec<u8>> {
    const READY: &[u8] = b"MEMCORDON-INVENTORY-READY:";
    const RETAINED: &[u8] = b"MEMCORDON-INVENTORY-RETAINED:";
    if stdout.len() > IDENTITY_STREAM_BYTES {
        return Err(error("installed fixture readiness output exceeds bound"));
    }
    let mut stream = Vec::new();
    for line in stdout.split(|byte| *byte == b'\n') {
        let Some(payload) = line.strip_prefix(READY) else {
            continue;
        };
        let value: FixtureReadiness = serde_json::from_slice(payload)?;
        if !matches!(
            (value.kind.as_str(), value.ordinal),
            ("inventory-root-ready", None) | ("inventory-leaf-ready", Some(_))
        ) {
            return Err(error("installed fixture readiness marker has wrong kind"));
        }
        let identity = FixtureProcessIdentityV1 {
            ordinal: value.ordinal,
            pid: value.pid,
            birth: value.birth,
        };
        serde_json::to_writer(&mut stream, &identity)?;
        stream.push(b'\n');
    }
    if case == WindowsExecutionCaseV2::IdentityAccessDenied
        && !stdout.split(|byte| *byte == b'\n').any(|line| {
            line.strip_prefix(RETAINED)
                .and_then(|payload| serde_json::from_slice::<serde_json::Value>(payload).ok())
                .is_some()
        })
    {
        return Err(error("identity denial lacks independently retained handle"));
    }
    validate_identity_stream(case, &stream)?;
    Ok(stream)
}
