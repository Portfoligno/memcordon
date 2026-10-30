//! Explicit diagnostic replay transport, separate from the authoritative wire.
use super::protocol::{Cell, Request, SourceObservation, SourceRole, encode_request};
use memcordon_windows_launch_core::ObservationUnavailable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "namespace replay wire refused")
}
fn nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayEnvelope {
    pub format: String,
    pub revision: u32,
    pub original_nonce: String,
    pub replay_nonce: String,
    pub request: Request,
    pub request_sha256: String,
    pub diagnostic_stop_qpc: u64,
    pub source_commit: Option<String>,
    pub run: Option<String>,
    pub attempt: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayResult {
    pub format: String,
    pub revision: u32,
    pub original_nonce: String,
    pub replay_nonce: String,
    pub diagnostic_stop_qpc: u64,
    pub request_sha256: String,
    pub outcome: ReplayOutcome,
    pub cleanup: ReplayCleanup,
    pub diagnostic_only: bool,
    pub acceptance_authority: bool,
}
pub type SourceCapture = Result<SourceObservation, ObservationUnavailable>;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReplayOutcome {
    NamespaceFailed {
        raw_error: i32,
        before: SourceCapture,
    },
    EventReturned {
        event_open: bool,
        raw_error: Option<i32>,
        before: SourceCapture,
        after: ReplayAfter,
    },
    CallNotAttempted {
        reason: NotAttemptedReason,
        observed_qpc: u64,
        before: Option<SourceCapture>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotAttemptedReason {
    DiagnosticStopBeforePre,
    DiagnosticStopAfterPre,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ReplayAfter {
    Observed { observation: Box<SourceObservation> },
    Unavailable { reason: ObservationUnavailable },
    SkippedDiagnosticStop,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReplayCleanup {
    Closed,
}

pub fn replay_digest(request: &Request) -> io::Result<String> {
    Ok(Sha256::digest(encode_request(request)?)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
pub fn event_name(request: &Request) -> io::Result<Vec<u16>> {
    encode_request(request)?;
    let mut name = if request.cell == Cell::Local {
        "Local\\".encode_utf16().collect::<Vec<_>>()
    } else {
        request.alias.encode_utf16().chain(Some(92)).collect()
    };
    name.extend(request.event.encode_utf16());
    name.push(0);
    Ok(name)
}
pub fn check_replay_command_line(command: &[u16]) -> io::Result<()> {
    if command.is_empty()
        || command.len() > 32767
        || command.last() != Some(&0)
        || command[..command.len() - 1].contains(&0)
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn encode_replay(value: &ReplayEnvelope) -> io::Result<String> {
    if value.format != "memcordon.namespace-debug-replay"
        || value.revision != 2
        || value.diagnostic_stop_qpc == 0
        || value.diagnostic_stop_qpc >= value.request.deadline_qpc
        || value.original_nonce != value.request.nonce
        || value.replay_nonce == value.original_nonce
        || !nonce(&value.replay_nonce)
        || value.request_sha256 != replay_digest(&value.request)?
    {
        return Err(invalid());
    }
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > 32768 {
        return Err(invalid());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}
pub fn decode_replay(encoded: &str) -> io::Result<ReplayEnvelope> {
    if encoded.len() > 65536 || encoded.len() % 2 != 0 {
        return Err(invalid());
    }
    let bytes = encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(invalid()),
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect::<io::Result<Vec<u8>>>()?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(|_| invalid())?;
    let value: ReplayEnvelope = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if encode_replay(&value)? != encoded {
        return Err(invalid());
    }
    Ok(value)
}
pub fn validate_replay_result(value: &ReplayResult, envelope: &ReplayEnvelope) -> io::Result<()> {
    encode_replay(envelope)?;
    if value.format != "memcordon.namespace-debug-replay-result"
        || value.revision != 2
        || value.original_nonce != envelope.original_nonce
        || value.replay_nonce != envelope.replay_nonce
        || value.diagnostic_stop_qpc != envelope.diagnostic_stop_qpc
        || value.request_sha256 != envelope.request_sha256
        || !value.diagnostic_only
        || value.acceptance_authority
    {
        return Err(invalid());
    }
    let (before, after) = match &value.outcome {
        ReplayOutcome::NamespaceFailed { before, .. } => (Some(before), None),
        ReplayOutcome::EventReturned {
            event_open,
            raw_error,
            before,
            after,
        } => {
            if *event_open != raw_error.is_none() {
                return Err(invalid());
            }
            (
                Some(before),
                match after {
                    ReplayAfter::Observed { observation } => Some(observation.as_ref()),
                    _ => None,
                },
            )
        }
        ReplayOutcome::CallNotAttempted {
            reason,
            observed_qpc,
            before,
        } => {
            if *observed_qpc < envelope.diagnostic_stop_qpc
                || (matches!(reason, NotAttemptedReason::DiagnosticStopAfterPre)
                    && before.is_none())
            {
                return Err(invalid());
            }
            (before.as_ref(), None)
        }
    };
    for (observation, role) in [
        (
            before.and_then(|capture| capture.as_ref().ok()),
            SourceRole::BeforeOpen,
        ),
        (after, SourceRole::ReplayAfter),
    ] {
        if let Some(observation) = observation {
            observation.validate()?;
            if observation.role != role
                || observation.started_qpc >= envelope.diagnostic_stop_qpc
                || observation.finished_qpc >= envelope.diagnostic_stop_qpc
                || observation.token.envelope != envelope.request.expected_token
                || observation.default_acl_sha256 != envelope.request.expected_default_acl_sha256
            {
                return Err(invalid());
            }
        }
    }
    if let (Some(Ok(before)), Some(after)) = (before, after) {
        if before.finished_qpc > after.started_qpc {
            return Err(invalid());
        }
    }
    Ok(())
}
pub fn encode_replay_result(
    value: &ReplayResult,
    envelope: &ReplayEnvelope,
) -> io::Result<Vec<u8>> {
    validate_replay_result(value, envelope)?;
    let mut bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    bytes.push(b'\n');
    if bytes.len() > 65536 {
        return Err(invalid());
    }
    Ok(bytes)
}
pub fn decode_replay_result(bytes: &[u8], envelope: &ReplayEnvelope) -> io::Result<ReplayResult> {
    if bytes.len() > 65536 || bytes.last() != Some(&b'\n') {
        return Err(invalid());
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(|_| invalid())?;
    let value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    validate_replay_result(&value, envelope)?;
    if encode_replay_result(&value, envelope)? != bytes {
        return Err(invalid());
    }
    Ok(value)
}
