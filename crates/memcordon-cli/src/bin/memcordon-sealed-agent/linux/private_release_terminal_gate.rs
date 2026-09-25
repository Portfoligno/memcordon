//! Protected post-release midpoint. The target stays live until CI observes
//! it independently and acknowledges this exact persisted ExecObserved state.
//! These leaves are not a terminal result or qualification authority.

use std::fs::File;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_attempt::{
    MidflightTerminalJoinReadbackV1, ReleaseCandidateReadbackExpectationV1,
    parse_midflight_terminal_join_journal_bytes,
};
use super::private_release_child_gate::{persist_atomic, protected_directory, read_leaf};
use super::private_release_terminal_join::SELECTOR;

const MIDFLIGHT_LEAF: &str = "terminal-join-midflight.json";
const MIDFLIGHT_TEMP: &str = "terminal-join-midflight.pending";
const GATE_LEAF: &str = "terminal-join-gate.json";
const GATE_TEMP: &str = "terminal-join-gate.pending";
const ACK_LEAF: &str = "terminal-join-ack.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    target: ProcessIdentityV4,
    checkpoint_sha256: DiagnosticSha256,
    execution_record_digest: DiagnosticSha256,
    midflight_bytes_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
}

pub(crate) fn persist_gate(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    midflight: &MidflightTerminalJoinReadbackV1,
    live_target: &ProcessIdentityV4,
) -> Result<DiagnosticSha256, String> {
    if unsafe { libc::geteuid() } != 0
        || midflight.target != *live_target
        || midflight.attempt_id.is_empty()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join gate authority differs".into());
    }
    protected_directory(directory)?;
    persist_atomic(
        directory,
        MIDFLIGHT_TEMP,
        MIDFLIGHT_LEAF,
        &midflight.execution_record_bytes,
    )?;
    let bytes = serde_json::to_vec(&TerminalJoinGateV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        attempt_id: midflight.attempt_id.clone(),
        target: live_target.clone(),
        checkpoint_sha256: midflight.checkpoint_digest.clone(),
        execution_record_digest: midflight.execution_record_digest.clone(),
        midflight_bytes_sha256: hash_bytes(&midflight.execution_record_bytes),
        filter_sha256: midflight.filter_sha256.clone(),
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, GATE_TEMP, GATE_LEAF, &bytes)?;
    if read_leaf(directory, GATE_LEAF, false)?.as_deref() != Some(bytes.as_slice())
        || read_leaf(directory, MIDFLIGHT_LEAF, false)?.as_deref()
            != Some(midflight.execution_record_bytes.as_slice())
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join gate readback differs".into());
    }
    Ok(hash_bytes(&bytes))
}

pub(crate) fn wait_for_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
    deadline: Instant,
) -> Result<(), String> {
    protected_directory(directory)?;
    loop {
        if let Some(bytes) = read_leaf(directory, ACK_LEAF, true)? {
            return verify_ack_bytes(&bytes, result_key, challenge, gate_sha256);
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join CI ack timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn readback_gate_and_ack(
    directory: &File,
    expected: &ReleaseCandidateReadbackExpectationV1<'_>,
    terminal_target: &ProcessIdentityV4,
    terminal_checkpoint: &DiagnosticSha256,
    terminal_filter: &DiagnosticSha256,
) -> Result<(DiagnosticSha256, DiagnosticSha256), String> {
    protected_directory(directory)?;
    let midflight_bytes = read_leaf(directory, MIDFLIGHT_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join midflight absent")?;
    let midflight = parse_midflight_terminal_join_journal_bytes(&midflight_bytes, expected)?;
    let gate_bytes = read_leaf(directory, GATE_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join gate absent")?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&gate_bytes)?;
    let gate: TerminalJoinGateV1 =
        serde_json::from_slice(&gate_bytes).map_err(|error| error.to_string())?;
    if gate.schema_version != 1
        || gate.selector != SELECTOR
        || &gate.result_key != expected.result_key
        || gate.challenge_sha256 != hash_bytes(expected.challenge)
        || gate.attempt_id != midflight.attempt_id
        || gate.target != midflight.target
        || &gate.target != terminal_target
        || gate.checkpoint_sha256 != midflight.checkpoint_digest
        || &gate.checkpoint_sha256 != terminal_checkpoint
        || gate.execution_record_digest != midflight.execution_record_digest
        || gate.midflight_bytes_sha256 != hash_bytes(&midflight_bytes)
        || gate.filter_sha256 != midflight.filter_sha256
        || &gate.filter_sha256 != terminal_filter
        || serde_json::to_vec(&gate).map_err(|error| error.to_string())? != gate_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join gate differs".into());
    }
    let digest = hash_bytes(&gate_bytes);
    let ack = read_leaf(directory, ACK_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join acknowledgment absent")?;
    verify_ack_bytes(&ack, expected.result_key, expected.challenge, &digest)?;
    Ok((digest, midflight.execution_record_digest))
}

fn verify_ack_bytes(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let ack: TerminalJoinAckV1 =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if ack.schema_version != 1
        || ack.selector != SELECTOR
        || &ack.result_key != result_key
        || ack.challenge_sha256 != hash_bytes(challenge)
        || &ack.terminal_join_gate_sha256 != gate_sha256
        || serde_json::to_vec(&ack).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join acknowledgment differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn ack_bytes_for_test(
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Vec<u8> {
    serde_json::to_vec(&TerminalJoinAckV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        terminal_join_gate_sha256: gate_sha256.clone(),
    })
    .expect("fixed terminal-join ack serialization")
}

#[cfg(feature = "test-support")]
pub(crate) fn verify_ack_for_test(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    verify_ack_bytes(bytes, result_key, challenge, gate_sha256)
}
