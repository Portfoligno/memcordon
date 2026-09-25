//! Held AF_UNIX target gate. The worker records its target namespace reads,
//! then waits for CI's separate live target observation before acknowledging
//! the target. Neither gate nor ACK alone is release qualification.

use std::fs::File;
use std::time::{Duration, Instant};

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_release_child_gate::{persist_atomic, protected_directory, read_leaf};
use super::private_release_unix_intent::{
    SELECTOR, UnixAbsenceSnapshotV1, UnixIntentSupervisorAbsenceV1,
};

const GATE_LEAF: &str = "unix-intent-gate.json";
const GATE_TEMP: &str = "unix-intent-gate.pending";
const ACK_LEAF: &str = "unix-intent-ack.json";
const ACK_TEMP: &str = "unix-intent-ack.pending";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UnixIntentGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    witness: UnixIntentSupervisorAbsenceV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct UnixIntentAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    gate_sha256: DiagnosticSha256,
    observed: UnixAbsenceSnapshotV1,
}

pub(crate) fn persist_gate(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    witness: &UnixIntentSupervisorAbsenceV1,
) -> Result<DiagnosticSha256, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix gate requires protected worker".into());
    }
    protected_directory(directory)?;
    witness.verify_binding(
        challenge,
        &witness.target,
        witness.before_release.network_namespace_inode,
    )?;
    let gate = UnixIntentGateV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        witness: witness.clone(),
    };
    let bytes = serde_json::to_vec(&gate).map_err(|error| error.to_string())?;
    persist_atomic(directory, GATE_TEMP, GATE_LEAF, &bytes)?;
    if read_leaf(directory, GATE_LEAF, false)?.as_deref() != Some(bytes.as_slice()) {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix gate readback differs".into());
    }
    Ok(hash_bytes(&bytes))
}

pub(crate) fn wait_for_ci_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    witness: &UnixIntentSupervisorAbsenceV1,
    gate_sha256: &DiagnosticSha256,
    deadline: Instant,
) -> Result<(), String> {
    protected_directory(directory)?;
    loop {
        if let Some(bytes) = read_leaf(directory, ACK_LEAF, true)? {
            return verify_ack(&bytes, result_key, challenge, witness, gate_sha256);
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: Unix CI live ACK timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn readback_gate_and_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    witness: &UnixIntentSupervisorAbsenceV1,
) -> Result<(), String> {
    protected_directory(directory)?;
    if read_leaf(directory, GATE_TEMP, false)?.is_some()
        || read_leaf(directory, ACK_TEMP, false)?.is_some()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix gate interrupted write exists".into());
    }
    let gate_bytes = read_leaf(directory, GATE_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: Unix live gate absent")?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&gate_bytes)?;
    let gate: UnixIntentGateV1 =
        serde_json::from_slice(&gate_bytes).map_err(|error| error.to_string())?;
    if serde_json::to_vec(&gate).map_err(|error| error.to_string())? != gate_bytes
        || gate.schema_version != 1
        || gate.selector != SELECTOR
        || &gate.result_key != result_key
        || gate.challenge_sha256 != hash_bytes(challenge)
        || gate.witness != *witness
    {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix live gate differs".into());
    }
    let ack_bytes = read_leaf(directory, ACK_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: Unix live ACK absent")?;
    verify_ack(
        &ack_bytes,
        result_key,
        challenge,
        witness,
        &hash_bytes(&gate_bytes),
    )
}

fn verify_ack(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    witness: &UnixIntentSupervisorAbsenceV1,
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let ack: UnixIntentAckV1 = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let expected = &witness.after_denials_before_ack;
    if serde_json::to_vec(&ack).map_err(|error| error.to_string())? != bytes
        || ack.schema_version != 1
        || ack.selector != SELECTOR
        || &ack.result_key != result_key
        || ack.challenge_sha256 != hash_bytes(challenge)
        || &ack.gate_sha256 != gate_sha256
        || ack.observed.network_namespace_inode != expected.network_namespace_inode
        || ack.observed.mount_namespace_inode != expected.mount_namespace_inode
        || ack.observed.target_root_inode != expected.target_root_inode
        || ack.observed.proc_unix_sha256 == DiagnosticSha256::from_bytes([0; 32])
        || !ack.observed.pathname_absent
        || !ack.observed.abstract_absent
    {
        return Err("MCSEALED-PRIVATE-RELEASE: Unix CI live ACK differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn ack_bytes_for_test(
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
    observed: UnixAbsenceSnapshotV1,
) -> Vec<u8> {
    serde_json::to_vec(&UnixIntentAckV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        gate_sha256: gate_sha256.clone(),
        observed,
    })
    .expect("fixed Unix ACK serialization")
}

#[cfg(feature = "test-support")]
pub(crate) fn verify_ack_for_test(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    witness: &UnixIntentSupervisorAbsenceV1,
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    verify_ack(bytes, result_key, challenge, witness, gate_sha256)
}
