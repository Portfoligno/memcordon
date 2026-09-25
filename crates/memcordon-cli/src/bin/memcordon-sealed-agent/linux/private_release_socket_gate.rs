//! Protected pre-release barrier for independent observation of the two
//! precreated socket descriptors. An acknowledgment is not completion proof.

use std::fs::File;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_release_child_gate::{persist_atomic, protected_directory, read_leaf};
use super::private_release_socket_launder::{PrecreatedSocketGatedWitnessV1, SELECTOR};

pub(crate) const GATE_LEAF: &str = "socket-gate.json";
pub(crate) const ACK_LEAF: &str = "socket-ack.json";
const GATE_TEMP: &str = "socket-gate.pending";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    witness: PrecreatedSocketGatedWitnessV1,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
}

pub(crate) fn persist_gate(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    attempt_id: &str,
    witness: &PrecreatedSocketGatedWitnessV1,
) -> Result<DiagnosticSha256, String> {
    if unsafe { libc::geteuid() } != 0
        || attempt_id.is_empty()
        || witness.schema_version != 1
        || witness.sendmsg_errno != libc::EPERM
        || witness.first_socket_inode == 0
        || witness.second_socket_inode == 0
        || (witness.first_socket_device, witness.first_socket_inode)
            == (witness.second_socket_device, witness.second_socket_inode)
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket gate authority differs".into());
    }
    protected_directory(directory)?;
    let bytes = serde_json::to_vec(&SocketGateV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        attempt_id: attempt_id.into(),
        witness: witness.clone(),
    })
    .map_err(|error| error.to_string())?;
    persist_atomic(directory, GATE_TEMP, GATE_LEAF, &bytes)?;
    if read_leaf(directory, GATE_LEAF, false)?.as_deref() != Some(bytes.as_slice()) {
        return Err("MCSEALED-PRIVATE-RELEASE: socket gate readback differs".into());
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
            return Err("MCSEALED-PRIVATE-RELEASE: socket CI observation timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn readback_gate_and_ack(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    attempt_id: &str,
    witness: &PrecreatedSocketGatedWitnessV1,
) -> Result<DiagnosticSha256, String> {
    protected_directory(directory)?;
    let bytes = read_leaf(directory, GATE_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: socket gate absent")?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let gate: SocketGateV1 = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if gate.schema_version != 1
        || gate.selector != SELECTOR
        || &gate.result_key != result_key
        || gate.challenge_sha256 != hash_bytes(challenge)
        || gate.attempt_id != attempt_id
        || &gate.witness != witness
        || serde_json::to_vec(&gate).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket gate differs".into());
    }
    let digest = hash_bytes(&bytes);
    let ack = read_leaf(directory, ACK_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: socket acknowledgment absent")?;
    verify_ack_bytes(&ack, result_key, challenge, &digest)?;
    Ok(digest)
}

fn verify_ack_bytes(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let ack: SocketAckV1 = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if ack.schema_version != 1
        || ack.selector != SELECTOR
        || &ack.result_key != result_key
        || ack.challenge_sha256 != hash_bytes(challenge)
        || &ack.socket_gate_sha256 != gate_sha256
        || serde_json::to_vec(&ack).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: socket acknowledgment differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn ack_bytes_for_test(
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Vec<u8> {
    serde_json::to_vec(&SocketAckV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        socket_gate_sha256: gate_sha256.clone(),
    })
    .expect("fixed socket ack serialization")
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
