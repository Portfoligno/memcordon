//! Protected two-target live midpoint. CI must independently sample both
//! kernel targets and publish the exact ACK before either target is released.

use std::fs::File;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use super::private_release_attempt::{
    MidflightTerminalJoinReadbackV1, ReleaseCandidateReadbackExpectationV1,
    parse_midflight_dual_journal_bytes,
};
use super::private_release_child_gate::{persist_atomic, protected_directory, read_leaf};
use super::private_release_dual_attempt::{self, SELECTOR};

const FIRST_MIDFLIGHT: &str = "dual-first-midflight.json";
const FIRST_PENDING: &str = "dual-first-midflight.pending";
const SECOND_MIDFLIGHT: &str = "dual-second-midflight.json";
const SECOND_PENDING: &str = "dual-second-midflight.pending";
const GATE_LEAF: &str = "dual-live-gate.json";
const GATE_PENDING: &str = "dual-live-gate.pending";
const ACK_LEAF: &str = "dual-live-ack.json";

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualLiveBranchV1 {
    pub(crate) subattempt_key: DiagnosticSha256,
    pub(crate) attempt_id: String,
    pub(crate) target: ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) listener_socket_inode: u64,
    pub(crate) checkpoint_sha256: DiagnosticSha256,
    pub(crate) execution_record_digest: DiagnosticSha256,
    pub(crate) midflight_bytes_sha256: DiagnosticSha256,
    pub(crate) filter_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DualLiveGateV1 {
    pub(crate) schema_version: u8,
    pub(crate) selector: String,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) port: u16,
    pub(crate) first: DualLiveBranchV1,
    pub(crate) second: DualLiveBranchV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DualLiveAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    dual_gate_sha256: DiagnosticSha256,
}

pub(crate) struct DualLiveWitnessV1<'a> {
    pub(crate) target: &'a ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) listener_socket_inode: u64,
    pub(crate) midflight: &'a MidflightTerminalJoinReadbackV1,
}

pub(crate) struct DualLiveHostObservationV1 {
    pub(crate) target: ProcessIdentityV4,
    pub(crate) network_namespace_inode: u64,
    pub(crate) listener_socket_inode: u64,
}

pub(crate) struct DualLiveGateReadbackV1 {
    pub(crate) gate: DualLiveGateV1,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) first_midflight: MidflightTerminalJoinReadbackV1,
    pub(crate) second_midflight: MidflightTerminalJoinReadbackV1,
}

pub(crate) fn persist_gate(
    directory: &File,
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    first: DualLiveWitnessV1<'_>,
    second: DualLiveWitnessV1<'_>,
) -> Result<DiagnosticSha256, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: dual gate requires root".into());
    }
    protected_directory(directory)?;
    let first_key = private_release_dual_attempt::subattempt_key(
        result_key,
        private_release_dual_attempt::DualAttemptRoleV1::First,
    );
    let second_key = private_release_dual_attempt::subattempt_key(
        result_key,
        private_release_dual_attempt::DualAttemptRoleV1::Second,
    );
    let first_branch = checked_branch(first_key, &first)?;
    let second_branch = checked_branch(second_key, &second)?;
    let port = private_release_dual_attempt::fixed_port(challenge);
    if first_branch.target == second_branch.target
        || first_branch.network_namespace_inode == second_branch.network_namespace_inode
        || first_branch.attempt_id == second_branch.attempt_id
        || first_branch.listener_socket_inode == second_branch.listener_socket_inode
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual live branches overlap".into());
    }
    persist_atomic(
        directory,
        FIRST_PENDING,
        FIRST_MIDFLIGHT,
        &first.midflight.execution_record_bytes,
    )?;
    persist_atomic(
        directory,
        SECOND_PENDING,
        SECOND_MIDFLIGHT,
        &second.midflight.execution_record_bytes,
    )?;
    let gate = DualLiveGateV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        port,
        first: first_branch,
        second: second_branch,
    };
    let bytes = serde_json::to_vec(&gate).map_err(|error| error.to_string())?;
    persist_atomic(directory, GATE_PENDING, GATE_LEAF, &bytes)?;
    if read_leaf(directory, FIRST_MIDFLIGHT, false)?.as_deref()
        != Some(first.midflight.execution_record_bytes.as_slice())
        || read_leaf(directory, SECOND_MIDFLIGHT, false)?.as_deref()
            != Some(second.midflight.execution_record_bytes.as_slice())
        || read_leaf(directory, GATE_LEAF, false)?.as_deref() != Some(bytes.as_slice())
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual gate readback differs".into());
    }
    Ok(hash_bytes(&bytes))
}

fn checked_branch(
    key: DiagnosticSha256,
    witness: &DualLiveWitnessV1<'_>,
) -> Result<DualLiveBranchV1, String> {
    let midflight = witness.midflight;
    if midflight.target != *witness.target
        || midflight.attempt_id != super::private_release_attempt::candidate_attempt_id(&key)
        || witness.network_namespace_inode != midflight.network_namespace_inode
        || witness.listener_socket_inode == 0
        || midflight.execution_record_bytes.is_empty()
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual branch witness differs".into());
    }
    Ok(DualLiveBranchV1 {
        subattempt_key: key,
        attempt_id: midflight.attempt_id.clone(),
        target: witness.target.clone(),
        network_namespace_inode: witness.network_namespace_inode,
        listener_socket_inode: witness.listener_socket_inode,
        checkpoint_sha256: midflight.checkpoint_digest.clone(),
        execution_record_digest: midflight.execution_record_digest.clone(),
        midflight_bytes_sha256: hash_bytes(&midflight.execution_record_bytes),
        filter_sha256: midflight.filter_sha256.clone(),
    })
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
            return Err("MCSEALED-PRIVATE-RELEASE: dual CI ack timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

pub(crate) fn readback_gate_and_ack(
    directory: &File,
    parent_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    first_expected: &ReleaseCandidateReadbackExpectationV1<'_>,
    second_expected: &ReleaseCandidateReadbackExpectationV1<'_>,
) -> Result<DualLiveGateReadbackV1, String> {
    protected_directory(directory)?;
    if first_expected.selector != SELECTOR
        || second_expected.selector != SELECTOR
        || first_expected.result_key
            != &private_release_dual_attempt::subattempt_key(
                parent_key,
                private_release_dual_attempt::DualAttemptRoleV1::First,
            )
        || second_expected.result_key
            != &private_release_dual_attempt::subattempt_key(
                parent_key,
                private_release_dual_attempt::DualAttemptRoleV1::Second,
            )
        || first_expected.challenge != challenge
        || second_expected.challenge != challenge
        || first_expected.installation_epoch != second_expected.installation_epoch
        || first_expected.candidate_manifest_sha256 != second_expected.candidate_manifest_sha256
        || first_expected.service_generation_sha256 != second_expected.service_generation_sha256
        || first_expected.coordinator != second_expected.coordinator
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual gate expectations differ".into());
    }
    let first_bytes = read_leaf(directory, FIRST_MIDFLIGHT, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: first dual midflight absent")?;
    let second_bytes = read_leaf(directory, SECOND_MIDFLIGHT, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: second dual midflight absent")?;
    let first_midflight = parse_midflight_dual_journal_bytes(&first_bytes, first_expected)?;
    let second_midflight = parse_midflight_dual_journal_bytes(&second_bytes, second_expected)?;
    let gate_bytes = read_leaf(directory, GATE_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: dual live gate absent")?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&gate_bytes)?;
    let gate: DualLiveGateV1 =
        serde_json::from_slice(&gate_bytes).map_err(|error| error.to_string())?;
    if gate.schema_version != 1
        || gate.selector != SELECTOR
        || &gate.result_key != parent_key
        || gate.challenge_sha256 != hash_bytes(challenge)
        || gate.port != private_release_dual_attempt::fixed_port(challenge)
        || gate.first.subattempt_key != *first_expected.result_key
        || gate.second.subattempt_key != *second_expected.result_key
        || gate.first.target == gate.second.target
        || gate.first.attempt_id == gate.second.attempt_id
        || gate.first.network_namespace_inode == gate.second.network_namespace_inode
        || gate.first.listener_socket_inode == gate.second.listener_socket_inode
        || !branch_matches(&gate.first, &first_midflight, &first_bytes)
        || !branch_matches(&gate.second, &second_midflight, &second_bytes)
        || serde_json::to_vec(&gate).map_err(|error| error.to_string())? != gate_bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual live gate differs".into());
    }
    let gate_sha256 = hash_bytes(&gate_bytes);
    let ack = read_leaf(directory, ACK_LEAF, false)?
        .ok_or("MCSEALED-PRIVATE-RELEASE: dual live acknowledgment absent")?;
    verify_ack_bytes(&ack, parent_key, challenge, &gate_sha256)?;
    Ok(DualLiveGateReadbackV1 {
        gate,
        gate_sha256,
        first_midflight,
        second_midflight,
    })
}

fn branch_matches(
    branch: &DualLiveBranchV1,
    midflight: &MidflightTerminalJoinReadbackV1,
    bytes: &[u8],
) -> bool {
    branch.attempt_id == midflight.attempt_id
        && branch.target == midflight.target
        && branch.network_namespace_inode == midflight.network_namespace_inode
        && branch.listener_socket_inode != 0
        && branch.checkpoint_sha256 == midflight.checkpoint_digest
        && branch.execution_record_digest == midflight.execution_record_digest
        && branch.midflight_bytes_sha256 == hash_bytes(bytes)
        && branch.filter_sha256 == midflight.filter_sha256
}

#[cfg(feature = "test-support")]
pub(crate) fn branch_matches_for_test(
    branch: &DualLiveBranchV1,
    midflight: &MidflightTerminalJoinReadbackV1,
    bytes: &[u8],
) -> bool {
    branch_matches(branch, midflight, bytes)
}

fn verify_ack_bytes(
    bytes: &[u8],
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let ack: DualLiveAckV1 = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if ack.schema_version != 1
        || ack.selector != SELECTOR
        || &ack.result_key != result_key
        || ack.challenge_sha256 != hash_bytes(challenge)
        || &ack.dual_gate_sha256 != gate_sha256
        || serde_json::to_vec(&ack).map_err(|error| error.to_string())? != bytes
    {
        return Err("MCSEALED-PRIVATE-RELEASE: dual CI acknowledgment differs".into());
    }
    Ok(())
}

#[cfg(feature = "test-support")]
pub(crate) fn ack_bytes_for_test(
    result_key: &DiagnosticSha256,
    challenge: &[u8; 32],
    gate_sha256: &DiagnosticSha256,
) -> Vec<u8> {
    serde_json::to_vec(&DualLiveAckV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: result_key.clone(),
        challenge_sha256: hash_bytes(challenge),
        dual_gate_sha256: gate_sha256.clone(),
    })
    .expect("fixed dual ack serialization")
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
