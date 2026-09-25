//! CI-owned pre-release observation of native SCM_RIGHTS socket custody.
//!
//! This module does not dispatch a case, validate its result, or construct Q.
//! It only acknowledges a native gate after direct Linux kernel readback.

use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};

use crate::{CiError, Result};

pub const SOCKET_SELECTOR: &str = "private_tcp::scm_rights_and_precreated_socket_denied";
const MAX_GATE_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentityV1 {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketWitnessV1 {
    schema_version: u8,
    target: ProcessIdentityV1,
    network_namespace_inode: u64,
    first_socket_device: u64,
    first_socket_inode: u64,
    second_socket_device: u64,
    second_socket_inode: u64,
    filter_sha256: DiagnosticSha256,
    sendmsg_errno: i32,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    witness: SocketWitnessV1,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SocketAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    socket_gate_sha256: DiagnosticSha256,
}

fn expected_attempt_id(key: &DiagnosticSha256) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-attempt-v1\0");
    digest.update(key.bytes());
    hex::encode(&digest.finalize()[..16])
}

fn parse_gate(
    bytes: &[u8],
    challenge: &[u8; 32],
    expected_filter: &DiagnosticSha256,
) -> Result<SocketGateV1> {
    if bytes.is_empty() || bytes.len() > MAX_GATE_BYTES {
        return Err(CiError::Message("SCM gate byte bound differs".into()));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let gate: SocketGateV1 = serde_json::from_slice(bytes)?;
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        SOCKET_SELECTOR,
        challenge,
    )
    .map_err(CiError::Message)?;
    let witness = &gate.witness;
    if gate.schema_version != 1
        || gate.selector != SOCKET_SELECTOR
        || gate.result_key != key
        || gate.challenge_sha256 != hash_bytes(challenge)
        || gate.attempt_id != expected_attempt_id(&key)
        || witness.schema_version != 1
        || witness.target.pid == 0
        || witness.target.start_time == 0
        || witness.network_namespace_inode == 0
        || witness.first_socket_inode == 0
        || witness.second_socket_inode == 0
        || (witness.first_socket_device, witness.first_socket_inode)
            == (witness.second_socket_device, witness.second_socket_inode)
        || witness.filter_sha256 != *expected_filter
        || witness.sendmsg_errno != libc::EPERM
        || serde_json::to_vec(&gate)? != bytes
    {
        return Err(CiError::Message("SCM gate fixed binding differs".into()));
    }
    Ok(gate)
}

/// Pure structural check for test vectors. A valid owner gate is not a live
/// OS observation and never constitutes native completion.
pub fn validate_socket_gate_bytes(
    bytes: &[u8],
    challenge: &[u8; 32],
    expected_filter: &DiagnosticSha256,
) -> Result<DiagnosticSha256> {
    parse_gate(bytes, challenge, expected_filter)?;
    Ok(hash_bytes(bytes))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use memcordon_core::private_release_case_v1::PRIVATE_RELEASE_RESULT_ROOT_V1;

    use super::*;
    use crate::private_protected_readback::StructuralProtectedNativeCaseV1;
    use crate::private_protected_readback::read_protected_raw_case_file;
    use crate::private_supervisor::parse_linux_child_stat;

    /// Distinct CI kernel sample retained in memory until a later raw/result
    /// contract exists. ACK publication is synchronization, not evidence.
    pub struct IndependentSocketObservationV1 {
        pub gate_sha256: DiagnosticSha256,
        pub target_pid: u32,
        pub target_start_time: u64,
        pub network_namespace_inode: u64,
        pub first_socket_device: u64,
        pub first_socket_inode: u64,
        pub second_socket_device: u64,
        pub second_socket_inode: u64,
    }

    fn observed_start_time(pid: u32) -> Result<u64> {
        let path = Path::new("/proc").join(pid.to_string()).join("stat");
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(CiError::Message(
                "SCM target stat byte bound differs".into(),
            ));
        }
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("SCM target stat is not UTF-8".into()))?;
        let (_, fields) = text
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("SCM target stat delimiter absent".into()))?;
        if matches!(
            fields.split_ascii_whitespace().next(),
            Some("Z" | "X" | "x") | None
        ) {
            return Err(CiError::Message("SCM target is not live".into()));
        }
        Ok(parse_linux_child_stat(text, pid)?.start_time_ticks)
    }

    fn observed_socket(pid: u32, slot: u32) -> Result<(u64, u64)> {
        let path = Path::new("/proc")
            .join(pid.to_string())
            .join("fd")
            .join(slot.to_string());
        let link = std::fs::symlink_metadata(&path)?;
        if !link.file_type().is_symlink() {
            return Err(CiError::Message(
                "SCM target descriptor is not proc link".into(),
            ));
        }
        let target = std::fs::read_link(&path)?;
        let text = target
            .to_str()
            .ok_or_else(|| CiError::Message("SCM socket link is not UTF-8".into()))?;
        let inode_text = text
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
            .ok_or_else(|| CiError::Message("SCM target descriptor is not socket".into()))?;
        let inode: u64 = inode_text
            .parse()
            .map_err(|_| CiError::Message("SCM socket inode differs".into()))?;
        let metadata = std::fs::metadata(&path)?;
        if !metadata.file_type().is_socket() || metadata.ino() != inode || inode == 0 {
            return Err(CiError::Message(
                "SCM socket kernel identity differs".into(),
            ));
        }
        Ok((metadata.dev(), metadata.ino()))
    }

    fn sample(
        witness: &SocketWitnessV1,
        gate_sha256: DiagnosticSha256,
    ) -> Result<IndependentSocketObservationV1> {
        let pid = witness.target.pid;
        let before = observed_start_time(pid)?;
        let net = std::fs::metadata(Path::new("/proc").join(pid.to_string()).join("ns/net"))?;
        let first = observed_socket(pid, 5)?;
        let second = observed_socket(pid, 6)?;
        let after = observed_start_time(pid)?;
        if before != witness.target.start_time
            || after != before
            || net.ino() != witness.network_namespace_inode
            || first != (witness.first_socket_device, witness.first_socket_inode)
            || second != (witness.second_socket_device, witness.second_socket_inode)
            || first == second
        {
            return Err(CiError::Message(
                "independent SCM live socket sample differs".into(),
            ));
        }
        Ok(IndependentSocketObservationV1 {
            gate_sha256,
            target_pid: pid,
            target_start_time: before,
            network_namespace_inode: net.ino(),
            first_socket_device: first.0,
            first_socket_inode: first.1,
            second_socket_device: second.0,
            second_socket_inode: second.1,
        })
    }

    fn publish_ack(directory_path: &Path, bytes: &[u8]) -> Result<()> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory_path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(CiError::Message(
                "SCM ACK directory protection differs".into(),
            ));
        }
        let temporary = directory_path.join("socket-ack.pending");
        let canonical = directory_path.join("socket-ack.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Safe atomic no-replace publication. Native waits for nlink=1 after
        // unlinking the temporary name before accepting this ACK.
        std::fs::hard_link(&temporary, &canonical)?;
        std::fs::remove_file(&temporary)?;
        directory.sync_all()?;
        if read_protected_raw_case_file(&canonical)? != bytes {
            return Err(CiError::Message(
                "SCM ACK protected readback differs".into(),
            ));
        }
        Ok(())
    }

    /// Poll this from the CI parent supervisor while its native child runs.
    /// The fixed gate must exist before any acknowledgment can be emitted.
    pub fn sample_and_ack_if_ready(
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
    ) -> Result<Option<IndependentSocketObservationV1>> {
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            SOCKET_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes = match read_protected_raw_case_file(&directory.join("socket-gate.json")) {
            Ok(bytes) => bytes,
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let gate = parse_gate(&gate_bytes, &challenge, expected_filter)?;
        let observed = sample(&gate.witness, hash_bytes(&gate_bytes))?;
        let ack = SocketAckV1 {
            schema_version: 1,
            selector: SOCKET_SELECTOR.into(),
            result_key: key,
            challenge_sha256: hash_bytes(&challenge),
            socket_gate_sha256: observed.gate_sha256.clone(),
        };
        publish_ack(&directory, &serde_json::to_vec(&ack)?)?;
        Ok(Some(observed))
    }

    /// Reopens the two extra protected leaves after detached native result
    /// publication and joins them to the separate CI kernel sample and raw
    /// owner projection. This remains non-authoritative for Q.
    pub fn join_sampled_gate_to_result(
        case: &StructuralProtectedNativeCaseV1,
        sampled: &IndependentSocketObservationV1,
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
    ) -> Result<()> {
        if case.result.selector != SOCKET_SELECTOR {
            return Err(CiError::Message("SCM result selector differs".into()));
        }
        let key_text: String = case.candidate_request.result_key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes = read_protected_raw_case_file(&directory.join("socket-gate.json"))?;
        let gate = parse_gate(&gate_bytes, &challenge, expected_filter)?;
        let ack_bytes = read_protected_raw_case_file(&directory.join("socket-ack.json"))?;
        reject_duplicate_json_keys(&ack_bytes).map_err(CiError::Message)?;
        let ack: SocketAckV1 = serde_json::from_slice(&ack_bytes)?;
        let gate_sha256 = hash_bytes(&gate_bytes);
        let witness = &gate.witness;
        let observer: serde_json::Value = serde_json::from_slice(
            case.attachments
                .get(3)
                .ok_or_else(|| CiError::Message("SCM raw observer absent".into()))?,
        )?;
        let report: serde_json::Value = serde_json::from_slice(
            case.attachments
                .get(1)
                .ok_or_else(|| CiError::Message("SCM raw report absent".into()))?,
        )?;
        if gate_sha256 != sampled.gate_sha256
            || witness.target.pid != sampled.target_pid
            || witness.target.start_time != sampled.target_start_time
            || witness.network_namespace_inode != sampled.network_namespace_inode
            || (witness.first_socket_device, witness.first_socket_inode)
                != (sampled.first_socket_device, sampled.first_socket_inode)
            || (witness.second_socket_device, witness.second_socket_inode)
                != (sampled.second_socket_device, sampled.second_socket_inode)
            || observer.get("gated_witness") != Some(&serde_json::to_value(witness)?)
            || report.get("socket_gate_sha256") != Some(&serde_json::to_value(&gate_sha256)?)
            || ack.schema_version != 1
            || ack.selector != SOCKET_SELECTOR
            || ack.result_key != case.candidate_request.result_key
            || ack.challenge_sha256 != hash_bytes(&challenge)
            || ack.socket_gate_sha256 != gate_sha256
            || serde_json::to_vec(&ack)? != ack_bytes
        {
            return Err(CiError::Message(
                "independent SCM gate/raw join differs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub struct IndependentSocketObservationV1;

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready(
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
) -> Result<Option<IndependentSocketObservationV1>> {
    Err(CiError::Message(
        "SCM live socket observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn join_sampled_gate_to_result(
    _case: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    _sampled: &IndependentSocketObservationV1,
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
) -> Result<()> {
    Err(CiError::Message(
        "SCM live socket observation requires native Linux".into(),
    ))
}
