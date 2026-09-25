//! CI-owned post-release midpoint observation. The target remains held while
//! the CI parent samples procfs/cgroupfs; an ACK is not terminal proof or Q.

use memcordon_core::DiagnosticSha256;
#[cfg(target_os = "linux")]
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};

use crate::private_protected_readback::StructuralTerminalMidflightV1;
use crate::{CiError, Result};

pub const TERMINAL_JOIN_SELECTOR: &str = "private_tcp::release_checkpoint_terminal_joined";
const MAX_GATE_BYTES: usize = 8192;

pub struct IndependentTerminalMidpointV1 {
    pub gate_sha256: DiagnosticSha256,
    pub midflight_sha256: DiagnosticSha256,
    pub target_pid: u32,
    pub target_start_time: u64,
    pub network_namespace_inode: u64,
    pub image_device: u64,
    pub image_inode: u64,
    pub cgroup_procs_sha256: DiagnosticSha256,
    pub target_pid_chain: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentityV1 {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    target: ProcessIdentityV1,
    checkpoint_sha256: DiagnosticSha256,
    execution_record_digest: DiagnosticSha256,
    midflight_bytes_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TerminalJoinAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    terminal_join_gate_sha256: DiagnosticSha256,
}

fn parse_gate(
    bytes: &[u8],
    key: &DiagnosticSha256,
    challenge: [u8; 32],
    midflight: &StructuralTerminalMidflightV1,
    midflight_bytes: &[u8],
    expected_filter: &DiagnosticSha256,
) -> Result<TerminalJoinGateV1> {
    if bytes.is_empty() || bytes.len() > MAX_GATE_BYTES {
        return Err(CiError::Message("terminal gate byte bound differs".into()));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let gate: TerminalJoinGateV1 = serde_json::from_slice(bytes)?;
    if gate.schema_version != 1
        || gate.selector != TERMINAL_JOIN_SELECTOR
        || &gate.result_key != key
        || gate.challenge_sha256 != hash_bytes(&challenge)
        || gate.attempt_id != midflight.attempt_id
        || gate.target.pid != midflight.target.pid
        || gate.target.start_time != midflight.target.start_time
        || gate.target.pid == 0
        || gate.target.start_time == 0
        || gate.checkpoint_sha256 != midflight.checkpoint_sha256
        || gate.execution_record_digest != midflight.execution_record_digest
        || gate.midflight_bytes_sha256 != hash_bytes(midflight_bytes)
        || gate.filter_sha256 != midflight.filter_sha256
        || &gate.filter_sha256 != expected_filter
        || serde_json::to_vec(&gate)? != bytes
    {
        return Err(CiError::Message("terminal midpoint gate differs".into()));
    }
    Ok(gate)
}

/// Pure structural vector check. Even valid bytes do not prove a live target.
pub fn validate_terminal_gate_bytes(
    bytes: &[u8],
    key: &DiagnosticSha256,
    challenge: [u8; 32],
    midflight: &StructuralTerminalMidflightV1,
    midflight_bytes: &[u8],
    expected_filter: &DiagnosticSha256,
) -> Result<DiagnosticSha256> {
    parse_gate(
        bytes,
        key,
        challenge,
        midflight,
        midflight_bytes,
        expected_filter,
    )?;
    Ok(hash_bytes(bytes))
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use memcordon_core::private_release_case_v1::PRIVATE_RELEASE_RESULT_ROOT_V1;

    use super::*;
    use crate::private_protected_readback::{
        StructuralProtectedNativeCaseV1, parse_protected_candidate_request,
        parse_protected_terminal_midflight, read_protected_raw_case_file,
    };
    use crate::private_supervisor::parse_linux_child_stat;

    fn read_bounded(path: &Path) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file).take(4097).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(CiError::Message(
                "terminal live kernel bound differs".into(),
            ));
        }
        Ok(bytes)
    }

    fn live_start(pid: u32) -> Result<u64> {
        let bytes = read_bounded(&Path::new("/proc").join(pid.to_string()).join("stat"))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("terminal live stat is not UTF-8".into()))?;
        let (_, fields) = text
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("terminal live stat delimiter absent".into()))?;
        if matches!(
            fields.split_ascii_whitespace().next(),
            Some("Z" | "X" | "x") | None
        ) {
            return Err(CiError::Message(
                "terminal midpoint target is not live".into(),
            ));
        }
        Ok(parse_linux_child_stat(text, pid)?.start_time_ticks)
    }

    fn live_pid_chain(pid: u32) -> Result<Vec<u32>> {
        let bytes = read_bounded(&Path::new("/proc").join(pid.to_string()).join("status"))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("terminal live status is not UTF-8".into()))?;
        let mut chain = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("NSpid:") {
                let ids: Vec<u32> = value
                    .split_ascii_whitespace()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|_| CiError::Message("terminal live NSpid differs".into()))?;
                if ids.is_empty()
                    || ids.len() > 8
                    || ids.contains(&0)
                    || chain.replace(ids).is_some()
                {
                    return Err(CiError::Message("terminal live NSpid chain differs".into()));
                }
            }
        }
        let chain = chain.ok_or_else(|| CiError::Message("terminal live NSpid absent".into()))?;
        if chain.first() != Some(&pid) {
            return Err(CiError::Message(
                "terminal live host PID chain differs".into(),
            ));
        }
        Ok(chain)
    }

    fn sample(
        midflight: &StructuralTerminalMidflightV1,
        expected_image: (u64, u64),
        gate_sha256: DiagnosticSha256,
        midflight_sha256: DiagnosticSha256,
    ) -> Result<IndependentTerminalMidpointV1> {
        let pid = midflight.target.pid;
        let proc = Path::new("/proc").join(pid.to_string());
        let before = live_start(pid)?;
        let target_pid_chain = live_pid_chain(pid)?;
        let net = std::fs::metadata(proc.join("ns/net"))?;
        let image = std::fs::metadata(proc.join("exe"))?;
        let cgroup = Path::new("/sys/fs/cgroup/memcordon-sealed")
            .join(&midflight.attempt_id)
            .join("cgroup.procs");
        let procs = read_bounded(&cgroup)?;
        let text = std::str::from_utf8(&procs)
            .map_err(|_| CiError::Message("terminal cgroup list is not UTF-8".into()))?;
        let mut present = false;
        for line in text.lines() {
            let member: u32 = line
                .parse()
                .map_err(|_| CiError::Message("terminal cgroup member differs".into()))?;
            if member == 0 {
                return Err(CiError::Message("terminal cgroup has zero PID".into()));
            }
            present |= member == pid;
        }
        if before != midflight.target.start_time
            || live_start(pid)? != before
            || live_pid_chain(pid)? != target_pid_chain
            || net.ino() != midflight.network_namespace_inode
            || (image.dev(), image.ino()) != expected_image
            || !present
        {
            return Err(CiError::Message(
                "independent terminal live sample differs".into(),
            ));
        }
        Ok(IndependentTerminalMidpointV1 {
            gate_sha256,
            midflight_sha256,
            target_pid: pid,
            target_start_time: before,
            network_namespace_inode: net.ino(),
            image_device: image.dev(),
            image_inode: image.ino(),
            cgroup_procs_sha256: hash_bytes(&procs),
            target_pid_chain,
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
                "terminal ACK directory protection differs".into(),
            ));
        }
        let temporary = directory_path.join("terminal-join-ack.pending");
        let canonical = directory_path.join("terminal-join-ack.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&temporary, &canonical)?;
        std::fs::remove_file(&temporary)?;
        directory.sync_all()?;
        if read_protected_raw_case_file(&canonical)? != bytes {
            return Err(CiError::Message("terminal ACK readback differs".into()));
        }
        Ok(())
    }

    /// Observe once from the CI parent process while the native child runs.
    /// The native midpoint waits for this ACK but cannot convert it to Q.
    pub fn sample_and_ack_if_ready(
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
        expected_image: (u64, u64),
    ) -> Result<Option<IndependentTerminalMidpointV1>> {
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            TERMINAL_JOIN_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes =
            match read_protected_raw_case_file(&directory.join("terminal-join-gate.json")) {
                Ok(bytes) => bytes,
                Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        let request_bytes = read_protected_raw_case_file(&directory.join("request.json"))?;
        let request = parse_protected_candidate_request(
            &request_bytes,
            TERMINAL_JOIN_SELECTOR,
            challenge,
            &key,
        )?;
        let midflight_bytes =
            read_protected_raw_case_file(&directory.join("terminal-join-midflight.json"))?;
        let midflight = parse_protected_terminal_midflight(&midflight_bytes, &request, challenge)?;
        let gate = parse_gate(
            &gate_bytes,
            &key,
            challenge,
            &midflight,
            &midflight_bytes,
            expected_filter,
        )?;
        let observed = sample(
            &midflight,
            expected_image,
            hash_bytes(&gate_bytes),
            hash_bytes(&midflight_bytes),
        )?;
        let ack = TerminalJoinAckV1 {
            schema_version: 1,
            selector: TERMINAL_JOIN_SELECTOR.into(),
            result_key: gate.result_key,
            challenge_sha256: hash_bytes(&challenge),
            terminal_join_gate_sha256: observed.gate_sha256.clone(),
        };
        publish_ack(&directory, &serde_json::to_vec(&ack)?)?;
        Ok(Some(observed))
    }

    /// Reopens the protected midpoint and ACK after native finalization,
    /// binding their exact bytes to the separate pre-ACK CI kernel sample.
    pub fn join_sampled_midpoint_to_result(
        case: &StructuralProtectedNativeCaseV1,
        sampled: &IndependentTerminalMidpointV1,
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
    ) -> Result<StructuralTerminalMidflightV1> {
        if case.result.selector != TERMINAL_JOIN_SELECTOR {
            return Err(CiError::Message("terminal result selector differs".into()));
        }
        let key = &case.candidate_request.result_key;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let midflight_bytes =
            read_protected_raw_case_file(&directory.join("terminal-join-midflight.json"))?;
        let midflight = parse_protected_terminal_midflight(
            &midflight_bytes,
            &case.candidate_request,
            challenge,
        )?;
        let gate_bytes = read_protected_raw_case_file(&directory.join("terminal-join-gate.json"))?;
        let gate = parse_gate(
            &gate_bytes,
            key,
            challenge,
            &midflight,
            &midflight_bytes,
            expected_filter,
        )?;
        let ack_bytes = read_protected_raw_case_file(&directory.join("terminal-join-ack.json"))?;
        reject_duplicate_json_keys(&ack_bytes).map_err(CiError::Message)?;
        let ack: TerminalJoinAckV1 = serde_json::from_slice(&ack_bytes)?;
        if hash_bytes(&gate_bytes) != sampled.gate_sha256
            || hash_bytes(&midflight_bytes) != sampled.midflight_sha256
            || midflight.target.pid != sampled.target_pid
            || midflight.target.start_time != sampled.target_start_time
            || midflight.network_namespace_inode != sampled.network_namespace_inode
            || ack.schema_version != 1
            || ack.selector != TERMINAL_JOIN_SELECTOR
            || ack.result_key != *key
            || ack.challenge_sha256 != hash_bytes(&challenge)
            || ack.terminal_join_gate_sha256 != sampled.gate_sha256
            || serde_json::to_vec(&ack)? != ack_bytes
            || gate.target.pid != sampled.target_pid
            || gate.target.start_time != sampled.target_start_time
        {
            return Err(CiError::Message(
                "independent terminal midpoint join differs".into(),
            ));
        }
        Ok(midflight)
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready(
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
    _expected_image: (u64, u64),
) -> Result<Option<IndependentTerminalMidpointV1>> {
    Err(CiError::Message(
        "terminal live observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn join_sampled_midpoint_to_result(
    _case: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    _sampled: &IndependentTerminalMidpointV1,
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
) -> Result<StructuralTerminalMidflightV1> {
    Err(CiError::Message(
        "terminal live observation requires native Linux".into(),
    ))
}
