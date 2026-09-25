//! CI-owned simultaneous observation of the two native dual-attempt targets.
//!
//! The protected gate only holds both targets in place. This module samples
//! Linux procfs and cgroupfs independently before publishing one ACK; neither
//! the gate nor the ACK is a completed result or release-Q authority.

use memcordon_core::DiagnosticSha256;
#[cfg(target_os = "linux")]
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::private_protected_readback::{
    ProtectedCandidateReleaseRequestV1, StructuralTerminalMidflightV1,
};
use crate::{CiError, Result};

pub const DUAL_SELECTOR: &str = "private_tcp::dual_attempt_namespace_isolation";
const MAX_GATE_BYTES: usize = 8192;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessIdentityV1 {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DualBranchV1 {
    subattempt_key: DiagnosticSha256,
    attempt_id: String,
    target: ProcessIdentityV1,
    network_namespace_inode: u64,
    listener_socket_inode: u64,
    checkpoint_sha256: DiagnosticSha256,
    execution_record_digest: DiagnosticSha256,
    midflight_bytes_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DualGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    port: u16,
    first: DualBranchV1,
    second: DualBranchV1,
}

#[cfg(target_os = "linux")]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DualAckV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    dual_gate_sha256: DiagnosticSha256,
}

fn subattempt_key(parent: &DiagnosticSha256, tag: u8) -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-dual-subattempt-v1\0");
    digest.update(parent.bytes());
    digest.update([tag]);
    DiagnosticSha256::from_bytes(digest.finalize().into())
}

fn fixed_port(challenge: &[u8; 32]) -> u16 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-dual-port-v1\0");
    digest.update(challenge);
    let bytes = digest.finalize();
    20_000 + u16::from_le_bytes([bytes[0], bytes[1]]) % 30_000
}

fn validate_branch(
    branch: &DualBranchV1,
    expected_key: &DiagnosticSha256,
    midpoint: &StructuralTerminalMidflightV1,
    midpoint_bytes: &[u8],
    expected_filter: &DiagnosticSha256,
) -> bool {
    branch.subattempt_key == *expected_key
        && branch.attempt_id == midpoint.attempt_id
        && branch.target.pid == midpoint.target.pid
        && branch.target.start_time == midpoint.target.start_time
        && branch.target.pid != 0
        && branch.target.start_time != 0
        && branch.network_namespace_inode == midpoint.network_namespace_inode
        && branch.network_namespace_inode != 0
        && branch.listener_socket_inode != 0
        && branch.checkpoint_sha256 == midpoint.checkpoint_sha256
        && branch.execution_record_digest == midpoint.execution_record_digest
        && branch.midflight_bytes_sha256 == hash_bytes(midpoint_bytes)
        && branch.filter_sha256 == midpoint.filter_sha256
        && branch.filter_sha256 == *expected_filter
}

fn parse_gate(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: [u8; 32],
    first: &StructuralTerminalMidflightV1,
    first_midflight: &[u8],
    second: &StructuralTerminalMidflightV1,
    second_midflight: &[u8],
    expected_filter: &DiagnosticSha256,
) -> Result<DualGateV1> {
    if bytes.is_empty() || bytes.len() > MAX_GATE_BYTES {
        return Err(CiError::Message("dual gate byte bound differs".into()));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let gate: DualGateV1 = serde_json::from_slice(bytes)?;
    let first_key = subattempt_key(&request.result_key, 1);
    let second_key = subattempt_key(&request.result_key, 2);
    if request.selector != DUAL_SELECTOR
        || gate.schema_version != 1
        || gate.selector != DUAL_SELECTOR
        || gate.result_key != request.result_key
        || gate.challenge_sha256 != hash_bytes(&challenge)
        || gate.port != fixed_port(&challenge)
        || first_key == second_key
        || gate.first.target == gate.second.target
        || gate.first.network_namespace_inode == gate.second.network_namespace_inode
        || gate.first.listener_socket_inode == gate.second.listener_socket_inode
        || gate.first.attempt_id == gate.second.attempt_id
        || !validate_branch(
            &gate.first,
            &first_key,
            first,
            first_midflight,
            expected_filter,
        )
        || !validate_branch(
            &gate.second,
            &second_key,
            second,
            second_midflight,
            expected_filter,
        )
        || serde_json::to_vec(&gate)? != bytes
    {
        return Err(CiError::Message("dual gate binding differs".into()));
    }
    Ok(gate)
}

/// Structural vector check. Passing this does not establish simultaneous
/// kernel liveness and cannot authorize a completed case or Q.
pub fn validate_dual_gate_bytes(
    bytes: &[u8],
    request: &ProtectedCandidateReleaseRequestV1,
    challenge: [u8; 32],
    first: &StructuralTerminalMidflightV1,
    first_midflight: &[u8],
    second: &StructuralTerminalMidflightV1,
    second_midflight: &[u8],
    expected_filter: &DiagnosticSha256,
) -> Result<DiagnosticSha256> {
    parse_gate(
        bytes,
        request,
        challenge,
        first,
        first_midflight,
        second,
        second_midflight,
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
        parse_protected_dual_midflight, parse_protected_dual_retired_attempt,
        read_protected_raw_case_file,
    };
    use crate::private_supervisor::{
        LinuxChildIdentityV1, parse_linux_child_stat, verify_recorded_process_exited,
    };

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct DualRawBranchV1 {
        subattempt_key: DiagnosticSha256,
        attempt_id: String,
        checkpoint_sha256: DiagnosticSha256,
        terminal_record_digest: DiagnosticSha256,
        terminal_sha256: DiagnosticSha256,
        settlement_sha256: DiagnosticSha256,
        network_namespace_inode: u64,
        listener_socket_inode: u64,
        candidate_exit_code: i32,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct DualRawReportV1 {
        schema_version: u8,
        selector: String,
        result_key: DiagnosticSha256,
        challenge_sha256: DiagnosticSha256,
        gate_sha256: DiagnosticSha256,
        port: u16,
        first: DualRawBranchV1,
        second: DualRawBranchV1,
        installed_inspection_json: String,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct DualSettlementV1 {
        schema_version: u8,
        monitor_outcome: String,
        cgroup_empty_before_cleanup: bool,
        containment_removed: bool,
        target_pidfd_exited: bool,
        namespace_init_reaped: bool,
        guardian_terminal: [u8; 20],
        candidate_exit_code: Option<i32>,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct DualRawObserverV1 {
        schema_version: u8,
        gate_sha256: DiagnosticSha256,
        first: DualSettlementV1,
        second: DualSettlementV1,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct DualCleanupV1 {
        schema_version: u8,
        selector: String,
        result_key: DiagnosticSha256,
        gate_sha256: DiagnosticSha256,
        first_attempt_id: String,
        second_attempt_id: String,
        first_terminal_sha256: DiagnosticSha256,
        second_terminal_sha256: DiagnosticSha256,
        observer_sha256: DiagnosticSha256,
        coordinator: ProcessIdentityV1,
        worker: ProcessIdentityV1,
        worker_pidfd_exited: bool,
        service_generation_sha256: DiagnosticSha256,
        settlement_source: String,
    }

    fn strict_json<T>(bytes: &[u8]) -> Result<T>
    where
        T: for<'de> Deserialize<'de> + Serialize,
    {
        reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
        let value: T = serde_json::from_slice(bytes)?;
        if serde_json::to_vec(&value)? != bytes {
            return Err(CiError::Message("dual raw canonical bytes differ".into()));
        }
        Ok(value)
    }

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct IndependentDualBranchV1 {
        pub target_pid: u32,
        pub target_start_time: u64,
        pub network_namespace_device: u64,
        pub network_namespace_inode: u64,
        pub image_device: u64,
        pub image_inode: u64,
        pub listener_socket_inode: u64,
        pub cgroup_procs_sha256: DiagnosticSha256,
    }

    pub struct IndependentDualLiveObservationV1 {
        pub gate_sha256: DiagnosticSha256,
        pub first_midflight_sha256: DiagnosticSha256,
        pub second_midflight_sha256: DiagnosticSha256,
        pub port: u16,
        pub first: IndependentDualBranchV1,
        pub second: IndependentDualBranchV1,
    }

    fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((limit + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > limit {
            return Err(CiError::Message("dual kernel byte bound differs".into()));
        }
        Ok(bytes)
    }

    fn live_start(pid: u32) -> Result<u64> {
        let bytes = read_bounded(&Path::new("/proc").join(pid.to_string()).join("stat"), 4096)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("dual target stat is not UTF-8".into()))?;
        let (_, fields) = text
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("dual target stat delimiter absent".into()))?;
        if matches!(
            fields.split_ascii_whitespace().next(),
            Some("Z" | "X" | "x") | None
        ) {
            return Err(CiError::Message("dual target is not live".into()));
        }
        Ok(parse_linux_child_stat(text, pid)?.start_time_ticks)
    }

    fn listener_inode(pid: u32, port: u16) -> Result<u64> {
        let proc = Path::new("/proc").join(pid.to_string());
        let bytes = read_bounded(&proc.join("net/tcp"), 65_536)?;
        let table = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("dual TCP table is not UTF-8".into()))?;
        let port_text = format!("{port:04X}");
        let mut found = None;
        for line in table.lines().skip(1) {
            let fields: Vec<_> = line.split_ascii_whitespace().collect();
            let (Some(local), Some(state), Some(inode_text)) =
                (fields.get(1), fields.get(3), fields.get(9))
            else {
                return Err(CiError::Message("dual TCP row truncated".into()));
            };
            let Some((address, row_port)) = local.split_once(':') else {
                return Err(CiError::Message("dual TCP local address differs".into()));
            };
            if address == "0100007F" && row_port == port_text && *state == "0A" {
                let inode: u64 = inode_text
                    .parse()
                    .map_err(|_| CiError::Message("dual socket inode differs".into()))?;
                if inode == 0 || found.replace(inode).is_some() {
                    return Err(CiError::Message("dual listener is ambiguous".into()));
                }
            }
        }
        let inode = found.ok_or_else(|| CiError::Message("dual listener absent".into()))?;
        let link_text = format!("socket:[{inode}]");
        let mut matched = false;
        for entry in std::fs::read_dir(proc.join("fd"))? {
            let entry = entry?;
            let link = std::fs::read_link(entry.path())?;
            matched |= link.to_str() == Some(link_text.as_str());
        }
        if !matched {
            return Err(CiError::Message("dual target listener fd absent".into()));
        }
        Ok(inode)
    }

    fn cgroup_membership(attempt_id: &str, pid: u32) -> Result<DiagnosticSha256> {
        let path = Path::new("/sys/fs/cgroup/memcordon-sealed")
            .join(attempt_id)
            .join("cgroup.procs");
        let bytes = read_bounded(&path, 4096)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("dual cgroup list is not UTF-8".into()))?;
        let mut present = false;
        for line in text.lines() {
            let member: u32 = line
                .parse()
                .map_err(|_| CiError::Message("dual cgroup member differs".into()))?;
            if member == 0 {
                return Err(CiError::Message("dual cgroup has zero PID".into()));
            }
            present |= member == pid;
        }
        if !present {
            return Err(CiError::Message("dual target absent from cgroup".into()));
        }
        Ok(hash_bytes(&bytes))
    }

    fn sample_branch(
        branch: &DualBranchV1,
        port: u16,
        expected_image: (u64, u64),
    ) -> Result<IndependentDualBranchV1> {
        let pid = branch.target.pid;
        let before = live_start(pid)?;
        let net = std::fs::metadata(Path::new("/proc").join(pid.to_string()).join("ns/net"))?;
        let image = std::fs::metadata(Path::new("/proc").join(pid.to_string()).join("exe"))?;
        let listener = listener_inode(pid, port)?;
        let cgroup = cgroup_membership(&branch.attempt_id, pid)?;
        let after = live_start(pid)?;
        if before != branch.target.start_time
            || after != before
            || net.dev() == 0
            || net.ino() != branch.network_namespace_inode
            || (image.dev(), image.ino()) != expected_image
            || listener != branch.listener_socket_inode
        {
            return Err(CiError::Message("dual live branch differs".into()));
        }
        Ok(IndependentDualBranchV1 {
            target_pid: pid,
            target_start_time: before,
            network_namespace_device: net.dev(),
            network_namespace_inode: net.ino(),
            image_device: image.dev(),
            image_inode: image.ino(),
            listener_socket_inode: listener,
            cgroup_procs_sha256: cgroup,
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
                "dual ACK directory protection differs".into(),
            ));
        }
        let pending = directory_path.join("dual-live-ack.pending");
        let canonical = directory_path.join("dual-live-ack.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::hard_link(&pending, &canonical)?;
        std::fs::remove_file(&pending)?;
        directory.sync_all()?;
        if read_protected_raw_case_file(&canonical)? != bytes {
            return Err(CiError::Message("dual ACK readback differs".into()));
        }
        Ok(())
    }

    /// The CI parent polls this while its native release-case child is alive.
    /// It acknowledges only after sampling both live branches twice, with
    /// equal identities and socket/cgroup custody across the entire interval.
    pub fn sample_and_ack_if_ready(
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
        expected_image: (u64, u64),
    ) -> Result<Option<IndependentDualLiveObservationV1>> {
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            DUAL_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes = match read_protected_raw_case_file(&directory.join("dual-live-gate.json"))
        {
            Ok(bytes) => bytes,
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let request_bytes = read_protected_raw_case_file(&directory.join("request.json"))?;
        let request =
            parse_protected_candidate_request(&request_bytes, DUAL_SELECTOR, challenge, &key)?;
        let first_midflight =
            read_protected_raw_case_file(&directory.join("dual-first-midflight.json"))?;
        let second_midflight =
            read_protected_raw_case_file(&directory.join("dual-second-midflight.json"))?;
        let first_key = subattempt_key(&key, 1);
        let second_key = subattempt_key(&key, 2);
        let first_midpoint =
            parse_protected_dual_midflight(&first_midflight, &request, challenge, &first_key)?;
        let second_midpoint =
            parse_protected_dual_midflight(&second_midflight, &request, challenge, &second_key)?;
        let gate = parse_gate(
            &gate_bytes,
            &request,
            challenge,
            &first_midpoint,
            &first_midflight,
            &second_midpoint,
            &second_midflight,
            expected_filter,
        )?;
        let first = sample_branch(&gate.first, gate.port, expected_image)?;
        let second = sample_branch(&gate.second, gate.port, expected_image)?;
        let first_again = sample_branch(&gate.first, gate.port, expected_image)?;
        let second_again = sample_branch(&gate.second, gate.port, expected_image)?;
        if first != first_again
            || second != second_again
            || (
                first.network_namespace_device,
                first.network_namespace_inode,
            ) == (
                second.network_namespace_device,
                second.network_namespace_inode,
            )
            || first.listener_socket_inode == second.listener_socket_inode
        {
            return Err(CiError::Message(
                "dual simultaneous live interval differs".into(),
            ));
        }
        let gate_sha256 = hash_bytes(&gate_bytes);
        let ack = DualAckV1 {
            schema_version: 1,
            selector: DUAL_SELECTOR.into(),
            result_key: key,
            challenge_sha256: hash_bytes(&challenge),
            dual_gate_sha256: gate_sha256.clone(),
        };
        publish_ack(&directory, &serde_json::to_vec(&ack)?)?;
        Ok(Some(IndependentDualLiveObservationV1 {
            gate_sha256,
            first_midflight_sha256: hash_bytes(&first_midflight),
            second_midflight_sha256: hash_bytes(&second_midflight),
            port: gate.port,
            first,
            second,
        }))
    }

    fn require_exited(identity: &ProcessIdentityV1) -> Result<()> {
        verify_recorded_process_exited(LinuxChildIdentityV1 {
            pid: identity.pid,
            start_time_ticks: identity.start_time,
        })
    }

    fn require_retired_cgroup_absent(attempt_id: &str) -> Result<()> {
        let path = Path::new("/sys/fs/cgroup/memcordon-sealed").join(attempt_id);
        match std::fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
            Ok(_) => Err(CiError::Message("dual retired cgroup still exists".into())),
        }
    }

    fn verify_branch(
        report: &DualRawBranchV1,
        settlement: &DualSettlementV1,
        gate: &DualBranchV1,
        sampled: &IndependentDualBranchV1,
        branch: &memcordon_core::private_release_case_v1::PrivateReleaseDualRetiredBranchV1,
        journal: &crate::private_protected_readback::ProtectedCandidateAttemptV1,
        journal_bytes: &[u8],
        child_key: &DiagnosticSha256,
    ) -> Result<()> {
        let attempt_bytes = hex::decode(&branch.attempt_id)
            .map_err(|_| CiError::Message("dual attempt id is not hex".into()))?;
        if attempt_bytes.len() != 16
            || report.subattempt_key != *child_key
            || gate.subattempt_key != *child_key
            || report.attempt_id != branch.attempt_id
            || gate.attempt_id != branch.attempt_id
            || report.checkpoint_sha256 != branch.checkpoint_sha256
            || report.checkpoint_sha256 != gate.checkpoint_sha256
            || report.terminal_record_digest != *journal.terminal_record_digest()
            || report.terminal_record_digest != branch.retirement_sha256
            || report.terminal_sha256 != hash_bytes(journal_bytes)
            || report.terminal_sha256 != branch.terminal_sha256
            || report.settlement_sha256 != hash_bytes(&serde_json::to_vec(settlement)?)
            || report.network_namespace_inode != gate.network_namespace_inode
            || report.network_namespace_inode != sampled.network_namespace_inode
            || report.listener_socket_inode != gate.listener_socket_inode
            || report.listener_socket_inode != sampled.listener_socket_inode
            || report.candidate_exit_code != 0
            || settlement.schema_version != 1
            || settlement.monitor_outcome != "Completed"
            || !settlement.cgroup_empty_before_cleanup
            || !settlement.containment_removed
            || !settlement.target_pidfd_exited
            || !settlement.namespace_init_reaped
            || settlement.candidate_exit_code != Some(0)
            || settlement.guardian_terminal[0] != 4
            || settlement.guardian_terminal[1..17] != attempt_bytes
            || settlement.guardian_terminal[17..] != [1, 0, 0]
        {
            return Err(CiError::Message("dual raw branch differs".into()));
        }
        let processes = journal
            .terminal_processes()
            .ok_or_else(|| CiError::Message("dual terminal process set absent".into()))?;
        if processes[2].pid != sampled.target_pid
            || processes[2].start_time != sampled.target_start_time
            || journal.checkpoint_filter_sha256() != Some(&gate.filter_sha256)
            || journal.checkpoint_network_namespace_inode() != Some(sampled.network_namespace_inode)
        {
            return Err(CiError::Message("dual journal/live branch differs".into()));
        }
        for process in processes {
            require_exited(&ProcessIdentityV1 {
                pid: process.pid,
                start_time: process.start_time,
            })?;
        }
        require_retired_cgroup_absent(&branch.attempt_id)
    }

    /// Joins the completed two-branch structural result to protected parent
    /// and child files and to the separate CI live observation. This remains
    /// non-authoritative for release qualification.
    pub fn join_sampled_dual_to_result(
        case: &StructuralProtectedNativeCaseV1,
        sampled: &IndependentDualLiveObservationV1,
        challenge: [u8; 32],
        expected_filter: &DiagnosticSha256,
        expected_inspection_sha256: &DiagnosticSha256,
    ) -> Result<()> {
        use memcordon_core::private_release_case_v1::PrivateReleaseObservationV1;

        let PrivateReleaseObservationV1::DualAttemptsRetired {
            first,
            second,
            native_observer_sha256,
        } = &case.result.observation
        else {
            return Err(CiError::Message("dual result observation absent".into()));
        };
        if case.result.selector != DUAL_SELECTOR
            || case.candidate_request.selector != DUAL_SELECTOR
            || case.attempt_record.is_some()
            || case.attempt_record_bytes.is_some()
        {
            return Err(CiError::Message("dual result parent domain differs".into()));
        }
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            DUAL_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        if case.candidate_request.result_key != key {
            return Err(CiError::Message("dual result key differs".into()));
        }
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let first_key = subattempt_key(&key, 1);
        let second_key = subattempt_key(&key, 2);
        let first_midflight =
            read_protected_raw_case_file(&directory.join("dual-first-midflight.json"))?;
        let second_midflight =
            read_protected_raw_case_file(&directory.join("dual-second-midflight.json"))?;
        let first_midpoint = parse_protected_dual_midflight(
            &first_midflight,
            &case.candidate_request,
            challenge,
            &first_key,
        )?;
        let second_midpoint = parse_protected_dual_midflight(
            &second_midflight,
            &case.candidate_request,
            challenge,
            &second_key,
        )?;
        let gate_bytes = read_protected_raw_case_file(&directory.join("dual-live-gate.json"))?;
        let gate = parse_gate(
            &gate_bytes,
            &case.candidate_request,
            challenge,
            &first_midpoint,
            &first_midflight,
            &second_midpoint,
            &second_midflight,
            expected_filter,
        )?;
        let gate_sha256 = hash_bytes(&gate_bytes);
        let ack_bytes = read_protected_raw_case_file(&directory.join("dual-live-ack.json"))?;
        let ack: DualAckV1 = strict_json(&ack_bytes)?;
        if gate_sha256 != sampled.gate_sha256
            || hash_bytes(&first_midflight) != sampled.first_midflight_sha256
            || hash_bytes(&second_midflight) != sampled.second_midflight_sha256
            || gate.port != sampled.port
            || ack.schema_version != 1
            || ack.selector != DUAL_SELECTOR
            || ack.result_key != key
            || ack.challenge_sha256 != hash_bytes(&challenge)
            || ack.dual_gate_sha256 != gate_sha256
        {
            return Err(CiError::Message("dual live gate/ACK join differs".into()));
        }
        let first_bytes = read_protected_raw_case_file(&directory.join("dual-first/attempt.json"))?;
        let second_bytes =
            read_protected_raw_case_file(&directory.join("dual-second/attempt.json"))?;
        let first_journal = parse_protected_dual_retired_attempt(
            &first_bytes,
            &case.candidate_request,
            first,
            &first_key,
            challenge,
            native_observer_sha256,
        )?;
        let second_journal = parse_protected_dual_retired_attempt(
            &second_bytes,
            &case.candidate_request,
            second,
            &second_key,
            challenge,
            native_observer_sha256,
        )?;
        if first.attempt_id == second.attempt_id
            || first.checkpoint_sha256 == second.checkpoint_sha256
            || first_midpoint.target.pid != sampled.first.target_pid
            || first_midpoint.target.start_time != sampled.first.target_start_time
            || second_midpoint.target.pid != sampled.second.target_pid
            || second_midpoint.target.start_time != sampled.second.target_start_time
            || (
                sampled.first.network_namespace_device,
                sampled.first.network_namespace_inode,
            ) == (
                sampled.second.network_namespace_device,
                sampled.second.network_namespace_inode,
            )
            || sampled.first.listener_socket_inode == sampled.second.listener_socket_inode
        {
            return Err(CiError::Message("dual branches are not separate".into()));
        }
        let attachments: [&[u8]; 5] = case
            .attachments
            .iter()
            .map(Vec::as_slice)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| CiError::Message("dual raw role count differs".into()))?;
        let [
            request_bytes,
            report_bytes,
            stdio_bytes,
            observer_bytes,
            cleanup_bytes,
        ] = attachments;
        let report: DualRawReportV1 = strict_json(report_bytes)?;
        let observer: DualRawObserverV1 = strict_json(observer_bytes)?;
        let cleanup: DualCleanupV1 = strict_json(cleanup_bytes)?;
        if request_bytes != case.candidate_request_bytes
            || report.schema_version != 1
            || report.selector != DUAL_SELECTOR
            || report.result_key != key
            || report.challenge_sha256 != hash_bytes(&challenge)
            || report.gate_sha256 != gate_sha256
            || report.port != gate.port
            || hash_bytes(report.installed_inspection_json.as_bytes())
                != *expected_inspection_sha256
            || observer.schema_version != 1
            || observer.gate_sha256 != gate_sha256
            || hash_bytes(observer_bytes) != *native_observer_sha256
            || cleanup.schema_version != 1
            || cleanup.selector != DUAL_SELECTOR
            || cleanup.result_key != key
            || cleanup.gate_sha256 != gate_sha256
            || cleanup.first_attempt_id != first.attempt_id
            || cleanup.second_attempt_id != second.attempt_id
            || cleanup.first_terminal_sha256 != first.terminal_sha256
            || cleanup.second_terminal_sha256 != second.terminal_sha256
            || cleanup.observer_sha256 != hash_bytes(observer_bytes)
            || cleanup.coordinator.pid != case.candidate_request.coordinator.pid
            || cleanup.coordinator.start_time != case.candidate_request.coordinator.start_time
            || cleanup.worker == cleanup.coordinator
            || cleanup.worker.pid == 0
            || cleanup.worker.start_time == 0
            || !cleanup.worker_pidfd_exited
            || cleanup.service_generation_sha256 != case.candidate_request.service_generation_sha256
            || cleanup.settlement_source != "control-coordinator-pidfd"
        {
            return Err(CiError::Message("dual parent raw join differs".into()));
        }
        let mut expected_stdio = Vec::with_capacity(116);
        expected_stdio.extend_from_slice(&challenge);
        let mut ready_digest = Sha256::new();
        ready_digest.update(b"memcordon-private-release-dual-ready-v1\0");
        ready_digest.update(challenge);
        let ready_digest = ready_digest.finalize();
        for namespace in [
            report.first.network_namespace_inode,
            report.second.network_namespace_inode,
        ] {
            expected_stdio.extend_from_slice(&ready_digest);
            expected_stdio.extend_from_slice(&report.port.to_le_bytes());
            expected_stdio.extend_from_slice(&namespace.to_le_bytes());
        }
        if stdio_bytes != expected_stdio {
            return Err(CiError::Message("dual target ready frames differ".into()));
        }
        verify_branch(
            &report.first,
            &observer.first,
            &gate.first,
            &sampled.first,
            first,
            &first_journal,
            &first_bytes,
            &first_key,
        )?;
        verify_branch(
            &report.second,
            &observer.second,
            &gate.second,
            &sampled.second,
            second,
            &second_journal,
            &second_bytes,
            &second_key,
        )?;
        require_exited(&cleanup.worker)
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub struct IndependentDualLiveObservationV1;

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready(
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
    _expected_image: (u64, u64),
) -> Result<Option<IndependentDualLiveObservationV1>> {
    Err(CiError::Message(
        "dual live observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn join_sampled_dual_to_result(
    _case: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    _sampled: &IndependentDualLiveObservationV1,
    _challenge: [u8; 32],
    _expected_filter: &DiagnosticSha256,
    _expected_inspection_sha256: &DiagnosticSha256,
) -> Result<()> {
    Err(CiError::Message(
        "dual live observation requires native Linux".into(),
    ))
}
