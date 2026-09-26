//! Independent CI-side live child observation and synchronization.
//!
//! The acknowledgment only lets the native owner continue. It is not a
//! completion, and neither it nor an owner-authored gate can qualify Q.

#[cfg(target_os = "linux")]
mod linux {

    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use memcordon_core::DiagnosticSha256;
    use memcordon_core::private_release_case_v1::{
        PRIVATE_RELEASE_RESULT_ROOT_V1, PrivateReleaseStageV1, private_release_case_key_v1,
    };
    use memcordon_core::workload_codec::hash_bytes;
    use memcordon_core::workload_contract::reject_duplicate_json_keys;
    use serde::{Deserialize, Serialize};

    use crate::private_protected_readback::{
        StructuralProtectedNativeCaseV1, read_protected_raw_case_file,
    };
    use crate::private_supervisor::parse_linux_child_stat;
    use crate::{CiError, Result};

    pub const CHILD_RUNTIME_SELECTOR: &str = "private_tcp::child_runtime_and_threads_retired";
    const MAX_GATE_BYTES: u64 = 8192;
    const MAX_KERNEL_BYTES: u64 = 4096;

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct ProcessIdentityV1 {
        pid: u32,
        start_time: u64,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct LiveWitnessV1 {
        schema_version: u8,
        target: ProcessIdentityV1,
        child: ProcessIdentityV1,
        thread_tid: u32,
        thread_start_time: u64,
        target_namespace_pid: u32,
        child_namespace_pid: u32,
        thread_namespace_tid: u32,
        target_pid_chain: Vec<u32>,
        child_pid_chain: Vec<u32>,
        thread_tid_chain: Vec<u32>,
        challenge_sha256: DiagnosticSha256,
        cgroup_procs_sha256: DiagnosticSha256,
        cgroup_threads_sha256: DiagnosticSha256,
    }

    #[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct LiveGateV1 {
        schema_version: u8,
        selector: String,
        result_key: DiagnosticSha256,
        challenge_sha256: DiagnosticSha256,
        live: LiveWitnessV1,
    }

    #[derive(Deserialize, Serialize)]
    #[serde(deny_unknown_fields)]
    struct LiveAckV1 {
        schema_version: u8,
        selector: String,
        result_key: DiagnosticSha256,
        challenge_sha256: DiagnosticSha256,
        live_gate_sha256: DiagnosticSha256,
    }

    /// Sampled directly from procfs/cgroupfs while the native target is held
    /// behind the live gate. The raw bytes remain separate from owner records.
    pub struct IndependentChildLiveObservationV1 {
        gate_bytes: Vec<u8>,
        live: LiveWitnessV1,
        cgroup_procs: Vec<u8>,
        cgroup_threads: Vec<u8>,
    }

    fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() as u64 > maximum {
            return Err(CiError::Message(
                "child live kernel file bound differs".into(),
            ));
        }
        Ok(bytes)
    }

    fn status_fields(path: &Path) -> Result<(u32, u32, Vec<u32>)> {
        let bytes = read_bounded(path, MAX_KERNEL_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("child live status is not UTF-8".into()))?;
        let mut tgid = None;
        let mut parent = None;
        let mut chain = None;
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("Tgid:") {
                let value = value
                    .trim()
                    .parse()
                    .map_err(|_| CiError::Message("child Tgid differs".into()))?;
                if tgid.replace(value).is_some() {
                    return Err(CiError::Message("duplicate child Tgid".into()));
                }
            }
            if let Some(value) = line.strip_prefix("PPid:") {
                let value = value
                    .trim()
                    .parse()
                    .map_err(|_| CiError::Message("child PPid differs".into()))?;
                if parent.replace(value).is_some() {
                    return Err(CiError::Message("duplicate child PPid".into()));
                }
            }
            if let Some(value) = line.strip_prefix("NSpid:") {
                let ids: Vec<u32> = value
                    .split_ascii_whitespace()
                    .map(str::parse)
                    .collect::<std::result::Result<_, _>>()
                    .map_err(|_| CiError::Message("child NSpid differs".into()))?;
                if ids.is_empty()
                    || ids.len() > 8
                    || ids.contains(&0)
                    || chain.replace(ids).is_some()
                {
                    return Err(CiError::Message("child NSpid chain differs".into()));
                }
            }
        }
        match (tgid, parent, chain) {
            (Some(tgid), Some(parent), Some(chain)) if tgid != 0 && parent != 0 => {
                Ok((tgid, parent, chain))
            }
            _ => Err(CiError::Message("child live status identity absent".into())),
        }
    }

    fn stat_start(path: &Path, pid: u32) -> Result<u64> {
        let bytes = read_bounded(path, MAX_KERNEL_BYTES)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("child live stat is not UTF-8".into()))?;
        let (_, fields) = text
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("child live stat delimiter absent".into()))?;
        let state = fields
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| CiError::Message("child live stat state absent".into()))?;
        if matches!(state, "Z" | "X" | "x") {
            return Err(CiError::Message("child live process is not running".into()));
        }
        Ok(parse_linux_child_stat(text, pid)?.start_time_ticks)
    }

    fn has_id(bytes: &[u8], id: u32) -> Result<bool> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| CiError::Message("child cgroup list is not UTF-8".into()))?;
        let mut found = false;
        for line in text.lines() {
            let value: u32 = line
                .parse()
                .map_err(|_| CiError::Message("child cgroup list differs".into()))?;
            if value == 0 {
                return Err(CiError::Message("child cgroup list has zero PID".into()));
            }
            found |= value == id;
        }
        Ok(found)
    }

    fn sample_live(live: &LiveWitnessV1, attempt_id: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let target = Path::new("/proc").join(live.target.pid.to_string());
        let child = Path::new("/proc").join(live.child.pid.to_string());
        let task = target.join("task").join(live.thread_tid.to_string());
        let (target_tgid, _, target_chain) = status_fields(&target.join("status"))?;
        let (child_tgid, child_parent, child_chain) = status_fields(&child.join("status"))?;
        let (thread_tgid, _, thread_chain) = status_fields(&task.join("status"))?;
        let group = Path::new("/sys/fs/cgroup/memcordon-sealed").join(attempt_id);
        let procs = read_bounded(&group.join("cgroup.procs"), MAX_KERNEL_BYTES)?;
        let threads = read_bounded(&group.join("cgroup.threads"), MAX_KERNEL_BYTES)?;
        if live.schema_version != 1
            || live.target.pid == 0
            || live.child.pid == 0
            || live.thread_tid == 0
            || live.target.pid == live.child.pid
            || live.thread_tid == live.target.pid
            || live.thread_tid == live.child.pid
            || target_tgid != live.target.pid
            || child_tgid != live.child.pid
            || child_parent != live.target.pid
            || thread_tgid != live.target.pid
            || stat_start(&target.join("stat"), live.target.pid)? != live.target.start_time
            || stat_start(&child.join("stat"), live.child.pid)? != live.child.start_time
            || stat_start(&task.join("stat"), live.thread_tid)? != live.thread_start_time
            || target_chain != live.target_pid_chain
            || child_chain != live.child_pid_chain
            || thread_chain != live.thread_tid_chain
            || target_chain.first() != Some(&live.target.pid)
            || child_chain.first() != Some(&live.child.pid)
            || thread_chain.first() != Some(&live.thread_tid)
            || target_chain.last() != Some(&live.target_namespace_pid)
            || child_chain.last() != Some(&live.child_namespace_pid)
            || thread_chain.last() != Some(&live.thread_namespace_tid)
            || !has_id(&procs, live.target.pid)?
            || !has_id(&procs, live.child.pid)?
            || !has_id(&threads, live.target.pid)?
            || !has_id(&threads, live.child.pid)?
            || !has_id(&threads, live.thread_tid)?
            || hash_bytes(&procs) != live.cgroup_procs_sha256
            || hash_bytes(&threads) != live.cgroup_threads_sha256
            || stat_start(&target.join("stat"), live.target.pid)? != live.target.start_time
            || stat_start(&child.join("stat"), live.child.pid)? != live.child.start_time
            || stat_start(&task.join("stat"), live.thread_tid)? != live.thread_start_time
        {
            return Err(CiError::Message(
                "independent child live kernel sample differs".into(),
            ));
        }
        Ok((procs, threads))
    }

    /// Called on each supervisor poll while the authenticated CLI child runs.
    /// Absent gate means the native case has not reached its physical live point.
    pub fn sample_and_ack_if_ready(
        challenge: [u8; 32],
    ) -> Result<Option<IndependentChildLiveObservationV1>> {
        sample_and_ack_if_ready_with_source(challenge, |_, _, _, _| Ok(()))
    }

    pub(crate) fn sample_and_ack_if_ready_with_source(
        challenge: [u8; 32],
        mut retain: impl FnMut(u32, u64, u32, u64) -> Result<()>,
    ) -> Result<Option<IndependentChildLiveObservationV1>> {
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            CHILD_RUNTIME_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let key_text: String = key.clone().into();
        let dir_path = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_path = dir_path.join("live-gate.json");
        let gate_bytes = match read_protected_raw_case_file(&gate_path) {
            Ok(bytes) => bytes,
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        if gate_bytes.len() as u64 > MAX_GATE_BYTES {
            return Err(CiError::Message("child gate oversized".into()));
        }
        reject_duplicate_json_keys(&gate_bytes).map_err(CiError::Message)?;
        let gate: LiveGateV1 = serde_json::from_slice(&gate_bytes)?;
        if gate.schema_version != 1
            || gate.selector != CHILD_RUNTIME_SELECTOR
            || gate.result_key != key
            || gate.challenge_sha256 != hash_bytes(&challenge)
            || gate.live.challenge_sha256 != hash_bytes(&challenge)
            || serde_json::to_vec(&gate)? != gate_bytes
        {
            return Err(CiError::Message(
                "child gate canonical binding differs".into(),
            ));
        }
        let attempt_id = candidate_attempt_id(&key);
        let (cgroup_procs, cgroup_threads) = sample_live(&gate.live, &attempt_id)?;
        retain(
            gate.live.target.pid,
            gate.live.target.start_time,
            gate.live.child.pid,
            gate.live.child.start_time,
        )?;
        let ack = LiveAckV1 {
            schema_version: 1,
            selector: CHILD_RUNTIME_SELECTOR.into(),
            result_key: key,
            challenge_sha256: hash_bytes(&challenge),
            live_gate_sha256: hash_bytes(&gate_bytes),
        };
        publish_ack(&dir_path, &serde_json::to_vec(&ack)?)?;
        Ok(Some(IndependentChildLiveObservationV1 {
            gate_bytes,
            live: gate.live,
            cgroup_procs,
            cgroup_threads,
        }))
    }

    fn candidate_attempt_id(key: &DiagnosticSha256) -> String {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        digest.update(b"memcordon-private-release-candidate-attempt-v1\0");
        digest.update(key.bytes());
        hex::encode(&digest.finalize()[..16])
    }

    fn publish_ack(directory_path: &Path, bytes: &[u8]) -> Result<()> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory_path)?;
        let metadata = directory.metadata()?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
            return Err(CiError::Message(
                "child ACK directory protection differs".into(),
            ));
        }
        let temporary = directory_path.join("live-ack.pending");
        let canonical = directory_path.join("live-ack.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        // Hard-link publication is atomic and no-replace. The retained root-only
        // directory and fixed leaves make this safe without unsafe renameat2 FFI.
        std::fs::hard_link(&temporary, &canonical)?;
        std::fs::remove_file(&temporary)?;
        directory.sync_all()?;
        if read_protected_raw_case_file(&canonical)? != bytes {
            return Err(CiError::Message("child ACK readback differs".into()));
        }
        Ok(())
    }

    /// Reopens protected leaves after native completion and joins the independently
    /// sampled live projection to the owner trace. This remains nonqualifying.
    pub fn join_live_sample_to_result(
        case: &StructuralProtectedNativeCaseV1,
        sampled: &IndependentChildLiveObservationV1,
    ) -> Result<()> {
        if case.result.selector != CHILD_RUNTIME_SELECTOR {
            return Err(CiError::Message("child live selector differs".into()));
        }
        let key_text: String = case.candidate_request.result_key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate = read_protected_raw_case_file(&directory.join("live-gate.json"))?;
        let ack_bytes = read_protected_raw_case_file(&directory.join("live-ack.json"))?;
        reject_duplicate_json_keys(&ack_bytes).map_err(CiError::Message)?;
        let ack: LiveAckV1 = serde_json::from_slice(&ack_bytes)?;
        let observer: serde_json::Value = serde_json::from_slice(&case.attachments[3])?;
        let owner_live = observer
            .get("live")
            .ok_or_else(|| CiError::Message("child owner live trace absent".into()))?;
        if gate != sampled.gate_bytes
            || ack.schema_version != 1
            || ack.selector != CHILD_RUNTIME_SELECTOR
            || ack.result_key != case.candidate_request.result_key
            || ack.challenge_sha256 != sampled.live.challenge_sha256
            || ack.live_gate_sha256 != hash_bytes(&gate)
            || serde_json::to_vec(&ack)? != ack_bytes
            || serde_json::to_value(&sampled.live)? != *owner_live
            || hash_bytes(&sampled.cgroup_procs) != sampled.live.cgroup_procs_sha256
            || hash_bytes(&sampled.cgroup_threads) != sampled.live.cgroup_threads_sha256
        {
            return Err(CiError::Message(
                "independent child live result join differs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub const CHILD_RUNTIME_SELECTOR: &str = "private_tcp::child_runtime_and_threads_retired";

#[cfg(not(target_os = "linux"))]
pub struct IndependentChildLiveObservationV1;

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready(
    _challenge: [u8; 32],
) -> crate::Result<Option<IndependentChildLiveObservationV1>> {
    Err(crate::CiError::Message(
        "independent child live observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn sample_and_ack_if_ready_with_source(
    _challenge: [u8; 32],
    _retain: impl FnMut(u32, u64, u32, u64) -> crate::Result<()>,
) -> crate::Result<Option<IndependentChildLiveObservationV1>> {
    Err(crate::CiError::Message(
        "independent child raw sampling requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn join_live_sample_to_result(
    _case: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    _sampled: &IndependentChildLiveObservationV1,
) -> crate::Result<()> {
    Err(crate::CiError::Message(
        "independent child live observation requires native Linux".into(),
    ))
}
