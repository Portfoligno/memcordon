//! Independent AF_UNIX namespace inventory parsing for a held target.
//!
//! A live sampler supplies bytes from the target's proc view. This parser
//! preserves the pathname remainder after the seven fixed proc columns; it
//! refuses ambiguous rows rather than treating a truncated name as absence.

use crate::{CiError, Result};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};

use crate::private_protected_readback::UnixAbsenceSnapshotV1;
use crate::private_protected_readback::{
    UnixIntentSupervisorAbsenceV1, validate_unix_supervisor_absence,
};

pub const UNIX_INTENT_SELECTOR: &str = "private_tcp::af_unix_abstract_and_pathname_denied";
const MAX_PROC_UNIX_BYTES: usize = 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixIntentGateV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    pub(crate) witness: UnixIntentSupervisorAbsenceV1,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixIntentAckV1 {
    pub(crate) schema_version: u8,
    pub(crate) selector: String,
    pub(crate) result_key: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) gate_sha256: DiagnosticSha256,
    pub(crate) observed: UnixAbsenceSnapshotV1,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct IndependentUnixLiveSampleV1 {
    gate_sha256: DiagnosticSha256,
    target_pid: u32,
    target_start_time: u64,
    observed: UnixAbsenceSnapshotV1,
}

pub(crate) fn parse_gate(
    bytes: &[u8],
    key: &DiagnosticSha256,
    challenge: [u8; 32],
) -> Result<UnixIntentGateV1> {
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(CiError::Message("Unix live gate byte bound differs".into()));
    }
    reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let gate: UnixIntentGateV1 = serde_json::from_slice(bytes)?;
    if gate.schema_version != 1
        || gate.selector != UNIX_INTENT_SELECTOR
        || gate.result_key != *key
        || gate.challenge_sha256 != hash_bytes(&challenge)
        || serde_json::to_vec(&gate)? != bytes
    {
        return Err(CiError::Message("Unix live gate identity differs".into()));
    }
    validate_unix_supervisor_absence(
        &gate.witness,
        challenge,
        &gate.witness.target,
        gate.witness.before_release.network_namespace_inode,
    )?;
    Ok(gate)
}

pub fn verify_proc_unix_endpoints_absent(
    bytes: &[u8],
    pathname: &str,
    abstract_name: &str,
) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_PROC_UNIX_BYTES {
        return Err(CiError::Message(
            "Unix proc inventory byte bound differs".into(),
        ));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CiError::Message("Unix proc inventory is not UTF-8".into()))?;
    if !text.ends_with('\n') {
        return Err(CiError::Message("Unix proc inventory is truncated".into()));
    }
    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| CiError::Message("Unix proc inventory header is absent".into()))?;
    if header.split_ascii_whitespace().collect::<Vec<_>>()
        != [
            "Num", "RefCount", "Protocol", "Flags", "Type", "St", "Inode", "Path",
        ]
    {
        return Err(CiError::Message(
            "Unix proc inventory header differs".into(),
        ));
    }
    for line in lines {
        let mut remaining = line;
        let mut fields = Vec::with_capacity(7);
        for _ in 0..7 {
            remaining = remaining.trim_ascii_start();
            let end = remaining
                .find(char::is_whitespace)
                .unwrap_or(remaining.len());
            if end == 0 {
                return Err(CiError::Message("Unix proc row field is empty".into()));
            }
            fields.push(&remaining[..end]);
            remaining = &remaining[end..];
        }
        let number = fields[0]
            .strip_suffix(':')
            .ok_or_else(|| CiError::Message("Unix proc row number differs".into()))?;
        if number.is_empty()
            || !number.bytes().all(|byte| byte.is_ascii_hexdigit())
            || fields[1..6]
                .iter()
                .any(|field| !field.bytes().all(|byte| byte.is_ascii_hexdigit()))
            || !fields[6].bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(CiError::Message("Unix proc row fields differ".into()));
        }
        let path = if remaining.is_empty() {
            ""
        } else {
            remaining
                .strip_prefix(' ')
                .ok_or_else(|| CiError::Message("Unix proc path delimiter differs".into()))?
        };
        if path == pathname || path == abstract_name {
            return Err(CiError::Message(
                "Unix endpoint exists in target namespace".into(),
            ));
        }
        if path.contains(pathname) || path.contains(abstract_name) {
            return Err(CiError::Message("Unix proc pathname is ambiguous".into()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;

    use memcordon_core::private_release_case_v1::{
        PRIVATE_RELEASE_RESULT_ROOT_V1, PrivateReleaseStageV1, private_release_case_key_v1,
    };

    use super::*;
    use crate::private_protected_readback::{
        StructuralProtectedNativeCaseV1, parsed_candidate_unix_absence_observer,
        read_protected_raw_case_file,
    };
    use crate::private_supervisor::parse_linux_child_stat;

    fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take((maximum + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err(CiError::Message(
                "Unix live kernel byte bound differs".into(),
            ));
        }
        Ok(bytes)
    }

    fn live_start(pid: u32) -> Result<u64> {
        let bytes = read_bounded(&Path::new("/proc").join(pid.to_string()).join("stat"), 4096)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| CiError::Message("Unix live stat is not UTF-8".into()))?;
        let (_, fields) = text
            .rsplit_once(") ")
            .ok_or_else(|| CiError::Message("Unix live stat delimiter absent".into()))?;
        if matches!(
            fields.split_ascii_whitespace().next(),
            Some("Z" | "X" | "x") | None
        ) {
            return Err(CiError::Message("Unix live target is not running".into()));
        }
        Ok(parse_linux_child_stat(text, pid)?.start_time_ticks)
    }

    fn sample(gate: &UnixIntentGateV1, challenge: [u8; 32]) -> Result<UnixAbsenceSnapshotV1> {
        let target = &gate.witness.target;
        let proc = Path::new("/proc").join(target.pid.to_string());
        if live_start(target.pid)? != target.start_time {
            return Err(CiError::Message("Unix live target start differs".into()));
        }
        let net = fs::metadata(proc.join("ns/net"))?;
        let mount = fs::metadata(proc.join("ns/mnt"))?;
        let root = fs::metadata(proc.join("root"))?;
        let inventory = read_bounded(&proc.join("net/unix"), MAX_PROC_UNIX_BYTES)?;
        let prefix = format!("memcordon-private-unix-{}", hex::encode(challenge));
        let pathname_name = format!("{prefix}-path");
        let pathname = format!("/tmp/{pathname_name}");
        let abstract_name = format!("@{prefix}-abstract");
        verify_proc_unix_endpoints_absent(&inventory, &pathname, &abstract_name)?;
        match fs::symlink_metadata(proc.join("root/tmp").join(&pathname_name)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err(CiError::Message("Unix pathname endpoint exists".into())),
        }
        if live_start(target.pid)? != target.start_time
            || fs::metadata(proc.join("ns/net"))?.ino() != net.ino()
            || fs::metadata(proc.join("ns/mnt"))?.ino() != mount.ino()
            || fs::metadata(proc.join("root"))?.ino() != root.ino()
            || net.ino()
                != gate
                    .witness
                    .after_denials_before_ack
                    .network_namespace_inode
            || mount.ino() != gate.witness.after_denials_before_ack.mount_namespace_inode
            || root.ino() != gate.witness.after_denials_before_ack.target_root_inode
        {
            return Err(CiError::Message("Unix live namespace changed".into()));
        }
        Ok(UnixAbsenceSnapshotV1 {
            network_namespace_inode: net.ino(),
            mount_namespace_inode: mount.ino(),
            target_root_inode: root.ino(),
            proc_unix_sha256: hash_bytes(&inventory),
            pathname_absent: true,
            abstract_absent: true,
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
                "Unix ACK directory protection differs".into(),
            ));
        }
        let temporary = directory_path.join("unix-intent-ack.pending");
        let canonical = directory_path.join("unix-intent-ack.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::hard_link(&temporary, &canonical)?;
        fs::remove_file(&temporary)?;
        directory.sync_all()?;
        if read_protected_raw_case_file(&canonical)? != bytes {
            return Err(CiError::Message("Unix ACK readback differs".into()));
        }
        Ok(())
    }

    pub fn sample_and_ack_if_ready(
        challenge: [u8; 32],
    ) -> Result<Option<IndependentUnixLiveSampleV1>> {
        sample_and_ack_if_ready_with_source(challenge, |_, _| Ok(()))
    }

    pub fn sample_and_ack_if_ready_with_source(
        challenge: [u8; 32],
        source: impl FnOnce(u32, u64) -> Result<()>,
    ) -> Result<Option<IndependentUnixLiveSampleV1>> {
        let key = private_release_case_key_v1(
            PrivateReleaseStageV1::CandidateCapability,
            UNIX_INTENT_SELECTOR,
            &challenge,
        )
        .map_err(CiError::Message)?;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes =
            match read_protected_raw_case_file(&directory.join("unix-intent-gate.json")) {
                Ok(bytes) => bytes,
                Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        let gate = parse_gate(&gate_bytes, &key, challenge)?;
        let observed = sample(&gate, challenge)?;
        source(gate.witness.target.pid, gate.witness.target.start_time)?;
        if sample(&gate, challenge)? != observed
            || read_protected_raw_case_file(&directory.join("unix-intent-gate.json"))? != gate_bytes
        {
            return Err(CiError::Message(
                "Unix target/gate changed before ACK".into(),
            ));
        }
        let gate_sha256 = hash_bytes(&gate_bytes);
        let ack = UnixIntentAckV1 {
            schema_version: 1,
            selector: UNIX_INTENT_SELECTOR.into(),
            result_key: key,
            challenge_sha256: hash_bytes(&challenge),
            gate_sha256: gate_sha256.clone(),
            observed: observed.clone(),
        };
        publish_ack(&directory, &serde_json::to_vec(&ack)?)?;
        Ok(Some(IndependentUnixLiveSampleV1 {
            gate_sha256,
            target_pid: gate.witness.target.pid,
            target_start_time: gate.witness.target.start_time,
            observed,
        }))
    }

    pub fn join_sampled_unix_to_result(
        case: &StructuralProtectedNativeCaseV1,
        sampled: &IndependentUnixLiveSampleV1,
        challenge: [u8; 32],
    ) -> Result<()> {
        if case.result.selector != UNIX_INTENT_SELECTOR {
            return Err(CiError::Message("Unix result selector differs".into()));
        }
        let key = &case.candidate_request.result_key;
        let key_text: String = key.clone().into();
        let directory = Path::new(PRIVATE_RELEASE_RESULT_ROOT_V1).join(key_text);
        let gate_bytes = read_protected_raw_case_file(&directory.join("unix-intent-gate.json"))?;
        let gate = parse_gate(&gate_bytes, key, challenge)?;
        let ack_bytes = read_protected_raw_case_file(&directory.join("unix-intent-ack.json"))?;
        reject_duplicate_json_keys(&ack_bytes).map_err(CiError::Message)?;
        let ack: UnixIntentAckV1 = serde_json::from_slice(&ack_bytes)?;
        let worker_observer = case.attachments.get(3).ok_or_else(|| {
            CiError::Message("Unix protected observer attachment is absent".into())
        })?;
        let worker_witness = parsed_candidate_unix_absence_observer(worker_observer)?;
        if hash_bytes(&gate_bytes) != sampled.gate_sha256
            || gate.witness.target.pid != sampled.target_pid
            || gate.witness.target.start_time != sampled.target_start_time
            || gate.witness.challenge_sha256 != hash_bytes(&challenge)
            || gate.witness.before_release.network_namespace_inode
                != sampled.observed.network_namespace_inode
            || gate
                .witness
                .after_denials_before_ack
                .network_namespace_inode
                != sampled.observed.network_namespace_inode
            || gate.witness != worker_witness
            || ack.schema_version != 1
            || ack.selector != UNIX_INTENT_SELECTOR
            || ack.result_key != *key
            || ack.challenge_sha256 != hash_bytes(&challenge)
            || ack.gate_sha256 != sampled.gate_sha256
            || ack.observed != sampled.observed
            || serde_json::to_vec(&ack)? != ack_bytes
        {
            return Err(CiError::Message(
                "Unix independent live join differs".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready(
    _challenge: [u8; 32],
) -> Result<Option<IndependentUnixLiveSampleV1>> {
    Err(CiError::Message(
        "Unix live observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn sample_and_ack_if_ready_with_source(
    _challenge: [u8; 32],
    _source: impl FnOnce(u32, u64) -> Result<()>,
) -> Result<Option<IndependentUnixLiveSampleV1>> {
    Err(CiError::Message(
        "Unix live observation requires native Linux".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn join_sampled_unix_to_result(
    _case: &crate::private_protected_readback::StructuralProtectedNativeCaseV1,
    _sampled: &IndependentUnixLiveSampleV1,
    _challenge: [u8; 32],
) -> Result<()> {
    Err(CiError::Message(
        "Unix live observation requires native Linux".into(),
    ))
}
