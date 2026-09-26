//! Installed-public retirement obstruction. A root observer holds the exact
//! first target's network namespace fd while the real native owner settles
//! processes. Only the held namespace prevents full retirement; no success
//! terminal or synthetic cleanup result is made for that first launch.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use memcordon_core::{BoundedText, DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::{
    PrivateAttemptPhase, PrivateAttemptRecordV4, ProcessIdentityV4, ReleaseKnowledge,
};
use crate::protocol::{Frame, MessageKind};
use crate::rejection::{RejectionCleanupV1, RejectionPhaseV1, RejectionV1};

pub(crate) const SELECTOR: &str = "private_tcp::retirement_failure_blocks_reuse";
const ROOT: &str = "/var/lib/memcordon/sealed/private-public-reuse";
const LIMIT: Duration = Duration::from_secs(20);
const MAX_RECORD: u64 = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReuseIntentV1 {
    schema_version: u8,
    selector: String,
    challenge: DiagnosticSha256,
    result_key: DiagnosticSha256,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    boot_id: String,
    holder: ProcessIdentityV4,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GatedTargetV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    target: ProcessIdentityV4,
    namespace_inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderOpenV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    holder: ProcessIdentityV4,
    held_fd: u32,
    namespace_inode: u64,
    opened_boot_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HolderCloseV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    holder: ProcessIdentityV4,
    held_fd: u32,
    namespace_inode: u64,
    closed_boot_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeSettledV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    namespace_inode: u64,
    checkpoint_sha256: DiagnosticSha256,
    holder: ProcessIdentityV4,
    held_fd: u32,
    settled_boot_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FailureV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    attempt_id: String,
    response_sha256: DiagnosticSha256,
    durable_incomplete_state_sha256: DiagnosticSha256,
    failure_boot_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BlockedV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    first_attempt_id: String,
    second_attempt_id: String,
    request_sha256: DiagnosticSha256,
    rejection_sha256: DiagnosticSha256,
    blocked_boot_nanos: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveredCleanupV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    first_attempt_id: String,
    namespace_inode: u64,
    holder_closed_boot_nanos: u64,
    recovery_boot_nanos: u64,
    durable_attempt_record_absent: bool,
}

pub(crate) fn verify_recovered_cleanup_bytes(
    bytes: &[u8],
    key: &DiagnosticSha256,
    attempt_id: &str,
) -> Result<(), String> {
    memcordon_core::workload_contract::reject_duplicate_json_keys(bytes)?;
    let record: RecoveredCleanupV1 = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes
        || record.schema_version != 1
        || record.result_key != *key
        || record.first_attempt_id != attempt_id
        || record.namespace_inode == 0
        || record.holder_closed_boot_nanos == 0
        || record.recovery_boot_nanos < record.holder_closed_boot_nanos
        || !record.durable_attempt_record_absent
    {
        return Err("MCSEALED-PUBLIC-REUSE: recovered cleanup bytes differ".into());
    }
    let dir = directory(key)?;
    if super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "recovered-cleanup.bin",
        "recovered-cleanup.bin.new",
    )? != bytes
    {
        return Err("MCSEALED-PUBLIC-REUSE: recovered cleanup journal differs".into());
    }
    Ok(())
}

pub(crate) fn verify_provider_response_bytes(
    key: &DiagnosticSha256,
    ordinal: usize,
    bytes: &[u8],
) -> Result<(), String> {
    let (leaf, temp) = match ordinal {
        0 => ("first-failure.bin", "first-failure.bin.new"),
        1 => ("blocked-rejection.bin", "blocked-rejection.bin.new"),
        _ => return Err("MCSEALED-PUBLIC-REUSE: provider ordinal differs".into()),
    };
    if super::private_release_alt_abi_raw::read_immutable(&directory(key)?, leaf, temp)? != bytes {
        return Err("MCSEALED-PUBLIC-REUSE: provider response journal differs".into());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReuseTranscriptV1 {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    boot_id: String,
    installation_epoch: DiagnosticSha256,
    active_h1_receipt_sha256: DiagnosticSha256,
    first_attempt_id: String,
    second_attempt_id: String,
    cleanup_failure_sha256: DiagnosticSha256,
    durable_incomplete_state_sha256: DiagnosticSha256,
    namespace_inode: u64,
    holder_pid: u32,
    holder_start_time: u64,
    held_fd: u32,
    failure_boot_nanos: u64,
    blocked_request_sha256: DiagnosticSha256,
    blocked_rejection_sha256: DiagnosticSha256,
    blocked_boot_nanos: u64,
    namespace_fd_closed_boot_nanos: u64,
    recovered_cleanup_sha256: DiagnosticSha256,
    recovery_boot_nanos: u64,
    durable_attempt_record_absent_after_recovery: bool,
}

fn boot_id() -> Result<String, String> {
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").map_err(|e| e.to_string())?;
    let boot = boot.trim();
    if boot.len() != 36
        || !boot
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b'-')
    {
        return Err("MCSEALED-PUBLIC-REUSE: boot identity differs".into());
    }
    Ok(boot.into())
}

fn boot_nanos() -> Result<u64, String> {
    let mut stamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut stamp) } != 0
        || stamp.tv_sec < 0
        || stamp.tv_nsec < 0
    {
        return Err("MCSEALED-PUBLIC-REUSE: boottime unavailable".into());
    }
    u64::try_from(stamp.tv_sec)
        .ok()
        .and_then(|s| s.checked_mul(1_000_000_000))
        .and_then(|s| s.checked_add(stamp.tv_nsec as u64))
        .filter(|value| *value != 0)
        .ok_or("MCSEALED-PUBLIC-REUSE: boottime overflow".into())
}

fn observe(pid: libc::pid_t) -> Result<ProcessIdentityV4, String> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err("MCSEALED-PUBLIC-REUSE: pidfd unavailable".into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    ProcessIdentityV4::observe(pid, fd.as_fd())
}

fn original_process_absent(identity: &ProcessIdentityV4) -> Result<bool, String> {
    match fs::symlink_metadata(format!("/proc/{}", identity.pid)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.to_string()),
        Ok(_) => Ok(observe(identity.pid as libc::pid_t)? != *identity),
    }
}

fn installed_root() -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PUBLIC-REUSE: root required".into());
    }
    let current = fs::metadata(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let installed =
        fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent").map_err(|e| e.to_string())?;
    if !installed.is_file() || current.dev() != installed.dev() || current.ino() != installed.ino()
    {
        return Err("MCSEALED-PUBLIC-REUSE: installed agent image required".into());
    }
    Ok(())
}

fn parse_case(
    selector: &str,
    challenge_hex: &str,
    dispatch_hex: &str,
) -> Result<(DiagnosticSha256, DiagnosticSha256), String> {
    if selector != SELECTOR {
        return Err("MCSEALED-PUBLIC-REUSE: selector differs".into());
    }
    let challenge =
        DiagnosticSha256::try_from(BoundedText::new(challenge_hex).map_err(str::to_owned)?)
            .map_err(str::to_owned)?;
    let key = DiagnosticSha256::try_from(BoundedText::new(dispatch_hex).map_err(str::to_owned)?)
        .map_err(str::to_owned)?;
    if challenge.bytes() == &[0; 32]
        || key
            != memcordon_core::private_release_case_v1::private_release_case_key_v1(
                memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
                SELECTOR,
                challenge.bytes(),
            )?
    {
        return Err("MCSEALED-PUBLIC-REUSE: final-public dispatch binding differs".into());
    }
    Ok((challenge, key))
}

#[cfg(feature = "test-support")]
pub(crate) fn validate_command_for_test(
    selector: &str,
    challenge_hex: &str,
    dispatch_hex: &str,
) -> Result<(), String> {
    parse_case(selector, challenge_hex, dispatch_hex).map(|_| ())
}

fn root() -> Result<PathBuf, String> {
    super::attempt::secure_state_root()?;
    let path = PathBuf::from(ROOT);
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|e| e.to_string())?;
    }
    let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-REUSE: protected root differs".into());
    }
    Ok(path)
}

fn directory(key: &DiagnosticSha256) -> Result<File, String> {
    let path = root()?.join(String::from(key.clone()));
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-REUSE: protected case differs".into());
    }
    Ok(file)
}

fn write<T: Serialize>(
    directory: &File,
    name: &'static str,
    temp: &'static str,
    record: &T,
) -> Result<DiagnosticSha256, String> {
    let bytes = serde_json::to_vec(record).map_err(|e| e.to_string())?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD as usize {
        return Err("MCSEALED-PUBLIC-REUSE: leaf bound differs".into());
    }
    super::private_release_alt_abi_raw::write_immutable(directory, name, temp, &bytes)?;
    Ok(hash_bytes(&bytes))
}

fn read<T: for<'de> Deserialize<'de> + Serialize>(
    directory: &File,
    name: &'static str,
    temp: &'static str,
) -> Result<T, String> {
    let bytes = super::private_release_alt_abi_raw::read_immutable(directory, name, temp)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD as usize {
        return Err("MCSEALED-PUBLIC-REUSE: leaf bound differs".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(&bytes)?;
    let record: T = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&record).map_err(|e| e.to_string())? != bytes {
        return Err("MCSEALED-PUBLIC-REUSE: canonical leaf differs".into());
    }
    Ok(record)
}

fn exact_record(attempt_id: &str) -> Result<(Vec<u8>, PrivateAttemptRecordV4), String> {
    if !super::cgroup::valid_attempt_identity(attempt_id) {
        return Err("MCSEALED-PUBLIC-REUSE: attempt identity differs".into());
    }
    let bytes = super::installed_release_qualification::read_protected_absolute(
        &Path::new(super::STATE_ROOT).join(attempt_id),
        super::private_attempt::MAX_PRIVATE_RECORD_BYTES as u64,
        Some(0o600),
    )?;
    let record = PrivateAttemptRecordV4::parse(&bytes)?;
    if record.attempt_id.as_str() != attempt_id || record.boot_identity.as_str() != boot_id()? {
        return Err("MCSEALED-PUBLIC-REUSE: durable attempt differs".into());
    }
    Ok((bytes, record))
}

fn live_holder(open: &HolderOpenV1, expected_ns: u64) -> Result<(), String> {
    if open.schema_version != 1 || open.namespace_inode != expected_ns || open.held_fd <= 2 {
        return Err("MCSEALED-PUBLIC-REUSE: holder binding differs".into());
    }
    let identity = observe(open.holder.pid as libc::pid_t)?;
    if identity != open.holder {
        return Err("MCSEALED-PUBLIC-REUSE: holder PID reused".into());
    }
    let link = fs::read_link(format!("/proc/{}/fd/{}", open.holder.pid, open.held_fd))
        .map_err(|e| e.to_string())?;
    if link.to_string_lossy() != format!("net:[{expected_ns}]") {
        return Err("MCSEALED-PUBLIC-REUSE: held namespace fd differs".into());
    }
    let meta = fs::metadata(format!("/proc/{}/fd/{}", open.holder.pid, open.held_fd))
        .map_err(|e| e.to_string())?;
    if meta.ino() != expected_ns {
        return Err("MCSEALED-PUBLIC-REUSE: held namespace inode differs".into());
    }
    Ok(())
}

/// Long-running root observer. The gated target waits for this owned fd before
/// release. The command does not report completion until a distinct release
/// command asks it to close the exact fd after the second refusal.
pub(crate) fn hold(selector: &str, challenge_hex: &str, dispatch_hex: &str) -> Result<(), String> {
    installed_root()?;
    super::private_public_provider::verify_prepared_reuse_helper_admission(
        selector,
        challenge_hex,
    )?;
    let (challenge, key) = parse_case(selector, challenge_hex, dispatch_hex)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    // The CI starts the holder while the public CLI is still gated. Only the
    // exact authenticated empty registration may wait for its actual accepted
    // plan; wrong keys/phases/installation fail immediately, never downgrade.
    let plan_deadline = Instant::now() + Duration::from_secs(30);
    let provider = loop {
        match super::private_public_provider::current_reuse_binding(Some(&key), None) {
            Ok(binding) => break binding,
            Err(error) => {
                if !super::private_public_provider::reuse_holder_registration_pending(&key)?
                    || Instant::now() >= plan_deadline
                {
                    return Err(error);
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    };
    if provider.challenge != challenge_hex
        || provider.ordinal != 0
        || provider.first_attempt_id.is_some()
        || provider.installation_epoch != *lease.generation_digest()
        || provider.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
    {
        return Err("MCSEALED-PUBLIC-REUSE: holder provider registration differs".into());
    }
    let root = root()?;
    let path = root.join(String::from(key.clone()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&path)
        .map_err(|e| e.to_string())?;
    let dir = directory(&key)?;
    let intent = ReuseIntentV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        challenge,
        result_key: key.clone(),
        installation_epoch: lease.generation_digest().clone(),
        active_h1_receipt_sha256: lease.active_host_receipt_sha256().clone(),
        boot_id: boot_id()?,
        holder: observe(unsafe { libc::getpid() })?,
    };
    write(&dir, "intent.json", "intent.json.new", &intent)?;
    let deadline = Instant::now() + LIMIT;
    let gate = loop {
        match read::<GatedTargetV1>(&dir, "gate.json", "gate.json.new") {
            Ok(gate) => break gate,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                return Err(format!(
                    "MCSEALED-PUBLIC-REUSE: gated target absent: {error}"
                ));
            }
        }
    };
    if gate.schema_version != 1
        || gate.result_key != key
        || gate.namespace_inode == 0
        || gate.attempt_id.is_empty()
    {
        return Err("MCSEALED-PUBLIC-REUSE: gated target differs".into());
    }
    if observe(gate.target.pid as libc::pid_t)? != gate.target {
        return Err("MCSEALED-PUBLIC-REUSE: gated target PID reused".into());
    }
    // Namespace entries are proc magic links: follow this exact live task's
    // entry, then independently bind the opened object and task identity.
    let namespace_path = Path::new("/proc")
        .join(gate.target.pid.to_string())
        .join("ns")
        .join("net");
    let fd = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC)
        .open(namespace_path)
        .map_err(|e| e.to_string())?;
    if fd.metadata().map_err(|e| e.to_string())?.ino() != gate.namespace_inode
        || observe(gate.target.pid as libc::pid_t)? != gate.target
    {
        return Err("MCSEALED-PUBLIC-REUSE: gated network namespace differs".into());
    }
    let open = HolderOpenV1 {
        schema_version: 1,
        result_key: key.clone(),
        attempt_id: gate.attempt_id,
        holder: intent.holder.clone(),
        held_fd: fd.as_raw_fd() as u32,
        namespace_inode: gate.namespace_inode,
        opened_boot_nanos: boot_nanos()?,
    };
    write(&dir, "holder-open.json", "holder-open.json.new", &open)?;
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Ok(release) =
            read::<ReleaseRequestV1>(&dir, "release-request.json", "release-request.json.new")
        {
            let blocked: BlockedV1 = read(&dir, "blocked.json", "blocked.json.new")?;
            if release.schema_version != 1
                || release.result_key != key
                || release.blocked_sha256 != blocked.rejection_sha256
                || blocked.result_key != key
                || blocked.first_attempt_id != open.attempt_id
                || blocked.blocked_boot_nanos < open.opened_boot_nanos
            {
                return Err("MCSEALED-PUBLIC-REUSE: holder release request differs".into());
            }
            break;
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PUBLIC-REUSE: holder release timed out".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    live_holder(&open, gate.namespace_inode)?;
    drop(fd);
    let close = HolderCloseV1 {
        schema_version: 1,
        result_key: key,
        attempt_id: open.attempt_id,
        holder: intent.holder,
        held_fd: open.held_fd,
        namespace_inode: open.namespace_inode,
        closed_boot_nanos: boot_nanos()?,
    };
    write(&dir, "holder-close.json", "holder-close.json.new", &close)?;
    lease.revalidate_release_boundary()?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseRequestV1 {
    schema_version: u8,
    result_key: DiagnosticSha256,
    blocked_sha256: DiagnosticSha256,
}

pub(crate) fn release(selector: &str, challenge: &str, key_hex: &str) -> Result<(), String> {
    installed_root()?;
    let (challenge, key) = parse_case(selector, challenge, key_hex)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let dir = directory(&key)?;
    let intent: ReuseIntentV1 = read(&dir, "intent.json", "intent.json.new")?;
    let blocked: BlockedV1 = read(&dir, "blocked.json", "blocked.json.new")?;
    if intent.result_key != key
        || intent.challenge != challenge
        || intent.installation_epoch != *lease.generation_digest()
        || intent.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || blocked.result_key != key
    {
        return Err("MCSEALED-PUBLIC-REUSE: release authority differs".into());
    }
    super::private_public_provider::preflight_reuse_recovery(
        &key,
        &blocked.first_attempt_id,
        &blocked.second_attempt_id,
    )?;
    let request = ReleaseRequestV1 {
        schema_version: 1,
        result_key: key,
        blocked_sha256: blocked.rejection_sha256,
    };
    write(
        &dir,
        "release-request.json",
        "release-request.json.new",
        &request,
    )?;
    lease.revalidate_release_boundary()
}

/// The observer's recovery interval is an installed-agent uprobe bracket,
/// not a pair of independently timed root commands. A CI parent first spawns
/// this child with piped stdin, observes its real PID/start/cgroup, arms the
/// probe, then writes exactly `G` to release the gate. The holder is a
/// different child and must be reaped by that parent while this bracket is
/// armed. No probe event or journal leaf is synthesized by this operation.
pub(crate) fn release_and_recover(
    selector: &str,
    challenge_hex: &str,
    key_hex: &str,
) -> Result<(), String> {
    installed_root()?;
    super::private_public_provider::verify_prepared_reuse_helper_admission(
        selector,
        challenge_hex,
    )?;
    let (challenge, key) = parse_case(selector, challenge_hex, key_hex)?;
    let dir = directory(&key)?;
    let intent: ReuseIntentV1 = read(&dir, "intent.json", "intent.json.new")?;
    let blocked: BlockedV1 = read(&dir, "blocked.json", "blocked.json.new")?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    if intent.result_key != key
        || intent.challenge != challenge
        || blocked.result_key != key
        || open.result_key != key
        || open.holder != intent.holder
        || open.attempt_id != blocked.first_attempt_id
    {
        return Err("MCSEALED-PUBLIC-REUSE: recovery gate custody differs".into());
    }
    super::private_public_provider::preflight_reuse_recovery(
        &key,
        &blocked.first_attempt_id,
        &blocked.second_attempt_id,
    )?;
    wait_recovery_gate()?;
    super::private_observer_hooks::mc_private_request_enter_v1();
    let result = (|| {
        release(selector, challenge_hex, key_hex)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(close) =
                read::<HolderCloseV1>(&dir, "holder-close.json", "holder-close.json.new")
            {
                if close.schema_version != 1
                    || close.result_key != key
                    || close.attempt_id != open.attempt_id
                    || close.holder != open.holder
                    || close.held_fd != open.held_fd
                    || close.namespace_inode != open.namespace_inode
                    || close.closed_boot_nanos <= blocked.blocked_boot_nanos
                {
                    return Err("MCSEALED-PUBLIC-REUSE: recovery holder close differs".into());
                }
                if original_process_absent(&close.holder)? {
                    break;
                }
            }
            if Instant::now() >= deadline {
                return Err("MCSEALED-PUBLIC-REUSE: recovery holder reap timed out".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        recover(selector, challenge_hex, key_hex)
    })();
    super::private_observer_hooks::mc_private_request_exit_v1();
    result
}

fn wait_recovery_gate() -> Result<(), String> {
    let mut poll = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&raw mut poll, 1, 20_000) } != 1 || poll.revents & libc::POLLIN == 0 {
        return Err("MCSEALED-PUBLIC-REUSE: recovery arm gate absent".into());
    }
    let mut gate = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut gate)
        .map_err(|error| error.to_string())?;
    if gate != [b'G'] {
        return Err("MCSEALED-PUBLIC-REUSE: recovery arm gate differs".into());
    }
    Ok(())
}

/// Called while the first target is still gated, after provider identity was
/// durably written. A missing exact holder never lets the private release run.
pub(crate) fn gated_target(
    attempt_id: &str,
    target: &ProcessIdentityV4,
    namespace_inode: u64,
) -> Result<(), String> {
    let Some(provider) = super::private_public_provider::reuse_binding_for_attempt(attempt_id)?
    else {
        return Ok(());
    };
    if provider.ordinal != 0 {
        return Err("MCSEALED-PUBLIC-REUSE: second target was allocated".into());
    }
    // The CLI and holder start concurrently after registration. Wait only
    // for an absent immutable intent; malformed/existing records fail closed.
    let intent_path = root()?
        .join(String::from(provider.result_key.clone()))
        .join("intent.json");
    let deadline = Instant::now() + LIMIT;
    loop {
        super::private_public_provider::current_reuse_binding(
            Some(&provider.result_key),
            Some(attempt_id),
        )?;
        match fs::symlink_metadata(&intent_path) {
            Ok(_) => break,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    let dir = directory(&provider.result_key)?;
    let intent: ReuseIntentV1 = read(&dir, "intent.json", "intent.json.new")?;
    if intent.schema_version != 1
        || intent.selector != SELECTOR
        || intent.result_key != provider.result_key
        || String::from(intent.challenge.clone()) != provider.challenge
        || intent.installation_epoch != provider.installation_epoch
        || intent.active_h1_receipt_sha256 != provider.active_h1_receipt_sha256
        || intent.boot_id != boot_id()?
        || observe(intent.holder.pid as libc::pid_t)? != intent.holder
    {
        return Err("MCSEALED-PUBLIC-REUSE: held intent differs".into());
    }
    let gate = GatedTargetV1 {
        schema_version: 1,
        result_key: provider.result_key.clone(),
        attempt_id: attempt_id.into(),
        target: target.clone(),
        namespace_inode,
    };
    write(&dir, "gate.json", "gate.json.new", &gate)?;
    let deadline = Instant::now() + LIMIT;
    loop {
        match read::<HolderOpenV1>(&dir, "holder-open.json", "holder-open.json.new") {
            Ok(open)
                if open.result_key == provider.result_key
                    && open.attempt_id == attempt_id
                    && open.holder == intent.holder
                    && live_holder(&open, namespace_inode).is_ok() =>
            {
                return Ok(());
            }
            Ok(_) => return Err("MCSEALED-PUBLIC-REUSE: holder observation differs".into()),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            Err(error) => {
                return Err(format!(
                    "MCSEALED-PUBLIC-REUSE: holder did not arm: {error}"
                ));
            }
        }
    }
}

/// Native owner calls only after target/cgroup/guardian settlement and before
/// durable removal. An open external namespace fd is a real residual resource
/// and must force the durable `CleanupIncomplete` transition.
pub(crate) fn retire_obstructed(record: &PrivateAttemptRecordV4) -> Result<(), String> {
    let attempt = record.attempt_id.as_str();
    let Some(provider) = super::private_public_provider::reuse_binding_for_attempt(attempt)? else {
        return Ok(());
    };
    if provider.ordinal != 0 || record.release_knowledge != ReleaseKnowledge::ExecObserved {
        return Err("MCSEALED-PUBLIC-REUSE: retirement attempt differs".into());
    }
    let dir = directory(&provider.result_key)?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    let namespace = record
        .network_namespace_inode
        .ok_or("MCSEALED-PUBLIC-REUSE: network inode absent")?;
    if open.result_key != provider.result_key || open.attempt_id != attempt {
        return Err("MCSEALED-PUBLIC-REUSE: holder attempt differs".into());
    }
    live_holder(&open, namespace)?;
    let settled = NativeSettledV1 {
        schema_version: 1,
        result_key: provider.result_key,
        attempt_id: attempt.into(),
        namespace_inode: namespace,
        checkpoint_sha256: record
            .checkpoint_digest
            .clone()
            .ok_or("MCSEALED-PUBLIC-REUSE: checkpoint absent")?,
        holder: open.holder,
        held_fd: open.held_fd,
        settled_boot_nanos: boot_nanos()?,
    };
    write(
        &dir,
        "native-settled.json",
        "native-settled.json.new",
        &settled,
    )?;
    Err(
        "MCSEALED-PUBLIC-REUSE-HELD-NAMESPACE-FD: exact observer namespace handle still open"
            .into(),
    )
}

pub(crate) fn first_failure(request: &Frame, broker: &Frame) -> Result<Option<Frame>, String> {
    let attempt = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let Some(provider) = super::private_public_provider::reuse_binding_for_attempt(&attempt)?
    else {
        return Ok(None);
    };
    if provider.ordinal != 0 || broker.kind != MessageKind::Rejected {
        return Err("MCSEALED-PUBLIC-REUSE: first broker outcome differs".into());
    }
    super::private_execution::validate_reuse_obstruction_rejection(
        &broker.payload,
        request.attempt_id,
    )?;
    let (durable, record) = exact_record(&attempt)?;
    if record.phase != PrivateAttemptPhase::CleanupIncomplete || record.checkpoint_digest.is_none()
    {
        return Err("MCSEALED-PUBLIC-REUSE: durable incomplete state absent".into());
    }
    let dir = directory(&provider.result_key)?;
    let settled: NativeSettledV1 = read(&dir, "native-settled.json", "native-settled.json.new")?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    if settled.result_key != provider.result_key
        || settled.attempt_id != attempt
        || settled.checkpoint_sha256 != record.checkpoint_digest.clone().expect("checked")
        || settled.namespace_inode
            != record
                .network_namespace_inode
                .ok_or("network inode absent")?
    {
        return Err("MCSEALED-PUBLIC-REUSE: native settlement differs".into());
    }
    live_holder(&open, settled.namespace_inode)?;
    let rejection = RejectionV1::from_launch_facts(
        "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE",
        RejectionPhaseV1::Retirement,
        "released target and native owner settled; held observer namespace fd blocks complete retirement",
        true,
        true,
        RejectionCleanupV1 {
            attempted: true,
            direct_child_reaped: true,
            workload_empty: Some(true),
            helpers_reaped: true,
            containment_removed: true,
            sealed_boundary_retired: false,
            errors: vec!["MCSEALED-PUBLIC-REUSE-HELD-NAMESPACE-FD".into()],
        },
    )?;
    let payload = rejection.encode()?;
    let failure = FailureV1 {
        schema_version: 1,
        result_key: provider.result_key,
        attempt_id: attempt,
        response_sha256: hash_bytes(&payload),
        durable_incomplete_state_sha256: hash_bytes(&durable),
        failure_boot_nanos: boot_nanos()?,
    };
    write(
        &dir,
        "first-failure.json",
        "first-failure.json.new",
        &failure,
    )?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "incomplete-v4.bin",
        "incomplete-v4.bin.new",
        &durable,
    )?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "first-failure.bin",
        "first-failure.bin.new",
        &payload,
    )?;
    Ok(Some(Frame {
        kind: MessageKind::Rejected,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload,
    }))
}

pub(crate) fn blocked_second(request: &Frame) -> Result<Option<RejectionV1>, String> {
    let attempt = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let Some(provider) = super::private_public_provider::reuse_binding_for_attempt(&attempt)?
    else {
        return Ok(None);
    };
    if provider.ordinal != 1 {
        return Err("MCSEALED-PUBLIC-REUSE: second ordinal differs".into());
    }
    let first = provider
        .first_attempt_id
        .ok_or("MCSEALED-PUBLIC-REUSE: first attempt absent")?;
    let (_, durable) = exact_record(&first)?;
    let dir = directory(&provider.result_key)?;
    let failure: FailureV1 = read(&dir, "first-failure.json", "first-failure.json.new")?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    if durable.phase != PrivateAttemptPhase::CleanupIncomplete
        || failure.attempt_id != first
        || failure.result_key != provider.result_key
        || open.attempt_id != first
    {
        return Err("MCSEALED-PUBLIC-REUSE: incomplete first attempt not preserved".into());
    }
    live_holder(
        &open,
        durable
            .network_namespace_inode
            .ok_or("network inode absent")?,
    )?;
    Ok(Some(RejectionV1::request_error(
        "MCSEALED-PRIVATE-REUSE-BLOCKED",
        "first public attempt remains CleanupIncomplete with live observer namespace fd",
    )))
}

pub(crate) fn record_blocked(request: &Frame, response: &Frame) -> Result<(), String> {
    let attempt = request
        .attempt_id
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let Some(provider) = super::private_public_provider::reuse_binding_for_attempt(&attempt)?
    else {
        return Ok(());
    };
    if provider.ordinal == 0 {
        return Ok(());
    }
    if provider.ordinal != 1 || response.kind != MessageKind::Rejected {
        return Err("MCSEALED-PUBLIC-REUSE: blocked response differs".into());
    }
    let rejection =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&response.payload)?;
    if rejection.code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
        || rejection.target_created
        || rejection.target_released
    {
        return Err("MCSEALED-PUBLIC-REUSE: second launch was not preallocation blocked".into());
    }
    let first = provider
        .first_attempt_id
        .ok_or("MCSEALED-PUBLIC-REUSE: first attempt absent")?;
    let dir = directory(&provider.result_key)?;
    let blocked = BlockedV1 {
        schema_version: 1,
        result_key: provider.result_key,
        first_attempt_id: first,
        second_attempt_id: attempt,
        request_sha256: hash_bytes(&request.payload),
        rejection_sha256: hash_bytes(&response.payload),
        blocked_boot_nanos: boot_nanos()?,
    };
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "blocked-request.bin",
        "blocked-request.bin.new",
        &request.payload,
    )?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "blocked-rejection.bin",
        "blocked-rejection.bin.new",
        &response.payload,
    )?;
    write(&dir, "blocked.json", "blocked.json.new", &blocked)?;
    Ok(())
}

pub(crate) fn recover(selector: &str, challenge: &str, key_hex: &str) -> Result<(), String> {
    installed_root()?;
    let (challenge, key) = parse_case(selector, challenge, key_hex)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let dir = directory(&key)?;
    let intent: ReuseIntentV1 = read(&dir, "intent.json", "intent.json.new")?;
    let failure: FailureV1 = read(&dir, "first-failure.json", "first-failure.json.new")?;
    let blocked: BlockedV1 = read(&dir, "blocked.json", "blocked.json.new")?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    let close: HolderCloseV1 = read(&dir, "holder-close.json", "holder-close.json.new")?;
    if intent.result_key != key
        || intent.challenge != challenge
        || intent.boot_id != boot_id()?
        || intent.installation_epoch != *lease.generation_digest()
        || intent.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || failure.result_key != key
        || blocked.result_key != key
        || failure.attempt_id != blocked.first_attempt_id
        || open.attempt_id != failure.attempt_id
        || close.attempt_id != failure.attempt_id
        || close.held_fd != open.held_fd
        || close.namespace_inode != open.namespace_inode
        || close.holder != open.holder
        || close.closed_boot_nanos <= blocked.blocked_boot_nanos
    {
        return Err("MCSEALED-PUBLIC-REUSE: recovery custody differs".into());
    }
    if !original_process_absent(&close.holder)? {
        return Err("MCSEALED-PUBLIC-REUSE: namespace holder not reaped".into());
    }
    let (durable, record) = exact_record(&failure.attempt_id)?;
    if hash_bytes(&durable) != failure.durable_incomplete_state_sha256
        || record.phase != PrivateAttemptPhase::CleanupIncomplete
        || record.network_namespace_inode != Some(open.namespace_inode)
    {
        return Err("MCSEALED-PUBLIC-REUSE: durable failure changed".into());
    }
    super::private_public_provider::preflight_reuse_recovery(
        &key,
        &failure.attempt_id,
        &blocked.second_attempt_id,
    )?;
    super::private_attempt::recover_exact_reuse_incomplete(&failure.attempt_id, &record)?;
    let recovery_boot_nanos = boot_nanos()?;
    let cleanup = RecoveredCleanupV1 {
        schema_version: 1,
        result_key: key.clone(),
        first_attempt_id: failure.attempt_id.clone(),
        namespace_inode: open.namespace_inode,
        holder_closed_boot_nanos: close.closed_boot_nanos,
        recovery_boot_nanos,
        durable_attempt_record_absent: true,
    };
    let cleanup_bytes = serde_json::to_vec(&cleanup).map_err(|e| e.to_string())?;
    super::private_release_alt_abi_raw::write_immutable(
        &dir,
        "recovered-cleanup.bin",
        "recovered-cleanup.bin.new",
        &cleanup_bytes,
    )?;
    super::private_public_provider::complete_reuse_recovery(
        &key,
        &failure.attempt_id,
        &cleanup_bytes,
    )?;
    let transcript = ReuseTranscriptV1 {
        schema_version: 1,
        selector: SELECTOR.into(),
        result_key: key,
        boot_id: intent.boot_id,
        installation_epoch: intent.installation_epoch,
        active_h1_receipt_sha256: intent.active_h1_receipt_sha256,
        first_attempt_id: failure.attempt_id,
        second_attempt_id: blocked.second_attempt_id,
        cleanup_failure_sha256: failure.response_sha256,
        durable_incomplete_state_sha256: failure.durable_incomplete_state_sha256,
        namespace_inode: open.namespace_inode,
        holder_pid: open.holder.pid,
        holder_start_time: open.holder.start_time,
        held_fd: open.held_fd,
        failure_boot_nanos: failure.failure_boot_nanos,
        blocked_request_sha256: blocked.request_sha256,
        blocked_rejection_sha256: blocked.rejection_sha256,
        blocked_boot_nanos: blocked.blocked_boot_nanos,
        namespace_fd_closed_boot_nanos: close.closed_boot_nanos,
        recovered_cleanup_sha256: hash_bytes(&cleanup_bytes),
        recovery_boot_nanos,
        durable_attempt_record_absent_after_recovery: true,
    };
    write(&dir, "reuse.json", "reuse.json.new", &transcript)?;
    lease.revalidate_release_boundary()?;
    Ok(())
}

/// Detached installed-generation readback. The recovered state is never
/// reconstructed from a claimant's transcript: all leaves are reopened from
/// the protected journal and the provider independently replays its own V2
/// transcript before these bytes may be exported to the final-public join.
pub(crate) fn verify_completed(
    selector: &str,
    challenge_hex: &str,
    key_hex: &str,
) -> Result<String, String> {
    installed_root()?;
    let (challenge, key) = parse_case(selector, challenge_hex, key_hex)?;
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let dir = directory(&key)?;
    let intent: ReuseIntentV1 = read(&dir, "intent.json", "intent.json.new")?;
    let gate: GatedTargetV1 = read(&dir, "gate.json", "gate.json.new")?;
    let open: HolderOpenV1 = read(&dir, "holder-open.json", "holder-open.json.new")?;
    let settled: NativeSettledV1 = read(&dir, "native-settled.json", "native-settled.json.new")?;
    let failure: FailureV1 = read(&dir, "first-failure.json", "first-failure.json.new")?;
    let blocked: BlockedV1 = read(&dir, "blocked.json", "blocked.json.new")?;
    let release: ReleaseRequestV1 = read(&dir, "release-request.json", "release-request.json.new")?;
    let close: HolderCloseV1 = read(&dir, "holder-close.json", "holder-close.json.new")?;
    let transcript: ReuseTranscriptV1 = read(&dir, "reuse.json", "reuse.json.new")?;
    let incomplete = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "incomplete-v4.bin",
        "incomplete-v4.bin.new",
    )?;
    let durable = PrivateAttemptRecordV4::parse(&incomplete)?;
    let first = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "first-failure.bin",
        "first-failure.bin.new",
    )?;
    let second_request = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "blocked-request.bin",
        "blocked-request.bin.new",
    )?;
    let second_response = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "blocked-rejection.bin",
        "blocked-rejection.bin.new",
    )?;
    let recovery = super::private_release_alt_abi_raw::read_immutable(
        &dir,
        "recovered-cleanup.bin",
        "recovered-cleanup.bin.new",
    )?;
    verify_recovered_cleanup_bytes(&recovery, &key, &failure.attempt_id)?;
    let recovered: RecoveredCleanupV1 =
        serde_json::from_slice(&recovery).map_err(|error| error.to_string())?;
    let first_rejection = memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&first)?;
    let second_rejection =
        memcordon_core::provider_rejection_wire::RejectionWireV1::parse(&second_response)?;
    if intent.schema_version != 1
        || intent.selector != SELECTOR
        || intent.challenge != challenge
        || intent.result_key != key
        || intent.installation_epoch != *lease.generation_digest()
        || intent.active_h1_receipt_sha256 != *lease.active_host_receipt_sha256()
        || intent.boot_id != boot_id()?
        || gate.schema_version != 1
        || gate.result_key != key
        || gate.attempt_id != failure.attempt_id
        || gate.namespace_inode == 0
        || open.schema_version != 1
        || open.result_key != key
        || open.attempt_id != gate.attempt_id
        || open.holder != intent.holder
        || open.namespace_inode != gate.namespace_inode
        || open.held_fd <= 2
        || settled.schema_version != 1
        || settled.result_key != key
        || settled.attempt_id != gate.attempt_id
        || settled.namespace_inode != gate.namespace_inode
        || settled.holder != intent.holder
        || settled.held_fd != open.held_fd
        || settled.checkpoint_sha256
            != durable
                .checkpoint_digest
                .clone()
                .ok_or("reuse checkpoint absent")?
        || failure.schema_version != 1
        || failure.result_key != key
        || failure.response_sha256 != hash_bytes(&first)
        || failure.durable_incomplete_state_sha256 != hash_bytes(&incomplete)
        || durable.attempt_id.as_str() != failure.attempt_id
        || durable.phase != PrivateAttemptPhase::CleanupIncomplete
        || durable.network_namespace_inode != Some(gate.namespace_inode)
        || blocked.schema_version != 1
        || blocked.result_key != key
        || blocked.first_attempt_id != failure.attempt_id
        || blocked.second_attempt_id == blocked.first_attempt_id
        || blocked.request_sha256 != hash_bytes(&second_request)
        || blocked.rejection_sha256 != hash_bytes(&second_response)
        || release.schema_version != 1
        || release.result_key != key
        || release.blocked_sha256 != blocked.rejection_sha256
        || close.schema_version != 1
        || close.result_key != key
        || close.attempt_id != open.attempt_id
        || close.holder != open.holder
        || close.held_fd != open.held_fd
        || close.namespace_inode != open.namespace_inode
        || first_rejection.code != "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE"
        || !first_rejection.target_created
        || !first_rejection.target_released
        || !first_rejection.cleanup.attempted
        || first_rejection.cleanup.sealed_boundary_retired
        || first_rejection.cleanup.errors.is_empty()
        || second_rejection.code != "MCSEALED-PRIVATE-REUSE-BLOCKED"
        || second_rejection.target_created
        || second_rejection.target_released
        || second_rejection.cleanup.attempted
        || !second_rejection.cleanup.errors.is_empty()
        || !(open.opened_boot_nanos <= settled.settled_boot_nanos
            && settled.settled_boot_nanos <= failure.failure_boot_nanos
            && failure.failure_boot_nanos <= blocked.blocked_boot_nanos
            && blocked.blocked_boot_nanos < close.closed_boot_nanos
            && close.closed_boot_nanos <= recovered.recovery_boot_nanos)
    {
        return Err("MCSEALED-PUBLIC-REUSE: detached lifecycle custody differs".into());
    }
    if transcript.schema_version != 1
        || transcript.selector != SELECTOR
        || transcript.result_key != key
        || transcript.boot_id != intent.boot_id
        || transcript.installation_epoch != intent.installation_epoch
        || transcript.active_h1_receipt_sha256 != intent.active_h1_receipt_sha256
        || transcript.first_attempt_id != failure.attempt_id
        || transcript.second_attempt_id != blocked.second_attempt_id
        || transcript.cleanup_failure_sha256 != failure.response_sha256
        || transcript.durable_incomplete_state_sha256 != failure.durable_incomplete_state_sha256
        || transcript.namespace_inode != gate.namespace_inode
        || transcript.holder_pid != open.holder.pid
        || transcript.holder_start_time != open.holder.start_time
        || transcript.held_fd != open.held_fd
        || transcript.failure_boot_nanos != failure.failure_boot_nanos
        || transcript.blocked_request_sha256 != blocked.request_sha256
        || transcript.blocked_rejection_sha256 != blocked.rejection_sha256
        || transcript.blocked_boot_nanos != blocked.blocked_boot_nanos
        || transcript.namespace_fd_closed_boot_nanos != close.closed_boot_nanos
        || transcript.recovered_cleanup_sha256 != hash_bytes(&recovery)
        || transcript.recovery_boot_nanos != recovered.recovery_boot_nanos
        || !transcript.durable_attempt_record_absent_after_recovery
        || !original_process_absent(&close.holder)?
        || fs::symlink_metadata(Path::new(super::STATE_ROOT).join(&failure.attempt_id)).is_ok()
    {
        return Err("MCSEALED-PUBLIC-REUSE: detached transcript differs".into());
    }
    let _provider = super::private_public_provider::verify_completed(SELECTOR, challenge_hex)?;
    lease.revalidate_release_boundary()?;
    serde_json::to_string(&transcript).map_err(|error| error.to_string())
}
