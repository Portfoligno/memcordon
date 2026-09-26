//! One-shot, credential-bound V2 policy decision endpoint. It never enters the
//! root ReleaseCase/broker path and never constructs a target owner.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use serde::{Deserialize, Serialize};

use crate::protocol::{Frame, MessageKind, read_network_frame, write_network_frame};

use super::private_release_case::{ReleaseCaseRequestV1, ReleaseStageV1};

const REGISTRATION: &str = "/var/lib/memcordon/sealed/policy-decision-peer.v1.json";
const LOCK: &str = "/var/lib/memcordon/sealed/policy-decision-peer.lock";
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";
const SELECTOR: &str = "private_tcp::wrong_grant_profile_and_port_rejected";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationV1 {
    schema_version: u8,
    selector: String,
    challenge: [u8; 32],
    result_key: DiagnosticSha256,
    peer_pid: u32,
    peer_start_time_ticks: u64,
    peer_uid: u32,
    peer_gid: u32,
    accepted_contract_sha256: DiagnosticSha256,
    accepted_plan_sha256: DiagnosticSha256,
}

fn state_root() -> Result<(), String> {
    let metadata = fs::symlink_metadata(super::STATE_ROOT).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o7777 != 0o700 {
        return Err("policy decision state root protection differs".into());
    }
    Ok(())
}

fn lock() -> Result<File, String> {
    state_root()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(LOCK)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err("policy decision lock protection differs".into());
    }
    // SAFETY: flock receives one live owned descriptor and a constant operation.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(file)
}

fn observed_start(pid: u32) -> Result<u64, String> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| "policy peer PID out of range")?;
    if pid <= 0 {
        return Err("policy peer PID absent".into());
    }
    // SAFETY: pidfd_open uses scalar inputs; success returns one owned descriptor.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful pidfd_open returned an owned descriptor.
    let pidfd = unsafe { File::from_raw_fd(fd) };
    let identity = super::private_attempt::ProcessIdentityV4::observe(pid, pidfd.as_fd())?;
    Ok(identity.start_time)
}

fn installed_image() -> Result<(), String> {
    let current = fs::metadata(std::env::current_exe().map_err(|error| error.to_string())?)
        .map_err(|error| error.to_string())?;
    let installed = fs::symlink_metadata(AGENT).map_err(|error| error.to_string())?;
    if !installed.is_file()
        || installed.uid() != 0
        || installed.mode() & 0o022 != 0
        || (current.dev(), current.ino()) != (installed.dev(), installed.ino())
    {
        return Err("policy decision requires installed root-owned agent image".into());
    }
    Ok(())
}

fn installed_peer_image(pid: libc::pid_t) -> Result<(), String> {
    let peer = fs::metadata(format!("/proc/{pid}/exe")).map_err(|error| error.to_string())?;
    let installed = fs::symlink_metadata(AGENT).map_err(|error| error.to_string())?;
    if !installed.is_file()
        || installed.uid() != 0
        || installed.mode() & 0o022 != 0
        || (peer.dev(), peer.ino()) != (installed.dev(), installed.ino())
    {
        return Err("policy decision peer executable differs from installed agent".into());
    }
    Ok(())
}

fn hex_challenge(bytes: &[u8; 32]) -> String {
    let mut result = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("hex string write");
    }
    result
}

fn clear_own_registration(pid: u32) -> Result<(), String> {
    let _guard = lock()?;
    let bytes = match fs::read(REGISTRATION) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    reject_duplicate_json_keys(&bytes)?;
    let entry: RegistrationV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if entry.peer_pid == pid {
        fs::remove_file(REGISTRATION).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Root supervisor starts a gated nonroot instance of the installed image.
/// The registration is installed only after PID/start observation and before
/// the child may connect to the provider socket.
pub(crate) fn run_root_supervised(request: &ReleaseCaseRequestV1) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0
        || request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != SELECTOR
    {
        return Err("policy decision root supervisor identity differs".into());
    }
    installed_image()?;
    let _package = crate::package::acquire_verified_release_candidate_package_lease()?;
    let (uid, contract, plan) =
        super::private_release_policy_predicate::read_protected_policy_registration_fields(
            &request.challenge,
        )?;
    if uid == 0 {
        return Err("policy decision peer must be nonroot".into());
    }
    let endpoint = fs::symlink_metadata(super::SOCKET_PATH).map_err(|error| error.to_string())?;
    if !endpoint.file_type().is_socket()
        || endpoint.uid() != 0
        || endpoint.gid() == 0
        || endpoint.mode() & 0o007 != 0
    {
        return Err("policy decision provider endpoint protection differs".into());
    }
    let gid = endpoint.gid();
    let mut command = Command::new(AGENT);
    command
        .arg("policy-decision-peer")
        .arg(hex_challenge(&request.challenge))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: child-side pre_exec invokes only async-signal-safe libc credential
    // transitions, dropping supplementary groups and all saved root IDs before
    // the installed agent image is executed.
    unsafe {
        command.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(gid, gid, gid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|error| error.to_string())?;
    let registered = (|| {
        let start = observed_start(child.id())?;
        let entry = RegistrationV1 {
            schema_version: 1,
            selector: SELECTOR.into(),
            challenge: request.challenge,
            result_key: request.result_key(),
            peer_pid: child.id(),
            peer_start_time_ticks: start,
            peer_uid: uid,
            peer_gid: gid,
            accepted_contract_sha256: contract,
            accepted_plan_sha256: plan,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|error| error.to_string())?;
        let _guard = lock()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(REGISTRATION)
            .map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok::<(), String>(())
    })();
    if let Err(error) = registered {
        drop(child.stdin.take());
        let _ = child.wait();
        return Err(error);
    }
    let released = child
        .stdin
        .take()
        .ok_or("policy decision child gate absent")?
        .write_all(&[1])
        .map_err(|error| error.to_string());
    if released.is_err() {
        drop(child.stdin.take());
    }
    let pid = child.id();
    let output = child
        .wait_with_output()
        .map_err(|error| error.to_string())?;
    clear_own_registration(pid)?;
    if !output.status.success() {
        return Err(format!(
            "policy decision peer failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    released
}

pub(crate) fn run_nonroot_peer(challenge: &OsStr) -> Result<(), String> {
    installed_image()?;
    if unsafe { libc::geteuid() } == 0 {
        return Err("policy decision peer must be nonroot".into());
    }
    let request = ReleaseCaseRequestV1::parse(
        OsStr::new("candidate-capability"),
        OsStr::new(SELECTOR),
        challenge,
    )?;
    let mut gate = [0u8; 1];
    std::io::stdin()
        .read_exact(&mut gate)
        .map_err(|error| error.to_string())?;
    if gate != [1] {
        return Err("policy decision child gate differs".into());
    }
    let mut stream = UnixStream::connect(super::SOCKET_PATH).map_err(|error| error.to_string())?;
    super::launcher::authenticate_control_service(&stream)?;
    let nonce = super::launcher::nonce()?;
    let attempt_id = super::launcher::nonce()?;
    if attempt_id == [0; 16] {
        return Err("policy decision peer attempt nonce absent".into());
    }
    let frame = Frame {
        kind: MessageKind::PolicyDecision,
        nonce,
        attempt_id,
        payload: super::private_release_run::encode_control_request(&request)?,
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &frame).map_err(|error| error.to_string())?;
    super::transport::send(&stream, &bytes, &[])?;
    let response = read_network_frame(&mut stream).map_err(|error| error.to_string())?;
    if response.nonce != nonce
        || response.attempt_id != attempt_id
        || response.kind != MessageKind::PolicyDecisionRecorded
        || response.payload.len() != 32
        || response.payload.iter().all(|byte| *byte == 0)
    {
        return Err("policy decision response differs".into());
    }
    Ok(())
}

pub(crate) fn consume_registration(
    request: &ReleaseCaseRequestV1,
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    if request.stage != ReleaseStageV1::CandidateCapability
        || request.selector != SELECTOR
        || uid == 0
        || pid <= 0
    {
        return Err("policy decision peer identity differs".into());
    }
    let _guard = lock()?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(REGISTRATION)
        .map_err(|error| error.to_string())?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() == 0
        || metadata.len() > 4096
    {
        return Err("policy decision registration protection differs".into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() {
        return Err("policy decision registration length changed".into());
    }
    reject_duplicate_json_keys(&bytes)?;
    let entry: RegistrationV1 =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    let (expected_uid, contract, plan) =
        super::private_release_policy_predicate::read_protected_policy_registration_fields(
            &request.challenge,
        )?;
    if entry.schema_version != 1
        || entry.selector != SELECTOR
        || entry.challenge != request.challenge
        || entry.result_key != request.result_key()
        || entry.peer_pid != pid as u32
        || entry.peer_start_time_ticks != observed_start(pid as u32)?
        || entry.peer_uid != uid
        || entry.peer_gid != gid
        || entry.peer_uid != expected_uid
        || entry.accepted_contract_sha256 != contract
        || entry.accepted_plan_sha256 != plan
        || serde_json::to_vec(&entry).map_err(|error| error.to_string())? != bytes
    {
        return Err("policy decision registration/contract/peer differs".into());
    }
    installed_peer_image(pid)?;
    fs::remove_file(REGISTRATION).map_err(|error| error.to_string())?;
    Ok(())
}

pub(crate) fn decision_response(request: &Frame, digest: &DiagnosticSha256) -> Frame {
    Frame {
        kind: MessageKind::PolicyDecisionRecorded,
        nonce: request.nonce,
        attempt_id: request.attempt_id,
        payload: digest.bytes().to_vec(),
    }
}
