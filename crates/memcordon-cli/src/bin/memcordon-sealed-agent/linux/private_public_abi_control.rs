//! Installed-public alternate-ABI *outer* controls. These children inherit the
//! sealed service unit and never enter a private attempt or install its filter.
//! Their journal is auxiliary evidence, never a public CLI target/result.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use memcordon_core::{BoundedText, DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::private_attempt::ProcessIdentityV4;
use crate::protocol::{Frame, MessageKind, read_frame, write_frame};

pub(crate) const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";
const ROOT: &str = "/var/lib/memcordon/sealed/private-public-abi-controls";
const DOMAIN: &[u8] = b"memcordon-public-abi-outer-v1\0";
const REQUEST_LEAF: &str = "request.json";
const RAW_LEAF: &str = "outer-control.raw.json";
const MAX_RAW: usize = 16 * 1024;
const CHILD_LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ControlRequestV1 {
    schema: u32,
    selector: String,
    challenge: DiagnosticSha256,
    dispatch_key: DiagnosticSha256,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OuterProvenanceV1 {
    pub(crate) service: ProcessIdentityV4,
    pub(crate) service_worker: ProcessIdentityV4,
    pub(crate) cgroup: String,
    pub(crate) cgroup_inode: u64,
    pub(crate) seccomp_mode: u32,
    pub(crate) seccomp_filters: u32,
    pub(crate) no_new_privs: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OuterBranchV1 {
    pub(crate) branch: String,
    pub(crate) child: ProcessIdentityV4,
    pub(crate) audit_arch: u32,
    pub(crate) syscall_nr: u32,
    pub(crate) return_value: Option<i64>,
    pub(crate) errno: Option<i32>,
    pub(crate) return_marker: Option<u8>,
    pub(crate) exec_device: Option<u64>,
    pub(crate) exec_inode: Option<u64>,
    pub(crate) exit_code: i32,
    pub(crate) reaped: bool,
    pub(crate) inherited_outer_filters: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PublicAbiOuterRawV1 {
    pub(crate) schema: u32,
    pub(crate) selector: String,
    pub(crate) auxiliary_only: bool,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) dispatch_key: DiagnosticSha256,
    pub(crate) auxiliary_key: DiagnosticSha256,
    pub(crate) h1_sha256: DiagnosticSha256,
    pub(crate) installation_epoch: DiagnosticSha256,
    pub(crate) outer: OuterProvenanceV1,
    pub(crate) branches: Vec<OuterBranchV1>,
}

pub(crate) fn auxiliary_key(
    h1: &DiagnosticSha256,
    epoch: &DiagnosticSha256,
    dispatch_key: &DiagnosticSha256,
    challenge: &DiagnosticSha256,
) -> DiagnosticSha256 {
    let mut bytes = DOMAIN.to_vec();
    for value in [h1, epoch, dispatch_key, challenge] {
        bytes.extend_from_slice(value.bytes());
    }
    hash_bytes(&bytes)
}

fn parse_request(
    selector: &str,
    challenge: &str,
    dispatch_key: &str,
) -> Result<ControlRequestV1, String> {
    if selector != SELECTOR {
        return Err("MCSEALED-PUBLIC-ABI: selector differs".into());
    }
    let challenge = DiagnosticSha256::try_from(BoundedText::new(challenge).map_err(str::to_owned)?)
        .map_err(str::to_owned)?;
    let dispatch_key =
        DiagnosticSha256::try_from(BoundedText::new(dispatch_key).map_err(str::to_owned)?)
            .map_err(str::to_owned)?;
    if challenge.bytes() == &[0; 32] {
        return Err("MCSEALED-PUBLIC-ABI: zero challenge".into());
    }
    let expected = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        SELECTOR,
        challenge.bytes(),
    )?;
    if dispatch_key != expected {
        return Err("MCSEALED-PUBLIC-ABI: dispatch key differs".into());
    }
    Ok(ControlRequestV1 {
        schema: 1,
        selector: SELECTOR.into(),
        challenge,
        dispatch_key,
    })
}

#[cfg(test)]
pub(crate) fn validate_command_for_test(
    selector: &str,
    challenge: &str,
    dispatch_key: &str,
) -> Result<(), String> {
    parse_request(selector, challenge, dispatch_key).map(|_| ())
}

/// Root CLI asks the installed sealed service to execute the controls. The
/// CLI never runs a child itself and cannot substitute its own outer context.
pub(crate) fn request_control(
    selector: &str,
    challenge: &str,
    dispatch_key: &str,
) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("MCSEALED-PUBLIC-ABI: root required".into());
    }
    let current = fs::metadata(std::env::current_exe().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let installed =
        fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent").map_err(|e| e.to_string())?;
    if !installed.is_file() || current.dev() != installed.dev() || current.ino() != installed.ino()
    {
        return Err("MCSEALED-PUBLIC-ABI: installed agent image required".into());
    }
    let fixed = parse_request(selector, challenge, dispatch_key)?;
    let stream = UnixStream::connect(super::SOCKET_PATH).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(60)))
        .map_err(|e| e.to_string())?;
    super::launcher::authenticate_control_service(&stream)?;
    let frame = Frame {
        kind: MessageKind::PublicAbiOuterControl,
        nonce: super::launcher::nonce()?,
        attempt_id: super::launcher::nonce()?,
        payload: serde_json::to_vec(&fixed).map_err(|e| e.to_string())?,
    };
    if frame.nonce == [0; 16] || frame.attempt_id == [0; 16] {
        return Err("MCSEALED-PUBLIC-ABI: zero transport identity".into());
    }
    let mut bytes = Vec::new();
    write_frame(&mut bytes, &frame).map_err(|e| e.to_string())?;
    super::transport::send(&stream, &bytes, &[])?;
    let mut reader = &stream;
    let response = read_frame(&mut reader).map_err(|e| e.to_string())?;
    if response.nonce != frame.nonce
        || response.attempt_id != frame.attempt_id
        || response.kind != MessageKind::PublicAbiOuterRecorded
        || response.payload.len() != 64
    {
        return Err("MCSEALED-PUBLIC-ABI: service response differs".into());
    }
    let auxiliary_key =
        DiagnosticSha256::from_bytes(response.payload[..32].try_into().expect("length checked"));
    let raw_sha256 =
        DiagnosticSha256::from_bytes(response.payload[32..].try_into().expect("length checked"));
    println!(
        "{}",
        serde_json::json!({
            "schema": 1,
            "auxiliary_key": String::from(auxiliary_key),
            "raw_sha256": String::from(raw_sha256),
        })
    );
    Ok(())
}

/// Runs in the authenticated root service worker under a held M1/Q/H1 lease.
pub(crate) fn service_control(
    payload: &[u8],
) -> Result<(DiagnosticSha256, DiagnosticSha256), String> {
    if payload.len() > 1024 {
        return Err("MCSEALED-PUBLIC-ABI: request too large".into());
    }
    memcordon_core::workload_contract::reject_duplicate_json_keys(payload)?;
    let request: ControlRequestV1 = serde_json::from_slice(payload).map_err(|e| e.to_string())?;
    if serde_json::to_vec(&request).map_err(|e| e.to_string())? != payload || request.schema != 1 {
        return Err("MCSEALED-PUBLIC-ABI: request encoding differs".into());
    }
    let checked = parse_request(
        &request.selector,
        &String::from(request.challenge.clone()),
        &String::from(request.dispatch_key.clone()),
    )?;
    if checked.challenge != request.challenge || checked.dispatch_key != request.dispatch_key {
        return Err("MCSEALED-PUBLIC-ABI: request binding differs".into());
    }
    let lease = crate::package::acquire_verified_private_qualification_lease()?;
    let h1 = lease.active_host_receipt_sha256().clone();
    let epoch = lease.generation_digest().clone();
    let key = auxiliary_key(&h1, &epoch, &request.dispatch_key, &request.challenge);
    let outer = observe_outer()?;
    let directory = create_journal(&key)?;
    let mut branches = Vec::new();
    branches.push(run_child(Branch::Native, outer.seccomp_filters)?);
    #[cfg(target_arch = "x86_64")]
    {
        branches.push(run_child(Branch::X32, outer.seccomp_filters)?);
        branches.push(run_child(Branch::I386, outer.seccomp_filters)?);
    }
    #[cfg(target_arch = "aarch64")]
    branches.push(run_child(Branch::Arm32, outer.seccomp_filters)?);
    lease.revalidate_release_boundary()?;
    let raw = PublicAbiOuterRawV1 {
        schema: 1,
        selector: SELECTOR.into(),
        auxiliary_only: true,
        challenge_sha256: hash_bytes(request.challenge.bytes()),
        dispatch_key: request.dispatch_key.clone(),
        auxiliary_key: key.clone(),
        h1_sha256: h1,
        installation_epoch: epoch,
        outer,
        branches,
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    let raw_bytes = serde_json::to_vec(&raw).map_err(|e| e.to_string())?;
    if raw_bytes.len() > MAX_RAW {
        return Err("MCSEALED-PUBLIC-ABI: raw too large".into());
    }
    super::private_release_alt_abi_raw::write_immutable(
        &directory,
        REQUEST_LEAF,
        "request.json.new",
        &request_bytes,
    )?;
    super::private_release_alt_abi_raw::write_immutable(
        &directory,
        RAW_LEAF,
        "outer-control.raw.json.new",
        &raw_bytes,
    )?;
    lease.revalidate_release_boundary()?;
    Ok((key, hash_bytes(&raw_bytes)))
}

fn create_journal(key: &DiagnosticSha256) -> Result<File, String> {
    let root = Path::new(ROOT);
    if !root.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root)
            .map_err(|e| e.to_string())?;
    }
    let metadata = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-ABI: protected root differs".into());
    }
    let directory = root.join(String::from(key.clone()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .map_err(|e| format!("MCSEALED-PUBLIC-ABI: duplicate journal: {e}"))?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(&directory)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("MCSEALED-PUBLIC-ABI: protected journal differs".into());
    }
    Ok(file)
}

fn observe_outer() -> Result<OuterProvenanceV1, String> {
    let status = fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let number = |name: &str| -> Result<u32, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("MCSEALED-PUBLIC-ABI: missing {name}"))?
            .trim()
            .parse()
            .map_err(|_| format!("MCSEALED-PUBLIC-ABI: invalid {name}"))
    };
    let cgroup = fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?;
    let path = cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .ok_or("MCSEALED-PUBLIC-ABI: cgroup v2 absent")?;
    if !path.ends_with("/memcordon-sealed-agent.service") {
        return Err("MCSEALED-PUBLIC-ABI: not in installed sealed service cgroup".into());
    }
    let inode = fs::metadata(Path::new("/sys/fs/cgroup").join(path.trim_start_matches('/')))
        .map_err(|e| e.to_string())?
        .ino();
    let observe = |pid: libc::pid_t| -> Result<ProcessIdentityV4, String> {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if fd < 0 {
            return Err("MCSEALED-PUBLIC-ABI: service pidfd unavailable".into());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        ProcessIdentityV4::observe(pid, fd.as_fd())
    };
    let parent = unsafe { libc::getppid() };
    let service = observe(parent)?;
    let worker = observe(unsafe { libc::getpid() })?;
    let parent_cgroup =
        fs::read_to_string(format!("/proc/{parent}/cgroup")).map_err(|e| e.to_string())?;
    if parent_cgroup != cgroup {
        return Err("MCSEALED-PUBLIC-ABI: service worker cgroup differs".into());
    }
    let seccomp_mode = number("Seccomp:")?;
    let seccomp_filters = number("Seccomp_filters:")?;
    let no_new_privs = number("NoNewPrivs:")?;
    if seccomp_mode != 2 || seccomp_filters == 0 || no_new_privs != 1 {
        return Err("MCSEALED-PUBLIC-ABI: sealed service outer seccomp prerequisite absent".into());
    }
    Ok(OuterProvenanceV1 {
        service,
        service_worker: worker,
        cgroup: path.into(),
        cgroup_inode: inode,
        seccomp_mode,
        seccomp_filters,
        no_new_privs,
    })
}

#[derive(Clone, Copy)]
enum Branch {
    Native,
    #[cfg(target_arch = "x86_64")]
    X32,
    #[cfg(target_arch = "x86_64")]
    I386,
    #[cfg(target_arch = "aarch64")]
    Arm32,
}

impl Branch {
    fn name(self) -> &'static str {
        match self {
            Self::Native => "native",
            #[cfg(target_arch = "x86_64")]
            Self::X32 => "x32",
            #[cfg(target_arch = "x86_64")]
            Self::I386 => "i386",
            #[cfg(target_arch = "aarch64")]
            Self::Arm32 => "arm32",
        }
    }
    fn arch_nr(self) -> (u32, u32) {
        match self {
            Self::Native => (
                if cfg!(target_arch = "x86_64") {
                    0xc000_003e
                } else {
                    0xc000_00b7
                },
                libc::SYS_getpid as u32,
            ),
            #[cfg(target_arch = "x86_64")]
            Self::X32 => (0xc000_003e, libc::SYS_getpid as u32 | 0x4000_0000),
            #[cfg(target_arch = "x86_64")]
            Self::I386 => (0x4000_0003, 20),
            #[cfg(target_arch = "aarch64")]
            Self::Arm32 => (0x4000_0028, 20),
        }
    }
}

struct ChildGuard {
    pid: libc::pid_t,
    fd: OwnedFd,
    reaped: bool,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if !self.reaped {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.fd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
                libc::waitpid(self.pid, std::ptr::null_mut(), 0);
            }
        }
    }
}

fn run_child(branch: Branch, inherited_filters: u32) -> Result<OuterBranchV1, String> {
    let (mut parent, child) = UnixStream::pair().map_err(|e| e.to_string())?;
    parent
        .set_read_timeout(Some(CHILD_LIMIT))
        .map_err(|e| e.to_string())?;
    parent
        .set_write_timeout(Some(CHILD_LIMIT))
        .map_err(|e| e.to_string())?;
    #[cfg(target_arch = "aarch64")]
    let helper = if matches!(branch, Branch::Arm32) {
        Some(open_arm32_helper()?)
    } else {
        None
    };
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "MCSEALED-PUBLIC-ABI: fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let result = child_branch(
            parent,
            child,
            branch,
            #[cfg(target_arch = "aarch64")]
            helper.as_ref().map(|(file, _, _)| file),
        );
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
    }
    drop(child);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err("MCSEALED-PUBLIC-ABI: child pidfd unavailable".into());
    }
    let mut guard = ChildGuard {
        pid,
        fd: unsafe { OwnedFd::from_raw_fd(fd) },
        reaped: false,
    };
    let identity = ProcessIdentityV4::observe(pid, guard.fd.as_fd())?;
    let child_status =
        fs::read_to_string(format!("/proc/{pid}/status")).map_err(|e| e.to_string())?;
    let status_number = |name: &str| -> Result<u32, String> {
        child_status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or_else(|| format!("MCSEALED-PUBLIC-ABI: child {name} absent"))?
            .trim()
            .parse::<u32>()
            .map_err(|_| format!("MCSEALED-PUBLIC-ABI: child {name} invalid"))
    };
    let filters = status_number("Seccomp_filters:")?;
    if filters != inherited_filters {
        return Err("MCSEALED-PUBLIC-ABI: child added filter".into());
    }
    let parent_status = fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    for name in ["Seccomp:", "NoNewPrivs:"] {
        let expected = parent_status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or("MCSEALED-PUBLIC-ABI: parent status absent")?
            .trim();
        let actual = child_status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .ok_or("MCSEALED-PUBLIC-ABI: child status absent")?
            .trim();
        if actual != expected {
            return Err(format!("MCSEALED-PUBLIC-ABI: child {name} differs"));
        }
    }
    if fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?
        != fs::read_to_string("/proc/self/cgroup").map_err(|e| e.to_string())?
    {
        return Err("MCSEALED-PUBLIC-ABI: child escaped service cgroup".into());
    }
    let mut ready = [0_u8; 1];
    parent.read_exact(&mut ready).map_err(|e| e.to_string())?;
    if ready != [b'R'] {
        return Err("MCSEALED-PUBLIC-ABI: child not gated".into());
    }
    parent.write_all(&[b'G']).map_err(|e| e.to_string())?;
    let mut result = [0_u8; 12];
    let (returned, errno, marker) = if cfg!(target_arch = "aarch64") && branch.name() == "arm32" {
        let mut byte = [0];
        parent.read_exact(&mut byte).map_err(|e| e.to_string())?;
        if byte != [b'A'] {
            return Err("MCSEALED-PUBLIC-ABI: ARM32 return marker differs".into());
        }
        (None, None, Some(byte[0]))
    } else {
        parent.read_exact(&mut result).map_err(|e| e.to_string())?;
        let value = i64::from_be_bytes(result[..8].try_into().expect("fixed result"));
        let errno = i32::from_be_bytes(result[8..].try_into().expect("fixed result"));
        if branch.name() == "x32" {
            if !(value == pid as i64 && errno == 0 || value == -1 && errno == libc::ENOSYS) {
                return Err("MCSEALED-PUBLIC-ABI: x32 outer control differs".into());
            }
        } else if value != pid as i64 || errno != 0 {
            return Err("MCSEALED-PUBLIC-ABI: getpid outer control differs".into());
        }
        (
            Some(value),
            if errno == 0 { None } else { Some(errno) },
            None,
        )
    };
    let deadline = Instant::now() + CHILD_LIMIT;
    let status = loop {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if waited == pid {
            break status;
        }
        if waited < 0 {
            return Err(format!(
                "MCSEALED-PUBLIC-ABI: waitpid: {}",
                std::io::Error::last_os_error()
            ));
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PUBLIC-ABI: child timeout".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    guard.reaped = true;
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err("MCSEALED-PUBLIC-ABI: child did not exit cleanly".into());
    }
    let (arch, nr) = branch.arch_nr();
    #[cfg(target_arch = "aarch64")]
    let (device, inode) = if let Some((_, device, inode)) = helper {
        (Some(device), Some(inode))
    } else {
        (None, None)
    };
    #[cfg(not(target_arch = "aarch64"))]
    let (device, inode) = (None, None);
    Ok(OuterBranchV1 {
        branch: branch.name().into(),
        child: identity,
        audit_arch: arch,
        syscall_nr: nr,
        return_value: returned,
        errno,
        return_marker: marker,
        exec_device: device,
        exec_inode: inode,
        exit_code: 0,
        reaped: true,
        inherited_outer_filters: filters,
    })
}

fn child_branch(
    parent: UnixStream,
    child: UnixStream,
    branch: Branch,
    #[cfg(target_arch = "aarch64")] helper: Option<&File>,
) -> Result<(), String> {
    drop(parent);
    // The only child write/read channel is fd 3; all service/lease/observer
    // descriptors are closed before an ABI entry or helper exec.
    #[cfg(target_arch = "aarch64")]
    let helper_source = if let Some(helper) = helper {
        let fd = unsafe { libc::fcntl(helper.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        if fd < 0 {
            return Err("helper source fd differs".into());
        }
        Some(fd)
    } else {
        None
    };
    if unsafe { libc::dup2(child.as_raw_fd(), 3) } != 3 {
        return Err("child fd differs".into());
    }
    std::mem::forget(child);
    #[cfg(target_arch = "aarch64")]
    if let Some(helper_source) = helper_source {
        if unsafe { libc::dup2(helper_source, 4) } != 4
            || unsafe { libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
        {
            return Err("helper fd differs".into());
        }
    }
    if unsafe {
        libc::syscall(
            libc::SYS_close_range,
            if branch.name() == "arm32" {
                5_u32
            } else {
                4_u32
            },
            u32::MAX,
            0_u32,
        )
    } != 0
    {
        return Err("inherited descriptors remain".into());
    }
    let mut channel = unsafe { UnixStream::from_raw_fd(3) };
    channel.write_all(b"R").map_err(|e| e.to_string())?;
    let mut go = [0];
    channel.read_exact(&mut go).map_err(|e| e.to_string())?;
    if go != [b'G'] {
        return Err("child release byte differs".into());
    }
    #[cfg(target_arch = "aarch64")]
    if matches!(branch, Branch::Arm32) {
        if unsafe { libc::dup2(3, 1) } != 1 {
            return Err("ARM32 stdout differs".into());
        }
        drop(channel);
        let argv = [
            b"memcordon-arm32-abi-helper\0"
                .as_ptr()
                .cast::<libc::c_char>(),
            std::ptr::null(),
        ];
        let env = [std::ptr::null::<libc::c_char>()];
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                4,
                b"\0".as_ptr(),
                argv.as_ptr(),
                env.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        return Err("ARM32 helper exec failed".into());
    }
    let value = match branch {
        Branch::Native => unsafe { libc::syscall(libc::SYS_getpid) as i64 },
        #[cfg(target_arch = "x86_64")]
        Branch::X32 => unsafe {
            libc::syscall((libc::SYS_getpid as u32 | 0x4000_0000) as libc::c_long) as i64
        },
        #[cfg(target_arch = "x86_64")]
        Branch::I386 => {
            let mut eax = 20_i32;
            unsafe {
                std::arch::asm!("int 0x80", inout("eax") eax,
                lateout("ecx") _, lateout("edx") _, options(nostack));
            }
            eax as i64
        }
        #[cfg(target_arch = "aarch64")]
        Branch::Arm32 => unreachable!(),
    };
    let errno = if value == -1 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    channel
        .write_all(&value.to_be_bytes())
        .map_err(|e| e.to_string())?;
    channel
        .write_all(&errno.to_be_bytes())
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn open_arm32_helper() -> Result<(File, u64, u64), String> {
    let path = super::runtime_manifest::INSTALLED_ARM32_HELPER;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.dev() == 0 || metadata.ino() == 0 {
        return Err("MCSEALED-PUBLIC-ABI: ARM32 helper identity differs".into());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(8192)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() != 4152
        || bytes[..4] != [0x7f, b'E', b'L', b'F']
        || bytes[4] != 1
        || bytes[18] != 40
    {
        return Err("MCSEALED-PUBLIC-ABI: ARM32 helper ELF differs".into());
    }
    let candidate = super::runtime_manifest::source_v3_candidate(Path::new(
        "/usr/libexec/memcordon-sealed-agent",
    ))?
    .ok_or("MCSEALED-PUBLIC-ABI: installed M1 absent")?;
    let expected = candidate
        .manifest
        .components
        .iter()
        .find(|component| {
            component.role == memcordon_core::runtime_manifest::RuntimeComponentRole::Arm32AbiHelper
        })
        .ok_or("MCSEALED-PUBLIC-ABI: ARM32 component absent")?;
    if String::from(hash_bytes(&bytes)) != expected.sha256 {
        return Err("MCSEALED-PUBLIC-ABI: ARM32 B helper differs".into());
    }
    Ok((file, metadata.dev(), metadata.ino()))
}
