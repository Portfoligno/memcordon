use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const ENDPOINT: &str = "/run/memcordon/sealed-agent.sock";
const VERSION: u16 = 1;
const HEADER_LENGTH: usize = 72;
const MAX_FRAME: usize = 1024 * 1024;
const MAX_NATIVE_VALUE: usize = 64 * 1024;
const MAX_ARGUMENTS: usize = 4096;
const MAX_ENVIRONMENT_ENTRIES: usize = 8192;

pub struct ProbeReceipt {
    pub provider_identity: String,
    pub receipt_digest: String,
}

#[derive(Deserialize)]
struct QualificationReceipt {
    schema_version: u32,
    mechanism: String,
    provider_identity: String,
    receipt_digest: String,
    unified_cgroup_v2: bool,
    private_cgroup_subtree: bool,
    clone3: bool,
    clone3_into_cgroup: bool,
    pid_namespace: bool,
    mount_namespace: bool,
    cgroup_namespace: bool,
    pidfd: bool,
    close_range: bool,
    guardian_outside_boundary: bool,
    target_gated: bool,
    assignment_verified: bool,
    inherited_descriptors_verified: bool,
    frontend_loss_authority_verified: bool,
    cgroup_kill: bool,
    workload_empty: bool,
    helpers_reaped: bool,
    boundary_retired: bool,
    recovery_complete: bool,
}

impl QualificationReceipt {
    fn is_complete(&self) -> bool {
        self.schema_version == 1
            && self.mechanism == "linux-pid-namespace-cgroup-v1"
            && !self.provider_identity.is_empty()
            && self.receipt_digest.len() == 64
            && self
                .receipt_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            && self.unified_cgroup_v2
            && self.private_cgroup_subtree
            && self.clone3
            && self.clone3_into_cgroup
            && self.pid_namespace
            && self.mount_namespace
            && self.cgroup_namespace
            && self.pidfd
            && self.close_range
            && self.guardian_outside_boundary
            && self.target_gated
            && self.assignment_verified
            && self.inherited_descriptors_verified
            && self.frontend_loss_authority_verified
            && self.cgroup_kill
            && self.workload_empty
            && self.helpers_reaped
            && self.boundary_retired
            && self.recovery_complete
    }
}

pub struct TerminalReceipt {
    pub status: i32,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub credentials_verified: bool,
    pub capabilities_empty: bool,
    pub descriptors_verified: bool,
    pub cgroup_view_denied: bool,
    pub guardian_ready: bool,
    pub frontend_loss_authority: bool,
    pub cgroup_kill: bool,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

pub fn run(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
) -> Result<crate::backend::Execution, memcordon_core::Error> {
    let started = std::time::Instant::now();
    let terminal = launch(policy, command).map_err(|error| {
        memcordon_core::Error::new(
            memcordon_core::ErrorCategory::Setup,
            "MCSEALED-PROVIDER-TRANSACTION",
            error,
        )
    })?;
    let cleanup = memcordon_core::CleanupSummary {
        direct_child_reaped: terminal.init_reaped,
        workload_empty: Some(terminal.cgroup_empty),
        errors: Vec::new(),
        ..memcordon_core::CleanupSummary::default()
    };
    let child = memcordon_core::ChildTermination::ExitCode {
        code: terminal.status,
    };
    let outcome = if terminal.memory_limit_exceeded {
        let limit = policy.memory.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-MEMORY-EVIDENCE",
                "provider reported a memory limit without a configured limit",
            )
        })?;
        memcordon_core::RunOutcome::LimitExceeded {
            limit,
            observed: None,
            peak: None,
            evidence: memcordon_core::LimitEvidence {
                backend: "linux-pid-namespace-cgroup-v1".to_owned(),
                metric: "memory.current".to_owned(),
                detail: "memory.events oom_kill incremented".to_owned(),
            },
            child_after_termination: Some(child),
            cleanup,
        }
    } else if terminal.deadline_exceeded {
        let configured = policy.deadline.ok_or_else(|| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider reported a deadline without a configured deadline",
            )
        })?;
        let duration_ms = configured.duration().as_millis() as u64;
        let deadline = memcordon_core::DeadlineEvidence::new(
            duration_ms,
            configured.scope(),
            "provider-absolute-deadline".to_owned(),
            duration_ms,
            duration_ms,
            policy.limit_grace.as_millis() as u64,
            0,
            None,
            Some("cgroup.kill".to_owned()),
        )
        .map_err(|_| {
            memcordon_core::Error::new(
                memcordon_core::ErrorCategory::Monitor,
                "MCSEALED-DEADLINE-EVIDENCE",
                "provider deadline evidence was inconsistent",
            )
        })?;
        memcordon_core::RunOutcome::DeadlineExceeded {
            deadline,
            child_after_termination: Some(child),
            peak: None,
            cleanup,
        }
    } else {
        memcordon_core::RunOutcome::Exited {
            child,
            peak: None,
            cleanup,
        }
    };
    let evidence = memcordon_core::LinuxSealedEvidence {
        schema_version: 1,
        provider_identity: "memcordon-sealed-agent-v1".to_owned(),
        cgroup_identity_digest: "provider-terminal-receipt".to_owned(),
        cgroup_created: true,
        cgroup_owned_by_provider: true,
        memory_configuration_verified: true,
        init_created_into_cgroup: terminal.assignment_verified,
        pid_namespace_created: terminal.namespaces_verified,
        mount_namespace_created: terminal.namespaces_verified,
        cgroup_namespace_created: terminal.namespaces_verified,
        target_pidfd_verified: true,
        target_cgroup_membership_verified: terminal.assignment_verified,
        target_pid_namespace_verified: terminal.namespaces_verified,
        target_credentials_verified: terminal.credentials_verified,
        target_capabilities_empty: terminal.capabilities_empty,
        no_new_privs_verified: true,
        inherited_descriptors_verified: terminal.descriptors_verified,
        writable_cgroup_view_denied: terminal.cgroup_view_denied,
        guardian_ready: terminal.guardian_ready,
        target_released: true,
        cgroup_kill_invoked: terminal.cgroup_kill,
        cgroup_empty_verified: terminal.cgroup_empty,
        namespace_init_reaped: terminal.init_reaped,
        guardian_reaped: terminal.guardian_reaped,
        cgroup_removed: terminal.boundary_retired,
    };
    Ok(crate::backend::Execution {
        outcome,
        backend: crate::linux_cgroup::info(),
        child_pid: terminal.target_pid,
        duration: started.elapsed(),
        authorization_offset: Some(Duration::from_millis(terminal.authorization_offset_millis)),
        launch: memcordon_core::LaunchEvidence {
            mechanism: "linux-pid-namespace-cgroup-v1".to_owned(),
            target_released: true,
            containment_verified_before_authorization: terminal.assignment_verified
                && terminal.namespaces_verified,
            guardian_started_before_authorization: terminal.guardian_ready,
            target_spawn_error_reported: true,
            boundary_requested: memcordon_core::BoundaryRequirement::Sealed,
            boundary_effective: memcordon_core::BoundaryClass::Sealed,
            boundary_assignment_verified: terminal.assignment_verified,
            boundary_reconfiguration_denied: terminal.cgroup_view_denied,
            inherited_resources_restricted: terminal.descriptors_verified,
            frontend_loss_cleanup_authority_verified: terminal.frontend_loss_authority,
        },
        restart_safety: memcordon_core::RestartSafetyProof {
            direct_child_reaped: true,
            workload_empty: Some(terminal.cgroup_empty),
            helpers_reaped: terminal.init_reaped && terminal.guardian_reaped,
            containment_removed: terminal.boundary_retired,
            containment_incapable_of_live_members: terminal.cgroup_empty,
            sealed_boundary_retired: terminal.boundary_retired,
            errors: Vec::new(),
        },
        boundary_detail: memcordon_core::BoundaryMechanismEvidence::LinuxPidNamespaceCgroupV1(
            evidence,
        ),
    })
}

pub fn launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
) -> Result<TerminalReceipt, String> {
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    let attempt = nonce()?;
    let nonce = nonce()?;
    let payload = encode_launch(policy, command)?;
    let frame = encoded_frame(2, nonce, attempt, &payload)?;
    let cwd = fs::File::open(".").map_err(|error| error.to_string())?;
    let frontend_pidfd = pidfd_self()?;
    let descriptors = [cwd.as_raw_fd(), 0, 1, 2, frontend_pidfd.as_raw_fd()];
    send_with_descriptors(&stream, &frame, &descriptors)?;
    let (kind, returned_nonce, returned_attempt, payload) = read_frame(&mut stream)?;
    if returned_nonce != nonce || returned_attempt != attempt {
        return Err("provider terminal receipt identity mismatch".to_owned());
    }
    if kind == 106 {
        return Err(String::from_utf8_lossy(&payload).into_owned());
    }
    if kind != 105 {
        return Err("provider omitted terminal receipt".to_owned());
    }
    parse_terminal(&payload)
}

pub fn probe() -> Result<ProbeReceipt, String> {
    verify_endpoint()?;
    let mut stream = UnixStream::connect(Path::new(ENDPOINT)).map_err(|error| error.to_string())?;
    verify_peer(&stream)?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;
    let nonce = nonce()?;
    write_frame(&mut stream, 1, nonce, [0; 16], &[])?;
    let (kind, returned_nonce, attempt, payload) = read_frame(&mut stream)?;
    if kind != 101 || returned_nonce != nonce || attempt != [0; 16] {
        return Err("provider probe receipt identity mismatch".to_owned());
    }
    let identity = String::from_utf8(payload)
        .map_err(|_| "provider qualification receipt is not UTF-8".to_owned())?;
    let receipt: QualificationReceipt = serde_json::from_str(&identity)
        .map_err(|error| format!("provider qualification receipt is invalid: {error}"))?;
    if !receipt.is_complete() {
        return Err("provider reported an uncertified mechanism".to_owned());
    }
    Ok(ProbeReceipt {
        provider_identity: receipt.provider_identity,
        receipt_digest: receipt.receipt_digest,
    })
}

fn verify_endpoint() -> Result<(), String> {
    let metadata = fs::symlink_metadata(ENDPOINT)
        .map_err(|error| format!("provider endpoint unavailable: {error}"))?;
    if !metadata.file_type().is_socket() || metadata.uid() != 0 || metadata.mode() & 0o007 != 0 {
        return Err("provider endpoint is not a root-owned socket identity".to_owned());
    }
    let executable = fs::symlink_metadata("/usr/libexec/memcordon-sealed-agent")
        .map_err(|error| format!("provider executable unavailable: {error}"))?;
    if !executable.file_type().is_file() || executable.uid() != 0 || executable.mode() & 0o022 != 0
    {
        return Err("provider executable identity or permissions are unsafe".to_owned());
    }
    Ok(())
}

fn verify_peer(stream: &UnixStream) -> Result<(), String> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `credentials` and `length` are initialized writable values of the exact
    // SO_PEERCRED ABI sizes; the borrowed stream fd remains open for the call.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    } == -1
        || credentials.uid != 0
    {
        return Err("connected provider peer is not root-owned".to_owned());
    }
    Ok(())
}

fn encode_launch(
    policy: &memcordon_core::Policy,
    command: &memcordon_core::CommandSpec,
) -> Result<Vec<u8>, String> {
    if command.arguments().len() > MAX_ARGUMENTS {
        return Err("launch argument count exceeds protocol limit".to_owned());
    }
    let mut output = Vec::new();
    output.extend_from_slice(&1_u16.to_be_bytes());
    put_bytes(&mut output, command.program().as_bytes())?;
    put_count(&mut output, command.arguments().len())?;
    for argument in command.arguments() {
        put_bytes(&mut output, argument.as_bytes())?;
    }
    let environment: Vec<_> = std::env::vars_os().collect();
    if environment.len() > MAX_ENVIRONMENT_ENTRIES {
        return Err("launch environment count exceeds protocol limit".to_owned());
    }
    put_count(&mut output, environment.len())?;
    for (name, value) in environment {
        put_bytes(&mut output, name.as_bytes())?;
        put_bytes(&mut output, value.as_bytes())?;
    }
    put_optional(
        &mut output,
        policy.memory.map(memcordon_core::ByteSize::bytes),
    );
    match policy.swap {
        memcordon_core::SwapPolicy::Bytes(bytes) => {
            output.push(1);
            output.extend_from_slice(&bytes.bytes().to_be_bytes());
        }
        memcordon_core::SwapPolicy::Unlimited => output.push(2),
        memcordon_core::SwapPolicy::Host => output.push(3),
    }
    put_optional(
        &mut output,
        policy.deadline.map(|deadline| {
            monotonic_millis().saturating_add(deadline.duration().as_millis() as u64)
        }),
    );
    output.push(
        match policy
            .deadline
            .map(|value| value.scope())
            .unwrap_or(memcordon_core::DeadlineScope::Attempt)
        {
            memcordon_core::DeadlineScope::Attempt => 1,
            memcordon_core::DeadlineScope::Supervision => 2,
        },
    );
    output.push(match policy.lifetime {
        memcordon_core::Lifetime::Command => 1,
        memcordon_core::Lifetime::Workload => 2,
    });
    for duration in [
        policy.poll_interval,
        policy.signal_grace,
        policy.command_exit_grace,
        policy.limit_grace,
    ] {
        output.extend_from_slice(&(duration.as_millis() as u64).to_be_bytes());
    }
    put_count(&mut output, 5)?;
    output.extend_from_slice(&[1, 2, 3, 4, 5]);
    Ok(output)
}

fn put_count(output: &mut Vec<u8>, value: usize) -> Result<(), String> {
    output.extend_from_slice(
        &u32::try_from(value)
            .map_err(|_| "launch count overflow".to_owned())?
            .to_be_bytes(),
    );
    Ok(())
}
fn put_bytes(output: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_NATIVE_VALUE {
        return Err("launch native value exceeds protocol limit".to_owned());
    }
    put_count(output, value.len())?;
    output.extend_from_slice(value);
    Ok(())
}
fn put_optional(output: &mut Vec<u8>, value: Option<u64>) {
    output.push(u8::from(value.is_some()));
    if let Some(value) = value {
        output.extend_from_slice(&value.to_be_bytes());
    }
}

fn monotonic_millis() -> u64 {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `value` is a valid writable timespec and CLOCK_MONOTONIC needs no other lifetime.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut value) };
    (value.tv_sec as u64)
        .saturating_mul(1000)
        .saturating_add(value.tv_nsec as u64 / 1_000_000)
}

fn pidfd_self() -> Result<OwnedFd, String> {
    // SAFETY: getpid has no pointer arguments; pidfd_open receives the live caller pid and flags 0.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) } as i32;
    if fd < 0 {
        Err(std::io::Error::last_os_error().to_string())
    } else {
        // SAFETY: a nonnegative successful pidfd_open result is newly owned by this process.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}

fn encoded_frame(
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame exceeds protocol limit".to_owned());
    }
    let total = u32::try_from(total).map_err(|_| "frame exceeds protocol limit".to_owned())?;
    bytes.extend_from_slice(&VERSION.to_be_bytes());
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&total.to_be_bytes());
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&attempt);
    bytes.extend_from_slice(&Sha256::digest(payload));
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn send_with_descriptors(
    stream: &UnixStream,
    bytes: &[u8],
    descriptors: &[i32],
) -> Result<(), String> {
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: CMSG_SPACE is a pure ABI sizing macro and the descriptor byte count fits u32.
    let length = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) } as usize;
    let mut control = vec![0_u8; length];
    // SAFETY: an all-zero msghdr is the required empty initialization before assigning its buffers.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &raw mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: message_control points at `control`, sized with CMSG_SPACE and alive below.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    // SAFETY: `header` lies within `control`; CMSG_LEN bounds the exact descriptor copy and
    // descriptors are borrowed for the duration of sendmsg without transferring local ownership.
    unsafe {
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            descriptors.as_ptr(),
            libc::CMSG_DATA(header).cast(),
            descriptors.len(),
        );
    }
    // SAFETY: all iovec/control pointers refer to live immutable buffers through this synchronous call.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &raw const message, libc::MSG_NOSIGNAL) };
    if sent != bytes.len() as isize {
        return Err("short provider launch transaction".to_owned());
    }
    Ok(())
}

fn parse_terminal(payload: &[u8]) -> Result<TerminalReceipt, String> {
    let text = std::str::from_utf8(payload).map_err(|_| "terminal receipt encoding".to_owned())?;
    let status = text
        .lines()
        .find_map(|line| line.strip_prefix("status="))
        .ok_or_else(|| "terminal status missing".to_owned())?
        .parse()
        .map_err(|_| "terminal status invalid".to_owned())?;
    let target_pid = text
        .lines()
        .find_map(|line| line.strip_prefix("target-pid="))
        .ok_or_else(|| "target pid missing".to_owned())?
        .parse()
        .map_err(|_| "target pid invalid".to_owned())?;
    let authorization_offset_millis = text
        .lines()
        .find_map(|line| line.strip_prefix("authorization-offset-millis="))
        .ok_or_else(|| "authorization offset missing".to_owned())?
        .parse()
        .map_err(|_| "authorization offset invalid".to_owned())?;
    let fact = |name: &str| -> Result<bool, String> {
        let prefix = format!("{name}=");
        match text.lines().find_map(|line| line.strip_prefix(&prefix)) {
            Some("true") => Ok(true),
            Some("false") => Ok(false),
            _ => Err(format!("terminal fact {name} missing or invalid")),
        }
    };
    Ok(TerminalReceipt {
        status,
        target_pid,
        authorization_offset_millis,
        assignment_verified: fact("assignment-verified")?,
        namespaces_verified: fact("namespaces-verified")?,
        credentials_verified: fact("credentials-verified")?,
        capabilities_empty: fact("capabilities-empty")?,
        descriptors_verified: fact("descriptors-verified")?,
        cgroup_view_denied: fact("cgroup-view-denied")?,
        guardian_ready: fact("guardian-ready-before-authorization")?,
        frontend_loss_authority: fact("frontend-loss-authority-verified")?,
        cgroup_kill: fact("cgroup-kill-invoked")?,
        cgroup_empty: fact("cgroup-empty")?,
        init_reaped: fact("init-reaped")?,
        guardian_reaped: fact("guardian-reaped")?,
        boundary_retired: fact("boundary-retired")?,
        memory_limit_exceeded: fact("memory-limit-exceeded")?,
        deadline_exceeded: fact("deadline-exceeded")?,
    })
}

fn nonce() -> Result<[u8; 16], String> {
    let mut bytes = [0_u8; 16];
    let mut file = fs::File::open("/dev/urandom").map_err(|error| error.to_string())?;
    file.read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(bytes)
}

fn write_frame(
    stream: &mut UnixStream,
    kind: u16,
    nonce: [u8; 16],
    attempt: [u8; 16],
    payload: &[u8],
) -> Result<(), String> {
    let total = HEADER_LENGTH
        .checked_add(payload.len())
        .ok_or_else(|| "frame length overflow".to_owned())?;
    if total > MAX_FRAME {
        return Err("frame too large".to_owned());
    }
    let digest = Sha256::digest(payload);
    stream
        .write_all(&VERSION.to_be_bytes())
        .and_then(|()| stream.write_all(&kind.to_be_bytes()))
        .and_then(|()| stream.write_all(&(total as u32).to_be_bytes()))
        .and_then(|()| stream.write_all(&nonce))
        .and_then(|()| stream.write_all(&attempt))
        .and_then(|()| stream.write_all(&digest))
        .and_then(|()| stream.write_all(payload))
        .map_err(|error| error.to_string())
}

fn read_frame(stream: &mut UnixStream) -> Result<(u16, [u8; 16], [u8; 16], Vec<u8>), String> {
    let mut header = [0_u8; HEADER_LENGTH];
    stream
        .read_exact(&mut header)
        .map_err(|error| error.to_string())?;
    if u16::from_be_bytes([header[0], header[1]]) != VERSION {
        return Err("unsupported provider protocol".to_owned());
    }
    let kind = u16::from_be_bytes([header[2], header[3]]);
    let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if !(HEADER_LENGTH..=MAX_FRAME).contains(&total) {
        return Err("invalid provider frame length".to_owned());
    }
    let mut nonce = [0; 16];
    nonce.copy_from_slice(&header[8..24]);
    let mut attempt = [0; 16];
    attempt.copy_from_slice(&header[24..40]);
    let mut payload = vec![0; total - HEADER_LENGTH];
    stream
        .read_exact(&mut payload)
        .map_err(|error| error.to_string())?;
    if Sha256::digest(&payload).as_slice() != &header[40..72] {
        return Err("provider payload digest mismatch".to_owned());
    }
    Ok((kind, nonce, attempt, payload))
}
