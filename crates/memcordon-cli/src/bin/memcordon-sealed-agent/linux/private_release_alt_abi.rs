//! Closed x86_64 alternate-ABI subwitness. This proves only that the reviewed
//! native filter admits a harmless native getpid and kills the x32-numbered
//! entry in two distinct supervised children. It never publishes the 25th
//! release selector: AArch64 still needs a pinned AArch32 ELF and compat-kernel
//! execution proof.

use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::network_filter::{NativeAbi, install_gated_private_filter};
use super::private_attempt::ProcessIdentityV4;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

pub(crate) const SELECTOR: &str = "private_tcp::abi_alternate_entry_denied";
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const GO: u8 = 0x41;
const RETURNED_MARKER: u8 = 0x52;
const MAX_CHILD_WAIT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Branch {
    Native,
    X32,
    I386Control,
    I386Filtered,
}

impl Branch {
    fn byte(self) -> u8 {
        match self {
            Self::Native => 1,
            Self::X32 => 2,
            Self::I386Control => 3,
            Self::I386Filtered => 4,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct X32AlternateAbiSubwitnessV1 {
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) native: ProcessIdentityV4,
    pub(crate) native_response_sha256: DiagnosticSha256,
    pub(crate) alternate: ProcessIdentityV4,
    pub(crate) alternate_signal: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct I386AlternateAbiSubwitnessV1 {
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) outer_control: ProcessIdentityV4,
    pub(crate) outer_control_response_sha256: DiagnosticSha256,
    pub(crate) filtered: ProcessIdentityV4,
    pub(crate) filtered_signal: i32,
}

impl I386AlternateAbiSubwitnessV1 {
    pub(crate) fn verify_binding(
        &self,
        challenge: &[u8; 32],
        filter: &DiagnosticSha256,
    ) -> Result<(), String> {
        let control_pid = libc::pid_t::try_from(self.outer_control.pid)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: i386 control PID overflows")?;
        if self.challenge_sha256 != hash_bytes(challenge)
            || self.filter_sha256 != *filter
            || self.outer_control.pid == 0
            || self.outer_control.start_time == 0
            || self.filtered.pid == 0
            || self.filtered.start_time == 0
            || self.outer_control == self.filtered
            || self.outer_control_response_sha256
                != i386_response_digest(challenge, filter, control_pid, control_pid.into())
            || self.filtered_signal != libc::SIGSYS
        {
            return Err("MCSEALED-PRIVATE-RELEASE: i386 witness binding differs".into());
        }
        Ok(())
    }
}

impl X32AlternateAbiSubwitnessV1 {
    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        let mut bytes = b"memcordon-private-release-x32-subwitness-v1\0".to_vec();
        bytes.extend_from_slice(&serde_json::to_vec(self).map_err(|error| error.to_string())?);
        Ok(hash_bytes(&bytes))
    }

    pub(crate) fn verify_binding(
        &self,
        challenge: &[u8; 32],
        filter: &DiagnosticSha256,
    ) -> Result<(), String> {
        let native_pid = libc::pid_t::try_from(self.native.pid)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: native x32 witness PID overflows")?;
        if self.challenge_sha256 != hash_bytes(challenge)
            || self.filter_sha256 != *filter
            || self.native.pid == 0
            || self.native.start_time == 0
            || self.alternate.pid == 0
            || self.alternate.start_time == 0
            || self.native == self.alternate
            || self.native_response_sha256
                != native_response_digest(challenge, filter, native_pid, native_pid.into())
            || self.alternate_signal != libc::SIGSYS
        {
            return Err("MCSEALED-PRIVATE-RELEASE: x32 witness binding differs".into());
        }
        Ok(())
    }
}

struct ChildObservation {
    identity: ProcessIdentityV4,
    native_response: Option<DiagnosticSha256>,
    signal: Option<i32>,
}

struct ChildGuard {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    reaped: bool,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        // SAFETY: retained pidfd addresses this exact forked child only.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        let mut status = 0;
        loop {
            // SAFETY: waitpid reaps only our still-owned forked child.
            let waited = unsafe { libc::waitpid(self.pid, &raw mut status, 0) };
            if waited == self.pid
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
            {
                break;
            }
        }
    }
}

/// The enclosing selector remains unsupported. This function is only a
/// borrow of a live, installed M0 candidate authority, not a result producer.
#[allow(dead_code)] // No AArch64 physical half or final case publication exists.
pub(crate) fn observe_x32_subwitness(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<X32AlternateAbiSubwitnessV1, String> {
    if case.selector() != SELECTOR || case.native_abi()? != NativeAbi::X86_64 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 authority or target ABI differs".into());
    }
    let (uid, gid) = case.target_ids()?;
    if uid == 0 || gid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child identity is root".into());
    }
    let challenge = case.challenge_bytes();
    let filter = case.filter_digest().clone();
    let native = run_branch(
        Branch::Native,
        challenge,
        &filter,
        uid,
        gid,
        case.deadline(),
    )?;
    case.revalidate()?;
    let alternate = run_branch(Branch::X32, challenge, &filter, uid, gid, case.deadline())?;
    case.revalidate()?;
    let witness = X32AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(&challenge),
        filter_sha256: filter,
        native: native.identity,
        native_response_sha256: native
            .native_response
            .ok_or("MCSEALED-PRIVATE-RELEASE: native getpid response absent")?,
        alternate: alternate.identity,
        alternate_signal: alternate
            .signal
            .ok_or("MCSEALED-PRIVATE-RELEASE: x32 SIGSYS absent")?,
    };
    if witness.native == witness.alternate || witness.alternate_signal != libc::SIGSYS {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child separation differs".into());
    }
    witness.verify_binding(&challenge, &witness.filter_sha256)?;
    Ok(witness)
}

/// The outer-policy-only control must execute the real i386 `int 0x80`
/// entry before the reviewed private filter's architecture kill is tested.
/// This is a closed physical subwitness, never a publishable case result.
#[allow(dead_code)]
pub(crate) fn observe_i386_entry_subwitness(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<I386AlternateAbiSubwitnessV1, String> {
    if case.selector() != SELECTOR || case.native_abi()? != NativeAbi::X86_64 {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 authority or target ABI differs".into());
    }
    let (uid, gid) = case.target_ids()?;
    if uid == 0 || gid == 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: i386 child identity is root".into());
    }
    let challenge = case.challenge_bytes();
    let filter = case.filter_digest().clone();
    let control = run_branch(
        Branch::I386Control,
        challenge,
        &filter,
        uid,
        gid,
        case.deadline(),
    )?;
    case.revalidate()?;
    let filtered = run_branch(
        Branch::I386Filtered,
        challenge,
        &filter,
        uid,
        gid,
        case.deadline(),
    )?;
    case.revalidate()?;
    let witness = I386AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(&challenge),
        filter_sha256: filter,
        outer_control: control.identity,
        outer_control_response_sha256: control
            .native_response
            .ok_or("MCSEALED-PRIVATE-RELEASE: i386 control response absent")?,
        filtered: filtered.identity,
        filtered_signal: filtered
            .signal
            .ok_or("MCSEALED-PRIVATE-RELEASE: i386 SIGSYS absent")?,
    };
    witness.verify_binding(&challenge, &witness.filter_sha256)?;
    Ok(witness)
}

fn ready_digest(
    branch: Branch,
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: libc::pid_t,
) -> DiagnosticSha256 {
    let mut bytes = b"memcordon-private-release-abi-ready-v1\0".to_vec();
    bytes.push(branch.byte());
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(filter.bytes());
    bytes.extend_from_slice(&pid.to_be_bytes());
    hash_bytes(&bytes)
}

fn native_response_digest(
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: libc::pid_t,
    returned: libc::c_long,
) -> DiagnosticSha256 {
    let mut bytes = b"memcordon-private-release-native-getpid-v1\0".to_vec();
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(filter.bytes());
    bytes.extend_from_slice(&pid.to_be_bytes());
    bytes.extend_from_slice(&returned.to_be_bytes());
    hash_bytes(&bytes)
}

fn i386_response_digest(
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: libc::pid_t,
    returned: libc::c_long,
) -> DiagnosticSha256 {
    let mut bytes = b"memcordon-private-release-i386-getpid-v1\0".to_vec();
    bytes.extend_from_slice(challenge);
    bytes.extend_from_slice(filter.bytes());
    bytes.extend_from_slice(&pid.to_be_bytes());
    bytes.extend_from_slice(&returned.to_be_bytes());
    hash_bytes(&bytes)
}

#[cfg(test)]
pub(crate) fn i386_response_digest_for_test(
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: libc::pid_t,
) -> DiagnosticSha256 {
    i386_response_digest(challenge, filter, pid, pid.into())
}

fn run_branch(
    branch: Branch,
    challenge: [u8; 32],
    filter: &DiagnosticSha256,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> Result<ChildObservation, String> {
    if Instant::now() >= deadline {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child deadline expired".into());
    }
    let tasks = std::fs::read_dir("/proc/self/task").map_err(|error| error.to_string())?;
    let mut task_count = 0_u8;
    for task in tasks {
        task.map_err(|error| error.to_string())?;
        task_count = task_count.saturating_add(1);
        if task_count > 1 {
            break;
        }
    }
    if task_count != 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 supervisor is multithreaded".into());
    }
    let branch_deadline = deadline.min(Instant::now() + MAX_CHILD_WAIT);
    let inherited_filter_count = seccomp_filter_count("/proc/self/status")?;
    let (mut parent, child) = UnixStream::pair().map_err(|error| error.to_string())?;
    let timeout = branch_deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child deadline expired".into());
    }
    parent
        .set_read_timeout(Some(timeout))
        .and_then(|()| parent.set_write_timeout(Some(timeout)))
        .map_err(|error| error.to_string())?;
    // SAFETY: this fixed release worker forks only from its single-threaded
    // supervisor context; the child closes inherited privileged descriptors.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: x32 child fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let result = child_branch(parent, child, branch, challenge, filter, uid, gid);
        // SAFETY: no inherited Rust authority may unwind or run parent drops.
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
    }
    drop(child);
    let pidfd = match pidfd_open(pid) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            // SAFETY: the child has not been waited, so its numeric PID
            // cannot yet be recycled; kill/reap only this forked child.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(error);
        }
    };
    let mut guard = ChildGuard {
        pid,
        pidfd,
        reaped: false,
    };
    let identity = ProcessIdentityV4::observe(pid, guard.pidfd.as_fd())?;
    let expected_ready = ready_digest(branch, &challenge, filter, pid);
    let mut ready = [0_u8; 32];
    parent
        .read_exact(&mut ready)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: x32 ready: {error}"))?;
    if ready != *expected_ready.bytes() {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 ready challenge differs".into());
    }
    verify_child_proc(
        pid,
        uid,
        gid,
        inherited_filter_count,
        branch != Branch::I386Control,
    )?;
    parent
        .write_all(&[GO])
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: x32 release: {error}"))?;
    let native_response = if matches!(branch, Branch::Native | Branch::I386Control) {
        let mut response = [0_u8; 32];
        parent
            .read_exact(&mut response)
            .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: ABI control getpid: {error}"))?;
        let expected = if branch == Branch::Native {
            native_response_digest(&challenge, filter, pid, pid as libc::c_long)
        } else {
            i386_response_digest(&challenge, filter, pid, pid as libc::c_long)
        };
        if response != *expected.bytes() {
            return Err("MCSEALED-PRIVATE-RELEASE: ABI control getpid response differs".into());
        }
        Some(expected)
    } else {
        let mut marker = [0_u8; 1];
        match parent.read_exact(&mut marker) {
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {}
            Ok(()) if marker == [RETURNED_MARKER] => {
                return Err("MCSEALED-PRIVATE-RELEASE: denied ABI syscall returned".into());
            }
            Ok(()) => return Err("MCSEALED-PRIVATE-RELEASE: ABI return marker differs".into()),
            Err(error) => {
                return Err(format!(
                    "MCSEALED-PRIVATE-RELEASE: ABI return channel: {error}"
                ));
            }
        }
        None
    };
    let status = wait_child(&mut guard, branch_deadline)?;
    match branch {
        Branch::Native if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => {
            Ok(ChildObservation {
                identity,
                native_response,
                signal: None,
            })
        }
        Branch::I386Control if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 => {
            Ok(ChildObservation {
                identity,
                native_response,
                signal: None,
            })
        }
        Branch::X32 if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS => {
            Ok(ChildObservation {
                identity,
                native_response: None,
                signal: Some(libc::SIGSYS),
            })
        }
        Branch::I386Filtered
            if libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSYS =>
        {
            Ok(ChildObservation {
                identity,
                native_response: None,
                signal: Some(libc::SIGSYS),
            })
        }
        _ => Err("MCSEALED-PRIVATE-RELEASE: native/x32 child terminal differs".into()),
    }
}

fn child_branch(
    parent: UnixStream,
    child: UnixStream,
    branch: Branch,
    challenge: [u8; 32],
    filter: &DiagnosticSha256,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    let child_fd = child.as_raw_fd();
    // SAFETY: fd 3 is the only retained supervisor channel in this child.
    if unsafe { libc::dup2(child_fd, 3) } != 3 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 control descriptor differs".into());
    }
    std::mem::forget(parent);
    std::mem::forget(child);
    // SAFETY: close_range removes inherited package, pidfd and service handles.
    if unsafe { libc::syscall(libc::SYS_close_range, 4_u32, u32::MAX, 0_u32) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 inherited descriptors remain".into());
    }
    // SAFETY: the successful dup2 created one owned fd 3.
    let mut control = unsafe { UnixStream::from_raw_fd(3) };
    // SAFETY: all three credential sets are dropped before the filter and the
    // syscall probe; no supplementary group is retained.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child identity drop failed".into());
    }
    if branch != Branch::I386Control {
        let installed = install_gated_private_filter(NativeAbi::X86_64, *filter.bytes())?;
        if installed.instruction_digest != *filter.bytes() {
            return Err("MCSEALED-PRIVATE-RELEASE: ABI installed filter differs".into());
        }
    }
    // SAFETY: getpid returns only this child process identity.
    let pid = unsafe { libc::getpid() };
    control
        .write_all(ready_digest(branch, &challenge, filter, pid).bytes())
        .map_err(|error| error.to_string())?;
    let mut go = [0_u8; 1];
    control
        .read_exact(&mut go)
        .map_err(|error| error.to_string())?;
    if go != [GO] {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 release byte differs".into());
    }
    match branch {
        Branch::Native => {
            // SAFETY: harmless native getpid is reviewed and allowed.
            let returned = unsafe { libc::syscall(libc::SYS_getpid) };
            if returned != pid as libc::c_long {
                return Err("MCSEALED-PRIVATE-RELEASE: native getpid failed".into());
            }
            control
                .write_all(native_response_digest(&challenge, filter, pid, returned).bytes())
                .map_err(|error| error.to_string())
        }
        Branch::X32 => {
            // SAFETY: the x32-numbered harmless getpid must hit the reviewed
            // filter's kill-process branch before kernel syscall dispatch.
            unsafe { libc::syscall((libc::SYS_getpid as u32 | X32_SYSCALL_BIT) as libc::c_long) };
            control
                .write_all(&[RETURNED_MARKER])
                .map_err(|error| error.to_string())?;
            Err("MCSEALED-PRIVATE-RELEASE: x32 entry unexpectedly returned".into())
        }
        Branch::I386Control => {
            let returned = i386_getpid_entry()?;
            if returned != pid as libc::c_long {
                return Err("MCSEALED-PRIVATE-RELEASE: i386 control getpid failed".into());
            }
            control
                .write_all(i386_response_digest(&challenge, filter, pid, returned).bytes())
                .map_err(|error| error.to_string())
        }
        Branch::I386Filtered => {
            let _returned = i386_getpid_entry()?;
            control
                .write_all(&[RETURNED_MARKER])
                .map_err(|error| error.to_string())?;
            Err("MCSEALED-PRIVATE-RELEASE: i386 entry unexpectedly returned".into())
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn i386_getpid_entry() -> Result<libc::c_long, String> {
    // Linux x86 i386 UAPI __NR_getpid is 20. `int 0x80` uses the i386 entry
    // path even from a 64-bit process; this syscall has no pointer arguments.
    const I386_NR_GETPID: i32 = 20;
    let mut eax = I386_NR_GETPID;
    // SAFETY: the fixed instruction enters the kernel for harmless getpid,
    // takes no pointers or arguments, and explicitly lists touched registers.
    unsafe {
        std::arch::asm!(
            "int 0x80",
            inout("eax") eax,
            lateout("ecx") _,
            lateout("edx") _,
            options(nostack),
        );
    }
    Ok(eax as libc::c_long)
}

#[cfg(not(target_arch = "x86_64"))]
fn i386_getpid_entry() -> Result<libc::c_long, String> {
    Err("MCSEALED-PRIVATE-RELEASE: i386 entry requires x86_64".into())
}

fn pidfd_open(pid: libc::pid_t) -> Result<OwnedFd, String> {
    // SAFETY: pidfd_open takes one positive, not-yet-reaped forked child PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: x32 pidfd: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transfers one descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn wait_child(guard: &mut ChildGuard, deadline: Instant) -> Result<i32, String> {
    let mut pollfd = libc::pollfd {
        fd: guard.pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(MAX_CHILD_WAIT);
        if remaining.is_zero() {
            return Err("MCSEALED-PRIVATE-RELEASE: x32 child deadline expired".into());
        }
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        // SAFETY: poll observes only the retained exact child pidfd.
        let observed = unsafe { libc::poll(&raw mut pollfd, 1, millis) };
        if observed > 0 && pollfd.revents & libc::POLLIN != 0 {
            break;
        }
        if observed == 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: x32 child did not exit".into());
        }
        if observed < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err("MCSEALED-PRIVATE-RELEASE: x32 pidfd wait failed".into());
    }
    let mut status = 0;
    // SAFETY: readable pidfd proves this exact forked child has exited.
    let waited = unsafe { libc::waitpid(guard.pid, &raw mut status, 0) };
    if waited != guard.pid {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child reap failed".into());
    }
    guard.reaped = true;
    Ok(status)
}

fn seccomp_filter_count(path: &str) -> Result<u32, String> {
    let status = std::fs::read_to_string(path).map_err(|error| error.to_string())?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Seccomp_filters:"))
        .ok_or("MCSEALED-PRIVATE-RELEASE: seccomp filter count absent")?
        .trim()
        .parse::<u32>()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: seccomp filter count invalid".into())
}

fn verify_child_proc(
    pid: libc::pid_t,
    uid: u32,
    gid: u32,
    inherited_filter_count: u32,
    private_filter_installed: bool,
) -> Result<(), String> {
    let expected_filter_count = inherited_filter_count
        .checked_add(u32::from(private_filter_installed))
        .ok_or("MCSEALED-PRIVATE-RELEASE: x32 filter count overflows")?;
    let path = format!("/proc/{pid}/status");
    let status = std::fs::read_to_string(&path).map_err(|error| error.to_string())?;
    let values = |prefix: &str| -> Result<Vec<u32>, String> {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .ok_or("MCSEALED-PRIVATE-RELEASE: x32 proc field absent")?
            .split_ascii_whitespace()
            .map(|value| value.parse::<u32>().map_err(|error| error.to_string()))
            .collect()
    };
    let zero_cap = |prefix: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(prefix))
            .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
            == Some(0)
    };
    if values("Uid:")? != [uid; 4]
        || values("Gid:")? != [gid; 4]
        || !values("Groups:")?.is_empty()
        || values("NoNewPrivs:")? != [1]
        || values("Seccomp:")? != [if expected_filter_count == 0 { 0 } else { 2 }]
        || values("Seccomp_filters:")? != [expected_filter_count]
        || !zero_cap("CapEff:")
        || !zero_cap("CapPrm:")
        || !zero_cap("CapAmb:")
    {
        return Err("MCSEALED-PRIVATE-RELEASE: x32 child kernel state differs".into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn ready_digest_for_test(
    branch_x32: bool,
    challenge: &[u8; 32],
    filter: &DiagnosticSha256,
    pid: libc::pid_t,
) -> DiagnosticSha256 {
    ready_digest(
        if branch_x32 {
            Branch::X32
        } else {
            Branch::Native
        },
        challenge,
        filter,
        pid,
    )
}
