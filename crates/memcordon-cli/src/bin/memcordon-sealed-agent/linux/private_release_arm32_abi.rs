//! Physical AArch32 helper execution under the installed ARM64 candidate.
//! This is a closed subwitness: CI still needs an independent exec/seccomp
//! observer and a detached aggregate before the ABI selector can be routed.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use serde::{Deserialize, Serialize};

use super::network_filter::{NativeAbi, install_gated_private_filter};
use super::private_attempt::ProcessIdentityV4;
use super::private_release_run::ReleaseCandidateRunAuthorityV1;

const HELPER: &str = super::runtime_manifest::INSTALLED_ARM32_HELPER;
const GO: u8 = 0x47;
const READY: u8 = 0x52;
const RETURNED: u8 = b'A';
const MAX_BRANCH: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Arm32AlternateAbiSubwitnessV1 {
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) helper_sha256: DiagnosticSha256,
    pub(crate) filter_sha256: DiagnosticSha256,
    pub(crate) native: ProcessIdentityV4,
    pub(crate) native_response_sha256: DiagnosticSha256,
    pub(crate) outer_control: ProcessIdentityV4,
    pub(crate) filtered: ProcessIdentityV4,
    pub(crate) control_exec_observed: bool,
    pub(crate) filtered_exec_observed: bool,
    pub(crate) control_returned: bool,
    pub(crate) filtered_signal: i32,
}

impl Arm32AlternateAbiSubwitnessV1 {
    pub(crate) fn digest(&self) -> Result<DiagnosticSha256, String> {
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        Ok(hash_bytes(&bytes))
    }

    pub(crate) fn verify_binding(
        &self,
        challenge: &[u8; 32],
        helper: &DiagnosticSha256,
        filter: &DiagnosticSha256,
    ) -> Result<(), String> {
        let native_pid = libc::pid_t::try_from(self.native.pid)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: ARM64 native PID overflows")?;
        if self.challenge_sha256 != hash_bytes(challenge)
            || self.helper_sha256 != *helper
            || self.filter_sha256 != *filter
            || self.native.pid == 0
            || self.native.start_time == 0
            || self.native == self.outer_control
            || self.native == self.filtered
            || self.native_response_sha256
                != super::private_release_alt_abi::native_response_digest_for_arm64(
                    challenge, filter, native_pid,
                )
            || self.outer_control.pid == 0
            || self.filtered.pid == 0
            || self.outer_control == self.filtered
            || !self.control_exec_observed
            || !self.filtered_exec_observed
            || !self.control_returned
            || self.filtered_signal != libc::SIGSYS
        {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 ABI witness differs".into());
        }
        Ok(())
    }
}

struct BranchObservation {
    child: ProcessIdentityV4,
    exec_observed: bool,
    returned: bool,
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
        // SAFETY: pidfd addresses the exact retained child, and waitpid
        // reaps only that child even after an interrupted ptrace exchange.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            );
            libc::ptrace(libc::PTRACE_CONT, self.pid, 0, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

/// Runs both actual helper execs. The outer-only branch must return from the
/// AArch32 getpid and write its fixed marker. The private-filtered branch
/// must exec the same pinned image, emit no marker and die by SIGSYS.
#[allow(dead_code)] // ABI result publication awaits independent CI observation.
pub(crate) fn observe_arm32_subwitness(
    case: &ReleaseCandidateRunAuthorityV1,
) -> Result<Arm32AlternateAbiSubwitnessV1, String> {
    if case.selector() != super::private_release_alt_abi::SELECTOR
        || case.native_abi()? != NativeAbi::Aarch64
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 ABI authority differs".into());
    }
    case.revalidate()?;
    let helper = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(HELPER)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: ARM32 helper open: {error}"))?;
    let metadata = helper.metadata().map_err(|error| error.to_string())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o755
        || metadata.len() == 0
        || metadata.len() > 1024 * 1024
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 helper identity differs".into());
    }
    let mut bytes = Vec::new();
    (&helper)
        .take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 != metadata.len() || !bytes.starts_with(b"\x7fELF\x01\x01\x01") {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 helper bytes differ".into());
    }
    let helper_digest = hash_bytes(&bytes);
    let expected = case.installed_arm32_helper_digest()?;
    if String::from(helper_digest.clone()) != expected {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 helper differs from B".into());
    }
    let (uid, gid) = case.target_ids()?;
    let challenge = case.challenge_bytes();
    let filter = case.filter_digest().clone();
    let native = super::private_release_alt_abi::observe_native_arm64_positive(case)?;
    case.revalidate()?;
    let control = run_branch(&helper, &bytes, uid, gid, &filter, case.deadline(), false)?;
    case.revalidate()?;
    let filtered = run_branch(&helper, &bytes, uid, gid, &filter, case.deadline(), true)?;
    case.revalidate()?;
    let witness = Arm32AlternateAbiSubwitnessV1 {
        challenge_sha256: hash_bytes(&challenge),
        helper_sha256: helper_digest.clone(),
        filter_sha256: filter.clone(),
        native: native.native,
        native_response_sha256: native.response_sha256,
        outer_control: control.child,
        filtered: filtered.child,
        control_exec_observed: control.exec_observed,
        filtered_exec_observed: filtered.exec_observed,
        control_returned: control.returned,
        filtered_signal: filtered
            .signal
            .ok_or("MCSEALED-PRIVATE-RELEASE: ARM32 SIGSYS absent")?,
    };
    witness.verify_binding(&challenge, &helper_digest, &filter)?;
    Ok(witness)
}

fn run_branch(
    helper: &File,
    helper_bytes: &[u8],
    uid: u32,
    gid: u32,
    filter: &DiagnosticSha256,
    deadline: Instant,
    private_filter: bool,
) -> Result<BranchObservation, String> {
    let deadline = deadline.min(Instant::now() + MAX_BRANCH);
    let (mut parent, child) = UnixStream::pair().map_err(|error| error.to_string())?;
    parent
        .set_read_timeout(Some(deadline.saturating_duration_since(Instant::now())))
        .map_err(|error| error.to_string())?;
    // SAFETY: the candidate worker is single-threaded and child exits with
    // _exit or execveat without unwinding inherited Rust authority.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: ARM32 fork: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        let result = child_exec(parent, child, helper, uid, gid, filter, private_filter);
        unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
    }
    drop(child);
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 pidfd unavailable".into());
    }
    let mut guard = ChildGuard {
        pid,
        pidfd: unsafe { OwnedFd::from_raw_fd(fd) },
        reaped: false,
    };
    let child = ProcessIdentityV4::observe(pid, guard.pidfd.as_fd())?;
    let stopped = wait_status(pid, deadline)?;
    if !libc::WIFSTOPPED(stopped) || libc::WSTOPSIG(stopped) != libc::SIGSTOP {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 trace arm differs".into());
    }
    if unsafe { libc::ptrace(libc::PTRACE_SETOPTIONS, pid, 0, libc::PTRACE_O_TRACEEXEC) } != 0
        || unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 exec trace setup failed".into());
    }
    let mut ready = [0_u8; 1];
    parent
        .read_exact(&mut ready)
        .map_err(|error| error.to_string())?;
    if ready != [READY] {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 ready differs".into());
    }
    parent.write_all(&[GO]).map_err(|error| error.to_string())?;
    let exec_stop = wait_status(pid, deadline)?;
    if !libc::WIFSTOPPED(exec_stop)
        || libc::WSTOPSIG(exec_stop) != libc::SIGTRAP
        || (exec_stop >> 16) != libc::PTRACE_EVENT_EXEC
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 exec event absent".into());
    }
    let image = std::fs::read(format!("/proc/{pid}/exe"))
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: ARM32 exec image: {error}"))?;
    if image != helper_bytes {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 executed image differs".into());
    }
    if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, 0) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 exec resume failed".into());
    }
    let terminal = wait_status(pid, deadline)?;
    let mut marker = [0_u8; 1];
    let returned = parent.read_exact(&mut marker).is_ok() && marker == [RETURNED];
    let terminal = if libc::WIFSTOPPED(terminal) && libc::WSTOPSIG(terminal) == libc::SIGSYS {
        if unsafe { libc::ptrace(libc::PTRACE_CONT, pid, 0, libc::SIGSYS) } != 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 SIGSYS delivery failed".into());
        }
        wait_status(pid, deadline)?
    } else {
        terminal
    };
    if !libc::WIFEXITED(terminal) && !libc::WIFSIGNALED(terminal) {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 child did not terminate".into());
    }
    guard.reaped = true;
    if private_filter {
        if returned || !libc::WIFSIGNALED(terminal) || libc::WTERMSIG(terminal) != libc::SIGSYS {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 filtered branch differs".into());
        }
        Ok(BranchObservation {
            child,
            exec_observed: true,
            returned: false,
            signal: Some(libc::SIGSYS),
        })
    } else {
        if !returned || !libc::WIFEXITED(terminal) || libc::WEXITSTATUS(terminal) != 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 outer control differs".into());
        }
        Ok(BranchObservation {
            child,
            exec_observed: true,
            returned: true,
            signal: None,
        })
    }
}

fn wait_status(pid: libc::pid_t, deadline: Instant) -> Result<i32, String> {
    loop {
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 child deadline expired".into());
        }
        let mut status = 0;
        // SAFETY: this child is traced by the current worker and has not
        // been reaped; WNOHANG keeps the case deadline effective.
        let observed = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if observed == pid {
            return Ok(status);
        }
        if observed < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 waitpid failed".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn child_exec(
    parent: UnixStream,
    child: UnixStream,
    helper: &File,
    uid: u32,
    gid: u32,
    filter: &DiagnosticSha256,
    private_filter: bool,
) -> Result<(), String> {
    if unsafe { libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 trace request failed".into());
    }
    unsafe { libc::raise(libc::SIGSTOP) };
    // Duplicate both sources above the fixed destination slots before either
    // dup2, so inherited descriptor numbering cannot swap helper and pipe.
    let helper_source = unsafe { libc::fcntl(helper.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    let control_source = unsafe { libc::fcntl(child.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
    if helper_source < 0
        || control_source < 0
        || unsafe { libc::dup2(helper_source, 4) } != 4
        || unsafe { libc::dup2(control_source, 3) } != 3
        || unsafe { libc::fcntl(4, libc::F_SETFD, libc::FD_CLOEXEC) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 child descriptors differ".into());
    }
    std::mem::forget(parent);
    std::mem::forget(child);
    if unsafe { libc::syscall(libc::SYS_close_range, 5_u32, u32::MAX, 0_u32) } != 0 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 inherited descriptors remain".into());
    }
    let mut control = unsafe { UnixStream::from_raw_fd(3) };
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0
        || unsafe { libc::setresgid(gid, gid, gid) } != 0
        || unsafe { libc::setresuid(uid, uid, uid) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 child identity drop failed".into());
    }
    if private_filter {
        let installed = install_gated_private_filter(NativeAbi::Aarch64, *filter.bytes())?;
        if installed.instruction_digest != *filter.bytes() {
            return Err("MCSEALED-PRIVATE-RELEASE: ARM32 filter digest differs".into());
        }
    }
    control
        .write_all(&[READY])
        .map_err(|error| error.to_string())?;
    let mut go = [0_u8; 1];
    control
        .read_exact(&mut go)
        .map_err(|error| error.to_string())?;
    if go != [GO] || unsafe { libc::dup2(3, 1) } != 1 {
        return Err("MCSEALED-PRIVATE-RELEASE: ARM32 release differs".into());
    }
    drop(control);
    let empty = b"\0";
    let argv: [*const libc::c_char; 2] = [
        b"memcordon-arm32-abi-helper\0".as_ptr().cast(),
        std::ptr::null(),
    ];
    let envp = [std::ptr::null::<libc::c_char>()];
    // SAFETY: fd 4 is the pinned, checked static ELF. The empty pathname
    // selects that fd exactly; argv/envp are fixed terminated pointer arrays.
    unsafe {
        libc::syscall(
            libc::SYS_execveat,
            4,
            empty.as_ptr(),
            argv.as_ptr(),
            envp.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    Err(format!(
        "MCSEALED-PRIVATE-RELEASE: ARM32 execveat: {}",
        std::io::Error::last_os_error()
    ))
}
