//! Physical frontend and guardian loss for the fixed private host canary.
//!
//! A per-attempt frontend proxy owns the three relay peers and a control
//! channel. Its pidfd is the guardian's frontend input, not a placeholder
//! process. The root control coordinator stays live throughout both cases.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::namespace::CallerMountContext;
use super::network_profile::current_network_namespace;
use super::private_attempt::ProcessIdentityV4;
use super::private_guardian::{GuardianTerminalV4, ProbeGuardianKilledV1};
use super::private_lifecycle::{PrivateExecObservation, PrivateMonitorOutcome};
use super::private_qualification::{ProbeCaseAuthority, ProbeLossKindV1};
use crate::request::{FileIdentity, NamespaceIdentity, SwapLimit};

const ARMED_DOMAIN: &[u8] = b"memcordon-private-probe-loss-armed-v1\0";
const PROXY_STOP: u8 = 1;

#[derive(Serialize)]
pub(crate) enum ProbeLossPhysicalProofV1 {
    Frontend {
        proxy_wait_signal: i32,
        guardian_terminal: GuardianTerminalV4,
    },
    Guardian {
        guardian_killed: ProbeGuardianKilledV1,
        proxy_exit_code: i32,
    },
}

/// Obtained only after one actual branch target was armed, its selected live
/// process was lost, and the owner durably retired the exact native attempt.
#[derive(Serialize)]
pub(crate) struct ProbeLossSubattemptObservationV1 {
    pub(crate) kind: ProbeLossKindV1,
    pub(crate) attempt_id: String,
    pub(crate) checkpoint_digest: DiagnosticSha256,
    pub(crate) terminal_record_digest: DiagnosticSha256,
    pub(crate) challenge_sha256: DiagnosticSha256,
    pub(crate) armed_response_sha256: DiagnosticSha256,
    pub(crate) frontend: ProcessIdentityV4,
    pub(crate) candidate_exit_code: Option<i32>,
    pub(crate) physical: ProbeLossPhysicalProofV1,
}

/// One branch is one journal, one cgroup and one genuine loss. The base case
/// cannot be published until both branches independently complete.
pub(crate) fn execute_loss_subattempt(
    case: &ProbeCaseAuthority<'_>,
    kind: ProbeLossKindV1,
) -> Result<ProbeLossSubattemptObservationV1, String> {
    let mut proxy = FrontendProxy::spawn()?;
    let subcase = case.loss_subcase(
        kind,
        proxy.identity().pid as libc::pid_t,
        proxy.duplicate_pidfd()?,
    )?;
    subcase.verify_proxy_live()?;
    let prelaunch = subcase.prepare_native_prelaunch()?;
    let (uid, gid) = subcase.target_ids();
    let identity = super::execution_identity::ResolvedTargetIdentity::for_probe_account(uid, gid)?;
    let abi = subcase.native_abi()?;
    let mount = File::open("/proc/self/ns/mnt")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: mount namespace: {error}"))?;
    let root = File::open("/")
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: root descriptor: {error}"))?;
    let mount_metadata = mount.metadata().map_err(|error| error.to_string())?;
    let root_metadata = root.metadata().map_err(|error| error.to_string())?;
    let mount_context = CallerMountContext {
        mount_namespace: mount.into(),
        root: root.into(),
        mount_namespace_identity: NamespaceIdentity {
            device: mount_metadata.dev(),
            inode: mount_metadata.ino(),
        },
        root_identity: FileIdentity {
            device: root_metadata.dev(),
            inode: root_metadata.ino(),
        },
    };
    let work_directory = subcase.work_directory()?;
    let provider_namespace = current_network_namespace()?;
    let worker_pidfd = super::private_execution::pidfd_for_self()?;
    let challenge = subcase.challenge_bytes();
    let armed_response = subcase.expected_armed_response();
    let mut owner = subcase.begin_native_owner()?;
    let startup_deadline = (Instant::now() + Duration::from_secs(5)).min(subcase.deadline());
    if startup_deadline <= Instant::now() {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: startup deadline expired".into());
    }
    let setup = (|| -> Result<DiagnosticSha256, String> {
        owner.create_boundary(None, SwapLimit::Host)?;
        owner.spawn_namespace(
            prelaunch,
            mount_context,
            work_directory.into(),
            provider_namespace,
            provider_namespace,
        )?;
        owner.start_guardian(
            subcase.attempt_bytes(),
            subcase.frontend_pidfd(),
            worker_pidfd.as_fd(),
            startup_deadline,
        )?;
        let observed = owner.observe_gated_target(
            provider_namespace,
            provider_namespace,
            &identity,
            abi,
            *subcase.filter_digest().bytes(),
            startup_deadline,
        )?;
        owner.prepare_relay(proxy.take_relay()?)?;
        proxy.start(challenge)?;
        let checkpoint = owner.commit_probe_and_release(observed, subcase.as_case())?;
        if !matches!(
            owner.observe_exec(startup_deadline)?,
            PrivateExecObservation::ArmedAndControlClosed
        ) {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: target did not exec".into());
        }
        owner.pump_loss_probe_until_armed(&subcase, &proxy)?;
        Ok(checkpoint)
    })();
    let checkpoint = match setup {
        Ok(checkpoint) => checkpoint,
        Err(error) => {
            let cleanup = owner.retire_probe(Instant::now() + Duration::from_secs(30));
            return Err(match cleanup {
                Ok(_) => error,
                Err(cleanup) => format!("{error}; native cleanup: {cleanup}"),
            });
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let (retirement, physical) = match kind {
        ProbeLossKindV1::Frontend => {
            if let Err(error) = proxy.signal_loss() {
                let cleanup = owner.retire_probe(deadline);
                return Err(match cleanup {
                    Ok(_) => error,
                    Err(cleanup) => format!("{error}; native cleanup: {cleanup}"),
                });
            }
            let monitored = owner.monitor_frontend_loss_probe(&subcase);
            let reaped = proxy.reap_after_loss(deadline);
            // A monitor/reap error must not skip bounded native settlement.
            let (retirement, guardian_terminal) =
                owner.retire_probe_after_frontend_loss(&subcase, deadline)?;
            if monitored? != PrivateMonitorOutcome::FrontendLost {
                return Err("MCSEALED-PRIVATE-PROBE-LOSS: frontend loss not monitored".into());
            }
            let proxy_wait_signal = reaped?;
            (
                retirement,
                ProbeLossPhysicalProofV1::Frontend {
                    proxy_wait_signal,
                    guardian_terminal,
                },
            )
        }
        ProbeLossKindV1::Guardian => {
            let (retirement, guardian_killed) = owner.retire_probe_after_guardian_loss(deadline)?;
            let proxy_exit_code = proxy.stop(deadline)?;
            (
                retirement,
                ProbeLossPhysicalProofV1::Guardian {
                    guardian_killed,
                    proxy_exit_code,
                },
            )
        }
    };
    if retirement.checkpoint_digest.as_ref() != Some(&checkpoint)
        || current_network_namespace()? != provider_namespace
    {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: terminal or provider namespace differs".into());
    }
    subcase.revalidate()?;
    Ok(ProbeLossSubattemptObservationV1 {
        kind,
        attempt_id: retirement.attempt_id,
        checkpoint_digest: checkpoint,
        terminal_record_digest: retirement.terminal_record_digest,
        challenge_sha256: hash_bytes(&challenge),
        armed_response_sha256: hash_bytes(&armed_response),
        frontend: proxy.identity().clone(),
        candidate_exit_code: retirement.candidate_exit_code,
        physical,
    })
}

pub(crate) fn armed_response(challenge: &[u8; 32]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(ARMED_DOMAIN);
    digest.update(challenge);
    digest.finalize().into()
}

/// The installed fixture proves actual loopback TCP work before announcing
/// that it is armed. It cannot exit zero; only the supervisor's exact native
/// loss and retirement observations can complete this case.
pub(crate) fn run_loss_fixture(challenge: &[u8; 32]) -> Result<(), String> {
    let listener = TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP bind: {error}"))?;
    let address = listener
        .local_addr()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP address: {error}"))?;
    let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP connect: {error}"))?;
    let (mut accepted, peer) = listener
        .accept()
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP accept: {error}"))?;
    if peer.ip() != address.ip() {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: TCP peer is not loopback".into());
    }
    client
        .set_write_timeout(Some(Duration::from_secs(2)))
        .and_then(|()| accepted.set_read_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| accepted.set_write_timeout(Some(Duration::from_secs(2))))
        .and_then(|()| client.set_read_timeout(Some(Duration::from_secs(2))))
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP timeout: {error}"))?;
    client
        .write_all(challenge)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP send: {error}"))?;
    let mut observed = [0_u8; 32];
    accepted
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: TCP challenge differs".into());
    }
    accepted
        .write_all(&observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP echo: {error}"))?;
    client
        .read_exact(&mut observed)
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: TCP echo receive: {error}"))?;
    if observed != *challenge {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: TCP echo differs".into());
    }
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&armed_response(challenge))
        .and_then(|()| stdout.flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-PROBE-LOSS: armed response: {error}"))?;
    // Keep the real TCP listener and target alive until the native supervisor
    // injects loss and retires the boundary. No EOF or response is success.
    loop {
        std::thread::park();
    }
}

pub(crate) struct FrontendProxy {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    identity: ProcessIdentityV4,
    control: OwnedFd,
    relay: Option<[OwnedFd; 3]>,
    reaped: bool,
}

impl FrontendProxy {
    /// Forks one real relay-owning frontend for a single loss subattempt. The
    /// fork child closes inherited provider handles before touching its four
    /// typed endpoints; it never owns package or qualification authority.
    pub(crate) fn spawn() -> Result<Self, String> {
        let (stdin_read, stdin_write) = pipe()?;
        let (stdout_read, stdout_write) = pipe()?;
        let (stderr_read, stderr_write) = pipe()?;
        let (control_child, control_parent) = control_pair()?;
        // SAFETY: the launcher worker is single-threaded per attempt. The
        // child uses only its typed descriptors, then terminates with _exit.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy fork: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            drop(stdin_read);
            drop(stdout_write);
            drop(stderr_write);
            drop(control_parent);
            let keep = [
                stdin_write.as_raw_fd(),
                stdout_read.as_raw_fd(),
                stderr_read.as_raw_fd(),
                control_child.as_raw_fd(),
            ];
            let success = close_inherited_except(&keep).and_then(|()| {
                proxy_loop(
                    stdin_write.as_fd(),
                    stdout_read.as_fd(),
                    stderr_read.as_fd(),
                    control_child.as_fd(),
                )
            });
            // SAFETY: no child path may unwind into the inherited provider.
            unsafe { libc::_exit(if success.is_ok() { 0 } else { 125 }) };
        }
        drop(stdin_write);
        drop(stdout_read);
        drop(stderr_read);
        drop(control_child);
        // SAFETY: this binds the direct, not-yet-reaped child by kernel pidfd.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw == -1 {
            // SAFETY: the child is our unreaped direct child, not a recycled PID.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy pidfd: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful pidfd_open transferred one owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        let identity = match ProcessIdentityV4::observe(pid, pidfd.as_fd()) {
            Ok(identity) => identity,
            Err(error) => {
                // SAFETY: the retained pidfd still names our unreaped child.
                unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        pidfd.as_raw_fd(),
                        libc::SIGKILL,
                        0,
                        0,
                    );
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
                return Err(error);
            }
        };
        Ok(Self {
            pid,
            pidfd,
            identity,
            control: control_parent,
            relay: Some([stdin_read, stdout_write, stderr_write]),
            reaped: false,
        })
    }

    pub(crate) fn identity(&self) -> &ProcessIdentityV4 {
        &self.identity
    }

    pub(crate) fn pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    pub(crate) fn duplicate_pidfd(&self) -> Result<OwnedFd, String> {
        self.pidfd.try_clone().map_err(|error| error.to_string())
    }

    pub(crate) fn take_relay(&mut self) -> Result<[OwnedFd; 3], String> {
        self.relay
            .take()
            .ok_or("MCSEALED-PRIVATE-PROBE-LOSS: proxy relay already transferred".into())
    }

    pub(crate) fn start(&self, challenge: [u8; 32]) -> Result<(), String> {
        write_exact(self.control.as_fd(), &challenge)
    }

    pub(crate) fn wait_armed(&self, expected: [u8; 32], deadline: Instant) -> Result<(), String> {
        let mut observed = [0_u8; 32];
        read_exact_until(self.control.as_fd(), &mut observed, deadline)?;
        if observed != expected {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: proxy armed response differs".into());
        }
        Ok(())
    }

    pub(crate) fn try_armed(&self, expected: [u8; 32]) -> Result<bool, String> {
        let mut pollfd = libc::pollfd {
            fd: self.control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows the retained typed control endpoint.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
        if ready == -1 || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: proxy control poll failed".into());
        }
        if ready == 0 {
            return Ok(false);
        }
        let mut observed = [0_u8; 32];
        read_exact(self.control.as_fd(), &mut observed)?;
        if observed != expected {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: proxy armed response differs".into());
        }
        Ok(true)
    }

    pub(crate) fn signal_loss(&self) -> Result<(), String> {
        // SAFETY: pidfd_send_signal targets only the retained exact child.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                0,
                0,
            )
        } == -1
        {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy signal: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    pub(crate) fn reap_after_loss(&mut self, deadline: Instant) -> Result<i32, String> {
        let status = wait_exact_child(self.pid, self.pidfd.as_fd(), deadline)?;
        if !libc::WIFSIGNALED(status) || libc::WTERMSIG(status) != libc::SIGKILL {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: frontend did not die by SIGKILL".into());
        }
        self.reaped = true;
        Ok(libc::SIGKILL)
    }

    pub(crate) fn stop(&mut self, deadline: Instant) -> Result<i32, String> {
        write_exact(self.control.as_fd(), &[PROXY_STOP])?;
        let status = wait_exact_child(self.pid, self.pidfd.as_fd(), deadline)?;
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: live frontend failed clean stop".into());
        }
        self.reaped = true;
        Ok(0)
    }
}

impl Drop for FrontendProxy {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: best-effort containment only; Drop never claims proof.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                );
                libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG);
            }
        }
    }
}

fn proxy_loop(
    stdin: BorrowedFd<'_>,
    stdout: BorrowedFd<'_>,
    stderr: BorrowedFd<'_>,
    control: BorrowedFd<'_>,
) -> Result<(), ()> {
    for fd in [stdin, stdout, stderr] {
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) }
                == -1
        {
            return Err(());
        }
    }
    let mut challenge = [0_u8; 32];
    read_exact(control, &mut challenge).map_err(|_| ())?;
    write_exact(stdin, &challenge).map_err(|_| ())?;
    let mut response = [0_u8; 32];
    read_exact(stdout, &mut response).map_err(|_| ())?;
    if response != armed_response(&challenge) {
        return Err(());
    }
    let mut stderr_probe = [0_u8; 1];
    let mut stderr_poll = libc::pollfd {
        fd: stderr.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&raw mut stderr_poll, 1, 0) } > 0
        && unsafe { libc::read(stderr.as_raw_fd(), stderr_probe.as_mut_ptr().cast(), 1) } > 0
    {
        return Err(());
    }
    write_exact(control, &response).map_err(|_| ())?;
    let mut command = [0_u8; 1];
    read_exact(control, &mut command).map_err(|_| ())?;
    if command != [PROXY_STOP] {
        return Err(());
    }
    Ok(())
}

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    // SAFETY: pipe2 writes two descriptor slots on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-LOSS: pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pipe2 returned two unique owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn control_pair() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1; 2];
    // SAFETY: socketpair writes two descriptor slots on success.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return Err(format!(
            "MCSEALED-PRIVATE-PROBE-LOSS: control pair: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful socketpair returned two unique owned descriptors.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn close_inherited_except(keep: &[i32; 4]) -> Result<(), ()> {
    let mut sorted = *keep;
    sorted.sort_unstable();
    if sorted.iter().any(|fd| *fd < 3) || sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(());
    }
    let mut first = 3_u32;
    for fd in sorted {
        let fd = fd as u32;
        if first < fd && unsafe { libc::syscall(libc::SYS_close_range, first, fd - 1, 0_u32) } == -1
        {
            return Err(());
        }
        first = fd + 1;
    }
    if unsafe { libc::syscall(libc::SYS_close_range, first, u32::MAX, 0_u32) } == -1 {
        return Err(());
    }
    Ok(())
}

fn write_exact(fd: BorrowedFd<'_>, bytes: &[u8]) -> Result<(), String> {
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: write borrows only the remaining initialized bytes.
        let count = unsafe {
            libc::write(
                fd.as_raw_fd(),
                bytes[written..].as_ptr().cast(),
                bytes.len() - written,
            )
        };
        if count > 0 {
            written += count as usize;
        } else if count == -1
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy write: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn read_exact(fd: BorrowedFd<'_>, bytes: &mut [u8]) -> Result<(), String> {
    let mut read = 0;
    while read < bytes.len() {
        // SAFETY: read writes only the remaining initialized bytes.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[read..].as_mut_ptr().cast(),
                bytes.len() - read,
            )
        };
        if count > 0 {
            read += count as usize;
        } else if count == -1
            && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        } else {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy read: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

fn read_exact_until(fd: BorrowedFd<'_>, bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    let now = Instant::now();
    if now >= deadline {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: armed response deadline expired".into());
    }
    let timeout = deadline
        .saturating_duration_since(now)
        .as_millis()
        .min(i32::MAX as u128) as i32;
    let mut pollfd = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll borrows one initialized fd record.
    if unsafe { libc::poll(&raw mut pollfd, 1, timeout) } <= 0
        || pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0
    {
        return Err("MCSEALED-PRIVATE-PROBE-LOSS: armed response absent".into());
    }
    read_exact(fd, bytes)
}

fn wait_exact_child(
    pid: libc::pid_t,
    pidfd: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<i32, String> {
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: proxy reap deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pidfd poll observes the exact retained child identity.
        let ready = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if ready == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if ready <= 0 || pollfd.revents & libc::POLLIN == 0 {
            return Err("MCSEALED-PRIVATE-PROBE-LOSS: proxy exit unobserved".into());
        }
        let mut status = 0;
        // SAFETY: the PID is our exact direct child, retained by its pidfd.
        let reaped = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if reaped == pid {
            return Ok(status);
        }
        if reaped == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-PROBE-LOSS: proxy reap: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}
