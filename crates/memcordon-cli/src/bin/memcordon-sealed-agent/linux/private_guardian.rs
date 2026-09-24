//! Independent private-attempt guardian. It owns only exact pidfds, the
//! attempt cgroup identity, and three protocol endpoints. In particular the
//! fork child closes every inherited target, ELF, namespace and pipe handle.

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use super::cgroup::AttemptCgroup;
use super::private_attempt::ProcessIdentityV4;

const GUARDIAN_VERSION: u8 = 4;
const READY: u8 = 1;
const STOP: u8 = 1;
const TERMINAL_LEN: usize = 20;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianTriggerV4 {
    Stopped,
    FrontendLost,
    WorkerLost,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardianTerminalV4 {
    pub attempt_id: [u8; 16],
    pub trigger: GuardianTriggerV4,
    pub boundary_retired: bool,
}

impl GuardianTerminalV4 {
    pub(crate) fn encode(self) -> [u8; TERMINAL_LEN] {
        let mut bytes = [0_u8; TERMINAL_LEN];
        bytes[0] = GUARDIAN_VERSION;
        bytes[1..17].copy_from_slice(&self.attempt_id);
        bytes[17] = match self.trigger {
            GuardianTriggerV4::Stopped => 1,
            GuardianTriggerV4::FrontendLost => 2,
            GuardianTriggerV4::WorkerLost => 3,
        };
        bytes[18] = u8::from(self.boundary_retired);
        bytes
    }

    pub(crate) fn decode(bytes: [u8; TERMINAL_LEN], attempt_id: [u8; 16]) -> Result<Self, String> {
        if bytes[0] != GUARDIAN_VERSION || bytes[1..17] != attempt_id || bytes[19] != 0 {
            return Err("MCSEALED-PRIVATE-GUARDIAN: terminal identity differs".into());
        }
        let trigger = match bytes[17] {
            1 => GuardianTriggerV4::Stopped,
            2 => GuardianTriggerV4::FrontendLost,
            3 => GuardianTriggerV4::WorkerLost,
            _ => return Err("MCSEALED-PRIVATE-GUARDIAN: terminal trigger differs".into()),
        };
        let boundary_retired = match bytes[18] {
            0 => false,
            1 => true,
            _ => return Err("MCSEALED-PRIVATE-GUARDIAN: terminal boundary flag differs".into()),
        };
        if trigger == GuardianTriggerV4::Stopped && boundary_retired {
            return Err("MCSEALED-PRIVATE-GUARDIAN: stopped guardian cannot claim cleanup".into());
        }
        Ok(Self {
            attempt_id,
            trigger,
            boundary_retired,
        })
    }
}

pub struct PrivateGuardian {
    pid: libc::pid_t,
    pidfd: OwnedFd,
    control: Option<OwnedFd>,
    terminal: OwnedFd,
    attempt_id: [u8; 16],
    reaped: bool,
}

impl PrivateGuardian {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        attempt_id: [u8; 16],
        frontend_pidfd: BorrowedFd<'_>,
        worker_pidfd: BorrowedFd<'_>,
        init_pidfd: BorrowedFd<'_>,
        cgroup: AttemptCgroup,
        deadline: Instant,
    ) -> Result<Self, String> {
        let (control_read, control_write) = pipe()?;
        let (ready_read, ready_write) = pipe()?;
        let (terminal_read, terminal_write) = pipe()?;
        // SAFETY: this is a single-threaded per-attempt worker fork. The child
        // closes every inherited descriptor except its six typed endpoints.
        let pid = unsafe { libc::fork() };
        if pid == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-GUARDIAN: fork: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            let keep = [
                frontend_pidfd.as_raw_fd(),
                worker_pidfd.as_raw_fd(),
                init_pidfd.as_raw_fd(),
                control_read.as_raw_fd(),
                ready_write.as_raw_fd(),
                terminal_write.as_raw_fd(),
            ];
            if close_inherited_except(&keep).is_err() {
                // SAFETY: the fork child must never unwind into provider code.
                unsafe { libc::_exit(125) };
            }
            let result = guardian_loop(
                attempt_id, keep[0], keep[1], keep[2], keep[3], keep[4], keep[5], cgroup,
            );
            // SAFETY: the child has no parent-owned Rust state to unwind.
            unsafe { libc::_exit(if result.is_ok() { 0 } else { 125 }) };
        }
        drop(control_read);
        drop(ready_write);
        drop(terminal_write);
        // SAFETY: the returned descriptor belongs to this direct child.
        let raw_pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
        if raw_pidfd == -1 {
            // SAFETY: the still-unreaped direct child PID cannot have been reused.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(format!(
                "MCSEALED-PRIVATE-GUARDIAN: pidfd_open: {}",
                std::io::Error::last_os_error()
            ));
        }
        // SAFETY: successful pidfd_open returns a fresh owned descriptor.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
        if let Err(error) = ProcessIdentityV4::observe(pid, pidfd.as_fd())
            .and_then(|_| wait_ready(ready_read.as_fd(), deadline))
        {
            // SAFETY: pidfd is bound to the exact unreaped guardian child.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    0,
                    0,
                );
            }
            let cleanup = wait_exact_child(pid, Instant::now() + Duration::from_secs(5));
            return Err(match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; guardian cleanup: {cleanup}"),
            });
        }
        Ok(Self {
            pid,
            pidfd,
            control: Some(control_write),
            terminal: terminal_read,
            attempt_id,
            reaped: false,
        })
    }

    pub fn identity(&self) -> Result<ProcessIdentityV4, String> {
        ProcessIdentityV4::observe(self.pid, self.pidfd.as_fd())
    }

    pub fn is_live(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows one live pidfd without mutation.
        (unsafe { libc::poll(&raw mut pollfd, 1, 0) }) == 0 && pollfd.revents == 0
    }

    /// Stop only after the owner has retired the cgroup and closed all
    /// provider-held resources. The guardian's stopped frame proves no such
    /// cleanup itself; a supervisor must also reap this exact child.
    pub fn stop(mut self, deadline: Instant) -> Result<GuardianTerminalV4, String> {
        let control = self
            .control
            .take()
            .ok_or("MCSEALED-PRIVATE-GUARDIAN: control absent")?;
        write_one(control.as_raw_fd(), STOP)?;
        drop(control);
        let terminal = read_terminal(self.terminal.as_fd(), self.attempt_id, deadline)?;
        if terminal.trigger != GuardianTriggerV4::Stopped {
            return Err("MCSEALED-PRIVATE-GUARDIAN: guardian observed a loss before stop".into());
        }
        wait_exact_child(self.pid, deadline)?;
        self.reaped = true;
        Ok(terminal)
    }

    pub fn finish_after_loss(mut self, deadline: Instant) -> Result<GuardianTerminalV4, String> {
        let terminal = read_terminal(self.terminal.as_fd(), self.attempt_id, deadline)?;
        if terminal.trigger == GuardianTriggerV4::Stopped {
            return Err("MCSEALED-PRIVATE-GUARDIAN: loss terminal reported stop".into());
        }
        wait_exact_child(self.pid, deadline)?;
        self.reaped = true;
        Ok(terminal)
    }
}

impl Drop for PrivateGuardian {
    fn drop(&mut self) {
        // Closing the lease makes the guardian kill the exact attempt boundary
        // if this owner disappears. Drop cannot claim retirement or wait for
        // its terminal facts.
        self.control.take();
        if !self.reaped {
            // SAFETY: this observes only the exact direct child and never
            // treats an incomplete best-effort reap as terminal success.
            unsafe {
                libc::waitpid(self.pid, std::ptr::null_mut(), libc::WNOHANG);
            }
        }
    }
}

fn pipe() -> Result<(OwnedFd, OwnedFd), String> {
    let mut fds = [-1_i32; 2];
    // SAFETY: pipe2 writes exactly two descriptors on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-GUARDIAN: pipe2: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pipe2 transfers ownership of both descriptors.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn close_inherited_except(keep: &[i32; 6]) -> Result<(), String> {
    let mut sorted = keep.to_vec();
    sorted.sort_unstable();
    if sorted.iter().any(|fd| *fd < 3) || sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("MCSEALED-PRIVATE-GUARDIAN: descriptor inventory differs".into());
    }
    let mut first = 3_u32;
    for fd in sorted {
        let fd = fd as u32;
        if first < fd {
            close_range(first, fd - 1)?;
        }
        first = fd + 1;
    }
    close_range(first, u32::MAX)
}

fn close_range(first: u32, last: u32) -> Result<(), String> {
    // SAFETY: close_range receives only scalar bounds and closes child copies.
    if unsafe { libc::syscall(libc::SYS_close_range, first, last, 0_u32) } == -1 {
        return Err(format!(
            "MCSEALED-PRIVATE-GUARDIAN: close_range: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn guardian_loop(
    attempt_id: [u8; 16],
    frontend: i32,
    worker: i32,
    init: i32,
    control: i32,
    ready: i32,
    terminal: i32,
    cgroup: AttemptCgroup,
) -> Result<(), String> {
    write_one(ready, READY)?;
    let mut pollfds = [
        libc::pollfd {
            fd: frontend,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: worker,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
        libc::pollfd {
            fd: control,
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        },
    ];
    let trigger = loop {
        // SAFETY: poll borrows three initialized fd records.
        let status = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as libc::nfds_t, -1) };
        if status == -1 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(format!(
                "MCSEALED-PRIVATE-GUARDIAN: poll: {}",
                std::io::Error::last_os_error()
            ));
        }
        if pollfds[0].revents != 0 {
            break GuardianTriggerV4::FrontendLost;
        }
        if pollfds[1].revents != 0 {
            break GuardianTriggerV4::WorkerLost;
        }
        if pollfds[2].revents != 0 {
            let mut byte = [0_u8; 1];
            // SAFETY: read writes at most one byte to initialized memory.
            let read = unsafe { libc::read(control, byte.as_mut_ptr().cast(), 1) };
            if read == 1 && byte[0] == STOP {
                break GuardianTriggerV4::Stopped;
            }
            break GuardianTriggerV4::WorkerLost;
        }
    };
    let retired = if trigger == GuardianTriggerV4::Stopped {
        false
    } else {
        // SAFETY: init is the exact transferred pidfd, never a numeric PID.
        unsafe {
            libc::syscall(libc::SYS_pidfd_send_signal, init, libc::SIGKILL, 0, 0);
        }
        cgroup
            .kill_and_retire(Instant::now() + Duration::from_secs(30))
            .is_ok()
    };
    if trigger == GuardianTriggerV4::FrontendLost {
        // Give the worker a bounded interval to close its namespace and pipe
        // references. A stalled worker is then terminated by exact pidfd.
        let mut pollfd = libc::pollfd {
            fd: worker,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows the exact worker pidfd.
        if unsafe { libc::poll(&raw mut pollfd, 1, 5000) } == 0 {
            // SAFETY: only this attempt's authenticated worker pidfd is used.
            unsafe {
                libc::syscall(libc::SYS_pidfd_send_signal, worker, libc::SIGKILL, 0, 0);
            }
        }
    }
    let frame = GuardianTerminalV4 {
        attempt_id,
        trigger,
        boundary_retired: retired,
    }
    .encode();
    write_all(terminal, &frame)
}

fn write_one(fd: i32, byte: u8) -> Result<(), String> {
    write_all(fd, &[byte])
}

fn write_all(fd: i32, bytes: &[u8]) -> Result<(), String> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        // SAFETY: write borrows the immutable byte slice for this syscall.
        let count = unsafe { libc::write(fd, remaining.as_ptr().cast(), remaining.len()) };
        if count > 0 {
            remaining = &remaining[count as usize..];
            continue;
        }
        if count == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        return Err(format!(
            "MCSEALED-PRIVATE-GUARDIAN: write: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn wait_ready(fd: BorrowedFd<'_>, deadline: Instant) -> Result<(), String> {
    let mut byte = [0_u8; 1];
    read_exact_until(fd, &mut byte, deadline)?;
    if byte != [READY] {
        return Err("MCSEALED-PRIVATE-GUARDIAN: readiness differs".into());
    }
    Ok(())
}

fn read_terminal(
    fd: BorrowedFd<'_>,
    attempt_id: [u8; 16],
    deadline: Instant,
) -> Result<GuardianTerminalV4, String> {
    let mut bytes = [0_u8; TERMINAL_LEN];
    read_exact_until(fd, &mut bytes, deadline)?;
    GuardianTerminalV4::decode(bytes, attempt_id)
}

fn read_exact_until(fd: BorrowedFd<'_>, bytes: &mut [u8], deadline: Instant) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let now = Instant::now();
        if now >= deadline {
            return Err("MCSEALED-PRIVATE-GUARDIAN: protocol deadline expired".into());
        }
        let timeout = deadline
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut pollfd = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0,
        };
        // SAFETY: poll borrows one initialized descriptor record.
        let status = unsafe { libc::poll(&raw mut pollfd, 1, timeout) };
        if status == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        if status <= 0 || pollfd.revents & libc::POLLIN == 0 {
            return Err("MCSEALED-PRIVATE-GUARDIAN: protocol closed or timed out".into());
        }
        // SAFETY: read writes only to the unfilled byte slice.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count > 0 {
            offset += count as usize;
            continue;
        }
        if count == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        {
            continue;
        }
        return Err("MCSEALED-PRIVATE-GUARDIAN: short protocol frame".into());
    }
    Ok(())
}

fn wait_exact_child(pid: libc::pid_t, deadline: Instant) -> Result<(), String> {
    loop {
        let mut status = 0;
        // SAFETY: pid is the exact unreaped fork child of this worker.
        let observed = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if observed == pid {
            return Ok(());
        }
        if observed == -1 {
            return Err(format!(
                "MCSEALED-PRIVATE-GUARDIAN: waitpid: {}",
                std::io::Error::last_os_error()
            ));
        }
        if Instant::now() >= deadline {
            return Err("MCSEALED-PRIVATE-GUARDIAN: reap deadline expired".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
