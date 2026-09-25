//! Process custody for a future fixed native private-case driver.
//!
//! This observes a child process independently of its stdout, but an exit
//! status is not a private-case completion. Only a stage-specific native
//! driver may interpret its raw terminal and retirement observations.

use std::ffi::OsString;
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::{CiError, Result};

const MAX_STREAM_BYTES: u64 = 1024 * 1024;

pub struct SupervisedProcessV2 {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Sampled from the Linux kernel while this process is still our child.
    /// This is process custody, not proof of any native private-case outcome.
    pub linux_child: Option<LinuxChildIdentityV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LinuxChildIdentityV1 {
    pub pid: u32,
    pub start_time_ticks: u64,
}

/// Independently corroborates that a recorded Linux process identity is no
/// longer live. A reused numeric PID is not mistaken for the old worker.
/// This is a narrow OS observation, not proof of target exec or retirement.
#[cfg(target_os = "linux")]
pub fn verify_recorded_process_exited(identity: LinuxChildIdentityV1) -> Result<()> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    if identity.pid == 0 || identity.start_time_ticks == 0 {
        return Err(CiError::Message(
            "recorded private process identity is incomplete".into(),
        ));
    }
    // SAFETY: pidfd_open observes exactly one positive numeric PID and does
    // not signal or mutate the process.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid as libc::pid_t, 0) } as i32;
    if raw == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(());
        }
        return Err(error.into());
    }
    // SAFETY: successful pidfd_open returned a unique owned descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let path = Path::new("/proc")
        .join(identity.pid.to_string())
        .join("stat");
    let stat = match std::fs::read_to_string(path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let current = parse_linux_child_stat(&stat, identity.pid)?;
    if current != identity {
        return Ok(());
    }
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll reads the retained pidfd without changing process state.
    let ready = unsafe { libc::poll(&raw mut pollfd, 1, 0) };
    if ready == 1 && pollfd.revents & libc::POLLIN != 0 {
        return Ok(());
    }
    if ready == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    Err(CiError::Message(
        "recorded private process is still live".into(),
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn verify_recorded_process_exited(_identity: LinuxChildIdentityV1) -> Result<()> {
    Err(CiError::Message(
        "private process exit observation requires native Linux".into(),
    ))
}

/// `/proc/<pid>/stat` starts with `pid (comm)`, where `comm` may itself
/// contain spaces and parentheses. Parse from the final close delimiter and
/// count fields from state (field 3) to starttime (field 22).
pub fn parse_linux_child_stat(stat: &str, expected_pid: u32) -> Result<LinuxChildIdentityV1> {
    let (prefix, fields) = stat
        .rsplit_once(") ")
        .ok_or_else(|| CiError::Message("private child proc stat delimiter absent".into()))?;
    let (pid_text, command) = prefix
        .split_once(" (")
        .ok_or_else(|| CiError::Message("private child proc stat header differs".into()))?;
    let pid: u32 = pid_text
        .parse()
        .map_err(|_| CiError::Message("private child proc stat PID differs".into()))?;
    let start_time_ticks: u64 = fields
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| CiError::Message("private child proc start time absent".into()))?
        .parse()
        .map_err(|_| CiError::Message("private child proc start time differs".into()))?;
    if pid == 0 || pid != expected_pid || command.is_empty() || start_time_ticks == 0 {
        return Err(CiError::Message(
            "private child proc identity differs".into(),
        ));
    }
    Ok(LinuxChildIdentityV1 {
        pid,
        start_time_ticks,
    })
}

#[cfg(target_os = "linux")]
fn observe_linux_child(pid: u32) -> Result<Option<LinuxChildIdentityV1>> {
    let path = Path::new("/proc").join(pid.to_string()).join("stat");
    let stat = std::fs::read_to_string(path)?;
    Ok(Some(parse_linux_child_stat(&stat, pid)?))
}

#[cfg(not(target_os = "linux"))]
fn observe_linux_child(_pid: u32) -> Result<Option<LinuxChildIdentityV1>> {
    Ok(None)
}

fn read_bounded(
    stream: impl Read + Send + 'static,
) -> thread::JoinHandle<std::io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.take(MAX_STREAM_BYTES + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

/// Spawns one argv-based child and observes its actual termination. Neither
/// child output nor exit code is trusted native case evidence by itself.
pub fn supervise_private_case_process(
    program: &Path,
    arguments: &[OsString],
    deadline: Duration,
) -> Result<SupervisedProcessV2> {
    let (process, _) =
        supervise_private_case_process_with_observer(program, arguments, deadline, || {
            Ok(None::<()>)
        })?;
    Ok(process)
}

/// Samples one independently owned live observation while the supervised
/// child is still running. `None` means the fixed observation gate has not
/// appeared yet; a failed observer terminates and reaps the child.
pub fn supervise_private_case_process_with_observer<T, F>(
    program: &Path,
    arguments: &[OsString],
    deadline: Duration,
    mut observe: F,
) -> Result<(SupervisedProcessV2, Option<T>)>
where
    F: FnMut() -> Result<Option<T>>,
{
    if !program.is_absolute()
        || arguments.len() > 64
        || arguments
            .iter()
            .any(|argument| argument.is_empty() || argument.as_encoded_bytes().len() > 4096)
        || deadline.is_zero()
    {
        return Err(CiError::Message(
            "private case process specification differs".into(),
        ));
    }
    let mut child = Command::new(program)
        .args(arguments)
        .env_remove("GITHUB_TOKEN")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let linux_child = match observe_linux_child(child.id()) {
        Ok(identity) => identity,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let stdout = read_bounded(child.stdout.take().expect("piped stdout"));
    let stderr = read_bounded(child.stderr.take().expect("piped stderr"));
    let started = Instant::now();
    let mut live_observation = None;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(error.into());
            }
        }
        if live_observation.is_none() {
            match observe() {
                Ok(value) => live_observation = value,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout.join();
                    let _ = stderr.join();
                    return Err(error);
                }
            }
        }
        if started.elapsed() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(CiError::Message(
                "private native child exceeded deadline".into(),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout
        .join()
        .map_err(|_| CiError::Message("private native stdout observer died".into()))??;
    let stderr = stderr
        .join()
        .map_err(|_| CiError::Message("private native stderr observer died".into()))??;
    if stdout.len() as u64 > MAX_STREAM_BYTES || stderr.len() as u64 > MAX_STREAM_BYTES {
        return Err(CiError::Message(
            "private native output exceeds byte bound".into(),
        ));
    }
    Ok((
        SupervisedProcessV2 {
            status,
            stdout,
            stderr,
            linux_child,
        },
        live_observation,
    ))
}
