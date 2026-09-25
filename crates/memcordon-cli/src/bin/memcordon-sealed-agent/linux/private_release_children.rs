//! Fixed target-side child/thread lifetime fixture. This module does not
//! authorize or complete a release case: the release owner must independently
//! observe the live identities and their retirement before it may dispatch.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::mpsc;

use memcordon_core::workload_codec::hash_bytes;

pub(crate) const SELECTOR: &str = "private_tcp::child_runtime_and_threads_retired";
pub(crate) const LIVE_PREFIX: &[u8; 8] = b"MCRCHLD1";
pub(crate) const LIVE_BYTES: usize = LIVE_PREFIX.len() + 4 + 4 + 4 + 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TargetLiveChildrenV1 {
    pub(crate) target_pid: u32,
    pub(crate) child_pid: u32,
    pub(crate) thread_tid: u32,
    pub(crate) challenge_sha256: memcordon_core::DiagnosticSha256,
}

impl TargetLiveChildrenV1 {
    pub(crate) fn decode(bytes: &[u8], challenge: &[u8; 32]) -> Result<Self, String> {
        if bytes.len() != LIVE_BYTES || !bytes.starts_with(LIVE_PREFIX) {
            return Err("MCSEALED-PRIVATE-RELEASE: child live frame differs".into());
        }
        let mut offset = LIVE_PREFIX.len();
        let read_u32 = |offset: &mut usize| {
            let value = u32::from_le_bytes(
                bytes[*offset..*offset + 4]
                    .try_into()
                    .expect("fixed live frame width"),
            );
            *offset += 4;
            value
        };
        let target_pid = read_u32(&mut offset);
        let child_pid = read_u32(&mut offset);
        let thread_tid = read_u32(&mut offset);
        let challenge_sha256 = hash_bytes(challenge);
        if target_pid == 0
            || child_pid == 0
            || thread_tid == 0
            || child_pid == target_pid
            || thread_tid == target_pid
            || child_pid == thread_tid
            || bytes[offset..] != *challenge_sha256.bytes()
        {
            return Err("MCSEALED-PRIVATE-RELEASE: child live identity differs".into());
        }
        Ok(Self {
            target_pid,
            child_pid,
            thread_tid,
            challenge_sha256,
        })
    }
}

/// Called only by the fixed installed target entrypoint. It emits a bounded
/// early frame while both descendants are live, then waits for the owner to
/// acknowledge its independent kernel observation before joining them.
#[allow(dead_code)] // Selector remains closed until owner/readback joins land.
pub(crate) fn run_target(challenge: &[u8; 32]) -> Result<(), String> {
    super::private_qualification::tcp_listener_client_competitor(challenge)?;
    let mut child_pipe = [-1; 2];
    // SAFETY: pipe2 initializes exactly two descriptor slots on success.
    if unsafe { libc::pipe2(child_pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pipe2 transferred one owned descriptor per slot.
    let child_read = unsafe { std::fs::File::from_raw_fd(child_pipe[0]) };
    // SAFETY: successful pipe2 transferred the separate write descriptor.
    let mut child_write = unsafe { std::fs::File::from_raw_fd(child_pipe[1]) };

    // SAFETY: the child executes only an async-signal-safe read and _exit.
    // SIGCHLD makes this a separate process, not a CLONE_THREAD task.
    let child = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
    if child < 0 {
        return Err(format!(
            "MCSEALED-PRIVATE-RELEASE: child clone: {}",
            std::io::Error::last_os_error()
        ));
    }
    if child == 0 {
        let mut byte = 0_u8;
        // SAFETY: a fixed one-byte buffer and live pipe descriptor are passed.
        let received = unsafe {
            libc::read(
                child_read.as_raw_fd(),
                (&raw mut byte).cast(),
                std::mem::size_of_val(&byte),
            )
        };
        // SAFETY: _exit performs no Rust cleanup after the raw clone branch.
        unsafe { libc::_exit(if received == 1 && byte == 1 { 0 } else { 125 }) };
    }
    drop(child_read);
    let child_pid = u32::try_from(child)
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child pid differs".to_owned())?;
    let (tid_tx, tid_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel::<()>(1);
    let thread = std::thread::spawn(move || {
        // SAFETY: gettid returns the calling kernel task identifier.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let _ = tid_tx.send(tid);
        let _ = release_rx.recv();
    });
    let thread_tid = u32::try_from(
        tid_rx
            .recv()
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child thread absent")?,
    )
    .map_err(|_| "MCSEALED-PRIVATE-RELEASE: child thread id differs")?;
    let target_pid = unsafe { libc::getpid() } as u32;
    let mut live = Vec::with_capacity(LIVE_BYTES);
    live.extend_from_slice(LIVE_PREFIX);
    live.extend_from_slice(&target_pid.to_le_bytes());
    live.extend_from_slice(&child_pid.to_le_bytes());
    live.extend_from_slice(&thread_tid.to_le_bytes());
    live.extend_from_slice(hash_bytes(challenge).bytes());
    if live.len() != LIVE_BYTES {
        return Err("MCSEALED-PRIVATE-RELEASE: child live encoding differs".into());
    }
    std::io::stdout()
        .write_all(&live)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child live response: {error}"))?;
    let mut stdin = std::io::stdin();
    let mut waiting = libc::pollfd {
        fd: stdin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only the fixed target stdin pipe while the owner
    // performs its bounded live process/thread checks.
    // The independent CI live-observation gate may use its full 15-second
    // budget before the owner sends this target ACK.
    if unsafe { libc::poll(&raw mut waiting, 1, 20_000) } != 1
        || waiting.revents & libc::POLLIN == 0
        || waiting.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child owner ack timed out".into());
    }
    let mut ack = [0_u8; 1];
    stdin
        .read_exact(&mut ack)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child owner ack: {error}"))?;
    if ack != [1] {
        return Err("MCSEALED-PRIVATE-RELEASE: child owner ack differs".into());
    }
    child_write
        .write_all(&ack)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child release: {error}"))?;
    release_tx
        .send(())
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: thread release failed")?;
    let mut status = 0;
    // SAFETY: waitpid reaps exactly the fixed child returned by clone.
    if unsafe { libc::waitpid(child as libc::pid_t, &raw mut status, 0) } != child as libc::pid_t
        || status != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: child exit differs".into());
    }
    thread
        .join()
        .map_err(|_| "MCSEALED-PRIVATE-RELEASE: thread exit differs")?;
    std::io::stdout()
        .write_all(&super::private_release_case::candidate_fixture_response(
            SELECTOR, challenge,
        ))
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: child completion: {error}"))
}
