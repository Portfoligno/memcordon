//! Fixed post-release target barrier. The owner must read the durable
//! ExecObserved journal and the live target before acknowledging this frame;
//! an eventual terminal result cannot be inferred from the frame alone.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::Instant;

use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

pub(crate) const SELECTOR: &str = "private_tcp::release_checkpoint_terminal_joined";
const LIVE_PREFIX: &[u8; 8] = b"MCRJOIN1";
pub(crate) const LIVE_BYTES: usize = LIVE_PREFIX.len() + 4 + 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalJoinLiveFrameV1 {
    pub(crate) target_pid: u32,
    pub(crate) challenge_sha256: DiagnosticSha256,
}

impl TerminalJoinLiveFrameV1 {
    pub(crate) fn decode(bytes: &[u8], challenge: &[u8; 32]) -> Result<Self, String> {
        if bytes.len() != LIVE_BYTES || !bytes.starts_with(LIVE_PREFIX) {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join live frame differs".into());
        }
        let pid_end = LIVE_PREFIX.len() + std::mem::size_of::<u32>();
        let target_pid = u32::from_le_bytes(
            bytes[LIVE_PREFIX.len()..pid_end]
                .try_into()
                .expect("fixed terminal-join PID width"),
        );
        let challenge_sha256 = hash_bytes(challenge);
        if target_pid == 0 || bytes[pid_end..] != *challenge_sha256.bytes() {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join live binding differs".into());
        }
        Ok(Self {
            target_pid,
            challenge_sha256,
        })
    }
}

pub(crate) fn read_live_frame(
    fd: BorrowedFd<'_>,
    deadline: Instant,
) -> Result<[u8; LIVE_BYTES], String> {
    let mut bytes = [0_u8; LIVE_BYTES];
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or("MCSEALED-PRIVATE-RELEASE: terminal-join live frame timed out")?;
        let timeout = i32::try_from(remaining.as_millis().min(i32::MAX as u128))
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: terminal-join deadline differs")?;
        let mut polled = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll borrows only the target's fixed stdout descriptor.
        if unsafe { libc::poll(&raw mut polled, 1, timeout) } != 1
            || polled.revents & libc::POLLIN == 0
            || polled.revents & (libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join live frame unavailable".into());
        }
        // SAFETY: read writes only the unwritten suffix of the fixed frame.
        let count = unsafe {
            libc::read(
                fd.as_raw_fd(),
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
            )
        };
        if count <= 0 {
            return Err("MCSEALED-PRIVATE-RELEASE: terminal-join live frame truncated".into());
        }
        offset += usize::try_from(count)
            .map_err(|_| "MCSEALED-PRIVATE-RELEASE: terminal-join frame size differs")?;
    }
    Ok(bytes)
}

/// Runs only as the pinned, unprivileged target after the normal release and
/// exec proof. It performs real TCP before declaring the live midpoint.
pub(crate) fn run_target(challenge: &[u8; 32]) -> Result<(), String> {
    super::private_qualification::tcp_listener_client_competitor(challenge)?;
    let mut live = Vec::with_capacity(LIVE_BYTES);
    live.extend_from_slice(LIVE_PREFIX);
    live.extend_from_slice(&(unsafe { libc::getpid() } as u32).to_le_bytes());
    live.extend_from_slice(hash_bytes(challenge).bytes());
    std::io::stdout()
        .write_all(&live)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: terminal-join live output: {error}"))?;
    let stdin = std::io::stdin();
    let mut waiting = libc::pollfd {
        fd: stdin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: poll observes only fixed stdin while the owner and CI perform
    // bounded independent post-release midpoint readback.
    if unsafe { libc::poll(&raw mut waiting, 1, 20_000) } != 1
        || waiting.revents & libc::POLLIN == 0
        || waiting.revents & (libc::POLLERR | libc::POLLNVAL | libc::POLLHUP) != 0
    {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join owner ack timed out".into());
    }
    let mut ack = [0_u8; 1];
    std::io::stdin()
        .read_exact(&mut ack)
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: terminal-join owner ack: {error}"))?;
    if ack != [1] {
        return Err("MCSEALED-PRIVATE-RELEASE: terminal-join owner ack differs".into());
    }
    let response = super::private_release_case::candidate_fixture_response(SELECTOR, challenge);
    std::io::stdout()
        .write_all(&response)
        .and_then(|()| std::io::stdout().flush())
        .map_err(|error| format!("MCSEALED-PRIVATE-RELEASE: terminal-join final output: {error}"))
}
