//! Failure-only context from the exact owned init, never startup authority.
#[cfg(test)]
#[path = "../../../../tests/sealed_agent/native_private_init_diagnostic.rs"]
mod tests;

use std::cell::Cell;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};

const HEADER: &[u8] = b"MCID\x01";
const MAX_PACKET: usize = 1024;
const MAX_DETAIL: usize = 512;
const MAX_RECORDS: u8 = 2;

pub(super) struct Provider(File);
pub(super) struct Init {
    endpoint: File,
    attempts: Cell<u8>,
}

pub(super) fn channel() -> Result<(Provider, Init), String> {
    let mut fds = [-1; 2];
    // SAFETY: successful socketpair initializes exactly two owned descriptors.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "private init diagnostic socketpair: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: each successful socketpair result transfers one unique descriptor.
    let provider = Provider(unsafe { File::from_raw_fd(fds[0]) });
    // SAFETY: the second descriptor is distinct and uniquely owned.
    let endpoint = unsafe { File::from_raw_fd(fds[1]) };
    Ok((
        provider,
        Init {
            endpoint,
            attempts: Cell::new(0),
        },
    ))
}

fn bounded_detail(detail: &str) -> (String, bool) {
    if detail.len() <= MAX_DETAIL {
        return (detail.to_owned(), false);
    }
    let marker = "...";
    let half = (MAX_DETAIL - marker.len()) / 2;
    let mut head = half;
    while !detail.is_char_boundary(head) {
        head -= 1;
    }
    let mut tail = detail.len() - half;
    while !detail.is_char_boundary(tail) {
        tail += 1;
    }
    (
        format!("{}{marker}{}", &detail[..head], &detail[tail..]),
        true,
    )
}

impl Init {
    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.endpoint.as_fd()
    }

    pub(super) fn record(&self, kind: u8, phase: u8, detail: &str) -> Result<(), String> {
        let attempts = self.attempts.get();
        if attempts >= MAX_RECORDS {
            return Err("private init diagnostic attempt bound reached".into());
        }
        self.attempts.set(attempts + 1);
        if !matches!(kind, 1 | 2) || !matches!(phase, 1..=3) {
            return Err("private init diagnostic kind or phase differs".into());
        }
        let (detail, truncated) = bounded_detail(detail);
        let mut packet = Vec::with_capacity(HEADER.len() + 3 + detail.len());
        packet.extend_from_slice(HEADER);
        packet.extend_from_slice(&[kind, phase, u8::from(truncated)]);
        packet.extend_from_slice(detail.as_bytes());
        // SAFETY: one bounded packet is borrowed by one nonblocking send; no SIGPIPE policy changes.
        let sent = unsafe {
            libc::send(
                self.as_fd().as_raw_fd(),
                packet.as_ptr().cast(),
                packet.len(),
                libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT,
            )
        };
        if sent < 0 {
            return Err(format!(
                "private init diagnostic send: {}",
                std::io::Error::last_os_error()
            ));
        }
        if sent as usize != packet.len() {
            return Err("private init diagnostic partial packet".into());
        }
        Ok(())
    }
}

impl Provider {
    pub(super) fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    pub(super) fn context(&self) -> String {
        let mut records = Vec::new();
        let mut original_phase = None;
        let mut publication_seen = false;
        for _ in 0..MAX_RECORDS {
            let mut packet = [0_u8; MAX_PACKET];
            // SAFETY: fixed writable storage and a live owned nonblocking endpoint.
            let count = unsafe {
                libc::recv(
                    self.0.as_raw_fd(),
                    packet.as_mut_ptr().cast(),
                    packet.len(),
                    libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() == std::io::ErrorKind::WouldBlock {
                    break;
                }
                records.push(format!("transport-error={error:?}"));
                break;
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            let body = HEADER.len() + 3;
            if count > packet.len() || count < body || &packet[..HEADER.len()] != HEADER {
                records.push("malformed-or-oversized-record".to_owned());
                break;
            }
            let kind = packet[HEADER.len()];
            let phase = packet[HEADER.len() + 1];
            let truncated = packet[HEADER.len() + 2];
            if !matches!(phase, 1..=3) || truncated > 1 || count - body > MAX_DETAIL {
                records.push("malformed-record".to_owned());
                break;
            }
            let Ok(detail) = std::str::from_utf8(&packet[body..count]) else {
                records.push("invalid-utf8-record".to_owned());
                break;
            };
            let label = match kind {
                1 if original_phase.is_none() && !publication_seen => {
                    original_phase = Some(phase);
                    "original-failure"
                }
                2 if !publication_seen
                    && original_phase.is_none_or(|original| original == phase) =>
                {
                    publication_seen = true;
                    "publication-failure"
                }
                _ => {
                    records.push("duplicate-or-inconsistent-record".to_owned());
                    break;
                }
            };
            records.push(format!(
                "{label} phase={phase} truncated={} detail={detail:?}",
                truncated != 0
            ));
        }
        if records.is_empty() {
            records.push("record-absent".to_owned());
        }
        format!("diagnostic-only private-init [{}]", records.join("; "))
    }
}
