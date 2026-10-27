//! Failure-consumed progress from the exact owned init, never startup authority.
#[cfg(test)]
#[path = "../../../../tests/sealed_agent/native_private_init_diagnostic.rs"]
mod tests;

use std::cell::Cell;
use std::fs::File;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd};

const HEADER: &[u8] = b"MCID\x02";
const MAX_PACKET: usize = 1024;
const MAX_DETAIL: usize = 512;
const FAILURE_RECORDS: u8 = 2;
const MAX_RECORDS: u8 = Phase::TargetForkBefore as u8 + FAILURE_RECORDS;
const FIELDS: usize = 5;

#[derive(Clone, Copy)]
#[repr(u8)]
pub(super) enum Phase {
    ChildClosureEntered = 1,
    NetworkPrepareBefore,
    NetworkPrepareAfter,
    RootEnterBefore,
    RootEnterAfter,
    WorkingDirectoryBefore,
    WorkingDirectoryAfter,
    EntrypointBefore,
    EntrypointAfter,
    FilterAndIdentityBefore,
    FilterAndIdentityAfter,
    RootPublishBefore,
    RootPublishAfter,
    TargetForkBefore,
}

fn phase_name(phase: u8) -> Option<&'static str> {
    Some(match phase {
        1 => "ChildClosureEntered",
        2 => "NetworkPrepareBefore",
        3 => "NetworkPrepareAfter",
        4 => "RootEnterBefore",
        5 => "RootEnterAfter",
        6 => "WorkingDirectoryBefore",
        7 => "WorkingDirectoryAfter",
        8 => "EntrypointBefore",
        9 => "EntrypointAfter",
        10 => "FilterAndIdentityBefore",
        11 => "FilterAndIdentityAfter",
        12 => "RootPublishBefore",
        13 => "RootPublishAfter",
        14 => "TargetForkBefore",
        _ => return None,
    })
}

pub(super) struct Provider(File);
pub(super) struct Init {
    endpoint: File,
    attempts: Cell<u8>,
    failures: Cell<u8>,
    dropped: Cell<u8>,
    last_phase: Cell<u8>,
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
            failures: Cell::new(0),
            dropped: Cell::new(0),
            last_phase: Cell::new(0),
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
        if self.failures.get() >= FAILURE_RECORDS {
            return Err("private init diagnostic attempt bound reached".into());
        }
        if !matches!(kind, 1 | 2) || !matches!(phase, 1..=3) {
            return Err("private init diagnostic kind or phase differs".into());
        }
        self.failures.set(self.failures.get() + 1);
        let (detail, truncated) = bounded_detail(detail);
        self.send(kind, phase, truncated, detail.as_bytes())
    }

    pub(super) fn progress(&self, phase: Phase) {
        let phase = phase as u8;
        if phase <= self.last_phase.get() || self.failures.get() != 0 {
            return;
        }
        self.last_phase.set(phase);
        let _ = self.send(3, phase, false, &[]);
    }

    fn send(&self, kind: u8, phase: u8, truncated: bool, detail: &[u8]) -> Result<(), String> {
        let sequence = self.attempts.get();
        if sequence >= MAX_RECORDS {
            return Err("private init diagnostic total attempt bound reached".into());
        }
        self.attempts.set(sequence + 1);
        let mut packet = Vec::with_capacity(HEADER.len() + FIELDS + detail.len());
        packet.extend_from_slice(HEADER);
        packet.extend_from_slice(&[
            sequence,
            self.dropped.get(),
            kind,
            phase,
            u8::from(truncated),
        ]);
        packet.extend_from_slice(detail);
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
            let error = std::io::Error::last_os_error();
            self.dropped.set(self.dropped.get() + 1);
            return Err(format!("private init diagnostic send: {}", error));
        }
        if sent as usize != packet.len() {
            self.dropped.set(self.dropped.get() + 1);
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
        let mut next_sequence = 0_u8;
        let mut dropped = 0_u8;
        let mut last_phase = 0_u8;
        for index in 0..=MAX_RECORDS {
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
                records.push(format!(
                    "transport-error-kind={:?},raw={:?}",
                    error.kind(),
                    error.raw_os_error()
                ));
                break;
            }
            if count == 0 {
                break;
            }
            let count = count as usize;
            if index == MAX_RECORDS {
                records.push("extra-record-cap-exceeded".into());
                break;
            }
            let body = HEADER.len() + FIELDS;
            if count > packet.len() || count < body || &packet[..HEADER.len()] != HEADER {
                records.push("malformed-or-oversized-record".to_owned());
                break;
            }
            let sequence = packet[HEADER.len()];
            let reported_dropped = packet[HEADER.len() + 1];
            let kind = packet[HEADER.len() + 2];
            let phase = packet[HEADER.len() + 3];
            let truncated = packet[HEADER.len() + 4];
            if sequence < next_sequence
                || sequence >= MAX_RECORDS
                || dropped.checked_add(sequence - next_sequence) != Some(reported_dropped)
            {
                records.push("duplicate-backward-or-inconsistent-sequence".into());
                break;
            }
            if sequence > next_sequence {
                records.push(format!(
                    "missing-records={},reported-send-failures={reported_dropped}",
                    sequence - next_sequence
                ));
            }
            next_sequence = sequence + 1;
            dropped = reported_dropped;
            if kind == 3 {
                let Some(name) = phase_name(phase) else {
                    records.push("unknown-progress-phase".into());
                    break;
                };
                if phase <= last_phase
                    || original_phase.is_some()
                    || publication_seen
                    || truncated != 0
                    || count != body
                {
                    records.push("inconsistent-progress-record".into());
                    break;
                }
                if last_phase == 0 && phase != Phase::ChildClosureEntered as u8 {
                    records.push("entered-marker-missing".into());
                }
                last_phase = phase;
                records.push(format!("progress seq={sequence} phase={name}"));
                continue;
            }
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
        if last_phase == 0 {
            records.push("progress-unavailable".into());
        }
        records.push(format!(
            "prefix-only next-sequence={next_sequence},reported-send-failures={dropped}"
        ));
        format!("diagnostic-only private-init [{}]", records.join("; "))
    }
}
