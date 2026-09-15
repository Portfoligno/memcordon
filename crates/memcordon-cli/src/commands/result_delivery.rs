//! A result writer has output authority, but never target-launch authority.
//!
//! The frontend observes successful writer exit and reaps it before accepting
//! delivery. The submitted report cannot certify its own later persistence.
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use memcordon_core::MemcordonReport;
use serde::{Deserialize, Serialize};

const MAX_PAYLOAD: usize = 64 * 1024 * 1024;
const DELIVERY_NANOS: u64 = 1_000_000_000;
const REAP_RESERVE_NANOS: u64 = 100_000_000;
static OWNER_RESERVED: AtomicBool = AtomicBool::new(false);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema: u32,
    diagnostics: Vec<u8>,
    report_path: Option<Vec<u8>>,
    report: Option<MemcordonReport>,
    #[cfg(feature = "test-fixtures")]
    barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
}

struct BoundedBytes(Vec<u8>);

impl Write for BoundedBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_PAYLOAD.saturating_sub(self.0.len()) {
            return Err(io::Error::other("result payload exceeds reserved capacity"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn now() -> io::Result<u64> {
    memcordon_platform::macos_continuous_nanos()
}

/// An optional immutable return deadline belongs to the native execution.
/// Setup errors without that evidence still receive a finite delivery bound.
pub(super) fn deliver(
    diagnostics: Vec<u8>,
    report_path: Option<&Path>,
    report: Option<MemcordonReport>,
    return_deadline: Option<u64>,
) -> bool {
    deliver_inner(
        diagnostics,
        report_path,
        report,
        return_deadline,
        #[cfg(feature = "test-fixtures")]
        None,
    )
}

fn deliver_inner(
    diagnostics: Vec<u8>,
    report_path: Option<&Path>,
    report: Option<MemcordonReport>,
    return_deadline: Option<u64>,
    #[cfg(feature = "test-fixtures")] barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
) -> bool {
    let mut observation = super::delivery_observation::Delivery::new(return_deadline);
    if diagnostics.is_empty() && report.is_none() {
        observation.stage = "empty";
        observation.reason = "nothing-to-deliver";
        observation.delivered = true;
        return true;
    }
    let started = match now() {
        Ok(value) => value,
        Err(error) => {
            observation.error(&error);
            return false;
        }
    };
    observation.started = Some(started);
    let Some(local_deadline) = started.checked_add(DELIVERY_NANOS) else {
        observation.reason = "deadline-overflow";
        return false;
    };
    let deadline = return_deadline.map_or(local_deadline, |value| value.min(local_deadline));
    let write_deadline = deadline.saturating_sub(REAP_RESERVE_NANOS);
    observation.return_deadline = Some(deadline);
    observation.write_deadline = Some(write_deadline);
    if started >= write_deadline {
        observation.reason = "deadline-before-start";
        return false;
    }
    let payload = Payload {
        schema: 1,
        diagnostics,
        report_path: report_path.map(|path| path.as_os_str().as_bytes().to_vec()),
        report,
        #[cfg(feature = "test-fixtures")]
        barrier,
    };
    if OWNER_RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        observation.stage = "owner-reservation";
        observation.reason = "owner-already-reserved";
        return false;
    }
    // Native creation can stall. Its reserved owner retains late creation and
    // cancels it if the frontend has already stopped receiving. No write occurs
    // until the frontend transfers the complete, bounded payload.
    let (sender, receiver) = mpsc::sync_channel(0);
    observation.stage = "spawn-owner-thread";
    if let Err(error) = std::thread::Builder::new()
        .name("result-spawn-owner".into())
        .spawn(move || {
            let result = (|| -> Result<(Child, BoundedBytes), (&'static str, io::Error)> {
                let mut bytes = BoundedBytes(Vec::new());
                serde_json::to_writer(&mut bytes, &payload)
                    .map_err(|error| ("serialize", io::Error::from(error)))?;
                if now().map_err(|error| ("creation-clock", error))? >= write_deadline {
                    return Err((
                        "preparation-deadline",
                        io::Error::other("result preparation deadline"),
                    ));
                }
                let executable =
                    std::env::current_exe().map_err(|error| ("current-executable", error))?;
                let child = Command::new(executable)
                    .arg("__result-writer-v1")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|error| ("writer-spawn", error))?;
                Ok((child, bytes))
            })();
            if let Err(mpsc::SendError(result)) = sender.send(result) {
                if let Ok((mut child, _)) = result {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                OWNER_RESERVED.store(false, Ordering::Release);
            }
        })
    {
        observation.error(&error);
        OWNER_RESERVED.store(false, Ordering::Release);
        return false;
    }
    observation.stage = "owner-handoff";
    let (mut child, bytes) = loop {
        let tick = match now() {
            Ok(value) => value,
            Err(error) => {
                observation.error(&error);
                return false;
            }
        };
        if tick >= write_deadline {
            // The owner may be serializing or creating the writer. No specific
            // creation failure is inferred without receiving its result.
            observation.reason = "deadline-awaiting-owner";
            return false;
        }
        match receiver.recv_timeout(Duration::from_millis(2)) {
            Ok(Ok(value)) => break value,
            Ok(Err((stage, error))) => {
                observation.stage = stage;
                observation.error(&error);
                OWNER_RESERVED.store(false, Ordering::Release);
                return false;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                observation.reason = "owner-disconnected";
                return false;
            }
        }
    };
    observation.writer_pid = Some(child.id());
    observation.payload_bytes = Some(bytes.0.len());
    let delivered = (|| -> io::Result<bool> {
        observation.stage = "writer-pipe";
        let mut input = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("missing writer pipe"))?;
        let fd = input.as_raw_fd();
        // SAFETY: this is the live, exclusively owned parent pipe descriptor.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let length = u64::try_from(bytes.0.len())
            .map_err(io::Error::other)?
            .to_le_bytes();
        for (stage, mut pending) in [
            ("write-length", length.as_slice()),
            ("write-payload", bytes.0.as_slice()),
        ] {
            observation.stage = stage;
            while !pending.is_empty() {
                if now()? >= write_deadline {
                    observation.reason = "write-deadline";
                    return Ok(false);
                }
                match input.write(pending) {
                    Ok(0) => {
                        observation.reason = "write-zero";
                        return Ok(false);
                    }
                    Ok(count) => {
                        observation.transferred_bytes += count;
                        pending = &pending[count..];
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        drop(input);
        observation.stage = "writer-exit";
        loop {
            if now()? >= write_deadline {
                observation.reason = "writer-exit-deadline";
                return Ok(false);
            }
            if let Some(status) = child.try_wait()? {
                observation.status(status);
                observation.reason = if status.success() {
                    "writer-success"
                } else {
                    "writer-failed"
                };
                return Ok(status.success());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    let delivered = match delivered {
        Ok(value) => value,
        Err(error) => {
            observation.error(&error);
            false
        }
    };
    if delivered {
        observation.delivered = true;
        OWNER_RESERVED.store(false, Ordering::Release);
        return true;
    }
    retire_writer(child, deadline, &mut observation);
    false
}

fn retire_writer(
    mut child: Child,
    deadline: u64,
    observation: &mut super::delivery_observation::Delivery,
) {
    if let Err(error) = child.kill() {
        observation.retirement_os_error = error.raw_os_error();
    }
    while now().is_ok_and(|value| value < deadline) {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Preserve an already observed writer failure before recording
                // forced termination used only for retirement.
                if observation.retirement != "reaped" {
                    observation.status(status);
                }
                OWNER_RESERVED.store(false, Ordering::Release);
                return;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(_) => break,
        }
    }
    // No success or cleanup assertion is made for this unresolved I/O owner.
    // In a library host the bounded slot stays reserved until its reap completes;
    // CLI process exit is not claimed to preserve this in-process reaper.
    observation.retirement = "reaper-pending";
    if let Err(error) = std::thread::Builder::new()
        .name("result-reap-owner".into())
        .spawn(move || {
            if child.wait().is_ok() {
                OWNER_RESERVED.store(false, Ordering::Release);
            }
        })
    {
        observation.retirement = "reaper-spawn-failed";
        observation.retirement_os_error = error.raw_os_error();
    }
}

pub(super) fn writer() -> i32 {
    let result = (|| -> io::Result<()> {
        let mut input = io::stdin().lock();
        let mut length = [0_u8; size_of::<u64>()];
        input.read_exact(&mut length)?;
        let length = usize::try_from(u64::from_le_bytes(length)).map_err(io::Error::other)?;
        if length > MAX_PAYLOAD {
            return Err(io::Error::other("oversized result payload"));
        }
        let mut bytes = vec![0; length];
        input.read_exact(&mut bytes)?;
        let mut payload: Payload = serde_json::from_slice(&bytes)?;
        if payload.schema != 1 || payload.report_path.is_some() != payload.report.is_some() {
            return Err(io::Error::other("invalid result payload"));
        }
        if let Some(report) = &mut payload.report {
            let writer_pid =
                std::num::NonZeroU32::new(std::process::id()).expect("native writer PID");
            for runtime in report
                .attempts
                .iter_mut()
                .filter_map(|attempt| attempt.runtime.as_mut())
                .chain(
                    report
                        .error
                        .iter_mut()
                        .filter_map(|error| error.runtime.as_mut()),
                )
            {
                runtime.delivery = memcordon_core::DeliveryEvidence::PreparedBy { writer_pid };
            }
        }
        if let (Some(path), Some(report)) = (payload.report_path, payload.report) {
            let path = PathBuf::from(OsString::from_vec(path));
            #[cfg(feature = "test-fixtures")]
            if let Some((phase, marker)) = payload.barrier {
                let marker = PathBuf::from(OsString::from_vec(marker));
                memcordon_core::write_report_atomic_with_test_barrier(
                    &path, &report, phase, &marker,
                )
                .map_err(io::Error::other)?;
                return Err(io::Error::other("writer barrier unexpectedly returned"));
            }
            memcordon_core::write_report_atomic(&path, &report).map_err(io::Error::other)?;
        }
        write_diagnostics(&payload.diagnostics)
    })();
    match result {
        Ok(()) => 0,
        Err(error) => {
            let mut output = crate::presentation::Presentation::automatic().stderr();
            let _ = crate::presentation::write_runtime_error(&mut output, error);
            125
        }
    }
}

fn write_diagnostics(bytes: &[u8]) -> io::Result<()> {
    let mut output = crate::presentation::Presentation::automatic().stderr();
    output.write_all(bytes)?;
    output.flush()
}

#[cfg(feature = "test-fixtures")]
pub(super) fn synchronous_stderr_mutant() -> i32 {
    // Deliberately restore the forbidden frontend sink placement so the outer
    // regression must detect its failure to return within the delivery reserve.
    if write_diagnostics(&vec![b'x'; 1024 * 1024]).is_ok() {
        0
    } else {
        125
    }
}

#[cfg(feature = "test-fixtures")]
pub(super) fn fault_test(
    phase: memcordon_core::ReportWritePhase,
    input: &Path,
    output: &Path,
    marker: &Path,
) -> i32 {
    let report: MemcordonReport = match std::fs::read(input)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(report) => report,
        None => return 126,
    };
    if deliver_inner(
        Vec::new(),
        Some(output),
        Some(report),
        None,
        Some((phase, marker.as_os_str().as_bytes().to_vec())),
    ) {
        0
    } else {
        125
    }
}
