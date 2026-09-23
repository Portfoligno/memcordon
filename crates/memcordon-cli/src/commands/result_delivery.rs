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

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureStage {
    Clock,
    Deadline,
    OwnerReservation,
    OwnerThread,
    Serialization,
    PreparationDeadline,
    ExecutableResolution,
    WriterSpawn,
    OwnerChannel,
    PipeConfiguration,
    PipeWrite,
    PipeDeadline,
    WriterWait,
    WriterDeadline,
    WriterExit,
}

#[cfg(feature = "test-fixtures")]
static EVIDENCE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(feature = "test-fixtures")]
static WRITER_OBSERVED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "test-fixtures")]
#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
enum WriterPhase {
    Entered = 1,
    PayloadRead,
    PayloadDecoded,
    BeforeWrite,
    BeforeRename,
    BeforeAck,
    Diagnostics,
    Complete,
}

#[cfg(feature = "test-fixtures")]
fn writer_phase(phase: WriterPhase) {
    if WRITER_OBSERVED.load(Ordering::Relaxed) {
        let byte = phase as u8;
        // Dedicated nonblocking helper stdout; one byte, never retry/flush.
        unsafe {
            libc::write(libc::STDOUT_FILENO, (&raw const byte).cast(), 1);
        }
    }
}

#[cfg(feature = "test-fixtures")]
#[derive(Serialize)]
struct WriterObservation {
    // Best-effort prefix only: an unresolved writer or dropped nonblocking
    // publication can have advanced beyond the last retained phase.
    phases: Vec<WriterPhase>,
    os_error: Option<i32>,
    malformed: bool,
    truncated: bool,
}

#[cfg(feature = "test-fixtures")]
struct WriterTrace {
    pipe: std::process::ChildStdout,
    configuration_error: Option<io::Error>,
}

#[cfg(feature = "test-fixtures")]
impl WriterTrace {
    fn new(pipe: std::process::ChildStdout) -> Self {
        let fd = pipe.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let configuration_error = if flags < 0
            || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            Some(io::Error::last_os_error())
        } else {
            None
        };
        Self {
            pipe,
            configuration_error,
        }
    }
    fn finish(mut self) -> WriterObservation {
        let mut observation = WriterObservation {
            phases: Vec::new(),
            os_error: self
                .configuration_error
                .as_ref()
                .and_then(io::Error::raw_os_error),
            malformed: false,
            truncated: false,
        };
        if self.configuration_error.is_some() {
            return observation;
        }
        let mut bytes = [0_u8; 32];
        match self.pipe.read(&mut bytes) {
            Ok(count) => {
                observation.truncated = count == bytes.len();
                for byte in &bytes[..count] {
                    let phase = match byte {
                        1 => WriterPhase::Entered,
                        2 => WriterPhase::PayloadRead,
                        3 => WriterPhase::PayloadDecoded,
                        4 => WriterPhase::BeforeWrite,
                        5 => WriterPhase::BeforeRename,
                        6 => WriterPhase::BeforeAck,
                        7 => WriterPhase::Diagnostics,
                        8 => WriterPhase::Complete,
                        _ => {
                            observation.malformed = true;
                            continue;
                        }
                    };
                    observation.phases.push(phase);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => (),
            Err(error) => observation.os_error = error.raw_os_error(),
        }
        observation
    }
}

/// Explicit test-only telemetry channel: never stderr or a filesystem sink.
#[cfg(feature = "test-fixtures")]
pub(crate) fn observe_failures(descriptor: i32) -> io::Result<()> {
    if descriptor < 3 {
        return Err(io::Error::other("invalid delivery evidence descriptor"));
    }
    // SAFETY: fcntl/fstat inspect the supplied live inherited descriptor.
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let kind = unsafe { metadata.assume_init() }.st_mode & libc::S_IFMT;
    if flags & libc::O_NONBLOCK == 0 || ![libc::S_IFIFO, libc::S_IFSOCK].contains(&kind) {
        return Err(io::Error::other(
            "delivery evidence requires a nonblocking pipe or socket",
        ));
    }
    // Prevent descendants from retaining this frontend-only evidence channel.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    EVIDENCE_FD.store(descriptor, Ordering::Release);
    Ok(())
}

fn failed(stage: FailureStage, error: Option<&io::Error>, exit_code: Option<i32>) -> bool {
    failed_observed(
        stage,
        error,
        exit_code,
        #[cfg(feature = "test-fixtures")]
        None,
    )
}

fn failed_observed(
    stage: FailureStage,
    error: Option<&io::Error>,
    exit_code: Option<i32>,
    #[cfg(feature = "test-fixtures")] writer: Option<WriterObservation>,
) -> bool {
    #[cfg(feature = "test-fixtures")]
    {
        #[derive(Serialize)]
        struct Evidence {
            schema: u32,
            stage: FailureStage,
            os_error: Option<i32>,
            writer_exit_code: Option<i32>,
            writer: Option<WriterObservation>,
        }
        let descriptor = EVIDENCE_FD.load(Ordering::Acquire);
        if descriptor >= 3 {
            let evidence = Evidence {
                schema: 1,
                stage,
                os_error: error.and_then(io::Error::raw_os_error),
                writer_exit_code: exit_code,
                writer,
            };
            if let Ok(mut bytes) = serde_json::to_vec(&evidence) {
                bytes.push(b'\n');
                // A single best-effort nonblocking write: no retry, flush or
                // fallback to stderr. A full channel cannot delay CLI return.
                unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) };
            }
        }
    }
    #[cfg(not(feature = "test-fixtures"))]
    let _ = (stage, error, exit_code);
    false
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    schema: u32,
    diagnostics: Vec<u8>,
    report_path: Option<Vec<u8>>,
    report: Option<MemcordonReport>,
    #[cfg(feature = "test-fixtures")]
    barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
    #[cfg(feature = "test-fixtures")]
    delay_before_write: bool,
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
        #[cfg(feature = "test-fixtures")]
        false,
    )
}

fn deliver_inner(
    diagnostics: Vec<u8>,
    report_path: Option<&Path>,
    report: Option<MemcordonReport>,
    return_deadline: Option<u64>,
    #[cfg(feature = "test-fixtures")] barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
    #[cfg(feature = "test-fixtures")] delay_before_write: bool,
) -> bool {
    if diagnostics.is_empty() && report.is_none() {
        return true;
    }
    let started = match now() {
        Ok(value) => value,
        Err(error) => return failed(FailureStage::Clock, Some(&error), None),
    };
    let Some(local_deadline) = started.checked_add(DELIVERY_NANOS) else {
        return failed(FailureStage::Deadline, None, None);
    };
    // A completed native execution already owns one immutable return deadline
    // covering its retirement and result-delivery reserves. Preserve unused
    // retirement time for a durable report write instead of replacing it with
    // a fresh, shorter scheduling window. Setup errors without that evidence
    // remain bounded by the local delivery reserve.
    let deadline = return_deadline.unwrap_or(local_deadline);
    let write_deadline = deadline.saturating_sub(REAP_RESERVE_NANOS);
    if started >= write_deadline {
        return failed(FailureStage::Deadline, None, None);
    }
    let payload = Payload {
        schema: 1,
        diagnostics,
        report_path: report_path.map(|path| path.as_os_str().as_bytes().to_vec()),
        report,
        #[cfg(feature = "test-fixtures")]
        barrier,
        #[cfg(feature = "test-fixtures")]
        delay_before_write,
    };
    if OWNER_RESERVED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return failed(FailureStage::OwnerReservation, None, None);
    }
    // Native creation can stall. Its reserved owner retains late creation and
    // cancels it if the frontend has already stopped receiving. No write occurs
    // until the frontend transfers the complete, bounded payload.
    let (sender, receiver) = mpsc::sync_channel(0);
    #[cfg(feature = "test-fixtures")]
    let observe_writer = EVIDENCE_FD.load(Ordering::Acquire) >= 3;
    if let Err(error) = std::thread::Builder::new()
        .name("result-spawn-owner".into())
        .spawn(move || {
            let result = (|| -> Result<(Child, BoundedBytes), (FailureStage, io::Error)> {
                let mut bytes = BoundedBytes(Vec::new());
                serde_json::to_writer(&mut bytes, &payload)
                    .map_err(|error| (FailureStage::Serialization, io::Error::other(error)))?;
                if now().map_err(|error| (FailureStage::Clock, error))? >= write_deadline {
                    return Err((
                        FailureStage::PreparationDeadline,
                        io::Error::other("result preparation deadline"),
                    ));
                }
                let executable = std::env::current_exe()
                    .map_err(|error| (FailureStage::ExecutableResolution, error))?;
                let mut command = Command::new(executable);
                #[cfg(feature = "test-fixtures")]
                if observe_writer {
                    command
                        .arg("__result-writer-observed-v1")
                        .stdout(Stdio::piped());
                } else {
                    command.arg("__result-writer-v1").stdout(Stdio::null());
                }
                #[cfg(not(feature = "test-fixtures"))]
                command.arg("__result-writer-v1").stdout(Stdio::null());
                let child = command
                    .stdin(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|error| (FailureStage::WriterSpawn, error))?;
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
        OWNER_RESERVED.store(false, Ordering::Release);
        return failed(FailureStage::OwnerThread, Some(&error), None);
    }
    let (mut child, bytes) = loop {
        if now().unwrap_or(write_deadline) >= write_deadline {
            return failed(FailureStage::Deadline, None, None);
        }
        match receiver.recv_timeout(Duration::from_millis(2)) {
            Ok(Ok(value)) => break value,
            Ok(Err((stage, error))) => {
                OWNER_RESERVED.store(false, Ordering::Release);
                return failed(stage, Some(&error), None);
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return failed(FailureStage::OwnerChannel, None, None);
            }
        }
    };
    let mut stage = FailureStage::PipeConfiguration;
    #[cfg(feature = "test-fixtures")]
    let writer_trace = child.stdout.take().map(WriterTrace::new);
    let mut writer_exit_code = None;
    let delivery = (|| -> io::Result<bool> {
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
        for mut pending in [length.as_slice(), bytes.0.as_slice()] {
            while !pending.is_empty() {
                if now()? >= write_deadline {
                    stage = FailureStage::PipeDeadline;
                    return Ok(false);
                }
                stage = FailureStage::PipeWrite;
                match input.write(pending) {
                    Ok(0) => return Ok(false),
                    Ok(count) => pending = &pending[count..],
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        drop(input);
        stage = FailureStage::WriterWait;
        loop {
            if now()? >= write_deadline {
                stage = FailureStage::WriterDeadline;
                return Ok(false);
            }
            if let Some(status) = child.try_wait()? {
                stage = FailureStage::WriterExit;
                writer_exit_code = status.code();
                return Ok(status.success());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })();
    if matches!(delivery, Ok(true)) {
        OWNER_RESERVED.store(false, Ordering::Release);
        return true;
    }
    retire_writer(child, deadline);
    failed_observed(
        stage,
        delivery.as_ref().err(),
        writer_exit_code,
        #[cfg(feature = "test-fixtures")]
        writer_trace.map(WriterTrace::finish),
    )
}

fn retire_writer(mut child: Child, deadline: u64) {
    let _ = child.kill();
    while now().is_ok_and(|value| value < deadline) {
        match child.try_wait() {
            Ok(Some(_)) => {
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
    let _ = std::thread::Builder::new()
        .name("result-reap-owner".into())
        .spawn(move || {
            if child.wait().is_ok() {
                OWNER_RESERVED.store(false, Ordering::Release);
            }
        });
}

#[cfg(feature = "test-fixtures")]
pub(super) fn writer_observed() -> i32 {
    let flags = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return 125;
    }
    WRITER_OBSERVED.store(true, Ordering::Relaxed);
    writer()
}

pub(super) fn writer() -> i32 {
    #[cfg(feature = "test-fixtures")]
    writer_phase(WriterPhase::Entered);
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
        #[cfg(feature = "test-fixtures")]
        writer_phase(WriterPhase::PayloadRead);
        let mut payload: Payload = serde_json::from_slice(&bytes)?;
        if payload.schema != 1 || payload.report_path.is_some() != payload.report.is_some() {
            return Err(io::Error::other("invalid result payload"));
        }
        #[cfg(feature = "test-fixtures")]
        writer_phase(WriterPhase::PayloadDecoded);
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
            {
                let delay_before_write = payload.delay_before_write;
                let barrier = payload
                    .barrier
                    .map(|(phase, marker)| (phase, PathBuf::from(OsString::from_vec(marker))));
                memcordon_core::write_report_atomic_with_test_observer(
                    &path,
                    &report,
                    barrier
                        .as_ref()
                        .map(|(phase, marker)| (*phase, marker.as_path())),
                    |phase| {
                        writer_phase(match phase {
                            memcordon_core::ReportWritePhase::BeforeWrite => {
                                WriterPhase::BeforeWrite
                            }
                            memcordon_core::ReportWritePhase::BeforeRename => {
                                WriterPhase::BeforeRename
                            }
                            memcordon_core::ReportWritePhase::BeforeAck => WriterPhase::BeforeAck,
                        });
                        if delay_before_write
                            && phase == memcordon_core::ReportWritePhase::BeforeWrite
                        {
                            std::thread::sleep(Duration::from_millis(1100));
                        }
                    },
                )
                .map_err(io::Error::other)?;
            }
            #[cfg(not(feature = "test-fixtures"))]
            memcordon_core::write_report_atomic(&path, &report).map_err(io::Error::other)?;
        }
        #[cfg(feature = "test-fixtures")]
        writer_phase(WriterPhase::Diagnostics);
        write_diagnostics(&payload.diagnostics)
    })();
    match result {
        Ok(()) => {
            #[cfg(feature = "test-fixtures")]
            writer_phase(WriterPhase::Complete);
            0
        }
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
        false,
    ) {
        0
    } else {
        125
    }
}

#[cfg(feature = "test-fixtures")]
pub(super) fn delayed_write_test(input: &Path, output: &Path) -> i32 {
    let report: MemcordonReport = match std::fs::read(input)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    {
        Some(report) => report,
        None => return 126,
    };
    let return_deadline = match now().and_then(|started| {
        started
            .checked_add(3_000_000_000)
            .ok_or_else(|| io::Error::other("test return deadline overflow"))
    }) {
        Ok(deadline) => deadline,
        Err(_) => return 126,
    };
    if deliver_inner(
        Vec::new(),
        Some(output),
        Some(report),
        Some(return_deadline),
        None,
        true,
    ) {
        0
    } else {
        125
    }
}
