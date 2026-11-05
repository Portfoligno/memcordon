//! A result writer has output authority, but never target-launch authority.
//!
//! The frontend observes successful writer exit and reaps it before accepting
//! delivery. The submitted report cannot certify its own later persistence.
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[cfg(feature = "test-fixtures")]
use memcordon_core::MemcordonReport;
use memcordon_core::ResultReport;
#[cfg(feature = "test-fixtures")]
#[path = "result_delivery_evidence.rs"]
mod evidence;
#[cfg(feature = "test-fixtures")]
use evidence::{EvidenceOutcome, WriterPhase};

#[cfg(feature = "test-fixtures")]
use memcordon_platform::DeliveryObservation;
use memcordon_platform::{
    DeliveryLimits, DeliveryOutcome, DeliveryRequest, DeliveryStage as FailureStage,
    MacosDeliveryRuntime, WriterImage,
};

#[cfg(feature = "test-fixtures")]
static EVIDENCE_FD: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(-1);

#[cfg(feature = "test-fixtures")]
static WRITER_OBSERVED: AtomicBool = AtomicBool::new(false);

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

fn failed_observed(
    stage: FailureStage,
    error: Option<&io::Error>,
    exit_code: Option<i32>,
    #[cfg(feature = "test-fixtures")] outcome: EvidenceOutcome,
    #[cfg(feature = "test-fixtures")] observation: Option<DeliveryObservation>,
) -> bool {
    #[cfg(feature = "test-fixtures")]
    {
        let descriptor = EVIDENCE_FD.load(Ordering::Acquire);
        if descriptor < 3 {
            return false;
        }
        if let Ok(bytes) = evidence::encode(
            outcome,
            stage,
            error.and_then(io::Error::raw_os_error),
            observation,
        ) {
            // A single best-effort nonblocking write: no retry, flush or
            // fallback to stderr. A full channel cannot delay CLI return.
            unsafe { libc::write(descriptor, bytes.as_ptr().cast(), bytes.len()) };
        }
    }
    #[cfg(feature = "test-fixtures")]
    let _ = exit_code;
    #[cfg(not(feature = "test-fixtures"))]
    let _ = (stage, error, exit_code);
    false
}

pub(super) fn runtime_initialization_failed(error: &io::Error) {
    // The caller uses fixed valid default limits and CurrentProcess; the
    // remaining initialization failure is creation of the bounded owner thread.
    failed_observed(
        FailureStage::OwnerThread,
        Some(error),
        None,
        #[cfg(feature = "test-fixtures")]
        EvidenceOutcome::InitializationFailed,
        #[cfg(feature = "test-fixtures")]
        None,
    );
}

fn now() -> io::Result<u64> {
    memcordon_platform::macos_continuous_nanos()
}

pub(super) fn deliver(
    runtime: &MacosDeliveryRuntime,
    diagnostics: Vec<u8>,
    report_path: Option<PathBuf>,
    report: Option<ResultReport>,
    return_deadline: Option<u64>,
) -> bool {
    deliver_inner(
        runtime,
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
    runtime: &MacosDeliveryRuntime,
    diagnostics: Vec<u8>,
    report_path: Option<PathBuf>,
    report: Option<ResultReport>,
    return_deadline: Option<u64>,
    #[cfg(feature = "test-fixtures")] barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
    #[cfg(feature = "test-fixtures")] delay_before_write: bool,
) -> bool {
    let mut request = DeliveryRequest::new(diagnostics, report_path, report, return_deadline);
    #[cfg(feature = "test-fixtures")]
    {
        request.barrier = barrier;
        request.delay_before_write = delay_before_write;
        request.observe_writer = EVIDENCE_FD.load(Ordering::Acquire) >= 3;
    }
    match runtime.deliver(request) {
        DeliveryOutcome::Completed { .. } => true,
        DeliveryOutcome::Busy => failed_observed(
            FailureStage::OwnerReservation,
            None,
            None,
            #[cfg(feature = "test-fixtures")]
            EvidenceOutcome::Busy,
            #[cfg(feature = "test-fixtures")]
            None,
        ),
        DeliveryOutcome::Failed {
            stage,
            error,
            observation,
        } => failed_observed(
            stage,
            error.as_ref(),
            observation.exit_code,
            #[cfg(feature = "test-fixtures")]
            EvidenceOutcome::Failed,
            #[cfg(feature = "test-fixtures")]
            Some(observation),
        ),
        DeliveryOutcome::Uncertain {
            stage,
            error,
            observation,
        } => failed_observed(
            stage,
            error.as_ref(),
            observation.exit_code,
            #[cfg(feature = "test-fixtures")]
            EvidenceOutcome::Uncertain,
            #[cfg(feature = "test-fixtures")]
            Some(observation),
        ),
    }
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
        let payload = super::result_frame::Frame::read(&mut input)?;
        #[cfg(feature = "test-fixtures")]
        writer_phase(WriterPhase::PayloadRead);
        #[cfg(feature = "test-fixtures")]
        writer_phase(WriterPhase::PayloadDecoded);
        if let (Some(path), Some(report)) = (payload.report_path, payload.report) {
            let path = PathBuf::from(OsString::from_vec(path));
            #[cfg(feature = "test-fixtures")]
            {
                let delay_before_write = payload.delay_before_write;
                let barrier = payload
                    .barrier
                    .map(|(phase, marker)| (phase, PathBuf::from(OsString::from_vec(marker))));
                memcordon_core::write_report_bytes_atomic_with_test_observer(
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
            memcordon_core::write_report_bytes_atomic(&path, &report).map_err(io::Error::other)?;
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
        &match MacosDeliveryRuntime::new(DeliveryLimits::default(), WriterImage::CurrentProcess) {
            Ok(runtime) => runtime,
            Err(_) => return 126,
        },
        Vec::new(),
        Some(output.to_path_buf()),
        Some(ResultReport::Standard(Box::new(report))),
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
        &match MacosDeliveryRuntime::new(DeliveryLimits::default(), WriterImage::CurrentProcess) {
            Ok(runtime) => runtime,
            Err(_) => return 126,
        },
        Vec::new(),
        Some(output.to_path_buf()),
        Some(ResultReport::Standard(Box::new(report))),
        Some(return_deadline),
        None,
        true,
    ) {
        0
    } else {
        125
    }
}
