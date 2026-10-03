//! Scoped, bounded ownership of native result writers.
//! Independent runtimes provide no ordering between writes to the same file.
use memcordon_core::ResultReport;
use std::collections::BTreeSet;
use std::io::{self, Read, Write};
use std::num::{NonZeroU32, NonZeroUsize};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::Duration;

use crate::macos_result_frame::{self as frame, WriterFrame};

const IDLE: u64 = 0;
const QUEUED: u64 = 1;
const ACTIVE: u64 = 2;
const COMPLETE: u64 = 3;
const RETAINED: u64 = 4;
const COMMITTING: u64 = 5;
const CANCELLED: u64 = 6;
const RESERVED: u64 = 7;
const STATE_BITS: u32 = u8::BITS;
const STATE_MASK: u64 = u8::MAX as u64;
const MAX_GENERATION: u64 = u64::MAX >> STATE_BITS;
const DELIVERY_NANOS: u64 = 1_000_000_000;
const REAP_RESERVE_NANOS: u64 = 100_000_000;

#[derive(Clone, Copy, Debug)]
pub struct DeliveryLimits {
    pub max_in_flight: NonZeroUsize,
    pub max_total_bytes: usize,
}
impl Default for DeliveryLimits {
    fn default() -> Self {
        Self {
            max_in_flight: NonZeroUsize::MIN,
            max_total_bytes: frame::MAX_PAYLOAD,
        }
    }
}

#[derive(Clone, Debug)]
pub enum WriterImage {
    CurrentProcess,
    Installed(PathBuf),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum DeliveryStage {
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
    Destination,
    Shutdown,
}
impl DeliveryStage {
    fn from_byte(value: u8) -> Self {
        match value {
            0 => Self::Clock,
            1 => Self::Deadline,
            2 => Self::OwnerReservation,
            3 => Self::OwnerThread,
            4 => Self::Serialization,
            5 => Self::PreparationDeadline,
            6 => Self::ExecutableResolution,
            7 => Self::WriterSpawn,
            8 => Self::OwnerChannel,
            9 => Self::PipeConfiguration,
            10 => Self::PipeWrite,
            11 => Self::PipeDeadline,
            12 => Self::WriterWait,
            13 => Self::WriterDeadline,
            14 => Self::WriterExit,
            15 => Self::Destination,
            _ => Self::Shutdown,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DeliveryObservation {
    pub writer_pid: Option<NonZeroU32>,
    pub exit_code: Option<i32>,
    pub frame_transferred: bool,
    pub cleanup_outstanding: bool,
    /// Test-only, best-effort ordered writer phase prefix, encoded one byte each.
    pub writer_phases: [u8; 8],
    pub writer_phase_count: usize,
    pub writer_phase_error: Option<i32>,
    pub writer_phase_malformed: bool,
    pub writer_phase_truncated: bool,
}

#[derive(Debug)]
pub enum DeliveryOutcome {
    Completed {
        observation: DeliveryObservation,
    },
    Failed {
        stage: DeliveryStage,
        error: Option<io::Error>,
        observation: DeliveryObservation,
    },
    Uncertain {
        stage: DeliveryStage,
        error: Option<io::Error>,
        observation: DeliveryObservation,
    },
    Busy,
}

pub struct DeliveryRequest {
    diagnostics: Vec<u8>,
    report_path: Option<PathBuf>,
    report: Option<ResultReport>,
    return_deadline: Option<u64>,
    #[cfg(feature = "test-support")]
    pub barrier: Option<(memcordon_core::ReportWritePhase, Vec<u8>)>,
    #[cfg(feature = "test-support")]
    pub delay_before_write: bool,
    #[cfg(feature = "test-support")]
    pub observe_writer: bool,
    #[cfg(feature = "test-support")]
    pub panic_after_spawn: bool,
    #[cfg(feature = "test-support")]
    pub creation_gate: Option<Arc<AtomicBool>>,
    #[cfg(feature = "test-support")]
    pub creation_entered: Option<Arc<AtomicBool>>,
}
impl DeliveryRequest {
    pub fn new(
        diagnostics: Vec<u8>,
        report_path: Option<PathBuf>,
        report: Option<ResultReport>,
        return_deadline: Option<u64>,
    ) -> Self {
        Self {
            diagnostics,
            report_path,
            report,
            return_deadline,
            #[cfg(feature = "test-support")]
            barrier: None,
            #[cfg(feature = "test-support")]
            delay_before_write: false,
            #[cfg(feature = "test-support")]
            observe_writer: false,
            #[cfg(feature = "test-support")]
            panic_after_spawn: false,
            #[cfg(feature = "test-support")]
            creation_gate: None,
            #[cfg(feature = "test-support")]
            creation_entered: None,
        }
    }
}

struct Work {
    request: DeliveryRequest,
    deadline: u64,
}
struct Lane {
    state: AtomicU64,
    cancel: AtomicBool,
    caller_done: AtomicBool,
    stage: AtomicU8,
    pid: AtomicU32,
    transferred: AtomicBool,
    cleanup_outstanding: AtomicBool,
    work: Mutex<Option<Work>>,
    result: Mutex<Option<DeliveryOutcome>>,
    /// The native handle stays in preallocated storage across worker unwinding.
    child: Mutex<Option<Child>>,
    wake: mpsc::SyncSender<()>,
}
struct Inner {
    lanes: Box<[Lane]>,
    bytes_per_lane: usize,
    image: WriterImage,
    destinations: Mutex<BTreeSet<PathBuf>>,
    closing: AtomicBool,
    clients: AtomicUsize,
}

/// Initialize before deadline-critical execution. A timed-out operation remains
/// charged until its actual writer is reaped; Drop never joins or waits.
pub struct MacosDeliveryRuntime {
    inner: Arc<Inner>,
}
#[cfg(feature = "test-support")]
pub struct DeliveryRuntimeObserver {
    inner: Arc<Inner>,
}
#[cfg(feature = "test-support")]
impl DeliveryRuntimeObserver {
    pub fn outstanding(&self) -> usize {
        self.inner
            .lanes
            .iter()
            .filter(|lane| state(lane.state.load(Ordering::Acquire)) != IDLE)
            .count()
    }
}
impl Clone for MacosDeliveryRuntime {
    fn clone(&self) -> Self {
        self.inner
            .clients
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("delivery runtime client count overflow");
        Self {
            inner: self.inner.clone(),
        }
    }
}
impl Drop for MacosDeliveryRuntime {
    fn drop(&mut self) {
        if self.inner.clients.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.inner.closing.store(true, Ordering::Release);
            for lane in &self.inner.lanes {
                lane.cancel.store(true, Ordering::Release);
                let _ = lane.wake.try_send(());
            }
        }
    }
}
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn try_lock<T>(mutex: &Mutex<T>) -> Option<MutexGuard<'_, T>> {
    match mutex.try_lock() {
        Ok(guard) => Some(guard),
        Err(std::sync::TryLockError::Poisoned(error)) => Some(error.into_inner()),
        Err(std::sync::TryLockError::WouldBlock) => None,
    }
}
fn now() -> io::Result<u64> {
    crate::macos_deadline::continuous_nanos()
}
fn state(value: u64) -> u64 {
    value & STATE_MASK
}
fn with_state(value: u64, state: u64) -> u64 {
    (value & !STATE_MASK) | state
}

impl MacosDeliveryRuntime {
    pub fn new(limits: DeliveryLimits, image: WriterImage) -> io::Result<Self> {
        let capacity = limits.max_in_flight.get();
        let bytes_per_lane = limits.max_total_bytes / capacity;
        if capacity > 256 || bytes_per_lane < frame::HEADER || bytes_per_lane > frame::MAX_PAYLOAD {
            return Err(io::Error::other(
                "invalid bounded delivery lanes/payload budget",
            ));
        }
        if matches!(&image, WriterImage::Installed(path) if !path.is_absolute()) {
            return Err(io::Error::other("installed writer image must be absolute"));
        }
        let mut receivers = Vec::with_capacity(capacity);
        let lanes = (0..capacity)
            .map(|_| {
                let (wake, receive) = mpsc::sync_channel(1);
                receivers.push(receive);
                Lane {
                    state: AtomicU64::new(IDLE),
                    cancel: AtomicBool::new(false),
                    caller_done: AtomicBool::new(false),
                    stage: AtomicU8::new(DeliveryStage::PreparationDeadline as u8),
                    pid: AtomicU32::new(0),
                    transferred: AtomicBool::new(false),
                    cleanup_outstanding: AtomicBool::new(false),
                    work: Mutex::new(None),
                    result: Mutex::new(None),
                    child: Mutex::new(None),
                    wake,
                }
            })
            .collect();
        let inner = Arc::new(Inner {
            lanes,
            bytes_per_lane,
            image,
            destinations: Mutex::new(BTreeSet::new()),
            closing: AtomicBool::new(false),
            clients: AtomicUsize::new(1),
        });
        for (index, receive) in receivers.into_iter().enumerate() {
            let owner = inner.clone();
            if let Err(error) = std::thread::Builder::new()
                .name("memcordon-result-owner".into())
                .spawn(move || owner_loop(owner, index, receive))
            {
                inner.closing.store(true, Ordering::Release);
                for lane in &inner.lanes {
                    let _ = lane.wake.try_send(());
                }
                return Err(error);
            }
        }
        Ok(Self { inner })
    }

    pub fn outstanding(&self) -> usize {
        self.inner
            .lanes
            .iter()
            .filter(|lane| state(lane.state.load(Ordering::Acquire)) != IDLE)
            .count()
    }
    #[cfg(feature = "test-support")]
    pub fn observer(&self) -> DeliveryRuntimeObserver {
        DeliveryRuntimeObserver {
            inner: self.inner.clone(),
        }
    }

    pub fn deliver(&self, request: DeliveryRequest) -> DeliveryOutcome {
        if request.report_path.is_some() != request.report.is_some() {
            return failed(
                DeliveryStage::Serialization,
                io::Error::other("report path/model presence differs"),
            );
        }
        let minimum_payload = frame::HEADER
            .checked_add(request.diagnostics.len())
            .and_then(|length| {
                length.checked_add(
                    request
                        .report_path
                        .as_ref()
                        .map_or(0, |path| path.as_os_str().as_bytes().len()),
                )
            });
        if minimum_payload.is_none_or(|length| length > self.inner.bytes_per_lane) {
            return failed(
                DeliveryStage::Serialization,
                io::Error::other("request exceeds reserved payload budget"),
            );
        }
        if request.diagnostics.is_empty() && request.report.is_none() {
            return DeliveryOutcome::Completed {
                observation: DeliveryObservation::default(),
            };
        }
        let start = match now() {
            Ok(value) => value,
            Err(error) => return failed(DeliveryStage::Clock, error),
        };
        let deadline = match request
            .return_deadline
            .or_else(|| start.checked_add(DELIVERY_NANOS))
        {
            Some(value) if start < value.saturating_sub(REAP_RESERVE_NANOS) => value,
            _ => {
                return failed(
                    DeliveryStage::Deadline,
                    io::Error::new(io::ErrorKind::TimedOut, "result return deadline"),
                );
            }
        };
        if self.inner.closing.load(Ordering::Acquire) {
            return failed(
                DeliveryStage::Shutdown,
                io::Error::other("delivery runtime is closing"),
            );
        }
        let mut reserved = None;
        for lane in &self.inner.lanes {
            let value = lane.state.load(Ordering::Acquire);
            if state(value) != IDLE || value >> STATE_BITS == MAX_GENERATION {
                continue;
            }
            let key = ((value >> STATE_BITS) + 1) << STATE_BITS;
            if lane
                .state
                .compare_exchange(value, key | RESERVED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                reserved = Some((lane, key));
                break;
            }
        }
        let Some((lane, key)) = reserved else {
            return DeliveryOutcome::Busy;
        };
        lane.cancel.store(false, Ordering::Release);
        lane.caller_done.store(false, Ordering::Release);
        lane.pid.store(0, Ordering::Relaxed);
        lane.transferred.store(false, Ordering::Relaxed);
        lane.cleanup_outstanding.store(false, Ordering::Relaxed);
        lane.stage
            .store(DeliveryStage::PreparationDeadline as u8, Ordering::Relaxed);
        let Some(mut result) = try_lock(&lane.result) else {
            lane.state.store(key | IDLE, Ordering::Release);
            return DeliveryOutcome::Busy;
        };
        *result = None;
        drop(result);
        let Some(mut mailbox) = try_lock(&lane.work) else {
            lane.state.store(key | IDLE, Ordering::Release);
            return DeliveryOutcome::Busy;
        };
        *mailbox = Some(Work { request, deadline });
        drop(mailbox);
        // The worker cannot touch the mailbox until the complete request is
        // published. An idle owner never contends with a fresh reservation.
        lane.state.store(key | QUEUED, Ordering::Release);
        if self.inner.closing.load(Ordering::Acquire) {
            lane.cancel.store(true, Ordering::Release);
        }
        let _ = lane.wake.try_send(());
        loop {
            let value = lane.state.load(Ordering::Acquire);
            if value & !STATE_MASK == key && matches!(state(value), COMPLETE | RETAINED) {
                if let Some(mut guard) = try_lock(&lane.result) {
                    if let Some(result) = guard.take() {
                        lane.caller_done.store(true, Ordering::Release);
                        if state(value) == COMPLETE {
                            let _ = lane.state.compare_exchange(
                                value,
                                key | IDLE,
                                Ordering::AcqRel,
                                Ordering::Acquire,
                            );
                            let _ = lane.wake.try_send(());
                        }
                        return result;
                    }
                }
            }
            if now().map_or(true, |value| value >= deadline) {
                lane.cancel.store(true, Ordering::Release);
                for previous in [key | QUEUED, key | ACTIVE] {
                    let _ = lane.state.compare_exchange(
                        previous,
                        key | CANCELLED,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                }
                let observation = observation(lane);
                let stage = DeliveryStage::from_byte(lane.stage.load(Ordering::Acquire));
                let uncertain = observation.frame_transferred
                    || state(lane.state.load(Ordering::Acquire)) == COMMITTING;
                // Publish abandonment last: the owner may now release this
                // generation, so the caller must not mutate its lane again.
                lane.caller_done.store(true, Ordering::Release);
                let _ = lane.wake.try_send(());
                return if uncertain {
                    DeliveryOutcome::Uncertain {
                        stage,
                        error: None,
                        observation,
                    }
                } else {
                    DeliveryOutcome::Failed {
                        stage,
                        error: None,
                        observation,
                    }
                };
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

fn failed(stage: DeliveryStage, error: io::Error) -> DeliveryOutcome {
    DeliveryOutcome::Failed {
        stage,
        error: Some(error),
        observation: DeliveryObservation::default(),
    }
}
fn observation(lane: &Lane) -> DeliveryObservation {
    DeliveryObservation {
        writer_pid: NonZeroU32::new(lane.pid.load(Ordering::Acquire)),
        frame_transferred: lane.transferred.load(Ordering::Acquire),
        cleanup_outstanding: lane.cleanup_outstanding.load(Ordering::Acquire),
        ..Default::default()
    }
}
fn stage(lane: &Lane, value: DeliveryStage) {
    lane.stage.store(value as u8, Ordering::Release);
}
fn cancelled(inner: &Inner, lane: &Lane, deadline: u64) -> io::Result<()> {
    if inner.closing.load(Ordering::Acquire)
        || lane.cancel.load(Ordering::Acquire)
        || now()? >= deadline
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "result owner deadline/cancellation",
        ));
    }
    Ok(())
}
fn nonblocking(fd: i32) -> io::Result<()> {
    // SAFETY: the caller holds the actual pipe descriptor throughout this call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct BoundedBytes<'a> {
    bytes: Vec<u8>,
    bound: usize,
    inner: &'a Inner,
    lane: &'a Lane,
    deadline: u64,
}
impl Write for BoundedBytes<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        cancelled(self.inner, self.lane, self.deadline)?;
        if bytes.len() > self.bound.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("result exceeds reserved payload budget"));
        }
        if self.bytes.len() + bytes.len() > self.bytes.capacity() {
            self.bytes
                .try_reserve_exact(bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn destination(path: &Path) -> io::Result<PathBuf> {
    let file = path
        .file_name()
        .ok_or_else(|| io::Error::other("report destination has no file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    Ok(parent.canonicalize()?.join(file))
}

fn owner_loop(inner: Arc<Inner>, index: usize, receive: mpsc::Receiver<()>) {
    let lane = &inner.lanes[index];
    loop {
        let value = lane.state.load(Ordering::Acquire);
        if state(value) == COMPLETE && lane.caller_done.load(Ordering::Acquire) {
            let mut result = lock(&lane.result);
            if lane
                .state
                .compare_exchange(
                    value,
                    with_state(value, IDLE),
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                *result = None;
            }
        }
        if inner.closing.load(Ordering::Acquire)
            && state(lane.state.load(Ordering::Acquire)) == IDLE
        {
            return;
        }
        let work = if matches!(
            state(lane.state.load(Ordering::Acquire)),
            QUEUED | CANCELLED
        ) {
            lock(&lane.work).take()
        } else {
            None
        };
        let Some(work) = work else {
            if receive.recv().is_err() {
                return;
            }
            continue;
        };
        let key = lane.state.load(Ordering::Acquire) & !STATE_MASK;
        let _ = lane.state.compare_exchange(
            key | QUEUED,
            key | ACTIVE,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
        let mut destination_key = None;
        let mut observed = DeliveryObservation::default();
        let operation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            run_writer(&inner, lane, work, &mut destination_key, &mut observed)
        }));
        let mut result = match operation {
            Ok(value) => value,
            Err(_) => {
                stage(lane, DeliveryStage::OwnerThread);
                Err(io::Error::other(
                    "result owner panicked; native handle retained",
                ))
            }
        };
        let mut lost = false;
        if result.is_err() {
            let mut held = lock(&lane.child);
            if let Some(child) = held.as_mut() {
                let native_wait = loop {
                    match child.try_wait() {
                        Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
                        observation => break observation,
                    }
                };
                match native_wait {
                    Ok(Some(status)) => {
                        observed.exit_code = status.code();
                        *held = None;
                        lane.cleanup_outstanding.store(false, Ordering::Release);
                    }
                    Ok(None) => {
                        if let Err(error) = child.kill() {
                            result = Err(error);
                        }
                    }
                    Err(error) => {
                        result = Err(error);
                        lost = true;
                    }
                }
            }
        }
        // Retirement remains in this preallocated owner even after caller expiry.
        loop {
            if lost {
                break;
            }
            let terminal = {
                let mut held = lock(&lane.child);
                match held.as_mut() {
                    None => true,
                    Some(child) => match child.try_wait() {
                        Ok(Some(status)) => {
                            observed.exit_code = status.code();
                            *held = None;
                            lane.cleanup_outstanding.store(false, Ordering::Release);
                            true
                        }
                        Ok(None) => false,
                        Err(error) if error.raw_os_error() == Some(libc::EINTR) => false,
                        Err(error) => {
                            result = Err(error);
                            lost = true;
                            true
                        }
                    },
                }
            };
            if terminal {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if !lost {
            if let Some(path) = destination_key.take() {
                lock(&inner.destinations).remove(&path);
            }
        }
        observed.writer_pid = NonZeroU32::new(lane.pid.load(Ordering::Acquire));
        observed.frame_transferred = lane.transferred.load(Ordering::Acquire);
        observed.cleanup_outstanding = lost;
        let current_stage = DeliveryStage::from_byte(lane.stage.load(Ordering::Acquire));
        let outcome = match result {
            Ok(()) if !lost => DeliveryOutcome::Completed {
                observation: observed,
            },
            Err(error) if observed.frame_transferred || lost => DeliveryOutcome::Uncertain {
                stage: current_stage,
                error: Some(error),
                observation: observed,
            },
            Err(error)
                if current_stage == DeliveryStage::Destination
                    && error.kind() == io::ErrorKind::WouldBlock =>
            {
                DeliveryOutcome::Busy
            }
            Err(error) => DeliveryOutcome::Failed {
                stage: current_stage,
                error: Some(error),
                observation: observed,
            },
            Ok(()) => DeliveryOutcome::Uncertain {
                stage: current_stage,
                error: None,
                observation: observed,
            },
        };
        *lock(&lane.result) = Some(outcome);
        lane.state.store(
            key | if lost { RETAINED } else { COMPLETE },
            Ordering::Release,
        );
        if lost {
            // Ownership loss never grants capacity or permits another raw PID signal.
            loop {
                let reaped = {
                    let mut held = lock(&lane.child);
                    held.as_mut()
                        .is_some_and(|child| child.try_wait().is_ok_and(|status| status.is_some()))
                };
                if reaped {
                    *lock(&lane.child) = None;
                    lane.cleanup_outstanding.store(false, Ordering::Release);
                    if let Some(path) = destination_key.take() {
                        lock(&inner.destinations).remove(&path);
                    }
                    lane.state.store(key | COMPLETE, Ordering::Release);
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn run_writer(
    inner: &Inner,
    lane: &Lane,
    work: Work,
    destination_key: &mut Option<PathBuf>,
    observed: &mut DeliveryObservation,
) -> io::Result<()> {
    let write_deadline = work.deadline.saturating_sub(REAP_RESERVE_NANOS);
    let DeliveryRequest {
        diagnostics,
        report_path,
        report,
        return_deadline: _,
        #[cfg(feature = "test-support")]
        barrier,
        #[cfg(feature = "test-support")]
        delay_before_write,
        #[cfg(feature = "test-support")]
        observe_writer,
        #[cfg(feature = "test-support")]
        panic_after_spawn,
        #[cfg(feature = "test-support")]
        creation_gate,
        #[cfg(feature = "test-support")]
        creation_entered,
    } = work.request;
    stage(lane, DeliveryStage::PreparationDeadline);
    cancelled(inner, lane, write_deadline)?;
    if report_path.is_some() != report.is_some() {
        return Err(io::Error::other("report path/model presence differs"));
    }
    stage(lane, DeliveryStage::Destination);
    let path = report_path.as_deref().map(destination).transpose()?;
    if let Some(path) = &path {
        if !lock(&inner.destinations).insert(path.clone()) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "destination already owned by this runtime",
            ));
        }
        *destination_key = Some(path.clone());
    }
    let path_bytes = path
        .as_ref()
        .map(|path| path.as_os_str().as_bytes().to_vec());
    let fixed = frame::HEADER
        .checked_add(diagnostics.len())
        .and_then(|value| value.checked_add(path_bytes.as_ref().map_or(0, Vec::len)))
        .ok_or_else(|| io::Error::other("result payload length overflow"))?;
    #[cfg(feature = "test-support")]
    let fixed = fixed
        .checked_add(barrier.as_ref().map_or(0, |(_, bytes)| bytes.len()))
        .ok_or_else(|| io::Error::other("fixture payload length overflow"))?;
    let bound = inner
        .bytes_per_lane
        .checked_sub(fixed)
        .ok_or_else(|| io::Error::other("diagnostics/path exceed reserved payload budget"))?;
    stage(lane, DeliveryStage::ExecutableResolution);
    let executable = match &inner.image {
        WriterImage::CurrentProcess => std::env::current_exe()?,
        WriterImage::Installed(path) => path.clone(),
    };
    cancelled(inner, lane, write_deadline)?;
    stage(lane, DeliveryStage::WriterSpawn);
    let mut command = Command::new(executable);
    #[cfg(feature = "test-support")]
    if observe_writer {
        command
            .arg("__result-writer-observed-v2")
            .stdout(Stdio::piped());
    } else {
        command.arg("__result-writer-v2").stdout(Stdio::null());
    }
    #[cfg(not(feature = "test-support"))]
    command.arg("__result-writer-v2").stdout(Stdio::null());
    let child = command
        .stdin(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let writer_pid = child.id();
    *lock(&lane.child) = Some(child);
    lane.cleanup_outstanding.store(true, Ordering::Release);
    #[cfg(feature = "test-support")]
    if let Some(entered) = creation_entered {
        entered.store(true, Ordering::Release);
    }
    #[cfg(feature = "test-support")]
    if let Some(gate) = creation_gate {
        // Hold actual native ownership while publication is delayed. The
        // caller's timeout does not free the lane or create a fallback owner.
        while !gate.load(Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    lane.pid.store(writer_pid, Ordering::Release);
    #[cfg(feature = "test-support")]
    if panic_after_spawn {
        panic!("controlled result owner panic after actual child registration");
    }
    cancelled(inner, lane, write_deadline)?;
    stage(lane, DeliveryStage::Serialization);
    let report_bytes = report
        .map(|mut report| {
            report.prepare_writer(
                NonZeroU32::new(lane.pid.load(Ordering::Acquire))
                    .expect("actual native writer PID"),
            );
            let mut bytes = BoundedBytes {
                bytes: Vec::new(),
                bound,
                inner,
                lane,
                deadline: write_deadline,
            };
            report.write_bytes(&mut bytes).map_err(io::Error::other)?;
            Ok::<_, io::Error>(bytes.bytes)
        })
        .transpose()?;
    let frame = WriterFrame {
        diagnostics,
        report_path: path_bytes,
        report: report_bytes,
        #[cfg(feature = "test-support")]
        barrier,
        #[cfg(feature = "test-support")]
        delay_before_write,
    };
    let header = frame.header(inner.bytes_per_lane)?;
    cancelled(inner, lane, write_deadline)?;
    stage(lane, DeliveryStage::PipeConfiguration);
    let (mut input, mut trace) = {
        let mut child = lock(&lane.child);
        let child = child.as_mut().expect("registered writer owned by lane");
        (
            child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("writer stdin absent"))?,
            child.stdout.take(),
        )
    };
    nonblocking(input.as_raw_fd())?;
    if let Some(trace) = trace.as_ref() {
        nonblocking(trace.as_raw_fd())?;
    }
    let mut remaining = frame
        .pieces()
        .iter()
        .try_fold(header.len(), |total, piece| total.checked_add(piece.len()))
        .ok_or_else(|| io::Error::other("writer frame total overflow"))?;
    let mut committing = false;
    for mut piece in std::iter::once(header.as_slice()).chain(frame.pieces()) {
        while !piece.is_empty() {
            stage(lane, DeliveryStage::PipeDeadline);
            cancelled(inner, lane, write_deadline)?;
            let count_bound = if remaining == size_of::<u8>() {
                if !committing {
                    let value = lane.state.load(Ordering::Acquire);
                    lane.state
                        .compare_exchange(
                            with_state(value, ACTIVE),
                            with_state(value, COMMITTING),
                            Ordering::AcqRel,
                            Ordering::Acquire,
                        )
                        .map_err(|_| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "writer payload cancelled before complete frame",
                            )
                        })?;
                    committing = true;
                }
                size_of::<u8>()
            } else {
                piece.len().min(remaining - size_of::<u8>())
            };
            stage(lane, DeliveryStage::PipeWrite);
            match input.write(&piece[..count_bound]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "writer pipe closed",
                    ));
                }
                Ok(count) => {
                    piece = &piece[count..];
                    remaining -= count;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(error) => return Err(error),
            }
        }
    }
    lane.transferred.store(true, Ordering::Release);
    drop(input);
    loop {
        if let Some(trace) = trace.as_mut() {
            collect_trace(trace, observed);
        }
        stage(lane, DeliveryStage::WriterWait);
        let status = {
            let mut child = lock(&lane.child);
            child.as_mut().expect("registered writer").try_wait()?
        };
        if let Some(status) = status {
            observed.exit_code = status.code();
            *lock(&lane.child) = None;
            lane.cleanup_outstanding.store(false, Ordering::Release);
            if let Some(trace) = trace.as_mut() {
                collect_trace(trace, observed);
            }
            stage(lane, DeliveryStage::WriterExit);
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other("writer returned failure"))
            };
        }
        stage(lane, DeliveryStage::WriterDeadline);
        cancelled(inner, lane, write_deadline)?;
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn collect_trace(trace: &mut impl Read, observed: &mut DeliveryObservation) {
    let mut bytes = [0u8; 32];
    match trace.read(&mut bytes) {
        Ok(count) => {
            for byte in &bytes[..count] {
                if !(1..=8).contains(byte) {
                    observed.writer_phase_malformed = true;
                    continue;
                }
                if observed.writer_phase_count == observed.writer_phases.len() {
                    observed.writer_phase_truncated = true;
                    continue;
                }
                observed.writer_phases[observed.writer_phase_count] = *byte;
                observed.writer_phase_count += 1;
            }
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) => {}
        Err(error) => observed.writer_phase_error = error.raw_os_error(),
    }
}
