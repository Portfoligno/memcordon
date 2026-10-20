#![forbid(unsafe_code)]

pub mod harness_budget;

#[cfg(target_os = "linux")]
pub use memcordon_platform::test_support::{
    NativeExecObservation, configure_native_exec_observation,
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use memcordon_platform::test_support::unsearchable_directory;

#[cfg(target_os = "macos")]
pub use memcordon_platform::test_support::macos_read_only_descriptor_path;
#[cfg(windows)]
pub use memcordon_platform::test_support::{
    ProcessIdentity, WindowsHeldFileIdentity, WindowsImageProcess, windows_available_memory_bytes,
    windows_console_host_path, windows_held_file_identity, windows_native_work_cutoff,
    windows_performance_counter, windows_processes_for_image, windows_processes_for_image_until,
};

use std::fmt;
use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, TryRecvError};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use memcordon_platform::test_support::OuterTestBoundary;

#[derive(Debug)]
pub struct ObservedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub elapsed: Duration,
}

#[derive(Debug)]
pub struct TimeoutObservation {
    /// Post-cleanup child, callback and reader settlement; the other fields
    /// intentionally retain the observations made before termination.
    pub settlement_complete: bool,
    pub child_id: u32,
    /// Status observed before timeout cleanup; never the forced termination status.
    pub observed_status: Option<ExitStatus>,
    pub callback_completed: bool,
    pub spawn_returned: Duration,
    pub boundary_admitted: Duration,
    pub timeout_observed: Duration,
    pub stdout_reader_finished: bool,
    pub stderr_reader_finished: bool,
}

#[derive(Clone, Copy, Debug)]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug)]
pub struct ProgressChunk {
    pub stream: OutputStream,
    pub bytes: Vec<u8>,
}

/// Observational only: a slow logger never blocks an output reader or retirement.
#[derive(Clone)]
pub struct ProgressOutput {
    pub sender: mpsc::SyncSender<ProgressChunk>,
    pub omitted: Arc<AtomicU64>,
}

#[derive(Default)]
struct ProcessControl {
    cancelled: Option<Arc<AtomicBool>>,
    progress: Option<ProgressOutput>,
    failure: Option<Arc<dyn Fn(NativeFailureNotice) + Send + Sync>>,
    external_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeFailureCause {
    ObservedFailureStatus,
    DeadlineReached,
    OutputBoundReached,
    InputOrAssertionFailure,
    OwnerSpawnFailure,
    OwnershipUncertain,
}

#[derive(Clone, Copy, Debug)]
pub struct NativeFailureNotice {
    pub cause: NativeFailureCause,
    pub status: Option<ExitStatus>,
}

#[derive(Debug)]
pub struct CancellationObservation {
    pub child_id: u32,
    pub observed_status: Option<ExitStatus>,
    pub cancellation_observed: Duration,
    pub external_interruption: bool,
    pub callback_completed: bool,
    pub stdout_reader_finished: bool,
    pub stderr_reader_finished: bool,
}

#[derive(Debug)]
pub enum ProcessTestError {
    Spawn(io::Error),
    Wait(io::Error),
    Callback {
        error: io::Error,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        capture_complete: bool,
        observed_status: Option<ExitStatus>,
        termination: Option<ExitStatus>,
        cleanup: Result<(), String>,
    },
    Output(io::Error),
    OutputLimit {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        cleanup: Result<(), String>,
        termination: Option<ExitStatus>,
    },
    Timeout {
        deadline: Duration,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        cleanup: Result<(), String>,
        observation: Box<TimeoutObservation>,
    },
    Cancelled {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        cleanup: Result<(), String>,
        termination: Option<ExitStatus>,
        observation: Box<CancellationObservation>,
    },
}

impl fmt::Display for ProcessTestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Spawn(error) => write!(formatter, "test command failed to spawn: {error}"),
            Self::Wait(error) => write!(formatter, "test command wait failed: {error}"),
            Self::Callback {
                error,
                observed_status,
                termination,
                cleanup,
                ..
            } => write!(
                formatter,
                "test command callback failed: {error}; observed-status={observed_status:?}; termination={termination:?}; cleanup={cleanup:?}"
            ),
            Self::Output(error) => write!(formatter, "test output reader failed: {error}"),
            Self::Cancelled {
                cleanup,
                termination,
                observation,
                ..
            } => write!(
                formatter,
                "test command cancelled by peer; cleanup={cleanup:?}; termination={termination:?}; observation={observation:?}"
            ),
            Self::OutputLimit {
                stdout,
                stderr,
                cleanup,
                termination,
            } => write!(
                formatter,
                "subprocess output exceeds byte limit; cleanup={cleanup:?}; termination={termination:?}; stdout-bytes={}; stderr-bytes={}",
                stdout.len(),
                stderr.len()
            ),
            Self::Timeout {
                deadline,
                stdout,
                stderr,
                cleanup,
                observation,
            } => write!(
                formatter,
                "test command exceeded {deadline:?}; cleanup={cleanup:?}; observation={observation:?}; stdout={:?}; stderr={:?}",
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr)
            ),
        }
    }
}

impl std::error::Error for ProcessTestError {}

struct OutputReader {
    bytes: Arc<Mutex<Vec<u8>>>,
    worker: thread::JoinHandle<io::Result<()>>,
    output_limited: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct OutputSnapshot {
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
}
impl OutputSnapshot {
    pub fn stdout(&self) -> io::Result<Vec<u8>> {
        self.stdout
            .lock()
            .map(|bytes| bytes.clone())
            .map_err(|_| io::Error::other("stdout snapshot lock poisoned"))
    }
    pub fn stderr(&self) -> io::Result<Vec<u8>> {
        self.stderr
            .lock()
            .map(|bytes| bytes.clone())
            .map_err(|_| io::Error::other("stderr snapshot lock poisoned"))
    }
}

impl OutputReader {
    fn snapshot(&self) -> Vec<u8> {
        self.bytes
            .lock()
            .expect("output reader buffer poisoned")
            .clone()
    }

    fn join(self) -> thread::Result<io::Result<Vec<u8>>> {
        self.worker.join().map(|result| {
            result.map(|()| {
                std::mem::take(&mut *self.bytes.lock().expect("output reader buffer poisoned"))
            })
        })
    }
}

fn reader(
    mut stream: impl Read + Send + 'static,
    limit: Option<usize>,
    progress: Option<ProgressOutput>,
    output_stream: OutputStream,
) -> OutputReader {
    let bytes = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&bytes);
    let output_limited = Arc::new(AtomicBool::new(false));
    let worker_limited = Arc::clone(&output_limited);
    let worker = thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        loop {
            let length = match stream.read(&mut chunk) {
                Ok(0) => return Ok(()),
                Ok(length) => length,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            };
            let mut captured = captured.lock().expect("output reader buffer poisoned");
            if limit.is_some_and(|limit| captured.len().saturating_add(length) > limit) {
                if let Some(limit) = limit {
                    let remaining = limit.saturating_sub(captured.len());
                    captured.extend_from_slice(&chunk[..remaining]);
                }
                worker_limited.store(true, Ordering::Release);
                return Err(io::Error::other("subprocess output exceeds byte limit"));
            }
            captured.extend_from_slice(&chunk[..length]);
            drop(captured);
            if let Some(progress) = &progress {
                if progress
                    .sender
                    .try_send(ProgressChunk {
                        stream: output_stream,
                        bytes: chunk[..length].to_vec(),
                    })
                    .is_err()
                {
                    progress.omitted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    });
    OutputReader {
        bytes,
        worker,
        output_limited,
    }
}

pub fn run_with_deadline(
    command: &mut Command,
    deadline: Duration,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_after(command, deadline, |_| Ok(()))
}

pub fn run_with_deadline_after(
    command: &mut Command,
    deadline: Duration,
    after_spawn: impl FnOnce(u32) -> io::Result<()> + Send + 'static,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_after_limit(command, deadline, after_spawn, None)
}

/// Limit each captured stream as well as the process lifetime.
pub fn run_with_deadline_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_after_limit(command, deadline, |_| Ok(()), Some(limit))
}

/// Bound output while recording an identity sampled immediately after spawn.
pub fn run_with_deadline_after_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
    after_spawn: impl FnOnce(u32) -> io::Result<()> + Send + 'static,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_after_limit(command, deadline, after_spawn, Some(limit))
}

fn run_with_deadline_after_limit(
    command: &mut Command,
    deadline: Duration,
    after_spawn: impl FnOnce(u32) -> io::Result<()> + Send + 'static,
    output_limit: Option<usize>,
) -> Result<ObservedOutput, ProcessTestError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    OuterTestBoundary::configure(command).map_err(ProcessTestError::Spawn)?;
    let started = Instant::now();
    let child = command.spawn().map_err(ProcessTestError::Spawn)?;
    let spawn_returned = started.elapsed();
    observe_deadline_child(
        child,
        started,
        spawn_returned,
        deadline,
        move |pid, _, _| after_spawn(pid),
        output_limit,
        ProcessControl::default(),
    )
}

/// Ordinary disposable subprocesses may settle early after a peer fails.
/// Native operations with persistent host state must use between-command stopping instead.
pub fn run_with_deadline_controlled_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
    progress: Option<ProgressOutput>,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_notified_output_limit(command, deadline, limit, cancelled, progress, None)
}

/// Notify the coordinator at an observed failure, before native retirement or readers settle.
/// The callback must be nonblocking and must not perform report I/O.
pub fn run_with_deadline_notified_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
    progress: Option<ProgressOutput>,
    failure: Option<Arc<dyn Fn() + Send + Sync>>,
) -> Result<ObservedOutput, ProcessTestError> {
    let failure = failure.map(|notify| {
        Arc::new(move |_| notify()) as Arc<dyn Fn(NativeFailureNotice) + Send + Sync>
    });
    run_with_deadline_failure_notice_output_limit(
        command, deadline, limit, cancelled, progress, failure,
    )
}

pub fn run_with_deadline_failure_notice_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
    progress: Option<ProgressOutput>,
    failure: Option<Arc<dyn Fn(NativeFailureNotice) + Send + Sync>>,
) -> Result<ObservedOutput, ProcessTestError> {
    run_with_deadline_external_stop_output_limit(
        command, deadline, limit, cancelled, progress, failure, None,
    )
}

/// Observe external interruption separately from a peer workload failure.
pub fn run_with_deadline_external_stop_output_limit(
    command: &mut Command,
    deadline: Duration,
    limit: usize,
    cancelled: Option<Arc<AtomicBool>>,
    progress: Option<ProgressOutput>,
    failure: Option<Arc<dyn Fn(NativeFailureNotice) + Send + Sync>>,
    external_stop: Option<Arc<dyn Fn() -> bool + Send + Sync>>,
) -> Result<ObservedOutput, ProcessTestError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let notify = || {
        if let Some(notify) = &failure {
            notify(NativeFailureNotice {
                cause: NativeFailureCause::OwnerSpawnFailure,
                status: None,
            });
        }
    };
    OuterTestBoundary::configure(command).map_err(|error| {
        notify();
        ProcessTestError::Spawn(error)
    })?;
    let started = Instant::now();
    let child = command.spawn().map_err(|error| {
        notify();
        ProcessTestError::Spawn(error)
    })?;
    let returned = started.elapsed();
    observe_deadline_child(
        child,
        started,
        returned,
        deadline,
        |_, _, _| Ok(()),
        Some(limit),
        ProcessControl {
            cancelled,
            progress,
            failure,
            external_stop,
        },
    )
}

/// Own the command and its native descriptor setup through exactly one spawn.
/// The spawning adapter must return a child with the configured piped streams.
pub fn run_with_deadline_owned_spawn_after_output_limit(
    mut command: Command,
    deadline: Duration,
    limit: usize,
    spawn: impl FnOnce(Command) -> io::Result<std::process::Child>,
    after_spawn: impl FnOnce(u32) -> io::Result<()> + Send + 'static,
) -> Result<ObservedOutput, ProcessTestError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    OuterTestBoundary::configure(&mut command).map_err(ProcessTestError::Spawn)?;
    let started = Instant::now();
    let child = spawn(command).map_err(ProcessTestError::Spawn)?;
    let spawn_returned = started.elapsed();
    observe_deadline_child(
        child,
        started,
        spawn_returned,
        deadline,
        move |pid, _, _| after_spawn(pid),
        Some(limit),
        ProcessControl::default(),
    )
}

/// Snapshot access is observational only. Streams remain bounded and owned
/// by joined readers; callback stdin is the exact sole configured child pipe.
pub fn run_with_deadline_owned_spawn_with_io_output_limit(
    mut command: Command,
    deadline: Duration,
    limit: usize,
    spawn: impl FnOnce(Command) -> io::Result<std::process::Child>,
    after_spawn: impl FnOnce(u32, Option<std::process::ChildStdin>, OutputSnapshot) -> io::Result<()>
    + Send
    + 'static,
) -> Result<ObservedOutput, ProcessTestError> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    OuterTestBoundary::configure(&mut command).map_err(ProcessTestError::Spawn)?;
    let started = Instant::now();
    let child = spawn(command).map_err(ProcessTestError::Spawn)?;
    let returned = started.elapsed();
    observe_deadline_child(
        child,
        started,
        returned,
        deadline,
        after_spawn,
        Some(limit),
        ProcessControl::default(),
    )
}

fn observe_deadline_child(
    mut child: std::process::Child,
    started: Instant,
    spawn_returned: Duration,
    deadline: Duration,
    after_spawn: impl FnOnce(u32, Option<std::process::ChildStdin>, OutputSnapshot) -> io::Result<()>
    + Send
    + 'static,
    output_limit: Option<usize>,
    control: ProcessControl,
) -> Result<ObservedOutput, ProcessTestError> {
    let ProcessControl {
        cancelled,
        progress,
        failure,
        external_stop,
    } = control;
    let notified = std::cell::Cell::new(false);
    let notify = |cause, status| {
        if !notified.replace(true) {
            if let Some(notify) = &failure {
                // An observational hook cannot unwind through the exact child owner.
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    notify(NativeFailureNotice { cause, status })
                }));
            }
        }
    };
    let boundary = match OuterTestBoundary::after_spawn(&child) {
        Ok(boundary) => boundary,
        Err(error) => {
            notify(NativeFailureCause::OwnershipUncertain, None);
            let kill = child.kill();
            let wait = child.wait();
            // No outer boundary was admitted, so descendant settlement is unknown
            // even if the direct child was successfully reaped.
            return Err(ProcessTestError::Wait(io::Error::other(format!(
                "native boundary admission failed: {error}; direct kill={kill:?}; direct wait={wait:?}"
            ))));
        }
    };
    let boundary_admitted = started.elapsed();
    let stdout_reader = reader(
        child.stdout.take().expect("stdout was configured as piped"),
        output_limit,
        progress.clone(),
        OutputStream::Stdout,
    );
    let stderr_reader = reader(
        child.stderr.take().expect("stderr was configured as piped"),
        output_limit,
        progress,
        OutputStream::Stderr,
    );
    let (callback_sender, callback_receiver) = mpsc::sync_channel(1);
    let child_id = child.id();
    let child_stdin = child.stdin.take();
    let snapshot = OutputSnapshot {
        stdout: Arc::clone(&stdout_reader.bytes),
        stderr: Arc::clone(&stderr_reader.bytes),
    };
    let callback = thread::spawn(move || {
        let _ = callback_sender.send(after_spawn(child_id, child_stdin, snapshot));
    });
    let mut callback_result = None;
    let mut observed_status = None;

    let status = loop {
        if stdout_reader.output_limited.load(Ordering::Acquire)
            || stderr_reader.output_limited.load(Ordering::Acquire)
        {
            notify(NativeFailureCause::OutputBoundReached, observed_status);
            // Preserve the first cap violation and settle the owned boundary before
            // any report formatting. A full pipe must not consume the whole guard.
            let cleanup = boundary
                .terminate_and_reap(&mut child)
                .map_err(|error| error.to_string());
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let wait = child.wait().map_err(|error| error.to_string());
            let stdout = stdout_reader.snapshot();
            let stderr = stderr_reader.snapshot();
            let mut reader_cleanup = Ok(());
            if cleanup.is_ok() {
                let out_limited = stdout_reader.output_limited.load(Ordering::Acquire);
                let err_limited = stderr_reader.output_limited.load(Ordering::Acquire);
                let out = stdout_reader.join();
                let err = stderr_reader.join();
                let settled = |result: thread::Result<io::Result<Vec<u8>>>, limited| {
                    matches!(result, Ok(Ok(_))) || (limited && matches!(result, Ok(Err(_))))
                };
                if !settled(out, out_limited) || !settled(err, err_limited) {
                    reader_cleanup =
                        Err("output-limit readers did not settle successfully".to_owned());
                }
            }
            let callback_cleanup = callback_result.take().map_or_else(
                || {
                    callback_receiver
                        .recv_timeout(deadline.saturating_sub(started.elapsed()))
                        .map_err(|error| format!("after-spawn callback did not settle: {error}"))
                },
                Ok,
            );
            let callback_cleanup = match callback_cleanup {
                Ok(result) => {
                    let joined = callback
                        .join()
                        .map_err(|_| "after-spawn callback panicked".to_owned());
                    result.map_err(|error| error.to_string()).and(joined)
                }
                Err(error) => Err(error),
            };
            return Err(ProcessTestError::OutputLimit {
                stdout,
                stderr,
                termination: wait.as_ref().ok().copied(),
                cleanup: cleanup
                    .and(wait.map(|_| ()))
                    .and(reader_cleanup)
                    .and(callback_cleanup),
            });
        }
        if callback_result.is_none() {
            match callback_receiver.try_recv() {
                Ok(result) => callback_result = Some(result),
                Err(TryRecvError::Empty) => {}
                Err(TryRecvError::Disconnected) => {
                    callback_result = Some(Err(io::Error::other("after-spawn callback panicked")));
                }
            }
        }
        if callback_result.as_ref().is_some_and(Result::is_err) {
            notify(NativeFailureCause::InputOrAssertionFailure, observed_status);
            let error = callback_result
                .take()
                .expect("callback result was present")
                .expect_err("callback result was checked as an error");
            let cleanup = boundary.terminate_and_reap(&mut child);
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let wait = child.wait();
            let mut stdout = stdout_reader.snapshot();
            let mut stderr = stderr_reader.snapshot();
            let mut capture_complete = false;
            if cleanup.is_ok() {
                let out = stdout_reader.join();
                let err = stderr_reader.join();
                if let (Ok(Ok(out)), Ok(Ok(err))) = (out, err) {
                    stdout = out;
                    stderr = err;
                    capture_complete = true;
                }
            }
            let _ = callback.join();
            return Err(ProcessTestError::Callback {
                error,
                stdout,
                stderr,
                capture_complete,
                observed_status,
                termination: wait.as_ref().ok().copied(),
                cleanup: cleanup
                    .map_err(|error| error.to_string())
                    .and(wait.map(|_| ()).map_err(|error| error.to_string())),
            });
        }
        if observed_status.is_none() {
            match child.try_wait() {
                Ok(status) => {
                    observed_status = status;
                    if status.is_some_and(|status| !status.success()) {
                        notify(NativeFailureCause::ObservedFailureStatus, status);
                    }
                }
                Err(error) => {
                    notify(NativeFailureCause::OwnershipUncertain, observed_status);
                    let cleanup = boundary.terminate_and_reap(&mut child);
                    if cleanup.is_err() {
                        let _ = child.kill();
                    }
                    let _ = child.wait();
                    if cleanup.is_ok() {
                        let _ = stdout_reader.join();
                        let _ = stderr_reader.join();
                    }
                    return Err(ProcessTestError::Wait(error));
                }
            }
        }
        if let (Some(status), Some(Ok(()))) = (observed_status, callback_result.as_ref()) {
            let _ = callback.join();
            break status;
        }
        if started.elapsed() < deadline
            && observed_status.is_none_or(|status| status.success())
            && (external_stop.as_ref().is_some_and(|stop| stop())
                || cancelled
                    .as_ref()
                    .is_some_and(|flag| flag.load(Ordering::Acquire)))
        {
            let mut observation = CancellationObservation {
                child_id,
                observed_status,
                cancellation_observed: started.elapsed(),
                external_interruption: external_stop.as_ref().is_some_and(|stop| stop()),
                callback_completed: callback_result.is_some(),
                stdout_reader_finished: false,
                stderr_reader_finished: false,
            };
            let cleanup = boundary
                .terminate_and_reap(&mut child)
                .map_err(|error| error.to_string());
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let wait = child.wait().map_err(|error| error.to_string());
            let mut stdout = stdout_reader.snapshot();
            let mut stderr = stderr_reader.snapshot();
            let mut reader_cleanup = Ok(());
            if cleanup.is_ok() {
                match stdout_reader.join() {
                    Ok(Ok(bytes)) => {
                        stdout = bytes;
                        observation.stdout_reader_finished = true;
                    }
                    _ => reader_cleanup = Err("stdout reader did not settle successfully".into()),
                }
                match stderr_reader.join() {
                    Ok(Ok(bytes)) => {
                        stderr = bytes;
                        observation.stderr_reader_finished = true;
                    }
                    _ => reader_cleanup = Err("stderr reader did not settle successfully".into()),
                }
            }
            // This entrypoint admits only the trivial callback. Retain ownership anyway.
            let callback_cleanup = callback
                .join()
                .map_err(|_| "after-spawn callback panicked".to_string());
            observation.callback_completed = callback_cleanup.is_ok();
            return Err(ProcessTestError::Cancelled {
                stdout,
                stderr,
                termination: wait.as_ref().ok().copied(),
                cleanup: cleanup
                    .and(wait.map(|_| ()))
                    .and(reader_cleanup)
                    .and(callback_cleanup),
                observation: Box::new(observation),
            });
        }
        if started.elapsed() >= deadline {
            notify(NativeFailureCause::DeadlineReached, observed_status);
            // Snapshot existing observations before cleanup changes process state. No extra
            // process queries or output reads may delay retirement for diagnostic collection.
            let mut observation = TimeoutObservation {
                settlement_complete: false,
                child_id,
                observed_status,
                callback_completed: callback_result.is_some(),
                spawn_returned,
                boundary_admitted,
                timeout_observed: started.elapsed(),
                stdout_reader_finished: stdout_reader.worker.is_finished(),
                stderr_reader_finished: stderr_reader.worker.is_finished(),
            };
            let cleanup = boundary
                .terminate_and_reap(&mut child)
                .map_err(|error| error.to_string());
            if cleanup.is_err() {
                let _ = child.kill();
            }
            let wait_result = observed_status.map_or_else(|| child.wait(), Ok);
            if let Err(error) = cleanup {
                return Err(ProcessTestError::Timeout {
                    deadline,
                    stdout: stdout_reader.snapshot(),
                    stderr: stderr_reader.snapshot(),
                    cleanup: Err(error),
                    observation: Box::new(observation),
                });
            }
            let stdout_snapshot = stdout_reader.snapshot();
            let stderr_snapshot = stderr_reader.snapshot();
            // Timeout was the first observation. Reader failures are cleanup
            // observations, and both reader owners must still be joined.
            let out = stdout_reader.join();
            let err = stderr_reader.join();
            let mut cleanup = wait_result.map(|_| ()).map_err(|error| error.to_string());
            let stdout = match out {
                Ok(Ok(bytes)) => bytes,
                failure => {
                    cleanup =
                        cleanup.and(Err(format!("timeout stdout reader failed: {failure:?}")));
                    stdout_snapshot
                }
            };
            let stderr = match err {
                Ok(Ok(bytes)) => bytes,
                failure => {
                    cleanup =
                        cleanup.and(Err(format!("timeout stderr reader failed: {failure:?}")));
                    stderr_snapshot
                }
            };
            // A callback that has not returned remains unresolved. Do not wait
            // beyond the original deadline just to produce a cache observation.
            let callback_settled = callback_result.is_some() && callback.join().is_ok();
            observation.settlement_complete = cleanup.is_ok() && callback_settled;
            return Err(ProcessTestError::Timeout {
                deadline,
                stdout,
                stderr,
                cleanup,
                observation: Box::new(observation),
            });
        }
        thread::sleep(Duration::from_millis(5));
    };

    // A direct child may have exited while a descendant still owns inherited pipes. Empty the
    // independent outer boundary before joining readers so that such a defect cannot hang tests.
    if let Err(error) = boundary.terminate() {
        return Err(ProcessTestError::Wait(error));
    }
    let stdout = stdout_reader
        .join()
        .map_err(|_| ProcessTestError::Output(io::Error::other("stdout reader panicked")))?
        .map_err(ProcessTestError::Output)?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ProcessTestError::Output(io::Error::other("stderr reader panicked")))?
        .map_err(ProcessTestError::Output)?;
    Ok(ObservedOutput {
        status,
        stdout,
        stderr,
        elapsed: started.elapsed(),
    })
}

pub fn assert_stdout_empty(output: &ObservedOutput) {
    assert!(
        output.stdout.is_empty(),
        "wrapper wrote unexpected stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
#[cfg(windows)]
pub use memcordon_platform::test_support::windows_trace_volume;
#[cfg(windows)]
pub use memcordon_platform::test_support::{windows_file_identity, windows_reparse_data};

#[cfg(test)]
#[path = "../tests/support/early_failure.rs"]
mod early_failure;
