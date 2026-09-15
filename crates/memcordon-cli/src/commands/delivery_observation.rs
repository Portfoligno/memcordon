//! Test-only datagram observation has no report, exit, or cleanup authority.
//! A full or absent receiver never delays delivery and never changes its result.
use std::io;

use serde::Serialize;

#[derive(Serialize)]
pub(super) struct Delivery {
    schema: u32,
    kind: &'static str,
    pub stage: &'static str,
    pub reason: &'static str,
    pub delivered: bool,
    pub started: Option<u64>,
    pub write_deadline: Option<u64>,
    pub native_return_deadline: Option<u64>,
    pub return_deadline: Option<u64>,
    pub finished: Option<u64>,
    pub payload_bytes: Option<usize>,
    pub transferred_bytes: usize,
    pub writer_pid: Option<u32>,
    pub writer_code: Option<i32>,
    pub writer_signal: Option<i32>,
    pub error_kind: Option<String>,
    pub os_error: Option<i32>,
    pub retirement: &'static str,
    pub retirement_os_error: Option<i32>,
}

impl Delivery {
    pub fn new(return_deadline: Option<u64>) -> Self {
        Self {
            schema: 1,
            kind: "delivery",
            stage: "clock",
            reason: "operation-error",
            delivered: false,
            started: None,
            write_deadline: None,
            native_return_deadline: return_deadline,
            return_deadline,
            finished: None,
            payload_bytes: None,
            transferred_bytes: 0,
            writer_pid: None,
            writer_code: None,
            writer_signal: None,
            error_kind: None,
            os_error: None,
            retirement: "no-writer-received",
            retirement_os_error: None,
        }
    }

    pub fn error(&mut self, error: &io::Error) {
        // ErrorKind is a finite standard-library enum; arbitrary error strings
        // and paths are deliberately excluded from the bounded observation.
        self.error_kind = Some(format!("{:?}", error.kind()));
        self.os_error = error.raw_os_error();
    }

    pub fn status(&mut self, status: std::process::ExitStatus) {
        use std::os::unix::process::ExitStatusExt as _;
        self.writer_code = status.code();
        self.writer_signal = status.signal();
        self.retirement = "reaped";
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        #[cfg(feature = "test-fixtures")]
        {
            self.finished = memcordon_platform::macos_continuous_nanos().ok();
            emit(self);
        }
    }
}

#[cfg(feature = "test-fixtures")]
static OBSERVER: std::sync::OnceLock<std::os::unix::net::UnixDatagram> = std::sync::OnceLock::new();

/// Strip only the fixture envelope; the remaining argv uses normal CLI routing.
#[cfg(feature = "test-fixtures")]
pub(crate) fn initialize(argv: Vec<std::ffi::OsString>) -> io::Result<Vec<std::ffi::OsString>> {
    if argv
        .first()
        .is_none_or(|value| value != "__observe-delivery-v1")
    {
        return Ok(argv);
    }
    let [_, socket, separator, rest @ ..] = argv.as_slice() else {
        return Err(io::Error::other("invalid delivery observation envelope"));
    };
    if separator != "--" || rest.is_empty() {
        return Err(io::Error::other("invalid delivery observation arguments"));
    }
    let observer = std::os::unix::net::UnixDatagram::unbound()?;
    observer.set_nonblocking(true)?;
    observer.connect(std::path::Path::new(socket))?;
    OBSERVER
        .set(observer)
        .map_err(|_| io::Error::other("delivery observer already initialized"))?;
    Ok(rest.to_vec())
}

#[cfg(feature = "test-fixtures")]
fn emit(value: &impl Serialize) {
    let Some(observer) = OBSERVER.get() else {
        return;
    };
    // Fixed capacity, one nonblocking send, no retries or secondary sink.
    let mut bytes = [0_u8; 2048];
    let mut writer = io::Cursor::new(bytes.as_mut_slice());
    if serde_json::to_writer(&mut writer, value).is_ok() {
        let length = usize::try_from(writer.position()).expect("bounded cursor position");
        let _ = observer.send(&bytes[..length]);
    }
}

#[cfg(feature = "test-fixtures")]
pub(super) fn execution(execution: &memcordon_core::SupervisionExecution) {
    use memcordon_core::{RunOutcome, SupervisionTerminal};

    #[derive(Serialize)]
    struct Execution {
        schema: u32,
        kind: &'static str,
        outcome: &'static str,
        wrapper_exit_code: i32,
        graceful_attempted: Option<bool>,
        force_attempted: Option<bool>,
        direct_child_reaped: Option<bool>,
        workload_empty: Option<bool>,
        cleanup_errors: Option<usize>,
    }
    let (outcome, cleanup) = match execution.terminal() {
        SupervisionTerminal::AttemptOutcome { outcome, .. } => (
            match outcome {
                RunOutcome::Exited { .. } => "exited",
                RunOutcome::LimitExceeded { .. } => "limit-exceeded",
                RunOutcome::DeadlineExceeded { .. } => "deadline-exceeded",
                RunOutcome::Interrupted { .. } => "interrupted",
                RunOutcome::MonitorFailed { .. } => "monitor-failed",
            },
            Some(outcome.cleanup()),
        ),
        SupervisionTerminal::DeadlineOutsideAttempt { .. } => ("deadline-outside-attempt", None),
        SupervisionTerminal::Error { .. } => ("supervision-error", None),
    };
    emit(&Execution {
        schema: 1,
        kind: "execution",
        outcome,
        wrapper_exit_code: execution.wrapper_exit_code(),
        graceful_attempted: cleanup.map(|value| value.graceful_attempted),
        force_attempted: cleanup.map(|value| value.force_attempted),
        direct_child_reaped: cleanup.map(|value| value.direct_child_reaped),
        workload_empty: cleanup.and_then(|value| value.workload_empty),
        cleanup_errors: cleanup.map(|value| value.errors.len()),
    });
}
