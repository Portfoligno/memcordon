use std::ffi::OsStr;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, Enforcement,
    Error, ErrorCategory, Interruption, LimitEvidence, Policy, RunOutcome,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Console::{
    CTRL_BREAK_EVENT, CTRL_C_EVENT, CTRL_CLOSE_EVENT, GenerateConsoleCtrlEvent,
    SetConsoleCtrlHandler,
};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_ASSOCIATE_COMPLETION_PORT,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION, JobObjectAssociateCompletionPortInformation,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    JobObjectNotificationLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::SystemServices::{
    JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO, JOB_OBJECT_MSG_JOB_MEMORY_LIMIT,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use crate::backend::{BackendInfo, Execution, ProbeReport};

const LIMIT_TERMINATION_STATUS: u32 = 0xC000_0017;
const INTERRUPT_TERMINATION_STATUS: u32 = 0xC000_013A;
const NO_CONSOLE_EVENT: u32 = u32::MAX;
static CONSOLE_EVENT: AtomicU32 = AtomicU32::new(NO_CONSOLE_EVENT);

unsafe extern "system" fn console_handler(event: u32) -> i32 {
    if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT) {
        CONSOLE_EVENT.store(event, Ordering::SeqCst);
        1
    } else {
        0
    }
}

struct ConsoleControl;

impl ConsoleControl {
    fn install() -> io::Result<Self> {
        CONSOLE_EVENT.store(NO_CONSOLE_EVENT, Ordering::SeqCst);
        // SAFETY: the handler has the required system ABI and remains valid for process lifetime.
        if unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self)
        }
    }

    fn take(&self) -> Option<u32> {
        let event = CONSOLE_EVENT.swap(NO_CONSOLE_EVENT, Ordering::SeqCst);
        (event != NO_CONSOLE_EVENT).then_some(event)
    }
}

impl Drop for ConsoleControl {
    fn drop(&mut self) {
        // SAFETY: removes the exact handler installed by `install`.
        unsafe {
            SetConsoleCtrlHandler(Some(console_handler), 0);
        }
    }
}

pub fn probe() -> ProbeReport {
    match Job::create() {
        Ok(job) => {
            drop(job);
            let backend = info();
            ProbeReport {
                selected: Some(backend.clone()),
                available: vec![backend],
                unavailable: Vec::new(),
            }
        }
        Err(error) => ProbeReport {
            selected: None,
            available: Vec::new(),
            unavailable: vec![crate::backend::UnavailableBackend {
                name: "windows-job-object",
                reason: format!("could not create Job Object: {error}"),
            }],
        },
    }
}

fn info() -> BackendInfo {
    BackendInfo {
        name: "windows-job-object",
        class: "hard",
        metric: "windows-job-commit",
        hard_limit: true,
        startup_containment: "target created suspended, assigned to Job Object, then resumed",
        limitations: vec![
            "metric is committed memory rather than resident physical memory",
            "nested host Job Object restrictions may prevent assignment",
            "console graceful termination is application-dependent",
        ],
    }
}

pub fn run(policy: Policy, command: &CommandSpec) -> Result<Execution, Error> {
    if policy.enforcement == Enforcement::Watchdog {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-WINDOWS-WATCHDOG",
            "the Windows sampled watchdog is not enabled; no target was launched",
        ));
    }
    let started = Instant::now();
    let console = ConsoleControl::install().map_err(setup_error)?;
    let job = Job::create().map_err(setup_error)?;
    job.configure(policy.memory.bytes()).map_err(setup_error)?;
    let mut process =
        SuspendedProcess::create(command).map_err(|error| spawn_error(error, command))?;
    if let Err(error) = job.assign(process.process) {
        process.terminate();
        return Err(setup_error(error));
    }
    process.resume().map_err(|error| {
        process.terminate();
        setup_error(error)
    })?;

    let child_pid = process.id;
    let mut peak = 0_u64;
    let outcome = loop {
        // SAFETY: the process handle remains owned by `process`.
        let wait = unsafe { WaitForSingleObject(process.process, 0) };
        if wait == WAIT_OBJECT_0 {
            let child = process
                .exit_status()
                .unwrap_or(ChildTermination::Unavailable);
            let mut cleanup = CleanupSummary {
                direct_child_reaped: true,
                ..CleanupSummary::default()
            };
            let active = job.active_processes().unwrap_or(0);
            if active > 0 {
                cleanup.force_attempted = true;
                if let Err(error) = job.terminate(INTERRUPT_TERMINATION_STATUS) {
                    cleanup
                        .errors
                        .push(cleanup_error("TerminateJobObject", error));
                }
                cleanup.workload_empty =
                    Some(job.wait_empty(Duration::from_secs(5)).unwrap_or(false));
            } else {
                cleanup.workload_empty = Some(true);
            }
            peak = peak.max(job.peak_commit().unwrap_or(0));
            break RunOutcome::Exited {
                child,
                peak: Some(ByteSize::from_bytes(peak)),
                cleanup,
            };
        }
        if wait != WAIT_TIMEOUT {
            let error = io::Error::last_os_error();
            let cleanup = job.force_cleanup(&process, INTERRUPT_TERMINATION_STATUS);
            break RunOutcome::MonitorFailed {
                error: format!("direct process wait failed: {error}"),
                child_after_termination: process.exit_status().ok(),
                cleanup,
            };
        }
        if let Some(event) = console.take() {
            // SAFETY: the target was created with CREATE_NEW_PROCESS_GROUP and `child_pid` is its
            // process-group identifier.
            unsafe {
                GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_pid);
            }
            if !policy.signal_grace.is_zero() {
                std::thread::sleep(policy.signal_grace);
            }
            let cleanup = job.force_cleanup(&process, INTERRUPT_TERMINATION_STATUS);
            break RunOutcome::Interrupted {
                signal: Interruption {
                    signal: if event == CTRL_CLOSE_EVENT { 15 } else { 2 },
                },
                child_after_termination: process.exit_status().ok(),
                cleanup,
            };
        }

        match job.wait_message(policy.poll_interval) {
            Ok(Some(message)) if message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT => {
                peak = peak.max(job.peak_commit().unwrap_or(0));
                let cleanup = job.force_cleanup(&process, LIMIT_TERMINATION_STATUS);
                break RunOutcome::LimitExceeded {
                    limit: policy.memory,
                    observed: None,
                    peak: Some(ByteSize::from_bytes(peak)),
                    evidence: LimitEvidence {
                        backend: "windows-job-object".to_owned(),
                        metric: "windows-job-commit".to_owned(),
                        detail: "Job Object emitted JOB_OBJECT_MSG_JOB_MEMORY_LIMIT".to_owned(),
                    },
                    child_after_termination: process.exit_status().ok(),
                    cleanup,
                };
            }
            Ok(_) => {
                peak = peak.max(job.peak_commit().unwrap_or(0));
            }
            Err(error) => {
                let cleanup = job.force_cleanup(&process, INTERRUPT_TERMINATION_STATUS);
                break RunOutcome::MonitorFailed {
                    error: format!("completion-port monitoring failed: {error}"),
                    child_after_termination: process.exit_status().ok(),
                    cleanup,
                };
            }
        }
    };

    Ok(Execution {
        outcome,
        backend: info(),
        child_pid,
        duration: started.elapsed(),
    })
}

struct Job {
    handle: HANDLE,
    completion_port: HANDLE,
}

impl Job {
    fn create() -> io::Result<Self> {
        // SAFETY: null attributes/name request an unnamed job with default security.
        let handle = unsafe { CreateJobObjectW(ptr::null(), ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: INVALID_HANDLE_VALUE requests a new completion port.
        let completion_port =
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) };
        if completion_port.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: handle is uniquely owned.
            unsafe { CloseHandle(handle) };
            return Err(error);
        }
        let association = JOB_OBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: handle,
            CompletionPort: completion_port,
        };
        // SAFETY: association points to a correctly sized initialized structure.
        let result = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                u32::try_from(size_of::<JOB_OBJECT_ASSOCIATE_COMPLETION_PORT>())
                    .unwrap_or(u32::MAX),
            )
        };
        if result == 0 {
            let error = io::Error::last_os_error();
            // SAFETY: both handles are uniquely owned.
            unsafe {
                CloseHandle(completion_port);
                CloseHandle(handle);
            }
            return Err(error);
        }
        Ok(Self {
            handle,
            completion_port,
        })
    }

    fn configure(&self, limit: u64) -> io::Result<()> {
        // SAFETY: a zeroed extended-limit structure is a valid starting state.
        let mut information =
            unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
        information.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        information.JobMemoryLimit = usize::try_from(limit).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "memory limit exceeds native SIZE_T",
            )
        })?;
        // SAFETY: information is initialized and the size matches its Job Object information class.
        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                (&raw const information).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(u32::MAX),
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: zeroed storage is a valid output buffer for GetSystemInfo.
        let mut system = unsafe { MaybeUninit::<SYSTEM_INFO>::zeroed().assume_init() };
        // SAFETY: `system` points to writable SYSTEM_INFO storage.
        unsafe { GetSystemInfo(&raw mut system) };
        let notification_limit = limit.saturating_sub(u64::from(system.dwPageSize)).max(1);
        let notification = JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION {
            JobMemoryLimit: notification_limit,
            LimitFlags: JOB_OBJECT_LIMIT_JOB_MEMORY,
            ..Default::default()
        };
        // SAFETY: notification is initialized and sized for its information class.
        let result = unsafe {
            SetInformationJobObject(
                self.handle,
                JobObjectNotificationLimitInformation,
                (&raw const notification).cast(),
                u32::try_from(size_of::<JOBOBJECT_NOTIFICATION_LIMIT_INFORMATION>())
                    .unwrap_or(u32::MAX),
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn assign(&self, process: HANDLE) -> io::Result<()> {
        // SAFETY: both handles are live and owned by this run.
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn wait_message(&self, timeout: Duration) -> io::Result<Option<u32>> {
        let mut message = 0_u32;
        let mut key = 0_usize;
        let mut overlapped = ptr::null_mut();
        let timeout_ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: all output pointers are valid for the duration of the call.
        let result = unsafe {
            GetQueuedCompletionStatus(
                self.completion_port,
                &mut message,
                &mut key,
                &mut overlapped,
                timeout_ms,
            )
        };
        if result != 0 {
            Ok(Some(message))
        } else {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(258) {
                Ok(None)
            } else {
                Err(error)
            }
        }
    }

    fn query(&self) -> io::Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION> {
        // SAFETY: zeroed storage is writable for the queried structure.
        let mut information =
            unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
        // SAFETY: output buffer and length match the requested information class.
        let result = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectExtendedLimitInformation,
                (&raw mut information).cast(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .unwrap_or(u32::MAX),
                ptr::null_mut(),
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(information)
        }
    }

    fn peak_commit(&self) -> io::Result<u64> {
        self.query()
            .map(|information| information.PeakJobMemoryUsed as u64)
    }

    fn active_processes(&self) -> io::Result<u32> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: the output buffer matches the accounting information class.
        let result = unsafe {
            QueryInformationJobObject(
                self.handle,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                u32::try_from(size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>())
                    .unwrap_or(u32::MAX),
                ptr::null_mut(),
            )
        };
        if result == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(accounting.ActiveProcesses)
        }
    }

    fn wait_empty(&self, timeout: Duration) -> io::Result<bool> {
        if self.active_processes()? == 0 {
            return Ok(true);
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(message) = self.wait_message(Duration::from_millis(10))? {
                if message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO {
                    return Ok(true);
                }
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }

    fn terminate(&self, status: u32) -> io::Result<()> {
        // SAFETY: job handle is live; the status is deliberately recorded for terminated members.
        if unsafe { TerminateJobObject(self.handle, status) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn force_cleanup(&self, process: &SuspendedProcess, status: u32) -> CleanupSummary {
        let mut summary = CleanupSummary {
            force_attempted: true,
            ..CleanupSummary::default()
        };
        if let Err(error) = self.terminate(status) {
            summary
                .errors
                .push(cleanup_error("TerminateJobObject", error));
        }
        // SAFETY: process handle remains live.
        let waited = unsafe { WaitForSingleObject(process.process, 5_000) } == WAIT_OBJECT_0;
        summary.direct_child_reaped = waited;
        summary.workload_empty = Some(self.wait_empty(Duration::from_secs(5)).unwrap_or(false));
        summary
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE makes this a final fail-closed cleanup path.
        // SAFETY: both handles are uniquely owned and closed exactly once.
        unsafe {
            CloseHandle(self.completion_port);
            CloseHandle(self.handle);
        }
    }
}

struct SuspendedProcess {
    process: HANDLE,
    thread: HANDLE,
    id: u32,
}

impl SuspendedProcess {
    fn create(command: &CommandSpec) -> io::Result<Self> {
        let mut command_line = encode_command_line(command);
        // SAFETY: zeroed startup/process structures are the documented initialization form.
        let mut startup = unsafe { MaybeUninit::<STARTUPINFOW>::zeroed().assume_init() };
        startup.cb = u32::try_from(size_of::<STARTUPINFOW>()).unwrap_or(u32::MAX);
        // SAFETY: zeroed process information is an output buffer.
        let mut process = unsafe { MaybeUninit::<PROCESS_INFORMATION>::zeroed().assume_init() };
        // SAFETY: command_line is mutable, NUL-terminated, and all optional pointers are null.
        let result = unsafe {
            CreateProcessW(
                ptr::null(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
                ptr::null(),
                ptr::null(),
                &raw const startup,
                &raw mut process,
            )
        };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            process: process.hProcess,
            thread: process.hThread,
            id: process.dwProcessId,
        })
    }

    fn resume(&mut self) -> io::Result<()> {
        // SAFETY: primary thread is live and suspended exactly once at this point.
        if unsafe { ResumeThread(self.thread) } == u32::MAX {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn terminate(&self) {
        // SAFETY: process handle is live; this is pre-resume failure cleanup.
        unsafe {
            TerminateProcess(self.process, INTERRUPT_TERMINATION_STATUS);
            WaitForSingleObject(self.process, 5_000);
        }
    }

    fn exit_status(&self) -> io::Result<ChildTermination> {
        let mut status = 0_u32;
        // SAFETY: status is writable and process handle remains live.
        if unsafe { GetExitCodeProcess(self.process, &mut status) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ChildTermination::WindowsStatus { status })
        }
    }
}

impl Drop for SuspendedProcess {
    fn drop(&mut self) {
        // SAFETY: handles are uniquely owned and closed exactly once.
        unsafe {
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}

fn encode_command_line(command: &CommandSpec) -> Vec<u16> {
    let mut encoded = quote_windows(command.program());
    for argument in command.arguments() {
        encoded.push(' ');
        encoded.push_str(&quote_windows(argument));
    }
    OsStr::new(&encoded)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quote_windows(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if !value.contains([' ', '\t', '"']) {
        return value.into_owned();
    }
    let mut output = String::from("\"");
    let mut backslashes = 0;
    for character in value.chars() {
        if character == '\\' {
            backslashes += 1;
        } else if character == '"' {
            output.push_str(&"\\".repeat(backslashes * 2 + 1));
            output.push('"');
            backslashes = 0;
        } else {
            output.push_str(&"\\".repeat(backslashes));
            backslashes = 0;
            output.push(character);
        }
    }
    output.push_str(&"\\".repeat(backslashes * 2));
    output.push('"');
    output
}

fn setup_error(error: io::Error) -> Error {
    Error::new(
        ErrorCategory::Setup,
        "MCSETUP-WINDOWS-JOB",
        error.to_string(),
    )
    .with_os_error(&error)
}

fn spawn_error(error: io::Error, command: &CommandSpec) -> Error {
    Error::new(
        ErrorCategory::Spawn,
        if error.kind() == io::ErrorKind::NotFound {
            "MCSPAWN-NOT-FOUND"
        } else if error.kind() == io::ErrorKind::PermissionDenied {
            "MCSPAWN-NOT-EXECUTABLE"
        } else {
            "MCSPAWN-FAILED"
        },
        format!(
            "could not create suspended command {}: {error}",
            command.program().to_string_lossy()
        ),
    )
    .with_os_error(&error)
}

fn cleanup_error(operation: &str, error: io::Error) -> CleanupErrorRecord {
    CleanupErrorRecord {
        operation: operation.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use super::quote_windows;

    #[test]
    fn windows_quoting_preserves_spaces_and_quotes() {
        assert_eq!(quote_windows(OsStr::new("plain")), "plain");
        assert_eq!(quote_windows(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote_windows(OsStr::new("a\"b")), "\"a\\\"b\"");
    }
}
