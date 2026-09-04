use std::ffi::OsStr;
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicIsize, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use memcordon_core::{
    ByteSize, ChildTermination, CleanupErrorRecord, CleanupSummary, CommandSpec, DeadlineEvidence,
    Enforcement, Error, ErrorCategory, InitialSpawnFailure, Interruption, LimitEvidence, Policy,
    RunOutcome,
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
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_JOB_MEMORY,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
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
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CreateEventW, CreateProcessW, GetExitCodeProcess,
    PROCESS_INFORMATION, ResumeThread, STARTUPINFOW, SetEvent, TerminateProcess,
    WaitForSingleObject,
};

use crate::backend::{BackendCleanupFacts, BackendInfo, Execution, ProbeReport};

const LIMIT_TERMINATION_STATUS: u32 = 0xC000_0017;
const INTERRUPT_TERMINATION_STATUS: u32 = 0xC000_013A;
const NO_CONSOLE_EVENT: u32 = u32::MAX;

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn bounded_wait(
    context: crate::supervisor::AttemptContext,
    started: Instant,
    duration: Duration,
) -> Duration {
    context
        .supervision_deadline(started)
        .map_or(duration, |deadline| {
            duration.min(deadline.saturating_duration_since(Instant::now()))
        })
}
static CONSOLE_EVENT: AtomicU32 = AtomicU32::new(NO_CONSOLE_EVENT);
static CONSOLE_WAKE: AtomicIsize = AtomicIsize::new(0);

unsafe extern "system" fn console_handler(event: u32) -> i32 {
    if matches!(event, CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT) {
        CONSOLE_EVENT.store(event, Ordering::SeqCst);
        let wake = CONSOLE_WAKE.load(Ordering::SeqCst) as HANDLE;
        if !wake.is_null() {
            // SAFETY: the invocation-scoped ConsoleControl keeps this event live.
            unsafe { SetEvent(wake) };
        }
        1
    } else {
        0
    }
}

pub(crate) struct ConsoleControl {
    wake: HANDLE,
}

impl ConsoleControl {
    pub(crate) fn install() -> io::Result<Self> {
        CONSOLE_EVENT.store(NO_CONSOLE_EVENT, Ordering::SeqCst);
        // SAFETY: null security and name pointers create a private auto-reset event.
        let wake = unsafe { CreateEventW(ptr::null(), 0, 0, ptr::null()) };
        if wake.is_null() {
            return Err(io::Error::last_os_error());
        }
        CONSOLE_WAKE.store(wake as isize, Ordering::SeqCst);
        // SAFETY: the handler has the required system ABI and remains valid for process lifetime.
        if unsafe { SetConsoleCtrlHandler(Some(console_handler), 1) } == 0 {
            let error = io::Error::last_os_error();
            CONSOLE_WAKE.store(0, Ordering::SeqCst);
            // SAFETY: wake was created above and is uniquely owned here.
            unsafe { CloseHandle(wake) };
            Err(error)
        } else {
            Ok(Self { wake })
        }
    }

    fn take(&self) -> Option<u32> {
        let event = CONSOLE_EVENT.swap(NO_CONSOLE_EVENT, Ordering::SeqCst);
        (event != NO_CONSOLE_EVENT).then_some(event)
    }

    pub(crate) fn wait(&self, duration: Duration) -> io::Result<Option<i32>> {
        let timeout = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: wake is a live event owned by this ConsoleControl.
        let result = unsafe { WaitForSingleObject(self.wake, timeout) };
        if result != WAIT_OBJECT_0 && result != WAIT_TIMEOUT {
            return Err(io::Error::last_os_error());
        }
        Ok(self
            .take()
            .map(|event| if event == CTRL_CLOSE_EVENT { 15 } else { 2 }))
    }
}

impl Drop for ConsoleControl {
    fn drop(&mut self) {
        // SAFETY: removes the exact handler installed by `install`.
        unsafe {
            SetConsoleCtrlHandler(Some(console_handler), 0);
            CONSOLE_WAKE.store(0, Ordering::SeqCst);
            CloseHandle(self.wake);
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

pub(crate) fn info() -> BackendInfo {
    match crate::sealed::windows::probe() {
        Ok(qualification) => info_from_qualification(qualification),
        Err(reason) => info_with_sealed(crate::backend::SealedAvailability::Unavailable {
            reason: format!("Windows sealed provider is not installed or qualified: {reason}"),
            prerequisites: vec![
                "matching memcordon-sealed-agent.exe package installation".to_owned(),
                "qualified MemCordonSealedControl and MemCordonSealedLauncher services".to_owned(),
                "native creation-time Job-list and exact handle-list certification".to_owned(),
            ],
        }),
    }
}

pub(crate) fn info_from_qualification(
    qualification: memcordon_core::WindowsQualificationReceiptV1,
) -> BackendInfo {
    info_with_sealed(crate::sealed::windows::availability(qualification))
}

pub(crate) fn info_with_sealed(sealed: crate::backend::SealedAvailability) -> BackendInfo {
    BackendInfo {
        name: "windows-job-object",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "windows-job-commit",
        hard_limit: true,
        startup_containment: "target created suspended, assigned to Job Object, then resumed",
        limitations: vec![
            "metric is committed memory rather than resident physical memory",
            "nested host Job Object restrictions may prevent assignment",
            "console graceful termination is application-dependent",
        ],
        boundary_support: crate::backend::BoundarySupport {
            standard: crate::backend::standard_boundary_support(
                "suspended-job-assignment-v1",
                true,
                "the LocalSystem sealed-agent service is unavailable or not qualified",
                &[
                    "MemCordonSealedAgent LocalSystem service",
                    "creation-time Job-list and exact handle-list support",
                ],
            )
            .standard,
            sealed,
        },
    }
}

#[allow(
    clippy::result_large_err,
    reason = "execution propagates the categorized Error unchanged through the public boundary"
)]
pub fn run_attempt(
    policy: Policy,
    command: &CommandSpec,
    console: &ConsoleControl,
    context: crate::supervisor::AttemptContext,
) -> Result<Execution, Error> {
    if policy.enforcement == Enforcement::Watchdog {
        return Err(Error::new(
            ErrorCategory::Unsupported,
            "MCUNSUPPORTED-WINDOWS-WATCHDOG",
            "the Windows sampled watchdog is not enabled; no target was launched",
        ));
    }
    let started = Instant::now();
    let job = Job::create().map_err(setup_error)?;
    job.configure(policy.memory.map(|memory| memory.bytes()))
        .map_err(setup_error)?;
    let mut process =
        SuspendedProcess::create(command).map_err(|error| spawn_error(error, command))?;
    let authorized = assign_then_resume(&job, &mut process).map_err(setup_error)?;

    let child_pid = process.id;
    let mut peak = 0_u64;
    let mut command_exit_grace_started = None;
    let outcome = loop {
        let mut memory_due = false;
        let mut drain_error = None;
        loop {
            match job.wait_message(Duration::ZERO) {
                Ok(Some(JOB_OBJECT_MSG_JOB_MEMORY_LIMIT)) => memory_due = true,
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(error) => {
                    drain_error = Some(error);
                    break;
                }
            }
        }
        if memory_due {
            if let Some(limit) = policy.memory {
                peak = peak.max(job.peak_commit().unwrap_or(0));
                let grace_started = Instant::now();
                if !policy.limit_grace.is_zero() {
                    // SAFETY: the target was created as a new process group led by child_pid.
                    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_pid) };
                    let _ = console.wait(bounded_wait(context, started, policy.limit_grace));
                }
                let cleanup = job.force_cleanup(
                    &process,
                    LIMIT_TERMINATION_STATUS,
                    context.clamp_deadline(started, Duration::from_secs(5)),
                );
                break RunOutcome::LimitExceeded {
                    limit,
                    observed: None,
                    peak: Some(ByteSize::from_bytes(peak)),
                    evidence: LimitEvidence {
                        backend: "windows-job-object".to_owned(),
                        metric: "windows-job-commit".to_owned(),
                        detail: format!(
                            "Job Object memory notification drained before completion; limit grace elapsed {}ms",
                            millis(grace_started.elapsed())
                        ),
                    },
                    child_after_termination: process.exit_status().ok(),
                    cleanup,
                };
            }
        }
        if let Some(error) = drain_error {
            let cleanup = job.force_cleanup(
                &process,
                INTERRUPT_TERMINATION_STATUS,
                context.clamp_deadline(started, Duration::from_secs(5)),
            );
            break RunOutcome::MonitorFailed {
                error: format!("completion-port drain failed: {error}"),
                child_after_termination: process.exit_status().ok(),
                cleanup,
            };
        }
        // SAFETY: the process handle remains owned by `process`.
        let wait = unsafe { WaitForSingleObject(process.process, 0) };
        if wait == WAIT_OBJECT_0 {
            if let Some(deadline) = policy.deadline {
                let active_duration = context
                    .supervision_deadline_remaining
                    .unwrap_or_else(|| deadline.duration());
                if authorized.elapsed() >= active_duration {
                    let observed = authorized.elapsed();
                    let cleanup = job.force_cleanup(
                        &process,
                        INTERRUPT_TERMINATION_STATUS,
                        context.clamp_deadline(started, Duration::from_secs(5)),
                    );
                    break RunOutcome::DeadlineExceeded {
                        deadline: DeadlineEvidence::new(
                            millis(deadline.duration()),
                            deadline.scope(),
                            "suspended-thread-resume".to_owned(),
                            millis(context.supervision_offset + active_duration),
                            millis(context.supervision_offset + observed),
                            millis(policy.limit_grace),
                            0,
                            None,
                            Some("terminate-job-object".to_owned()),
                        )
                        .map_err(|_| {
                            Error::new(
                                ErrorCategory::Monitor,
                                "MCLIMIT-DEADLINE-EVIDENCE",
                                "deadline evidence is inconsistent",
                            )
                        })?,
                        child_after_termination: process.exit_status().ok(),
                        peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                        cleanup,
                    };
                }
            }
            let child = process
                .exit_status()
                .unwrap_or(ChildTermination::Unavailable);
            let active = match job.active_processes() {
                Ok(active) => active,
                Err(error) => {
                    let mut cleanup = job.force_cleanup(
                        &process,
                        INTERRUPT_TERMINATION_STATUS,
                        context.clamp_deadline(started, Duration::from_secs(5)),
                    );
                    cleanup
                        .errors
                        .push(cleanup_error("QueryInformationJobObject", error));
                    break RunOutcome::Exited {
                        child,
                        peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                        cleanup,
                    };
                }
            };
            if active == 0 {
                peak = peak.max(job.peak_commit().unwrap_or(0));
                break RunOutcome::Exited {
                    child,
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup: CleanupSummary {
                        direct_child_reaped: true,
                        workload_empty: Some(true),
                        ..CleanupSummary::default()
                    },
                };
            }
            let grace_expired = if policy.command_exit_grace.is_zero() {
                true
            } else {
                let grace_started = command_exit_grace_started.get_or_insert_with(Instant::now);
                grace_started.elapsed() >= policy.command_exit_grace
            };
            if grace_expired {
                let cleanup = job.force_cleanup(
                    &process,
                    INTERRUPT_TERMINATION_STATUS,
                    context.clamp_deadline(started, Duration::from_secs(5)),
                );
                peak = peak.max(job.peak_commit().unwrap_or(0));
                break RunOutcome::Exited {
                    child,
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup,
                };
            }
        }
        if wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT {
            let error = io::Error::last_os_error();
            let cleanup = job.force_cleanup(
                &process,
                INTERRUPT_TERMINATION_STATUS,
                context.clamp_deadline(started, Duration::from_secs(5)),
            );
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
                let _ = console.wait(bounded_wait(context, started, policy.signal_grace));
            }
            let cleanup = job.force_cleanup(
                &process,
                INTERRUPT_TERMINATION_STATUS,
                context.clamp_deadline(started, Duration::from_secs(5)),
            );
            break RunOutcome::Interrupted {
                signal: Interruption {
                    signal: if event == CTRL_CLOSE_EVENT { 15 } else { 2 },
                },
                child_after_termination: process.exit_status().ok(),
                cleanup,
            };
        }

        let wait = command_exit_grace_started.map_or(policy.poll_interval, |grace_started| {
            policy.poll_interval.min(
                policy
                    .command_exit_grace
                    .saturating_sub(grace_started.elapsed()),
            )
        });
        match job.wait_message(bounded_wait(context, started, wait)) {
            Ok(Some(message)) if message == JOB_OBJECT_MSG_JOB_MEMORY_LIMIT => {
                let Some(limit) = policy.memory else {
                    continue;
                };
                peak = peak.max(job.peak_commit().unwrap_or(0));
                let grace_started = Instant::now();
                if !policy.limit_grace.is_zero() {
                    // SAFETY: the target was created as a new process group led by child_pid.
                    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_pid) };
                    let _ = console.wait(bounded_wait(context, started, policy.limit_grace));
                }
                let cleanup = job.force_cleanup(
                    &process,
                    LIMIT_TERMINATION_STATUS,
                    context.clamp_deadline(started, Duration::from_secs(5)),
                );
                break RunOutcome::LimitExceeded {
                    limit,
                    observed: None,
                    peak: Some(ByteSize::from_bytes(peak)),
                    evidence: LimitEvidence {
                        backend: "windows-job-object".to_owned(),
                        metric: "windows-job-commit".to_owned(),
                        detail: format!(
                            "Job Object emitted JOB_OBJECT_MSG_JOB_MEMORY_LIMIT; limit grace elapsed {}ms",
                            millis(grace_started.elapsed())
                        ),
                    },
                    child_after_termination: process.exit_status().ok(),
                    cleanup,
                };
            }
            Ok(_) => {
                peak = peak.max(job.peak_commit().unwrap_or(0));
            }
            Err(error) => {
                let cleanup = job.force_cleanup(
                    &process,
                    INTERRUPT_TERMINATION_STATUS,
                    context.clamp_deadline(started, Duration::from_secs(5)),
                );
                break RunOutcome::MonitorFailed {
                    error: format!("completion-port monitoring failed: {error}"),
                    child_after_termination: process.exit_status().ok(),
                    cleanup,
                };
            }
        }
        if let Some(deadline) = policy.deadline {
            let active_duration = context
                .supervision_deadline_remaining
                .unwrap_or_else(|| deadline.duration());
            if authorized.elapsed() >= active_duration {
                let observed = authorized.elapsed();
                let grace_started = Instant::now();
                if !policy.limit_grace.is_zero() {
                    // SAFETY: the target was created as a new process group led by child_pid.
                    unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_pid) };
                    let _ = console.wait(bounded_wait(context, started, policy.limit_grace));
                }
                let cleanup = job.force_cleanup(
                    &process,
                    INTERRUPT_TERMINATION_STATUS,
                    context.clamp_deadline(started, Duration::from_secs(5)),
                );
                break RunOutcome::DeadlineExceeded {
                    deadline: DeadlineEvidence::new(
                        millis(deadline.duration()),
                        deadline.scope(),
                        "suspended-thread-resume".to_owned(),
                        millis(context.supervision_offset + active_duration),
                        millis(context.supervision_offset + observed),
                        millis(policy.limit_grace),
                        millis(grace_started.elapsed().min(policy.limit_grace)),
                        (!policy.limit_grace.is_zero())
                            .then(|| "ctrl-break-process-group".to_owned()),
                        Some("terminate-job-object".to_owned()),
                    )
                    .map_err(|_| {
                        Error::new(
                            ErrorCategory::Monitor,
                            "MCLIMIT-DEADLINE-EVIDENCE",
                            "deadline evidence is inconsistent",
                        )
                    })?,
                    child_after_termination: process.exit_status().ok(),
                    peak: policy.memory.map(|_| ByteSize::from_bytes(peak)),
                    cleanup,
                };
            }
        }
    };

    let cleanup = outcome.cleanup();
    let cleanup_facts = BackendCleanupFacts {
        direct_child_reaped: cleanup.direct_child_reaped,
        workload_empty: cleanup.workload_empty,
        helpers_reaped: true,
        containment_removed: false,
        containment_incapable_of_live_members: cleanup.workload_empty == Some(true),
        errors: cleanup
            .errors
            .iter()
            .map(|error| format!("{}: {}", error.operation, error.message))
            .collect(),
    };
    let backend = info();
    let (launch, restart_safety, boundary_detail) =
        crate::backend::standard_execution_evidence(&backend, cleanup_facts);
    Ok(Execution {
        outcome,
        backend,
        child_pid,
        duration: started.elapsed(),
        authorization_offset: Some(authorized.saturating_duration_since(started)),
        launch,
        restart_safety,
        boundary_detail,
    })
}

fn assign_then_resume(job: &Job, process: &mut SuspendedProcess) -> io::Result<Instant> {
    if let Err(error) = job.assign(process.process) {
        process.terminate();
        return Err(error);
    }
    let authorized = Instant::now();
    if let Err(error) = process.resume() {
        process.terminate();
        Err(error)
    } else {
        Ok(authorized)
    }
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
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: handle,
            CompletionPort: completion_port,
        };
        // SAFETY: association points to a correctly sized initialized structure.
        let result = unsafe {
            SetInformationJobObject(
                handle,
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                u32::try_from(size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>()).unwrap_or(u32::MAX),
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

    fn configure(&self, limit: Option<u64>) -> io::Result<()> {
        // SAFETY: a zeroed extended-limit structure is a valid starting state.
        let mut information =
            unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if let Some(limit) = limit {
            information.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            information.JobMemoryLimit = usize::try_from(limit).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "memory limit exceeds native SIZE_T",
                )
            })?;
        }
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
        let Some(limit) = limit else {
            return Ok(());
        };
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

    fn wait_empty(&self, deadline: Instant) -> io::Result<bool> {
        if self.active_processes()? == 0 {
            return Ok(true);
        }
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            if let Some(message) = self.wait_message(Duration::from_millis(10).min(remaining))? {
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

    fn force_cleanup(
        &self,
        process: &SuspendedProcess,
        status: u32,
        deadline: Instant,
    ) -> CleanupSummary {
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
        let timeout = u32::try_from(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis(),
        )
        .unwrap_or(u32::MAX - 1);
        let waited = unsafe { WaitForSingleObject(process.process, timeout) } == WAIT_OBJECT_0;
        summary.direct_child_reaped = waited;
        summary.workload_empty = Some(self.wait_empty(deadline).unwrap_or(false));
        summary
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE makes this a final fail-closed cleanup path.
        // SAFETY: both handles are uniquely owned and closed exactly once.
        unsafe {
            CloseHandle(self.completion_port);
            if !self.handle.is_null() {
                CloseHandle(self.handle);
            }
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
    // CreateProcessW exposes only the native mutable command-line buffer. Serialize wide argv
    // directly so unpaired UTF-16 units remain lossless and no shell interprets the result.
    let mut encoded = Vec::new();
    append_windows_argument(&mut encoded, command.program());
    for argument in command.arguments() {
        encoded.push(u16::from(b' '));
        append_windows_argument(&mut encoded, argument);
    }
    encoded.push(0);
    encoded
}

fn append_windows_argument(output: &mut Vec<u16>, value: &OsStr) {
    let units: Vec<u16> = value.encode_wide().collect();
    let quote = units.is_empty()
        || units.iter().any(|unit| {
            *unit == u16::from(b' ') || *unit == u16::from(b'\t') || *unit == u16::from(b'"')
        });
    if !quote {
        output.extend(units);
        return;
    }
    output.push(u16::from(b'"'));
    let mut backslashes = 0;
    for unit in units {
        if unit == u16::from(b'\\') {
            backslashes += 1;
        } else if unit == u16::from(b'"') {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2 + 1));
            output.push(u16::from(b'"'));
            backslashes = 0;
        } else {
            output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes));
            backslashes = 0;
            output.push(unit);
        }
    }
    output.extend(std::iter::repeat_n(u16::from(b'\\'), backslashes * 2));
    output.push(u16::from(b'"'));
}

#[cfg(feature = "test-support")]
pub(crate) fn test_encode_command_line(command: &CommandSpec) -> Vec<u16> {
    encode_command_line(command)
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
    let failure = if error.kind() == io::ErrorKind::NotFound {
        Some(InitialSpawnFailure::NotFound)
    } else if error.kind() == io::ErrorKind::PermissionDenied {
        Some(InitialSpawnFailure::NotExecutable)
    } else {
        None
    };
    let mut result = Error::new(
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
    .with_os_error(&error);
    result.launch_phase = Some("target-spawn-failed");
    failure.map_or(result.clone(), |failure| {
        result.with_initial_spawn_failure(failure)
    })
}

fn cleanup_error(operation: &str, error: io::Error) -> CleanupErrorRecord {
    CleanupErrorRecord {
        operation: operation.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(feature = "test-support")]
pub(crate) fn test_target_remains_suspended_until_assignment() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let command = CommandSpec::new("ping.exe").args(["-n", "1", "127.0.0.1"]);
    let mut process = SuspendedProcess::create(&command)?;
    // SAFETY: process handle is live and queried without mutation.
    let suspended = unsafe { WaitForSingleObject(process.process, 0) } == WAIT_TIMEOUT;
    let job = Job::create()?;
    job.configure(Some(256 * 1024 * 1024))?;
    job.assign(process.process)?;
    let assigned = job.active_processes()? == 1;
    process.resume()?;
    // SAFETY: process handle remains live until process is dropped.
    let exited = unsafe { WaitForSingleObject(process.process, 5_000) } == WAIT_OBJECT_0;
    Ok(suspended && assigned && exited)
}

#[cfg(feature = "test-support")]
pub(crate) fn test_kill_on_job_close() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let command = CommandSpec::new("ping.exe").args(["-n", "30", "127.0.0.1"]);
    let mut process = SuspendedProcess::create(&command)?;
    let job = Job::create()?;
    job.configure(Some(256 * 1024 * 1024))?;
    job.assign(process.process)?;
    process.resume()?;
    let active = job.active_processes()? > 0;
    drop(job);
    // SAFETY: process handle remains live until process is dropped.
    let exited = unsafe { WaitForSingleObject(process.process, 5_000) } == WAIT_OBJECT_0;
    Ok(active && exited)
}

#[cfg(feature = "test-support")]
pub(crate) fn test_nested_assignment() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let command = CommandSpec::new("ping.exe").args(["-n", "1", "127.0.0.1"]);
    let mut process = SuspendedProcess::create(&command)?;
    let outer = Job::create()?;
    outer.configure(Some(512 * 1024 * 1024))?;
    outer.assign(process.process)?;
    let memcordon = Job::create()?;
    memcordon.configure(Some(256 * 1024 * 1024))?;
    memcordon.assign(process.process)?;
    let assigned = memcordon.active_processes()? == 1;
    let limits = memcordon.query()?;
    let configured = limits.JobMemoryLimit == 256 * 1024 * 1024
        && limits.BasicLimitInformation.LimitFlags
            & (JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
            == JOB_OBJECT_LIMIT_JOB_MEMORY | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    process.resume()?;
    // SAFETY: process handle remains live until process is dropped.
    let exited = unsafe { WaitForSingleObject(process.process, 5_000) } == WAIT_OBJECT_0;
    Ok(assigned && configured && exited)
}

#[cfg(feature = "test-support")]
pub(crate) fn test_assignment_failure() -> io::Result<bool> {
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let command = CommandSpec::new("ping.exe").args(["-n", "30", "127.0.0.1"]);
    let mut process = SuspendedProcess::create(&command)?;
    let mut invalid_job = Job::create()?;
    // SAFETY: invalidating the uniquely owned handle exercises the assignment failure path.
    unsafe { CloseHandle(invalid_job.handle) };
    invalid_job.handle = std::ptr::null_mut();
    let failed = assign_then_resume(&invalid_job, &mut process).is_err();
    // SAFETY: assignment failure synchronously terminates and waits for the suspended target.
    let terminated = unsafe { WaitForSingleObject(process.process, 0) } == WAIT_OBJECT_0;
    Ok(failed && terminated)
}
