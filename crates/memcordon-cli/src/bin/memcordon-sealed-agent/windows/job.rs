use std::io;
use std::mem::{MaybeUninit, size_of};
use std::ptr;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK, JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectAssociateCompletionPortInformation, JobObjectBasicAccountingInformation,
    JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
    TerminateJobObject,
};

use super::pipe::OwnedHandle;
use memcordon_core::{WindowsSealedFault, WindowsSealedMutant};

// The windows-sys release used by this workspace does not expose the Job
// completion message constants. These are the stable values from WinNT.h.
const JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
const JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT: u32 = 9;
const JOB_OBJECT_MSG_JOB_MEMORY_LIMIT: u32 = 10;
const JOB_OBJECT_BASIC_PROCESS_ID_LIST: i32 = 3;

pub struct Job {
    handle: OwnedHandle,
    completion_port: OwnedHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JobNotification {
    ActiveProcessesZero,
    MemoryLimit,
    Other(u32),
}

enum JobObjectSecurity {
    LauncherService,
    NestedCanaryCreator,
    SessionHolder,
}

impl Job {
    pub fn process_is_in_any_job(process: HANDLE) -> Result<bool, String> {
        let mut inside = 0_i32;
        // SAFETY: process is live; a null Job asks whether it belongs to any Job.
        if unsafe { IsProcessInJob(process, ptr::null_mut(), &raw mut inside) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(inside != 0)
        }
    }

    pub fn create(
        memory_limit: Option<u64>,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
    ) -> Result<Self, String> {
        Self::create_with_security(
            memory_limit,
            certification_fault,
            certification_mutant,
            JobObjectSecurity::LauncherService,
        )
    }

    pub fn create_nested_canary(memory_limit: Option<u64>) -> Result<Self, String> {
        Self::create_with_security(
            memory_limit,
            None,
            None,
            JobObjectSecurity::NestedCanaryCreator,
        )
    }

    pub fn create_session_holder() -> Result<Self, String> {
        let job = Self::create_with_security(None, None, None, JobObjectSecurity::SessionHolder)?;
        job.configure_session_holder()?;
        job.verify_session_holder_configuration()?;
        if job.active_processes()? != 0 || job.total_processes()? != 0 {
            return Err("session-holder Job was not empty at creation".to_owned());
        }
        Ok(job)
    }

    fn create_with_security(
        memory_limit: Option<u64>,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
        object_security: JobObjectSecurity,
    ) -> Result<Self, String> {
        reject_fault(certification_fault, WindowsSealedFault::JobCreate)?;
        let sddl = match object_security {
            JobObjectSecurity::LauncherService => super::security::launcher_job_sddl()?,
            JobObjectSecurity::NestedCanaryCreator => super::security::nested_canary_job_sddl()?,
            JobObjectSecurity::SessionHolder => super::security::session_holder_job_sddl()?,
        };
        let security = super::security::SecurityDescriptor::from_sddl(&sddl)?;
        let attributes = security.attributes(false);
        // SAFETY: attributes holds the exact role-appropriate descriptor and
        // remains live for the call. The unnamed Job handle is transferred
        // into OwnedHandle.
        let handle =
            OwnedHandle::new(unsafe { CreateJobObjectW(&raw const attributes, ptr::null()) })?;
        security.verify_kernel_object(handle.raw(), super::security::SecurityObjectKind::Job)?;
        // SAFETY: INVALID_HANDLE_VALUE requests a new completion port; the
        // returned handle is independently owned.
        let completion_port = OwnedHandle::new(unsafe {
            CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1)
        })?;
        let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: handle.raw(),
            CompletionPort: completion_port.raw(),
        };
        reject_fault(certification_fault, WindowsSealedFault::CompletionPort)?;
        // SAFETY: structure and size match the requested Job information class.
        if unsafe {
            SetInformationJobObject(
                handle.raw(),
                JobObjectAssociateCompletionPortInformation,
                (&raw const association).cast(),
                size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        let job = Self {
            handle,
            completion_port,
        };
        job.configure(memory_limit, certification_fault, certification_mutant)?;
        if certification_mutant == Some(WindowsSealedMutant::PermitBreakaway) {
            if !job.breakaway_allowed()? {
                return Err("breakaway mutant did not change the Job limit readback".to_owned());
            }
        } else {
            job.verify_configuration(memory_limit)?;
        }
        Ok(job)
    }

    pub const fn handle(&self) -> HANDLE {
        self.handle.raw()
    }

    fn configure(
        &self,
        memory_limit: Option<u64>,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
    ) -> Result<(), String> {
        // SAFETY: all-zero is a valid initial value for this POD structure.
        let mut limits =
            unsafe { MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed().assume_init() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if certification_mutant == Some(WindowsSealedMutant::PermitBreakaway) {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_BREAKAWAY_OK;
        }
        if let Some(bytes) = memory_limit {
            limits.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            limits.JobMemoryLimit = usize::try_from(bytes)
                .map_err(|_| "Job memory limit exceeds native SIZE_T".to_owned())?;
        }
        reject_fault(certification_fault, WindowsSealedFault::JobConfigure)?;
        // SAFETY: structure and size match the requested Job information class.
        if unsafe {
            SetInformationJobObject(
                self.handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    fn query_limits(&self) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, String> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: output structure and size match the requested Job information class.
        if unsafe {
            QueryInformationJobObject(
                self.handle(),
                JobObjectExtendedLimitInformation,
                (&raw mut limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(limits)
        }
    }

    fn configure_session_holder(&self) -> Result<(), String> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        limits.BasicLimitInformation.ActiveProcessLimit = 1;
        // SAFETY: structure and size match the requested Job information class.
        if unsafe {
            SetInformationJobObject(
                self.handle(),
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub fn verify_session_holder_configuration(&self) -> Result<(), String> {
        Self::verify_session_holder_handle(self.handle())
    }

    pub fn verify_session_holder_handle(handle: HANDLE) -> Result<(), String> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: handle is a live Job query capability and output is writable.
        if unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw mut limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        let expected = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if limits.BasicLimitInformation.LimitFlags != expected
            || limits.BasicLimitInformation.ActiveProcessLimit != 1
        {
            return Err("session-holder Job policy differs from the exact one-process crash-containment contract".to_owned());
        }
        Ok(())
    }

    pub fn verify_session_holder_empty_handle(handle: HANDLE) -> Result<(), String> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: handle is a live Job query capability and output is writable.
        if unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if accounting.ActiveProcesses != 0 || accounting.TotalProcesses != 0 {
            return Err("session-holder Job is not empty at broker adoption".to_owned());
        }
        Ok(())
    }

    pub fn breakaway_allowed(&self) -> Result<bool, String> {
        let flags = self.query_limits()?.BasicLimitInformation.LimitFlags;
        Ok(flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0)
    }

    fn verify_configuration(&self, memory_limit: Option<u64>) -> Result<(), String> {
        let limits = self.query_limits()?;
        let flags = limits.BasicLimitInformation.LimitFlags;
        if flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0
            || flags & (JOB_OBJECT_LIMIT_BREAKAWAY_OK | JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK) != 0
        {
            return Err(
                "Job limit readback did not prove kill-on-close and breakaway denial".to_owned(),
            );
        }
        if let Some(expected) = memory_limit {
            if flags & JOB_OBJECT_LIMIT_JOB_MEMORY == 0 || limits.JobMemoryLimit as u64 != expected
            {
                return Err("Job memory-limit readback differs from the request".to_owned());
            }
        }
        Ok(())
    }

    pub fn contains(&self, process: HANDLE) -> Result<bool, String> {
        let mut inside = 0;
        // SAFETY: both handles are live and output storage is initialized.
        if unsafe { IsProcessInJob(process, self.handle(), &raw mut inside) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(inside != 0)
        }
    }

    pub fn active_processes(&self) -> Result<u32, String> {
        Ok(self.accounting()?.ActiveProcesses)
    }

    pub fn total_processes(&self) -> Result<u32, String> {
        Ok(self.accounting()?.TotalProcesses)
    }

    pub fn process_ids(&self) -> Result<Vec<u32>, String> {
        let mut capacity = usize::try_from(self.active_processes()?)
            .map_err(|error| error.to_string())?
            .saturating_add(16);
        loop {
            // One pointer-sized word holds the two u32 header fields on every
            // supported 64-bit Windows target; following words are ULONG_PTR
            // process IDs. Vec<usize> provides the native pointer alignment
            // required by QueryInformationJobObject.
            let mut storage = vec![0_usize; capacity.saturating_add(1)];
            let byte_len = storage
                .len()
                .checked_mul(size_of::<usize>())
                .and_then(|value| u32::try_from(value).ok())
                .ok_or_else(|| "Job process-list buffer exceeds the native limit".to_owned())?;
            let mut returned = 0_u32;
            // SAFETY: storage is native-aligned and byte_len describes its
            // complete writable allocation for JobObjectBasicProcessIdList.
            let success = unsafe {
                QueryInformationJobObject(
                    self.handle(),
                    JOB_OBJECT_BASIC_PROCESS_ID_LIST,
                    storage.as_mut_ptr().cast(),
                    byte_len,
                    &raw mut returned,
                )
            };
            // SAFETY: the fixed two-u32 header fits in the first usize word on
            // x86_64 and ARM64, the only supported Windows provider targets.
            let header = storage.as_ptr().cast::<u32>();
            let assigned = unsafe { *header } as usize;
            let listed = unsafe { *header.add(1) } as usize;
            if success == 0 && assigned > capacity {
                capacity = assigned.saturating_add(16);
                continue;
            }
            if success == 0 {
                return Err(io::Error::last_os_error().to_string());
            }
            if listed > capacity || listed > assigned {
                return Err("Job process-list readback is inconsistent".to_owned());
            }
            return storage[1..1 + listed]
                .iter()
                .map(|value| {
                    u32::try_from(*value)
                        .map_err(|_| "Job process id exceeds the Windows PID width".to_owned())
                })
                .collect();
        }
    }

    fn accounting(&self) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, String> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: output structure and size match the requested accounting class.
        if unsafe {
            QueryInformationJobObject(
                self.handle(),
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                ptr::null_mut(),
            )
        } == 0
        {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(accounting)
        }
    }

    pub fn peak_memory(&self) -> Result<u64, String> {
        Ok(self.query_limits()?.PeakJobMemoryUsed as u64)
    }

    pub fn terminate(&self, status: u32) -> Result<(), String> {
        // SAFETY: the Job handle remains live and the status is an intentional
        // terminal NT status for every active member.
        if unsafe { TerminateJobObject(self.handle(), status) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(())
        }
    }

    pub fn take_notification(&self) -> Result<Option<JobNotification>, String> {
        let mut message = 0_u32;
        let mut key = 0_usize;
        let mut overlapped = ptr::null_mut();
        // SAFETY: all output pointers are valid and the zero timeout makes this
        // a nonblocking completion-port poll.
        if unsafe {
            GetQueuedCompletionStatus(
                self.completion_port.raw(),
                &raw mut message,
                &raw mut key,
                &raw mut overlapped,
                0,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok())
                == Some(WAIT_TIMEOUT)
            {
                Ok(None)
            } else {
                Err(error.to_string())
            };
        }
        if key != self.handle() as usize {
            return Err("Job completion packet has an unexpected completion key".to_owned());
        }
        Ok(Some(match message {
            JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO => JobNotification::ActiveProcessesZero,
            JOB_OBJECT_MSG_JOB_MEMORY_LIMIT | JOB_OBJECT_MSG_PROCESS_MEMORY_LIMIT => {
                JobNotification::MemoryLimit
            }
            other => JobNotification::Other(other),
        }))
    }

    pub fn wait_empty(&self, deadline: Instant) -> Result<bool, String> {
        while Instant::now() < deadline {
            if self.active_processes()? == 0 {
                return Ok(true);
            }
            let mut message = 0_u32;
            let mut key = 0_usize;
            let mut overlapped = ptr::null_mut();
            // SAFETY: all output pointers are valid and completion port remains live.
            unsafe {
                GetQueuedCompletionStatus(
                    self.completion_port.raw(),
                    &raw mut message,
                    &raw mut key,
                    &raw mut overlapped,
                    10,
                )
            };
            std::thread::sleep(Duration::from_millis(1));
        }
        Ok(self.active_processes()? == 0)
    }
}

fn reject_fault(
    actual: Option<WindowsSealedFault>,
    expected: WindowsSealedFault,
) -> Result<(), String> {
    if actual == Some(expected) {
        Err(format!(
            "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected {expected:?}"
        ))
    } else {
        Ok(())
    }
}
