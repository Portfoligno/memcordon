use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::time::Duration;

use memcordon_core::{
    NativeWindowsCommandV1, WindowsEnvironmentEntryV1, WindowsProcessIdentityV1,
    WindowsRemoteStreamV1, WindowsSealedFault, WindowsSealedMutant, WindowsStreamRoleV1,
};
use windows_sys::Win32::Foundation::{
    DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle, FILETIME, GetHandleInformation,
    HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    FreeSid, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
    CreateProcessAsUserW, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, GetProcessId,
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject,
};

use super::job::Job;
use super::pipe::OwnedHandle;

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;

pub struct StreamSet {
    target_stdin: OwnedHandle,
    target_stdout: OwnedHandle,
    target_stderr: OwnedHandle,
    pub remote: Vec<WindowsRemoteStreamV1>,
    relay_retired_event: OwnedHandle,
    pub remote_relay_retired_event: u64,
    frontend_process: HANDLE,
    remote_lease_armed: bool,
}

impl StreamSet {
    pub fn create(
        frontend_process: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<Self, String> {
        reject_fault(certification_fault, WindowsSealedFault::StreamCreate)?;
        let (stdin_target, stdin_relay) = pipe_pair(true)?;
        let (stdout_relay, stdout_target) = pipe_pair(true)?;
        let (stderr_relay, stderr_target) = pipe_pair(true)?;
        clear_inherit(stdin_relay.raw())?;
        clear_inherit(stdout_relay.raw())?;
        clear_inherit(stderr_relay.raw())?;
        let mut remote = Vec::new();
        for (role, handle) in [
            (WindowsStreamRoleV1::Stdin, stdin_relay.raw()),
            (WindowsStreamRoleV1::Stdout, stdout_relay.raw()),
            (WindowsStreamRoleV1::Stderr, stderr_relay.raw()),
        ] {
            reject_fault(
                certification_fault,
                WindowsSealedFault::RelayHandleDuplicate,
            )?;
            match duplicate_remote(handle, frontend_process) {
                Ok(remote_handle) => remote.push(WindowsRemoteStreamV1 {
                    role,
                    remote_handle,
                }),
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            }
        }
        // SAFETY: null security/name create one private, noninheritable,
        // manual-reset event owned by this attempt.
        let relay_retired_event =
            match OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) }) {
                Ok(event) => event,
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            };
        let remote_relay_retired_event =
            match duplicate_remote(relay_retired_event.raw(), frontend_process) {
                Ok(handle) => handle,
                Err(error) => {
                    for transferred in &remote {
                        let _ = close_remote(transferred.remote_handle, frontend_process);
                    }
                    return Err(error);
                }
            };
        Ok(Self {
            target_stdin: stdin_target,
            target_stdout: stdout_target,
            target_stderr: stderr_target,
            remote,
            relay_retired_event,
            remote_relay_retired_event,
            frontend_process,
            remote_lease_armed: true,
        })
    }

    fn target_handles(&self) -> [HANDLE; 3] {
        [
            self.target_stdin.raw(),
            self.target_stdout.raw(),
            self.target_stderr.raw(),
        ]
    }

    pub fn certification_target_handle_values(&self) -> [u64; 3] {
        self.target_handles().map(|handle| handle as usize as u64)
    }

    pub fn accept_remote_handles(&mut self) {
        self.remote_lease_armed = false;
    }

    pub fn relay_retired_event(&self) -> HANDLE {
        self.relay_retired_event.raw()
    }
}

impl Drop for StreamSet {
    fn drop(&mut self) {
        if self.remote_lease_armed {
            for transferred in &self.remote {
                if transferred.remote_handle != 0 {
                    let _ = close_remote(transferred.remote_handle, self.frontend_process);
                }
            }
            if self.remote_relay_retired_event != 0 {
                let _ = close_remote(self.remote_relay_retired_event, self.frontend_process);
            }
        }
    }
}

fn pipe_pair(inherit: bool) -> Result<(OwnedHandle, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: i32::from(inherit),
    };
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    // SAFETY: both output pointers and security attributes remain live; each
    // returned handle transfers into an independent OwnedHandle.
    if unsafe {
        CreatePipe(
            &raw mut read,
            &raw mut write,
            &raw const attributes,
            64 * 1024,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((OwnedHandle::new(read)?, OwnedHandle::new(write)?))
}

fn clear_inherit(handle: HANDLE) -> Result<(), String> {
    // SAFETY: handle is live and the call changes only its inherit flag.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

pub fn verify_not_inheritable(handle: HANDLE) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is owned by the caller and flags is writable output.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else if flags & HANDLE_FLAG_INHERIT != 0 {
        Err("transferred privileged-boundary handle is inheritable".to_owned())
    } else {
        Ok(())
    }
}

pub fn mark_certification_handle_inheritable(handle: HANDLE) -> Result<(), String> {
    // SAFETY: this is called only for certification canaries after privileged
    // boundary adoption; the exact handle list must prove they remain excluded.
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn duplicate_remote(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: source/current and target process handles are live; output receives
    // a target-process handle value without making it inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(remote as usize as u64)
    }
}

pub fn duplicate_remote_process_query(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: source and target process handles are live; the target receives
    // only query/synchronize rights and the duplicate is non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE_ACCESS,
            0,
            0,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(remote as usize as u64)
    }
}

pub fn revoke_remote_handle(remote_handle: u64, process: HANDLE) -> Result<(), String> {
    close_remote(remote_handle, process)
}

fn close_remote(handle: u64, process: HANDLE) -> Result<(), String> {
    let mut local = ptr::null_mut();
    // SAFETY: process is the live frontend process and handle is a value that
    // this provider transferred into it. CLOSE_SOURCE revokes that exact value;
    // the returned local duplicate is immediately owned and closed.
    if unsafe {
        DuplicateHandle(
            process,
            handle as usize as HANDLE,
            GetCurrentProcess(),
            &raw mut local,
            0,
            0,
            DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        drop(OwnedHandle::new(local)?);
        Ok(())
    }
}

pub struct SuspendedTarget {
    process: OwnedHandle,
    thread: OwnedHandle,
    pub process_id: u32,
    pub creation_observation: TargetCreationObservation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TargetCreationObservation {
    pub used_create_process_as_user: bool,
    pub job_list_present: bool,
    pub handle_list_present: bool,
    pub post_create_job_assignment: bool,
    pub unexpected_handle_count: usize,
}

pub struct TargetCreateError {
    pub detail: String,
    pub os_code: Option<i32>,
}

impl From<String> for TargetCreateError {
    fn from(detail: String) -> Self {
        Self {
            detail,
            os_code: None,
        }
    }
}

impl SuspendedTarget {
    #[allow(clippy::too_many_arguments)] // Native creation requires each authority input explicitly.
    pub fn create(
        token: HANDLE,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
        launcher_pipe: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
    ) -> Result<Self, TargetCreateError> {
        validate_native_command(command)?;
        let mut effective_command = command.clone();
        let mut mutant_inheritable_handles = Vec::new();
        if let Some(kind) = match certification_mutant {
            Some(WindowsSealedMutant::LeakJobHandleToTarget) => Some("job"),
            Some(WindowsSealedMutant::LeakLauncherPipe) => Some("pipe"),
            _ => None,
        } {
            let source = if kind == "job" {
                job.handle()
            } else {
                launcher_pipe
            };
            let inherited = duplicate_local_inheritable(source)?;
            effective_command
                .arguments
                .push("windows-mutant-leaked-handle".encode_utf16().collect());
            effective_command
                .arguments
                .push(kind.encode_utf16().collect());
            effective_command.arguments.push(
                (inherited.raw() as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect(),
            );
            mutant_inheritable_handles.push(inherited);
        }
        let mut command_line = encode_command_line(
            &std::iter::once(effective_command.program.clone())
                .chain(effective_command.arguments.iter().cloned())
                .collect::<Vec<_>>(),
        );
        command_line.push(0);
        let mut application = command.program.clone();
        application.push(0);
        let environment = encode_environment(environment)?;
        let process_security = super::security::SecurityDescriptor::from_sddl(
            &super::security::launcher_process_sddl()?,
        )?;
        let process_attributes = process_security.attributes(false);
        let mut current_directory = current_directory.to_vec();
        if current_directory.last().copied() != Some(0) {
            current_directory.push(0);
        }
        let mut handles = streams.target_handles().to_vec();
        handles.extend(mutant_inheritable_handles.iter().map(|handle| handle.raw()));
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::LeakJobHandleToTarget | WindowsSealedMutant::LeakLauncherPipe
            )
        ) {
            validate_target_handle_list(&handles)?;
        }
        let jobs = [job.handle()];
        let mut process_attributes_manifest = Vec::new();
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::AssignJobAfterCreate
                    | WindowsSealedMutant::OmitJobList
                    | WindowsSealedMutant::SkipJobMembershipReadback
            )
        ) {
            process_attributes_manifest.push(Attribute::new(
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(&jobs),
            ));
        }
        if certification_mutant != Some(WindowsSealedMutant::OmitHandleList) {
            process_attributes_manifest.push(Attribute::new(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles.as_slice()),
            ));
        }
        let attributes = AttributeList::new(&process_attributes_manifest, certification_fault)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
        startup.lpAttributeList = attributes.raw();
        let mut process = PROCESS_INFORMATION::default();
        reject_fault(certification_fault, WindowsSealedFault::CreateProcessAsUser)?;
        // SAFETY: all UTF-16 buffers are NUL-terminated; environment is
        // double-NUL-terminated; startup attributes and referenced handle arrays
        // remain live through process creation; output handles become owned.
        let mut service_token = ptr::null_mut();
        let service_token =
            if certification_mutant == Some(WindowsSealedMutant::CreateUnderServiceToken) {
                if unsafe {
                    OpenProcessToken(
                        GetCurrentProcess(),
                        TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY,
                        &raw mut service_token,
                    )
                } == 0
                {
                    return Err(TargetCreateError::from(
                        io::Error::last_os_error().to_string(),
                    ));
                }
                Some(OwnedHandle::new(service_token).map_err(TargetCreateError::from)?)
            } else {
                None
            };
        let created = if matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::UseCreateProcessW
                    | WindowsSealedMutant::SkipTargetTokenReadback
            )
        ) {
            unsafe {
                CreateProcessW(
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    &raw const process_attributes,
                    &raw const process_attributes,
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_PROCESS_GROUP,
                    environment.as_ptr().cast::<c_void>(),
                    current_directory.as_ptr(),
                    &raw const startup.StartupInfo,
                    &raw mut process,
                )
            }
        } else {
            unsafe {
                CreateProcessAsUserW(
                    service_token.as_ref().map_or(token, OwnedHandle::raw),
                    application.as_ptr(),
                    command_line.as_mut_ptr(),
                    &raw const process_attributes,
                    &raw const process_attributes,
                    1,
                    CREATE_SUSPENDED
                        | EXTENDED_STARTUPINFO_PRESENT
                        | CREATE_UNICODE_ENVIRONMENT
                        | CREATE_NEW_PROCESS_GROUP,
                    environment.as_ptr().cast::<c_void>(),
                    current_directory.as_ptr(),
                    &raw const startup.StartupInfo,
                    &raw mut process,
                )
            }
        };
        if created == 0 {
            let error = io::Error::last_os_error();
            return Err(TargetCreateError {
                detail: error.to_string(),
                os_code: error.raw_os_error(),
            });
        }
        let process_handle = OwnedHandle::new(process.hProcess).map_err(TargetCreateError::from)?;
        let thread_handle = OwnedHandle::new(process.hThread).map_err(TargetCreateError::from)?;
        if certification_mutant == Some(WindowsSealedMutant::AssignJobAfterCreate)
            && unsafe { AssignProcessToJobObject(job.handle(), process_handle.raw()) } == 0
        {
            return Err(TargetCreateError::from(
                io::Error::last_os_error().to_string(),
            ));
        }
        process_security
            .verify_kernel_object(process_handle.raw())
            .map_err(TargetCreateError::from)?;
        Ok(Self {
            process: process_handle,
            thread: thread_handle,
            process_id: process.dwProcessId,
            creation_observation: TargetCreationObservation {
                used_create_process_as_user: !matches!(
                    certification_mutant,
                    Some(
                        WindowsSealedMutant::UseCreateProcessW
                            | WindowsSealedMutant::SkipTargetTokenReadback
                    )
                ),
                job_list_present: !matches!(
                    certification_mutant,
                    Some(
                        WindowsSealedMutant::AssignJobAfterCreate
                            | WindowsSealedMutant::OmitJobList
                            | WindowsSealedMutant::SkipJobMembershipReadback
                    )
                ),
                handle_list_present: certification_mutant
                    != Some(WindowsSealedMutant::OmitHandleList),
                post_create_job_assignment: certification_mutant
                    == Some(WindowsSealedMutant::AssignJobAfterCreate),
                unexpected_handle_count: mutant_inheritable_handles.len(),
            },
        })
    }

    pub const fn handle(&self) -> HANDLE {
        self.process.raw()
    }

    pub fn resume(&self, certification_fault: Option<WindowsSealedFault>) -> Result<(), String> {
        reject_fault(certification_fault, WindowsSealedFault::Resume)?;
        // SAFETY: the primary thread is live and has not previously been resumed.
        let previous = unsafe { ResumeThread(self.thread.raw()) };
        if previous == u32::MAX {
            Err(io::Error::last_os_error().to_string())
        } else if previous != 1 {
            Err(format!(
                "target primary thread suspend count was {previous}, expected 1"
            ))
        } else {
            Ok(())
        }
    }

    pub fn wait(&self, duration: Duration) -> Result<bool, String> {
        let timeout = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX - 1);
        // SAFETY: process handle remains live for the wait.
        match unsafe { WaitForSingleObject(self.process.raw(), timeout) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error().to_string()),
        }
    }

    pub fn exit_status(&self) -> Result<u32, String> {
        let mut status = 0_u32;
        // SAFETY: process is signaled before this query and output is writable.
        if unsafe { GetExitCodeProcess(self.process.raw(), &raw mut status) } == 0 {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(status)
        }
    }
}

fn validate_target_handle_list(handles: &[HANDLE]) -> Result<(), String> {
    if handles.len() != 3 {
        return Err("target handle list must contain exactly stdin, stdout, and stderr".to_owned());
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(format!("target handle list entry {index} is invalid"));
        }
        if handles[..index].contains(&handle) {
            return Err(format!("target handle list entry {index} is duplicated"));
        }
    }
    Ok(())
}

pub fn certify_target_handle_list_negatives() -> Result<(), String> {
    let first = 1_usize as HANDLE;
    let second = 2_usize as HANDLE;
    let third = 3_usize as HANDLE;
    let omitted_rejected = validate_target_handle_list(&[first, second]).is_err();
    let duplicate_rejected = validate_target_handle_list(&[first, second, second]).is_err();
    let invalid_rejected = validate_target_handle_list(&[first, ptr::null_mut(), third]).is_err()
        && validate_target_handle_list(&[first, INVALID_HANDLE_VALUE, third]).is_err();
    if omitted_rejected && duplicate_rejected && invalid_rejected {
        Ok(())
    } else {
        Err("target HANDLE_LIST negative-shape certification failed".to_owned())
    }
}

struct Attribute {
    kind: usize,
    value: *const c_void,
    size: usize,
}

impl Attribute {
    const fn new(kind: usize, value: *const c_void, size: usize) -> Self {
        Self { kind, value, size }
    }
}

struct AttributeList {
    raw: LPPROC_THREAD_ATTRIBUTE_LIST,
    layout: Layout,
}

impl AttributeList {
    fn new(
        attributes: &[Attribute],
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<Self, String> {
        reject_fault(certification_fault, WindowsSealedFault::AttributeList)?;
        let count = u32::try_from(attributes.len())
            .map_err(|_| "too many process attributes".to_owned())?;
        let mut size = 0_usize;
        // SAFETY: documented size-query call uses a null list and writes size.
        unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), count, 0, &raw mut size) };
        let layout = Layout::from_size_align(size, std::mem::align_of::<usize>())
            .map_err(|error| error.to_string())?;
        // SAFETY: layout has nonzero API-supplied size and native pointer alignment.
        let allocation = unsafe { alloc_zeroed(layout) };
        if allocation.is_null() {
            return Err("process attribute-list allocation failed".to_owned());
        }
        let raw = allocation.cast();
        // SAFETY: allocation has API-requested size and remains owned by Self.
        if unsafe { InitializeProcThreadAttributeList(raw, count, 0, &raw mut size) } == 0 {
            // SAFETY: allocation/layout are the exact pair returned above.
            unsafe { dealloc(allocation, layout) };
            return Err(io::Error::last_os_error().to_string());
        }
        let list = Self { raw, layout };
        for attribute in attributes {
            let fault = if attribute.kind == PROC_THREAD_ATTRIBUTE_JOB_LIST as usize {
                Some(WindowsSealedFault::JobList)
            } else if attribute.kind == PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize {
                Some(WindowsSealedFault::HandleList)
            } else if attribute.kind == PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize {
                None
            } else {
                return Err("unsupported process attribute in sealed target manifest".to_owned());
            };
            if let Some(fault) = fault {
                reject_fault(certification_fault, fault)?;
            }
            // SAFETY: list is initialized; each referenced structured value
            // remains live through the subsequent process-creation call.
            if unsafe {
                UpdateProcThreadAttribute(
                    list.raw,
                    0,
                    attribute.kind,
                    attribute.value,
                    attribute.size,
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error().to_string());
            }
        }
        Ok(list)
    }

    const fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.raw
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

impl Drop for AttributeList {
    fn drop(&mut self) {
        // SAFETY: raw is initialized and allocation/layout remain the exact
        // ownership pair until this single teardown.
        unsafe {
            DeleteProcThreadAttributeList(self.raw);
            dealloc(self.raw.cast(), self.layout);
        }
    }
}

pub fn encode_command_line(arguments: &[Vec<u16>]) -> Vec<u16> {
    memcordon_core::encode_windows_command_line(arguments)
}

struct AppContainerProfile {
    name: Vec<u16>,
    sid: *mut c_void,
    active: bool,
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        // SAFETY: name remains NUL-terminated and sid is the exact allocation
        // returned by CreateAppContainerProfile.
        unsafe {
            if self.active {
                DeleteAppContainerProfile(self.name.as_ptr());
            }
            FreeSid(self.sid);
        }
    }
}

impl AppContainerProfile {
    fn delete_and_verify(mut self) -> Result<(), String> {
        // SAFETY: name remains a live NUL-terminated profile name.
        let deleted = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        if deleted < 0 {
            return Err(format!(
                "cannot delete AppContainer qualification profile: HRESULT {deleted:#x}"
            ));
        }
        self.active = false;
        // Re-create the exact same profile name. Fresh creation succeeding is
        // the native absence readback (DeleteAppContainerProfile itself is
        // intentionally idempotent and also succeeds for an absent profile).
        let display = super::pipe::wide_null("MemCordon sealed AppContainer absence readback");
        let description = super::pipe::wide_null("Ephemeral native qualification fixture");
        let mut proof_sid = ptr::null_mut();
        let recreated = unsafe {
            CreateAppContainerProfile(
                self.name.as_ptr(),
                display.as_ptr(),
                description.as_ptr(),
                ptr::null(),
                0,
                &raw mut proof_sid,
            )
        };
        if recreated < 0 || proof_sid.is_null() {
            return Err(format!(
                "AppContainer qualification profile absence readback returned HRESULT {recreated:#x}"
            ));
        }
        let proof_deleted = unsafe { DeleteAppContainerProfile(self.name.as_ptr()) };
        unsafe { FreeSid(proof_sid) };
        if proof_deleted < 0 {
            return Err(format!(
                "cannot delete AppContainer absence-readback profile: HRESULT {proof_deleted:#x}"
            ));
        }
        Ok(())
    }
}

pub fn run_appcontainer_rejection_client() -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;

    let profile_name = format!(
        "memcordon.certification.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|error| error.to_string())?
            .as_nanos()
    );
    let name = super::pipe::wide_null(&profile_name);
    let display = super::pipe::wide_null("MemCordon sealed AppContainer rejection canary");
    let description = super::pipe::wide_null("Ephemeral native qualification fixture");
    let mut sid = ptr::null_mut();
    // SAFETY: all strings are NUL-terminated, the empty capability inventory
    // permits a null pointer, and sid receives a FreeSid-owned allocation.
    let result = unsafe {
        CreateAppContainerProfile(
            name.as_ptr(),
            display.as_ptr(),
            description.as_ptr(),
            ptr::null(),
            0,
            &raw mut sid,
        )
    };
    if result < 0 || sid.is_null() {
        return Err(format!(
            "cannot create AppContainer qualification profile: HRESULT {result:#x}"
        ));
    }
    let profile = AppContainerProfile {
        name,
        sid,
        active: true,
    };
    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: profile.sid,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&raw const capabilities).cast(),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
        )],
        None,
    )?;
    let executable = crate::windows::package::installed_binary();
    let mut command_line = encode_command_line(&[
        executable.as_os_str().encode_wide().collect(),
        "windows-certification-appcontainer"
            .encode_utf16()
            .collect(),
    ]);
    command_line.push(0);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: command line and attribute list remain live for the synchronous
    // call; no handles are inherited into the AppContainer fixture.
    if unsafe {
        CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(format!(
            "cannot create AppContainer qualification client: {}",
            io::Error::last_os_error()
        ));
    }
    let thread = OwnedHandle::new(process.hThread)?;
    let process = OwnedHandle::new(process.hProcess)?;
    drop(thread);
    match unsafe { WaitForSingleObject(process.raw(), 30_000) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => {
            // SAFETY: process is live and owned; forced termination bounds the
            // native rejection fixture without granting it target authority.
            unsafe { TerminateProcess(process.raw(), 125) };
            let _ = unsafe { WaitForSingleObject(process.raw(), 5_000) };
            return Err("AppContainer rejection client timed out".to_owned());
        }
        _ => return Err(io::Error::last_os_error().to_string()),
    }
    let mut exit_code = 0_u32;
    // SAFETY: the process is signaled and the output is writable.
    if unsafe { GetExitCodeProcess(process.raw(), &raw mut exit_code) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    if exit_code != 0 {
        return Err(format!(
            "AppContainer rejection client failed with status {exit_code:#x}"
        ));
    }
    profile.delete_and_verify()
}

fn validate_native_command(command: &NativeWindowsCommandV1) -> Result<(), String> {
    if command.program.is_empty()
        || command.program.contains(&0)
        || command.arguments.iter().any(|value| value.contains(&0))
    {
        return Err("native Windows command contains an empty program or NUL".to_owned());
    }
    Ok(())
}

pub fn encode_environment(entries: &[WindowsEnvironmentEntryV1]) -> Result<Vec<u16>, String> {
    memcordon_core::encode_windows_environment_block(entries).map_err(str::to_owned)
}

pub fn process_identity(process: HANDLE) -> Result<WindowsProcessIdentityV1, String> {
    let process_id = unsafe { GetProcessId(process) };
    if process_id == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: process is live and all FILETIME outputs are writable.
    if unsafe {
        GetProcessTimes(
            process,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(WindowsProcessIdentityV1 {
        process_id,
        creation_time_100ns: (u64::from(creation.dwHighDateTime) << 32)
            | u64::from(creation.dwLowDateTime),
    })
}

pub fn process_identity_for_pid(
    process_id: u32,
) -> Result<Option<WindowsProcessIdentityV1>, String> {
    // SAFETY: the PID came from a Job process-list kernel readback and the
    // returned handle is adopted immediately.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw.is_null() {
        let error = io::Error::last_os_error();
        return if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)
        {
            Ok(None)
        } else {
            Err(error.to_string())
        };
    }
    let process = OwnedHandle::new(raw)?;
    process_identity(process.raw()).map(Some)
}

pub fn verify_image_path(process: HANDLE, expected: &Path) -> Result<(), String> {
    let mut path = vec![0_u16; 32 * 1024];
    let mut length = path.len() as u32;
    // SAFETY: path provides writable storage and length contains its capacity.
    if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &raw mut length) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    path.truncate(length as usize);
    let actual = PathBuf::from(String::from_utf16_lossy(&path));
    if !actual
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.to_string_lossy())
    {
        return Err(
            "authenticated service process does not use the installed agent image".to_owned(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // The five exact inherited handles stay individually visible.
pub fn create_guardian(
    job: HANDLE,
    frontend: HANDLE,
    worker: HANDLE,
    disarm: HANDLE,
    ready: HANDLE,
    attempt_id: &str,
    cleanup_deadline_millis: u64,
    readiness_delay_millis: u64,
) -> Result<(OwnedHandle, u32), String> {
    let inherited_owners = [job, frontend, worker, disarm, ready]
        .into_iter()
        .map(duplicate_local_inheritable)
        .collect::<Result<Vec<_>, _>>()?;
    let inherited = inherited_owners
        .iter()
        .map(OwnedHandle::raw)
        .collect::<Vec<_>>();
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    use std::os::windows::ffi::OsStrExt;
    let arguments = vec![
        executable.as_os_str().encode_wide().collect(),
        "windows-guardian".encode_utf16().collect(),
        (inherited[0] as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (inherited[1] as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (inherited[2] as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (inherited[3] as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (inherited[4] as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        attempt_id.encode_utf16().collect(),
        cleanup_deadline_millis.to_string().encode_utf16().collect(),
        readiness_delay_millis.to_string().encode_utf16().collect(),
    ];
    let mut command_line = encode_command_line(&arguments);
    command_line.push(0);
    let process_security =
        super::security::SecurityDescriptor::from_sddl(&super::security::launcher_process_sddl()?)?;
    let process_attributes = process_security.attributes(false);
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            std::mem::size_of::<HANDLE>() * inherited.len(),
        )],
        None,
    )?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: command and attribute list remain live; the exact handle list is
    // inheritable; guardian is deliberately created outside the target Job.
    if unsafe {
        CreateProcessW(
            ptr::null(),
            command_line.as_mut_ptr(),
            &raw const process_attributes,
            &raw const process_attributes,
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let thread = OwnedHandle::new(process.hThread)?;
    let process_handle = OwnedHandle::new(process.hProcess)?;
    process_security.verify_kernel_object(process_handle.raw())?;
    drop(thread);
    Ok((process_handle, process.dwProcessId))
}

fn duplicate_local_inheritable(handle: HANDLE) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: current process and source handle are live; output receives an
    // independently owned inheritable duplicate for the exact guardian list.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        OwnedHandle::new(duplicate)
    }
}

pub fn duplicate_owned(handle: HANDLE) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: source/current handles are live and output receives a
    // non-inheritable same-access duplicate owned by the returned wrapper.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &raw mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        OwnedHandle::new(duplicate)
    }
}
