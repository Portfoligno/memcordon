//! Isolated diagnostic reproduction; never product execution or readiness authority.
#![cfg(windows)]

use memcordon_windows_launch_core::{
    NativeSecurityDescriptorV1 as Security, ProductionJobV1 as Job,
};
use memcordon_windows_loader_lab::holder_protocol::{
    self, Binding, Frame, Outcome, ReadyPolicy, Stage,
};
use memcordon_windows_loader_lab::workload::WorkloadDiagnosticRequestV1 as Request;
use memcordon_windows_loader_lab::{
    module_observation::{self, EventKind, ModuleTable},
    selected_policy::{self, Domain},
    selected_policy_native,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsString, c_void},
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{
        Diagnostics::Debug::*, JobObjects::IsProcessInJob, Pipes::*,
        ProcessStatus::K32GetMappedFileNameW, Services::*, StationsAndDesktops::*,
        SystemInformation::GetTickCount64, Threading::*,
    },
};

const LIMIT: usize = 256 * 1024;
const EVENT_LIMIT: usize = 2048;
const FAILURE: u32 = 0x4d43_0d01;
static STOP: AtomicBool = AtomicBool::new(false);

fn error(api: &str) -> String {
    format!("{api}: {}", std::io::Error::last_os_error())
}
fn live(cutoff: Instant) -> Result<(), String> {
    if STOP.load(Ordering::Acquire) || Instant::now() >= cutoff {
        Err("original diagnostic cutoff exhausted or service stopping".into())
    } else {
        Ok(())
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
struct Handle(HANDLE);
impl Handle {
    fn new(raw: HANDLE) -> Result<Self, String> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(error("native handle"))
        } else {
            Ok(Self(raw))
        }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn birth(process: HANDLE) -> Result<u64, String> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(error("GetProcessTimes"));
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
fn read(path: &Path, bound: usize) -> Result<Vec<u8>, String> {
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| e.to_string())?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > bound as u64
    {
        return Err("diagnostic input is not a bounded ordinary file".into());
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(bound as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > bound {
        return Err("diagnostic input grew beyond bound".into());
    }
    Ok(bytes)
}
fn request(path: &Path) -> Result<Request, String> {
    let bytes = read(path, 16 * 1024 * 1024)?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    request.validate()?;
    Ok(request)
}
fn publish(path: &Path, value: &Value) -> Result<(), String> {
    let bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())?;
    drop(file);
    if read(path, bytes.len())? != bytes {
        return Err("diagnostic result readback differs".into());
    }
    Ok(())
}
fn deadlines(request: &Request) -> Result<(Instant, Instant), String> {
    let now = unsafe { GetTickCount64() };
    let work = request
        .work_deadline_tick_ms
        .checked_sub(now)
        .ok_or("original work cutoff expired during service startup")?;
    let cleanup = request
        .cleanup_deadline_tick_ms
        .checked_sub(now)
        .ok_or("original cleanup cutoff expired during service startup")?;
    let origin = Instant::now();
    Ok((
        origin
            .checked_add(Duration::from_millis(work))
            .ok_or("work cutoff overflow")?,
        origin
            .checked_add(Duration::from_millis(cleanup))
            .ok_or("cleanup cutoff overflow")?,
    ))
}

/// A disposable impersonation carrier; the service primary is never mutated.
struct Privileges {
    token: Handle,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl Privileges {
    fn enter() -> Result<Self, String> {
        let mut existing = ptr::null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut existing) } != 0 {
            drop(Handle::new(existing)?);
            return Err("diagnostic thread already impersonates".into());
        }
        if unsafe { GetLastError() } != ERROR_NO_TOKEN {
            return Err(error("OpenThreadToken preflight"));
        }
        let mut source = ptr::null_mut();
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut source,
            )
        } == 0
        {
            return Err(error("OpenProcessToken carrier"));
        }
        let source = Handle::new(source)?;
        let mut carrier = ptr::null_mut();
        if unsafe {
            DuplicateTokenEx(
                source.0,
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &mut carrier,
            )
        } == 0
        {
            return Err(error("DuplicateTokenEx carrier"));
        }
        let token = Handle::new(carrier)?;
        for name in [
            "SeTcbPrivilege",
            "SeAssignPrimaryTokenPrivilege",
            "SeIncreaseQuotaPrivilege",
            "SeRestorePrivilege",
        ] {
            let mut luid = LUID::default();
            if unsafe { LookupPrivilegeValueW(ptr::null(), wide(name).as_ptr(), &mut luid) } == 0 {
                return Err(error("LookupPrivilegeValueW"));
            }
            let privilege = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };
            unsafe {
                SetLastError(0);
            }
            if unsafe {
                AdjustTokenPrivileges(token.0, 0, &privilege, 0, ptr::null_mut(), ptr::null_mut())
            } == 0
                || unsafe { GetLastError() } != ERROR_SUCCESS
            {
                return Err(error("enable disposable carrier privilege"));
            }
        }
        if unsafe { SetThreadToken(ptr::null(), token.0) } == 0 {
            return Err(error("SetThreadToken carrier"));
        }
        Ok(Self {
            token,
            _thread: std::marker::PhantomData,
        })
    }
}
impl Drop for Privileges {
    fn drop(&mut self) {
        if unsafe { RevertToSelf() } == 0 {
            std::process::abort();
        }
        let _ = &self.token;
    }
}
fn system_for_session(session: u32) -> Result<Handle, String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &mut raw) }
        == 0
    {
        return Err(error("OpenProcessToken SYSTEM"));
    }
    let source = Handle::new(raw)?;
    let original =
        memcordon_windows_launch_core::query_token_envelope(source.0).map_err(|e| e.to_string())?;
    if original.user_sid != "S-1-5-18" {
        return Err("diagnostic holder source is not SYSTEM".into());
    }
    let mut raw = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            source.0,
            TOKEN_QUERY
                | TOKEN_DUPLICATE
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_SESSIONID
                | TOKEN_ADJUST_DEFAULT,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut raw,
        )
    } == 0
    {
        return Err(error("DuplicateTokenEx holder"));
    }
    let token = Handle::new(raw)?;
    if unsafe {
        SetTokenInformation(
            token.0,
            TokenSessionId,
            (&session as *const u32).cast(),
            std::mem::size_of::<u32>() as u32,
        )
    } == 0
    {
        return Err(error("SetTokenInformation holder session"));
    }
    let observed =
        memcordon_windows_launch_core::query_token_envelope(token.0).map_err(|e| e.to_string())?;
    if observed.user_sid != "S-1-5-18" || observed.session_id != session {
        return Err("diagnostic holder token session or user differs".into());
    }
    Ok(token)
}
fn restricted(source: HANDLE) -> Result<Handle, String> {
    let mut sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide("S-1-5-12").as_ptr(), &mut sid) } == 0 {
        return Err(error("RestrictedCode SID"));
    }
    let restriction = SID_AND_ATTRIBUTES {
        Sid: sid,
        Attributes: 0,
    };
    let mut token = ptr::null_mut();
    let result = unsafe {
        CreateRestrictedToken(
            source,
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null(),
            0,
            ptr::null(),
            1,
            &restriction,
            &mut token,
        )
    };
    unsafe {
        LocalFree(sid);
    }
    if result == 0 {
        return Err(error("CreateRestrictedToken actual baseline"));
    }
    Handle::new(token)
}

struct Attributes {
    storage: Vec<usize>,
    jobs: Vec<HANDLE>,
    handles: Vec<HANDLE>,
    initialized: bool,
}
impl Attributes {
    fn new(job: HANDLE, handles: &[HANDLE]) -> Result<Self, String> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 2, 0, &mut bytes);
        }
        let mut owner = Self {
            storage: vec![0; bytes.div_ceil(std::mem::size_of::<usize>())],
            jobs: vec![job],
            handles: handles.to_vec(),
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(owner.raw(), 2, 0, &mut bytes) } == 0 {
            return Err(error("InitializeProcThreadAttributeList"));
        }
        owner.initialized = true;
        if unsafe {
            UpdateProcThreadAttribute(
                owner.raw(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                owner.jobs.as_ptr().cast(),
                std::mem::size_of_val(owner.jobs.as_slice()),
                ptr::null_mut(),
                ptr::null(),
            )
        } == 0
            || unsafe {
                UpdateProcThreadAttribute(
                    owner.raw(),
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    owner.handles.as_ptr().cast(),
                    std::mem::size_of_val(owner.handles.as_slice()),
                    ptr::null_mut(),
                    ptr::null(),
                )
            } == 0
        {
            return Err(error("UpdateProcThreadAttribute"));
        }
        Ok(owner)
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
}
struct Process {
    debugger: Option<DebugOwner>,
    creation_flags: u32,
    process: Handle,
    thread: Handle,
    pid: u32,
    birth: u64,
    tid: u32,
    resume_attempted: bool,
}
#[derive(Clone, Copy)]
enum DebugCreation<'a> {
    None,
    OnlyThisProcess(&'a Path),
}
impl DebugCreation<'_> {
    fn flags(self) -> u32 {
        match self {
            Self::None => 0,
            Self::OnlyThisProcess(_) => DEBUG_ONLY_THIS_PROCESS,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CreationCheckpoint {
    Created,
    Validated,
}
struct SpawnSpec<'a> {
    token: HANDLE,
    command: &'a memcordon_core::NativeWindowsCommandV1,
    environment: &'a [memcordon_core::WindowsEnvironmentEntryV1],
    cwd: &'a [u16],
    desktop: Option<&'a str>,
    job: &'a Job,
    handles: &'a [HANDLE],
    standard: bool,
    descriptors: Option<(&'a str, &'a str)>,
    cleanup: Instant,
    debug: DebugCreation<'a>,
}

fn spawn(spec: SpawnSpec<'_>) -> Result<Process, String> {
    spawn_checked(spec, |_| Ok(()))
}

fn spawn_checked(
    spec: SpawnSpec<'_>,
    mut checkpoint: impl FnMut(CreationCheckpoint) -> Result<(), String>,
) -> Result<Process, String> {
    let SpawnSpec {
        token,
        command,
        environment,
        cwd,
        desktop,
        job,
        handles,
        standard,
        descriptors,
        cleanup,
        debug,
    } = spec;
    let mut attrs = Attributes::new(job.handle(), handles)?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut desktop = desktop.map(wide);
    if let Some(desktop) = desktop.as_mut() {
        startup.StartupInfo.lpDesktop = desktop.as_mut_ptr();
    }
    if standard {
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = handles[0];
        startup.StartupInfo.hStdOutput = handles[1];
        startup.StartupInfo.hStdError = handles[2];
    }
    startup.lpAttributeList = attrs.raw();
    let mut application = command.program.clone();
    application.push(0);
    let arguments = std::iter::once(command.program.clone())
        .chain(command.arguments.iter().cloned())
        .collect::<Vec<_>>();
    let mut encoded = memcordon_core::encode_windows_command_line(&arguments);
    encoded.push(0);
    let env =
        memcordon_core::encode_windows_environment_block(environment).map_err(str::to_owned)?;
    let mut cwd = cwd.to_vec();
    if cwd.last() != Some(&0) {
        cwd.push(0);
    }
    let process_sd = descriptors
        .map(|(process, _)| Security::from_sddl(process))
        .transpose()
        .map_err(|e| format!("process descriptor: {e:?}"))?;
    let thread_sd = descriptors
        .map(|(_, thread)| Security::from_sddl(thread))
        .transpose()
        .map_err(|e| format!("thread descriptor: {e:?}"))?;
    let process_sa = process_sd
        .as_ref()
        .map(Security::security_attributes)
        .transpose()
        .map_err(|e| format!("process attributes: {e:?}"))?;
    let thread_sa = thread_sd
        .as_ref()
        .map(Security::security_attributes)
        .transpose()
        .map_err(|e| format!("thread attributes: {e:?}"))?;
    let mut information = PROCESS_INFORMATION::default();
    let flags = debug.flags()
        | CREATE_SUSPENDED
        | EXTENDED_STARTUPINFO_PRESENT
        | CREATE_UNICODE_ENVIRONMENT
        | if standard {
            CREATE_NEW_PROCESS_GROUP
        } else {
            DETACHED_PROCESS
        };
    if unsafe {
        CreateProcessAsUserW(
            token,
            application.as_ptr(),
            encoded.as_mut_ptr(),
            process_sa.as_ref().map_or(ptr::null(), |v| v),
            thread_sa.as_ref().map_or(ptr::null(), |v| v),
            1,
            flags,
            env.as_ptr().cast::<c_void>(),
            cwd.as_ptr(),
            &startup.StartupInfo,
            &mut information,
        )
    } == 0
    {
        return Err(error("CreateProcessAsUserW diagnostic"));
    }
    // Successful native creation transfers the debug obligation to THIS thread.
    // Adopt it before any fallible readback or checkpoint, including birth.
    let mut debugger = match debug {
        DebugCreation::None => None,
        DebugCreation::OnlyThisProcess(output) => {
            Some(DebugOwner::created(information.dwProcessId, output))
        }
    };
    // CreateProcessAsUserW success guarantees both returned handles are valid.
    let process = Handle(information.hProcess);
    let thread = Handle(information.hThread);
    let mut created_birth = None;
    let observed = (|| -> Result<u64, String> {
        checkpoint(CreationCheckpoint::Created)?;
        let created = birth(process.0)?;
        created_birth = Some(created);
        if let Some(owner) = debugger.as_mut() {
            owner.verified_birth = Some(created);
        }
        let mut in_job = 0;
        if unsafe { IsProcessInJob(process.0, job.handle(), &mut in_job) } == 0 || in_job == 0 {
            return Err("diagnostic process atomic Job readback differs".into());
        }
        if let Some(sd) = process_sd {
            sd.verify_kernel_object(
                process.0,
                memcordon_windows_launch_core::NativeKernelObjectKindV1::Process,
            )
            .map_err(|e| format!("process SD readback: {e:?}"))?;
        }
        if let Some(sd) = thread_sd {
            sd.verify_kernel_object(
                thread.0,
                memcordon_windows_launch_core::NativeKernelObjectKindV1::Thread,
            )
            .map_err(|e| format!("thread SD readback: {e:?}"))?;
        }
        checkpoint(CreationCheckpoint::Validated)?;
        Ok(created)
    })();
    let created = match observed {
        Ok(created) => Process {
            debugger,
            creation_flags: flags,
            birth: created,
            process,
            thread,
            pid: information.dwProcessId,
            tid: information.dwThreadId,
            resume_attempted: false,
        },
        Err(primary) => {
            let terminated = unsafe { TerminateProcess(process.0, FAILURE) } != 0;
            let debug_settled = match debugger.as_mut() {
                Some(owner) => owner.settle(process.0, cleanup),
                None => Ok(()),
            };
            let settled = wait(process.0, cleanup);
            let retained = match (debug, debugger.as_ref()) {
                (DebugCreation::OnlyThisProcess(output), Some(owner)) => publish(
                    &output.join("post-create-rollback.json"),
                    &json!({"format":"memcordon.workload-post-create-rollback","revision":1,"diagnostic_only":true,"certification_authority":false,"original_failure_unchanged":true,"pid":information.dwProcessId,"birth":created_birth,"tid":information.dwThreadId,"creator_thread":owner.creator,"debug_creation":"only-this-process","creation_flags":flags,"primary":primary,"termination_request":{"phase":"cleanup","code":FAILURE,"succeeded":terminated},"events":owner.events,"omitted_events":owner.omitted,"module_coverage":owner.module_coverage(),"exit":owner.exit,"exit_phase":owner.exit_phase,"debug_settlement":format!("{debug_settled:?}"),"held_process_settlement":format!("{settled:?}")}),
                ),
                _ => Ok(()),
            };
            return Err(format!(
                "{primary}; exact post-create rollback terminated={terminated} debug={debug_settled:?} settlement={settled:?} retained={retained:?}"
            ));
        }
    };
    Ok(created)
}
#[derive(Debug, serde::Serialize)]
struct ResumeObservation {
    role: &'static str,
    stage: &'static str,
    pid: u32,
    birth: u64,
    tid: u32,
    call_ordinal: u32,
    expected_previous_count: u32,
    debugger_attached: bool,
    result: memcordon_windows_loader_lab::resume_thread::ResumeResult,
}
fn resume(
    process: &mut Process,
    role: &'static str,
    stage: &'static str,
    debugger_attached: bool,
) -> Result<ResumeObservation, String> {
    if process.resume_attempted {
        return Err("diagnostic primary thread resume already attempted; no retry".into());
    }
    process.resume_attempted = true;
    let raw = unsafe { ResumeThread(process.thread.0) };
    let result =
        memcordon_windows_loader_lab::resume_thread::classify(raw, || unsafe { GetLastError() });
    Ok(ResumeObservation {
        role,
        stage,
        pid: process.pid,
        birth: process.birth,
        tid: process.tid,
        call_ordinal: 1,
        expected_previous_count: 1,
        debugger_attached,
        result,
    })
}
fn pipe() -> Result<(Handle, Handle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut reader, mut writer) = (ptr::null_mut(), ptr::null_mut());
    if unsafe { CreatePipe(&mut reader, &mut writer, &attributes, 64 * 1024) } == 0 {
        return Err(error("CreatePipe diagnostic"));
    }
    Ok((Handle::new(reader)?, Handle::new(writer)?))
}
fn clear(handle: HANDLE) -> Result<(), String> {
    if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, 0) } == 0 {
        Err(error("clear relay inheritance"))
    } else {
        Ok(())
    }
}
pub(crate) fn drain(handle: HANDLE, bytes: &mut Vec<u8>, omitted: &mut u64) -> Result<(), String> {
    drain_bounded(handle, bytes, omitted, LIMIT)
}

fn drain_bounded(
    handle: HANDLE,
    bytes: &mut Vec<u8>,
    omitted: &mut u64,
    limit: usize,
) -> Result<(), String> {
    let mut available = 0;
    if unsafe {
        PeekNamedPipe(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        let status = unsafe { GetLastError() };
        if status == ERROR_BROKEN_PIPE {
            return Ok(());
        }
        return Err(error("PeekNamedPipe"));
    }
    // One finite chunk per iteration keeps stream traffic from starving the cutoff.
    let mut buffer = [0; 4096];
    let length = available.min(buffer.len() as u32);
    if length == 0 {
        return Ok(());
    }
    let mut count = 0;
    if unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            length,
            &mut count,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(error("diagnostic bounded pipe read"));
    }
    let retain = limit.saturating_sub(bytes.len()).min(count as usize);
    bytes.extend_from_slice(&buffer[..retain]);
    *omitted += count as u64 - retain as u64;
    Ok(())
}

fn desktop_name(request: &Request) -> String {
    format!("MemCordonDiagnostic-{}\\Restricted", request.diagnostic_id)
}
struct HolderContext {
    stage: Stage,
    operation: &'static str,
    native_code: Option<u32>,
    binding: Option<Binding>,
    cleanup: Vec<String>,
    readiness_started: bool,
}

impl HolderContext {
    fn enter(&mut self, stage: Stage, operation: &'static str) {
        self.stage = stage;
        self.operation = operation;
        self.native_code = None;
    }

    fn native_error(&mut self, operation: &'static str) -> String {
        let code = unsafe { GetLastError() };
        self.native_status(operation, code)
    }

    fn native_status(&mut self, operation: &'static str, code: u32) -> String {
        self.operation = operation;
        self.native_code = Some(code);
        format!(
            "{operation}: {}",
            std::io::Error::from_raw_os_error(code as i32)
        )
    }
}

/// Helper runs as SYSTEM in the target session; its objects remain alive until stop.
pub fn run_desktop_holder(
    path: &Path,
    ready: u64,
    stop: u64,
    target_token: u64,
) -> Result<(), String> {
    let ready =
        Handle::new(usize::try_from(ready).map_err(|_| "ready handle overflow")? as HANDLE)?;
    let identity = memcordon_core::WindowsProcessIdentityV1 {
        process_id: unsafe { GetCurrentProcessId() },
        creation_time_100ns: birth(unsafe { GetCurrentProcess() })?,
    };
    let mut context = HolderContext {
        stage: Stage::InheritedHandles,
        operation: "adopt inherited capabilities",
        native_code: None,
        binding: None,
        cleanup: Vec::new(),
        readiness_started: false,
    };
    let result =
        desktop_holder_operation(path, &ready, stop, target_token, &identity, &mut context);
    if let Err(primary) = &result
        && !context.readiness_started
    {
        let frame = Frame::failure(
            identity,
            context.binding,
            context.stage,
            context.operation,
            context.native_code,
            primary,
            &context.cleanup,
        );
        let publication = holder_protocol::encode(&frame).and_then(|bytes| {
            let mut count = 0;
            if unsafe {
                WriteFile(
                    ready.0,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                    &mut count,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(error("WriteFile holder failure"));
            }
            if count as usize != bytes.len() {
                return Err(format!(
                    "holder failure partial write: {count} of {}",
                    bytes.len()
                ));
            }
            Ok(())
        });
        if let Err(secondary) = publication {
            return Err(format!(
                "{primary}; holder failure publication: {secondary}"
            ));
        }
    }
    result
}

fn desktop_holder_operation(
    path: &Path,
    ready: &Handle,
    stop: u64,
    target_token: u64,
    identity: &memcordon_core::WindowsProcessIdentityV1,
    context: &mut HolderContext,
) -> Result<(), String> {
    let stop = Handle::new(usize::try_from(stop).map_err(|_| "stop handle overflow")? as HANDLE)?;
    clear(ready.0)?;
    clear(stop.0)?;
    let target_token = Handle::new(
        usize::try_from(target_token).map_err(|_| "target query handle overflow")? as HANDLE,
    )?;
    clear(target_token.0)?;
    query_only_token(target_token.0)?;
    context.enter(Stage::Request, "read and validate holder request");
    let request = request(path)?;
    context.binding = Some(Binding {
        diagnostic_id: request.diagnostic_id.clone(),
        request_sha256: hex::encode(Sha256::digest(
            serde_json::to_vec(&request).map_err(|e| e.to_string())?,
        )),
    });
    context.enter(Stage::Deadlines, "validate original holder deadlines");
    let (_, cleanup) = deadlines(&request)?;
    context.enter(Stage::HolderToken, "query holder token and session");
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(context.native_error("OpenProcessToken holder"));
    }
    let token = Handle::new(raw)?;
    let envelope =
        memcordon_windows_launch_core::query_token_envelope(token.0).map_err(|e| e.to_string())?;
    if envelope.user_sid != "S-1-5-18"
        || envelope.session_id != request.reference_plan.target_token().session_id
    {
        return Err("holder native token/session mismatch".into());
    }
    context.enter(Stage::TargetToken, "query target token envelope");
    let target_envelope = memcordon_windows_launch_core::query_token_envelope(target_token.0)?;
    if target_envelope.session_id != envelope.session_id
        || memcordon_windows_launch_core::token_envelope_sha256(&target_envelope)?
            != request.reference_plan.target_token().envelope_sha256
    {
        return Err("holder target query capability envelope differs".into());
    }
    let binding = request.reference_plan.desktop();
    context.enter(Stage::StationSecurity, "parse station security");
    let station_sd = Security::from_sddl(&binding.window_station_security_descriptor_sddl)
        .map_err(|e| format!("station SDDL: {e:?}"))?;
    context.enter(Stage::DesktopSecurity, "parse desktop security");
    let desktop_sd = Security::from_sddl(&binding.desktop_security_descriptor_sddl)
        .map_err(|e| format!("desktop SDDL: {e:?}"))?;
    context.enter(Stage::StationSecurity, "derive station security attributes");
    let station_creation =
        memcordon_windows_loader_lab::holder_creation::CreationSecurity::new(&station_sd)?;
    let station_sa = station_creation.attributes();
    context.enter(Stage::DesktopSecurity, "derive desktop security attributes");
    let desktop_creation =
        memcordon_windows_loader_lab::holder_creation::CreationSecurity::new(&desktop_sd)?;
    let desktop_sa = desktop_creation.attributes();
    let name = desktop_name(&request);
    let (station_name, desktop_name) = name.split_once('\\').ok_or("invalid diagnostic desktop")?;
    context.enter(Stage::WindowStation, "create and select holder station");
    let original = unsafe { GetProcessWindowStation() };
    if original.is_null() {
        return Err(context.native_error("GetProcessWindowStation holder"));
    }
    context.enter(
        Stage::Privileges,
        "enter Security-only holder creation role",
    );
    let creation = memcordon_windows_loader_lab::holder_creation::SecurityCreationCarrier::enter(
        envelope.session_id,
    )?;
    context.enter(
        Stage::WindowStation,
        "CreateWindowStationW diagnostic holder",
    );
    let station_wide = wide(station_name);
    let station = unsafe {
        CreateWindowStationW(
            station_wide.as_ptr(),
            memcordon_windows_loader_lab::holder_creation::STATION_CREATE_ONLY,
            memcordon_windows_loader_lab::holder_creation::STATION_ACCESS,
            &station_sa,
        )
    };
    let station_status = unsafe { GetLastError() };
    if station.is_null() {
        let primary =
            context.native_status("CreateWindowStationW diagnostic holder", station_status);
        if let Err(error) = creation.finish() {
            context.cleanup.push(error);
        }
        return Err(primary);
    }
    if unsafe { SetProcessWindowStation(station) } == 0 {
        let primary = context.native_error("SetProcessWindowStation holder");
        if unsafe { CloseWindowStation(station) } == 0 {
            context
                .cleanup
                .push(error("CloseWindowStation after selection failure"));
        }
        if let Err(error) = creation.finish() {
            context.cleanup.push(error);
        }
        return Err(primary);
    }
    context.enter(Stage::Desktop, "CreateDesktopW diagnostic holder");
    let desktop_wide = wide(desktop_name);
    let desktop = unsafe {
        CreateDesktopW(
            desktop_wide.as_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            0x000f01ff,
            &desktop_sa,
        )
    };
    let desktop_status = unsafe { GetLastError() };
    let creation_restoration = creation.finish();
    let operation = (|| -> Result<(), String> {
        if desktop.is_null() {
            if let Err(error) = creation_restoration {
                context.cleanup.push(error);
            }
            return Err(context.native_status("CreateDesktopW diagnostic holder", desktop_status));
        }
        context.enter(Stage::Privileges, "restore holder primary after creation");
        creation_restoration?;
        context.enter(
            Stage::ObjectSecurity,
            "verify native user-object descriptors",
        );
        let station_observed = unsafe { selected_policy_native::read_user(station) };
        let desktop_observed = unsafe { selected_policy_native::read_user(desktop) };
        let station_expected = selected_policy_native::expected(&station_sd, 0x17)?;
        let desktop_expected = selected_policy_native::expected(&desktop_sd, 0x17)?;
        let station_observed = station_observed.map_err(|e| format!("station readback: {e}"))?;
        let desktop_observed = desktop_observed.map_err(|e| format!("desktop readback: {e}"))?;
        let station_policy = selected_policy::verify_and_fingerprint(
            Domain::Station,
            &station_expected,
            &station_observed,
        );
        let desktop_policy = selected_policy::verify_and_fingerprint(
            Domain::Desktop,
            &desktop_expected,
            &desktop_observed,
        );
        if station_policy.is_err() || desktop_policy.is_err() {
            // Both comparisons were performed. Keep each object's first field
            // facts within the existing finite holder failure-frame detail.
            let compact = |result: &Result<selected_policy::VerifiedPolicy, String>,
                           expected: &selected_policy::Snapshot,
                           actual: &selected_policy::Snapshot| {
                let fields = match result {
                    Ok(_) => "verified".to_owned(),
                    Err(error) => error.chars().take(80).collect::<String>(),
                };
                format!(
                    "{fields}; raw={}/{}",
                    expected.raw_sha256, actual.raw_sha256
                )
            };
            return Err(format!(
                "station={}; desktop={}",
                compact(&station_policy, &station_expected, &station_observed),
                compact(&desktop_policy, &desktop_expected, &desktop_observed)
            ));
        }
        let station_policy = station_policy?;
        let desktop_policy = desktop_policy?;
        context.enter(Stage::GateSecurity, "parse original gate security");
        let gate_name = request.descriptor["start_gate"]
            .as_str()
            .ok_or("fresh start gate absent")?;
        let gate_sddl = &request.gate_security_descriptor_sddl;
        let gate_sd =
            Security::from_sddl(gate_sddl).map_err(|e| format!("fresh gate security: {e:?}"))?;
        let gate_sa = gate_sd
            .security_attributes()
            .map_err(|e| format!("gate attributes: {e:?}"))?;
        context.enter(Stage::Privileges, "enter separate gate ownership carrier");
        let gate_privileges = Privileges::enter()?;
        context.enter(Stage::Gate, "CreateEventW target-session gate");
        let gate_wide = wide(gate_name);
        unsafe {
            SetLastError(0);
        }
        let raw_gate = unsafe { CreateEventW(&gate_sa, 1, 0, gate_wide.as_ptr()) };
        let gate_status = unsafe { GetLastError() };
        if raw_gate.is_null() {
            return Err(context.native_status("CreateEventW target-session gate", gate_status));
        }
        let gate = Handle::new(raw_gate)?;
        if gate_status == ERROR_ALREADY_EXISTS {
            context.native_code = Some(gate_status);
            return Err("fresh target-session diagnostic gate already exists".into());
        }
        context.enter(Stage::GateSecurity, "verify native gate security");
        let gate_expected = selected_policy_native::expected(&gate_sd, 7)?;
        let gate_observed = unsafe { selected_policy_native::read_gate(gate.0) }?;
        let gate_policy =
            selected_policy::verify_and_fingerprint(Domain::Gate, &gate_expected, &gate_observed)
                .map_err(|error| {
                format!(
                    "gate={}; raw={}/{}",
                    error.chars().take(80).collect::<String>(),
                    gate_expected.raw_sha256,
                    gate_observed.raw_sha256
                )
            })?;
        drop(gate_privileges);
        context.enter(Stage::Readiness, "publish holder readiness");
        let frame = Frame {
            schema_version: holder_protocol::FRAME_SCHEMA_VERSION,
            identity: identity.clone(),
            observed_request: context.binding.clone(),
            outcome: Outcome::Ready {
                policy: Box::new(ReadyPolicy {
                    session_id: envelope.session_id,
                    desktop: name,
                    station_sha256: station_observed.raw_sha256,
                    desktop_sha256: desktop_observed.raw_sha256,
                    station_policy,
                    desktop_policy,
                    gate: gate_name.into(),
                    gate_sddl: gate_sddl.clone(),
                    gate_sha256: gate_observed.raw_sha256,
                    gate_policy,
                    target_envelope_sha256: memcordon_windows_launch_core::token_envelope_sha256(
                        &target_envelope,
                    )?,
                }),
            },
        };
        let bytes = holder_protocol::encode(&frame)?;
        let mut count = 0;
        context.readiness_started = true;
        if unsafe {
            WriteFile(
                ready.0,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(context.native_error("WriteFile holder readiness"));
        }
        if count as usize != bytes.len() {
            return Err(format!(
                "holder readiness partial write: {count} of {}",
                bytes.len()
            ));
        }
        while Instant::now() < cleanup {
            let result = unsafe { WaitForSingleObject(stop.0, 25) };
            if result == WAIT_OBJECT_0 {
                return Ok(());
            }
            if result != WAIT_TIMEOUT {
                return Err(error("holder stop wait"));
            }
        }
        Err("holder original cleanup cutoff expired".into())
    })();
    if unsafe { SetProcessWindowStation(original) } == 0 {
        context.cleanup.push(error("restore holder station"));
    }
    if !desktop.is_null() && unsafe { CloseDesktop(desktop) } == 0 {
        context.cleanup.push(error("CloseDesktop holder"));
    }
    if unsafe { CloseWindowStation(station) } == 0 {
        context.cleanup.push(error("CloseWindowStation holder"));
    }
    if operation.is_ok() && !context.cleanup.is_empty() {
        context.enter(Stage::Cleanup, "retire holder user objects");
        return Err("holder user-object retirement failed".into());
    }
    operation
}

fn query_only_token(token: HANDLE) -> Result<(), String> {
    #[repr(C)]
    struct Basic {
        attributes: u32,
        access: u32,
        handles: u32,
        pointers: u32,
        reserved: [u32; 10],
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    let mut basic = Basic {
        attributes: 0,
        access: 0,
        handles: 0,
        pointers: 0,
        reserved: [0; 10],
    };
    let mut length = 0;
    let mut flags = 0;
    if unsafe { GetHandleInformation(token, &mut flags) } == 0
        || flags & HANDLE_FLAG_INHERIT != 0
        || unsafe {
            NtQueryObject(
                token,
                0,
                (&mut basic as *mut Basic).cast(),
                std::mem::size_of::<Basic>() as u32,
                &mut length,
            )
        } < 0
        || basic.access != TOKEN_QUERY
    {
        return Err("target query capability rights or inheritance differ".into());
    }
    let envelope = memcordon_windows_launch_core::query_token_envelope(token)?;
    if envelope.token_type != TokenPrimary as u32 {
        return Err("target query capability is not primary".into());
    }
    Ok(())
}

/// Only the initial debugger breakpoint is consumed; application exceptions retain dispatch.
pub fn exception_disposition(code: u32, first_chance: bool, initial_seen: &mut bool) -> u32 {
    if code == 0x8000_0003 && first_chance && !*initial_seen {
        *initial_seen = true;
        DBG_CONTINUE as u32
    } else {
        DBG_EXCEPTION_NOT_HANDLED as u32
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
enum DebugPhase {
    Work,
    Cleanup,
}
struct DebugOwner {
    pid: u32,
    attached: bool,
    pending: Option<(u32, u32, u32)>,
    initial_seen: bool,
    exit: Option<u32>,
    exit_phase: Option<DebugPhase>,
    events: Vec<Value>,
    event_bytes: usize,
    omitted: u64,
    creator: u32,
    verified_birth: Option<u64>,
    sequence: u64,
    modules: ModuleTable,
    module_queries: u64,
    incomplete_module_queries: u64,
    null_module_handles: u64,
    module_loads: u64,
    module_unloads: u64,
    uncorrelated_unloads: u64,
    untracked_loads: u64,
    incomplete_event_file_identity: u64,
    emergency_path: PathBuf,
    _thread: std::marker::PhantomData<std::rc::Rc<()>>,
}
impl DebugOwner {
    fn created(pid: u32, output: &Path) -> Self {
        Self {
            pid,
            attached: true,
            pending: None,
            initial_seen: false,
            exit: None,
            exit_phase: None,
            events: Vec::new(),
            event_bytes: 0,
            omitted: 0,
            creator: unsafe { GetCurrentThreadId() },
            verified_birth: None,
            sequence: 0,
            modules: ModuleTable::new(256),
            module_queries: 0,
            incomplete_module_queries: 0,
            null_module_handles: 0,
            module_loads: 0,
            module_unloads: 0,
            uncorrelated_unloads: 0,
            untracked_loads: 0,
            incomplete_event_file_identity: 0,
            emergency_path: output.join("incomplete-debug-owner.json"),
            _thread: std::marker::PhantomData,
        }
    }
    fn record(&mut self, value: Value) {
        let length = serde_json::to_vec(&value).map_or(usize::MAX, |bytes| bytes.len());
        if self.events.len() < EVENT_LIMIT && length <= LIMIT.saturating_sub(self.event_bytes) {
            self.event_bytes += length;
            self.events.push(value);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
    fn observe_module_load(
        &mut self,
        process: HANDLE,
        base: u64,
        event_file: HANDLE,
        cutoff: Instant,
    ) -> Value {
        self.module_loads = self.module_loads.saturating_add(1);
        let association = self.modules.load(base, self.sequence);
        if association.generation.is_none() {
            self.untracked_loads = self.untracked_loads.saturating_add(1);
        }
        let mut value = self.observe_module_identity(process, base, event_file, cutoff);
        value["base"] = json!(base);
        value["association"] = json!(association);
        value
    }
    fn observe_module_identity(
        &mut self,
        process: HANDLE,
        base: u64,
        event_file: HANDLE,
        cutoff: Instant,
    ) -> Value {
        let mut value =
            json!({"event_file_handle":if event_file.is_null(){"absent"}else{"present"}});
        if event_file.is_null() {
            self.null_module_handles = self.null_module_handles.saturating_add(1);
            self.module_queries = self.module_queries.saturating_add(1);
            let (observed, complete) =
                mapped_module_name(process, self.pid, self.verified_birth, base, cutoff);
            value["mapped_name"] = observed;
            if !complete {
                self.incomplete_module_queries = self.incomplete_module_queries.saturating_add(1);
            }
        } else {
            match Handle::new(event_file) {
                Ok(file) => {
                    let identity = file_identity(file.0);
                    if identity["native_identity_measured"] != true {
                        self.incomplete_event_file_identity =
                            self.incomplete_event_file_identity.saturating_add(1);
                    }
                    value["image"] = identity;
                }
                Err(error) => {
                    self.incomplete_event_file_identity =
                        self.incomplete_event_file_identity.saturating_add(1);
                    value["event_file_identity_error"] = json!(error);
                }
            }
        }
        value
    }
    fn module_coverage(&self) -> Value {
        json!({"load_events":self.module_loads,"unload_events":self.module_unloads,
            "null_event_file_handles":self.null_module_handles,"incomplete_event_file_identities":self.incomplete_event_file_identity,
            "mapped_name_queries":self.module_queries,"incomplete_mapped_name_queries":self.incomplete_module_queries,
            "uncorrelated_unloads":self.uncorrelated_unloads,"untracked_loads":self.untracked_loads,
            "module_table_unique_base_limit":256,"table_storage":"bounded metadata only; names remain in bounded event records",
            "module_evidence_capture_complete":self.omitted==0 && self.incomplete_module_queries==0 && self.uncorrelated_unloads==0 && self.untracked_loads==0 && self.incomplete_event_file_identity==0,
            "all_load_events_had_native_file_identity":self.null_module_handles==0 && self.incomplete_event_file_identity==0,
            "identity_limit":"mapped section paths are name observations, not reopened file identity or digest pins"})
    }
    fn continue_pending(&mut self) -> Result<(), String> {
        if self.creator != unsafe { GetCurrentThreadId() } {
            return Err("debug owner moved threads".into());
        }
        if let Some((pid, tid, disposition)) = self.pending {
            if unsafe { ContinueDebugEvent(pid, tid, disposition as i32) } == 0 {
                return Err(error("ContinueDebugEvent actual workload"));
            }
            self.pending = None;
        }
        Ok(())
    }
    fn poll(
        &mut self,
        process: HANDLE,
        cutoff: Instant,
        phase: DebugPhase,
    ) -> Result<bool, String> {
        self.poll_checked(process, cutoff, phase, |_, _| Ok(()))
    }
    fn poll_checked(
        &mut self,
        process: HANDLE,
        cutoff: Instant,
        phase: DebugPhase,
        observe_pending: impl FnOnce(&mut Self, &DEBUG_EVENT) -> Result<(), String>,
    ) -> Result<bool, String> {
        self.continue_pending()?;
        let mut event = DEBUG_EVENT::default();
        let remaining = cutoff
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(10) as u32;
        if unsafe { WaitForDebugEventEx(&mut event, remaining) } == 0 {
            if unsafe { GetLastError() } == ERROR_SEM_TIMEOUT {
                return Ok(false);
            }
            return Err(error("WaitForDebugEventEx actual workload"));
        }
        let mut disposition = DBG_CONTINUE as u32;
        if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT {
            let exception = unsafe { event.u.Exception };
            disposition = exception_disposition(
                exception.ExceptionRecord.ExceptionCode as u32,
                exception.dwFirstChance != 0,
                &mut self.initial_seen,
            );
        }
        self.pending = Some((event.dwProcessId, event.dwThreadId, disposition));
        self.sequence = self.sequence.saturating_add(1);
        let mut value = json!({"event":event.dwDebugEventCode,"event_kind":EventKind::from_code(event.dwDebugEventCode),"sequence":self.sequence,"pid":event.dwProcessId,"tid":event.dwThreadId,"disposition":disposition,"observation_phase":phase});
        if event.dwProcessId != self.pid {
            value["process_binding"] = json!("unexpected-process; no remote query performed");
            let file = match event.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => unsafe { event.u.CreateProcessInfo.hFile },
                LOAD_DLL_DEBUG_EVENT => unsafe { event.u.LoadDll.hFile },
                _ => ptr::null_mut(),
            };
            if !file.is_null() {
                value["event_file_close_request"] = json!(Handle::new(file).map(drop));
            }
            self.record(value);
            // Leave the exact pending event owned for bounded cleanup.
            return Err("debug event belongs to unexpected process".into());
        }
        // File handles are debugger-owned; event process/thread handles are closed
        // by Windows on the corresponding continued exit events.
        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let information = unsafe { event.u.CreateProcessInfo };
                let module = self.observe_module_load(
                    process,
                    information.lpBaseOfImage as usize as u64,
                    information.hFile,
                    cutoff,
                );
                value["base"] = module["base"].clone();
                if let Some(image) = module.get("image") {
                    value["image"] = image.clone();
                }
                value["module"] = module;
            }
            LOAD_DLL_DEBUG_EVENT => {
                let information = unsafe { event.u.LoadDll };
                let module = self.observe_module_load(
                    process,
                    information.lpBaseOfDll as usize as u64,
                    information.hFile,
                    cutoff,
                );
                value["base"] = module["base"].clone();
                if let Some(image) = module.get("image") {
                    value["image"] = image.clone();
                }
                value["module"] = module;
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let base = unsafe { event.u.UnloadDll.lpBaseOfDll } as usize as u64;
                self.module_unloads = self.module_unloads.saturating_add(1);
                let association = self.modules.unload(base, self.sequence);
                if association.outcome != module_observation::UnloadOutcome::Matched {
                    self.uncorrelated_unloads = self.uncorrelated_unloads.saturating_add(1);
                }
                value["base"] = json!(base);
                value["module_unload"] = json!(association);
            }
            EXCEPTION_DEBUG_EVENT => {
                let information = unsafe { event.u.Exception };
                value["code"] = json!(information.ExceptionRecord.ExceptionCode as u32);
                value["address"] =
                    json!(information.ExceptionRecord.ExceptionAddress as usize as u64);
                value["first_chance"] = json!(information.dwFirstChance != 0);
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let information = unsafe { event.u.DebugString };
                let units = usize::from(information.nDebugStringLength);
                let width = if information.fUnicode != 0 {
                    std::mem::size_of::<u16>()
                } else {
                    std::mem::size_of::<u8>()
                };
                let length = units.saturating_mul(width).min(2048);
                let mut bytes = vec![0_u8; length];
                let mut count = 0;
                let success = unsafe {
                    ReadProcessMemory(
                        process,
                        information.lpDebugStringData.cast(),
                        bytes.as_mut_ptr().cast(),
                        bytes.len(),
                        &mut count,
                    )
                } != 0;
                bytes.truncate(count.min(bytes.len()));
                value["read_complete"] = json!(success && count == length);
                value["unicode"] = json!(information.fUnicode != 0);
                value["bytes"] = json!(bytes);
                value["truncated"] = json!(units.saturating_mul(width) > length);
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                if event.dwProcessId == self.pid {
                    self.exit = Some(unsafe { event.u.ExitProcess.dwExitCode });
                    self.exit_phase = Some(phase);
                }
                value["native_exit"] = json!(unsafe { event.u.ExitProcess.dwExitCode });
            }
            _ => {}
        }
        let observation = observe_pending(self, &event);
        self.record(value);
        self.continue_pending()?;
        if self.exit.is_some() {
            self.attached = false;
        }
        observation?;
        Ok(true)
    }
    fn settle(&mut self, process: HANDLE, cutoff: Instant) -> Result<(), String> {
        self.continue_pending()?;
        while self.attached && Instant::now() < cutoff {
            self.poll(process, cutoff, DebugPhase::Cleanup)?;
        }
        if self.attached {
            if unsafe { DebugActiveProcessStop(self.pid) } == 0 {
                return Err(error("DebugActiveProcessStop after bounded retirement"));
            }
            self.attached = false;
            return Err("debug exit event not observed within original cleanup cutoff".into());
        }
        Ok(())
    }
}
impl Drop for DebugOwner {
    fn drop(&mut self) {
        if self.attached {
            // Never let a thread with an outstanding event return into SCM.
            // Process exit closes the retained kill-on-close Jobs as a final boundary.
            let retained = publish(
                &self.emergency_path,
                &json!({"format":"memcordon.workload-startup-diagnostic-incomplete-debug-owner","revision":1,"diagnostic_only":true,"certification_authority":false,"inconclusive":true,"original_failure_unchanged":true,"pid":self.pid,"creator_thread":self.creator,"pending":self.pending,"events":self.events,"omitted":self.omitted,"module_coverage":self.module_coverage(),"cleanup_complete":false}),
            );
            eprintln!(
                "workload diagnostic native debug ownership incomplete; emergency publication={retained:?}"
            );
            std::process::abort();
        }
    }
}
#[derive(serde::Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
enum MappedModuleObservation {
    SkippedDeadline {
        pid: u32,
        base: u64,
        name: module_observation::MappedName,
    },
    UnverifiedIdentity {
        pid: u32,
        base: u64,
        detail: &'static str,
    },
    IdentityQueryFailed {
        pid: u32,
        base: u64,
        expected_birth: u64,
        detail: String,
    },
    IdentityMismatch {
        pid: u32,
        base: u64,
        expected_birth: u64,
        observed_birth: u64,
    },
    ProcessMismatch {
        expected_pid: u32,
        observed_pid: u32,
        base: u64,
    },
    UnsupportedAddress {
        pid: u32,
        base: u64,
    },
    Queried {
        pid: u32,
        birth: u64,
        base: u64,
        name: module_observation::MappedName,
        completed_after_cutoff: bool,
    },
}

fn mapped_module_name(
    process: HANDLE,
    pid: u32,
    expected_birth: Option<u64>,
    base: u64,
    cutoff: Instant,
) -> (Value, bool) {
    const CAPACITY: usize = 4096;
    let skipped = || MappedModuleObservation::SkippedDeadline {
        pid,
        base,
        name: module_observation::MappedName::skipped_deadline(CAPACITY),
    };
    if Instant::now() >= cutoff {
        return (json!(skipped()), false);
    }
    let Some(expected_birth) = expected_birth else {
        return (
            json!(MappedModuleObservation::UnverifiedIdentity {
                pid,
                base,
                detail: "birth has not yet been verified; no remote mapping query performed"
            }),
            false,
        );
    };
    let observed_pid = unsafe { GetProcessId(process) };
    if observed_pid == 0 {
        return (
            json!(MappedModuleObservation::IdentityQueryFailed {
                pid,
                base,
                expected_birth,
                detail: error("GetProcessId held mapped-image process")
            }),
            false,
        );
    }
    if observed_pid != pid {
        return (
            json!(MappedModuleObservation::ProcessMismatch {
                expected_pid: pid,
                observed_pid,
                base
            }),
            false,
        );
    }
    match birth(process) {
        Err(detail) => {
            return (
                json!(MappedModuleObservation::IdentityQueryFailed {
                    pid,
                    base,
                    expected_birth,
                    detail
                }),
                false,
            );
        }
        Ok(observed_birth) if observed_birth != expected_birth => {
            return (
                json!(MappedModuleObservation::IdentityMismatch {
                    pid,
                    base,
                    expected_birth,
                    observed_birth
                }),
                false,
            );
        }
        Ok(_) => {}
    }
    if Instant::now() >= cutoff {
        return (json!(skipped()), false);
    }
    let Ok(address) = usize::try_from(base) else {
        return (
            json!(MappedModuleObservation::UnsupportedAddress { pid, base }),
            false,
        );
    };
    let mut buffer = [0_u16; CAPACITY];
    let returned = unsafe {
        K32GetMappedFileNameW(
            process,
            address as *const c_void,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    let native_error = if returned == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    let name = module_observation::classify_mapped_name(&buffer, returned, native_error);
    let completed_after_cutoff = Instant::now() >= cutoff;
    let complete =
        name.outcome == module_observation::MappedNameOutcome::Complete && !completed_after_cutoff;
    (
        json!(MappedModuleObservation::Queried {
            pid,
            birth: expected_birth,
            base,
            name,
            completed_after_cutoff
        }),
        complete,
    )
}

fn file_identity(handle: HANDLE) -> Value {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let mut path = vec![0_u16; 32768];
    let length = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_OPENED,
        )
    };
    let measured = unsafe { GetFileInformationByHandle(handle, &mut information) } != 0;
    let path = if length > 0 && (length as usize) < path.len() {
        String::from_utf16(&path[..length as usize]).ok()
    } else {
        None
    };
    json!({"path":path,"native_identity_measured":measured,"volume_serial":measured.then_some(information.dwVolumeSerialNumber),"file_id":measured.then_some((u64::from(information.nFileIndexHigh)<<32)|u64::from(information.nFileIndexLow))})
}
fn process_token(process: HANDLE) -> Result<Handle, String> {
    let mut raw = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(error("OpenProcessToken observed actual process"));
    }
    Handle::new(raw)
}
fn wait(process: HANDLE, cutoff: Instant) -> Result<(), String> {
    loop {
        let remaining = cutoff.saturating_duration_since(Instant::now());
        let milliseconds = remaining.as_millis().min(25) as u32;
        let result = unsafe { WaitForSingleObject(process, milliseconds) };
        if result == WAIT_OBJECT_0 {
            return Ok(());
        }
        if result != WAIT_TIMEOUT {
            return Err(error("WaitForSingleObject retained process"));
        }
        if Instant::now() >= cutoff {
            return Err("retained process did not settle under original cleanup cutoff".into());
        }
    }
}

fn run(path: &Path, input: &Request, source: HANDLE, work: Instant, cleanup: Instant) -> Value {
    let mut image_pin: Option<File> = None;
    let mut target: Option<Process> = None;
    let mut holder: Option<Process> = None;
    let mut debugger: Option<DebugOwner> = None;
    let mut target_job: Option<Job> = None;
    let mut holder_job: Option<Job> = None;
    let mut holder_stop: Option<Handle> = None;
    let mut measured = json!({});
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut stdout_omitted = 0;
    let mut stderr_omitted = 0;
    let mut streams: Option<(Handle, Handle, Handle)> = None;
    let primary = (|| -> Result<(), String> {
        live(work)?;
        input.validate()?;
        let creator = process_token(unsafe { GetCurrentProcess() })?;
        let creator_envelope = memcordon_windows_launch_core::query_token_envelope(creator.0)?;
        measured["creator"] = json!({"pid":unsafe { GetCurrentProcessId() },"birth":birth(unsafe { GetCurrentProcess() })?,"envelope_sha256":memcordon_windows_launch_core::token_envelope_sha256(&creator_envelope)?,"envelope":creator_envelope,"parent_context":"separate LocalSystem diagnostic service; binary/service SID differ from production launcher","literal_production_parent_equivalence":false});
        let _carrier = Privileges::enter()?;
        let token = restricted(source)?;
        let envelope = memcordon_windows_launch_core::query_token_envelope(token.0)?;
        let digest = memcordon_windows_launch_core::token_envelope_sha256(&envelope)?;
        measured["derived_envelope"] = json!(envelope);
        measured["derived_envelope_sha256"] = json!(digest);
        if digest != input.reference_plan.target_token().envelope_sha256
            || envelope.authentication_id != input.reference_plan.target_token().authentication_id
            || envelope.session_id != input.reference_plan.target_token().session_id
        {
            return Err(
                "fresh restricted token does not match full original envelope; inconclusive".into(),
            );
        }
        let image_path = PathBuf::from(OsString::from_wide(&input.command.program));
        // Keep this read-only pin live through target retirement; writers/deleters
        // are denied sharing rather than trusting a pathname after measurement.
        let mut pin = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&image_path)
            .map_err(|e| e.to_string())?;
        let metadata = pin.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file()
            || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || metadata.len() > 64 * 1024 * 1024
        {
            return Err("actual fixture image pin differs from bounded regular image".into());
        }
        let mut image = Vec::new();
        Read::by_ref(&mut pin)
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut image)
            .map_err(|e| e.to_string())?;
        if image.len() > 64 * 1024 * 1024
            || hex::encode(Sha256::digest(&image)) != input.image_sha256
        {
            return Err("actual fixture image hash differs".into());
        }
        let imports = memcordon_core::parse_windows_pe_imports(&image)?;
        let imports = json!({"machine":imports.machine,"normal_imports":imports.normal,"delayed_imports":imports.delayed});
        let import_bytes = serde_json::to_vec(&imports).map_err(|e| e.to_string())?;
        if import_bytes.len() > LIMIT {
            measured["actual_imports"] = json!({"retained":false,"encoded_bytes":import_bytes.len(),"sha256":hex::encode(Sha256::digest(&import_bytes)),"limit":LIMIT});
            return Err(
                "actual image import evidence exceeds finite byte bound; inconclusive".into(),
            );
        }
        measured["actual_image"] = json!({"path":image_path,"sha256":input.image_sha256,"identity":file_identity(pin.as_raw_handle()),"imports":imports});
        image_pin = Some(pin);
        let descriptor = read(&input.descriptor_path, 1024 * 1024)?;
        let descriptor: Value = serde_json::from_slice(&descriptor).map_err(|e| e.to_string())?;
        if descriptor != input.descriptor {
            return Err("fresh diagnostic descriptor bytes differ".into());
        }
        live(work)?;
        holder_job = Some(
            Job::create(input.reference_plan.job_security_descriptor_sddl())
                .map_err(|e| format!("holder Job: {e:?}"))?,
        );
        target_job = Some(
            Job::create(input.reference_plan.job_security_descriptor_sddl())
                .map_err(|e| format!("target Job: {e:?}"))?,
        );
        let system = system_for_session(envelope.session_id)?;
        let (ready_read, ready_write) = pipe()?;
        clear(ready_read.0)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: 1,
        };
        let stop = Handle::new(unsafe { CreateEventW(&attributes, 1, 0, ptr::null()) })?;
        let mut raw_query = ptr::null_mut();
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                token.0,
                GetCurrentProcess(),
                &mut raw_query,
                TOKEN_QUERY,
                1,
                0,
            )
        } == 0
        {
            return Err(error("duplicate inherited target query-only capability"));
        }
        let target_query = Handle::new(raw_query)?;
        let helper_image = std::env::current_exe().map_err(|e| e.to_string())?;
        let helper = memcordon_core::NativeWindowsCommandV1 {
            program: helper_image.as_os_str().encode_wide().collect(),
            arguments: vec![
                "workload-desktop-holder".encode_utf16().collect(),
                "--request".encode_utf16().collect(),
                path.as_os_str().encode_wide().collect(),
                "--ready".encode_utf16().collect(),
                (ready_write.0 as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect(),
                "--stop".encode_utf16().collect(),
                (stop.0 as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect(),
                "--target-token".encode_utf16().collect(),
                (target_query.0 as usize as u64)
                    .to_string()
                    .encode_utf16()
                    .collect(),
            ],
        };
        holder = Some(spawn(SpawnSpec {
            token: system.0,
            command: &helper,
            environment: &input.original_request.environment,
            cwd: &input.original_request.current_directory,
            desktop: None,
            job: holder_job.as_ref().expect("stored holder Job"),
            handles: &[ready_write.0, stop.0, target_query.0],
            standard: false,
            descriptors: None,
            cleanup,
            debug: DebugCreation::None,
        })?);
        drop(target_query);
        clear(stop.0)?;
        holder_stop = Some(stop);
        drop(ready_write);
        let held_holder = holder.as_mut().expect("stored holder");
        let resumed = resume(held_holder, "desktop-holder", "before-readiness", false)?;
        measured["holder_resume"] = serde_json::to_value(&resumed).map_err(|e| e.to_string())?;
        resumed.result.require_exact_one()?;
        let mut ready_bytes = Vec::new();
        let mut ready_omitted = 0;
        let expected_holder = memcordon_core::WindowsProcessIdentityV1 {
            process_id: held_holder.pid,
            creation_time_100ns: held_holder.birth,
        };
        let expected_request = Binding {
            diagnostic_id: input.diagnostic_id.clone(),
            request_sha256: hex::encode(Sha256::digest(
                serde_json::to_vec(input).map_err(|e| e.to_string())?,
            )),
        };
        let (frame, holder_ended, work_expired) = loop {
            let cutoff_error = live(work).err();
            drain_bounded(
                ready_read.0,
                &mut ready_bytes,
                &mut ready_omitted,
                holder_protocol::MAX_FRAME_BYTES + 1,
            )?;
            let state = unsafe { WaitForSingleObject(held_holder.process.0, 0) };
            if state != WAIT_TIMEOUT && state != WAIT_OBJECT_0 {
                return Err(error("query held holder readiness lifetime"));
            }
            let ended = state == WAIT_OBJECT_0;
            // Catch queued trailing bytes as well as the final write racing
            // exact held-process signaling. Two finite reads, no extra wait.
            drain_bounded(
                ready_read.0,
                &mut ready_bytes,
                &mut ready_omitted,
                holder_protocol::MAX_FRAME_BYTES + 1,
            )?;
            measured["holder_protocol"] = json!({"expected_identity":expected_holder,
                "expected_request":expected_request,"held_process_signaled":ended,
                "bytes":ready_bytes,"omitted_bytes":ready_omitted,
                "native_exit":if ended { Some(unsafe { holder_protocol::query_exit(held_holder.process.0) }.map_err(|e| e.to_string())) } else { None }});
            if ready_omitted != 0 {
                return Err("holder readiness exceeded bound".into());
            }
            if let Some(frame) = holder_protocol::decode_initial(
                &ready_bytes,
                &expected_holder,
                &expected_request,
                ended,
            )? {
                measured["holder_protocol"]["frame"] =
                    serde_json::to_value(&frame).map_err(|e| e.to_string())?;
                break (frame, ended, cutoff_error.is_some());
            }
            if let Some(error) = cutoff_error {
                return Err(error);
            }
            std::thread::sleep(Duration::from_millis(5));
        };
        let policy = holder_protocol::ready_policy(&frame, holder_ended, work_expired)?;
        for (domain, sddl, observed) in [
            (
                Domain::Station,
                input
                    .reference_plan
                    .desktop()
                    .window_station_security_descriptor_sddl
                    .as_str(),
                &policy.station_policy,
            ),
            (
                Domain::Desktop,
                input
                    .reference_plan
                    .desktop()
                    .desktop_security_descriptor_sddl
                    .as_str(),
                &policy.desktop_policy,
            ),
            (
                Domain::Gate,
                input.gate_security_descriptor_sddl.as_str(),
                &policy.gate_policy,
            ),
        ] {
            let descriptor =
                Security::from_sddl(sddl).map_err(|e| format!("bound expected policy: {e:?}"))?;
            let expected = selected_policy_native::expected(
                &descriptor,
                if domain == Domain::Gate { 7 } else { 0x17 },
            )?;
            selected_policy::validate_verified(domain, &expected, observed)?;
        }
        let mut readiness = serde_json::to_value(policy).map_err(|e| e.to_string())?;
        readiness["pid"] = json!(frame.identity.process_id);
        readiness["birth"] = json!(frame.identity.creation_time_100ns);
        let binding = frame
            .observed_request
            .ok_or("holder ready request binding absent")?;
        readiness["diagnostic_id"] = json!(binding.diagnostic_id);
        readiness["request_sha256"] = json!(binding.request_sha256);
        let request_hash = hex::encode(Sha256::digest(
            serde_json::to_vec(input).map_err(|e| e.to_string())?,
        ));
        if readiness["diagnostic_id"] != input.diagnostic_id
            || readiness["request_sha256"] != request_hash
            || readiness["pid"] != held_holder.pid
            || readiness["birth"] != held_holder.birth
            || readiness["session_id"] != envelope.session_id
            || readiness["desktop"] != desktop_name(input)
            || readiness["target_envelope_sha256"] != digest
            || readiness["gate"] != input.descriptor["start_gate"]
            || readiness["gate_sddl"] != input.gate_security_descriptor_sddl
        {
            return Err(
                "target-session holder readiness differs from held native identity or policy"
                    .into(),
            );
        }
        measured["holder"] = readiness;
        live(work)?;
        let (stdin_read, stdin_write) = pipe()?;
        clear(stdin_write.0)?;
        let (stdout_read, stdout_write) = pipe()?;
        clear(stdout_read.0)?;
        let (stderr_read, stderr_write) = pipe()?;
        clear(stderr_read.0)?;
        streams = Some((stdin_write, stdout_read, stderr_read));
        live(work)?;
        measured["target_creation_mode"] = json!({"debug_creation":"only-this-process","debugger_perturbation":true,"creator_thread":unsafe{GetCurrentThreadId()},"intended_creation_flags":DEBUG_ONLY_THIS_PROCESS|CREATE_SUSPENDED|EXTENDED_STARTUPINFO_PRESENT|CREATE_UNICODE_ENVIRONMENT|CREATE_NEW_PROCESS_GROUP});
        let spawned = spawn(SpawnSpec {
            token: token.0,
            command: &input.command,
            environment: &input.original_request.environment,
            cwd: &input.original_request.current_directory,
            desktop: Some(&desktop_name(input)),
            job: target_job.as_ref().expect("stored target Job"),
            handles: &[stdin_read.0, stdout_write.0, stderr_write.0],
            standard: true,
            descriptors: Some((
                input.reference_plan.process_security_descriptor_sddl(),
                input.reference_plan.thread_security_descriptor_sddl(),
            )),
            cleanup,
            debug: DebugCreation::OnlyThisProcess(&input.output_directory),
        });
        target = Some(match spawned {
            Ok(process) => process,
            Err(primary) => {
                let retained = read(
                    &input.output_directory.join("post-create-rollback.json"),
                    LIMIT * 2,
                )
                .and_then(|bytes| {
                    serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
                });
                measured["target_post_create_rollback"] = match retained {
                    Ok(value) => value,
                    Err(error) => {
                        json!({"retention_error":error,"meaning":"no rollback authority inferred"})
                    }
                };
                return Err(primary);
            }
        });
        debugger = target.as_mut().expect("stored target").debugger.take();
        let created = target.as_ref().expect("stored target");
        measured["target"] = json!({"pid":created.pid,"birth":created.birth,"creation_flags":created.creation_flags,"debug_creation":"only-this-process","debugger_perturbation":true,"post_create_image_and_token_checks":"not yet complete"});
        drop((stdin_read, stdout_write, stderr_write));
        let target = target.as_mut().expect("stored target");
        let mut observed_path = vec![0_u16; 32768];
        let mut length = observed_path.len() as u32;
        if unsafe {
            QueryFullProcessImageNameW(target.process.0, 0, observed_path.as_mut_ptr(), &mut length)
        } == 0
            || length as usize > observed_path.len()
        {
            return Err(error("QueryFullProcessImageNameW actual target"));
        }
        let observed_path = PathBuf::from(OsString::from_wide(&observed_path[..length as usize]));
        if observed_path.canonicalize().map_err(|e| e.to_string())?
            != image_path.canonicalize().map_err(|e| e.to_string())?
        {
            return Err("executing actual target path differs from measured image".into());
        }
        let actual_token = process_token(target.process.0)?;
        let actual_envelope = memcordon_windows_launch_core::query_token_envelope(actual_token.0)?;
        if memcordon_windows_launch_core::token_envelope_sha256(&actual_envelope)? != digest {
            return Err("actual process primary token envelope differs".into());
        }
        measured["target"] = json!({"pid":target.pid,"birth":target.birth,"new_identity":true,"creation_flags":target.creation_flags,"debug_creation":"only-this-process","stdio_roles":["stdin","stdout","stderr"],"stdin":"empty-live-pipe","actual_envelope":actual_envelope,"desktop":desktop_name(input),"debugger_perturbation":true});
        let resumed = resume(
            target,
            "actual-workload-target",
            "debug-at-creation-before-single-resume",
            true,
        )?;
        measured["target_resume"] = serde_json::to_value(&resumed).map_err(|e| e.to_string())?;
        resumed.result.require_exact_one()?;
        loop {
            live(work)?;
            let (_, output, errors) = streams.as_ref().expect("retained stream owners");
            drain(output.0, &mut stdout, &mut stdout_omitted)?;
            drain(errors.0, &mut stderr, &mut stderr_omitted)?;
            let owner = debugger.as_mut().expect("retained debug owner");
            owner.poll(target.process.0, work, DebugPhase::Work)?;
            if owner.omitted > 0 {
                return Err(
                    "finite debug event count or encoded-byte bound exhausted; inconclusive".into(),
                );
            }
            if owner.exit.is_some() {
                break;
            }
            let transcript = input.descriptor["transcript"]
                .as_str()
                .ok_or("fresh transcript absent")?;
            if Path::new(transcript)
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                let bytes = read(Path::new(transcript), LIMIT)?;
                if !bytes.is_empty() {
                    measured["fixture_entry"] = json!({"observed":true,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes)),"meaning":"initialization progressed; original failure not reproduced"});
                    break;
                }
            }
        }
        // Keep immutable image custody until the process/Job cleanup below.
        measured["image_pin_held_during_observation"] = json!(true);
        Ok(())
    })();
    let mut cleanup_errors = Vec::new();
    if let Some(job) = &target_job {
        measured["target_termination_request"] = json!({"requested":true,"phase":"cleanup","reason":"diagnostic cleanup","code":FAILURE,"target":target.as_ref().map(|process|json!({"pid":process.pid,"birth":process.birth})),"meaning":"request provenance, not proof of a natural startup exit"});
        if let Err(e) = job.terminate(FAILURE) {
            measured["target_termination_request"]["native_result"] = json!(format!("{e:?}"));
            cleanup_errors.push(format!("target Job termination: {e:?}"));
        } else {
            measured["target_termination_request"]["native_result"] = json!("success");
        }
    }
    if let (Some(owner), Some(process)) = (debugger.as_mut(), target.as_ref()) {
        if let Err(e) = owner.settle(process.process.0, cleanup) {
            cleanup_errors.push(e);
        }
    }
    if let Some(process) = &target {
        if let Err(e) = wait(process.process.0, cleanup) {
            cleanup_errors.push(e);
        }
    }
    let mut holder_forced = false;
    if let Some(stop) = &holder_stop {
        if unsafe { SetEvent(stop.0) } == 0 {
            cleanup_errors.push(error("signal holder stop"));
        }
    }
    if let Some(process) = &holder {
        let remaining = cleanup
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(25) as u32;
        let orderly = unsafe { WaitForSingleObject(process.process.0, remaining) } == WAIT_OBJECT_0;
        if !orderly {
            holder_forced = true;
            if let Some(job) = &holder_job {
                measured["holder_termination_request"] = json!({"requested":true,"phase":"cleanup","reason":"holder did not retire orderly","code":FAILURE,"pid":process.pid,"birth":process.birth});
                if let Err(e) = job.terminate(FAILURE) {
                    cleanup_errors.push(format!("holder Job termination: {e:?}"));
                }
            }
        }
        if let Err(e) = wait(process.process.0, cleanup) {
            cleanup_errors.push(e);
        }
        if orderly {
            match unsafe { holder_protocol::query_exit(process.process.0) } {
                Err(error) => cleanup_errors.push(error.to_string()),
                Ok(0) => {}
                Ok(code) => {
                    cleanup_errors.push(format!("holder orderly retirement native exit={code}"))
                }
            }
        }
    } else if let Some(job) = &holder_job {
        measured["holder_termination_request"] = json!({"requested":true,"phase":"cleanup","reason":"partial holder creation","code":FAILURE});
        if let Err(e) = job.terminate(FAILURE) {
            cleanup_errors.push(format!("partial holder Job termination: {e:?}"));
        }
    }
    for (name, job) in [("target", &target_job), ("holder", &holder_job)] {
        if let Some(job) = job {
            match job.wait_empty(cleanup) {
                Ok(true) => {}
                other => cleanup_errors.push(format!("{name} Job empty: {other:?}")),
            }
        }
    }
    if let Some((_, output, errors)) = &streams {
        if let Err(e) = drain(output.0, &mut stdout, &mut stdout_omitted) {
            cleanup_errors.push(e);
        }
        if let Err(e) = drain(errors.0, &mut stderr, &mut stderr_omitted) {
            cleanup_errors.push(e);
        }
    }
    let debug = debugger.as_ref().map(|owner| json!({"events":owner.events,"encoded_event_bytes":owner.event_bytes,"encoded_event_limit":LIMIT,"event_count_limit":EVENT_LIMIT,"omitted":owner.omitted,"module_coverage":owner.module_coverage(),"native_exit":owner.exit,"exit_observation_phase":owner.exit_phase,"exit_provenance_limit":"cleanup-phase events may follow diagnostic termination; observation phase does not establish when or why native exit occurred","creator_thread":owner.creator,"attached":owner.attached,"pending":owner.pending.is_some()}));
    let work_exit = debugger.as_ref().and_then(|owner| {
        if matches!(owner.exit_phase, Some(DebugPhase::Work)) {
            owner.exit
        } else {
            None
        }
    });
    measured["startup_evidence"] = json!({"fixture_entry_observed":measured["fixture_entry"]["observed"]==true,"work_exit":work_exit,
        "interpretation":if measured["fixture_entry"]["observed"]==true {"fixture-entry-observed"}else if work_exit.is_some(){"work-exit-without-observed-fixture-entry"}else{"startup-not-established"},
        "authority":"diagnostic-only; successful collection is not successful target startup"});
    drop(image_pin);
    json!({"format":"memcordon.workload-startup-diagnostic","revision":1,"diagnostic_only":true,"certification_authority":false,"inconclusive":true,"original_failure_unchanged":true,"original_result_sha256":input.original_result_sha256,"original_pid":input.original_pid,"original_birth":input.original_birth,"diagnostic_id":input.diagnostic_id,"observation":measured,"operation":primary,"cleanup":{"complete":cleanup_errors.is_empty(),"holder_forced":holder_forced,"errors":cleanup_errors},"debug":debug,"stdout":stdout,"stderr":stderr,"stdout_omitted":stdout_omitted,"stderr_omitted":stderr_omitted})
}

struct ServiceArguments {
    name: Vec<u16>,
    request: PathBuf,
    result: PathBuf,
    source: usize,
}
static SERVICE: OnceLock<ServiceArguments> = OnceLock::new();
unsafe extern "system" fn service_control(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        STOP.store(true, Ordering::Release);
    }
}
unsafe extern "system" fn service_main(_count: u32, _arguments: *mut *mut u16) {
    let Some(arguments) = SERVICE.get() else {
        return;
    };
    let status_handle =
        unsafe { RegisterServiceCtrlHandlerW(arguments.name.as_ptr(), Some(service_control)) };
    if status_handle.is_null() {
        return;
    }
    let running = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: SERVICE_ACCEPT_STOP,
        ..SERVICE_STATUS::default()
    };
    if unsafe { SetServiceStatus(status_handle, &running) } == 0 {
        return;
    }
    let outcome = (|| -> Result<(), String> {
        let input = request(&arguments.request)?;
        let (work, cleanup) = deadlines(&input)?;
        let observation = run(
            &arguments.request,
            &input,
            arguments.source as HANDLE,
            work,
            cleanup,
        );
        publish(&arguments.result, &observation)
    })();
    if let Err(error) = &outcome {
        let _ = publish(
            &arguments.result,
            &json!({"format":"memcordon.workload-startup-diagnostic","revision":1,"diagnostic_only":true,"certification_authority":false,"inconclusive":true,"error":error,"original_failure_unchanged":true}),
        );
    }
    let stopped = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STOPPED,
        dwWin32ExitCode: if outcome.is_ok() { 0 } else { 1 },
        ..SERVICE_STATUS::default()
    };
    unsafe {
        SetServiceStatus(status_handle, &stopped);
    }
}

pub fn run_as_service(
    name: &str,
    request: &Path,
    result: &Path,
    source_pid: u32,
    source_birth: u64,
    source_token: u64,
) -> Result<(), String> {
    if source_pid == 0 || source_birth == 0 || name.is_empty() || name.contains('\0') {
        return Err("diagnostic source/service identity absent".into());
    }
    let process = Handle::new(unsafe {
        OpenProcess(
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            source_pid,
        )
    })?;
    if birth(process.0)? != source_birth {
        return Err("diagnostic source process birth differs".into());
    }
    let source =
        usize::try_from(source_token).map_err(|_| "source token handle overflow")? as HANDLE;
    let mut local = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            process.0,
            source,
            GetCurrentProcess(),
            &mut local,
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            0,
            0,
        )
    } == 0
    {
        return Err(error("DuplicateHandle held diagnostic source token"));
    }
    let token = Handle::new(local)?;
    if birth(process.0)? != source_birth {
        return Err("diagnostic source changed during token transfer".into());
    }
    SERVICE
        .set(ServiceArguments {
            name: wide(name),
            request: request.to_owned(),
            result: result.to_owned(),
            source: token.0 as usize,
        })
        .map_err(|_| "diagnostic service already initialized")?;
    let arguments = SERVICE.get().expect("service arguments stored");
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: arguments.name.as_ptr().cast_mut(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(error("StartServiceCtrlDispatcherW workload"));
    }
    drop(token);
    drop(process);
    Ok(())
}

#[cfg(test)]
#[path = "../tests/support/workload_native.rs"]
mod tests;
