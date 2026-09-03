use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use memcordon_core::{
    NativeWindowsCommandV1, WindowsCallerTokenEnvelopeV1, WindowsEnvironmentEntryV1,
    WindowsProcessIdentityV1, WindowsRemoteStreamV1, WindowsSealedFault, WindowsSealedMutant,
    WindowsStreamRoleV1,
};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_HANDLE,
    ERROR_PATH_NOT_FOUND, FILETIME, GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, EqualSid, FreeSid, LookupAccountNameW, LookupAccountSidW, RevertToSelf,
    SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_NAME_USE, SecurityImpersonation, SidTypeUser,
    TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
    TokenImpersonation,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR,
    GetFileType, OPEN_EXISTING,
};
use windows_sys::Win32::System::Console::{
    STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
    GetNamedPipeServerSessionId,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_USERS, KEY_READ, RegCloseKey, RegOpenKeyExW,
};
use windows_sys::Win32::System::Services::{
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STOP,
    SERVICE_STOPPED,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    UOI_FLAGS, UOI_IO, UOI_NAME, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
    CreateProcessAsUserW, CreateProcessW, DEBUG_ONLY_THIS_PROCESS, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentThread, GetCurrentThreadId,
    GetExitCodeProcess, GetProcessId, GetProcessIdOfThread, GetProcessTimes,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess, OpenProcessToken,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, ResumeThread,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, SetThreadToken, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use super::job::Job;
use super::pipe::{OwnedHandle, PipeListener};
use super::security::SecurityDescriptor;
use super::user_api::{
    close_desktop as CloseDesktop, close_window_station as CloseWindowStation,
    create_desktop_w as CreateDesktopW, create_window_station_w as CreateWindowStationW,
    enum_desktops_w as EnumDesktopsW, get_process_window_station as GetProcessWindowStation,
    get_thread_desktop as GetThreadDesktop,
    get_user_object_information_w as GetUserObjectInformationW, open_desktop_w as OpenDesktopW,
    open_window_station_w as OpenWindowStationW,
    set_process_window_station as SetProcessWindowStation, set_thread_desktop as SetThreadDesktop,
};

const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const WINSTA_READATTRIBUTES_ACCESS: u32 = 0x0000_0002;
const DESKTOP_READOBJECTS_ACCESS: u32 = 0x0000_0001;
const TARGET_STATION_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | WINSTA_READATTRIBUTES_ACCESS;
const TARGET_DESKTOP_ATTEST_ACCESS: u32 = READ_CONTROL_ACCESS | DESKTOP_READOBJECTS_ACCESS;
const TARGET_TOKEN_CAPABILITY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE;
const MAXIMUM_ALLOWED_ACCESS: u32 = 0x0200_0000;
const TOKEN_ATTESTATION_QUERY_ACCESS: u32 = TOKEN_QUERY | TOKEN_QUERY_SOURCE;
const GUARDIAN_PIPE_CLOSE_EXIT_GRACE_MILLIS: u32 = 250;
const IMPERSONATION_REVERT_FAILURE_STATUS: u32 = 0xC000_013A;
const TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS: u32 = 0xED14_0000;
const TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION: u32 = 18;
const TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES: usize = 1_024;
const TARGET_DESKTOP_NONCE_BYTES: usize = 32;
const TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT: Duration = Duration::from_secs(180);
const TARGET_ASSOCIATION_PREFLIGHT_MAX_PROGRESS_FRAMES: u32 = 4_096;
const CWF_CREATE_ONLY_FLAG: u32 = 0x0000_0001;
const UOI_HEAPSIZE_CLASS: i32 = 5;
const LOADER_ENVIRONMENT_MAX_UNITS: usize = 32_767;
const LOADER_REQUIRED_ENVIRONMENT_KEYS: [&str; 3] = ["SystemDrive", "SystemRoot", "windir"];
const STATUS_DLL_INIT_FAILED: i32 = 0xC000_0142_u32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xC000_0022_u32 as i32;

#[link(name = "userenv")]
unsafe extern "system" {
    fn CreateEnvironmentBlock(environment: *mut *mut c_void, token: HANDLE, inherit: i32) -> i32;
    fn DestroyEnvironmentBlock(environment: *const c_void) -> i32;
    fn GetUserProfileDirectoryW(token: HANDLE, profile: *mut u16, size: *mut u32) -> i32;
    fn LoadUserProfileW(token: HANDLE, profile: *mut ProfileInfoW) -> i32;
    fn UnloadUserProfile(token: HANDLE, profile: HANDLE) -> i32;
}

#[repr(C)]
struct ProfileInfoW {
    size: u32,
    flags: u32,
    user_name: *mut u16,
    profile_path: *mut u16,
    default_path: *mut u16,
    server_name: *mut u16,
    policy_path: *mut u16,
    profile: HANDLE,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetProcessMitigationPolicy(
        process: HANDLE,
        policy: i32,
        buffer: *mut c_void,
        length: usize,
    ) -> i32;
}
pub const fn target_desktop_bootstrap_failure_status() -> i32 {
    TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS as i32
}

struct ThreadImpersonationGuard {
    active: bool,
}

impl ThreadImpersonationGuard {
    fn install(token: HANDLE) -> Result<Self, io::Error> {
        // SAFETY: a null thread pointer selects this worker thread and token is
        // a live impersonation token retained by the caller.
        if unsafe { SetThreadToken(ptr::null(), token) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self { active: true })
        }
    }

    fn revert(mut self) -> Result<(), io::Error> {
        // SAFETY: this guard owns the successful impersonation installed on
        // the current worker thread.
        if unsafe { RevertToSelf() } == 0 {
            Err(io::Error::last_os_error())
        } else {
            self.active = false;
            Ok(())
        }
    }
}

impl Drop for ThreadImpersonationGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // A worker that cannot restore its restricted service identity must
        // never continue with caller authority. Retry once for unwind safety;
        // if the kernel still refuses, terminate the service process so the
        // independent guardian owns fail-closed attempt cleanup.
        if unsafe { RevertToSelf() } == 0 {
            unsafe {
                TerminateProcess(GetCurrentProcess(), IMPERSONATION_REVERT_FAILURE_STATUS);
            }
            std::process::abort();
        }
        self.active = false;
    }
}

#[derive(Debug)]
struct UserObjectQueryError {
    native_code: Option<i32>,
    detail: String,
}

impl UserObjectQueryError {
    fn native(detail: &'static str) -> Self {
        Self::from_io(detail, io::Error::last_os_error())
    }

    fn from_io(detail: &'static str, error: io::Error) -> Self {
        Self {
            native_code: error.raw_os_error(),
            detail: format!("{detail}: {error}"),
        }
    }

    fn contract(detail: impl Into<String>) -> Self {
        Self {
            native_code: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for UserObjectQueryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianLoaderPreparationSubphase {
    DesktopStationCapture,
    DesktopCapture,
    DesktopNameReadback,
    DesktopAttestation,
    StandardInput,
    StandardOutput,
    StandardError,
    HandleList,
}

impl GuardianLoaderPreparationSubphase {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::DesktopStationCapture => "desktop-station-capture",
            Self::DesktopCapture => "desktop-capture",
            Self::DesktopNameReadback => "desktop-name-readback",
            Self::DesktopAttestation => "desktop-attestation",
            Self::StandardInput => "standard-input-preparation",
            Self::StandardOutput => "standard-output-preparation",
            Self::StandardError => "standard-error-preparation",
            Self::HandleList => "loader-handle-list",
        }
    }
}

#[derive(Debug)]
pub(crate) struct GuardianLoaderPreparationError {
    pub(crate) subphase: GuardianLoaderPreparationSubphase,
    pub(crate) native_code: Option<i32>,
    detail: String,
}

impl GuardianLoaderPreparationError {
    fn native(subphase: GuardianLoaderPreparationSubphase, detail: &'static str) -> Self {
        let error = io::Error::last_os_error();
        Self {
            subphase,
            native_code: error.raw_os_error(),
            detail: format!("{detail}: {error}"),
        }
    }

    fn contract(subphase: GuardianLoaderPreparationSubphase, detail: impl Into<String>) -> Self {
        Self {
            subphase,
            native_code: None,
            detail: detail.into(),
        }
    }

    fn from_user_object(
        subphase: GuardianLoaderPreparationSubphase,
        error: UserObjectQueryError,
    ) -> Self {
        Self {
            subphase,
            native_code: error.native_code,
            detail: error.detail,
        }
    }
}

impl std::fmt::Display for GuardianLoaderPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "loader_context={} detail={}",
            self.subphase.name(),
            self.detail
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GuardianBootstrapOutcome {
    ChildRejected,
    ChannelClosedWhileLive,
    WaitFailed,
    Timeout,
    ProtocolViolation,
    LauncherFailure,
}

impl GuardianBootstrapOutcome {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ChildRejected => "child-rejection",
            Self::ChannelClosedWhileLive => "bootstrap-channel-closed-while-guardian-live",
            Self::WaitFailed => "bootstrap-process-wait-failed",
            Self::Timeout => "bootstrap-frame-timeout",
            Self::ProtocolViolation => "bootstrap-protocol-violation",
            Self::LauncherFailure => "launcher-failure",
        }
    }
}

#[derive(Debug)]
pub(crate) struct GuardianBootstrapError {
    pub(crate) outcome: GuardianBootstrapOutcome,
    pub(crate) loader_subphase: Option<GuardianLoaderPreparationSubphase>,
    pub(crate) subphase: super::guardian::GuardianStartupSubphase,
    pub(crate) role: Option<super::guardian::GuardianHandleRole>,
    pub(crate) native_code: Option<i32>,
    pub(crate) exit_code: Option<u32>,
    pub(crate) guardian_identity: Option<WindowsProcessIdentityV1>,
    pub(crate) elapsed_millis: u64,
    pub(crate) detail: String,
}

impl GuardianBootstrapError {
    fn launcher(detail: String) -> Self {
        Self {
            outcome: GuardianBootstrapOutcome::LauncherFailure,
            loader_subphase: None,
            subphase: super::guardian::GuardianStartupSubphase::BootstrapChannel,
            role: None,
            native_code: None,
            exit_code: None,
            guardian_identity: None,
            elapsed_millis: 0,
            detail,
        }
    }

    fn loader(error: GuardianLoaderPreparationError) -> Self {
        Self {
            outcome: GuardianBootstrapOutcome::LauncherFailure,
            loader_subphase: Some(error.subphase),
            subphase: super::guardian::GuardianStartupSubphase::LoaderContext,
            role: None,
            native_code: error.native_code,
            exit_code: None,
            guardian_identity: None,
            elapsed_millis: 0,
            detail: error.detail,
        }
    }

    fn observed(
        outcome: GuardianBootstrapOutcome,
        identity: &WindowsProcessIdentityV1,
        started: Instant,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            outcome,
            loader_subphase: None,
            subphase: super::guardian::GuardianStartupSubphase::BootstrapChannel,
            role: None,
            native_code: None,
            exit_code: None,
            guardian_identity: Some(identity.clone()),
            elapsed_millis: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            detail: detail.into(),
        }
    }
}

impl From<String> for GuardianBootstrapError {
    fn from(detail: String) -> Self {
        Self::launcher(detail)
    }
}

impl std::fmt::Display for GuardianBootstrapError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "outcome={} loader_context={} subphase={} role={} elapsed_millis={} exit_code={} detail={}",
            self.outcome.name(),
            self.loader_subphase
                .map_or("none", GuardianLoaderPreparationSubphase::name),
            self.subphase.name(),
            self.role
                .map_or("none", super::guardian::GuardianHandleRole::name),
            self.elapsed_millis,
            self.exit_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

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

fn verify_inheritable(handle: HANDLE) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is owned by the caller and flags is writable output.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else if flags & HANDLE_FLAG_INHERIT == 0 {
        Err("guardian manifest handle is not inheritable".to_owned())
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

fn duplicate_remote_token_query(handle: HANDLE, process: HANDLE) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: handle is a live launcher token-attestation capability and process is
    // the suspended authenticated bootstrap. The remote copy receives exactly
    // the exact query rights needed for TokenSource evidence and is deliberately
    // non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            TOKEN_ATTESTATION_QUERY_ACCESS,
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

fn duplicate_remote_target_token_capability(
    handle: HANDLE,
    process: HANDLE,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: the target token and suspended authenticated holder are live.
    // The holder receives only the rights needed for envelope inspection,
    // AccessCheck, and duplication of its own explicit impersonation token.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            TARGET_TOKEN_CAPABILITY_ACCESS,
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
    close_remote_native(
        super::session_broker::decode_protocol_handle(handle, "remote-revocation")?,
        process,
    )
}

pub(crate) fn revoke_remote_native_handle(
    remote_handle: HANDLE,
    process: HANDLE,
) -> Result<(), String> {
    if remote_handle.is_null() || remote_handle == INVALID_HANDLE_VALUE {
        return Err("remote-revocation native handle is invalid".to_owned());
    }
    close_remote_native(remote_handle, process)
}

fn close_remote_native(handle: HANDLE, process: HANDLE) -> Result<(), String> {
    let mut local = ptr::null_mut();
    // SAFETY: process is the live recipient process and handle is a value that
    // this process transferred into it. CLOSE_SOURCE revokes that exact
    // pre-delivery value; the returned local duplicate is immediately owned
    // and closed.
    if unsafe {
        DuplicateHandle(
            process,
            handle,
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

fn duplicate_local_handle_with_access(
    source: HANDLE,
    requested_access: u32,
    expected_granted_access: u32,
    role: &str,
) -> Result<OwnedHandle, String> {
    let mut duplicate = ptr::null_mut();
    // SAFETY: source is live; the current process receives a non-inheritable
    // duplicate with the exact requested access.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            GetCurrentProcess(),
            &raw mut duplicate,
            requested_access,
            0,
            0,
        )
    } == 0
    {
        return Err(format!(
            "cannot narrow {role} handle: {}",
            io::Error::last_os_error()
        ));
    }
    let duplicate = OwnedHandle::new(duplicate)?;
    let mut flags = 0_u32;
    // SAFETY: duplicate is live and flags is writable output.
    if unsafe { GetHandleInformation(duplicate.raw(), &raw mut flags) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let inherited = flags & HANDLE_FLAG_INHERIT != 0;
    let actual_granted_access = super::token::granted_handle_access(duplicate.raw())?;
    if inherited || actual_granted_access != expected_granted_access {
        return Err(format!(
            "role={role} operation=duplicate requested_access={requested_access:#010x} expected_granted_access={expected_granted_access:#010x} actual_granted_access={actual_granted_access:#010x} flags={flags:#010x} inherited={inherited}"
        ));
    }
    Ok(duplicate)
}

pub(crate) struct SessionBrokerCreatedHolder {
    _job: OwnedHandle,
    pub process: OwnedHandle,
    pub thread: OwnedHandle,
    pub primary_thread_id: u32,
    pub identity: WindowsProcessIdentityV1,
    pub query: super::token::TokenQueryAttestationSnapshot,
    pub broker_source: super::token::TokenAttestationSnapshot,
    pub holder_effective: super::token::TokenAttestationSnapshot,
    pub station_creation_carrier: OwnedHandle,
    pub station_creation_evidence: super::token::TokenAttestationSnapshot,
    pub desktop_creation_carrier: OwnedHandle,
    pub desktop_creation_evidence: super::token::TokenAttestationSnapshot,
    armed: bool,
}

impl SessionBrokerCreatedHolder {
    pub(crate) fn terminate(&mut self) {
        if self.armed {
            // SAFETY: process is the broker-created suspended holder. Failure
            // paths must not leave it alive in the launcher-owned Job.
            unsafe {
                TerminateProcess(self.process.raw(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
            };
            self.armed = false;
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SessionBrokerCreatedHolder {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub(crate) fn create_session_broker_holder(
    target_session_id: u32,
    holder_pipe_name: &str,
    holder_nonce: &str,
    launcher_process: HANDLE,
    launcher_job_handle: u64,
) -> Result<SessionBrokerCreatedHolder, String> {
    validate_target_desktop_bootstrap_nonce(holder_nonce)?;
    let expected_pipe_name = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        holder_nonce,
    );
    if target_session_id == 0 || holder_pipe_name != expected_pipe_name || launcher_job_handle == 0
    {
        return Err("session-broker holder launch request is not canonical".to_owned());
    }

    let mut local_job = ptr::null_mut();
    // SAFETY: launcher_process was authenticated with PROCESS_DUP_HANDLE and
    // launcher_job_handle is treated only as a value in that process. The
    // broker receives the exact minimal assignment/query capability.
    if unsafe {
        DuplicateHandle(
            launcher_process,
            super::session_broker::decode_protocol_handle(launcher_job_handle, "launcher-job")?,
            GetCurrentProcess(),
            &raw mut local_job,
            super::session_broker::HOLDER_JOB_BROKER_ACCESS,
            0,
            0,
        )
    } == 0
    {
        return Err(format!(
            "cannot adopt launcher session-holder Job capability: {}",
            io::Error::last_os_error(),
        ));
    }
    let local_job = OwnedHandle::new(local_job)?;
    verify_not_inheritable(local_job.raw())?;
    if super::token::granted_handle_access(local_job.raw())?
        != super::session_broker::HOLDER_JOB_BROKER_ACCESS
    {
        return Err("session-broker Job capability access differs from contract".to_owned());
    }
    Job::verify_session_holder_handle(local_job.raw())?;
    Job::verify_session_holder_empty_handle(local_job.raw())?;

    let holder_token = super::token::derive_session_broker_holder_primary(target_session_id)?;
    let holder_launch_before =
        super::token::token_attestation_snapshot(holder_token.launch_token.raw())?;
    super::token::require_same_token_instance(
        "session-broker-holder-final-to-launch",
        &holder_token.holder_effective,
        &holder_launch_before,
    )
    .map_err(|error| error.to_string())?;
    let executable = super::package::installed_target_desktop_bootstrap();
    let _image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
    use std::os::windows::ffi::OsStrExt;
    let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    application.push(0);
    let mut command_line = encode_command_line(&[
        executable.as_os_str().encode_wide().collect(),
        "holder".encode_utf16().collect(),
        holder_pipe_name.encode_utf16().collect(),
        holder_nonce.encode_utf16().collect(),
    ]);
    command_line.push(0);
    let jobs = [local_job.raw()];
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            jobs.as_ptr().cast(),
            std::mem::size_of_val(&jobs),
        )],
        None,
    )?;
    let process_security =
        SecurityDescriptor::from_sddl(&super::security::session_holder_process_sddl()?)?;
    let process_attributes = process_security.attributes(false);
    let thread_security =
        SecurityDescriptor::from_sddl(&super::security::session_holder_thread_sddl()?)?;
    let thread_attributes = thread_security.attributes(false);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    // Empty, rather than NULL, prevents the target-session holder from
    // inheriting the session-0 broker's USER objects. The nonce-private
    // station does not exist yet: after admission the holder must create it
    // before observing any ambient station or desktop binding.
    let mut empty_desktop = [0_u16];
    startup.StartupInfo.lpDesktop = empty_desktop.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut environment = [0_u16, 0_u16];
    let mut current_directory = super::package::install_root()
        .as_os_str()
        .encode_wide()
        .collect::<Vec<_>>();
    current_directory.push(0);
    let mut created = PROCESS_INFORMATION::default();
    super::token::with_session_broker_launch_privileges(|| {
        // SAFETY: all inputs are fixed, NUL-terminated, and remain live. The
        // Job attribute assigns the suspended process atomically; no handle
        // inherits. The disposable thread token scopes the two privileges
        // required only while assigning the primary token and quota.
        if unsafe {
            CreateProcessAsUserW(
                holder_token.launch_token.raw(),
                application.as_ptr(),
                command_line.as_mut_ptr(),
                &raw const process_attributes,
                &raw const thread_attributes,
                0,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr().cast(),
                current_directory.as_ptr(),
                &raw const startup.StartupInfo,
                &raw mut created,
            )
        } == 0
        {
            Err(format!(
                "CreateProcessAsUserW failed for brokered session holder: {}",
                io::Error::last_os_error(),
            ))
        } else {
            Ok(())
        }
    })?;
    let process = OwnedHandle::new(created.hProcess)?;
    let thread = OwnedHandle::new(created.hThread)?;
    let result = (|| {
        if created.dwProcessId == 0 || created.dwThreadId == 0 {
            return Err(format!(
                "brokered holder creation returned a zero identity: process_id={} primary_thread_id={}",
                created.dwProcessId, created.dwThreadId,
            ));
        }
        // SAFETY: thread is the still-live creator handle for the suspended
        // primary thread.
        let thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };
        if thread_process_id != created.dwProcessId {
            return Err(format!(
                "brokered holder primary-thread association differs: expected_pid={} actual_pid={} primary_thread_id={}",
                created.dwProcessId, thread_process_id, created.dwThreadId,
            ));
        }
        let mut in_job = 0_i32;
        // SAFETY: process and local_job are live; output is writable.
        if unsafe {
            windows_sys::Win32::System::JobObjects::IsProcessInJob(
                process.raw(),
                local_job.raw(),
                &raw mut in_job,
            )
        } == 0
            || in_job == 0
        {
            return Err("brokered holder is absent from the launcher-owned Job".to_owned());
        }
        process_security
            .verify_kernel_object(process.raw(), super::security::SecurityObjectKind::Process)?;
        thread_security
            .verify_kernel_object(thread.raw(), super::security::SecurityObjectKind::Thread)?;
        verify_image_path(process.raw(), &executable)?;
        let identity = process_identity(process.raw())?;
        if identity.process_id != created.dwProcessId {
            return Err(format!(
                "brokered holder process identity differs: expected_pid={} actual_pid={}",
                created.dwProcessId, identity.process_id,
            ));
        }
        let query = super::token::process_token_query_attestation(process.raw())?;
        let holder_launch_after =
            super::token::token_attestation_snapshot(holder_token.launch_token.raw())?;
        super::token::require_same_token_instance(
            "session-broker-holder-launch-invariance",
            &holder_launch_before,
            &holder_launch_after,
        )
        .map_err(|error| error.to_string())?;
        super::token::require_assigned_process_authority(
            "session-broker-holder-launch-to-process",
            &holder_launch_before,
            &query,
        )
        .map_err(|error| error.to_string())?;
        Ok((identity, query))
    })();
    let (identity, query) = match result {
        Ok(evidence) => evidence,
        Err(error) => {
            // SAFETY: the process is still suspended and private to this call.
            unsafe { TerminateProcess(process.raw(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
            return Err(error);
        }
    };
    let broker_source = holder_token.broker_source.clone();
    let holder_effective = holder_token.holder_effective.clone();
    drop(holder_token.launch_token);
    let broker_thread = duplicate_local_handle_with_access(
        thread.raw(),
        super::session_broker::HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,
        super::session_broker::HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,
        "broker-holder-thread",
    )?;
    drop(thread);
    Ok(SessionBrokerCreatedHolder {
        _job: local_job,
        process,
        thread: broker_thread,
        primary_thread_id: created.dwThreadId,
        identity,
        query,
        broker_source,
        holder_effective,
        station_creation_carrier: holder_token.station_creation_carrier,
        station_creation_evidence: holder_token.station_creation_evidence,
        desktop_creation_carrier: holder_token.desktop_creation_carrier,
        desktop_creation_evidence: holder_token.desktop_creation_evidence,
        armed: true,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RemoteHandleObjectIdentity {
    Absent,
    DifferentObject,
    SameObject,
}

pub(crate) fn compare_remote_handle_object(
    source_process: HANDLE,
    remote_value: HANDLE,
    expected_local: HANDLE,
) -> Result<RemoteHandleObjectIdentity, String> {
    let mut snapshot = ptr::null_mut();
    // SAFETY: source_process is a live process handle with PROCESS_DUP_HANDLE;
    // remote_value is deliberately interpreted in that process's namespace,
    // and the current process receives an independently owned snapshot.
    if unsafe {
        DuplicateHandle(
            source_process,
            remote_value,
            GetCurrentProcess(),
            &raw mut snapshot,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_INVALID_HANDLE as i32) {
            Ok(RemoteHandleObjectIdentity::Absent)
        } else {
            Err(format!(
                "duplicate remote handle candidate for object identity: native_code={:?} detail={error}",
                error.raw_os_error()
            ))
        };
    }
    let snapshot = OwnedHandle::new(snapshot)?;
    // SAFETY: both arguments are live local handles. A false result is the
    // expected different-object collision classification, not an API failure.
    if unsafe { CompareObjectHandles(snapshot.raw(), expected_local) } != 0 {
        Ok(RemoteHandleObjectIdentity::SameObject)
    } else {
        Ok(RemoteHandleObjectIdentity::DifferentObject)
    }
}

pub struct SuspendedTarget {
    process: OwnedHandle,
    thread: OwnedHandle,
    process_snapshot: Option<super::token::TokenQueryAttestationSnapshot>,
    _desktop_lease: Option<TargetDesktopLease>,
    desktop_binding: String,
    pub process_id: u32,
    pub creation_observation: TargetCreationObservation,
}

pub(super) struct NestedSuspendedTarget {
    pub target: SuspendedTarget,
    pub initial: super::token::InstalledThreadTokenAttestation,
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
    pub loader_context: bool,
}

enum TargetObjectSecurity {
    LauncherService,
    NestedCanaryCreator,
}

struct OwnedDesktop {
    handle: HANDLE,
    assigned: bool,
}

struct BootstrapWindowStation {
    handle: HANDLE,
    assigned: bool,
    closed: bool,
}

struct OwnedUserObjectDuplicate(HANDLE);

// SAFETY: an opened desktop handle is process-scoped. The creator thread exits
// before ownership moves back to the bootstrap thread, quarantining any
// creator-thread binding side effect.
unsafe impl Send for OwnedDesktop {}

impl OwnedDesktop {
    const fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            assigned: false,
        }
    }

    const fn raw(&self) -> HANDLE {
        self.handle
    }

    fn mark_assigned(&mut self) {
        self.assigned = true;
    }
}

impl BootstrapWindowStation {
    const fn new(handle: HANDLE) -> Self {
        Self {
            handle,
            assigned: false,
            closed: false,
        }
    }

    const fn raw(&self) -> HANDLE {
        self.handle
    }

    fn mark_assigned(&mut self) {
        self.assigned = true;
    }

    fn restore_and_close(
        &mut self,
        source: HANDLE,
        expected_source_name: &str,
    ) -> Result<(), String> {
        if !self.assigned {
            return Err("private window station is not assigned during restoration".to_owned());
        }
        if unsafe { SetProcessWindowStation(source) } == 0 {
            return Err(format!(
                "cannot restore source process window station: {}",
                io::Error::last_os_error()
            ));
        }
        self.assigned = false;
        let restored = unsafe { GetProcessWindowStation() };
        if restored.is_null()
            || user_object_name(restored).map_err(|error| error.to_string())?
                != expected_source_name
        {
            return Err("source process window station restoration did not persist".to_owned());
        }
        if unsafe { CloseWindowStation(self.handle) } == 0 {
            return Err(format!(
                "cannot close restored private window station: {}",
                io::Error::last_os_error()
            ));
        }
        self.closed = true;
        Ok(())
    }
}

impl Drop for BootstrapWindowStation {
    fn drop(&mut self) {
        if !self.assigned && !self.closed {
            // SAFETY: before assignment this wrapper exclusively owns the
            // CreateWindowStationW result and CloseWindowStation is permitted.
            unsafe { CloseWindowStation(self.handle) };
        }
        // An assigned process window-station handle cannot be closed. The
        // dedicated bootstrap retains it until process exit tears down the
        // complete private USER namespace.
    }
}

impl Drop for OwnedDesktop {
    fn drop(&mut self) {
        if !self.assigned && !self.handle.is_null() {
            // SAFETY: this wrapper exclusively owns a CreateDesktopW or
            // OpenDesktopW result and no live thread is assigned through it.
            unsafe { CloseDesktop(self.handle) };
        }
        // An assigned desktop handle cannot be closed. The dedicated
        // bootstrap retains it until process exit tears down the complete
        // private USER namespace.
    }
}

struct DesktopEnumerationState {
    expected_name: *const u16,
    expected_name_len: usize,
    expected_count: usize,
    unexpected_name: bool,
}

unsafe extern "system" fn enumerate_private_desktop(name: *const u16, state: isize) -> i32 {
    let state = unsafe { &mut *(state as *mut DesktopEnumerationState) };
    if name.is_null() {
        state.unexpected_name = true;
        return 1;
    }
    let mut name_len = 0;
    while unsafe { *name.add(name_len) } != 0 {
        name_len += 1;
    }
    let name = unsafe { std::slice::from_raw_parts(name, name_len) };
    let expected =
        unsafe { std::slice::from_raw_parts(state.expected_name, state.expected_name_len) };
    if name == expected {
        state.expected_count += 1;
    } else {
        state.unexpected_name = true;
    }
    1
}

fn verify_private_desktop_containment(
    window_station: HANDLE,
    desktop_wide: &[u16],
) -> Result<(), String> {
    let expected_name = desktop_wide
        .strip_suffix(&[0])
        .ok_or_else(|| "private desktop name is not NUL-terminated".to_owned())?;
    let mut state = DesktopEnumerationState {
        expected_name: expected_name.as_ptr(),
        expected_name_len: expected_name.len(),
        expected_count: 0,
        unexpected_name: false,
    };
    if unsafe {
        EnumDesktopsW(
            window_station,
            Some(enumerate_private_desktop),
            (&raw mut state) as isize,
        )
    } == 0
    {
        return Err(format!(
            "EnumDesktopsW failed for nonce private window station: {}",
            io::Error::last_os_error()
        ));
    }
    if state.expected_count != 1 || state.unexpected_name {
        return Err(format!(
            "nonce private window station desktop containment mismatch: expected_count={} unexpected_name={}",
            state.expected_count, state.unexpected_name
        ));
    }
    Ok(())
}

impl OwnedUserObjectDuplicate {
    fn duplicate(source: HANDLE, desired_access: u32) -> Result<Self, io::Error> {
        let mut duplicate = ptr::null_mut();
        // SAFETY: source is a live process/thread-assigned USER handle. The
        // target is this process, desired_access is role-specific, and the
        // duplicate is deliberately non-inheritable.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                desired_access,
                0,
                0,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else if duplicate.is_null() || duplicate == INVALID_HANDLE_VALUE {
            Err(io::Error::other(
                "DuplicateHandle returned an invalid USER-object handle",
            ))
        } else {
            Ok(Self(duplicate))
        }
    }

    const fn raw(&self) -> HANDLE {
        self.0
    }

    fn close_checked(&mut self) -> Result<(), io::Error> {
        if self.0.is_null() || self.0 == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(
                "duplicated USER-object handle is already closed",
            ));
        }
        let source = std::mem::replace(&mut self.0, ptr::null_mut());
        // SAFETY: source was exclusively owned by this wrapper. Microsoft
        // documents DUPLICATE_CLOSE_SOURCE as closing it even if the operation
        // subsequently reports failure, so ownership is cleared before the call.
        if unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                ptr::null_mut(),
                ptr::null_mut(),
                0,
                0,
                DUPLICATE_CLOSE_SOURCE,
            )
        } == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn close(mut self) -> Result<(), io::Error> {
        self.close_checked()
    }
}

impl Drop for OwnedUserObjectDuplicate {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            let _ = self.close_checked();
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TargetUserBindingReadRole {
    WindowStation,
    Desktop,
}

#[derive(Debug)]
struct TargetUserBindingReadError {
    role: TargetUserBindingReadRole,
    native_code: Option<i32>,
    detail: String,
}

impl TargetUserBindingReadError {
    fn native(role: TargetUserBindingReadRole, detail: &'static str, error: io::Error) -> Self {
        Self {
            role,
            native_code: error.raw_os_error(),
            detail: format!("{detail}: {error}"),
        }
    }

    fn from_user_object(role: TargetUserBindingReadRole, error: UserObjectQueryError) -> Self {
        Self {
            role,
            native_code: error.native_code,
            detail: error.detail,
        }
    }

    fn contract(role: TargetUserBindingReadRole, detail: impl Into<String>) -> Self {
        Self {
            role,
            native_code: None,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for TargetUserBindingReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "role={:?} native_code={:?} detail={}",
            self.role, self.native_code, self.detail,
        )
    }
}

struct TargetUserBindingReadHandles {
    window_station: OwnedUserObjectDuplicate,
    desktop: OwnedUserObjectDuplicate,
}

impl TargetUserBindingReadHandles {
    fn duplicate(
        window_station: HANDLE,
        desktop: HANDLE,
    ) -> Result<Self, TargetUserBindingReadError> {
        let window_station =
            OwnedUserObjectDuplicate::duplicate(window_station, TARGET_STATION_ATTEST_ACCESS)
                .map_err(|error| {
                    TargetUserBindingReadError::native(
                        TargetUserBindingReadRole::WindowStation,
                        "cannot duplicate current target window station for attestation",
                        error,
                    )
                })?;
        user_object_name(window_station.raw()).map_err(|error| {
            TargetUserBindingReadError::from_user_object(
                TargetUserBindingReadRole::WindowStation,
                error,
            )
        })?;

        let desktop = OwnedUserObjectDuplicate::duplicate(desktop, TARGET_DESKTOP_ATTEST_ACCESS)
            .map_err(|error| {
                TargetUserBindingReadError::native(
                    TargetUserBindingReadRole::Desktop,
                    "cannot duplicate current target desktop for attestation",
                    error,
                )
            })?;
        user_object_name(desktop.raw()).map_err(|error| {
            TargetUserBindingReadError::from_user_object(TargetUserBindingReadRole::Desktop, error)
        })?;
        verify_user_object_not_inheritable(window_station.raw()).map_err(|error| {
            TargetUserBindingReadError::contract(TargetUserBindingReadRole::WindowStation, error)
        })?;
        verify_user_object_not_inheritable(desktop.raw()).map_err(|error| {
            TargetUserBindingReadError::contract(TargetUserBindingReadRole::Desktop, error)
        })?;
        Ok(Self {
            window_station,
            desktop,
        })
    }
}

fn creation_failure_phase(
    phase: super::session_broker::SessionCreationPhaseV1,
) -> TargetDesktopBootstrapPhaseV1 {
    match phase {
        super::session_broker::SessionCreationPhaseV1::WindowStation => {
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation
        }
        super::session_broker::SessionCreationPhaseV1::Desktop => {
            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation
        }
    }
}

fn fail_stop_uncertain_creation_arm(
    phase: super::session_broker::SessionCreationPhaseV1,
    detail: impl std::fmt::Display,
) -> ! {
    eprintln!(
        "target creator authority became uncertain after readiness: phase={phase:?} detail={detail}"
    );
    // SAFETY: continuing after the broker may have attached a privileged
    // impersonation token would execute ordinary holder code with uncertain
    // authority. The launcher-owned Job remains the outer cleanup boundary.
    unsafe { TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
    std::process::abort();
}

fn request_creator_arm(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
    holder_primary: &super::token::TokenQueryAttestationSnapshot,
) -> Result<super::token::AttachedCreationCarrierGuard, TargetDesktopBootstrapFailure> {
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(creation_failure_phase(phase), error)
    })?;
    if holder_primary != &binding.holder_process_snapshot {
        return Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "holder primary changed before creation readiness",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationReadyWrite,
        &TargetDesktopBootstrapMessageV1::CreationReady {
            binding: binding.clone(),
            phase,
            ordinal,
            thread_id,
            holder_primary: holder_primary.clone(),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })?;
    let armed = match super::pipe::read_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationArmedRead,
    ) {
        Ok(armed) => armed,
        Err(error) => fail_stop_uncertain_creation_arm(phase, error),
    };
    match armed {
        TargetDesktopBootstrapMessageV1::CreationArmed {
            binding: observed_binding,
            phase: observed_phase,
            ordinal: observed_ordinal,
            thread_id: observed_thread,
            carrier,
        } if observed_binding == *binding
            && observed_phase == phase
            && observed_ordinal == ordinal
            && observed_thread == thread_id =>
        {
            let (guard, attached) = match super::token::AttachedCreationCarrierGuard::adopt() {
                Ok(attached) => attached,
                Err(error) => fail_stop_uncertain_creation_arm(phase, error),
            };
            if attached != carrier {
                return Err(TargetDesktopBootstrapFailure::contract(
                    creation_failure_phase(phase),
                    "attached creator carrier differs from authenticated Armed evidence",
                ));
            }
            Ok(guard)
        }
        _ => fail_stop_uncertain_creation_arm(
            phase,
            "launcher returned invalid creation Armed evidence",
        ),
    }
}

fn consume_creator_arm(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
    native_code: Option<i32>,
    holder_primary: &super::token::TokenQueryAttestationSnapshot,
) -> Result<(), TargetDesktopBootstrapFailure> {
    if holder_primary != &binding.holder_process_snapshot {
        return Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "holder primary changed while a creation carrier was attached",
        ));
    }
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(creation_failure_phase(phase), error)
    })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationConsumedWrite,
        &TargetDesktopBootstrapMessageV1::CreationConsumed {
            binding: binding.clone(),
            phase,
            ordinal,
            thread_id,
            holder_primary: holder_primary.clone(),
            native_code,
            thread_token_absent: true,
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })?;
    match super::pipe::read_frame_bounded(
        connection,
        Some(launcher_process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::CreationClearedRead,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(creation_failure_phase(phase), error)
    })? {
        TargetDesktopBootstrapMessageV1::CreationCleared {
            binding: observed_binding,
            phase: observed_phase,
            ordinal: observed_ordinal,
            thread_id: observed_thread,
        } if observed_binding == *binding
            && observed_phase == phase
            && observed_ordinal == ordinal
            && observed_thread == thread_id =>
        {
            Ok(())
        }
        _ => Err(TargetDesktopBootstrapFailure::contract(
            creation_failure_phase(phase),
            "launcher returned invalid creation Cleared evidence",
        )),
    }
}

fn create_target_desktop_on_creator_thread(
    desktop_wide: Vec<u16>,
    creation_security: super::security::AbsoluteSecurityDescriptor,
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: TargetDesktopBootstrapBindingV3,
) -> Result<OwnedDesktop, TargetDesktopBootstrapFailure> {
    let connection_value = connection as usize;
    let launcher_process_value = launcher_process as usize;
    std::thread::Builder::new()
        .name("memcordon-target-desktop-creator".to_owned())
        .spawn(move || {
            let connection = connection_value as HANDLE;
            let launcher_process = launcher_process_value as HANDLE;
            let attributes = creation_security.attributes(false);
            let thread_id = unsafe { GetCurrentThreadId() };
            let primary_before =
                super::token::process_token_query_attestation(unsafe { GetCurrentProcess() })
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                            error,
                        )
                    })?;
            let carrier_guard = request_creator_arm(
                connection,
                launcher_process,
                &binding,
                super::session_broker::SessionCreationPhaseV1::Desktop,
                2,
                thread_id,
                &primary_before,
            )?;
            // SAFETY: desktop_wide is NUL-terminated, attributes owns a live
            // absolute descriptor, and the requested rights are the exact
            // private-desktop policy rights. The worker quarantines any
            // OS-dependent creator-thread binding side effect; object
            // attestation uses the returned handle after this worker exits.
            let desktop = unsafe {
                CreateDesktopW(
                    desktop_wide.as_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                    &raw const attributes,
                )
            };
            let create_error = desktop.is_null().then(|| io::Error::last_os_error());
            if let Err(error) = carrier_guard.revert() {
                eprintln!("desktop creator carrier reversion failed: {error}");
                unsafe {
                    TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
                };
                std::process::abort();
            }
            let primary_after =
                super::token::process_token_query_attestation(unsafe { GetCurrentProcess() })
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                            error,
                        )
                    })?;
            consume_creator_arm(
                connection,
                launcher_process,
                &binding,
                super::session_broker::SessionCreationPhaseV1::Desktop,
                2,
                thread_id,
                create_error.as_ref().and_then(io::Error::raw_os_error),
                &primary_after,
            )?;
            if let Some(error) = create_error {
                return Err(TargetDesktopBootstrapFailure::captured_native(
                    TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                    error.raw_os_error().unwrap_or_default(),
                    format!("CreateDesktopW failed in target-token bootstrap station: {error}"),
                ));
            }
            Ok(OwnedDesktop::new(desktop))
        })
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                format!("cannot start private desktop creator thread: {error}"),
            )
        })?
        .join()
        .map_err(|_| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
                "private desktop creator thread panicked",
            )
        })?
}

struct TargetDesktopLease {
    bootstrap_process: OwnedHandle,
    bootstrap_job: Job,
    connection_lease: Option<OwnedHandle>,
    bootstrap_identity: WindowsProcessIdentityV1,
    holder_envelope: WindowsCallerTokenEnvelopeV1,
    broker_source_snapshot: super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: super::token::TokenAttestationSnapshot,
    holder_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    holder_binding: TargetDesktopBootstrapBindingV3,
    window_station_name: String,
    desktop_name: String,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    exact_name: String,
    startup_name: Vec<u16>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderLaunchFailurePhaseV1 {
    PreCreate,
    CreateProcessReturn,
    PreResumeAttestation,
    PostResumePreLoaderReady,
    PreInitialBreakpointStaticLoader,
    PostLoaderReadyContainment,
    ExitDrain,
    Unknown,
}

impl LoaderLaunchFailurePhaseV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::PreCreate => "pre-create",
            Self::CreateProcessReturn => "create-process-return",
            Self::PreResumeAttestation => "pre-resume-attestation",
            Self::PostResumePreLoaderReady => "post-resume-pre-loader-ready",
            Self::PreInitialBreakpointStaticLoader => "pre-initial-breakpoint-static-loader",
            Self::PostLoaderReadyContainment => "post-loader-ready-containment",
            Self::ExitDrain => "exit-drain",
            Self::Unknown => "unclassified",
        }
    }
}

struct TargetDesktopLeaseCreateError {
    detail: String,
    os_code: Option<i32>,
    loader_phase: LoaderLaunchFailurePhaseV1,
}

impl TargetDesktopLeaseCreateError {
    fn at_loader_phase(mut self, loader_phase: LoaderLaunchFailurePhaseV1) -> Self {
        self.loader_phase = loader_phase;
        self
    }
}

#[derive(Clone)]
struct TargetDesktopBootstrapLaunchContext {
    policy_role: super::security::TargetUserObjectPolicyRoleV1,
    scenario: &'static str,
    target_token_restricted: bool,
    target_token_write_restricted: bool,
    target_integrity: String,
    target_restricting_sid_sha256: String,
}

impl TargetDesktopBootstrapLaunchContext {
    fn capture(
        token: HANDLE,
        snapshot: &super::token::TokenAttestationSnapshot,
        policy_role: super::security::TargetUserObjectPolicyRoleV1,
    ) -> Result<Self, TargetDesktopLeaseCreateError> {
        let target_token_write_restricted =
            super::security::write_restricted_behavior_attested(token)?;
        let administrator_deny_only = snapshot.behavior.groups.iter().any(|entry| {
            entry
                .strip_prefix("S-1-5-32-544@")
                .and_then(|attributes| u32::from_str_radix(attributes, 16).ok())
                .is_some_and(|attributes| attributes & 0x10 != 0)
        });
        let scenario = if target_token_write_restricted {
            "write-restricted"
        } else if administrator_deny_only {
            "deny-only-admin"
        } else if snapshot.behavior.token_is_restricted {
            "restricted"
        } else if snapshot.behavior.envelope.integrity_level == "S-1-16-4096" {
            "low-integrity"
        } else if snapshot.behavior.envelope.elevated {
            "elevated-admin"
        } else {
            "ordinary-user"
        };
        Ok(Self {
            policy_role,
            scenario,
            target_token_restricted: snapshot.behavior.token_is_restricted,
            target_token_write_restricted,
            target_integrity: snapshot.behavior.envelope.integrity_level.clone(),
            target_restricting_sid_sha256: super::record::digest(
                snapshot.behavior.restricting_sids.join("\n").as_bytes(),
            ),
        })
    }

    fn accept_error(
        &self,
        role: TargetDesktopBootstrapRoleV1,
        bootstrap_pid: u32,
        bootstrap_image_sha256: &str,
        desktop_mode: &str,
        evidence: &str,
        error: super::pipe::TargetDesktopBootstrapPipeError,
    ) -> TargetDesktopLeaseCreateError {
        TargetDesktopLeaseCreateError {
            os_code: error.native_code(),
            loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
            detail: format!(
                "bootstrap_role={} policy_role={} scenario={} launch_phase=resumed bootstrap_pid={bootstrap_pid} bootstrap_image_sha256={bootstrap_image_sha256} target_token_restricted={} target_token_write_restricted={} target_integrity={} target_restricting_sid_sha256={} desktop_mode={desktop_mode} {evidence} detail={error}",
                role.diagnostic(),
                self.policy_role.diagnostic(),
                self.scenario,
                self.target_token_restricted,
                self.target_token_write_restricted,
                self.target_integrity,
                self.target_restricting_sid_sha256,
            ),
        }
    }
}

impl From<String> for TargetDesktopLeaseCreateError {
    fn from(detail: String) -> Self {
        Self {
            detail,
            os_code: None,
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
        }
    }
}

impl From<super::token::LauncherHolderTokenDerivationError> for TargetDesktopLeaseCreateError {
    fn from(error: super::token::LauncherHolderTokenDerivationError) -> Self {
        Self {
            os_code: error.native_code,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
        }
    }
}

impl From<super::security::TargetUserObjectPolicyError> for TargetDesktopLeaseCreateError {
    fn from(error: super::security::TargetUserObjectPolicyError) -> Self {
        Self {
            os_code: None,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
        }
    }
}

impl From<super::token::TokenAttestationRelationError> for TargetDesktopLeaseCreateError {
    fn from(error: super::token::TokenAttestationRelationError) -> Self {
        Self {
            os_code: None,
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
        }
    }
}

#[cfg(test)]
pub(crate) fn holder_derivation_error_mapping_for_test(
    error: super::token::LauncherHolderTokenDerivationError,
) -> (String, Option<i32>) {
    let mapped = TargetDesktopLeaseCreateError::from(error);
    (mapped.detail, mapped.os_code)
}

impl From<super::pipe::TargetDesktopBootstrapPipeError> for TargetDesktopLeaseCreateError {
    fn from(error: super::pipe::TargetDesktopBootstrapPipeError) -> Self {
        Self {
            os_code: error.native_code(),
            detail: error.to_string(),
            loader_phase: LoaderLaunchFailurePhaseV1::Unknown,
        }
    }
}

struct CapturedTargetDesktop {
    read_handles: TargetUserBindingReadHandles,
    window_station_name: String,
    window_station_security_sha256: String,
    desktop_name: String,
    desktop_security_sha256: String,
    exact_name: String,
    startup_name: Vec<u16>,
    window_station_security: SecurityDescriptor,
    desktop_security: SecurityDescriptor,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TargetDesktopBootstrapPhaseV1 {
    EndpointCreation,
    EndpointAdmission,
    AdmissionRead,
    ServerProcessAuthentication,
    ServerTokenAuthentication,
    StartedPublication,
    LauncherAuthentication,
    ResultEndpointAdmission,
    LifetimeEndpointAdmission,
    TargetTokenCapture,
    UserBindingAcquisition,
    UserBindingAttestation,
    StationReadHandle,
    StationSecurityReadback,
    DefaultDesktopReadHandle,
    DefaultDesktopSecurityReadback,
    DesktopNonceGeneration,
    WindowStationPolicyConstruction,
    PrivateWindowStationCreation,
    PrivateWindowStationBinding,
    PrivateWindowStationAttestation,
    DesktopPolicyConstruction,
    PrivateDesktopCreation,
    PrivateDesktopAttestation,
    SharedBindingPostAttestation,
    UserModuleResolution,
    ProcessIdentityCapture,
    ResultPublication,
    LifetimeHold,
    SessionGate,
    RestrictedProbeCreation,
    RestrictedProbeAuthentication,
    RestrictedProbeAttestation,
    TargetAssociationPreflight,
    TargetNativeLoaderAccessPreflight,
    LoaderControl,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TargetAssociationPreflightStageV1 {
    RetainedNamespaceBefore,
    SourceBootstrap,
    SourceSystemAncestry,
    SourceLoaderGraph,
    SourceKnownDlls,
    TargetTokenInstallation,
    TargetWindowStation,
    TargetDesktop,
    TargetBootstrap,
    TargetKnownDlls,
    TargetModules,
    RevertAndFinalization,
}

impl TargetAssociationPreflightStageV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::RetainedNamespaceBefore => "retained-namespace-before",
            Self::SourceBootstrap => "source-bootstrap",
            Self::SourceSystemAncestry => "source-system-ancestry",
            Self::SourceLoaderGraph => "source-loader-graph",
            Self::SourceKnownDlls => "source-known-dlls",
            Self::TargetTokenInstallation => "target-token-installation",
            Self::TargetWindowStation => "target-window-station",
            Self::TargetDesktop => "target-desktop",
            Self::TargetBootstrap => "target-bootstrap",
            Self::TargetKnownDlls => "target-known-dlls",
            Self::TargetModules => "target-modules",
            Self::RevertAndFinalization => "revert-and-finalization",
        }
    }

    const fn successor(self) -> Option<Self> {
        match self {
            Self::RetainedNamespaceBefore => Some(Self::SourceBootstrap),
            Self::SourceBootstrap => Some(Self::SourceSystemAncestry),
            Self::SourceSystemAncestry => Some(Self::SourceLoaderGraph),
            Self::SourceLoaderGraph => Some(Self::SourceKnownDlls),
            Self::SourceKnownDlls => Some(Self::TargetTokenInstallation),
            Self::TargetTokenInstallation => Some(Self::TargetWindowStation),
            Self::TargetWindowStation => Some(Self::TargetDesktop),
            Self::TargetDesktop => Some(Self::TargetBootstrap),
            Self::TargetBootstrap => Some(Self::TargetKnownDlls),
            Self::TargetKnownDlls => Some(Self::TargetModules),
            Self::TargetModules => Some(Self::RevertAndFinalization),
            Self::RevertAndFinalization => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(super) enum TargetDesktopBootstrapRoleV1 {
    Holder,
    LoaderControl,
    Probe,
}

impl TargetDesktopBootstrapRoleV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Holder => "holder",
            Self::LoaderControl => "loader-control",
            Self::Probe => "probe",
        }
    }
}

pub(super) use TargetDesktopBootstrapRoleV1 as TargetDesktopBootstrapRole;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetDesktopBootstrapBindingV3 {
    schema_version: u32,
    role: TargetDesktopBootstrapRoleV1,
    target_user_object_policy_role: super::security::TargetUserObjectPolicyRoleV1,
    nonce: String,
    binding_sha256: String,
    bootstrap_image_sha256: String,
    launcher_identity: WindowsProcessIdentityV1,
    launcher_session_id: u32,
    launcher_envelope: WindowsCallerTokenEnvelopeV1,
    launcher_process_snapshot: super::token::TokenAttestationSnapshot,
    broker_source_snapshot: super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: super::token::TokenAttestationSnapshot,
    holder_assignment: super::token::AssignedProcessTokenEvidenceV1,
    bootstrap_identity: WindowsProcessIdentityV1,
    bootstrap_envelope: WindowsCallerTokenEnvelopeV1,
    bootstrap_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    bootstrap_assignment: super::token::AssignedProcessTokenEvidenceV1,
    holder_process_snapshot: super::token::TokenQueryAttestationSnapshot,
    target_envelope: WindowsCallerTokenEnvelopeV1,
    target_request_snapshot: super::token::TokenAttestationSnapshot,
}

impl TargetDesktopBootstrapBindingV3 {
    fn seal(mut self) -> Result<Self, String> {
        self.binding_sha256 = self.calculated_sha256()?;
        Ok(self)
    }

    fn verify_digest(&self) -> Result<(), String> {
        if self.binding_sha256 != self.calculated_sha256()? {
            Err("target desktop bootstrap binding digest is mismatched".to_owned())
        } else {
            Ok(())
        }
    }

    fn calculated_sha256(&self) -> Result<String, String> {
        let mut claims = serde_json::to_value(self).map_err(|error| error.to_string())?;
        claims
            .as_object_mut()
            .ok_or_else(|| "target desktop bootstrap binding is not an object".to_owned())?
            .remove("binding_sha256")
            .ok_or_else(|| "target desktop bootstrap binding digest field is absent".to_owned())?;
        let mut canonical = b"memcordon-target-desktop-binding-v8\0".to_vec();
        canonical.extend(serde_json::to_vec(&claims).map_err(|error| error.to_string())?);
        Ok(super::record::digest(&canonical))
    }
}

impl TargetDesktopBootstrapPhaseV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::EndpointCreation => "endpoint-creation",
            Self::EndpointAdmission => "endpoint-admission",
            Self::AdmissionRead => "admission-read",
            Self::ServerProcessAuthentication => "server-process-authentication",
            Self::ServerTokenAuthentication => "server-token-authentication",
            Self::StartedPublication => "started-publication",
            Self::LauncherAuthentication => "launcher-authentication",
            Self::ResultEndpointAdmission => "result-endpoint-admission",
            Self::LifetimeEndpointAdmission => "lifetime-endpoint-admission",
            Self::TargetTokenCapture => "target-token-capture",
            Self::UserBindingAcquisition => "user-binding-acquisition",
            Self::UserBindingAttestation => "user-binding-attestation",
            Self::StationReadHandle => "station-read-handle",
            Self::StationSecurityReadback => "station-security-readback",
            Self::DefaultDesktopReadHandle => "default-desktop-read-handle",
            Self::DefaultDesktopSecurityReadback => "default-desktop-security-readback",
            Self::DesktopNonceGeneration => "desktop-nonce-generation",
            Self::WindowStationPolicyConstruction => "window-station-policy-construction",
            Self::PrivateWindowStationCreation => "private-window-station-creation",
            Self::PrivateWindowStationBinding => "private-window-station-binding",
            Self::PrivateWindowStationAttestation => "private-window-station-attestation",
            Self::DesktopPolicyConstruction => "desktop-policy-construction",
            Self::PrivateDesktopCreation => "private-desktop-creation",
            Self::PrivateDesktopAttestation => "private-desktop-attestation",
            Self::SharedBindingPostAttestation => "shared-binding-post-attestation",
            Self::UserModuleResolution => "user-module-resolution",
            Self::ProcessIdentityCapture => "process-identity-capture",
            Self::ResultPublication => "result-publication",
            Self::LifetimeHold => "lifetime-hold",
            Self::SessionGate => "session-gate",
            Self::RestrictedProbeCreation => "restricted-probe-creation",
            Self::RestrictedProbeAuthentication => "restricted-probe-authentication",
            Self::RestrictedProbeAttestation => "restricted-probe-attestation",
            Self::TargetAssociationPreflight => "target-association-preflight",
            Self::TargetNativeLoaderAccessPreflight => "target-native-loader-access-preflight",
            Self::LoaderControl => "loader-control",
        }
    }
}

#[derive(Debug)]
struct TargetDesktopBootstrapFailure {
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
    started_publication_bytes_transferred: usize,
}

impl TargetDesktopBootstrapFailure {
    fn contract(phase: TargetDesktopBootstrapPhaseV1, detail: impl ToString) -> Self {
        Self {
            phase,
            native_code: None,
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn native(phase: TargetDesktopBootstrapPhaseV1, detail: &'static str) -> Self {
        let error = io::Error::last_os_error();
        Self {
            phase,
            native_code: error.raw_os_error(),
            detail: bounded_target_desktop_bootstrap_detail(format!("{detail}: {error}")),
            started_publication_bytes_transferred: 0,
        }
    }

    fn captured_native(
        phase: TargetDesktopBootstrapPhaseV1,
        native_code: i32,
        detail: impl ToString,
    ) -> Self {
        Self {
            phase,
            native_code: Some(native_code),
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn observed_native(phase: TargetDesktopBootstrapPhaseV1, detail: impl ToString) -> Self {
        let native_code = io::Error::last_os_error().raw_os_error();
        Self {
            phase,
            native_code,
            detail: bounded_target_desktop_bootstrap_detail(detail.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_pipe(
        phase: TargetDesktopBootstrapPhaseV1,
        error: super::pipe::TargetDesktopBootstrapPipeError,
    ) -> Self {
        Self {
            phase,
            native_code: error.native_code(),
            detail: bounded_target_desktop_bootstrap_detail(error.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_user_object(phase: TargetDesktopBootstrapPhaseV1, error: UserObjectQueryError) -> Self {
        Self {
            phase,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.detail),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_native_loader(error: super::loader_access::NativeLoaderAccessFailureV1) -> Self {
        Self {
            phase: TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.to_string()),
            started_publication_bytes_transferred: 0,
        }
    }

    fn from_binding_read(error: TargetUserBindingReadError) -> Self {
        let phase = match error.role {
            TargetUserBindingReadRole::WindowStation => {
                TargetDesktopBootstrapPhaseV1::StationReadHandle
            }
            TargetUserBindingReadRole::Desktop => {
                TargetDesktopBootstrapPhaseV1::DefaultDesktopReadHandle
            }
        };
        Self {
            phase,
            native_code: error.native_code,
            detail: bounded_target_desktop_bootstrap_detail(error.detail),
            started_publication_bytes_transferred: 0,
        }
    }

    fn after_started_publication_error(mut self, bytes_transferred: usize) -> Self {
        self.started_publication_bytes_transferred = bytes_transferred;
        self
    }
}

impl std::fmt::Display for TargetDesktopBootstrapFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "phase={} native_code={:?} detail={}",
            self.phase.diagnostic(),
            self.native_code,
            self.detail,
        )
    }
}

fn bounded_target_desktop_bootstrap_detail(mut detail: String) -> String {
    if detail.len() > TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES {
        let mut boundary = TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    detail
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetDesktopBootstrapFrameV1 {
    schema_version: u32,
    bootstrap_identity: WindowsProcessIdentityV1,
    target_envelope: WindowsCallerTokenEnvelopeV1,
    window_station_name: String,
    desktop_name: String,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    source_objects_unmodified: bool,
    private_station_assigned: bool,
    private_desktop_assigned: bool,
    desktop_containment_verified: bool,
    window_station_policy_verified: bool,
    desktop_policy_verified: bool,
    window_station_not_inheritable: bool,
    desktop_not_inheritable: bool,
    noninteractive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TargetUserObjectOpenPreflightV1 {
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    desktop_heap_kb: u32,
    window_station_policy_sha256: String,
    desktop_policy_sha256: String,
    window_station_live_equality_sha256: String,
    desktop_live_equality_sha256: String,
    window_station_policy_verified_after_open: bool,
    desktop_policy_verified_after_open: bool,
    creator_live_baselines_unchanged: bool,
    target_snapshot_before: super::token::TokenAttestationSnapshot,
    target_snapshot_after: super::token::TokenAttestationSnapshot,
    thread_token_absent: bool,
    native_loader_access: super::loader_access::NativeLoaderAccessEvidenceV2,
}

impl TargetUserObjectOpenPreflightV1 {
    fn diagnostic(&self) -> String {
        format!(
            "association_preflight=passed station_requested={:#010x} station_granted={:#010x} desktop_requested={:#010x} desktop_granted={:#010x} desktop_heap_kb={}",
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            self.window_station_granted_access,
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
            self.desktop_granted_access,
            self.desktop_heap_kb,
        ) + " "
            + &self.native_loader_access.diagnostic()
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum TargetDesktopBootstrapMessageV1 {
    LoaderReady {
        schema_version: u32,
        nonce: String,
        expected_desktop: Option<String>,
        bootstrap_identity: WindowsProcessIdentityV1,
        process_envelope: WindowsCallerTokenEnvelopeV1,
        process_snapshot: super::token::TokenQueryAttestationSnapshot,
    },
    LoaderControlRelease {
        schema_version: u32,
        nonce: String,
        expected_desktop: String,
    },
    Admission {
        binding: TargetDesktopBootstrapBindingV3,
        launcher_process_query_handle: u64,
        launcher_token_query_handle: u64,
        target_token_capability_handle: Option<u64>,
    },
    Started {
        binding: TargetDesktopBootstrapBindingV3,
        phase: TargetDesktopBootstrapPhaseV1,
    },
    CreationReady {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
    },
    CreationArmed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        carrier: super::token::TokenAttestationSnapshot,
    },
    CreationConsumed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    },
    CreationCleared {
        binding: TargetDesktopBootstrapBindingV3,
        phase: super::session_broker::SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
    },
    Ready {
        binding: TargetDesktopBootstrapBindingV3,
        attestation: TargetDesktopBootstrapFrameV1,
    },
    AssociationPreflight {
        binding: TargetDesktopBootstrapBindingV3,
    },
    AssociationPreflightProgress {
        binding: TargetDesktopBootstrapBindingV3,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    },
    AssociationPreflightReady {
        binding: TargetDesktopBootstrapBindingV3,
        evidence: Box<TargetUserObjectOpenPreflightV1>,
    },
    Failed {
        binding: TargetDesktopBootstrapBindingV3,
        phase: TargetDesktopBootstrapPhaseV1,
        native_code: Option<i32>,
        detail: String,
    },
}

impl TargetDesktopLease {
    fn create(
        token: HANDLE,
        policy_role: super::security::TargetUserObjectPolicyRoleV1,
        loader_restriction_canary: Option<&LoaderRestrictionCanaryTokens>,
    ) -> Result<Self, TargetDesktopLeaseCreateError> {
        let target_envelope = super::token::envelope(token)?;
        let target_snapshot = super::token::token_attestation_snapshot(token)?;
        let launch_context =
            TargetDesktopBootstrapLaunchContext::capture(token, &target_snapshot, policy_role)?;
        let target_user_object_policy =
            super::security::target_user_object_policy(token, policy_role)?;
        let launcher_token = super::token::current_process_token_for_attestation()?;
        let launcher_envelope = super::token::envelope(launcher_token.raw())?;
        let launcher_snapshot = super::token::token_attestation_snapshot(launcher_token.raw())?;
        let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
        if launcher_envelope.session_id != 0 {
            return Err("launcher service token is outside session 0"
                .to_owned()
                .into());
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        let expected_window_station_sddl = target_user_object_policy.window_station_sddl();
        let expected_window_station_policy_sha256 =
            SecurityDescriptor::from_sddl(&expected_window_station_sddl)?
                .user_object_policy_fingerprint(
                    super::security::SecurityObjectKind::WindowStation,
                )?;
        let expected_desktop_sddl = target_user_object_policy.desktop_sddl();
        let expected_desktop_policy_sha256 = SecurityDescriptor::from_sddl(&expected_desktop_sddl)?
            .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)?;
        let nonce = target_desktop_nonce()?;
        validate_target_desktop_bootstrap_nonce(&nonce)?;
        let pipe_name = format!(
            "{}{}",
            super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
            nonce
        );
        let pipe_security =
            SecurityDescriptor::from_sddl(&super::security::holder_bootstrap_pipe_sddl()?)?;
        let prepared_pipe =
            super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
        clear_inherit(prepared_pipe.raw())?;
        verify_not_inheritable(prepared_pipe.raw())?;
        let bootstrap_job = Job::create_session_holder()?;
        let executable = super::package::installed_target_desktop_bootstrap();
        let bootstrap_image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
        let mut brokered = super::session_broker::request_holder(
            &bootstrap_job,
            target_envelope.session_id,
            &pipe_name,
            &nonce,
        )?;
        let mut broker_control = brokered
            .control
            .take()
            .ok_or_else(|| "session broker control lease is absent".to_owned())?;
        let bootstrap_process = brokered.process;
        let bootstrap_thread = brokered.thread;
        if !bootstrap_job.contains(bootstrap_process.raw())? {
            return Err("target desktop bootstrap is absent from its atomic Job"
                .to_owned()
                .into());
        }
        let observed_holder_snapshot = brokered.query;
        let broker_source_snapshot = brokered.broker_source;
        let holder_launch_snapshot = brokered.holder_effective;
        let holder_assignment = super::token::require_assigned_process_authority(
            "session-broker-holder-to-process",
            &holder_launch_snapshot,
            &observed_holder_snapshot,
        )?;
        let holder_envelope = observed_holder_snapshot.behavior.envelope.clone();
        let bootstrap_identity = brokered.identity;
        verify_image_path(bootstrap_process.raw(), &executable)?;
        let launcher_process_handle = duplicate_remote_process_query(
            unsafe { GetCurrentProcess() },
            bootstrap_process.raw(),
        )?;
        let launcher_token_handle =
            duplicate_remote_token_query(launcher_token.raw(), bootstrap_process.raw())?;
        let target_token_handle =
            duplicate_remote_target_token_capability(token, bootstrap_process.raw())?;
        let binding = TargetDesktopBootstrapBindingV3 {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            role: TargetDesktopBootstrapRoleV1::Holder,
            target_user_object_policy_role: policy_role,
            nonce,
            binding_sha256: String::new(),
            bootstrap_image_sha256: bootstrap_image_sha256.clone(),
            launcher_identity: launcher_identity.clone(),
            launcher_session_id: launcher_envelope.session_id,
            launcher_envelope: launcher_envelope.clone(),
            launcher_process_snapshot: launcher_snapshot.clone(),
            broker_source_snapshot: broker_source_snapshot.clone(),
            holder_launch_snapshot: holder_launch_snapshot.clone(),
            holder_assignment: holder_assignment.clone(),
            bootstrap_identity: bootstrap_identity.clone(),
            bootstrap_envelope: holder_envelope.clone(),
            bootstrap_process_snapshot: observed_holder_snapshot.clone(),
            bootstrap_assignment: holder_assignment,
            holder_process_snapshot: observed_holder_snapshot.clone(),
            target_envelope: target_envelope.clone(),
            target_request_snapshot: target_snapshot.clone(),
        }
        .seal()?;
        if unsafe { ResumeThread(bootstrap_thread.raw()) } != 1 {
            return Err(format!(
                "target desktop bootstrap primary thread did not resume exactly once: {}",
                io::Error::last_os_error()
            )
            .into());
        }
        drop(bootstrap_thread);
        let connection = super::pipe::accept_target_desktop_bootstrap_pipe(
            prepared_pipe,
            bootstrap_process.raw(),
            deadline,
        )
        .map_err(|error| {
            launch_context.accept_error(
                TargetDesktopBootstrapRoleV1::Holder,
                bootstrap_identity.process_id,
                &bootstrap_image_sha256,
                "empty-default-selection",
                "loader_control=not-run association_preflight=not-run",
                error,
            )
        })?;
        authenticate_target_desktop_bootstrap_client(
            connection.raw(),
            bootstrap_process.raw(),
            &bootstrap_job,
            &bootstrap_identity,
            &holder_envelope,
            &observed_holder_snapshot,
            &executable,
        )?;
        let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            Some(bootstrap_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
        )?;
        match loader_ready {
            TargetDesktopBootstrapMessageV1::LoaderReady {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
                bootstrap_identity: observed_identity,
                process_envelope: observed_envelope,
                process_snapshot: observed_snapshot,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == binding.nonce
                && observed_desktop.is_none()
                && observed_identity == bootstrap_identity
                && observed_envelope == holder_envelope
                && observed_snapshot == observed_holder_snapshot => {}
            _ => {
                return Err("target desktop bootstrap LoaderReady frame is invalid"
                    .to_owned()
                    .into());
            }
        }
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(bootstrap_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionWrite,
            &TargetDesktopBootstrapMessageV1::Admission {
                binding: binding.clone(),
                launcher_process_query_handle: launcher_process_handle,
                launcher_token_query_handle: launcher_token_handle,
                target_token_capability_handle: Some(target_token_handle),
            },
        )?;
        let frame = read_target_desktop_bootstrap_attestation(
            connection.raw(),
            bootstrap_process.raw(),
            Instant::now() + Duration::from_secs(30),
            &binding,
            Some(&mut broker_control),
        )?;
        if frame.schema_version != TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
            || frame.bootstrap_identity != bootstrap_identity
            || frame.target_envelope != target_envelope
            || frame.target_envelope.session_id != target_envelope.session_id
            || frame.window_station_policy_sha256 != expected_window_station_policy_sha256
            || frame.desktop_policy_sha256 != expected_desktop_policy_sha256
            || !frame.source_objects_unmodified
            || !frame.private_station_assigned
            || !frame.private_desktop_assigned
            || !frame.desktop_containment_verified
            || !frame.window_station_policy_verified
            || !frame.desktop_policy_verified
            || !frame.window_station_not_inheritable
            || !frame.desktop_not_inheritable
            || !frame.noninteractive
        {
            return Err(
                "target desktop bootstrap attestation is incomplete or mismatched"
                    .to_owned()
                    .into(),
            );
        }
        validate_target_desktop_binding(&frame.window_station_name, &frame.desktop_name)?;
        broker_control.finish(&binding.binding_sha256)?;
        let exact_name = format!("{}\\{}", frame.window_station_name, frame.desktop_name);
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let lease = Self {
            bootstrap_process,
            bootstrap_job,
            connection_lease: Some(connection),
            bootstrap_identity,
            holder_envelope,
            broker_source_snapshot,
            holder_launch_snapshot,
            holder_process_snapshot: observed_holder_snapshot,
            holder_binding: binding,
            window_station_name: frame.window_station_name,
            desktop_name: frame.desktop_name,
            window_station_policy_sha256: frame.window_station_policy_sha256,
            desktop_policy_sha256: frame.desktop_policy_sha256,
            window_station_live_equality_sha256: frame.window_station_live_equality_sha256,
            desktop_live_equality_sha256: frame.desktop_live_equality_sha256,
            exact_name,
            startup_name,
        };
        lease.attest_live()?;
        launch_target_desktop_probe(
            token,
            &target_envelope,
            &launcher_token,
            &launcher_envelope,
            &launcher_snapshot,
            &lease.broker_source_snapshot,
            &lease.holder_launch_snapshot,
            &lease.holder_process_snapshot,
            &target_snapshot,
            &launcher_identity,
            policy_role,
            &lease.exact_name,
            &expected_window_station_policy_sha256,
            &expected_desktop_policy_sha256,
            &launch_context,
            &lease,
            loader_restriction_canary,
        )?;
        lease.attest_live()?;
        Ok(lease)
    }

    fn attest_live(&self) -> Result<(), String> {
        validate_target_desktop_binding(&self.window_station_name, &self.desktop_name)?;
        if self.broker_source_snapshot.lineage.user_sid != "S-1-5-18"
            || self.broker_source_snapshot.lineage.session_id != 0
            || self.broker_source_snapshot.behavior.token_is_restricted
            || !self
                .broker_source_snapshot
                .behavior
                .restricting_sids
                .is_empty()
        {
            return Err("retained session-broker source evidence is invalid".to_owned());
        }
        if unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 0) } != WAIT_TIMEOUT {
            return Err(
                "target desktop bootstrap exited while its desktop lease was live".to_owned(),
            );
        }
        if process_identity(self.bootstrap_process.raw())? != self.bootstrap_identity {
            return Err("target desktop bootstrap process identity changed".to_owned());
        }
        let observed = super::token::process_token_query_attestation(self.bootstrap_process.raw())?;
        super::token::require_same_process_token_query(
            "holder-process-live",
            &self.holder_process_snapshot,
            &observed,
        )
        .map_err(|error| error.to_string())?;
        if observed.behavior.envelope != self.holder_envelope {
            return Err("target desktop holder token envelope changed".to_owned());
        }
        super::token::require_assigned_process_authority(
            "holder-launch-to-live-process",
            &self.holder_launch_snapshot,
            &observed,
        )
        .map_err(|error| error.to_string())?;
        if !self.bootstrap_job.contains(self.bootstrap_process.raw())? {
            return Err("target desktop bootstrap left its atomic Job".to_owned());
        }
        let connection = self
            .connection_lease
            .as_ref()
            .ok_or_else(|| "target desktop bootstrap connection lease is absent".to_owned())?;
        let (pipe_pid, pipe_session_id) =
            target_desktop_bootstrap_client_identity(connection.raw())?;
        if pipe_pid != self.bootstrap_identity.process_id
            || pipe_session_id != self.holder_envelope.session_id
        {
            return Err("target desktop bootstrap pipe peer identity changed".to_owned());
        }
        if !super::pipe::target_desktop_bootstrap_pipe_is_quiet(connection.raw())? {
            return Err("target desktop bootstrap sent data after Ready".to_owned());
        }
        Ok(())
    }
}

impl Drop for TargetDesktopLease {
    fn drop(&mut self) {
        drop(self.connection_lease.take());
        if unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 5_000) } == WAIT_TIMEOUT {
            let _ = self
                .bootstrap_job
                .terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS);
            let _ = unsafe { WaitForSingleObject(self.bootstrap_process.raw(), 5_000) };
        }
    }
}

fn validate_target_association_preflight_grants(
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    thread_token_absent: bool,
) -> Result<(), String> {
    if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        || desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS
            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        || !thread_token_absent
    {
        Err(format!(
            "station_requested={:#010x} station_granted={window_station_granted_access:#010x} desktop_requested={:#010x} desktop_granted={desktop_granted_access:#010x} thread_token_absent={thread_token_absent}",
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn target_association_preflight_grants_for_test(
    window_station_granted_access: u32,
    desktop_granted_access: u32,
    thread_token_absent: bool,
) -> Result<(), String> {
    validate_target_association_preflight_grants(
        window_station_granted_access,
        desktop_granted_access,
        thread_token_absent,
    )
}

pub(crate) fn target_association_preflight_progress_for_test(
    last_sequence: u32,
    last_stage_ordinal: Option<u32>,
    last_completed: u32,
    last_total: Option<u32>,
    sequence: u32,
    stage_ordinal: u32,
    completed: u32,
    total: Option<u32>,
) -> Result<(), String> {
    let stage = target_association_preflight_stage_from_ordinal(stage_ordinal)?;
    let last_stage = last_stage_ordinal
        .map(target_association_preflight_stage_from_ordinal)
        .transpose()?;
    let mut cursor = AssociationPreflightProgressCursor {
        sequence: last_sequence,
        stage: last_stage,
        completed: last_completed,
        total: last_total,
    };
    cursor
        .advance(sequence, stage, completed, total)
        .map(|_| ())
}

fn target_association_preflight_stage_from_ordinal(
    ordinal: u32,
) -> Result<TargetAssociationPreflightStageV1, String> {
    match ordinal {
        0 => Ok(TargetAssociationPreflightStageV1::RetainedNamespaceBefore),
        1 => Ok(TargetAssociationPreflightStageV1::SourceBootstrap),
        2 => Ok(TargetAssociationPreflightStageV1::SourceSystemAncestry),
        3 => Ok(TargetAssociationPreflightStageV1::SourceLoaderGraph),
        4 => Ok(TargetAssociationPreflightStageV1::SourceKnownDlls),
        5 => Ok(TargetAssociationPreflightStageV1::TargetTokenInstallation),
        6 => Ok(TargetAssociationPreflightStageV1::TargetWindowStation),
        7 => Ok(TargetAssociationPreflightStageV1::TargetDesktop),
        8 => Ok(TargetAssociationPreflightStageV1::TargetBootstrap),
        9 => Ok(TargetAssociationPreflightStageV1::TargetKnownDlls),
        10 => Ok(TargetAssociationPreflightStageV1::TargetModules),
        11 => Ok(TargetAssociationPreflightStageV1::RevertAndFinalization),
        _ => Err(format!(
            "association-preflight stage ordinal is unknown: {ordinal}"
        )),
    }
}

fn request_holder_target_association_preflight(
    holder_lease: &TargetDesktopLease,
    expected_target_snapshot: &super::token::TokenAttestationSnapshot,
    expected_station_policy_sha256: &str,
    expected_desktop_policy_sha256: &str,
) -> Result<TargetUserObjectOpenPreflightV1, TargetDesktopLeaseCreateError> {
    let connection = holder_lease
        .connection_lease
        .as_ref()
        .ok_or_else(|| "target desktop holder connection lease is absent".to_owned())?;
    let started = Instant::now();
    let overall_deadline = started + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT;
    let mut progress = AssociationPreflightProgressCursor::default();
    let result = (|| {
        super::pipe::write_frame_bounded(
            connection.raw(),
            Some(holder_lease.bootstrap_process.raw()),
            (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
            super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightWrite,
            &TargetDesktopBootstrapMessageV1::AssociationPreflight {
                binding: holder_lease.holder_binding.clone(),
            },
        )?;
        loop {
            let response: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
                connection.raw(),
                Some(holder_lease.bootstrap_process.raw()),
                (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
                super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyRead,
            )?;
            match response {
                TargetDesktopBootstrapMessageV1::AssociationPreflightProgress {
                    binding,
                    sequence,
                    stage,
                    completed,
                    total,
                } if binding == holder_lease.holder_binding => {
                    progress
                        .advance(sequence, stage, completed, total)
                        .map_err(TargetDesktopLeaseCreateError::from)?;
                    continue;
                }
                TargetDesktopBootstrapMessageV1::AssociationPreflightReady {
                    binding,
                    evidence,
                } if binding == holder_lease.holder_binding => {
                    if !progress.is_terminal() {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "target desktop holder association-preflight Ready arrived before final progress"
                                .to_owned(),
                        ));
                    }
                    validate_target_association_preflight_grants(
                        evidence.window_station_granted_access,
                        evidence.desktop_granted_access,
                        evidence.thread_token_absent,
                    )
                    .map_err(|detail| {
                        TargetDesktopLeaseCreateError::from(format!(
                            "holder target-association preflight access evidence is incomplete: {detail}"
                        ))
                    })?;
                    if evidence.window_station_policy_sha256 != expected_station_policy_sha256
                        || evidence.desktop_policy_sha256 != expected_desktop_policy_sha256
                        || evidence.window_station_policy_sha256
                            != holder_lease.window_station_policy_sha256
                        || evidence.desktop_policy_sha256 != holder_lease.desktop_policy_sha256
                        || evidence.window_station_live_equality_sha256
                            != holder_lease.window_station_live_equality_sha256
                        || evidence.desktop_live_equality_sha256
                            != holder_lease.desktop_live_equality_sha256
                        || !evidence.window_station_policy_verified_after_open
                        || !evidence.desktop_policy_verified_after_open
                        || !evidence.creator_live_baselines_unchanged
                    {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "holder target-association preflight policy or live-equality evidence is incomplete"
                                .to_owned(),
                        ));
                    }
                    super::token::require_same_token_instance(
                        "holder-association-preflight-before",
                        expected_target_snapshot,
                        &evidence.target_snapshot_before,
                    )?;
                    super::token::require_same_token_instance(
                        "holder-association-preflight-after",
                        expected_target_snapshot,
                        &evidence.target_snapshot_after,
                    )?;
                    evidence.native_loader_access.validate().map_err(|detail| {
                        TargetDesktopLeaseCreateError::from(format!(
                            "holder native loader access evidence is invalid: {detail}"
                        ))
                    })?;
                    return Ok(*evidence);
                }
                TargetDesktopBootstrapMessageV1::Failed {
                    binding,
                    phase,
                    native_code,
                    detail,
                } => {
                    return Err(validate_target_desktop_bootstrap_failure(
                        "association-preflight",
                        binding,
                        &holder_lease.holder_binding,
                        phase,
                        native_code,
                        detail,
                    ));
                }
                _ => return Err(TargetDesktopLeaseCreateError::from(
                    "target desktop holder association-preflight frame is invalid or out of order"
                        .to_owned(),
                )),
            }
        }
    })();
    match result {
        Ok(evidence) => Ok(evidence),
        Err(mut error) => {
            let cleanup = terminate_and_drain_failed_association_preflight(holder_lease);
            error.detail = format!(
                "{} last_stage={} sequence={} completed={} total={} elapsed_ms={} idle_timeout_ms={} overall_timeout_ms={} {cleanup}",
                error.detail,
                progress
                    .stage
                    .map_or("none", TargetAssociationPreflightStageV1::diagnostic),
                progress.sequence,
                progress.completed,
                progress
                    .total
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                started.elapsed().as_millis(),
                TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT.as_millis(),
                TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT.as_millis(),
            );
            Err(error)
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct AssociationPreflightProgressCursor {
    sequence: u32,
    stage: Option<TargetAssociationPreflightStageV1>,
    completed: u32,
    total: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AssociationPreflightProgressTransition {
    StageEntered,
    UnitAdvanced,
    StageClosed,
}

impl AssociationPreflightProgressCursor {
    fn validate_next(
        &self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<AssociationPreflightProgressTransition, String> {
        validate_target_association_preflight_progress(self, sequence, stage, completed, total)
    }

    fn commit(
        &mut self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) {
        self.sequence = sequence;
        self.stage = Some(stage);
        self.completed = completed;
        self.total = total;
    }

    fn advance(
        &mut self,
        sequence: u32,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<AssociationPreflightProgressTransition, String> {
        let transition = self.validate_next(sequence, stage, completed, total)?;
        self.commit(sequence, stage, completed, total);
        Ok(transition)
    }

    fn is_terminal(&self) -> bool {
        self.stage == Some(TargetAssociationPreflightStageV1::RevertAndFinalization)
            && self.completed == 1
            && self.total == Some(1)
    }
}

fn validate_target_association_preflight_progress(
    cursor: &AssociationPreflightProgressCursor,
    sequence: u32,
    stage: TargetAssociationPreflightStageV1,
    completed: u32,
    total: Option<u32>,
) -> Result<AssociationPreflightProgressTransition, String> {
    let invalid_reason = if sequence == 0 {
        Some("sequence is zero")
    } else if sequence > TARGET_ASSOCIATION_PREFLIGHT_MAX_PROGRESS_FRAMES {
        Some("sequence exceeds the progress-frame bound")
    } else if cursor.sequence.checked_add(1) != Some(sequence) {
        Some("sequence is not the exact successor")
    } else if total.is_some_and(|total| completed > total) {
        Some("completed exceeds total")
    } else if cursor.stage.is_none()
        && (cursor.sequence != 0 || cursor.completed != 0 || cursor.total.is_some())
    {
        Some("initial progress history is inconsistent")
    } else if cursor.stage.is_some() && cursor.sequence == 0 {
        Some("established progress history has a zero sequence")
    } else if cursor.stage.is_none()
        && stage != TargetAssociationPreflightStageV1::RetainedNamespaceBefore
    {
        Some("first progress stage is not retained-namespace-before")
    } else if cursor.stage.is_none() && completed != 0 {
        Some("first progress stage has a nonzero completed count")
    } else if let Some(last_stage) = cursor.stage {
        if stage == last_stage {
            if cursor.total == Some(cursor.completed) {
                Some("closed stage emitted another frame")
            } else if completed < cursor.completed {
                Some("completed regressed within the stage")
            } else if cursor.total.is_some() && total.is_none() {
                Some("known total became unknown within the stage")
            } else if cursor.total.is_some() && cursor.total != total {
                Some("known total mutated within the stage")
            } else if completed == cursor.completed
                && !(cursor.total.is_none() && total == Some(completed))
            {
                Some("frame carries no meaningful forward progress")
            } else {
                None
            }
        } else if last_stage.successor() != Some(stage) {
            Some("stage is not the exact successor")
        } else if cursor.total != Some(cursor.completed) {
            Some("previous stage has no exact completion frame")
        } else if completed != 0 {
            Some("new stage has a nonzero completed count")
        } else {
            None
        }
    } else {
        None
    };
    if let Some(reason) = invalid_reason {
        return Err(format!(
            "association-preflight progress is invalid: reason={reason} last_sequence={} sequence={sequence} last_stage={} last_completed={} last_total={} stage={} completed={completed} total={}",
            cursor.sequence,
            cursor
                .stage
                .map_or("none", TargetAssociationPreflightStageV1::diagnostic),
            cursor.completed,
            cursor
                .total
                .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
            stage.diagnostic(),
            total.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
        ));
    }
    if cursor.stage != Some(stage) {
        Ok(AssociationPreflightProgressTransition::StageEntered)
    } else if completed == cursor.completed {
        Ok(AssociationPreflightProgressTransition::StageClosed)
    } else if total == Some(completed) {
        Ok(AssociationPreflightProgressTransition::StageClosed)
    } else {
        Ok(AssociationPreflightProgressTransition::UnitAdvanced)
    }
}

fn terminate_and_drain_failed_association_preflight(holder_lease: &TargetDesktopLease) -> String {
    let peer_state = match unsafe { WaitForSingleObject(holder_lease.bootstrap_process.raw(), 0) } {
        WAIT_OBJECT_0 => "exited",
        WAIT_TIMEOUT => "live",
        _ => "wait-failed",
    };
    let holder_job = &holder_lease.bootstrap_job;
    let terminate = super::job::Job::terminate(holder_job, TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)
        .map_or_else(|error| format!("error:{error}"), |()| "ok".to_owned());
    let drain = holder_job
        .wait_empty(Instant::now() + Duration::from_secs(5))
        .map_or_else(
            |error| format!("error:{error}"),
            |empty| format!("empty={empty}"),
        );
    format!("peer_state={peer_state} cleanup_terminate={terminate} cleanup_drain={drain}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderEnvironmentModeV4 {
    Empty,
    CanonicalMinimalSystem,
}

impl LoaderEnvironmentModeV4 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Empty => "explicit-empty",
            Self::CanonicalMinimalSystem => "canonical-minimal-system",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LoaderControlMatrixCellV4 {
    environment: LoaderEnvironmentModeV4,
    debugger: LoaderDebuggerRelationV5,
    loader_snaps: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderDebuggerRelationV5 {
    None,
    MandatoryPump,
    FullObserver,
}

impl LoaderDebuggerRelationV5 {
    const fn observer(self) -> Option<super::loader_debug::LoaderDebugObserverV5> {
        match self {
            Self::None => None,
            Self::MandatoryPump => Some(super::loader_debug::LoaderDebugObserverV5::MandatoryPump),
            Self::FullObserver => Some(super::loader_debug::LoaderDebugObserverV5::FullObserver),
        }
    }
}

impl LoaderControlMatrixCellV4 {
    const PRODUCTION: Self = Self {
        environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
        debugger: LoaderDebuggerRelationV5::None,
        loader_snaps: false,
    };
    const RESTRICTION_FULL_OBSERVER_SNAPS_OFF: Self = Self {
        environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
        debugger: LoaderDebuggerRelationV5::FullObserver,
        loader_snaps: false,
    };
    const CERTIFICATION: [Self; 6] = [
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::None,
            loader_snaps: false,
        },
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::MandatoryPump,
            loader_snaps: false,
        },
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::FullObserver,
            loader_snaps: false,
        },
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::None,
            loader_snaps: true,
        },
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::MandatoryPump,
            loader_snaps: true,
        },
        Self {
            environment: LoaderEnvironmentModeV4::CanonicalMinimalSystem,
            debugger: LoaderDebuggerRelationV5::FullObserver,
            loader_snaps: true,
        },
    ];

    const fn diagnostic(self) -> &'static str {
        match (self.environment, self.debugger, self.loader_snaps) {
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::None, false) => {
                "explicit-empty-none-snaps-off"
            }
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::MandatoryPump, false) => {
                "explicit-empty-minimal-pump-snaps-off"
            }
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::FullObserver, false) => {
                "explicit-empty-full-observer-snaps-off"
            }
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::None, true) => {
                "explicit-empty-none-snaps-on"
            }
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::MandatoryPump, true) => {
                "explicit-empty-minimal-pump-snaps-on"
            }
            (LoaderEnvironmentModeV4::Empty, LoaderDebuggerRelationV5::FullObserver, true) => {
                "explicit-empty-full-observer-snaps-on"
            }
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::None,
                false,
            ) => "canonical-minimal-system-none-snaps-off",
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::MandatoryPump,
                false,
            ) => "canonical-minimal-system-minimal-pump-snaps-off",
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::FullObserver,
                false,
            ) => "canonical-minimal-system-full-observer-snaps-off",
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::None,
                true,
            ) => "canonical-minimal-system-none-snaps-on",
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::MandatoryPump,
                true,
            ) => "canonical-minimal-system-minimal-pump-snaps-on",
            (
                LoaderEnvironmentModeV4::CanonicalMinimalSystem,
                LoaderDebuggerRelationV5::FullObserver,
                true,
            ) => "canonical-minimal-system-full-observer-snaps-on",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum LoaderFailureEvidenceRankV6 {
    Unclassified,
    NativeExit,
    MandatoryPumpSnapsOff,
    MandatoryPumpSnapsOn,
    FullObserverSnapsOff,
    FullObserverSnapsOn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderControlMatrixOutcomeKindV6 {
    Passed,
    Failed,
}

impl LoaderControlMatrixOutcomeKindV6 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderControlMatrixOutcomeV6 {
    cell: &'static str,
    outcome: LoaderControlMatrixOutcomeKindV6,
    native_status: Option<i32>,
    failure_phase: &'static str,
    child_trace: bool,
    detail_sha256: String,
}

const LOADER_RESTRICTION_CANARY_DETAIL_MAX_BYTES: usize = 512;

pub(crate) struct LoaderRestrictionCanaryTokens {
    baseline: OwnedHandle,
    comparison: OwnedHandle,
    no_restricting_sid: OwnedHandle,
    profile: OwnedHandle,
    source_binding_sha256: String,
    pair_invariants_sha256: String,
    restriction_presence_binding_sha256: String,
    profile_binding_sha256: String,
}

impl LoaderRestrictionCanaryTokens {
    pub(crate) fn from_transferred(
        effective: HANDLE,
        baseline: OwnedHandle,
        comparison: OwnedHandle,
        no_restricting_sid: OwnedHandle,
        profile: OwnedHandle,
        source_binding_sha256: String,
        pair_invariants_sha256: String,
        restriction_presence_binding_sha256: String,
        profile_binding_sha256: String,
    ) -> Result<Self, String> {
        let digest_length = super::record::digest(&[]).len();
        if source_binding_sha256.len() != digest_length
            || pair_invariants_sha256.len() != digest_length
            || restriction_presence_binding_sha256.len() != digest_length
            || profile_binding_sha256.len() != digest_length
        {
            return Err("loader restriction canary binding digest has invalid length".to_owned());
        }
        super::token::validate_transferred_loader_restriction_diagnostic_pair(
            effective,
            baseline.raw(),
            comparison.raw(),
            &pair_invariants_sha256,
        )?;
        super::token::validate_transferred_loader_restriction_presence_pair(
            baseline.raw(),
            no_restricting_sid.raw(),
            &source_binding_sha256,
            &restriction_presence_binding_sha256,
        )?;
        super::token::validate_transferred_loader_profile_capability(
            effective,
            profile.raw(),
            &source_binding_sha256,
            &pair_invariants_sha256,
            &profile_binding_sha256,
        )?;
        Ok(Self {
            baseline,
            comparison,
            no_restricting_sid,
            profile,
            source_binding_sha256,
            pair_invariants_sha256,
            restriction_presence_binding_sha256,
            profile_binding_sha256,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderRestrictionCanaryOutcomeV1 {
    restriction: &'static str,
    outcome: LoaderControlMatrixOutcomeKindV6,
    native_status: Option<i32>,
    failure_phase: &'static str,
    detail_sha256: String,
    detail: String,
}

struct LoaderRestrictionCanaryEvaluationV1 {
    diagnostic: String,
    target_environment_required: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderEnvironmentCanaryOutcomeV1 {
    environment: &'static str,
    outcome: LoaderControlMatrixOutcomeKindV6,
    native_status: Option<i32>,
    failure_phase: &'static str,
    detail_sha256: String,
    detail: String,
}

struct LoaderEnvironmentPrerequisiteEvaluationV1 {
    diagnostic: String,
    profile_required: bool,
    comparison: LoaderEnvironmentCanaryOutcomeV1,
}

struct LoaderProfilePrerequisiteEvaluationV1 {
    diagnostic: String,
    object_security_required: bool,
    comparison: Option<Result<String, TargetDesktopLeaseCreateError>>,
}

struct LoaderObjectSecurityPrerequisiteEvaluationV1 {
    diagnostic: String,
    restriction_presence_required: bool,
}

struct LoaderRestrictionPresencePrerequisiteEvaluationV1 {
    diagnostic: String,
}

impl LoaderEnvironmentCanaryOutcomeV1 {
    fn diagnostic(&self) -> String {
        format!(
            "environment={}:outcome={}:native={}:phase={}:detail_sha256={}:detail={}",
            self.environment,
            self.outcome.diagnostic(),
            self.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            self.failure_phase,
            self.detail_sha256,
            self.detail,
        )
    }
}

impl LoaderRestrictionCanaryOutcomeV1 {
    fn diagnostic(&self) -> String {
        format!(
            "restriction={}:outcome={}:native={}:phase={}:detail_sha256={}:detail={}",
            self.restriction,
            self.outcome.diagnostic(),
            self.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            self.failure_phase,
            self.detail_sha256,
            self.detail,
        )
    }
}

fn bounded_loader_restriction_canary_detail(detail: &str) -> String {
    let mut bounded = detail.replace('\0', "\\0");
    if bounded.len() > LOADER_RESTRICTION_CANARY_DETAIL_MAX_BYTES {
        let mut boundary = LOADER_RESTRICTION_CANARY_DETAIL_MAX_BYTES;
        while !bounded.is_char_boundary(boundary) {
            boundary -= 1;
        }
        bounded.truncate(boundary);
    }
    bounded
}

fn loader_restriction_canary_outcome(
    restriction: &'static str,
    result: &Result<String, TargetDesktopLeaseCreateError>,
) -> LoaderRestrictionCanaryOutcomeV1 {
    match result {
        Ok(evidence) => LoaderRestrictionCanaryOutcomeV1 {
            restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: super::record::digest(evidence.as_bytes()),
            detail: "passed".to_owned(),
        },
        Err(error) => LoaderRestrictionCanaryOutcomeV1 {
            restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Failed,
            native_status: error.os_code,
            failure_phase: loader_failure_phase(error),
            detail_sha256: super::record::digest(error.detail.as_bytes()),
            detail: bounded_loader_restriction_canary_detail(&error.detail),
        },
    }
}

fn loader_restriction_canary_preflight_failure(
    stage: &'static str,
    error: String,
) -> LoaderRestrictionCanaryOutcomeV1 {
    LoaderRestrictionCanaryOutcomeV1 {
        restriction: "write-restricted-same-sid",
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: None,
        failure_phase: stage,
        detail_sha256: super::record::digest(error.as_bytes()),
        detail: bounded_loader_restriction_canary_detail(&error),
    }
}

fn loader_restriction_canary_is_required(results: &[LoaderControlMatrixOutcomeV6]) -> bool {
    results.len() == LoaderControlMatrixCellV4::CERTIFICATION.len()
        && results
            .iter()
            .all(|result| result.outcome == LoaderControlMatrixOutcomeKindV6::Failed)
}

#[cfg(test)]
pub(crate) fn loader_restriction_canary_required_for_test(failed_cells: usize) -> bool {
    let results = LoaderControlMatrixCellV4::CERTIFICATION
        .iter()
        .enumerate()
        .map(|(index, cell)| LoaderControlMatrixOutcomeV6 {
            cell: cell.diagnostic(),
            outcome: if index < failed_cells {
                LoaderControlMatrixOutcomeKindV6::Failed
            } else {
                LoaderControlMatrixOutcomeKindV6::Passed
            },
            native_status: (index < failed_cells).then_some(0xc000_0142_u32 as i32),
            failure_phase: if index < failed_cells {
                "pre-initial-breakpoint-static-loader"
            } else {
                "none"
            },
            child_trace: index < failed_cells,
            detail_sha256: super::record::digest(cell.diagnostic().as_bytes()),
        })
        .collect::<Vec<_>>();
    loader_restriction_canary_is_required(&results)
}

#[cfg(test)]
pub(crate) fn render_loader_restriction_canary_for_test(
    comparison_passes: bool,
    comparison_detail: &str,
) -> (String, String, bool) {
    let primary_detail = "authoritative full-restricted failure".to_owned();
    let baseline = Err(TargetDesktopLeaseCreateError {
        detail: primary_detail.clone(),
        os_code: Some(0xc000_0142_u32 as i32),
        loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
    });
    let comparison = if comparison_passes {
        Ok(comparison_detail.to_owned())
    } else {
        Err(TargetDesktopLeaseCreateError {
            detail: comparison_detail.to_owned(),
            os_code: Some(0xc000_0142_u32 as i32),
            loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
        })
    };
    let diagnostic = format!(
        "loader_init_prerequisite_canary=v1 baseline=[{}] comparison=[{}] selected_failure=[{}]",
        loader_restriction_canary_outcome("full-restricted", &baseline).diagnostic(),
        loader_restriction_canary_outcome("write-restricted", &comparison).diagnostic(),
        primary_detail,
    );
    (diagnostic, primary_detail, false)
}

impl LoaderControlMatrixOutcomeV6 {
    fn diagnostic(&self) -> String {
        format!(
            "cell={}:outcome={}:native={}:phase={}:child_trace={}:detail_sha256={}",
            self.cell,
            self.outcome.diagnostic(),
            self.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            self.failure_phase,
            self.child_trace,
            self.detail_sha256,
        )
    }
}

fn loader_failure_phase(error: &TargetDesktopLeaseCreateError) -> &'static str {
    error.loader_phase.diagnostic()
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoaderLaunchFailureBoundaryForTest {
    PreCreate,
    PostResumePreLoaderReady,
    PostLoaderReadyContainment,
    ExitDrain,
    Unknown,
}

#[cfg(test)]
pub(crate) fn loader_failure_phase_for_test(
    boundary: LoaderLaunchFailureBoundaryForTest,
    _untrusted_detail: &str,
) -> &'static str {
    match boundary {
        LoaderLaunchFailureBoundaryForTest::PreCreate => LoaderLaunchFailurePhaseV1::PreCreate,
        LoaderLaunchFailureBoundaryForTest::PostResumePreLoaderReady => {
            LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady
        }
        LoaderLaunchFailureBoundaryForTest::PostLoaderReadyContainment => {
            LoaderLaunchFailurePhaseV1::PostLoaderReadyContainment
        }
        LoaderLaunchFailureBoundaryForTest::ExitDrain => LoaderLaunchFailurePhaseV1::ExitDrain,
        LoaderLaunchFailureBoundaryForTest::Unknown => LoaderLaunchFailurePhaseV1::Unknown,
    }
    .diagnostic()
}

impl LoaderFailureEvidenceRankV6 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Unclassified => "unclassified",
            Self::NativeExit => "native-exit",
            Self::MandatoryPumpSnapsOff => "mandatory-pump-snaps-off",
            Self::MandatoryPumpSnapsOn => "mandatory-pump-snaps-on",
            Self::FullObserverSnapsOff => "full-observer-snaps-off",
            Self::FullObserverSnapsOn => "full-observer-snaps-on",
        }
    }
}

fn loader_failure_evidence_rank(
    cell: LoaderControlMatrixCellV4,
    error: &TargetDesktopLeaseCreateError,
) -> LoaderFailureEvidenceRankV6 {
    let has_native_trace = error.os_code.is_some() && error.detail.contains("loader_trace=v4");
    if !has_native_trace {
        return if error.os_code.is_some() {
            LoaderFailureEvidenceRankV6::NativeExit
        } else {
            LoaderFailureEvidenceRankV6::Unclassified
        };
    }
    match (cell.debugger, cell.loader_snaps) {
        (LoaderDebuggerRelationV5::FullObserver, true) => {
            LoaderFailureEvidenceRankV6::FullObserverSnapsOn
        }
        (LoaderDebuggerRelationV5::FullObserver, false) => {
            LoaderFailureEvidenceRankV6::FullObserverSnapsOff
        }
        (LoaderDebuggerRelationV5::MandatoryPump, true) => {
            LoaderFailureEvidenceRankV6::MandatoryPumpSnapsOn
        }
        (LoaderDebuggerRelationV5::MandatoryPump, false) => {
            LoaderFailureEvidenceRankV6::MandatoryPumpSnapsOff
        }
        (LoaderDebuggerRelationV5::None, _) => LoaderFailureEvidenceRankV6::NativeExit,
    }
}

fn loader_failure_should_replace(
    selected: Option<LoaderFailureEvidenceRankV6>,
    candidate: LoaderFailureEvidenceRankV6,
) -> bool {
    selected.map_or(true, |selected| candidate > selected)
}

fn loader_control_matrix_failure_detail(
    selected_cell: &'static str,
    selected_rank: LoaderFailureEvidenceRankV6,
    selected_native: Option<i32>,
    results: &[LoaderControlMatrixOutcomeV6],
    selected_detail: &str,
) -> String {
    format!(
        "loader_control_matrix=v6 dimensions=debugger-relation-x-loader-snaps environment={} selected_cell={} selected_rank={} selected_native={} completed={} results=[{}] selected_failure=[{}]",
        LoaderEnvironmentModeV4::CanonicalMinimalSystem.diagnostic(),
        selected_cell,
        selected_rank.diagnostic(),
        selected_native.map_or_else(
            || "unavailable".to_owned(),
            |code| format!("0x{:08x}", code as u32)
        ),
        results.len(),
        results
            .iter()
            .map(LoaderControlMatrixOutcomeV6::diagnostic)
            .collect::<Vec<_>>()
            .join(","),
        selected_detail,
    )
}

fn loader_result_detail(result: &Result<String, TargetDesktopLeaseCreateError>) -> &str {
    match result {
        Ok(evidence) => evidence,
        Err(error) => &error.detail,
    }
}

fn loader_result_field(
    result: &Result<String, TargetDesktopLeaseCreateError>,
    field: &str,
) -> Option<String> {
    let prefix = format!("{field}=");
    loader_result_detail(result)
        .split_ascii_whitespace()
        .find_map(|value| value.strip_prefix(&prefix))
        .map(|value| value.trim_end_matches([',', ']', ';']).to_owned())
}

fn loader_common_result_field(
    baseline: &Result<String, TargetDesktopLeaseCreateError>,
    comparison: &Result<String, TargetDesktopLeaseCreateError>,
    field: &str,
) -> Result<String, String> {
    let baseline = loader_result_field(baseline, field)
        .ok_or_else(|| format!("baseline {field} is unavailable"))?;
    let comparison = loader_result_field(comparison, field)
        .ok_or_else(|| format!("comparison {field} is unavailable"))?;
    if baseline != comparison {
        return Err(format!("{field} differs across the one-factor pair"));
    }
    Ok(baseline)
}

fn loader_control_cell_job_empty_attested(
    result: &Result<String, TargetDesktopLeaseCreateError>,
) -> bool {
    let detail = loader_result_detail(result);
    if let Some(cleanup) = detail
        .rsplit_once(" profile_child_cleanup=[")
        .and_then(|(_, cleanup)| cleanup.strip_suffix(']'))
    {
        return cleanup
            .split(',')
            .rev()
            .find_map(|field| field.strip_prefix("job_empty_after_cleanup="))
            == Some("true");
    }
    loader_result_field(result, "job_empty").as_deref() == Some("true")
}

const LOADER_OBJECT_SECURITY_COMMON_FIELDS_V1: [&str; 16] = [
    "matrix_cell",
    "debug_mode",
    "environment_classification",
    "environment_sha256",
    "environment_keys_sha256",
    "environment_profile_loaded",
    "source_token_sha256",
    "source_token_id",
    "source_modified_id",
    "source_authentication_id",
    "source_session_id",
    "desktop_sha256",
    "binary_sha256",
    "current_directory_sha256",
    "creation_flags",
    "job_membership_attested",
];

const LOADER_OBJECT_SECURITY_LIVE_FIELDS_V1: [&str; 8] = [
    "live_sha256",
    "dacl_protected",
    "ace_count",
    "requested",
    "target_allowed",
    "target_granted",
    "launcher_allowed",
    "launcher_granted",
];

struct LoaderObjectSecurityEvidenceValidityV1 {
    common_evidence_valid: bool,
    descriptor_evidence_present: bool,
    invariants_valid: bool,
    invariant_error: Option<String>,
}

fn loader_object_security_evidence_validity(
    results: &[&Result<String, TargetDesktopLeaseCreateError>],
    profile_stable: bool,
    authority_binding_valid: bool,
) -> LoaderObjectSecurityEvidenceValidityV1 {
    let common_error = results.split_first().and_then(|(baseline, comparisons)| {
        comparisons.iter().find_map(|comparison| {
            LOADER_OBJECT_SECURITY_COMMON_FIELDS_V1
                .iter()
                .find_map(|field| {
                    loader_common_result_field(baseline, comparison, field)
                        .err()
                        .map(|error| format!("{field}:{error}"))
                })
        })
    });
    let profile_authority_exact = !results.is_empty()
        && results.iter().all(|result| {
            loader_result_field(result, "environment_profile_loaded").as_deref() == Some("true")
        });
    let common_evidence_valid = results.len() >= 2
        && profile_stable
        && common_error.is_none()
        && authority_binding_valid
        && profile_authority_exact;
    let descriptor_evidence_present = !results.is_empty()
        && results.iter().all(|result| {
            ["process_object", "thread_object"].into_iter().all(|role| {
                LOADER_OBJECT_SECURITY_LIVE_FIELDS_V1
                    .iter()
                    .all(|field| loader_result_field(result, &format!("{role}_{field}")).is_some())
            })
        });
    let invariant_error = common_error
        .or_else(|| {
            (!profile_authority_exact).then(|| {
                "environment_profile_loaded is not present and exactly true for every cell"
                    .to_owned()
            })
        })
        .or_else(|| (!profile_stable).then(|| "profile observation changed".to_owned()))
        .or_else(|| {
            (!authority_binding_valid)
                .then(|| "object security authority binding differs".to_owned())
        })
        .or_else(|| {
            (results.len() < 2).then(|| "object security comparison evidence is absent".to_owned())
        })
        .or_else(|| {
            (!descriptor_evidence_present)
                .then(|| "live object security evidence is incomplete".to_owned())
        });
    LoaderObjectSecurityEvidenceValidityV1 {
        common_evidence_valid,
        descriptor_evidence_present,
        invariants_valid: common_evidence_valid && descriptor_evidence_present,
        invariant_error,
    }
}

#[allow(clippy::too_many_arguments)]
fn loader_restriction_canary_diagnostic(
    tokens: &LoaderRestrictionCanaryTokens,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
) -> LoaderRestrictionCanaryEvaluationV1 {
    let baseline_envelope = super::token::envelope(tokens.baseline.raw());
    let baseline_snapshot = super::token::token_attestation_snapshot(tokens.baseline.raw());
    let comparison_envelope = super::token::envelope(tokens.comparison.raw());
    let comparison_snapshot = super::token::token_attestation_snapshot(tokens.comparison.raw());
    let pair = match (
        baseline_envelope,
        baseline_snapshot,
        comparison_envelope,
        comparison_snapshot,
    ) {
        (
            Ok(baseline_envelope),
            Ok(baseline_snapshot),
            Ok(comparison_envelope),
            Ok(comparison_snapshot),
        ) => Some((
            baseline_envelope,
            baseline_snapshot,
            comparison_envelope,
            comparison_snapshot,
        )),
        results => {
            let error = format!("loader restriction pair re-attestation failed: {results:?}");
            return LoaderRestrictionCanaryEvaluationV1 {
                diagnostic: format!(
                    "loader_init_prerequisite_canary=v1 state=invalid source_binding_sha256={} pair_invariants_sha256={} error_sha256={} error={}",
                    tokens.source_binding_sha256,
                    tokens.pair_invariants_sha256,
                    super::record::digest(error.as_bytes()),
                    bounded_loader_restriction_canary_detail(&error),
                ),
                target_environment_required: false,
            };
        }
    };
    let (baseline_envelope, baseline_snapshot, comparison_envelope, comparison_snapshot) =
        pair.expect("loader restriction pair is present after successful re-attestation");
    let cell = LoaderControlMatrixCellV4::PRODUCTION;
    let baseline = launch_target_desktop_loader_control_cell(
        tokens.baseline.raw(),
        &baseline_envelope,
        &baseline_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        cell,
    );
    let comparison = launch_target_desktop_loader_control_cell(
        tokens.comparison.raw(),
        &comparison_envelope,
        &comparison_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        cell,
    );
    let baseline_outcome = loader_restriction_canary_outcome("full-restricted", &baseline);
    let comparison_outcome = loader_restriction_canary_outcome("write-restricted", &comparison);
    let common_fields = [
        "environment_sha256",
        "desktop_sha256",
        "binary_sha256",
        "current_directory_sha256",
        "command_semantics_sha256",
        "command_dynamic_fields",
        "creation_flags",
    ]
    .map(|field| {
        loader_common_result_field(&baseline, &comparison, field).map(|value| (field, value))
    });
    let common_error = common_fields
        .iter()
        .find_map(|result| result.as_ref().err());
    let state = if common_error.is_some() {
        "invalid"
    } else {
        "classified"
    };
    let common = common_fields
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|(field, value)| format!("{field}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    let process_sddl_sha256 = super::security::launcher_process_sddl()
        .map(|sddl| super::record::digest(sddl.as_bytes()))
        .unwrap_or_else(|error| super::record::digest(error.as_bytes()));
    let thread_sddl_sha256 = super::security::launcher_thread_sddl()
        .map(|sddl| super::record::digest(sddl.as_bytes()))
        .unwrap_or_else(|error| super::record::digest(error.as_bytes()));
    let baseline_modules_sha256 = loader_result_field(&baseline, "candidate_modules_sha256")
        .unwrap_or_else(|| "unavailable-no-debugger".to_owned());
    let comparison_modules_sha256 = loader_result_field(&comparison, "candidate_modules_sha256")
        .unwrap_or_else(|| "unavailable-no-debugger".to_owned());
    let baseline_unloads_sha256 = loader_result_field(&baseline, "unload_tail_sha256")
        .unwrap_or_else(|| "unavailable-no-debugger".to_owned());
    let comparison_unloads_sha256 = loader_result_field(&comparison, "unload_tail_sha256")
        .unwrap_or_else(|| "unavailable-no-debugger".to_owned());
    let invariant_error = common_error.map_or_else(
        || "none".to_owned(),
        |error| bounded_loader_restriction_canary_detail(error),
    );
    let target_environment_required = loader_target_environment_is_required(
        common_error.is_none(),
        &baseline_outcome,
        &comparison_outcome,
    );
    LoaderRestrictionCanaryEvaluationV1 {
        diagnostic: format!(
            "loader_init_prerequisite_canary=v1 state={state} baseline_semantics=full-restricted comparison_semantics=write-restricted differing_fields=[write_restricted] source_binding_sha256={} pair_invariants_sha256={} baseline=[{}] comparison=[{}] baseline_modules_sha256={} comparison_modules_sha256={} baseline_unloads_sha256={} comparison_unloads_sha256={} {} process_sddl_sha256={} thread_sddl_sha256={} job_policy_sha256={} invariant_error={}",
            tokens.source_binding_sha256,
            tokens.pair_invariants_sha256,
            baseline_outcome.diagnostic(),
            comparison_outcome.diagnostic(),
            baseline_modules_sha256,
            comparison_modules_sha256,
            baseline_unloads_sha256,
            comparison_unloads_sha256,
            common,
            process_sddl_sha256,
            thread_sddl_sha256,
            super::record::digest(b"Job::create(None,None,None)+PROC_THREAD_ATTRIBUTE_JOB_LIST"),
            invariant_error,
        ),
        target_environment_required,
    }
}

fn clone_loader_control_result(
    result: &Result<String, TargetDesktopLeaseCreateError>,
) -> Result<String, TargetDesktopLeaseCreateError> {
    match result {
        Ok(evidence) => Ok(evidence.clone()),
        Err(error) => Err(TargetDesktopLeaseCreateError {
            detail: error.detail.clone(),
            os_code: error.os_code,
            loader_phase: error.loader_phase,
        }),
    }
}

fn loader_environment_canary_outcome(
    environment: &'static str,
    result: &Result<String, TargetDesktopLeaseCreateError>,
) -> LoaderEnvironmentCanaryOutcomeV1 {
    match result {
        Ok(evidence) => LoaderEnvironmentCanaryOutcomeV1 {
            environment,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: super::record::digest(evidence.as_bytes()),
            detail: "passed".to_owned(),
        },
        Err(error) => LoaderEnvironmentCanaryOutcomeV1 {
            environment,
            outcome: LoaderControlMatrixOutcomeKindV6::Failed,
            native_status: error.os_code,
            failure_phase: loader_failure_phase(error),
            detail_sha256: super::record::digest(error.detail.as_bytes()),
            detail: bounded_loader_restriction_canary_detail(&error.detail),
        },
    }
}

fn loader_target_environment_is_required(
    invariants_valid: bool,
    baseline: &LoaderRestrictionCanaryOutcomeV1,
    comparison: &LoaderRestrictionCanaryOutcomeV1,
) -> bool {
    invariants_valid
        && baseline.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && comparison.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && baseline.native_status == Some(STATUS_DLL_INIT_FAILED)
        && comparison.native_status == Some(STATUS_DLL_INIT_FAILED)
        && baseline.failure_phase == comparison.failure_phase
}

#[cfg(test)]
pub(crate) fn loader_target_environment_required_for_test(
    invariants_valid: bool,
    baseline_failed: bool,
    baseline_native_status: Option<i32>,
    baseline_phase: &'static str,
    comparison_failed: bool,
    comparison_native_status: Option<i32>,
    comparison_phase: &'static str,
) -> bool {
    let outcome =
        |restriction, failed, native_status, failure_phase| LoaderRestrictionCanaryOutcomeV1 {
            restriction,
            outcome: if failed {
                LoaderControlMatrixOutcomeKindV6::Failed
            } else {
                LoaderControlMatrixOutcomeKindV6::Passed
            },
            native_status,
            failure_phase,
            detail_sha256: super::record::digest(b"test-loader-restriction-outcome"),
            detail: "test".to_owned(),
        };
    loader_target_environment_is_required(
        invariants_valid,
        &outcome(
            "full-restricted",
            baseline_failed,
            baseline_native_status,
            baseline_phase,
        ),
        &outcome(
            "write-restricted",
            comparison_failed,
            comparison_native_status,
            comparison_phase,
        ),
    )
}

#[allow(clippy::too_many_arguments)]
fn loader_environment_prerequisite_canary_diagnostic(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    tokens: &LoaderRestrictionCanaryTokens,
    baseline: &Result<String, TargetDesktopLeaseCreateError>,
) -> LoaderEnvironmentPrerequisiteEvaluationV1 {
    let comparison = launch_target_desktop_loader_control_cell_with_environment_authority(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        LoaderEnvironmentAuthorityV5::TargetTokenUserenv,
        LoaderObjectSecurityAuthorityV1::LauncherExplicit,
    );
    let baseline_outcome = loader_environment_canary_outcome("canonical-minimal-system", baseline);
    let comparison_outcome =
        loader_environment_canary_outcome("target-token-userenv-v1", &comparison);
    let common_fields = [
        "matrix_cell",
        "debug_mode",
        "source_token_sha256",
        "source_token_id",
        "source_modified_id",
        "source_authentication_id",
        "source_session_id",
        "desktop_sha256",
        "binary_sha256",
        "current_directory_sha256",
        "command_semantics_sha256",
        "command_dynamic_fields",
        "creation_flags",
        "job_membership_attested",
    ]
    .map(|field| {
        loader_common_result_field(baseline, &comparison, field).map(|value| (field, value))
    });
    let common_error = common_fields
        .iter()
        .find_map(|result| result.as_ref().err());
    let common = common_fields
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|(field, value)| format!("{field}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    let state = if common_error.is_some() {
        "invalid"
    } else if baseline_outcome.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && comparison_outcome.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && baseline_outcome.native_status == comparison_outcome.native_status
        && baseline_outcome.failure_phase == comparison_outcome.failure_phase
    {
        "classified-common-failure"
    } else {
        "classified"
    };
    let invariant_error = common_error.map_or_else(
        || "none".to_owned(),
        |error| bounded_loader_restriction_canary_detail(error),
    );
    let target_token_instance_sha256 = loader_snapshot_digest(
        b"memcordon-loader-target-environment-token-v1\0",
        target_snapshot,
    )
    .unwrap_or_else(|error| super::record::digest(error.detail.as_bytes()));
    let baseline_environment_sha256 = loader_result_field(baseline, "environment_sha256")
        .unwrap_or_else(|| "unavailable".to_owned());
    let comparison_environment_sha256 = loader_result_field(&comparison, "environment_sha256")
        .unwrap_or_else(|| "unavailable".to_owned());
    let comparison_environment_keys_sha256 =
        loader_result_field(&comparison, "environment_keys_sha256")
            .unwrap_or_else(|| "unavailable".to_owned());
    let comparison_environment_units = loader_result_field(&comparison, "environment_units")
        .unwrap_or_else(|| "unavailable".to_owned());
    let comparison_environment_entries = loader_result_field(&comparison, "environment_entries")
        .unwrap_or_else(|| "unavailable".to_owned());
    let diagnostic = render_loader_environment_prerequisite_canary(
        state,
        &baseline_outcome,
        &comparison_outcome,
        &tokens.source_binding_sha256,
        &tokens.pair_invariants_sha256,
        &target_token_instance_sha256,
        &baseline_environment_sha256,
        &comparison_environment_sha256,
        &comparison_environment_keys_sha256,
        &comparison_environment_units,
        &comparison_environment_entries,
        &common,
        &invariant_error,
    );
    LoaderEnvironmentPrerequisiteEvaluationV1 {
        profile_required: state == "classified-common-failure"
            && comparison_outcome.native_status == Some(STATUS_DLL_INIT_FAILED),
        diagnostic,
        comparison: comparison_outcome,
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_arguments)]
fn loader_profile_prerequisite_canary_diagnostic(
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    tokens: &LoaderRestrictionCanaryTokens,
    environment_baseline: &LoaderEnvironmentCanaryOutcomeV1,
) -> LoaderProfilePrerequisiteEvaluationV1 {
    let target_snapshot = match super::token::token_attestation_snapshot(tokens.baseline.raw()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return LoaderProfilePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_profile_prerequisite_canary=v1 state=invalid stage=target-attestation error_sha256={} workload_executed=false qualification_promoted=false",
                    super::record::digest(error.as_bytes())
                ),
                object_security_required: false,
                comparison: None,
            };
        }
    };
    let target_envelope = target_snapshot.behavior.envelope.clone();
    let before = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
    let run = |authority| {
        launch_target_desktop_loader_control_cell_with_environment_authority(
            tokens.baseline.raw(),
            &target_envelope,
            &target_snapshot,
            exact_desktop,
            launch_context,
            association_preflight,
            holder_identity,
            LoaderControlMatrixCellV4::PRODUCTION,
            authority,
            LoaderObjectSecurityAuthorityV1::LauncherExplicit,
        )
    };
    let mut lifecycle = Vec::new();
    lifecycle.push(format!("observed-before={}", before.state.diagnostic()));
    let (comparison, after, state) = match before.state {
        LoaderProfileHiveStateV1::AlreadyLoadedBorrowed => {
            let comparison = run(LoaderEnvironmentAuthorityV5::TargetTokenUserenvBorrowedProfile);
            let after = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
            let state = classify_loader_profile_observations(
                before.state,
                None,
                after.state,
                after == before,
            );
            lifecycle.push("borrowed-no-load=true".to_owned());
            lifecycle.push("borrowed-no-unload=true".to_owned());
            (Some(comparison), after, state)
        }
        LoaderProfileHiveStateV1::Absent => {
            let lease = match TargetUserProfileLease::acquire(
                tokens.profile.raw(),
                &target_envelope.user_sid,
            ) {
                Ok(lease) => lease,
                Err(error) => {
                    lifecycle.push(format!(
                        "load-error-sha256={}",
                        super::record::digest(error.as_bytes())
                    ));
                    return LoaderProfilePrerequisiteEvaluationV1 {
                        diagnostic: render_loader_profile_prerequisite_canary(
                            "invalid-load-failed",
                            environment_baseline,
                            None,
                            &before,
                            &before,
                            &tokens.profile_binding_sha256,
                            &lifecycle,
                        ),
                        object_security_required: false,
                        comparison: None,
                    };
                }
            };
            let loaded = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
            lifecycle.push(format!("observed-loaded={}", loaded.state.diagnostic()));
            if loaded.state != LoaderProfileHiveStateV1::AlreadyLoadedBorrowed {
                let unload = lease.unload();
                lifecycle.push(format!(
                    "unload-after-invalid-load-sha256={}",
                    super::record::digest(format!("{unload:?}").as_bytes())
                ));
                return LoaderProfilePrerequisiteEvaluationV1 {
                    diagnostic: render_loader_profile_prerequisite_canary(
                        "invalid-load-not-observed",
                        environment_baseline,
                        None,
                        &before,
                        &loaded,
                        &tokens.profile_binding_sha256,
                        &lifecycle,
                    ),
                    object_security_required: false,
                    comparison: None,
                };
            }
            let comparison = run(LoaderEnvironmentAuthorityV5::TargetTokenUserenvProfileLease);
            let unload = lease.unload();
            lifecycle.push(format!(
                "unload-sha256={}",
                super::record::digest(format!("{unload:?}").as_bytes())
            ));
            let after = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
            let state = classify_loader_profile_observations(
                before.state,
                Some(loaded.state),
                after.state,
                unload.is_ok(),
            );
            (Some(comparison), after, state)
        }
        LoaderProfileHiveStateV1::AccessDenied | LoaderProfileHiveStateV1::QueryFailed(_) => {
            lifecycle.push(format!(
                "observation_native={}",
                before
                    .state
                    .native_code()
                    .map_or_else(|| "unavailable".to_owned(), |code| code.to_string())
            ));
            return LoaderProfilePrerequisiteEvaluationV1 {
                diagnostic: render_loader_profile_prerequisite_canary(
                    "invalid-profile-observation",
                    environment_baseline,
                    None,
                    &before,
                    &before,
                    &tokens.profile_binding_sha256,
                    &lifecycle,
                ),
                object_security_required: false,
                comparison: None,
            };
        }
    };
    let comparison_outcome = comparison
        .as_ref()
        .map(|result| loader_environment_canary_outcome("target-token-userenv-profile-v1", result));
    let object_security_required =
        loader_object_security_required(state, environment_baseline, comparison_outcome.as_ref());
    LoaderProfilePrerequisiteEvaluationV1 {
        diagnostic: render_loader_profile_prerequisite_canary(
            state,
            environment_baseline,
            comparison_outcome.as_ref(),
            &before,
            &after,
            &tokens.profile_binding_sha256,
            &lifecycle,
        ),
        object_security_required,
        comparison,
    }
}

fn loader_object_security_required(
    profile_state: &str,
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    comparison: Option<&LoaderEnvironmentCanaryOutcomeV1>,
) -> bool {
    profile_state == "classified-borrowed-stable"
        && baseline.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && comparison.is_some_and(|comparison| {
            comparison.outcome == LoaderControlMatrixOutcomeKindV6::Failed
                && comparison.native_status == Some(STATUS_DLL_INIT_FAILED)
                && comparison.native_status == baseline.native_status
                && comparison.failure_phase == baseline.failure_phase
        })
}

fn render_loader_profile_prerequisite_canary(
    state: &str,
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    comparison: Option<&LoaderEnvironmentCanaryOutcomeV1>,
    before: &LoaderProfileObservationV1,
    after: &LoaderProfileObservationV1,
    profile_binding_sha256: &str,
    lifecycle: &[String],
) -> String {
    let outcome = |value: &LoaderEnvironmentCanaryOutcomeV1| {
        format!(
            "outcome={} native={} phase={} detail_sha256={}",
            value.outcome.diagnostic(),
            value.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            value.failure_phase,
            value.detail_sha256
        )
    };
    format!(
        "loader_profile_prerequisite_canary=v1 state={state} before_state={} after_state={} before_profile_directory_sha256={} after_profile_directory_sha256={} before_profile_directory_exists={} after_profile_directory_exists={} profile_binding_sha256={} baseline=[{}] comparison=[{}] lifecycle=[{}] profile_values_redacted=true workload_executed=false qualification_promoted=false",
        before.state.diagnostic(),
        after.state.diagnostic(),
        before.profile_directory_sha256,
        after.profile_directory_sha256,
        before.profile_directory_exists,
        after.profile_directory_exists,
        profile_binding_sha256,
        outcome(baseline),
        comparison.map_or_else(|| "not-run".to_owned(), outcome),
        lifecycle.join(","),
    )
}

fn classify_loader_object_security_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    process: &LoaderEnvironmentCanaryOutcomeV1,
    thread: &LoaderEnvironmentCanaryOutcomeV1,
    combined: Option<&LoaderEnvironmentCanaryOutcomeV1>,
    evidence_valid: bool,
) -> &'static str {
    if !evidence_valid
        || baseline.outcome != LoaderControlMatrixOutcomeKindV6::Failed
        || baseline.native_status != Some(STATUS_DLL_INIT_FAILED)
    {
        return "invalid";
    }
    if process.outcome == LoaderControlMatrixOutcomeKindV6::Passed
        && thread.outcome == LoaderControlMatrixOutcomeKindV6::Passed
    {
        return "process-and-thread-object-security-causal";
    }
    if process.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "process-object-security-causal";
    }
    if thread.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "thread-object-security-causal";
    }
    let singles_common = [process, thread].into_iter().all(|outcome| {
        outcome.outcome == LoaderControlMatrixOutcomeKindV6::Failed
            && outcome.native_status == baseline.native_status
            && outcome.failure_phase == baseline.failure_phase
    });
    if !singles_common {
        return "differing-inconclusive";
    }
    match combined {
        Some(outcome) if outcome.outcome == LoaderControlMatrixOutcomeKindV6::Passed => {
            "combined-object-security-causal"
        }
        Some(outcome)
            if outcome.outcome == LoaderControlMatrixOutcomeKindV6::Failed
                && outcome.native_status == baseline.native_status
                && outcome.failure_phase == baseline.failure_phase =>
        {
            "classified-common-failure"
        }
        Some(_) => "differing-inconclusive",
        None => "invalid",
    }
}

#[allow(clippy::too_many_arguments)]
fn loader_object_security_prerequisite_canary_diagnostic(
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    tokens: &LoaderRestrictionCanaryTokens,
    baseline: &Result<String, TargetDesktopLeaseCreateError>,
) -> LoaderObjectSecurityPrerequisiteEvaluationV1 {
    let target_snapshot = match super::token::token_attestation_snapshot(tokens.baseline.raw()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return LoaderObjectSecurityPrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_object_security_prerequisite_canary=v1 state=invalid stage=target-attestation error_sha256={} workload_executed=false qualification_promoted=false",
                    super::record::digest(error.as_bytes())
                ),
                restriction_presence_required: false,
            };
        }
    };
    let target_envelope = target_snapshot.behavior.envelope.clone();
    let before = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
    if before.state != LoaderProfileHiveStateV1::AlreadyLoadedBorrowed {
        return LoaderObjectSecurityPrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_object_security_prerequisite_canary=v1 state=invalid stage=profile-precondition profile_state={} workload_executed=false qualification_promoted=false",
                before.state.diagnostic()
            ),
            restriction_presence_required: false,
        };
    }
    let policy = match super::security::TargetKernelObjectPolicyV1::capture(tokens.baseline.raw()) {
        Ok(policy) => policy,
        Err(error) => {
            return LoaderObjectSecurityPrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_object_security_prerequisite_canary=v1 state=invalid stage=policy-capture error_sha256={} workload_executed=false qualification_promoted=false",
                    super::record::digest(error.as_bytes())
                ),
                restriction_presence_required: false,
            };
        }
    };
    let run = |authority| {
        launch_target_desktop_loader_control_cell_with_environment_authority(
            tokens.baseline.raw(),
            &target_envelope,
            &target_snapshot,
            exact_desktop,
            launch_context,
            association_preflight,
            holder_identity,
            LoaderControlMatrixCellV4::PRODUCTION,
            LoaderEnvironmentAuthorityV5::TargetTokenUserenvBorrowedProfile,
            authority,
        )
    };
    let process_result = run(LoaderObjectSecurityAuthorityV1::TargetAwareProcess);
    let thread_result = run(LoaderObjectSecurityAuthorityV1::TargetAwareThread);
    let baseline_outcome = loader_environment_canary_outcome("launcher-explicit-v1", baseline);
    let process_outcome =
        loader_environment_canary_outcome("target-aware-process-v1", &process_result);
    let thread_outcome =
        loader_environment_canary_outcome("target-aware-thread-v1", &thread_result);
    let singles_common = [&process_outcome, &thread_outcome]
        .into_iter()
        .all(|outcome| {
            outcome.outcome == LoaderControlMatrixOutcomeKindV6::Failed
                && outcome.native_status == baseline_outcome.native_status
                && outcome.failure_phase == baseline_outcome.failure_phase
        });
    let combined_result =
        singles_common.then(|| run(LoaderObjectSecurityAuthorityV1::TargetAwareBoth));
    let combined_outcome = combined_result
        .as_ref()
        .map(|result| loader_environment_canary_outcome("target-aware-both-v1", result));
    let after = observe_loader_profile(tokens.profile.raw(), &target_envelope.user_sid);
    let results = [
        Some(baseline),
        Some(&process_result),
        Some(&thread_result),
        combined_result.as_ref(),
    ];
    let authority_exact =
        loader_result_field(baseline, "object_security_authority").is_some_and(|value| {
            value == LoaderObjectSecurityAuthorityV1::LauncherExplicit.diagnostic()
        }) && loader_result_field(&process_result, "object_security_authority").is_some_and(
            |value| value == LoaderObjectSecurityAuthorityV1::TargetAwareProcess.diagnostic(),
        ) && loader_result_field(&thread_result, "object_security_authority").is_some_and(
            |value| value == LoaderObjectSecurityAuthorityV1::TargetAwareThread.diagnostic(),
        ) && combined_result.as_ref().is_none_or(|combined| {
            loader_result_field(combined, "object_security_authority").is_some_and(|value| {
                value == LoaderObjectSecurityAuthorityV1::TargetAwareBoth.diagnostic()
            })
        });
    let executed_results = results.into_iter().flatten().collect::<Vec<_>>();
    let evidence = loader_object_security_evidence_validity(
        &executed_results,
        after == before,
        authority_exact,
    );
    let state = classify_loader_object_security_outcomes(
        &baseline_outcome,
        &process_outcome,
        &thread_outcome,
        combined_outcome.as_ref(),
        evidence.invariants_valid,
    );
    let outcome = |value: &LoaderEnvironmentCanaryOutcomeV1| {
        format!(
            "authority={} outcome={} native={} phase={} detail_sha256={}",
            value.environment,
            value.outcome.diagnostic(),
            value.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            value.failure_phase,
            value.detail_sha256,
        )
    };
    let live = |result: &Result<String, TargetDesktopLeaseCreateError>| {
        [
            "process_object_live_sha256",
            "thread_object_live_sha256",
            "process_object_target_allowed",
            "process_object_target_granted",
            "thread_object_target_allowed",
            "thread_object_target_granted",
            "process_object_launcher_allowed",
            "thread_object_launcher_allowed",
        ]
        .into_iter()
        .map(|field| {
            format!(
                "{field}={}",
                loader_result_field(result, field).unwrap_or_else(|| "unavailable".to_owned())
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
    };
    let diagnostic = format!(
        "loader_object_security_prerequisite_canary=v1 state={state} workload_executed=false qualification_promoted=false object_security_values_redacted=true differing_fields=[process_object_dacl]|[thread_object_dacl]|[process_object_dacl,thread_object_dacl] profile_state=already-loaded-borrowed common_evidence_valid={} descriptor_evidence_present={} invariants_valid={} baseline=[{}] process=[{}] thread=[{}] combined=[{}] baseline_live=[{}] process_live=[{}] thread_live=[{}] combined_live=[{}] process_policy_sha256={} thread_policy_sha256={} target_logon_trustee=true restricting_trustee_count={} descriptor_readback={} job_empty=true invariant_error_sha256={}",
        evidence.common_evidence_valid,
        evidence.descriptor_evidence_present,
        evidence.invariants_valid,
        outcome(&baseline_outcome),
        outcome(&process_outcome),
        outcome(&thread_outcome),
        combined_outcome
            .as_ref()
            .map_or_else(|| "not-run".to_owned(), outcome),
        live(baseline),
        live(&process_result),
        live(&thread_result),
        combined_result
            .as_ref()
            .map_or_else(|| "not-run".to_owned(), live),
        policy.process_policy_sha256,
        policy.thread_policy_sha256,
        policy.restricting_trustee_count,
        evidence.descriptor_evidence_present,
        evidence.invariant_error.as_ref().map_or_else(
            || "none".to_owned(),
            |error| super::record::digest(error.as_bytes())
        ),
    );
    LoaderObjectSecurityPrerequisiteEvaluationV1 {
        diagnostic,
        restriction_presence_required: loader_restriction_presence_required(
            state,
            evidence.common_evidence_valid,
            evidence.descriptor_evidence_present,
            evidence.invariants_valid,
        ),
    }
}

fn classify_loader_restriction_presence_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    comparison: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> &'static str {
    if !invariants_valid
        || baseline.outcome != LoaderControlMatrixOutcomeKindV6::Failed
        || baseline.native_status != Some(STATUS_DLL_INIT_FAILED)
    {
        return "invalid";
    }
    if comparison.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "restricting-sid-presence-causal";
    }
    if comparison.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && comparison.native_status == baseline.native_status
        && comparison.failure_phase == baseline.failure_phase
    {
        return "classified-common-failure";
    }
    "differing-inconclusive"
}

fn classify_loader_restriction_identity_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> &'static str {
    let presence_state = classify_loader_restriction_presence_outcomes(
        baseline,
        no_restricting_sid,
        invariants_valid,
    );
    if presence_state != "restricting-sid-presence-causal" {
        return presence_state;
    }
    if same_access_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "restricted-code-sid-narrowing-causal";
    }
    if same_access_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && same_access_restricted.native_status == baseline.native_status
        && same_access_restricted.failure_phase == baseline.failure_phase
    {
        return "restricted-token-or-canonical-inventory-causal";
    }
    "differing-inconclusive"
}

fn classify_loader_restriction_logon_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    logon_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> &'static str {
    let identity_state = classify_loader_restriction_identity_outcomes(
        baseline,
        no_restricting_sid,
        same_access_restricted,
        invariants_valid,
    );
    if identity_state != "restricted-code-sid-narrowing-causal" {
        return identity_state;
    }
    if logon_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "restricted-code-sid-narrowing-logon-ceiling-compatible";
    }
    if logon_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && logon_restricted.native_status == baseline.native_status
        && logon_restricted.failure_phase == baseline.failure_phase
    {
        return "canonical-broader-group-or-union-required";
    }
    "differing-inconclusive"
}

fn classify_loader_restriction_authenticated_users_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    logon_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    authenticated_users_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> &'static str {
    let identity_state = classify_loader_restriction_identity_outcomes(
        baseline,
        no_restricting_sid,
        same_access_restricted,
        invariants_valid,
    );
    if identity_state == "invalid" {
        return "invalid";
    }
    if identity_state != "restricted-code-sid-narrowing-causal"
        || logon_restricted.outcome != LoaderControlMatrixOutcomeKindV6::Failed
    {
        return "authenticated-users-inconclusive";
    }
    if authenticated_users_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "authenticated-users-restriction-compatible-logon-too-narrow";
    }
    let matches_logon_access_failure = authenticated_users_restricted.native_status
        == Some(STATUS_ACCESS_DENIED)
        && authenticated_users_restricted.native_status == logon_restricted.native_status
        && authenticated_users_restricted.failure_phase == logon_restricted.failure_phase;
    let matches_baseline_init_failure = authenticated_users_restricted.native_status
        == Some(STATUS_DLL_INIT_FAILED)
        && authenticated_users_restricted.native_status == baseline.native_status
        && authenticated_users_restricted.failure_phase == baseline.failure_phase;
    if authenticated_users_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && (matches_logon_access_failure || matches_baseline_init_failure)
    {
        return "canonical-group-union-or-other-trustee-required";
    }
    "authenticated-users-inconclusive"
}

fn classify_loader_restriction_target_user_outcomes(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    logon_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    authenticated_users_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    target_user_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> &'static str {
    let identity_state = classify_loader_restriction_identity_outcomes(
        baseline,
        no_restricting_sid,
        same_access_restricted,
        invariants_valid,
    );
    if identity_state == "invalid" {
        return "invalid";
    }
    let prior_singletons_match = logon_restricted.outcome
        == LoaderControlMatrixOutcomeKindV6::Failed
        && logon_restricted.native_status == Some(STATUS_ACCESS_DENIED)
        && authenticated_users_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && authenticated_users_restricted.native_status == logon_restricted.native_status
        && authenticated_users_restricted.failure_phase == logon_restricted.failure_phase;
    if identity_state != "restricted-code-sid-narrowing-causal" || !prior_singletons_match {
        return "target-user-singleton-inconclusive";
    }
    if target_user_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Passed {
        return "target-user-restriction-bootstrap-compatible-group-singletons-too-narrow";
    }
    let matches_prior_singleton_access_failure = target_user_restricted.native_status
        == Some(STATUS_ACCESS_DENIED)
        && target_user_restricted.native_status == logon_restricted.native_status
        && target_user_restricted.failure_phase == logon_restricted.failure_phase
        && target_user_restricted.native_status == authenticated_users_restricted.native_status
        && target_user_restricted.failure_phase == authenticated_users_restricted.failure_phase;
    if target_user_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && matches_prior_singleton_access_failure
    {
        return "no-tested-singleton-sufficient-trace-required";
    }
    let matches_baseline_init_failure = target_user_restricted.native_status
        == Some(STATUS_DLL_INIT_FAILED)
        && target_user_restricted.native_status == baseline.native_status
        && target_user_restricted.failure_phase == baseline.failure_phase;
    if target_user_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && matches_baseline_init_failure
    {
        return "target-user-singleton-a-like-failure";
    }
    "target-user-singleton-inconclusive"
}

#[allow(clippy::too_many_arguments)]
fn loader_restriction_original_sext_reproduction_valid(
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    logon_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    authenticated_users_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    target_user_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
) -> bool {
    invariants_valid
        && baseline.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && baseline.native_status == Some(STATUS_DLL_INIT_FAILED)
        && baseline.failure_phase == "post-resume-pre-loader-ready"
        && no_restricting_sid.outcome == LoaderControlMatrixOutcomeKindV6::Passed
        && same_access_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Passed
        && logon_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && logon_restricted.native_status == Some(STATUS_ACCESS_DENIED)
        && logon_restricted.failure_phase == "post-resume-pre-loader-ready"
        && authenticated_users_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && authenticated_users_restricted.native_status == logon_restricted.native_status
        && authenticated_users_restricted.failure_phase == logon_restricted.failure_phase
        && target_user_restricted.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && target_user_restricted.native_status == logon_restricted.native_status
        && target_user_restricted.failure_phase == logon_restricted.failure_phase
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderFullObserverTraceReceiptV1 {
    trace_sha256: String,
    candidate_modules_sha256: String,
    candidate_modules_count: u64,
    stable_modules: Vec<LoaderFullObserverStableModuleIdentityV1>,
    stable_module_sequence_sha256: String,
    unload_tail_sha256: String,
    exception_tail_sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderFullObserverStableModuleIdentityV1 {
    sha256: String,
    stable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFullObserverModulePathSourceV1 {
    FileHandle,
    MappedFile,
    EventImageNameUntrusted,
    Unavailable,
}

impl LoaderFullObserverModulePathSourceV1 {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "file-handle" => Some(Self::FileHandle),
            "mapped-file" => Some(Self::MappedFile),
            "event-image-name-untrusted" => Some(Self::EventImageNameUntrusted),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }

    fn diagnostic(self) -> &'static str {
        match self {
            Self::FileHandle => "file-handle",
            Self::MappedFile => "mapped-file",
            Self::EventImageNameUntrusted => "event-image-name-untrusted",
            Self::Unavailable => "unavailable",
        }
    }

    fn stable(self) -> bool {
        matches!(self, Self::FileHandle | Self::MappedFile)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFullObserverModulePathProvenanceV1 {
    FileHandle,
    MappedFileFallback,
    EventWideFallback,
    EventAnsiFallback,
    Unavailable,
}

impl LoaderFullObserverModulePathProvenanceV1 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::FileHandle => "file-handle",
            Self::MappedFileFallback => "mapped-file-fallback",
            Self::EventWideFallback => "event-wide-fallback",
            Self::EventAnsiFallback => "event-ansi-fallback",
            Self::Unavailable => "unavailable",
        }
    }

    fn stable(self) -> bool {
        matches!(self, Self::FileHandle | Self::MappedFileFallback)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFullObserverTailV1 {
    CandidateModules,
    Unload,
    UnknownEvent,
    Exception,
}

impl LoaderFullObserverTailV1 {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::CandidateModules => "candidate-modules",
            Self::Unload => "unload",
            Self::UnknownEvent => "unknown-event",
            Self::Exception => "exception",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFullObserverTraceRejectionV1 {
    MissingTraceRecord,
    DuplicateTraceRecord,
    MissingScalar,
    DuplicateScalar,
    InvalidUnsigned,
    Version,
    Gate,
    Drain,
    DebugCleanup,
    CreateEvent,
    ExitEvent,
    CommandDeclaration,
    EventAccounting,
    EventBound,
    DebugStringCount,
    DebugStringBytes,
    DebugStringOverflow,
    TailCountRetained(LoaderFullObserverTailV1),
    TailOverflow(LoaderFullObserverTailV1),
    TailCapacity(LoaderFullObserverTailV1),
    LoaderSnapCount,
    LoaderSnapRetained,
    LoaderSnapOverflow,
    CandidateModuleTailMalformed,
    CandidateModuleTailDigest,
    DigestShape,
    EmptySnapDigest,
}

impl LoaderFullObserverTraceRejectionV1 {
    fn diagnostic(self) -> String {
        match self {
            Self::MissingTraceRecord => "rejected-missing-trace-record".to_owned(),
            Self::DuplicateTraceRecord => "rejected-duplicate-trace-record".to_owned(),
            Self::MissingScalar => "rejected-missing-scalar".to_owned(),
            Self::DuplicateScalar => "rejected-duplicate-scalar".to_owned(),
            Self::InvalidUnsigned => "rejected-invalid-unsigned".to_owned(),
            Self::Version => "rejected-version".to_owned(),
            Self::Gate => "rejected-gate".to_owned(),
            Self::Drain => "rejected-drain".to_owned(),
            Self::DebugCleanup => "rejected-debug-cleanup".to_owned(),
            Self::CreateEvent => "rejected-create-event".to_owned(),
            Self::ExitEvent => "rejected-exit-event".to_owned(),
            Self::CommandDeclaration => "rejected-command-declaration".to_owned(),
            Self::EventAccounting => "rejected-event-accounting".to_owned(),
            Self::EventBound => "rejected-event-bound".to_owned(),
            Self::DebugStringCount => "rejected-debug-string-count".to_owned(),
            Self::DebugStringBytes => "rejected-debug-string-bytes".to_owned(),
            Self::DebugStringOverflow => "rejected-debug-string-overflow".to_owned(),
            Self::TailCountRetained(tail) => {
                format!("rejected-{}-tail-count-retained", tail.diagnostic())
            }
            Self::TailOverflow(tail) => {
                format!("rejected-{}-tail-overflow", tail.diagnostic())
            }
            Self::TailCapacity(tail) => {
                format!("rejected-{}-tail-capacity", tail.diagnostic())
            }
            Self::LoaderSnapCount => "rejected-loader-snap-count".to_owned(),
            Self::LoaderSnapRetained => "rejected-loader-snap-retained".to_owned(),
            Self::LoaderSnapOverflow => "rejected-loader-snap-overflow".to_owned(),
            Self::CandidateModuleTailMalformed => {
                "rejected-candidate-module-tail-malformed".to_owned()
            }
            Self::CandidateModuleTailDigest => "rejected-candidate-module-tail-digest".to_owned(),
            Self::DigestShape => "rejected-digest-shape".to_owned(),
            Self::EmptySnapDigest => "rejected-empty-snap-digest".to_owned(),
        }
    }
}

fn loader_full_observer_trace_record(
    detail: &str,
) -> Result<&str, LoaderFullObserverTraceRejectionV1> {
    let marker = "loader_trace=";
    let mut markers = detail.match_indices(marker).filter_map(|(start, _)| {
        let token_start = start == 0
            || detail[..start]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace);
        token_start.then_some(start)
    });
    let start = markers
        .next()
        .ok_or(LoaderFullObserverTraceRejectionV1::MissingTraceRecord)?;
    if markers.next().is_some() {
        return Err(LoaderFullObserverTraceRejectionV1::DuplicateTraceRecord);
    }
    let trace = &detail[start..];
    if trace.split_ascii_whitespace().next() != Some("loader_trace=v4") {
        return Err(LoaderFullObserverTraceRejectionV1::Version);
    }
    Ok(trace)
}

fn loader_trace_scalar<'a>(
    detail: &'a str,
    field: &str,
) -> Result<&'a str, LoaderFullObserverTraceRejectionV1> {
    let prefix = format!("{field}=");
    let mut matches = detail
        .split_ascii_whitespace()
        .filter_map(|value| value.strip_prefix(&prefix))
        .map(|value| value.trim_end_matches([',', ']', ';']));
    let value = matches
        .next()
        .ok_or(LoaderFullObserverTraceRejectionV1::MissingScalar)?;
    if matches.next().is_some() {
        return Err(LoaderFullObserverTraceRejectionV1::DuplicateScalar);
    }
    Ok(value)
}

fn loader_trace_list_scalar<'a>(
    detail: &'a str,
    field: &str,
) -> Result<&'a str, LoaderFullObserverTraceRejectionV1> {
    let prefix = format!("{field}=");
    let mut matches = detail
        .split_ascii_whitespace()
        .filter_map(|value| value.strip_prefix(&prefix));
    let value = matches
        .next()
        .ok_or(LoaderFullObserverTraceRejectionV1::MissingScalar)?;
    if matches.next().is_some() {
        return Err(LoaderFullObserverTraceRejectionV1::DuplicateScalar);
    }
    value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)
}

fn loader_trace_status_with_numeric_suffix(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        suffix
            .parse::<i32>()
            .is_ok_and(|parsed| parsed.to_string() == suffix)
    })
}

fn loader_trace_status_numeric_suffix(value: &str, prefixes: &[&str]) -> Option<i32> {
    prefixes.iter().find_map(|prefix| {
        value
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.parse::<i32>().ok())
            .filter(|parsed| parsed.to_string() == value.strip_prefix(prefix).unwrap_or_default())
    })
}

fn loader_trace_file_failure_status_valid(value: &str) -> bool {
    matches!(value, "file-null" | "file-invalid" | "file-overflow")
        || loader_trace_status_with_numeric_suffix(value, "file-os-")
}

fn loader_trace_mapped_failure_status_valid(value: &str) -> bool {
    matches!(value, "mapped-null-base" | "mapped-overflow")
        || loader_trace_status_with_numeric_suffix(value, "mapped-os-")
}

fn loader_trace_event_failure_status_valid(value: &str) -> bool {
    matches!(
        value,
        "event-pointer-null"
            | "event-string-null"
            | "event-wide-unterminated"
            | "event-wide-empty"
            | "event-wide-invalid"
            | "event-ansi-unterminated"
            | "event-ansi-empty"
            | "event-ansi-invalid"
    ) || [
        "event-pointer-os-",
        "event-pointer-partial-",
        "event-wide-os-",
        "event-wide-partial-",
        "event-ansi-os-",
        "event-ansi-partial-",
    ]
    .into_iter()
    .any(|prefix| loader_trace_status_with_numeric_suffix(value, prefix))
}

fn loader_trace_module_provenance(
    source: LoaderFullObserverModulePathSourceV1,
    value: &str,
) -> Option<(
    LoaderFullObserverModulePathProvenanceV1,
    Option<Option<i32>>,
)> {
    let fields = value.split('>').collect::<Vec<_>>();
    match (source, fields.as_slice()) {
        (LoaderFullObserverModulePathSourceV1::FileHandle, ["file-ok"]) => Some((
            LoaderFullObserverModulePathProvenanceV1::FileHandle,
            Some(None),
        )),
        (LoaderFullObserverModulePathSourceV1::MappedFile, [file, "mapped-ok"])
            if loader_trace_file_failure_status_valid(file) =>
        {
            Some((
                LoaderFullObserverModulePathProvenanceV1::MappedFileFallback,
                Some(None),
            ))
        }
        (
            LoaderFullObserverModulePathSourceV1::EventImageNameUntrusted,
            [file, mapped, "event-wide-ok"],
        ) if loader_trace_file_failure_status_valid(file)
            && loader_trace_mapped_failure_status_valid(mapped) =>
        {
            Some((
                LoaderFullObserverModulePathProvenanceV1::EventWideFallback,
                Some(None),
            ))
        }
        (
            LoaderFullObserverModulePathSourceV1::EventImageNameUntrusted,
            [file, mapped, "event-ansi-ok"],
        ) if loader_trace_file_failure_status_valid(file)
            && loader_trace_mapped_failure_status_valid(mapped) =>
        {
            Some((
                LoaderFullObserverModulePathProvenanceV1::EventAnsiFallback,
                Some(None),
            ))
        }
        (LoaderFullObserverModulePathSourceV1::Unavailable, [file, mapped, event])
            if loader_trace_file_failure_status_valid(file)
                && loader_trace_mapped_failure_status_valid(mapped)
                && loader_trace_event_failure_status_valid(event) =>
        {
            let event_error = loader_trace_status_numeric_suffix(
                event,
                &[
                    "event-pointer-os-",
                    "event-pointer-partial-",
                    "event-wide-os-",
                    "event-wide-partial-",
                    "event-ansi-os-",
                    "event-ansi-partial-",
                ],
            );
            let mapped_error = loader_trace_status_numeric_suffix(mapped, &["mapped-os-"]);
            let file_error = if *file == "file-invalid" {
                Some(6)
            } else {
                loader_trace_status_numeric_suffix(file, &["file-os-"])
            };
            let partial_error_unobservable = [
                "event-pointer-partial-",
                "event-wide-partial-",
                "event-ansi-partial-",
            ]
            .into_iter()
            .any(|prefix| event.starts_with(prefix));
            Some((
                LoaderFullObserverModulePathProvenanceV1::Unavailable,
                (!partial_error_unobservable)
                    .then_some(event_error.or(mapped_error).or(file_error)),
            ))
        }
        _ => None,
    }
}

fn loader_trace_stable_module_identity(
    basename: &str,
    path_source: LoaderFullObserverModulePathSourceV1,
    path_sha256: &str,
    path_error: Option<i32>,
    path_provenance: LoaderFullObserverModulePathProvenanceV1,
) -> LoaderFullObserverStableModuleIdentityV1 {
    let mut basename_material = b"memcordon-loader-module-basename-v1\0".to_vec();
    basename_material.extend_from_slice(basename.to_ascii_lowercase().as_bytes());
    let basename_sha256 = super::record::digest(&basename_material);
    let mut identity_material = b"memcordon-loader-stable-module-identity-v1\0".to_vec();
    identity_material.extend_from_slice(basename_sha256.as_bytes());
    identity_material.extend_from_slice(path_sha256.as_bytes());
    identity_material.extend_from_slice(path_source.diagnostic().as_bytes());
    identity_material.push(0);
    identity_material.extend_from_slice(&path_error.unwrap_or_default().to_le_bytes());
    identity_material.push(u8::from(path_error.is_some()));
    identity_material.extend_from_slice(path_provenance.diagnostic().as_bytes());
    LoaderFullObserverStableModuleIdentityV1 {
        sha256: super::record::digest(&identity_material),
        stable: !basename.contains('?')
            && basename != "unavailable"
            && path_source.stable()
            && path_provenance.stable(),
    }
}

fn loader_stable_module_sequence_digest(
    modules: &[LoaderFullObserverStableModuleIdentityV1],
) -> String {
    let mut material = b"memcordon-loader-stable-module-sequence-v1\0".to_vec();
    for module in modules {
        material.extend_from_slice(module.sha256.as_bytes());
        material.push(u8::from(module.stable));
    }
    super::record::digest(&material)
}

fn loader_trace_candidate_modules(
    detail: &str,
    declared_sha256: &str,
    retained: u64,
) -> Result<Vec<LoaderFullObserverStableModuleIdentityV1>, LoaderFullObserverTraceRejectionV1> {
    let serialized = loader_trace_list_scalar(detail, "candidate_modules")?;
    let mut canonical_entries = Vec::new();
    let mut identities = Vec::new();
    let mut stable_identity_set = BTreeSet::new();
    let mut previous_ordinal = None;
    if !serialized.is_empty() {
        for entry in serialized.split(',') {
            let fields = entry.split(':').collect::<Vec<_>>();
            let [
                ordinal_base,
                basename,
                path_source,
                path_sha256,
                path_error,
                path_provenance,
            ] = fields.as_slice()
            else {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            };
            let (ordinal, base) = ordinal_base
                .split_once("@0x")
                .ok_or(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?;
            let ordinal = ordinal
                .parse::<u64>()
                .map_err(|_| LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?;
            if ordinal == 0 || previous_ordinal.is_some_and(|previous| ordinal <= previous) {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            }
            previous_ordinal = Some(ordinal);
            let base = u64::from_str_radix(base, 16)
                .map_err(|_| LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?;
            if base == 0 {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            }
            let basename = *basename;
            let path_sha256 = *path_sha256;
            let path_error = *path_error;
            let path_provenance = *path_provenance;
            if basename.is_empty()
                || basename.len() > super::loader_debug::MODULE_BASENAME_MAX_BYTES
                || !basename.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '?')
                })
                || !loader_trace_sha256_valid(path_sha256)
            {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            }
            let path_source = LoaderFullObserverModulePathSourceV1::parse(path_source)
                .ok_or(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?;
            let parsed_path_error = if path_error == "ok" {
                None
            } else {
                Some(
                    path_error
                        .strip_prefix("os-")
                        .and_then(|value| value.parse::<i32>().ok())
                        .ok_or(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?,
                )
            };
            let (parsed_provenance, expected_path_error) =
                loader_trace_module_provenance(path_source, path_provenance)
                    .ok_or(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed)?;
            if expected_path_error.is_some_and(|expected| parsed_path_error != expected) {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            }
            let canonical_path_error =
                parsed_path_error.map_or_else(|| "ok".to_owned(), |code| format!("os-{code}"));
            canonical_entries.push(format!(
                "{ordinal}@0x{base:x}:{basename}:{}:{path_sha256}:{canonical_path_error}:{path_provenance}",
                path_source.diagnostic(),
            ));
            let identity = loader_trace_stable_module_identity(
                basename,
                path_source,
                path_sha256,
                parsed_path_error,
                parsed_provenance,
            );
            if !stable_identity_set.insert(identity.sha256.clone()) {
                return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
            }
            identities.push(identity);
        }
    }
    if identities.len() as u64 != retained {
        return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailMalformed);
    }
    let canonical = canonical_entries.join(",");
    if super::loader_debug::candidate_modules_tail_digest(&canonical) != declared_sha256 {
        return Err(LoaderFullObserverTraceRejectionV1::CandidateModuleTailDigest);
    }
    Ok(identities)
}

fn loader_trace_u64(detail: &str, field: &str) -> Result<u64, LoaderFullObserverTraceRejectionV1> {
    loader_trace_scalar(detail, field)?
        .parse()
        .map_err(|_| LoaderFullObserverTraceRejectionV1::InvalidUnsigned)
}

fn loader_trace_bounded_tail_valid(
    detail: &str,
    count_field: &str,
    retained_field: &str,
    overflow_field: &str,
    capacity: usize,
    tail: LoaderFullObserverTailV1,
) -> Result<(), LoaderFullObserverTraceRejectionV1> {
    let count = loader_trace_u64(detail, count_field)?;
    let retained = loader_trace_u64(detail, retained_field)?;
    let overflow = loader_trace_u64(detail, overflow_field)?;
    if overflow != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::TailOverflow(tail));
    }
    if count != retained {
        return Err(LoaderFullObserverTraceRejectionV1::TailCountRetained(tail));
    }
    if retained > capacity as u64 {
        return Err(LoaderFullObserverTraceRejectionV1::TailCapacity(tail));
    }
    Ok(())
}

fn loader_trace_sha256_valid(value: &str) -> bool {
    value.len() == super::record::digest(b"").len()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn admit_loader_full_observer_trace(
    result: &Result<String, TargetDesktopLeaseCreateError>,
) -> Result<LoaderFullObserverTraceReceiptV1, LoaderFullObserverTraceRejectionV1> {
    let detail = loader_full_observer_trace_record(loader_result_detail(result))?;
    if loader_trace_scalar(detail, "loader_trace")? != "v4" {
        return Err(LoaderFullObserverTraceRejectionV1::Version);
    }
    if loader_trace_scalar(detail, "gate")? != "ephemeral-ci" {
        return Err(LoaderFullObserverTraceRejectionV1::Gate);
    }
    if loader_trace_scalar(detail, "drained")? != "true" {
        return Err(LoaderFullObserverTraceRejectionV1::Drain);
    }
    if loader_trace_scalar(detail, "debug_cleanup")? != "exit-process-event-continued" {
        return Err(LoaderFullObserverTraceRejectionV1::DebugCleanup);
    }
    if loader_trace_scalar(detail, "create_event")? != "true" {
        return Err(LoaderFullObserverTraceRejectionV1::CreateEvent);
    }
    if loader_trace_scalar(detail, "exit_event")? != "true" {
        return Err(LoaderFullObserverTraceRejectionV1::ExitEvent);
    }
    if loader_trace_scalar(detail, "command_dynamic_fields")?
        != "authenticated-private-pipe,authenticated-nonce"
    {
        return Err(LoaderFullObserverTraceRejectionV1::CommandDeclaration);
    }
    let events = loader_trace_u64(detail, "events")?;
    let accounted_events = loader_trace_u64(detail, "accounted_events")?;
    if events != accounted_events {
        return Err(LoaderFullObserverTraceRejectionV1::EventAccounting);
    }
    if events > super::loader_debug::LOADER_TRACE_EVENT_ADMISSION_MAX {
        return Err(LoaderFullObserverTraceRejectionV1::EventBound);
    }
    if loader_trace_u64(detail, "debug_strings")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::DebugStringCount);
    }
    if loader_trace_u64(detail, "debug_string_bytes")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::DebugStringBytes);
    }
    if loader_trace_u64(detail, "debug_string_overflow")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::DebugStringOverflow);
    }
    loader_trace_bounded_tail_valid(
        detail,
        "candidate_modules_count",
        "candidate_modules_retained",
        "candidate_modules_overflow",
        super::loader_debug::MODULE_TAIL_CAPACITY,
        LoaderFullObserverTailV1::CandidateModules,
    )?;
    let candidate_modules_count = loader_trace_u64(detail, "candidate_modules_count")?;
    let candidate_modules_retained = loader_trace_u64(detail, "candidate_modules_retained")?;
    loader_trace_bounded_tail_valid(
        detail,
        "unload_tail_count",
        "unload_tail_retained",
        "unload_tail_overflow",
        super::loader_debug::UNLOAD_TAIL_CAPACITY,
        LoaderFullObserverTailV1::Unload,
    )?;
    loader_trace_bounded_tail_valid(
        detail,
        "unknown_event_tail_count",
        "unknown_event_tail_retained",
        "unknown_event_tail_overflow",
        super::loader_debug::UNKNOWN_EVENT_TAIL_CAPACITY,
        LoaderFullObserverTailV1::UnknownEvent,
    )?;
    loader_trace_bounded_tail_valid(
        detail,
        "exception_tail_count",
        "exception_tail_retained",
        "exception_tail_overflow",
        super::loader_debug::EXCEPTION_TAIL_CAPACITY,
        LoaderFullObserverTailV1::Exception,
    )?;
    if loader_trace_u64(detail, "loader_snap_tail_count")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::LoaderSnapCount);
    }
    if loader_trace_u64(detail, "loader_snap_tail_retained")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::LoaderSnapRetained);
    }
    if loader_trace_u64(detail, "loader_snap_tail_overflow")? != 0 {
        return Err(LoaderFullObserverTraceRejectionV1::LoaderSnapOverflow);
    }
    let trace_sha256 = loader_trace_scalar(detail, "trace_sha256")?.to_owned();
    let candidate_modules_sha256 =
        loader_trace_scalar(detail, "candidate_modules_sha256")?.to_owned();
    let unload_tail_sha256 = loader_trace_scalar(detail, "unload_tail_sha256")?.to_owned();
    let unknown_event_tail_sha256 = loader_trace_scalar(detail, "unknown_event_tail_sha256")?;
    let exception_tail_sha256 = loader_trace_scalar(detail, "exception_tail_sha256")?.to_owned();
    let loader_snap_tail_sha256 = loader_trace_scalar(detail, "loader_snap_tail_sha256")?;
    let command_semantics_sha256 = loader_trace_scalar(detail, "command_semantics_sha256")?;
    if [
        trace_sha256.as_str(),
        candidate_modules_sha256.as_str(),
        unload_tail_sha256.as_str(),
        unknown_event_tail_sha256,
        exception_tail_sha256.as_str(),
        loader_snap_tail_sha256,
        command_semantics_sha256,
    ]
    .into_iter()
    .any(|value| !loader_trace_sha256_valid(value))
    {
        return Err(LoaderFullObserverTraceRejectionV1::DigestShape);
    }
    if loader_snap_tail_sha256 != super::record::digest(b"") {
        return Err(LoaderFullObserverTraceRejectionV1::EmptySnapDigest);
    }
    let stable_modules = loader_trace_candidate_modules(
        detail,
        &candidate_modules_sha256,
        candidate_modules_retained,
    )?;
    let stable_module_sequence_sha256 = loader_stable_module_sequence_digest(&stable_modules);
    Ok(LoaderFullObserverTraceReceiptV1 {
        trace_sha256,
        candidate_modules_sha256,
        candidate_modules_count,
        stable_modules,
        stable_module_sequence_sha256,
        unload_tail_sha256,
        exception_tail_sha256,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderFullObserverModuleFrontierV1 {
    debug_c_total: u64,
    debug_c_retained: usize,
    debug_c_sequence_sha256: String,
    debug_f_total: u64,
    debug_f_retained: usize,
    debug_f_sequence_sha256: String,
    common_prefix: usize,
    last_common_identity_sha256: Option<String>,
    first_c_only_identity_sha256: Option<String>,
    useful: bool,
}

fn loader_full_observer_module_frontier(
    debug_c: &LoaderFullObserverTraceReceiptV1,
    debug_f: &LoaderFullObserverTraceReceiptV1,
) -> LoaderFullObserverModuleFrontierV1 {
    let common_prefix = debug_c
        .stable_modules
        .iter()
        .zip(debug_f.stable_modules.iter())
        .take_while(|(canonical, target)| canonical.sha256 == target.sha256)
        .count();
    let identities_unique_and_stable = |modules: &[LoaderFullObserverStableModuleIdentityV1]| {
        let mut seen = BTreeSet::new();
        modules
            .iter()
            .all(|module| module.stable && seen.insert(module.sha256.as_str()))
    };
    let useful = identities_unique_and_stable(&debug_c.stable_modules)
        && identities_unique_and_stable(&debug_f.stable_modules)
        && debug_f.stable_modules.len() < debug_c.stable_modules.len()
        && common_prefix == debug_f.stable_modules.len();
    let projected_identity_digest = |domain: &[u8], identity: &str| {
        let mut material = domain.to_vec();
        material.extend_from_slice(identity.as_bytes());
        super::record::digest(&material)
    };
    LoaderFullObserverModuleFrontierV1 {
        debug_c_total: debug_c.candidate_modules_count,
        debug_c_retained: debug_c.stable_modules.len(),
        debug_c_sequence_sha256: debug_c.stable_module_sequence_sha256.clone(),
        debug_f_total: debug_f.candidate_modules_count,
        debug_f_retained: debug_f.stable_modules.len(),
        debug_f_sequence_sha256: debug_f.stable_module_sequence_sha256.clone(),
        common_prefix,
        last_common_identity_sha256: common_prefix
            .checked_sub(1)
            .and_then(|index| debug_c.stable_modules.get(index))
            .map(|identity| {
                projected_identity_digest(
                    b"memcordon-loader-stable-module-last-common-v1\0",
                    &identity.sha256,
                )
            }),
        first_c_only_identity_sha256: useful.then(|| {
            projected_identity_digest(
                b"memcordon-loader-stable-module-first-c-only-v1\0",
                &debug_c.stable_modules[common_prefix].sha256,
            )
        }),
        useful,
    }
}

#[allow(clippy::too_many_arguments)]
fn loader_trace_session_capability_allowed(
    ephemeral_ci: bool,
    passive_setup_admitted: bool,
    original_reproduction_valid: bool,
    original_invariants_valid: bool,
    debug_c: &LoaderEnvironmentCanaryOutcomeV1,
    debug_f: &LoaderEnvironmentCanaryOutcomeV1,
    debug_c_trace: &LoaderFullObserverTraceReceiptV1,
    debug_f_trace: &LoaderFullObserverTraceReceiptV1,
    frontier: &LoaderFullObserverModuleFrontierV1,
    invariants: &LoaderFullObserverInvariantReceiptV1,
    after_debug_c_stable: bool,
    after_debug_f_stable: bool,
) -> bool {
    ephemeral_ci
        && passive_setup_admitted
        && original_reproduction_valid
        && original_invariants_valid
        && invariants.valid()
        && debug_c.outcome == LoaderControlMatrixOutcomeKindV6::Passed
        && debug_c.native_status.is_none()
        && debug_c.failure_phase == "none"
        && debug_f.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && debug_f.native_status == Some(STATUS_ACCESS_DENIED)
        && debug_f.failure_phase == "post-resume-pre-loader-ready"
        && !debug_c_trace.stable_modules.is_empty()
        && !debug_f_trace.stable_modules.is_empty()
        && debug_c_trace.candidate_modules_count == debug_c_trace.stable_modules.len() as u64
        && debug_f_trace.candidate_modules_count == debug_f_trace.stable_modules.len() as u64
        && after_debug_c_stable
        && after_debug_f_stable
        && !frontier.useful
        && frontier.common_prefix == 0
        && frontier.last_common_identity_sha256.is_none()
        && frontier.first_c_only_identity_sha256.is_none()
}

#[allow(clippy::too_many_arguments)]
fn loader_trace_session_capability_trigger_sha256(
    ephemeral_ci: bool,
    passive_setup_sha256: Option<&str>,
    original_reproduction_valid: bool,
    original_invariants_valid: bool,
    source_binding_sha256: &str,
    pair_invariants_sha256: &str,
    restriction_presence_binding_sha256: &str,
    restriction_identity_binding_sha256: &str,
    logon_restriction_binding_sha256: &str,
    authenticated_users_restriction_binding_sha256: &str,
    target_user_restriction_binding_sha256: &str,
    profile_binding_sha256: &str,
    shared_evidence_sha256: &str,
    baseline: &LoaderEnvironmentCanaryOutcomeV1,
    no_restricting_sid: &LoaderEnvironmentCanaryOutcomeV1,
    same_access_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    logon_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    authenticated_users_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    target_user_restricted: &LoaderEnvironmentCanaryOutcomeV1,
    debug_c: &LoaderEnvironmentCanaryOutcomeV1,
    debug_f: &LoaderEnvironmentCanaryOutcomeV1,
    debug_c_trace: &LoaderFullObserverTraceReceiptV1,
    debug_f_trace: &LoaderFullObserverTraceReceiptV1,
    frontier: &LoaderFullObserverModuleFrontierV1,
    invariants: &LoaderFullObserverInvariantReceiptV1,
    after_debug_c: &SharedEnvironmentObservationV1,
    after_debug_f: &SharedEnvironmentObservationV1,
) -> Option<String> {
    if !loader_trace_session_capability_allowed(
        ephemeral_ci,
        passive_setup_sha256.is_some(),
        original_reproduction_valid,
        original_invariants_valid,
        debug_c,
        debug_f,
        debug_c_trace,
        debug_f_trace,
        frontier,
        invariants,
        after_debug_c.stable(),
        after_debug_f.stable(),
    ) {
        return None;
    }
    if [
        passive_setup_sha256.unwrap_or_default(),
        source_binding_sha256,
        pair_invariants_sha256,
        restriction_presence_binding_sha256,
        restriction_identity_binding_sha256,
        logon_restriction_binding_sha256,
        authenticated_users_restriction_binding_sha256,
        target_user_restriction_binding_sha256,
        profile_binding_sha256,
        shared_evidence_sha256,
        debug_c_trace.trace_sha256.as_str(),
        debug_f_trace.trace_sha256.as_str(),
        debug_c_trace.stable_module_sequence_sha256.as_str(),
        debug_f_trace.stable_module_sequence_sha256.as_str(),
        after_debug_c.detail_sha256.as_str(),
        after_debug_f.detail_sha256.as_str(),
    ]
    .into_iter()
    .filter(|digest| *digest != "none")
    .any(|digest| super::record::validate_attempt_id(digest).is_err())
        || [
            baseline,
            no_restricting_sid,
            same_access_restricted,
            logon_restricted,
            authenticated_users_restricted,
            target_user_restricted,
            debug_c,
            debug_f,
        ]
        .into_iter()
        .any(|outcome| super::record::validate_attempt_id(&outcome.detail_sha256).is_err())
    {
        return None;
    }
    let mut material = b"memcordon-loader-trace-session-capability-trigger-v1\0".to_vec();
    for field in [
        passive_setup_sha256.unwrap_or_default(),
        source_binding_sha256,
        pair_invariants_sha256,
        restriction_presence_binding_sha256,
        restriction_identity_binding_sha256,
        logon_restriction_binding_sha256,
        authenticated_users_restriction_binding_sha256,
        target_user_restriction_binding_sha256,
        profile_binding_sha256,
        shared_evidence_sha256,
        &debug_c_trace.trace_sha256,
        &debug_f_trace.trace_sha256,
        &debug_c_trace.stable_module_sequence_sha256,
        &debug_f_trace.stable_module_sequence_sha256,
        &after_debug_c.detail_sha256,
        &after_debug_f.detail_sha256,
    ] {
        material.extend_from_slice(&(field.len() as u64).to_le_bytes());
        material.extend_from_slice(field.as_bytes());
    }
    for value in [
        debug_c_trace.candidate_modules_count,
        debug_f_trace.candidate_modules_count,
        debug_c_trace.stable_modules.len() as u64,
        debug_f_trace.stable_modules.len() as u64,
        frontier.common_prefix as u64,
    ] {
        material.extend_from_slice(&value.to_le_bytes());
    }
    for outcome in [
        baseline,
        no_restricting_sid,
        same_access_restricted,
        logon_restricted,
        authenticated_users_restricted,
        target_user_restricted,
        debug_c,
        debug_f,
    ] {
        material.extend_from_slice(&(outcome.detail_sha256.len() as u64).to_le_bytes());
        material.extend_from_slice(outcome.detail_sha256.as_bytes());
        material.push(match outcome.outcome {
            LoaderControlMatrixOutcomeKindV6::Passed => 1,
            LoaderControlMatrixOutcomeKindV6::Failed => 2,
        });
        material.extend_from_slice(&outcome.native_status.unwrap_or(i32::MIN).to_le_bytes());
        material.extend_from_slice(&(outcome.failure_phase.len() as u64).to_le_bytes());
        material.extend_from_slice(outcome.failure_phase.as_bytes());
    }
    for (name, state) in invariants.named_states() {
        material.extend_from_slice(name.as_bytes());
        material.push(0);
        material.push(match state {
            LoaderFullObserverInvariantStateV1::Passed => 1,
            LoaderFullObserverInvariantStateV1::Failed => 2,
            LoaderFullObserverInvariantStateV1::NotRun => 3,
        });
    }
    Some(super::record::digest(&material))
}

#[allow(clippy::too_many_arguments)]
fn loader_trace_session_capability_shared_evidence_sha256(
    admitted_environment: &UserEnvironmentInventoryV1,
    observations: &[&SharedEnvironmentObservationV1],
    profile_before: &LoaderProfileObservationV1,
    profile_after_original: &LoaderProfileObservationV1,
    profile_after_all: &LoaderProfileObservationV1,
    launcher_authority_exact: bool,
    containment_exact: bool,
    job_empty_exact: bool,
    environment_destruction_sha256: &str,
) -> Option<String> {
    if observations.len() != 8
        || !admitted_environment.missing_required.is_empty()
        || [
            admitted_environment.sha256.as_str(),
            admitted_environment.keys_sha256.as_str(),
            profile_before.profile_directory_sha256.as_str(),
            profile_after_original.profile_directory_sha256.as_str(),
            profile_after_all.profile_directory_sha256.as_str(),
            environment_destruction_sha256,
        ]
        .into_iter()
        .any(|digest| super::record::validate_attempt_id(digest).is_err())
    {
        return None;
    }
    let mut material = b"memcordon-loader-trace-session-capability-shared-evidence-v1\0".to_vec();
    for field in [
        admitted_environment.sha256.as_str(),
        admitted_environment.keys_sha256.as_str(),
        environment_destruction_sha256,
    ] {
        material.extend_from_slice(&(field.len() as u64).to_le_bytes());
        material.extend_from_slice(field.as_bytes());
    }
    material.extend_from_slice(&(admitted_environment.units as u64).to_le_bytes());
    material.extend_from_slice(&(admitted_environment.entries as u64).to_le_bytes());
    for observation in observations {
        for field in [observation.scan, observation.detail_sha256.as_str()] {
            material.extend_from_slice(&(field.len() as u64).to_le_bytes());
            material.extend_from_slice(field.as_bytes());
        }
        material.push(u8::from(observation.metadata_match));
    }
    for profile in [profile_before, profile_after_original, profile_after_all] {
        let state = profile.state.diagnostic();
        material.extend_from_slice(&(state.len() as u64).to_le_bytes());
        material.extend_from_slice(state.as_bytes());
        material.extend_from_slice(
            &profile
                .state
                .native_code()
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        material.extend_from_slice(profile.profile_directory_sha256.as_bytes());
        material.push(u8::from(profile.profile_directory_exists));
    }
    material.extend_from_slice(&[
        u8::from(launcher_authority_exact),
        u8::from(containment_exact),
        u8::from(job_empty_exact),
    ]);
    Some(super::record::digest(&material))
}

fn classify_loader_full_observer_pair(
    debug_c: &LoaderEnvironmentCanaryOutcomeV1,
    debug_f: &LoaderEnvironmentCanaryOutcomeV1,
    invariants_valid: bool,
    useful_frontier_differential: Option<bool>,
) -> &'static str {
    let reproduction_valid = invariants_valid
        && debug_c.outcome == LoaderControlMatrixOutcomeKindV6::Passed
        && debug_f.outcome == LoaderControlMatrixOutcomeKindV6::Failed
        && debug_f.native_status == Some(STATUS_ACCESS_DENIED)
        && debug_f.failure_phase == "post-resume-pre-loader-ready";
    if !reproduction_valid || useful_frontier_differential.is_none() {
        "observer-perturbed-inconclusive"
    } else if useful_frontier_differential == Some(true) {
        "observer-perturbed-differential"
    } else {
        "observer-perturbed-nonlocalizing"
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderFullObserverInvariantStateV1 {
    Passed,
    Failed,
    NotRun,
}

impl LoaderFullObserverInvariantStateV1 {
    fn evaluated(value: bool) -> Self {
        if value { Self::Passed } else { Self::Failed }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderFullObserverInvariantReceiptV1 {
    fallback_authority: LoaderFullObserverInvariantStateV1,
    original_reproduction: LoaderFullObserverInvariantStateV1,
    original_invariants: LoaderFullObserverInvariantStateV1,
    original_projection: LoaderFullObserverInvariantStateV1,
    debug_pair_common: LoaderFullObserverInvariantStateV1,
    debug_mode: LoaderFullObserverInvariantStateV1,
    debug_c_trace_admission: LoaderFullObserverInvariantStateV1,
    debug_f_trace_admission: LoaderFullObserverInvariantStateV1,
    debug_containment: LoaderFullObserverInvariantStateV1,
    post_debug_c_environment: LoaderFullObserverInvariantStateV1,
    post_debug_f_environment: LoaderFullObserverInvariantStateV1,
    profile_stability: LoaderFullObserverInvariantStateV1,
    environment_destruction_once: LoaderFullObserverInvariantStateV1,
}

impl LoaderFullObserverInvariantReceiptV1 {
    #[allow(clippy::too_many_arguments)]
    fn evaluated(
        fallback_authority: bool,
        original_reproduction: bool,
        original_invariants: bool,
        original_projection: bool,
        debug_pair_common: bool,
        debug_mode: bool,
        debug_c_trace_admission: bool,
        debug_f_trace_admission: bool,
        debug_containment: bool,
        post_debug_c_environment: bool,
        post_debug_f_environment: bool,
        profile_stability: bool,
        environment_destruction_once: bool,
    ) -> Self {
        Self {
            fallback_authority: LoaderFullObserverInvariantStateV1::evaluated(fallback_authority),
            original_reproduction: LoaderFullObserverInvariantStateV1::evaluated(
                original_reproduction,
            ),
            original_invariants: LoaderFullObserverInvariantStateV1::evaluated(original_invariants),
            original_projection: LoaderFullObserverInvariantStateV1::evaluated(original_projection),
            debug_pair_common: LoaderFullObserverInvariantStateV1::evaluated(debug_pair_common),
            debug_mode: LoaderFullObserverInvariantStateV1::evaluated(debug_mode),
            debug_c_trace_admission: LoaderFullObserverInvariantStateV1::evaluated(
                debug_c_trace_admission,
            ),
            debug_f_trace_admission: LoaderFullObserverInvariantStateV1::evaluated(
                debug_f_trace_admission,
            ),
            debug_containment: LoaderFullObserverInvariantStateV1::evaluated(debug_containment),
            post_debug_c_environment: LoaderFullObserverInvariantStateV1::evaluated(
                post_debug_c_environment,
            ),
            post_debug_f_environment: LoaderFullObserverInvariantStateV1::evaluated(
                post_debug_f_environment,
            ),
            profile_stability: LoaderFullObserverInvariantStateV1::evaluated(profile_stability),
            environment_destruction_once: LoaderFullObserverInvariantStateV1::evaluated(
                environment_destruction_once,
            ),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn after_debug_c_rejection(
        fallback_authority: bool,
        original_reproduction: bool,
        original_invariants: bool,
        debug_c_trace_admission: bool,
        post_debug_c_environment: bool,
        profile_stability: bool,
        environment_destruction_once: bool,
    ) -> Self {
        Self {
            fallback_authority: LoaderFullObserverInvariantStateV1::evaluated(fallback_authority),
            original_reproduction: LoaderFullObserverInvariantStateV1::evaluated(
                original_reproduction,
            ),
            original_invariants: LoaderFullObserverInvariantStateV1::evaluated(original_invariants),
            original_projection: LoaderFullObserverInvariantStateV1::NotRun,
            debug_pair_common: LoaderFullObserverInvariantStateV1::NotRun,
            debug_mode: LoaderFullObserverInvariantStateV1::NotRun,
            debug_c_trace_admission: LoaderFullObserverInvariantStateV1::evaluated(
                debug_c_trace_admission,
            ),
            debug_f_trace_admission: LoaderFullObserverInvariantStateV1::NotRun,
            debug_containment: LoaderFullObserverInvariantStateV1::NotRun,
            post_debug_c_environment: LoaderFullObserverInvariantStateV1::evaluated(
                post_debug_c_environment,
            ),
            post_debug_f_environment: LoaderFullObserverInvariantStateV1::NotRun,
            profile_stability: LoaderFullObserverInvariantStateV1::evaluated(profile_stability),
            environment_destruction_once: LoaderFullObserverInvariantStateV1::evaluated(
                environment_destruction_once,
            ),
        }
    }

    fn valid(&self) -> bool {
        self.named_states()
            .into_iter()
            .all(|(_, state)| state == LoaderFullObserverInvariantStateV1::Passed)
    }

    fn failed_diagnostic(&self) -> String {
        self.named_states()
            .into_iter()
            .filter_map(|(name, state)| {
                (state == LoaderFullObserverInvariantStateV1::Failed).then_some(name)
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn named_states(&self) -> [(&'static str, LoaderFullObserverInvariantStateV1); 13] {
        [
            ("fallback-authority", self.fallback_authority),
            ("original-reproduction", self.original_reproduction),
            ("original-invariants", self.original_invariants),
            ("original-projection", self.original_projection),
            ("debug-pair-common", self.debug_pair_common),
            ("debug-mode", self.debug_mode),
            ("debug-c-trace-admission", self.debug_c_trace_admission),
            ("debug-f-trace-admission", self.debug_f_trace_admission),
            ("debug-containment", self.debug_containment),
            ("post-debug-c-environment", self.post_debug_c_environment),
            ("post-debug-f-environment", self.post_debug_f_environment),
            ("profile-stability", self.profile_stability),
            (
                "environment-destruction-once",
                self.environment_destruction_once,
            ),
        ]
    }
}

#[allow(clippy::too_many_arguments)]
fn render_loader_full_observer_diagnostic(
    state: &str,
    debug_c: &LoaderEnvironmentCanaryOutcomeV1,
    debug_f: Option<&LoaderEnvironmentCanaryOutcomeV1>,
    debug_c_detail_sha256: &str,
    debug_f_detail_sha256: Option<&str>,
    debug_c_trace: &Result<LoaderFullObserverTraceReceiptV1, LoaderFullObserverTraceRejectionV1>,
    debug_f_trace: Option<
        &Result<LoaderFullObserverTraceReceiptV1, LoaderFullObserverTraceRejectionV1>,
    >,
    module_frontier: Option<&LoaderFullObserverModuleFrontierV1>,
    after_debug_c: &SharedEnvironmentObservationV1,
    after_debug_f: Option<&SharedEnvironmentObservationV1>,
    environment_destroyed_once: bool,
    original_reproduction_valid: bool,
    invariants: &LoaderFullObserverInvariantReceiptV1,
    job_empty: bool,
) -> String {
    let frontier = |receipt: Option<
        &Result<LoaderFullObserverTraceReceiptV1, LoaderFullObserverTraceRejectionV1>,
    >,
                    field: &str| {
        if state == "observer-perturbed-inconclusive" {
            return "none".to_owned();
        }
        let Some(Ok(receipt)) = receipt else {
            return "none".to_owned();
        };
        match field {
            "trace" => receipt.trace_sha256.clone(),
            "modules" => receipt.candidate_modules_sha256.clone(),
            "unloads" => receipt.unload_tail_sha256.clone(),
            "exceptions" => receipt.exception_tail_sha256.clone(),
            _ => "none".to_owned(),
        }
    };
    let native = |outcome: &LoaderEnvironmentCanaryOutcomeV1| {
        outcome.native_status.map_or_else(
            || "unavailable".to_owned(),
            |code| format!("0x{:08x}", code as u32),
        )
    };
    let debug_f_outcome = debug_f.map_or("not-run", |outcome| outcome.outcome.diagnostic());
    let debug_f_native = debug_f.map_or_else(|| "unavailable".to_owned(), &native);
    let debug_f_phase = debug_f.map_or("none", |outcome| outcome.failure_phase);
    let after_debug_f_scan = after_debug_f.map_or("not-run", |observation| observation.scan);
    let after_debug_f_metadata =
        after_debug_f.map_or(false, |observation| observation.metadata_match);
    let after_debug_f_sha256 =
        after_debug_f.map_or("none", |observation| observation.detail_sha256.as_str());
    let trace_admission = |trace: Option<
        &Result<LoaderFullObserverTraceReceiptV1, LoaderFullObserverTraceRejectionV1>,
    >| {
        trace.map_or_else(
            || "not-run".to_owned(),
            |trace| match trace {
                Ok(_) => "admitted".to_owned(),
                Err(rejection) => rejection.diagnostic(),
            },
        )
    };
    let failed_invariants = invariants.failed_diagnostic();
    let module_frontier_visible = state != "observer-perturbed-inconclusive";
    let module_frontier_state = if !module_frontier_visible {
        "suppressed"
    } else {
        module_frontier.map_or("unavailable", |frontier| {
            if frontier.useful {
                "strict-f-prefix-c-extension"
            } else {
                "nonlocalizing"
            }
        })
    };
    let module_frontier_count = |field: &str| {
        if !module_frontier_visible {
            return "none".to_owned();
        }
        module_frontier.map_or_else(
            || "none".to_owned(),
            |frontier| match field {
                "c-total" => frontier.debug_c_total.to_string(),
                "c-retained" => frontier.debug_c_retained.to_string(),
                "f-total" => frontier.debug_f_total.to_string(),
                "f-retained" => frontier.debug_f_retained.to_string(),
                "common-prefix" => frontier.common_prefix.to_string(),
                _ => "none".to_owned(),
            },
        )
    };
    let module_frontier_hash = |field: &str| {
        if !module_frontier_visible {
            return "none".to_owned();
        }
        module_frontier
            .and_then(|frontier| match field {
                "c-sequence" => Some(&frontier.debug_c_sequence_sha256),
                "f-sequence" => Some(&frontier.debug_f_sequence_sha256),
                "last-common" if frontier.useful => frontier.last_common_identity_sha256.as_ref(),
                "first-c-only" if frontier.useful => frontier.first_c_only_identity_sha256.as_ref(),
                _ => None,
            })
            .cloned()
            .unwrap_or_else(|| "none".to_owned())
    };
    format!(
        "loader_observer_perturbation=v1 state={state} observer_perturbed=true changed_fields=[debugger_relation,debug_creation_flag] debug_c_observer=full-observer-v4 debug_f_observer=full-observer-v4 debug_c_loader_snaps=false debug_f_loader_snaps=false loader_snap_evidence=expected-empty ifeo_changed=false debug_c=[outcome={} native={} phase={} detail_sha256={debug_c_detail_sha256}] debug_f=[outcome={debug_f_outcome} native={debug_f_native} phase={debug_f_phase} detail_sha256={}] debug_c_trace_admission={} debug_f_trace_admission={} failed_invariants=[{failed_invariants}] debug_c_trace_sha256={} debug_f_trace_sha256={} debug_c_modules_sha256={} debug_f_modules_sha256={} debug_c_unloads_sha256={} debug_f_unloads_sha256={} debug_c_exceptions_sha256={} debug_f_exceptions_sha256={} stable_module_frontier={module_frontier_state} stable_module_c_total={} stable_module_c_retained={} stable_module_c_sequence_sha256={} stable_module_f_total={} stable_module_f_retained={} stable_module_f_sequence_sha256={} stable_module_common_prefix={} stable_module_last_common_sha256={} stable_module_first_c_only_sha256={} after_debug_c_scan={} after_debug_c_metadata_match={} after_debug_c_observation_sha256={} after_debug_f_scan={after_debug_f_scan} after_debug_f_metadata_match={after_debug_f_metadata} after_debug_f_observation_sha256={after_debug_f_sha256} shared_environment_owner=original-baseline shared_environment_destroyed_once={environment_destroyed_once} original_reproduction_valid={original_reproduction_valid} invariants_valid={} candidate_frontier_only=true requested_access_available=false exact_resource_identified=false acl_fix_identified=false primary_failure=original-a debugger_values_redacted=true environment_values_redacted=true token_values_redacted=true job_empty={job_empty} release_sent=false workload_executed=false qualification_promoted=false",
        debug_c.outcome.diagnostic(),
        native(debug_c),
        debug_c.failure_phase,
        debug_f_detail_sha256.unwrap_or("none"),
        trace_admission(Some(debug_c_trace)),
        trace_admission(debug_f_trace),
        frontier(Some(debug_c_trace), "trace"),
        frontier(debug_f_trace, "trace"),
        frontier(Some(debug_c_trace), "modules"),
        frontier(debug_f_trace, "modules"),
        frontier(Some(debug_c_trace), "unloads"),
        frontier(debug_f_trace, "unloads"),
        frontier(Some(debug_c_trace), "exceptions"),
        frontier(debug_f_trace, "exceptions"),
        module_frontier_count("c-total"),
        module_frontier_count("c-retained"),
        module_frontier_hash("c-sequence"),
        module_frontier_count("f-total"),
        module_frontier_count("f-retained"),
        module_frontier_hash("f-sequence"),
        module_frontier_count("common-prefix"),
        module_frontier_hash("last-common"),
        module_frontier_hash("first-c-only"),
        after_debug_c.scan,
        after_debug_c.metadata_match,
        after_debug_c.detail_sha256,
        invariants.valid(),
    )
}

#[allow(clippy::too_many_arguments)]
#[cfg(test)]
fn loader_full_observer_invariants_valid(
    fallback_allowed: bool,
    original_reproduction_valid: bool,
    original_invariants_valid: bool,
    original_projection_exact: bool,
    debug_pair_common_exact: bool,
    debug_mode_exact: bool,
    debug_traces_admitted: bool,
    debug_containment_exact: bool,
    after_debug_c_stable: bool,
    after_debug_f_stable: bool,
    profile_stable: bool,
    environment_destroyed_once: bool,
) -> bool {
    LoaderFullObserverInvariantReceiptV1::evaluated(
        fallback_allowed,
        original_reproduction_valid,
        original_invariants_valid,
        original_projection_exact,
        debug_pair_common_exact,
        debug_mode_exact,
        debug_traces_admitted,
        debug_traces_admitted,
        debug_containment_exact,
        after_debug_c_stable,
        after_debug_f_stable,
        profile_stable,
        environment_destroyed_once,
    )
    .valid()
}

fn loader_full_observer_debug_f_allowed(
    fallback_allowed: bool,
    after_debug_c: &SharedEnvironmentObservationV1,
) -> bool {
    fallback_allowed && after_debug_c.stable()
}

fn loader_restriction_presence_required(
    object_security_state: &str,
    object_security_common_evidence_valid: bool,
    object_security_descriptor_evidence_present: bool,
    object_security_invariants_valid: bool,
) -> bool {
    object_security_state == "classified-common-failure"
        && object_security_common_evidence_valid
        && object_security_descriptor_evidence_present
        && object_security_invariants_valid
}

#[allow(clippy::too_many_arguments)]
fn loader_restriction_presence_prerequisite_canary_diagnostic(
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    tokens: &LoaderRestrictionCanaryTokens,
) -> LoaderRestrictionPresencePrerequisiteEvaluationV1 {
    if let Err(error) = super::token::validate_transferred_loader_restriction_presence_pair(
        tokens.baseline.raw(),
        tokens.no_restricting_sid.raw(),
        &tokens.source_binding_sha256,
        &tokens.restriction_presence_binding_sha256,
    ) {
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=restriction-presence-reattestation restriction_presence_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                super::record::digest(error.as_bytes()),
            ),
        };
    }
    let baseline_snapshot = match super::token::token_attestation_snapshot(tokens.baseline.raw()) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=baseline-attestation restriction_presence_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    super::record::digest(error.as_bytes()),
                ),
            };
        }
    };
    let comparison_snapshot = match super::token::token_attestation_snapshot(
        tokens.no_restricting_sid.raw(),
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=comparison-attestation restriction_presence_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    super::record::digest(error.as_bytes()),
                ),
            };
        }
    };
    let (same_access_restricted, same_access_snapshot, restriction_identity_binding_sha256) =
        match super::token::loader_restriction_identity_sibling_from_presence_comparison(
            tokens.baseline.raw(),
            tokens.no_restricting_sid.raw(),
            &tokens.source_binding_sha256,
            &tokens.restriction_presence_binding_sha256,
        ) {
            Ok(sibling) => sibling,
            Err(error) => {
                return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                    diagnostic: format!(
                        "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=same-access-restriction-derivation restriction_presence_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                        tokens.restriction_presence_binding_sha256,
                        super::record::digest(error.as_bytes()),
                    ),
                };
            }
        };
    let (logon_restricted, logon_snapshot, logon_restriction_binding_sha256) =
        match super::token::loader_logon_restriction_sibling_from_identity_comparison(
            tokens.baseline.raw(),
            tokens.no_restricting_sid.raw(),
            same_access_restricted.raw(),
            &tokens.source_binding_sha256,
            &tokens.restriction_presence_binding_sha256,
            &restriction_identity_binding_sha256,
        ) {
            Ok(sibling) => sibling,
            Err(error) => {
                return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                    diagnostic: format!(
                        "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=logon-restriction-derivation restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                        tokens.restriction_presence_binding_sha256,
                        restriction_identity_binding_sha256,
                        super::record::digest(error.as_bytes()),
                    ),
                };
            }
        };
    let (
        authenticated_users_restricted,
        authenticated_users_snapshot,
        authenticated_users_restriction_binding_sha256,
    ) = match super::token::loader_authenticated_users_restriction_sibling_from_logon_comparison(
        tokens.baseline.raw(),
        tokens.no_restricting_sid.raw(),
        same_access_restricted.raw(),
        logon_restricted.raw(),
        &tokens.source_binding_sha256,
        &tokens.restriction_presence_binding_sha256,
        &restriction_identity_binding_sha256,
        &logon_restriction_binding_sha256,
    ) {
        Ok(sibling) => sibling,
        Err(error) => {
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=authenticated-users-restriction-derivation restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    restriction_identity_binding_sha256,
                    logon_restriction_binding_sha256,
                    super::record::digest(error.as_bytes()),
                ),
            };
        }
    };
    let (target_user_restricted, target_user_snapshot, target_user_restriction_binding_sha256) =
        match super::token::loader_target_user_restriction_sibling_from_authenticated_users_comparison(
            tokens.baseline.raw(),
            tokens.no_restricting_sid.raw(),
            same_access_restricted.raw(),
            logon_restricted.raw(),
            authenticated_users_restricted.raw(),
            &tokens.source_binding_sha256,
            &tokens.restriction_presence_binding_sha256,
            &restriction_identity_binding_sha256,
            &logon_restriction_binding_sha256,
            &authenticated_users_restriction_binding_sha256,
        ) {
            Ok(sibling) => sibling,
            Err(error) => {
                return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                    diagnostic: format!(
                        "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=target-user-restriction-derivation restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} authenticated_users_restriction_binding_sha256={} error_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                        tokens.restriction_presence_binding_sha256,
                        restriction_identity_binding_sha256,
                        logon_restriction_binding_sha256,
                        authenticated_users_restriction_binding_sha256,
                        super::record::digest(error.as_bytes()),
                    ),
                };
            }
        };
    let baseline_envelope = baseline_snapshot.behavior.envelope.clone();
    let comparison_envelope = comparison_snapshot.behavior.envelope.clone();
    let same_access_envelope = same_access_snapshot.behavior.envelope.clone();
    let logon_envelope = logon_snapshot.behavior.envelope.clone();
    let authenticated_users_envelope = authenticated_users_snapshot.behavior.envelope.clone();
    let target_user_envelope = target_user_snapshot.behavior.envelope.clone();
    let before = observe_loader_profile(tokens.profile.raw(), &baseline_envelope.user_sid);
    if before.state != LoaderProfileHiveStateV1::AlreadyLoadedBorrowed {
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=profile-precondition profile_state={} restriction_presence_binding_sha256={} token_values_redacted=true workload_executed=false qualification_promoted=false",
                before.state.diagnostic(),
                tokens.restriction_presence_binding_sha256,
            ),
        };
    }
    let mut shared_environment = match OwnedUserEnvironmentBlock::create(tokens.baseline.raw()) {
        Ok(environment) => environment,
        Err(error) => {
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-create restriction_presence_binding_sha256={} error_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    super::record::digest(error.detail.as_bytes()),
                ),
            };
        }
    };
    let admitted_environment = match shared_environment.inventory() {
        Ok(inventory) if inventory.missing_required.is_empty() => inventory,
        Ok(inventory) => {
            let detail = format!(
                "shared environment is missing {} required keys",
                inventory.missing_required.len()
            );
            let destruction = shared_environment.destroy_after_create();
            let destruction_sha256 = destruction.as_ref().map_or_else(
                |error| super::record::digest(error.detail.as_bytes()),
                |()| super::record::digest(b"ok"),
            );
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-admission restriction_presence_binding_sha256={} error_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    super::record::digest(detail.as_bytes()),
                    destruction_sha256,
                ),
            };
        }
        Err(error) => {
            let destruction = shared_environment.destroy_after_create();
            let destruction_sha256 = destruction.as_ref().map_or_else(
                |error| super::record::digest(error.detail.as_bytes()),
                |()| super::record::digest(b"ok"),
            );
            return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
                diagnostic: format!(
                    "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-admission restriction_presence_binding_sha256={} error_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                    tokens.restriction_presence_binding_sha256,
                    super::record::digest(error.detail.as_bytes()),
                    destruction_sha256,
                ),
            };
        }
    };
    let baseline = launch_target_desktop_loader_control_cell_with_shared_environment(
        tokens.baseline.raw(),
        &baseline_envelope,
        &baseline_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        None,
    );
    let after_baseline_environment = shared_environment.inventory();
    let after_baseline_observation = shared_environment_observation(
        &admitted_environment,
        &after_baseline_environment,
        "after-baseline",
    );
    if !after_baseline_observation.stable() {
        let destruction = shared_environment.destroy_after_create();
        let destruction_sha256 = destruction.as_ref().map_or_else(
            |error| super::record::digest(error.detail.as_bytes()),
            |()| super::record::digest(b"ok"),
        );
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-after-baseline restriction_presence_binding_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                after_baseline_observation.scan,
                after_baseline_observation.metadata_match,
                after_baseline_observation.detail_sha256,
                destruction_sha256,
            ),
        };
    }
    let comparison = launch_target_desktop_loader_control_cell_with_shared_environment(
        tokens.no_restricting_sid.raw(),
        &comparison_envelope,
        &comparison_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        None,
    );
    let after_comparison_environment = shared_environment.inventory();
    let after_comparison_observation = shared_environment_observation(
        &admitted_environment,
        &after_comparison_environment,
        "after-comparison",
    );
    if !after_comparison_observation.stable() {
        let destruction = shared_environment.destroy_after_create();
        let destruction_sha256 = destruction.as_ref().map_or_else(
            |error| super::record::digest(error.detail.as_bytes()),
            |()| super::record::digest(b"ok"),
        );
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-after-comparison restriction_presence_binding_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                after_comparison_observation.scan,
                after_comparison_observation.metadata_match,
                after_comparison_observation.detail_sha256,
                destruction_sha256,
            ),
        };
    }
    let passive_access_localization =
        super::access_trace::PassiveAccessLocalizationObserverV1::start_ready_before_child_creation(
        );
    let same_access = launch_target_desktop_loader_control_cell_with_shared_environment(
        same_access_restricted.raw(),
        &same_access_envelope,
        &same_access_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        passive_access_localization.as_ref().ok().map(|observer| {
            (
                observer,
                super::access_trace::PassiveAccessLocalizationCellV1::CanonicalSameAccess,
            )
        }),
    );
    let after_same_access_environment = shared_environment.inventory();
    let after_same_access_observation = shared_environment_observation(
        &admitted_environment,
        &after_same_access_environment,
        "after-same-access",
    );
    if !after_same_access_observation.stable() {
        let destruction = shared_environment.destroy_after_create();
        let destruction_sha256 = destruction.as_ref().map_or_else(
            |error| super::record::digest(error.detail.as_bytes()),
            |()| super::record::digest(b"ok"),
        );
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-after-same-access restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                restriction_identity_binding_sha256,
                after_same_access_observation.scan,
                after_same_access_observation.metadata_match,
                after_same_access_observation.detail_sha256,
                destruction_sha256,
            ),
        };
    }
    let logon = launch_target_desktop_loader_control_cell_with_shared_environment(
        logon_restricted.raw(),
        &logon_envelope,
        &logon_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        None,
    );
    let after_logon_environment = shared_environment.inventory();
    let after_logon_observation = shared_environment_observation(
        &admitted_environment,
        &after_logon_environment,
        "after-logon",
    );
    if !after_logon_observation.stable() {
        let destruction = shared_environment.destroy_after_create();
        let destruction_sha256 = destruction.as_ref().map_or_else(
            |error| super::record::digest(error.detail.as_bytes()),
            |()| super::record::digest(b"ok"),
        );
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-after-logon restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                restriction_identity_binding_sha256,
                logon_restriction_binding_sha256,
                after_logon_observation.scan,
                after_logon_observation.metadata_match,
                after_logon_observation.detail_sha256,
                destruction_sha256,
            ),
        };
    }
    let authenticated_users = launch_target_desktop_loader_control_cell_with_shared_environment(
        authenticated_users_restricted.raw(),
        &authenticated_users_envelope,
        &authenticated_users_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        None,
    );
    let after_authenticated_users_environment = shared_environment.inventory();
    let after_authenticated_users_observation = shared_environment_observation(
        &admitted_environment,
        &after_authenticated_users_environment,
        "after-authenticated-users",
    );
    if !after_authenticated_users_observation.stable() {
        let destruction = shared_environment.destroy_after_create();
        let destruction_sha256 = destruction.as_ref().map_or_else(
            |error| super::record::digest(error.detail.as_bytes()),
            |()| super::record::digest(b"ok"),
        );
        return LoaderRestrictionPresencePrerequisiteEvaluationV1 {
            diagnostic: format!(
                "loader_restriction_presence_prerequisite_canary=v2 state=invalid stage=shared-environment-after-authenticated-users restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} authenticated_users_restriction_binding_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} destruction_sha256={} environment_values_redacted=true token_values_redacted=true workload_executed=false qualification_promoted=false",
                tokens.restriction_presence_binding_sha256,
                restriction_identity_binding_sha256,
                logon_restriction_binding_sha256,
                authenticated_users_restriction_binding_sha256,
                after_authenticated_users_observation.scan,
                after_authenticated_users_observation.metadata_match,
                after_authenticated_users_observation.detail_sha256,
                destruction_sha256,
            ),
        };
    }
    let target_user = launch_target_desktop_loader_control_cell_with_shared_environment(
        target_user_restricted.raw(),
        &target_user_envelope,
        &target_user_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        LoaderControlMatrixCellV4::PRODUCTION,
        &mut shared_environment,
        &admitted_environment,
        LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
        passive_access_localization.as_ref().ok().map(|observer| {
            (
                observer,
                super::access_trace::PassiveAccessLocalizationCellV1::TargetUser,
            )
        }),
    );
    let after_target_user_environment = shared_environment.inventory();
    let after_target_user_observation = shared_environment_observation(
        &admitted_environment,
        &after_target_user_environment,
        "after-target-user",
    );
    let original_environment_stable = after_baseline_observation.stable()
        && after_comparison_observation.stable()
        && after_same_access_observation.stable()
        && after_logon_observation.stable()
        && after_authenticated_users_observation.stable()
        && after_target_user_observation.stable();
    let baseline_outcome = loader_environment_canary_outcome("full-restricted", &baseline);
    let comparison_outcome =
        loader_environment_canary_outcome("privilege-disabled/no-restricting-SID", &comparison);
    let same_access_outcome = loader_environment_canary_outcome(
        "privilege-disabled/canonical-same-access-restricted",
        &same_access,
    );
    let logon_outcome =
        loader_environment_canary_outcome("privilege-disabled/target-logon-SID-restricted", &logon);
    let authenticated_users_outcome = loader_environment_canary_outcome(
        "privilege-disabled/authenticated-users-SID-restricted",
        &authenticated_users,
    );
    let target_user_outcome = loader_environment_canary_outcome(
        "privilege-disabled/target-user-SID-restricted",
        &target_user,
    );
    let common_field_names = [
        "matrix_cell",
        "debug_mode",
        "environment_classification",
        "environment_sha256",
        "environment_keys_sha256",
        "environment_units",
        "environment_entries",
        "environment_profile_loaded",
        "source_authentication_id",
        "source_session_id",
        "desktop_sha256",
        "binary_sha256",
        "current_directory_sha256",
        "command_semantics_sha256",
        "command_dynamic_fields",
        "creation_flags",
        "job_membership_attested",
        "object_security_authority",
        "process_policy_sha256",
        "thread_policy_sha256",
        "process_object_live_sha256",
        "thread_object_live_sha256",
        "descriptor_readback",
    ];
    let common_fields: [Result<(&str, String), String>; 23] = common_field_names.map(|field| {
        let value = loader_common_result_field(&baseline, &comparison, field)?;
        loader_common_result_field(&baseline, &same_access, field)?;
        loader_common_result_field(&baseline, &logon, field)?;
        loader_common_result_field(&baseline, &authenticated_users, field)?;
        loader_common_result_field(&baseline, &target_user, field)?;
        Ok((field, value))
    });
    let common_error = common_fields
        .iter()
        .find_map(|result| result.as_ref().err());
    let launcher_authority_exact = [
        &baseline,
        &comparison,
        &same_access,
        &logon,
        &authenticated_users,
        &target_user,
    ]
    .into_iter()
    .all(|result| {
        loader_result_field(result, "object_security_authority").as_deref()
            == Some(LoaderObjectSecurityAuthorityV1::LauncherExplicit.diagnostic())
    });
    let job_empty_exact = [
        &baseline,
        &comparison,
        &same_access,
        &logon,
        &authenticated_users,
        &target_user,
    ]
    .into_iter()
    .all(loader_control_cell_job_empty_attested);
    let containment_exact = [
        &baseline,
        &comparison,
        &same_access,
        &logon,
        &authenticated_users,
        &target_user,
    ]
    .into_iter()
    .all(|result| {
        loader_result_field(result, "environment_profile_loaded").as_deref() == Some("true")
            && loader_result_field(result, "job_membership_attested").as_deref() == Some("true")
            && loader_result_field(result, "descriptor_readback").as_deref() == Some("true")
    }) && job_empty_exact;
    let after_original = observe_loader_profile(tokens.profile.raw(), &baseline_envelope.user_sid);
    let original_invariants_valid = common_error.is_none()
        && after_original == before
        && launcher_authority_exact
        && containment_exact
        && original_environment_stable;
    let original_reproduction_valid = loader_restriction_original_sext_reproduction_valid(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        &logon_outcome,
        &authenticated_users_outcome,
        &target_user_outcome,
        original_invariants_valid,
    );
    let passive_setup_evidence = passive_access_localization
        .as_ref()
        .err()
        .map(super::access_trace::PassiveAccessLocalizationEvidenceV1::observer_unavailable);
    let full_observer_fallback_allowed = original_reproduction_valid
        && matches!(
            passive_setup_evidence.as_ref(),
            Some(evidence) if evidence.exact_session_start_access_denied()
        );
    let debug_pair = if full_observer_fallback_allowed {
        let debug_c = launch_target_desktop_loader_control_cell_with_shared_environment(
            same_access_restricted.raw(),
            &same_access_envelope,
            &same_access_snapshot,
            exact_desktop,
            launch_context,
            association_preflight,
            holder_identity,
            LoaderControlMatrixCellV4::RESTRICTION_FULL_OBSERVER_SNAPS_OFF,
            &mut shared_environment,
            &admitted_environment,
            LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
            None,
        );
        let after_debug_c_environment = shared_environment.inventory();
        let after_debug_c_observation = shared_environment_observation(
            &admitted_environment,
            &after_debug_c_environment,
            "after-debug-c",
        );
        let debug_f = if loader_full_observer_debug_f_allowed(
            full_observer_fallback_allowed,
            &after_debug_c_observation,
        ) {
            let result = launch_target_desktop_loader_control_cell_with_shared_environment(
                target_user_restricted.raw(),
                &target_user_envelope,
                &target_user_snapshot,
                exact_desktop,
                launch_context,
                association_preflight,
                holder_identity,
                LoaderControlMatrixCellV4::RESTRICTION_FULL_OBSERVER_SNAPS_OFF,
                &mut shared_environment,
                &admitted_environment,
                LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary,
                None,
            );
            let after_environment = shared_environment.inventory();
            let after_observation = shared_environment_observation(
                &admitted_environment,
                &after_environment,
                "after-debug-f",
            );
            Some((result, after_observation))
        } else {
            None
        };
        Some((debug_c, after_debug_c_observation, debug_f))
    } else {
        None
    };
    let debug_environment_stable = match debug_pair.as_ref() {
        Some((_, after_debug_c, Some((_, after_debug_f)))) => {
            after_debug_c.stable() && after_debug_f.stable()
        }
        Some((_, _, None)) => false,
        None => true,
    };
    let environment_stable = original_environment_stable && debug_environment_stable;
    let environment_destruction = shared_environment.destroy_after_create();
    let environment_destruction_sha256 = environment_destruction.as_ref().map_or_else(
        |error| super::record::digest(error.detail.as_bytes()),
        |()| super::record::digest(b"shared-userenv-destroyed-once"),
    );
    let after = observe_loader_profile(tokens.profile.raw(), &baseline_envelope.user_sid);
    let shared_environment_valid = environment_stable && environment_destruction.is_ok();
    let invariants_valid = common_error.is_none()
        && after == before
        && launcher_authority_exact
        && containment_exact
        && shared_environment_valid;
    let presence_state = classify_loader_restriction_presence_outcomes(
        &baseline_outcome,
        &comparison_outcome,
        invariants_valid,
    );
    let identity_state = classify_loader_restriction_identity_outcomes(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        invariants_valid,
    );
    let logon_state = classify_loader_restriction_logon_outcomes(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        &logon_outcome,
        invariants_valid,
    );
    let authenticated_users_state = classify_loader_restriction_authenticated_users_outcomes(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        &logon_outcome,
        &authenticated_users_outcome,
        invariants_valid,
    );
    let state = classify_loader_restriction_target_user_outcomes(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        &logon_outcome,
        &authenticated_users_outcome,
        &target_user_outcome,
        invariants_valid,
    );
    let passive_access_reproduction_valid = loader_restriction_original_sext_reproduction_valid(
        &baseline_outcome,
        &comparison_outcome,
        &same_access_outcome,
        &logon_outcome,
        &authenticated_users_outcome,
        &target_user_outcome,
        invariants_valid,
    ) && state
        == "no-tested-singleton-sufficient-trace-required";
    let passive_access_localization = match passive_access_localization {
        Ok(observer) => observer.finish(passive_access_reproduction_valid),
        Err(error) => {
            super::access_trace::PassiveAccessLocalizationEvidenceV1::observer_unavailable(&error)
        }
    };
    let debug_preserved_field_names = [
        "environment_classification",
        "environment_sha256",
        "environment_keys_sha256",
        "environment_units",
        "environment_entries",
        "environment_profile_loaded",
        "source_token_sha256",
        "source_token_id",
        "source_modified_id",
        "source_authentication_id",
        "source_session_id",
        "desktop_sha256",
        "binary_sha256",
        "current_directory_sha256",
        "command_semantics_sha256",
        "command_dynamic_fields",
        "job_membership_attested",
        "object_security_authority",
        "process_policy_sha256",
        "thread_policy_sha256",
        "process_object_live_sha256",
        "thread_object_live_sha256",
        "descriptor_readback",
        "target_logon_trustee",
        "restricting_trustee_count",
    ];
    let (debug_observer_diagnostic, trace_session_capability_trigger_sha256) = match debug_pair
        .as_ref()
    {
        Some((debug_c, after_debug_c, Some((debug_f, after_debug_f)))) => {
            let debug_c_outcome = loader_environment_canary_outcome(
                "canonical-same-access/full-observer-snaps-off",
                debug_c,
            );
            let debug_f_outcome = loader_environment_canary_outcome(
                "target-user-singleton/full-observer-snaps-off",
                debug_f,
            );
            let original_projection_exact = debug_preserved_field_names.iter().all(|field| {
                loader_common_result_field(&same_access, debug_c, field).is_ok()
                    && loader_common_result_field(&target_user, debug_f, field).is_ok()
            });
            let debug_pair_common_exact = common_field_names
                .iter()
                .all(|field| loader_common_result_field(debug_c, debug_f, field).is_ok());
            let debug_mode_exact = [&debug_c, &debug_f].into_iter().all(|result| {
                loader_result_field(result, "matrix_cell").as_deref()
                    == Some(
                        LoaderControlMatrixCellV4::RESTRICTION_FULL_OBSERVER_SNAPS_OFF.diagnostic(),
                    )
                    && loader_result_field(result, "debug_mode").as_deref() == Some("true")
                    && loader_result_field(result, "creation_flags").as_deref()
                        == Some("0x00080406")
            });
            let debug_pair_job_empty_exact = [&debug_c, &debug_f]
                .into_iter()
                .all(|result| loader_control_cell_job_empty_attested(result));
            let debug_containment_exact = debug_pair_job_empty_exact
                && [&debug_c, &debug_f].into_iter().all(|result| {
                    loader_result_field(result, "environment_profile_loaded").as_deref()
                        == Some("true")
                        && loader_result_field(result, "job_membership_attested").as_deref()
                            == Some("true")
                        && loader_result_field(result, "descriptor_readback").as_deref()
                            == Some("true")
                        && loader_result_field(result, "object_security_authority").as_deref()
                            == Some(LoaderObjectSecurityAuthorityV1::LauncherExplicit.diagnostic())
                });
            let debug_c_trace = admit_loader_full_observer_trace(debug_c);
            let debug_f_trace = admit_loader_full_observer_trace(debug_f);
            let debug_invariants = LoaderFullObserverInvariantReceiptV1::evaluated(
                full_observer_fallback_allowed,
                original_reproduction_valid,
                original_invariants_valid,
                original_projection_exact,
                debug_pair_common_exact,
                debug_mode_exact,
                debug_c_trace.is_ok(),
                debug_f_trace.is_ok(),
                debug_containment_exact,
                after_debug_c.stable(),
                after_debug_f.stable(),
                after == before,
                environment_destruction.is_ok(),
            );
            let debug_invariants_valid = debug_invariants.valid();
            let module_frontier = debug_c_trace
                .as_ref()
                .ok()
                .zip(debug_f_trace.as_ref().ok())
                .map(|(canonical, target)| loader_full_observer_module_frontier(canonical, target));
            let observer_state = classify_loader_full_observer_pair(
                &debug_c_outcome,
                &debug_f_outcome,
                debug_invariants_valid,
                module_frontier.as_ref().map(|frontier| frontier.useful),
            );
            let detail_hash =
                |label: &[u8], result: &Result<String, TargetDesktopLeaseCreateError>| {
                    let mut material =
                        b"memcordon-loader-observer-perturbation-detail-v1\0".to_vec();
                    material.extend_from_slice(label);
                    material.extend_from_slice(loader_result_detail(result).as_bytes());
                    super::record::digest(&material)
                };
            let debug_c_detail_sha256 = detail_hash(b"debug-c", debug_c);
            let debug_f_detail_sha256 = detail_hash(b"debug-f", debug_f);
            let shared_evidence_sha256 = loader_trace_session_capability_shared_evidence_sha256(
                &admitted_environment,
                &[
                    &after_baseline_observation,
                    &after_comparison_observation,
                    &after_same_access_observation,
                    &after_logon_observation,
                    &after_authenticated_users_observation,
                    &after_target_user_observation,
                    after_debug_c,
                    after_debug_f,
                ],
                &before,
                &after_original,
                &after,
                launcher_authority_exact,
                containment_exact,
                job_empty_exact,
                &environment_destruction_sha256,
            );
            let trigger_sha256 = debug_c_trace
                .as_ref()
                .ok()
                .zip(debug_f_trace.as_ref().ok())
                .zip(module_frontier.as_ref())
                .and_then(|((debug_c_trace, debug_f_trace), module_frontier)| {
                    loader_trace_session_capability_trigger_sha256(
                        super::package::ephemeral_ci_enabled(),
                        passive_setup_evidence
                            .as_ref()
                            .and_then(|evidence| {
                                evidence.exact_session_start_access_denied_sha256()
                            })
                            .as_deref(),
                        original_reproduction_valid,
                        original_invariants_valid,
                        &tokens.source_binding_sha256,
                        &tokens.pair_invariants_sha256,
                        &tokens.restriction_presence_binding_sha256,
                        &restriction_identity_binding_sha256,
                        &logon_restriction_binding_sha256,
                        &authenticated_users_restriction_binding_sha256,
                        &target_user_restriction_binding_sha256,
                        &tokens.profile_binding_sha256,
                        shared_evidence_sha256.as_deref()?,
                        &baseline_outcome,
                        &comparison_outcome,
                        &same_access_outcome,
                        &logon_outcome,
                        &authenticated_users_outcome,
                        &target_user_outcome,
                        &debug_c_outcome,
                        &debug_f_outcome,
                        debug_c_trace,
                        debug_f_trace,
                        module_frontier,
                        &debug_invariants,
                        after_debug_c,
                        after_debug_f,
                    )
                });
            (
                render_loader_full_observer_diagnostic(
                    observer_state,
                    &debug_c_outcome,
                    Some(&debug_f_outcome),
                    &debug_c_detail_sha256,
                    Some(&debug_f_detail_sha256),
                    &debug_c_trace,
                    Some(&debug_f_trace),
                    module_frontier.as_ref(),
                    after_debug_c,
                    Some(after_debug_f),
                    environment_destruction.is_ok(),
                    original_reproduction_valid,
                    &debug_invariants,
                    debug_pair_job_empty_exact,
                ),
                trigger_sha256,
            )
        }
        Some((debug_c, after_debug_c, None)) => {
            let debug_c_outcome = loader_environment_canary_outcome(
                "canonical-same-access/full-observer-snaps-off",
                debug_c,
            );
            let mut material = b"memcordon-loader-observer-perturbation-detail-v1\0".to_vec();
            material.extend_from_slice(b"debug-c");
            material.extend_from_slice(loader_result_detail(debug_c).as_bytes());
            let debug_c_detail_sha256 = super::record::digest(&material);
            let debug_c_trace = admit_loader_full_observer_trace(debug_c);
            let debug_invariants = LoaderFullObserverInvariantReceiptV1::after_debug_c_rejection(
                full_observer_fallback_allowed,
                original_reproduction_valid,
                original_invariants_valid,
                debug_c_trace.is_ok(),
                after_debug_c.stable(),
                after == before,
                environment_destruction.is_ok(),
            );
            (
                render_loader_full_observer_diagnostic(
                    "observer-perturbed-inconclusive",
                    &debug_c_outcome,
                    None,
                    &debug_c_detail_sha256,
                    None,
                    &debug_c_trace,
                    None,
                    None,
                    after_debug_c,
                    None,
                    environment_destruction.is_ok(),
                    original_reproduction_valid,
                    &debug_invariants,
                    loader_control_cell_job_empty_attested(debug_c),
                ),
                None,
            )
        }
        None => (
            format!(
                "loader_observer_perturbation=v1 state=not-run observer_perturbed=false changed_fields=[] fallback_allowed={full_observer_fallback_allowed} original_reproduction_valid={original_reproduction_valid} debug_c=none debug_f=none after_debug_c_scan=not-run after_debug_f_scan=not-run shared_environment_owner=original-baseline shared_environment_destroyed_once={} candidate_frontier_only=true requested_access_available=false exact_resource_identified=false acl_fix_identified=false primary_failure=original-a debugger_values_redacted=true environment_values_redacted=true token_values_redacted=true release_sent=false workload_executed=false qualification_promoted=false",
                environment_destruction.is_ok(),
            ),
            None,
        ),
    };
    let debug_observer_diagnostic = match trace_session_capability_trigger_sha256 {
        Some(trigger_sha256) => format!(
            "{} {}",
            debug_observer_diagnostic,
            super::session_broker::request_trace_session_capability(trigger_sha256).diagnostic(),
        ),
        None => format!(
            "{} broker_trace_session_capability=v1 state=not-run trigger=none primary_failure=original-a release_sent=false workload_executed=false qualification_promoted=false",
            debug_observer_diagnostic,
        ),
    };
    let common = common_fields
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|(field, value)| format!("{field}={value}"))
        .collect::<Vec<_>>()
        .join(" ");
    let failed_common_fields = common_field_names
        .iter()
        .zip(common_fields.iter())
        .filter_map(|(field, result)| result.is_err().then_some(*field))
        .collect::<Vec<_>>()
        .join(",");
    let invariant_error_sha256 = common_error.map_or_else(
        || {
            if after != before {
                super::record::digest(b"profile observation changed")
            } else if !launcher_authority_exact {
                super::record::digest(b"launcher-explicit authority binding changed")
            } else if !containment_exact {
                super::record::digest(b"diagnostic containment evidence is incomplete")
            } else if !environment_stable {
                after_target_user_observation.detail_sha256.clone()
            } else if let Err(error) = &environment_destruction {
                super::record::digest(error.detail.as_bytes())
            } else {
                "none".to_owned()
            }
        },
        |error| super::record::digest(error.as_bytes()),
    );
    let outcome = |value: &LoaderEnvironmentCanaryOutcomeV1| {
        format!(
            "restriction={} outcome={} native={} phase={} detail_sha256={}",
            value.environment,
            value.outcome.diagnostic(),
            value.native_status.map_or_else(
                || "unavailable".to_owned(),
                |code| format!("0x{:08x}", code as u32)
            ),
            value.failure_phase,
            value.detail_sha256,
        )
    };
    LoaderRestrictionPresencePrerequisiteEvaluationV1 {
        diagnostic: format!(
            "loader_restriction_presence_prerequisite_canary=v2 state={state} presence_state={presence_state} identity_state={identity_state} logon_state={logon_state} authenticated_users_state={authenticated_users_state} baseline_semantics=full-restricted comparison_semantics=privilege-disabled/no-restricting-SID same_access_semantics=privilege-disabled/canonical-same-access-restricted logon_semantics=privilege-disabled/target-logon-SID-restricted authenticated_users_semantics=privilege-disabled/authenticated-users-SID-restricted target_user_semantics=privilege-disabled/target-user-SID-restricted differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids] failed_common_fields=[{failed_common_fields}] source_binding_sha256={} restriction_presence_binding_sha256={} restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} authenticated_users_restriction_binding_sha256={} target_user_restriction_binding_sha256={} shared_environment_sha256={} shared_environment_keys_sha256={} shared_environment_units={} shared_environment_entries={} shared_environment_profile_loaded=true after_baseline_scan={} after_baseline_metadata_match={} after_baseline_observation_sha256={} after_comparison_scan={} after_comparison_metadata_match={} after_comparison_observation_sha256={} after_same_access_scan={} after_same_access_metadata_match={} after_same_access_observation_sha256={} after_logon_scan={} after_logon_metadata_match={} after_logon_observation_sha256={} after_authenticated_users_scan={} after_authenticated_users_metadata_match={} after_authenticated_users_observation_sha256={} after_target_user_scan={} after_target_user_metadata_match={} after_target_user_observation_sha256={} shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} shared_environment_stable={} shared_environment_destroyed={} baseline=[{}] comparison=[{}] same_access=[{}] logon=[{}] authenticated_users=[{}] target_user=[{}] profile_state=already-loaded-borrowed profile_stable={} launcher_explicit={} invariants_valid={} {} invariant_error_sha256={} {} {} environment_values_redacted=true token_values_redacted=true job_empty={job_empty_exact} workload_executed=false qualification_promoted=false",
            tokens.source_binding_sha256,
            tokens.restriction_presence_binding_sha256,
            restriction_identity_binding_sha256,
            logon_restriction_binding_sha256,
            authenticated_users_restriction_binding_sha256,
            target_user_restriction_binding_sha256,
            admitted_environment.sha256,
            admitted_environment.keys_sha256,
            admitted_environment.units,
            admitted_environment.entries,
            after_baseline_observation.scan,
            after_baseline_observation.metadata_match,
            after_baseline_observation.detail_sha256,
            after_comparison_observation.scan,
            after_comparison_observation.metadata_match,
            after_comparison_observation.detail_sha256,
            after_same_access_observation.scan,
            after_same_access_observation.metadata_match,
            after_same_access_observation.detail_sha256,
            after_logon_observation.scan,
            after_logon_observation.metadata_match,
            after_logon_observation.detail_sha256,
            after_authenticated_users_observation.scan,
            after_authenticated_users_observation.metadata_match,
            after_authenticated_users_observation.detail_sha256,
            after_target_user_observation.scan,
            after_target_user_observation.metadata_match,
            after_target_user_observation.detail_sha256,
            after_target_user_observation.scan,
            after_target_user_observation.metadata_match,
            after_target_user_observation.detail_sha256,
            environment_stable,
            environment_destruction.is_ok(),
            outcome(&baseline_outcome),
            outcome(&comparison_outcome),
            outcome(&same_access_outcome),
            outcome(&logon_outcome),
            outcome(&authenticated_users_outcome),
            outcome(&target_user_outcome),
            after == before,
            launcher_authority_exact,
            invariants_valid,
            common,
            invariant_error_sha256,
            passive_access_localization.diagnostic(),
            debug_observer_diagnostic,
        ),
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum LoaderObjectSecurityOutcomeForTest {
    Passed,
    Failed { native: i32, phase: &'static str },
}

#[cfg(test)]
pub(crate) fn loader_restriction_presence_gate_for_test(
    object_security_state: &str,
    object_security_common_evidence_valid: bool,
    object_security_descriptor_evidence_present: bool,
    object_security_invariants_valid: bool,
) -> bool {
    loader_restriction_presence_required(
        object_security_state,
        object_security_common_evidence_valid,
        object_security_descriptor_evidence_present,
        object_security_invariants_valid,
    )
}

#[cfg(test)]
pub(crate) fn loader_control_cell_job_empty_attested_for_test(detail: &str) -> bool {
    loader_control_cell_job_empty_attested(&Ok(detail.to_owned()))
}

#[cfg(test)]
pub(crate) fn classify_loader_restriction_presence_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    comparison: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_restriction_presence_outcomes(
        &outcome("full-restricted", baseline),
        &outcome("privilege-disabled/no-restricting-SID", comparison),
        invariants_valid,
    )
}

#[cfg(test)]
pub(crate) fn classify_loader_restriction_identity_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    no_restricting_sid: LoaderObjectSecurityOutcomeForTest,
    same_access_restricted: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_restriction_identity_outcomes(
        &outcome("full-restricted", baseline),
        &outcome("privilege-disabled/no-restricting-SID", no_restricting_sid),
        &outcome(
            "privilege-disabled/canonical-same-access-restricted",
            same_access_restricted,
        ),
        invariants_valid,
    )
}

#[cfg(test)]
pub(crate) fn classify_loader_restriction_logon_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    no_restricting_sid: LoaderObjectSecurityOutcomeForTest,
    same_access_restricted: LoaderObjectSecurityOutcomeForTest,
    logon_restricted: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_restriction_logon_outcomes(
        &outcome("full-restricted", baseline),
        &outcome("privilege-disabled/no-restricting-SID", no_restricting_sid),
        &outcome(
            "privilege-disabled/canonical-same-access-restricted",
            same_access_restricted,
        ),
        &outcome(
            "privilege-disabled/target-logon-SID-restricted",
            logon_restricted,
        ),
        invariants_valid,
    )
}

#[cfg(test)]
pub(crate) fn classify_loader_restriction_authenticated_users_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    no_restricting_sid: LoaderObjectSecurityOutcomeForTest,
    same_access_restricted: LoaderObjectSecurityOutcomeForTest,
    logon_restricted: LoaderObjectSecurityOutcomeForTest,
    authenticated_users_restricted: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_restriction_authenticated_users_outcomes(
        &outcome("full-restricted", baseline),
        &outcome("privilege-disabled/no-restricting-SID", no_restricting_sid),
        &outcome(
            "privilege-disabled/canonical-same-access-restricted",
            same_access_restricted,
        ),
        &outcome(
            "privilege-disabled/target-logon-SID-restricted",
            logon_restricted,
        ),
        &outcome(
            "privilege-disabled/authenticated-users-SID-restricted",
            authenticated_users_restricted,
        ),
        invariants_valid,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn classify_loader_restriction_target_user_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    no_restricting_sid: LoaderObjectSecurityOutcomeForTest,
    same_access_restricted: LoaderObjectSecurityOutcomeForTest,
    logon_restricted: LoaderObjectSecurityOutcomeForTest,
    authenticated_users_restricted: LoaderObjectSecurityOutcomeForTest,
    target_user_restricted: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_restriction_target_user_outcomes(
        &outcome("full-restricted", baseline),
        &outcome("privilege-disabled/no-restricting-SID", no_restricting_sid),
        &outcome(
            "privilege-disabled/canonical-same-access-restricted",
            same_access_restricted,
        ),
        &outcome(
            "privilege-disabled/target-logon-SID-restricted",
            logon_restricted,
        ),
        &outcome(
            "privilege-disabled/authenticated-users-SID-restricted",
            authenticated_users_restricted,
        ),
        &outcome(
            "privilege-disabled/target-user-SID-restricted",
            target_user_restricted,
        ),
        invariants_valid,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_restriction_original_sext_reproduction_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    no_restricting_sid: LoaderObjectSecurityOutcomeForTest,
    same_access_restricted: LoaderObjectSecurityOutcomeForTest,
    logon_restricted: LoaderObjectSecurityOutcomeForTest,
    authenticated_users_restricted: LoaderObjectSecurityOutcomeForTest,
    target_user_restricted: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
) -> bool {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    loader_restriction_original_sext_reproduction_valid(
        &outcome("a", baseline),
        &outcome("b", no_restricting_sid),
        &outcome("c", same_access_restricted),
        &outcome("d", logon_restricted),
        &outcome("e", authenticated_users_restricted),
        &outcome("f", target_user_restricted),
        invariants_valid,
    )
}

#[cfg(test)]
pub(crate) fn classify_loader_full_observer_for_test(
    debug_c: LoaderObjectSecurityOutcomeForTest,
    debug_f: LoaderObjectSecurityOutcomeForTest,
    invariants_valid: bool,
    useful_frontier_differential: Option<bool>,
) -> &'static str {
    let outcome = |restriction, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: restriction,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: restriction,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    classify_loader_full_observer_pair(
        &outcome("canonical-same-access/full-observer-snaps-off", debug_c),
        &outcome("target-user-singleton/full-observer-snaps-off", debug_f),
        invariants_valid,
        useful_frontier_differential,
    )
}

#[cfg(test)]
pub(crate) fn loader_full_observer_fallback_gate_for_test(
    original_reproduction_valid: bool,
    setup: &super::access_trace::PassiveAccessLocalizationEvidenceV1,
) -> bool {
    original_reproduction_valid && setup.exact_session_start_access_denied()
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_full_observer_invariants_for_test(
    fallback_allowed: bool,
    original_reproduction_valid: bool,
    original_invariants_valid: bool,
    original_projection_exact: bool,
    debug_pair_common_exact: bool,
    debug_mode_exact: bool,
    debug_traces_admitted: bool,
    debug_containment_exact: bool,
    after_debug_c_stable: bool,
    after_debug_f_stable: bool,
    profile_stable: bool,
    environment_destroyed_once: bool,
) -> bool {
    loader_full_observer_invariants_valid(
        fallback_allowed,
        original_reproduction_valid,
        original_invariants_valid,
        original_projection_exact,
        debug_pair_common_exact,
        debug_mode_exact,
        debug_traces_admitted,
        debug_containment_exact,
        after_debug_c_stable,
        after_debug_f_stable,
        profile_stable,
        environment_destroyed_once,
    )
}

#[cfg(test)]
pub(crate) fn loader_full_observer_trace_admitted_for_test(detail: &str) -> bool {
    admit_loader_full_observer_trace(&Ok(detail.to_owned())).is_ok()
}

#[cfg(test)]
pub(crate) fn loader_full_observer_trace_admission_for_test(detail: &str) -> String {
    match admit_loader_full_observer_trace(&Ok(detail.to_owned())) {
        Ok(_) => "admitted".to_owned(),
        Err(rejection) => rejection.diagnostic(),
    }
}

#[cfg(test)]
pub(crate) fn loader_full_observer_candidate_tail_digest_for_test(serialized: &str) -> String {
    super::loader_debug::candidate_modules_tail_digest(serialized)
}

#[cfg(test)]
pub(crate) fn loader_full_observer_failed_invariants_for_test(
    values: [bool; 13],
) -> (bool, String) {
    let receipt = LoaderFullObserverInvariantReceiptV1::evaluated(
        values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7],
        values[8], values[9], values[10], values[11], values[12],
    );
    (receipt.valid(), receipt.failed_diagnostic())
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_trace_session_capability_gate_for_test(
    ephemeral_ci: bool,
    passive_setup_admitted: bool,
    original_reproduction_valid: bool,
    original_invariants_valid: bool,
    debug_c: LoaderObjectSecurityOutcomeForTest,
    debug_f: LoaderObjectSecurityOutcomeForTest,
    debug_c_detail: &str,
    debug_f_detail: &str,
    invariant_values: [bool; 13],
    after_debug_c_stable: bool,
    after_debug_f_stable: bool,
) -> bool {
    let outcome = |environment, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: super::record::digest(b"passed"),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: super::record::digest(b"failed"),
                detail: String::new(),
            }
        }
    };
    let debug_c = outcome("debug-c", debug_c);
    let debug_f = outcome("debug-f", debug_f);
    let Ok(debug_c_trace) = admit_loader_full_observer_trace(&Ok(debug_c_detail.to_owned())) else {
        return false;
    };
    let Ok(debug_f_trace) = admit_loader_full_observer_trace(&Ok(debug_f_detail.to_owned())) else {
        return false;
    };
    let frontier = loader_full_observer_module_frontier(&debug_c_trace, &debug_f_trace);
    let invariants = LoaderFullObserverInvariantReceiptV1::evaluated(
        invariant_values[0],
        invariant_values[1],
        invariant_values[2],
        invariant_values[3],
        invariant_values[4],
        invariant_values[5],
        invariant_values[6],
        invariant_values[7],
        invariant_values[8],
        invariant_values[9],
        invariant_values[10],
        invariant_values[11],
        invariant_values[12],
    );
    loader_trace_session_capability_allowed(
        ephemeral_ci,
        passive_setup_admitted,
        original_reproduction_valid,
        original_invariants_valid,
        &debug_c,
        &debug_f,
        &debug_c_trace,
        &debug_f_trace,
        &frontier,
        &invariants,
        after_debug_c_stable,
        after_debug_f_stable,
    )
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TraceSessionCapabilityTriggerMutationForTest {
    Pristine,
    RestrictionIdentity,
    LogonRestriction,
    AuthenticatedUsersRestriction,
    TargetUserRestriction,
    SharedEvidence,
    CellDetail,
}

#[cfg(test)]
pub(crate) fn loader_trace_session_capability_trigger_binding_for_test(
    debug_c_detail: &str,
    debug_f_detail: &str,
    mutation: TraceSessionCapabilityTriggerMutationForTest,
) -> Option<String> {
    let outcome =
        |environment: &'static str, seed: &'static [u8]| LoaderEnvironmentCanaryOutcomeV1 {
            environment,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: super::record::digest(seed),
            detail: String::new(),
        };
    let baseline = outcome("baseline", b"baseline");
    let comparison = outcome("comparison", b"comparison");
    let same_access = outcome("same-access", b"same-access");
    let logon = outcome("logon", b"logon");
    let authenticated_users = outcome("authenticated-users", b"authenticated-users");
    let mut target_user = outcome("target-user", b"target-user");
    if mutation == TraceSessionCapabilityTriggerMutationForTest::CellDetail {
        target_user.detail_sha256 = super::record::digest(b"changed-target-user-detail");
    }
    let debug_c = outcome("debug-c", b"debug-c");
    let debug_f = LoaderEnvironmentCanaryOutcomeV1 {
        environment: "debug-f",
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: Some(STATUS_ACCESS_DENIED),
        failure_phase: "post-resume-pre-loader-ready",
        detail_sha256: super::record::digest(b"debug-f"),
        detail: String::new(),
    };
    let debug_c_trace = admit_loader_full_observer_trace(&Ok(debug_c_detail.to_owned())).ok()?;
    let debug_f_trace = admit_loader_full_observer_trace(&Ok(debug_f_detail.to_owned())).ok()?;
    let frontier = loader_full_observer_module_frontier(&debug_c_trace, &debug_f_trace);
    let invariants = LoaderFullObserverInvariantReceiptV1::evaluated(
        true, true, true, true, true, true, true, true, true, true, true, true, true,
    );
    let after_debug_c = SharedEnvironmentObservationV1 {
        scan: "ok",
        metadata_match: true,
        detail_sha256: "none".to_owned(),
    };
    let after_debug_f = SharedEnvironmentObservationV1 {
        scan: "ok",
        metadata_match: true,
        detail_sha256: "none".to_owned(),
    };
    let changed = super::record::digest(b"changed-binding");
    let restriction_identity =
        if mutation == TraceSessionCapabilityTriggerMutationForTest::RestrictionIdentity {
            changed.clone()
        } else {
            super::record::digest(b"restriction-identity")
        };
    let logon_restriction =
        if mutation == TraceSessionCapabilityTriggerMutationForTest::LogonRestriction {
            changed.clone()
        } else {
            super::record::digest(b"logon-restriction")
        };
    let authenticated_users_restriction = if mutation
        == TraceSessionCapabilityTriggerMutationForTest::AuthenticatedUsersRestriction
    {
        changed.clone()
    } else {
        super::record::digest(b"authenticated-users-restriction")
    };
    let target_user_restriction =
        if mutation == TraceSessionCapabilityTriggerMutationForTest::TargetUserRestriction {
            changed.clone()
        } else {
            super::record::digest(b"target-user-restriction")
        };
    let shared_evidence =
        if mutation == TraceSessionCapabilityTriggerMutationForTest::SharedEvidence {
            changed
        } else {
            super::record::digest(b"shared-evidence")
        };
    loader_trace_session_capability_trigger_sha256(
        true,
        Some(&super::record::digest(b"passive-setup-denied")),
        true,
        true,
        &super::record::digest(b"source-binding"),
        &super::record::digest(b"pair-invariants"),
        &super::record::digest(b"restriction-presence"),
        &restriction_identity,
        &logon_restriction,
        &authenticated_users_restriction,
        &target_user_restriction,
        &super::record::digest(b"profile-binding"),
        &shared_evidence,
        &baseline,
        &comparison,
        &same_access,
        &logon,
        &authenticated_users,
        &target_user,
        &debug_c,
        &debug_f,
        &debug_c_trace,
        &debug_f_trace,
        &frontier,
        &invariants,
        &after_debug_c,
        &after_debug_f,
    )
}

#[cfg(test)]
pub(crate) fn loader_full_observer_debug_f_gate_for_test(
    fallback_allowed: bool,
    admitted: &[u16],
    after_debug_c: &[u16],
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let after_debug_c = user_environment_inventory_from_units(after_debug_c);
    let observation = shared_environment_observation(&admitted, &after_debug_c, "after-debug-c");
    Ok(loader_full_observer_debug_f_allowed(
        fallback_allowed,
        &observation,
    ))
}

#[cfg(test)]
pub(crate) fn render_loader_full_observer_canary_for_test(
    debug_c_detail: &str,
    debug_f_detail: &str,
    containment_valid: bool,
    job_empty: bool,
) -> String {
    let detail_hash = |label: &[u8], detail: &str| {
        let mut material = b"memcordon-loader-observer-perturbation-detail-v1\0".to_vec();
        material.extend_from_slice(label);
        material.extend_from_slice(detail.as_bytes());
        super::record::digest(&material)
    };
    let debug_c_result = Ok(debug_c_detail.to_owned());
    let debug_f_result = Ok(debug_f_detail.to_owned());
    let debug_c_trace = admit_loader_full_observer_trace(&debug_c_result);
    let debug_f_trace = admit_loader_full_observer_trace(&debug_f_result);
    let module_frontier = debug_c_trace
        .as_ref()
        .ok()
        .zip(debug_f_trace.as_ref().ok())
        .map(|(canonical, target)| loader_full_observer_module_frontier(canonical, target));
    let debug_c = LoaderEnvironmentCanaryOutcomeV1 {
        environment: "canonical-same-access/full-observer-snaps-off",
        outcome: LoaderControlMatrixOutcomeKindV6::Passed,
        native_status: None,
        failure_phase: "none",
        detail_sha256: String::new(),
        detail: String::new(),
    };
    let debug_f = LoaderEnvironmentCanaryOutcomeV1 {
        environment: "target-user-singleton/full-observer-snaps-off",
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: Some(STATUS_ACCESS_DENIED),
        failure_phase: "post-resume-pre-loader-ready",
        detail_sha256: String::new(),
        detail: String::new(),
    };
    let invariants = LoaderFullObserverInvariantReceiptV1::evaluated(
        true,
        true,
        true,
        true,
        true,
        true,
        debug_c_trace.is_ok(),
        debug_f_trace.is_ok(),
        containment_valid,
        true,
        true,
        true,
        true,
    );
    let invariants_valid = invariants.valid();
    let state = classify_loader_full_observer_pair(
        &debug_c,
        &debug_f,
        invariants_valid,
        module_frontier.as_ref().map(|frontier| frontier.useful),
    );
    let observation = SharedEnvironmentObservationV1 {
        scan: "ok",
        metadata_match: true,
        detail_sha256: "none".to_owned(),
    };
    render_loader_full_observer_diagnostic(
        state,
        &debug_c,
        Some(&debug_f),
        &detail_hash(b"debug-c", debug_c_detail),
        Some(&detail_hash(b"debug-f", debug_f_detail)),
        &debug_c_trace,
        Some(&debug_f_trace),
        module_frontier.as_ref(),
        &observation,
        Some(&observation),
        true,
        true,
        &invariants,
        job_empty,
    )
}

#[cfg(test)]
pub(crate) fn render_loader_restriction_presence_canary_for_test(
    state: &str,
    primary_detail: &str,
    comparison_detail: &str,
    same_access_detail: &str,
) -> String {
    format!(
        "loader_restriction_presence_prerequisite_canary=v2 state={state} presence_state=restricting-sid-presence-causal baseline_semantics=full-restricted comparison_semantics=privilege-disabled/no-restricting-SID same_access_semantics=privilege-disabled/canonical-same-access-restricted differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids] failed_common_fields=[] restriction_identity_binding_sha256={} shared_environment_sha256={} shared_environment_keys_sha256={} shared_environment_units=4 shared_environment_entries=1 shared_environment_profile_loaded=true after_baseline_scan=ok after_baseline_metadata_match=true after_baseline_observation_sha256=none after_comparison_scan=ok after_comparison_metadata_match=true after_comparison_observation_sha256=none shared_environment_scan=ok shared_environment_metadata_match=true shared_environment_observation_sha256=none shared_environment_stable=true shared_environment_destroyed=true primary_sha256={} comparison_sha256={} same_access_sha256={} environment_values_redacted=true token_values_redacted=true job_empty=true workload_executed=false qualification_promoted=false",
        super::record::digest(b"test-restriction-identity-binding"),
        super::record::digest(b"test-shared-environment"),
        super::record::digest(b"test-shared-environment-keys"),
        super::record::digest(primary_detail.as_bytes()),
        super::record::digest(comparison_detail.as_bytes()),
        super::record::digest(same_access_detail.as_bytes()),
    )
}

#[cfg(test)]
pub(crate) fn render_loader_restriction_logon_canary_for_test(
    state: &str,
    primary_detail: &str,
    comparison_detail: &str,
    same_access_detail: &str,
    logon_detail: &str,
) -> String {
    format!(
        "loader_restriction_presence_prerequisite_canary=v2 state={state} presence_state=restricting-sid-presence-causal identity_state=restricted-code-sid-narrowing-causal baseline_semantics=full-restricted comparison_semantics=privilege-disabled/no-restricting-SID same_access_semantics=privilege-disabled/canonical-same-access-restricted logon_semantics=privilege-disabled/target-logon-SID-restricted differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids] failed_common_fields=[] restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} shared_environment_sha256={} shared_environment_keys_sha256={} shared_environment_units=4 shared_environment_entries=1 shared_environment_profile_loaded=true after_baseline_scan=ok after_baseline_metadata_match=true after_baseline_observation_sha256=none after_comparison_scan=ok after_comparison_metadata_match=true after_comparison_observation_sha256=none after_same_access_scan=ok after_same_access_metadata_match=true after_same_access_observation_sha256=none after_logon_scan=ok after_logon_metadata_match=true after_logon_observation_sha256=none shared_environment_scan=ok shared_environment_metadata_match=true shared_environment_observation_sha256=none shared_environment_stable=true shared_environment_destroyed=true primary_sha256={} comparison_sha256={} same_access_sha256={} logon_sha256={} environment_values_redacted=true token_values_redacted=true job_empty=true workload_executed=false qualification_promoted=false",
        super::record::digest(b"test-restriction-identity-binding"),
        super::record::digest(b"test-logon-restriction-binding"),
        super::record::digest(b"test-shared-environment"),
        super::record::digest(b"test-shared-environment-keys"),
        super::record::digest(primary_detail.as_bytes()),
        super::record::digest(comparison_detail.as_bytes()),
        super::record::digest(same_access_detail.as_bytes()),
        super::record::digest(logon_detail.as_bytes()),
    )
}

#[cfg(test)]
pub(crate) fn render_loader_restriction_authenticated_users_canary_for_test(
    state: &str,
    primary_detail: &str,
    comparison_detail: &str,
    same_access_detail: &str,
    logon_detail: &str,
    authenticated_users_detail: &str,
) -> String {
    format!(
        "loader_restriction_presence_prerequisite_canary=v2 state={state} presence_state=restricting-sid-presence-causal identity_state=restricted-code-sid-narrowing-causal logon_state=differing-inconclusive baseline_semantics=full-restricted comparison_semantics=privilege-disabled/no-restricting-SID same_access_semantics=privilege-disabled/canonical-same-access-restricted logon_semantics=privilege-disabled/target-logon-SID-restricted authenticated_users_semantics=privilege-disabled/authenticated-users-SID-restricted differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids] failed_common_fields=[] restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} authenticated_users_restriction_binding_sha256={} shared_environment_sha256={} shared_environment_keys_sha256={} shared_environment_units=4 shared_environment_entries=1 shared_environment_profile_loaded=true after_baseline_scan=ok after_baseline_metadata_match=true after_baseline_observation_sha256=none after_comparison_scan=ok after_comparison_metadata_match=true after_comparison_observation_sha256=none after_same_access_scan=ok after_same_access_metadata_match=true after_same_access_observation_sha256=none after_logon_scan=ok after_logon_metadata_match=true after_logon_observation_sha256=none after_authenticated_users_scan=ok after_authenticated_users_metadata_match=true after_authenticated_users_observation_sha256=none shared_environment_scan=ok shared_environment_metadata_match=true shared_environment_observation_sha256=none shared_environment_stable=true shared_environment_destroyed=true primary_sha256={} comparison_sha256={} same_access_sha256={} logon_sha256={} authenticated_users_sha256={} environment_values_redacted=true token_values_redacted=true job_empty=true workload_executed=false qualification_promoted=false",
        super::record::digest(b"test-restriction-identity-binding"),
        super::record::digest(b"test-logon-restriction-binding"),
        super::record::digest(b"test-authenticated-users-restriction-binding"),
        super::record::digest(b"test-shared-environment"),
        super::record::digest(b"test-shared-environment-keys"),
        super::record::digest(primary_detail.as_bytes()),
        super::record::digest(comparison_detail.as_bytes()),
        super::record::digest(same_access_detail.as_bytes()),
        super::record::digest(logon_detail.as_bytes()),
        super::record::digest(authenticated_users_detail.as_bytes()),
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn render_loader_restriction_target_user_canary_for_test(
    state: &str,
    primary_detail: &str,
    comparison_detail: &str,
    same_access_detail: &str,
    logon_detail: &str,
    authenticated_users_detail: &str,
    target_user_detail: &str,
) -> String {
    format!(
        "loader_restriction_presence_prerequisite_canary=v2 state={state} presence_state=restricting-sid-presence-causal identity_state=restricted-code-sid-narrowing-causal logon_state=differing-inconclusive authenticated_users_state=canonical-group-union-or-other-trustee-required baseline_semantics=full-restricted comparison_semantics=privilege-disabled/no-restricting-SID same_access_semantics=privilege-disabled/canonical-same-access-restricted logon_semantics=privilege-disabled/target-logon-SID-restricted authenticated_users_semantics=privilege-disabled/authenticated-users-SID-restricted target_user_semantics=privilege-disabled/target-user-SID-restricted differing_fields=[restricting_sid_inventory,token_is_restricted,token_instance_ids] failed_common_fields=[] restriction_identity_binding_sha256={} logon_restriction_binding_sha256={} authenticated_users_restriction_binding_sha256={} target_user_restriction_binding_sha256={} shared_environment_sha256={} shared_environment_keys_sha256={} shared_environment_units=4 shared_environment_entries=1 shared_environment_profile_loaded=true after_baseline_scan=ok after_baseline_metadata_match=true after_baseline_observation_sha256=none after_comparison_scan=ok after_comparison_metadata_match=true after_comparison_observation_sha256=none after_same_access_scan=ok after_same_access_metadata_match=true after_same_access_observation_sha256=none after_logon_scan=ok after_logon_metadata_match=true after_logon_observation_sha256=none after_authenticated_users_scan=ok after_authenticated_users_metadata_match=true after_authenticated_users_observation_sha256=none after_target_user_scan=ok after_target_user_metadata_match=true after_target_user_observation_sha256=none shared_environment_scan=ok shared_environment_metadata_match=true shared_environment_observation_sha256=none shared_environment_stable=true shared_environment_destroyed=true primary_sha256={} comparison_sha256={} same_access_sha256={} logon_sha256={} authenticated_users_sha256={} target_user_sha256={} environment_values_redacted=true token_values_redacted=true job_empty=true workload_executed=false qualification_promoted=false",
        super::record::digest(b"test-restriction-identity-binding"),
        super::record::digest(b"test-logon-restriction-binding"),
        super::record::digest(b"test-authenticated-users-restriction-binding"),
        super::record::digest(b"test-target-user-restriction-binding"),
        super::record::digest(b"test-shared-environment"),
        super::record::digest(b"test-shared-environment-keys"),
        super::record::digest(primary_detail.as_bytes()),
        super::record::digest(comparison_detail.as_bytes()),
        super::record::digest(same_access_detail.as_bytes()),
        super::record::digest(logon_detail.as_bytes()),
        super::record::digest(authenticated_users_detail.as_bytes()),
        super::record::digest(target_user_detail.as_bytes()),
    )
}

#[cfg(test)]
pub(crate) fn loader_object_security_authority_labels_for_test() -> [&'static str; 4] {
    [
        LoaderObjectSecurityAuthorityV1::LauncherExplicit.diagnostic(),
        LoaderObjectSecurityAuthorityV1::TargetAwareProcess.diagnostic(),
        LoaderObjectSecurityAuthorityV1::TargetAwareThread.diagnostic(),
        LoaderObjectSecurityAuthorityV1::TargetAwareBoth.diagnostic(),
    ]
}

#[cfg(test)]
pub(crate) fn classify_loader_object_security_for_test(
    baseline: LoaderObjectSecurityOutcomeForTest,
    process: LoaderObjectSecurityOutcomeForTest,
    thread: LoaderObjectSecurityOutcomeForTest,
    combined: Option<LoaderObjectSecurityOutcomeForTest>,
    evidence_valid: bool,
) -> &'static str {
    let outcome = |authority, value| match value {
        LoaderObjectSecurityOutcomeForTest::Passed => LoaderEnvironmentCanaryOutcomeV1 {
            environment: authority,
            outcome: LoaderControlMatrixOutcomeKindV6::Passed,
            native_status: None,
            failure_phase: "none",
            detail_sha256: String::new(),
            detail: String::new(),
        },
        LoaderObjectSecurityOutcomeForTest::Failed { native, phase } => {
            LoaderEnvironmentCanaryOutcomeV1 {
                environment: authority,
                outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                native_status: Some(native),
                failure_phase: phase,
                detail_sha256: String::new(),
                detail: String::new(),
            }
        }
    };
    let baseline = outcome("baseline", baseline);
    let process = outcome("process", process);
    let thread = outcome("thread", thread);
    let combined = combined.map(|value| outcome("combined", value));
    classify_loader_object_security_outcomes(
        &baseline,
        &process,
        &thread,
        combined.as_ref(),
        evidence_valid,
    )
}

#[cfg(test)]
pub(crate) fn loader_object_security_gate_for_test(
    profile_state: &str,
    baseline_native: Option<i32>,
    comparison_native: Option<i32>,
    same_phase: bool,
) -> bool {
    let baseline = LoaderEnvironmentCanaryOutcomeV1 {
        environment: "baseline",
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: baseline_native,
        failure_phase: "baseline-phase",
        detail_sha256: String::new(),
        detail: String::new(),
    };
    let comparison = LoaderEnvironmentCanaryOutcomeV1 {
        environment: "comparison",
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: comparison_native,
        failure_phase: if same_phase {
            "baseline-phase"
        } else {
            "other-phase"
        },
        detail_sha256: String::new(),
        detail: String::new(),
    };
    loader_object_security_required(profile_state, &baseline, Some(&comparison))
}

#[cfg(test)]
pub(crate) struct LoaderObjectSecurityEvidenceValidityForTest {
    pub common_evidence_valid: bool,
    pub descriptor_evidence_present: bool,
    pub invariants_valid: bool,
    pub invariant_error: Option<String>,
}

#[cfg(test)]
pub(crate) fn loader_object_security_evidence_validity_for_test(
    baseline_detail: &str,
    comparison_details: &[&str],
    profile_stable: bool,
    authority_binding_valid: bool,
) -> LoaderObjectSecurityEvidenceValidityForTest {
    let baseline = Ok(baseline_detail.to_owned());
    let comparisons = comparison_details
        .iter()
        .map(|detail| Ok((*detail).to_owned()))
        .collect::<Vec<Result<String, TargetDesktopLeaseCreateError>>>();
    let results = std::iter::once(&baseline)
        .chain(comparisons.iter())
        .collect::<Vec<_>>();
    let evidence =
        loader_object_security_evidence_validity(&results, profile_stable, authority_binding_valid);
    LoaderObjectSecurityEvidenceValidityForTest {
        common_evidence_valid: evidence.common_evidence_valid,
        descriptor_evidence_present: evidence.descriptor_evidence_present,
        invariants_valid: evidence.invariants_valid,
        invariant_error: evidence.invariant_error,
    }
}

#[cfg(test)]
pub(crate) fn render_loader_object_security_canary_for_test(
    state: &str,
    primary_detail: &str,
    comparison_detail: &str,
) -> String {
    format!(
        "loader_object_security_prerequisite_canary=v1 state={state} primary_sha256={} comparison_sha256={} object_security_values_redacted=true workload_executed=false qualification_promoted=false",
        super::record::digest(primary_detail.as_bytes()),
        super::record::digest(comparison_detail.as_bytes()),
    )
}

fn preserve_loader_profile_primary_detail(primary: &str, cleanup: &[String]) -> String {
    if cleanup.is_empty() {
        primary.to_owned()
    } else {
        format!("{primary} profile_child_cleanup=[{}]", cleanup.join(","))
    }
}

pub(crate) fn preserve_loader_profile_primary_for_test(
    primary: &str,
    cleanup_error: Option<&str>,
) -> String {
    let cleanup = cleanup_error
        .map(|error| {
            vec![format!(
                "cleanup_error_sha256={}",
                super::record::digest(error.as_bytes())
            )]
        })
        .unwrap_or_default();
    preserve_loader_profile_primary_detail(primary, &cleanup)
}

pub(crate) fn render_loader_profile_canary_for_test(
    state: &str,
    before_state: LoaderProfileHiveStateV1,
    after_state: LoaderProfileHiveStateV1,
    primary_detail: &str,
    comparison_detail: &str,
    cleanup_detail: &str,
) -> String {
    let outcome = |environment, detail: &str| LoaderEnvironmentCanaryOutcomeV1 {
        environment,
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: Some(STATUS_DLL_INIT_FAILED),
        failure_phase: "pre-initial-breakpoint-static-loader",
        detail_sha256: super::record::digest(detail.as_bytes()),
        detail: String::new(),
    };
    let before = LoaderProfileObservationV1 {
        state: before_state,
        profile_directory_sha256: super::record::digest(b"before-profile-directory"),
        profile_directory_exists: true,
    };
    let after = LoaderProfileObservationV1 {
        state: after_state,
        profile_directory_sha256: super::record::digest(b"after-profile-directory"),
        profile_directory_exists: true,
    };
    render_loader_profile_prerequisite_canary(
        state,
        &outcome("target-token-userenv-v1", primary_detail),
        Some(&outcome(
            "target-token-userenv-profile-v1",
            comparison_detail,
        )),
        &before,
        &after,
        &super::record::digest(b"profile-binding"),
        &[format!(
            "cleanup_detail_sha256={}",
            super::record::digest(cleanup_detail.as_bytes())
        )],
    )
}

fn render_loader_environment_prerequisite_canary(
    state: &str,
    baseline_outcome: &LoaderEnvironmentCanaryOutcomeV1,
    comparison_outcome: &LoaderEnvironmentCanaryOutcomeV1,
    source_binding_sha256: &str,
    pair_invariants_sha256: &str,
    target_token_instance_sha256: &str,
    baseline_environment_sha256: &str,
    comparison_environment_sha256: &str,
    comparison_environment_keys_sha256: &str,
    comparison_environment_units: &str,
    comparison_environment_entries: &str,
    common: &str,
    invariant_error: &str,
) -> String {
    format!(
        "loader_environment_prerequisite_canary=v1 state={state} baseline_environment=canonical-minimal-system comparison_environment=target-token-userenv-v1 differing_fields=[environment] baseline=[{}] comparison=[{}] source_binding_sha256={} pair_invariants_sha256={} target_token_instance_sha256={} baseline_environment_sha256={} comparison_environment_sha256={} comparison_environment_keys_sha256={} comparison_environment_units={} comparison_environment_entries={} profile_loaded=false {} process_sddl_sha256={} thread_sddl_sha256={} job_policy_sha256={} invariant_error={} workload_executed=false qualification_promoted=false",
        baseline_outcome.diagnostic(),
        comparison_outcome.diagnostic(),
        source_binding_sha256,
        pair_invariants_sha256,
        target_token_instance_sha256,
        baseline_environment_sha256,
        comparison_environment_sha256,
        comparison_environment_keys_sha256,
        comparison_environment_units,
        comparison_environment_entries,
        common,
        super::security::launcher_process_sddl()
            .map(|sddl| super::record::digest(sddl.as_bytes()))
            .unwrap_or_else(|error| super::record::digest(error.as_bytes())),
        super::security::launcher_thread_sddl()
            .map(|sddl| super::record::digest(sddl.as_bytes()))
            .unwrap_or_else(|error| super::record::digest(error.as_bytes())),
        super::record::digest(b"Job::create(None,None,None)+PROC_THREAD_ATTRIBUTE_JOB_LIST"),
        invariant_error,
    )
}

#[cfg(test)]
pub(crate) fn render_loader_environment_prerequisite_canary_for_test(
    baseline_environment_sha256: &str,
    comparison_environment_sha256: &str,
    comparison_environment_keys_sha256: &str,
    comparison_environment_units: usize,
    comparison_environment_entries: usize,
) -> String {
    let outcome = |environment| LoaderEnvironmentCanaryOutcomeV1 {
        environment,
        outcome: LoaderControlMatrixOutcomeKindV6::Failed,
        native_status: Some(STATUS_DLL_INIT_FAILED),
        failure_phase: "pre-initial-breakpoint-static-loader",
        detail_sha256: super::record::digest(b"bounded-redacted-loader-detail"),
        detail: "redacted".to_owned(),
    };
    render_loader_environment_prerequisite_canary(
        "classified-common-failure",
        &outcome("canonical-minimal-system"),
        &outcome("target-token-userenv-v1"),
        &super::record::digest(b"test-source-binding"),
        &super::record::digest(b"test-pair-binding"),
        &super::record::digest(b"test-target-token-instance"),
        baseline_environment_sha256,
        comparison_environment_sha256,
        comparison_environment_keys_sha256,
        &comparison_environment_units.to_string(),
        &comparison_environment_entries.to_string(),
        "matrix_cell=canonical-minimal-system-none-snaps-off debug_mode=false creation_flags=0x00080404",
        "none",
    )
}

struct LoaderEnvironmentBlockV4 {
    units: Vec<u16>,
    classification: &'static str,
    sha256: String,
    keys: Vec<String>,
    missing_required: Vec<String>,
}

struct SystemEnvironmentBlock(*mut c_void);

impl Drop for SystemEnvironmentBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: CreateEnvironmentBlock returned this owned allocation and it is released
            // exactly once after its bounded contents have been copied.
            unsafe { DestroyEnvironmentBlock(self.0) };
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoaderProfileHiveStateV1 {
    AlreadyLoadedBorrowed,
    Absent,
    AccessDenied,
    QueryFailed(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoaderProfileLifecycleEventV1 {
    ObservedBefore,
    ProfileLoaded,
    EnvironmentCreated,
    ProcessCompleted,
    EnvironmentDestroyed,
    JobEmpty,
    ProfileUnloaded,
    ObservedAfter,
}

fn classify_loader_profile_observations(
    before: LoaderProfileHiveStateV1,
    loaded: Option<LoaderProfileHiveStateV1>,
    after: LoaderProfileHiveStateV1,
    unload_ok: bool,
) -> &'static str {
    match (before, loaded, after, unload_ok) {
        (
            LoaderProfileHiveStateV1::AlreadyLoadedBorrowed,
            None,
            LoaderProfileHiveStateV1::AlreadyLoadedBorrowed,
            true,
        ) => "classified-borrowed-stable",
        (
            LoaderProfileHiveStateV1::Absent,
            Some(LoaderProfileHiveStateV1::AlreadyLoadedBorrowed),
            LoaderProfileHiveStateV1::Absent,
            true,
        ) => "classified-owned-loaded-unloaded",
        (LoaderProfileHiveStateV1::AccessDenied, _, _, _)
        | (LoaderProfileHiveStateV1::QueryFailed(_), _, _, _) => "invalid-profile-observation",
        (LoaderProfileHiveStateV1::AlreadyLoadedBorrowed, _, _, _) => {
            "invalid-unstable-borrowed-profile"
        }
        (LoaderProfileHiveStateV1::Absent, Some(_), _, _) => "invalid-owned-profile-cleanup",
        (LoaderProfileHiveStateV1::Absent, None, _, _) => "invalid-load-not-observed",
    }
}

pub(crate) fn classify_loader_profile_observations_for_test(
    before: LoaderProfileHiveStateV1,
    loaded: Option<LoaderProfileHiveStateV1>,
    after: LoaderProfileHiveStateV1,
    unload_ok: bool,
) -> &'static str {
    classify_loader_profile_observations(before, loaded, after, unload_ok)
}

fn loader_profile_lifecycle_is_valid(
    events: &[LoaderProfileLifecycleEventV1],
    borrowed: bool,
) -> bool {
    let expected_borrowed = [
        LoaderProfileLifecycleEventV1::ObservedBefore,
        LoaderProfileLifecycleEventV1::EnvironmentCreated,
        LoaderProfileLifecycleEventV1::EnvironmentDestroyed,
        LoaderProfileLifecycleEventV1::ProcessCompleted,
        LoaderProfileLifecycleEventV1::JobEmpty,
        LoaderProfileLifecycleEventV1::ObservedAfter,
    ];
    let expected_owned = [
        LoaderProfileLifecycleEventV1::ObservedBefore,
        LoaderProfileLifecycleEventV1::ProfileLoaded,
        LoaderProfileLifecycleEventV1::EnvironmentCreated,
        LoaderProfileLifecycleEventV1::EnvironmentDestroyed,
        LoaderProfileLifecycleEventV1::ProcessCompleted,
        LoaderProfileLifecycleEventV1::JobEmpty,
        LoaderProfileLifecycleEventV1::ProfileUnloaded,
        LoaderProfileLifecycleEventV1::ObservedAfter,
    ];
    events
        == if borrowed {
            expected_borrowed.as_slice()
        } else {
            expected_owned.as_slice()
        }
}

pub(crate) fn loader_profile_lifecycle_valid_for_test(
    events: &[LoaderProfileLifecycleEventV1],
    borrowed: bool,
) -> bool {
    loader_profile_lifecycle_is_valid(events, borrowed)
}

impl LoaderProfileHiveStateV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::AlreadyLoadedBorrowed => "already-loaded-borrowed",
            Self::Absent => "absent",
            Self::AccessDenied => "access-denied",
            Self::QueryFailed(_) => "query-failed",
        }
    }

    const fn native_code(self) -> Option<u32> {
        match self {
            Self::QueryFailed(code) => Some(code),
            Self::AccessDenied => Some(ERROR_ACCESS_DENIED),
            Self::AlreadyLoadedBorrowed | Self::Absent => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoaderProfileObservationV1 {
    state: LoaderProfileHiveStateV1,
    profile_directory_sha256: String,
    profile_directory_exists: bool,
}

fn loader_profile_directory(token: HANDLE) -> Result<(String, bool), String> {
    let mut chars = 0_u32;
    unsafe { GetUserProfileDirectoryW(token, ptr::null_mut(), &raw mut chars) };
    if chars == 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(format!(
            "profile directory size query failed: {}",
            io::Error::last_os_error()
        ));
    }
    let mut path = vec![0_u16; chars as usize];
    if unsafe { GetUserProfileDirectoryW(token, path.as_mut_ptr(), &raw mut chars) } == 0 {
        return Err(format!(
            "profile directory query failed: {}",
            io::Error::last_os_error()
        ));
    }
    path.truncate(chars as usize);
    if path.last() == Some(&0) {
        path.pop();
    }
    use std::os::windows::ffi::OsStringExt;
    let filesystem_path = PathBuf::from(std::ffi::OsString::from_wide(&path));
    let path_bytes = path
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    Ok((super::record::digest(&path_bytes), filesystem_path.is_dir()))
}

fn observe_loader_profile(
    token: HANDLE,
    authenticated_user_sid: &str,
) -> LoaderProfileObservationV1 {
    let (profile_directory_sha256, profile_directory_exists) = match loader_profile_directory(token)
    {
        Ok(observation) => observation,
        Err(error) => {
            return LoaderProfileObservationV1 {
                state: LoaderProfileHiveStateV1::QueryFailed(
                    io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or_default() as u32,
                ),
                profile_directory_sha256: super::record::digest(error.as_bytes()),
                profile_directory_exists: false,
            };
        }
    };
    let key_name = super::pipe::wide_null(authenticated_user_sid);
    let mut key: HKEY = ptr::null_mut();
    let status = unsafe { RegOpenKeyExW(HKEY_USERS, key_name.as_ptr(), 0, KEY_READ, &raw mut key) };
    let state = if status == 0 {
        unsafe { RegCloseKey(key) };
        LoaderProfileHiveStateV1::AlreadyLoadedBorrowed
    } else if matches!(status, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
        LoaderProfileHiveStateV1::Absent
    } else if status == ERROR_ACCESS_DENIED {
        LoaderProfileHiveStateV1::AccessDenied
    } else {
        LoaderProfileHiveStateV1::QueryFailed(status)
    };
    LoaderProfileObservationV1 {
        state,
        profile_directory_sha256,
        profile_directory_exists,
    }
}

struct LocalProfileSid(*mut c_void);

impl Drop for LocalProfileSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
        }
    }
}

fn resolve_loader_profile_account_name(user_sid: &str) -> Result<(Vec<u16>, String), String> {
    let wide_sid = super::pipe::wide_null(user_sid);
    let mut raw_sid = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide_sid.as_ptr(), &raw mut raw_sid) } == 0 {
        return Err(format!(
            "profile SID conversion failed: {}",
            io::Error::last_os_error()
        ));
    }
    let sid = LocalProfileSid(raw_sid);
    let mut name_chars = 0_u32;
    let mut domain_chars = 0_u32;
    let mut use_kind: SID_NAME_USE = 0;
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.0,
            ptr::null_mut(),
            &raw mut name_chars,
            ptr::null_mut(),
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    };
    if name_chars == 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(format!(
            "profile account size query failed: {}",
            io::Error::last_os_error()
        ));
    }
    let mut name = vec![0_u16; name_chars as usize];
    let mut domain = vec![0_u16; domain_chars as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid.0,
            name.as_mut_ptr(),
            &raw mut name_chars,
            domain.as_mut_ptr(),
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    } == 0
        || use_kind != SidTypeUser
    {
        return Err("profile account resolution failed or was not a user SID".to_owned());
    }
    name.truncate(name_chars as usize);
    domain.truncate(domain_chars as usize);
    if name.last() == Some(&0) {
        name.pop();
    }
    if domain.last() == Some(&0) {
        domain.pop();
    }
    let mut qualified = domain;
    if !qualified.is_empty() {
        qualified.push('\\' as u16);
    }
    qualified.extend_from_slice(&name);
    qualified.push(0);
    let mut sid_bytes = 0_u32;
    let mut roundtrip_domain_chars = 0_u32;
    let mut roundtrip_use: SID_NAME_USE = 0;
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            qualified.as_ptr(),
            ptr::null_mut(),
            &raw mut sid_bytes,
            ptr::null_mut(),
            &raw mut roundtrip_domain_chars,
            &raw mut roundtrip_use,
        )
    };
    if sid_bytes == 0
        || unsafe { windows_sys::Win32::Foundation::GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err("profile account round-trip size query failed".to_owned());
    }
    let mut roundtrip_sid = vec![0_u32; (sid_bytes as usize).div_ceil(4)];
    let mut roundtrip_domain = vec![0_u16; roundtrip_domain_chars as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            qualified.as_ptr(),
            roundtrip_sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
            roundtrip_domain.as_mut_ptr(),
            &raw mut roundtrip_domain_chars,
            &raw mut roundtrip_use,
        )
    } == 0
        || roundtrip_use != SidTypeUser
        || unsafe { EqualSid(sid.0, roundtrip_sid.as_mut_ptr().cast()) } == 0
    {
        return Err("profile account did not round-trip to the authenticated SID".to_owned());
    }
    let qualified_bytes = qualified
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    name.push(0);
    Ok((name, super::record::digest(&qualified_bytes)))
}

struct TargetUserProfileLease {
    token: OwnedHandle,
    profile: HANDLE,
    account_binding_sha256: String,
    profile_directory_sha256: String,
    active: bool,
}

impl TargetUserProfileLease {
    fn acquire(profile_capability: HANDLE, authenticated_user_sid: &str) -> Result<Self, String> {
        const PROFILE_ACCESS: u32 = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE;
        let token = duplicate_local_handle_with_access(
            profile_capability,
            PROFILE_ACCESS,
            PROFILE_ACCESS,
            "loader-profile-capability-lease",
        )?;
        let (mut user_name, account_binding_sha256) =
            resolve_loader_profile_account_name(authenticated_user_sid)?;
        let (profile_directory_sha256, _) = loader_profile_directory(token.raw())?;
        let mut profile = ProfileInfoW {
            size: std::mem::size_of::<ProfileInfoW>() as u32,
            flags: 1,
            user_name: user_name.as_mut_ptr(),
            profile_path: ptr::null_mut(),
            default_path: ptr::null_mut(),
            server_name: ptr::null_mut(),
            policy_path: ptr::null_mut(),
            profile: ptr::null_mut(),
        };
        super::token::with_scoped_loader_profile_privileges(|| {
            if unsafe { LoadUserProfileW(token.raw(), &raw mut profile) } == 0 {
                Err(format!(
                    "LoadUserProfileW failed: {}",
                    io::Error::last_os_error()
                ))
            } else {
                Ok(())
            }
        })?;
        if profile.profile.is_null() {
            return Err("LoadUserProfileW returned an empty profile authority".to_owned());
        }
        Ok(Self {
            token,
            profile: profile.profile,
            account_binding_sha256,
            profile_directory_sha256,
            active: true,
        })
    }

    fn unload(mut self) -> Result<String, String> {
        let result = super::token::with_scoped_loader_profile_privileges(|| {
            if unsafe { UnloadUserProfile(self.token.raw(), self.profile) } == 0 {
                Err(format!(
                    "UnloadUserProfile failed: {}",
                    io::Error::last_os_error()
                ))
            } else {
                Ok(())
            }
        });
        self.active = false;
        result.map(|()| {
            format!(
                "owned-unloaded account_binding_sha256={} profile_directory_sha256={}",
                self.account_binding_sha256, self.profile_directory_sha256
            )
        })
    }
}

impl Drop for TargetUserProfileLease {
    fn drop(&mut self) {
        if self.active {
            eprintln!(
                "MCSEALED-WINDOWS-LOADER-PROFILE-RETAINED: owned profile lease dropped before UnloadUserProfile"
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderEnvironmentAuthorityV5 {
    MatrixProjection,
    TargetTokenUserenv,
    TargetTokenUserenvBorrowedProfile,
    TargetTokenUserenvProfileLease,
}

enum LoaderCellEnvironmentSourceV6<'a> {
    Create(LoaderEnvironmentAuthorityV5),
    BorrowedUserenv {
        block: &'a mut OwnedUserEnvironmentBlock,
        inventory: UserEnvironmentInventoryV1,
    },
}

impl<'a> LoaderCellEnvironmentSourceV6<'a> {
    const fn authority(&self) -> LoaderEnvironmentAuthorityV5 {
        match self {
            Self::Create(authority) => *authority,
            Self::BorrowedUserenv { .. } => {
                LoaderEnvironmentAuthorityV5::TargetTokenUserenvBorrowedProfile
            }
        }
    }

    fn into_environment(
        self,
        target_token: HANDLE,
        matrix_mode: LoaderEnvironmentModeV4,
    ) -> Result<LoaderLaunchEnvironmentV5<'a>, TargetDesktopLeaseCreateError> {
        match self {
            Self::Create(authority) => {
                LoaderLaunchEnvironmentV5::create(target_token, matrix_mode, authority)
            }
            Self::BorrowedUserenv { block, inventory } => Ok(
                LoaderLaunchEnvironmentV5::borrowed_userenv(block, &inventory),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoaderObjectSecurityAuthorityV1 {
    LauncherExplicit,
    LauncherExplicitRestrictingSidCanary,
    TargetAwareProcess,
    TargetAwareThread,
    TargetAwareBoth,
}

impl LoaderObjectSecurityAuthorityV1 {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::LauncherExplicit => "launcher-explicit-v1",
            Self::LauncherExplicitRestrictingSidCanary => "launcher-explicit-v1",
            Self::TargetAwareProcess => "target-aware-process-v1",
            Self::TargetAwareThread => "target-aware-thread-v1",
            Self::TargetAwareBoth => "target-aware-both-v1",
        }
    }

    const fn uses_target_policy(self) -> bool {
        matches!(
            self,
            Self::TargetAwareProcess | Self::TargetAwareThread | Self::TargetAwareBoth
        )
    }

    const fn diagnostic_only(self) -> bool {
        !matches!(self, Self::LauncherExplicit)
    }
}

struct OwnedUserEnvironmentBlock {
    raw: *mut c_void,
    units: usize,
    entries: usize,
    sha256: String,
    keys_sha256: String,
    missing_required: Vec<String>,
}

impl OwnedUserEnvironmentBlock {
    fn create(target_token: HANDLE) -> Result<Self, TargetDesktopLeaseCreateError> {
        let mut raw = ptr::null_mut();
        // SAFETY: target_token is the exact live authenticated primary token, inherit is FALSE,
        // and ownership of a successful allocation transfers to this RAII object.
        if unsafe { CreateEnvironmentBlock(&raw mut raw, target_token, 0) } == 0 {
            return Err(format!(
                "target-token environment creation failed: {}",
                io::Error::last_os_error()
            )
            .into());
        }
        if raw.is_null() {
            return Err("target-token environment creation returned a null block"
                .to_owned()
                .into());
        }
        let mut block = Self {
            raw,
            units: 0,
            entries: 0,
            sha256: String::new(),
            keys_sha256: String::new(),
            missing_required: Vec::new(),
        };
        let inventory = bounded_user_environment_inventory(block.raw)?;
        block.units = inventory.units;
        block.entries = inventory.entries;
        block.sha256 = inventory.sha256;
        block.keys_sha256 = inventory.keys_sha256;
        block.missing_required = inventory.missing_required;
        Ok(block)
    }

    fn pointer(&mut self) -> *mut c_void {
        self.raw
    }

    fn inventory(&self) -> Result<UserEnvironmentInventoryV1, TargetDesktopLeaseCreateError> {
        bounded_user_environment_inventory(self.raw)
    }

    fn destroy_after_create(&mut self) -> Result<(), TargetDesktopLeaseCreateError> {
        let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
        if raw.is_null() {
            return Err("target-token environment block was already destroyed"
                .to_owned()
                .into());
        }
        // SAFETY: raw is the exact live allocation returned by CreateEnvironmentBlock and this
        // method consumes its ownership before making the sole destruction call.
        if unsafe { DestroyEnvironmentBlock(raw) } == 0 {
            return Err(format!(
                "target-token environment destruction failed: {}",
                io::Error::last_os_error()
            )
            .into());
        }
        Ok(())
    }
}

impl Drop for OwnedUserEnvironmentBlock {
    fn drop(&mut self) {
        if !self.raw.is_null() {
            let raw = std::mem::replace(&mut self.raw, ptr::null_mut());
            // SAFETY: this is the still-owned CreateEnvironmentBlock allocation. This fallback
            // covers construction/pre-creation unwinds; the launch path destroys it explicitly.
            unsafe { DestroyEnvironmentBlock(raw) };
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserEnvironmentInventoryV1 {
    units: usize,
    entries: usize,
    sha256: String,
    keys_sha256: String,
    missing_required: Vec<String>,
}

struct SharedEnvironmentObservationV1 {
    scan: &'static str,
    metadata_match: bool,
    detail_sha256: String,
}

impl SharedEnvironmentObservationV1 {
    fn stable(&self) -> bool {
        self.scan == "ok" && self.metadata_match
    }
}

fn shared_environment_observation(
    admitted: &UserEnvironmentInventoryV1,
    observed: &Result<UserEnvironmentInventoryV1, TargetDesktopLeaseCreateError>,
    checkpoint: &str,
) -> SharedEnvironmentObservationV1 {
    match observed {
        Ok(observed) if observed == admitted => SharedEnvironmentObservationV1 {
            scan: "ok",
            metadata_match: true,
            detail_sha256: "none".to_owned(),
        },
        Ok(observed) => {
            let detail = format!(
                "checkpoint={checkpoint} classification=metadata-mismatch admitted_sha256={} admitted_keys_sha256={} admitted_units={} admitted_entries={} admitted_missing_required_sha256={} observed_sha256={} observed_keys_sha256={} observed_units={} observed_entries={} observed_missing_required_sha256={}",
                admitted.sha256,
                admitted.keys_sha256,
                admitted.units,
                admitted.entries,
                super::record::digest(admitted.missing_required.join("\0").as_bytes()),
                observed.sha256,
                observed.keys_sha256,
                observed.units,
                observed.entries,
                super::record::digest(observed.missing_required.join("\0").as_bytes()),
            );
            SharedEnvironmentObservationV1 {
                scan: "ok",
                metadata_match: false,
                detail_sha256: super::record::digest(detail.as_bytes()),
            }
        }
        Err(error) => {
            let detail = format!(
                "checkpoint={checkpoint} classification=scan-error detail={}",
                error.detail
            );
            SharedEnvironmentObservationV1 {
                scan: "error",
                metadata_match: false,
                detail_sha256: super::record::digest(detail.as_bytes()),
            }
        }
    }
}

enum LoaderLaunchEnvironmentStorageV5<'a> {
    Projected(Vec<u16>),
    Userenv(OwnedUserEnvironmentBlock),
    BorrowedUserenv(&'a mut OwnedUserEnvironmentBlock),
}

struct LoaderLaunchEnvironmentV5<'a> {
    storage: LoaderLaunchEnvironmentStorageV5<'a>,
    classification: &'static str,
    sha256: String,
    visible_keys: Vec<String>,
    keys_sha256: String,
    missing_required: Vec<String>,
    units: usize,
    entries: usize,
    profile_loaded: bool,
}

impl<'a> LoaderLaunchEnvironmentV5<'a> {
    fn create(
        target_token: HANDLE,
        matrix_mode: LoaderEnvironmentModeV4,
        authority: LoaderEnvironmentAuthorityV5,
    ) -> Result<Self, TargetDesktopLeaseCreateError> {
        match authority {
            LoaderEnvironmentAuthorityV5::MatrixProjection => {
                let projected = loader_environment_block(matrix_mode)?;
                let keys_sha256 = loader_environment_keys_sha256(&projected.keys);
                let units = projected.units.len();
                let entries = projected.keys.len();
                Ok(Self {
                    storage: LoaderLaunchEnvironmentStorageV5::Projected(projected.units),
                    classification: projected.classification,
                    sha256: projected.sha256,
                    visible_keys: projected.keys,
                    keys_sha256,
                    missing_required: projected.missing_required,
                    units,
                    entries,
                    profile_loaded: false,
                })
            }
            LoaderEnvironmentAuthorityV5::TargetTokenUserenv => {
                let block = OwnedUserEnvironmentBlock::create(target_token)?;
                Ok(Self {
                    classification: "target-token-userenv-v1",
                    sha256: block.sha256.clone(),
                    visible_keys: Vec::new(),
                    keys_sha256: block.keys_sha256.clone(),
                    missing_required: block.missing_required.clone(),
                    units: block.units,
                    entries: block.entries,
                    profile_loaded: false,
                    storage: LoaderLaunchEnvironmentStorageV5::Userenv(block),
                })
            }
            LoaderEnvironmentAuthorityV5::TargetTokenUserenvProfileLease => {
                let block = OwnedUserEnvironmentBlock::create(target_token)?;
                Ok(Self {
                    classification: "target-token-userenv-owned-profile-v1",
                    sha256: block.sha256.clone(),
                    visible_keys: Vec::new(),
                    keys_sha256: block.keys_sha256.clone(),
                    missing_required: block.missing_required.clone(),
                    units: block.units,
                    entries: block.entries,
                    profile_loaded: true,
                    storage: LoaderLaunchEnvironmentStorageV5::Userenv(block),
                })
            }
            LoaderEnvironmentAuthorityV5::TargetTokenUserenvBorrowedProfile => {
                let block = OwnedUserEnvironmentBlock::create(target_token)?;
                Ok(Self {
                    classification: "target-token-userenv-borrowed-profile-v1",
                    sha256: block.sha256.clone(),
                    visible_keys: Vec::new(),
                    keys_sha256: block.keys_sha256.clone(),
                    missing_required: block.missing_required.clone(),
                    units: block.units,
                    entries: block.entries,
                    profile_loaded: true,
                    storage: LoaderLaunchEnvironmentStorageV5::Userenv(block),
                })
            }
        }
    }
}

impl<'a> LoaderLaunchEnvironmentV5<'a> {
    fn borrowed_userenv(
        block: &'a mut OwnedUserEnvironmentBlock,
        inventory: &UserEnvironmentInventoryV1,
    ) -> Self {
        Self {
            classification: "target-token-userenv-borrowed-profile-v1",
            sha256: inventory.sha256.clone(),
            visible_keys: Vec::new(),
            keys_sha256: inventory.keys_sha256.clone(),
            missing_required: inventory.missing_required.clone(),
            units: inventory.units,
            entries: inventory.entries,
            profile_loaded: true,
            storage: LoaderLaunchEnvironmentStorageV5::BorrowedUserenv(block),
        }
    }

    fn pointer(&mut self) -> *mut c_void {
        match &mut self.storage {
            LoaderLaunchEnvironmentStorageV5::Projected(units) => units.as_mut_ptr().cast(),
            LoaderLaunchEnvironmentStorageV5::Userenv(block) => block.pointer(),
            LoaderLaunchEnvironmentStorageV5::BorrowedUserenv(block) => block.pointer(),
        }
    }

    fn destroy_userenv_after_create(&mut self) -> Result<(), TargetDesktopLeaseCreateError> {
        match &mut self.storage {
            LoaderLaunchEnvironmentStorageV5::Projected(_) => Ok(()),
            LoaderLaunchEnvironmentStorageV5::Userenv(block) => block.destroy_after_create(),
            LoaderLaunchEnvironmentStorageV5::BorrowedUserenv(_) => Ok(()),
        }
    }
}

fn loader_environment_keys_sha256(keys: &[String]) -> String {
    let mut keys = keys
        .iter()
        .map(|key| key.to_ascii_uppercase())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    let mut canonical = b"memcordon-loader-environment-keys-v1\0".to_vec();
    for key in &keys {
        canonical.extend_from_slice(key.as_bytes());
        canonical.push(0);
    }
    super::record::digest(&canonical)
}

fn bounded_user_environment_inventory(
    raw: *mut c_void,
) -> Result<UserEnvironmentInventoryV1, TargetDesktopLeaseCreateError> {
    if raw.is_null() {
        return Err("target-token environment block is null".to_owned().into());
    }
    let pointer = raw.cast::<u16>();
    let mut length = None;
    for index in 0..LOADER_ENVIRONMENT_MAX_UNITS.saturating_sub(1) {
        // SAFETY: Userenv promises a double-NUL block; the scan is bounded by the documented
        // native environment limit and stops before reading beyond that bound.
        let current = unsafe { *pointer.add(index) };
        let next = unsafe { *pointer.add(index + 1) };
        if current == 0 && next == 0 {
            length = Some(index + 2);
            break;
        }
    }
    let length = length.ok_or_else(|| {
        TargetDesktopLeaseCreateError::from(
            "target-token environment is not double-NUL terminated within its native bound"
                .to_owned(),
        )
    })?;
    // SAFETY: the bounded scan proved the full slice readable through its terminal double NUL.
    user_environment_inventory_from_units(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn user_environment_inventory_from_units(
    units: &[u16],
) -> Result<UserEnvironmentInventoryV1, TargetDesktopLeaseCreateError> {
    if units.len() < 2
        || units.len() > LOADER_ENVIRONMENT_MAX_UNITS
        || units[units.len() - 2..] != [0, 0]
    {
        return Err(
            "target-token environment units are not a bounded double-NUL block"
                .to_owned()
                .into(),
        );
    }
    if units[..units.len() - 2]
        .windows(2)
        .any(|pair| pair == [0, 0])
    {
        return Err(
            "target-token environment contains a premature terminal double NUL"
                .to_owned()
                .into(),
        );
    }
    let mut block_digest = b"memcordon-target-token-userenv-v1\0".to_vec();
    for unit in units {
        block_digest.extend_from_slice(&unit.to_le_bytes());
    }
    let mut keys = BTreeSet::new();
    let mut start = 0_usize;
    while start + 1 < units.len() && units[start] != 0 {
        let end = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .map(|offset| start + offset)
            .ok_or_else(|| {
                TargetDesktopLeaseCreateError::from(
                    "target-token environment entry is unterminated".to_owned(),
                )
            })?;
        let entry = &units[start..end];
        String::from_utf16(entry).map_err(|_| {
            TargetDesktopLeaseCreateError::from(
                "target-token environment entry is not valid UTF-16".to_owned(),
            )
        })?;
        let search = entry.strip_prefix(&[b'=' as u16]).unwrap_or(entry);
        let relative_separator = search.iter().position(|unit| *unit == b'=' as u16);
        let separator = relative_separator
            .map(|offset| entry.len().saturating_sub(search.len()) + offset)
            .filter(|separator| *separator != 0)
            .ok_or_else(|| {
                TargetDesktopLeaseCreateError::from(
                    "target-token environment entry has no key separator".to_owned(),
                )
            })?;
        let key = String::from_utf16(&entry[..separator])
            .map_err(|_| {
                TargetDesktopLeaseCreateError::from(
                    "target-token environment key is not valid UTF-16".to_owned(),
                )
            })?
            .to_ascii_uppercase();
        if !keys.insert(key) {
            return Err(
                "target-token environment contains a duplicate case-insensitive key"
                    .to_owned()
                    .into(),
            );
        }
        start = end + 1;
    }
    let keys = keys.into_iter().collect::<Vec<_>>();
    let missing_required = LOADER_REQUIRED_ENVIRONMENT_KEYS
        .iter()
        .filter(|required| !keys.iter().any(|key| key.eq_ignore_ascii_case(required)))
        .map(|required| (*required).to_owned())
        .collect();
    Ok(UserEnvironmentInventoryV1 {
        units: units.len(),
        entries: keys.len(),
        sha256: super::record::digest(&block_digest),
        keys_sha256: loader_environment_keys_sha256(&keys),
        missing_required,
    })
}

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UserEnvironmentInventoryForTest {
    pub units: usize,
    pub entries: usize,
    pub sha256: String,
    pub keys_sha256: String,
    pub missing_required: Vec<String>,
}

#[cfg(test)]
pub(crate) fn bounded_user_environment_inventory_for_test(
    units: Option<&[u16]>,
) -> Result<UserEnvironmentInventoryForTest, String> {
    let units = units.ok_or_else(|| "target-token environment block is null".to_owned())?;
    user_environment_inventory_from_units(units)
        .map(|inventory| UserEnvironmentInventoryForTest {
            units: inventory.units,
            entries: inventory.entries,
            sha256: inventory.sha256,
            keys_sha256: inventory.keys_sha256,
            missing_required: inventory.missing_required,
        })
        .map_err(|error| error.detail)
}

#[cfg(test)]
pub(crate) fn loader_shared_environment_pair_valid_for_test(
    admitted: &[u16],
    baseline: &[u16],
    comparison: &[u16],
    after_baseline: &[u16],
    after_comparison: &[u16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = [baseline, comparison, after_baseline, after_comparison]
        .map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "comparison",
                    "after-baseline",
                    "after-comparison",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_shared_environment_triplet_valid_for_test(
    admitted: &[u16],
    baseline: &[u16],
    after_baseline: &[u16],
    comparison: &[u16],
    after_comparison: &[u16],
    same_access: &[u16],
    after_same_access: &[u16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = [
        baseline,
        after_baseline,
        comparison,
        after_comparison,
        same_access,
        after_same_access,
    ]
    .map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "after-baseline",
                    "comparison",
                    "after-comparison",
                    "same-access",
                    "after-same-access",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_shared_environment_quad_valid_for_test(
    admitted: &[u16],
    baseline: &[u16],
    after_baseline: &[u16],
    comparison: &[u16],
    after_comparison: &[u16],
    same_access: &[u16],
    after_same_access: &[u16],
    logon: &[u16],
    after_logon: &[u16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = [
        baseline,
        after_baseline,
        comparison,
        after_comparison,
        same_access,
        after_same_access,
        logon,
        after_logon,
    ]
    .map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "after-baseline",
                    "comparison",
                    "after-comparison",
                    "same-access",
                    "after-same-access",
                    "logon",
                    "after-logon",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_shared_environment_quint_valid_for_test(
    admitted: &[u16],
    baseline: &[u16],
    after_baseline: &[u16],
    comparison: &[u16],
    after_comparison: &[u16],
    same_access: &[u16],
    after_same_access: &[u16],
    logon: &[u16],
    after_logon: &[u16],
    authenticated_users: &[u16],
    after_authenticated_users: &[u16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = [
        baseline,
        after_baseline,
        comparison,
        after_comparison,
        same_access,
        after_same_access,
        logon,
        after_logon,
        authenticated_users,
        after_authenticated_users,
    ]
    .map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "after-baseline",
                    "comparison",
                    "after-comparison",
                    "same-access",
                    "after-same-access",
                    "logon",
                    "after-logon",
                    "authenticated-users",
                    "after-authenticated-users",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn loader_shared_environment_sext_valid_for_test(
    admitted: &[u16],
    baseline: &[u16],
    after_baseline: &[u16],
    comparison: &[u16],
    after_comparison: &[u16],
    same_access: &[u16],
    after_same_access: &[u16],
    logon: &[u16],
    after_logon: &[u16],
    authenticated_users: &[u16],
    after_authenticated_users: &[u16],
    target_user: &[u16],
    after_target_user: &[u16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = [
        baseline,
        after_baseline,
        comparison,
        after_comparison,
        same_access,
        after_same_access,
        logon,
        after_logon,
        authenticated_users,
        after_authenticated_users,
        target_user,
        after_target_user,
    ]
    .map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "after-baseline",
                    "comparison",
                    "after-comparison",
                    "same-access",
                    "after-same-access",
                    "logon",
                    "after-logon",
                    "authenticated-users",
                    "after-authenticated-users",
                    "target-user",
                    "after-target-user",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
pub(crate) fn loader_shared_environment_octet_valid_for_test(
    admitted: &[u16],
    observations: [&[u16]; 16],
    destroyed: bool,
) -> Result<bool, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let inventories = observations.map(user_environment_inventory_from_units);
    Ok(destroyed
        && admitted.missing_required.is_empty()
        && inventories.iter().enumerate().all(|(index, inventory)| {
            shared_environment_observation(
                &admitted,
                inventory,
                [
                    "baseline",
                    "after-baseline",
                    "comparison",
                    "after-comparison",
                    "same-access",
                    "after-same-access",
                    "logon",
                    "after-logon",
                    "authenticated-users",
                    "after-authenticated-users",
                    "target-user",
                    "after-target-user",
                    "debug-c",
                    "after-debug-c",
                    "debug-f",
                    "after-debug-f",
                ][index],
            )
            .stable()
        }))
}

#[cfg(test)]
pub(crate) fn render_loader_shared_environment_observation_for_test(
    admitted: &[u16],
    observed: &[u16],
    checkpoint: &str,
) -> Result<String, String> {
    let admitted = user_environment_inventory_from_units(admitted).map_err(|error| error.detail)?;
    let observed = user_environment_inventory_from_units(observed);
    let evidence = shared_environment_observation(&admitted, &observed, checkpoint);
    Ok(format!(
        "shared_environment_scan={} shared_environment_metadata_match={} shared_environment_observation_sha256={} environment_values_redacted=true",
        evidence.scan, evidence.metadata_match, evidence.detail_sha256,
    ))
}

#[cfg(test)]
pub(crate) const fn loader_environment_max_units_for_test() -> usize {
    LOADER_ENVIRONMENT_MAX_UNITS
}

fn loader_environment_block(
    mode: LoaderEnvironmentModeV4,
) -> Result<LoaderEnvironmentBlockV4, TargetDesktopLeaseCreateError> {
    let (units, keys) = match mode {
        LoaderEnvironmentModeV4::Empty => (vec![0, 0], Vec::new()),
        LoaderEnvironmentModeV4::CanonicalMinimalSystem => {
            let source = system_environment_entries()?;
            let mut entries = Vec::with_capacity(LOADER_REQUIRED_ENVIRONMENT_KEYS.len());
            for key in LOADER_REQUIRED_ENVIRONMENT_KEYS {
                let value = source.get(&key.to_ascii_uppercase()).ok_or_else(|| {
                    TargetDesktopLeaseCreateError::from(format!(
                        "canonical loader environment is missing required system variable {key}"
                    ))
                })?;
                entries.push(WindowsEnvironmentEntryV1 {
                    name: key.encode_utf16().collect(),
                    value: value.clone(),
                });
            }
            let units = memcordon_core::encode_windows_environment_block(&entries)
                .map_err(|detail| TargetDesktopLeaseCreateError::from(detail.to_owned()))?;
            let keys = LOADER_REQUIRED_ENVIRONMENT_KEYS
                .iter()
                .map(|key| (*key).to_owned())
                .collect();
            (units, keys)
        }
    };
    let key_set = keys
        .iter()
        .map(|key| key.to_ascii_uppercase())
        .collect::<HashSet<_>>();
    let missing_required = LOADER_REQUIRED_ENVIRONMENT_KEYS
        .iter()
        .filter(|key| !key_set.contains(&key.to_ascii_uppercase()))
        .map(|key| (*key).to_owned())
        .collect();
    let mut canonical = b"memcordon-loader-environment-v4\0".to_vec();
    for unit in &units {
        canonical.extend_from_slice(&unit.to_le_bytes());
    }
    Ok(LoaderEnvironmentBlockV4 {
        units,
        classification: mode.diagnostic(),
        sha256: super::record::digest(&canonical),
        keys,
        missing_required,
    })
}

#[cfg(test)]
pub(crate) fn loader_control_matrix_contract_for_test() -> (
    (&'static str, &'static str),
    [(&'static str, &'static str); 6],
) {
    (
        (
            LoaderControlMatrixCellV4::PRODUCTION
                .environment
                .diagnostic(),
            LoaderControlMatrixCellV4::PRODUCTION.diagnostic(),
        ),
        LoaderControlMatrixCellV4::CERTIFICATION
            .map(|cell| (cell.environment.diagnostic(), cell.diagnostic())),
    )
}

#[cfg(test)]
fn loader_failure_for_test(cell: LoaderControlMatrixCellV4) -> TargetDesktopLeaseCreateError {
    TargetDesktopLeaseCreateError {
        detail: if cell.debugger == LoaderDebuggerRelationV5::None {
            "failure_phase=pre-initial-breakpoint-static-loader".to_owned()
        } else {
            "failure_phase=pre-initial-breakpoint-static-loader loader_trace=v4".to_owned()
        },
        os_code: Some(0xc000_0142_u32 as i32),
        loader_phase: LoaderLaunchFailurePhaseV1::PreInitialBreakpointStaticLoader,
    }
}

#[cfg(test)]
pub(crate) fn loader_failure_evidence_ranks_for_test() -> [(&'static str, &'static str); 6] {
    LoaderControlMatrixCellV4::CERTIFICATION.map(|cell| {
        let error = loader_failure_for_test(cell);
        (
            cell.diagnostic(),
            loader_failure_evidence_rank(cell, &error).diagnostic(),
        )
    })
}

#[cfg(test)]
pub(crate) fn select_loader_failure_evidence_for_test(
    order: &[usize],
) -> Result<&'static str, String> {
    let mut selected = None;
    for index in order {
        let cell = *LoaderControlMatrixCellV4::CERTIFICATION
            .get(*index)
            .ok_or_else(|| format!("loader matrix test index {index} is out of range"))?;
        let rank = loader_failure_evidence_rank(cell, &loader_failure_for_test(cell));
        if loader_failure_should_replace(selected.map(|(rank, _)| rank), rank) {
            selected = Some((rank, cell.diagnostic()));
        }
    }
    selected
        .map(|(_, cell)| cell)
        .ok_or_else(|| "loader matrix test order is empty".to_owned())
}

#[cfg(test)]
pub(crate) fn render_loader_control_matrix_failure_for_test(
    order: &[usize],
    selected_detail: &str,
) -> Result<String, String> {
    let mut outcomes = Vec::with_capacity(order.len());
    for index in order {
        let cell = *LoaderControlMatrixCellV4::CERTIFICATION
            .get(*index)
            .ok_or_else(|| format!("loader matrix test index {index} is out of range"))?;
        let error = loader_failure_for_test(cell);
        outcomes.push(LoaderControlMatrixOutcomeV6 {
            cell: cell.diagnostic(),
            outcome: LoaderControlMatrixOutcomeKindV6::Failed,
            native_status: error.os_code,
            failure_phase: loader_failure_phase(&error),
            child_trace: error.detail.contains("loader_trace=v4"),
            detail_sha256: super::record::digest(cell.diagnostic().as_bytes()),
        });
    }
    let selected_cell = select_loader_failure_evidence_for_test(order)?;
    Ok(loader_control_matrix_failure_detail(
        selected_cell,
        LoaderFailureEvidenceRankV6::FullObserverSnapsOn,
        Some(0xc000_0142_u32 as i32),
        &outcomes,
        selected_detail,
    ))
}

#[cfg(test)]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct LoaderEnvironmentBlockForTest {
    pub(crate) units: Vec<u16>,
    pub(crate) classification: &'static str,
    pub(crate) keys: Vec<String>,
    pub(crate) missing_required: Vec<String>,
}

#[cfg(test)]
pub(crate) fn loader_environment_block_for_test(
    canonical_minimal_system: bool,
) -> Result<LoaderEnvironmentBlockForTest, String> {
    let mode = if canonical_minimal_system {
        LoaderEnvironmentModeV4::CanonicalMinimalSystem
    } else {
        LoaderEnvironmentModeV4::Empty
    };
    let block = loader_environment_block(mode).map_err(|error| error.detail)?;
    Ok(LoaderEnvironmentBlockForTest {
        units: block.units,
        classification: block.classification,
        keys: block.keys,
        missing_required: block.missing_required,
    })
}

fn system_environment_entries() -> Result<BTreeMap<String, Vec<u16>>, TargetDesktopLeaseCreateError>
{
    let mut raw = ptr::null_mut();
    // SAFETY: a null token requests the system-only environment, inherit is FALSE, and raw
    // receives an allocation owned by DestroyEnvironmentBlock.
    if unsafe { CreateEnvironmentBlock(&raw mut raw, ptr::null_mut(), 0) } == 0 {
        return Err(format!(
            "CreateEnvironmentBlock failed for canonical loader environment: {}",
            io::Error::last_os_error()
        )
        .into());
    }
    let block = SystemEnvironmentBlock(raw);
    let pointer = block.0.cast::<u16>();
    let mut length = None;
    for index in 0..LOADER_ENVIRONMENT_MAX_UNITS.saturating_sub(1) {
        // SAFETY: CreateEnvironmentBlock returns a double-NUL-terminated Unicode block. Reads are
        // bounded by the native environment limit and stop at the first double NUL.
        let current = unsafe { *pointer.add(index) };
        let next = unsafe { *pointer.add(index + 1) };
        if current == 0 && next == 0 {
            length = Some(index + 2);
            break;
        }
    }
    let length = length.ok_or_else(|| {
        TargetDesktopLeaseCreateError::from(
            "system environment block is not double-NUL terminated within its native bound"
                .to_owned(),
        )
    })?;
    // SAFETY: the preceding bounded scan proved every unit through length is readable and includes
    // the terminal double NUL; the slice is copied before block is released.
    let units = unsafe { std::slice::from_raw_parts(pointer, length) };
    let mut entries = BTreeMap::new();
    let mut start = 0_usize;
    while start + 1 < units.len() && units[start] != 0 {
        let end = units[start..]
            .iter()
            .position(|unit| *unit == 0)
            .map(|offset| start + offset)
            .ok_or_else(|| {
                TargetDesktopLeaseCreateError::from(
                    "system environment entry is unterminated".to_owned(),
                )
            })?;
        let entry = &units[start..end];
        let separator = entry.iter().position(|unit| *unit == b'=' as u16);
        if let Some(separator) = separator.filter(|separator| *separator != 0) {
            let name = String::from_utf16(&entry[..separator]).map_err(|_| {
                TargetDesktopLeaseCreateError::from(
                    "system environment name is not valid UTF-16".to_owned(),
                )
            })?;
            let value = entry[separator + 1..].to_vec();
            if entries.insert(name.to_ascii_uppercase(), value).is_some() {
                return Err(
                    "system environment contains a duplicate case-insensitive key"
                        .to_owned()
                        .into(),
                );
            }
        }
        start = end + 1;
    }
    Ok(entries)
}

fn mitigation_policy_diagnostic(process: HANDLE) -> String {
    const POLICIES: [(&str, i32, u32); 6] = [
        ("dep", 0, 0x0000_0007),
        ("aslr", 1, 0x0000_000f),
        ("dynamic-code", 2, 0x0000_001f),
        ("control-flow-guard", 7, 0x0000_001f),
        ("binary-signature", 8, 0x0000_001f),
        ("image-load", 10, 0x0000_001f),
    ];
    POLICIES
        .iter()
        .map(|(name, policy, known_mask)| {
            let mut flags = 0_u32;
            // SAFETY: process is the live suspended child and flags has the exact documented
            // four-byte policy layout for each selected PROCESS_MITIGATION_* record.
            if unsafe {
                GetProcessMitigationPolicy(
                    process,
                    *policy,
                    (&raw mut flags).cast(),
                    std::mem::size_of::<u32>(),
                )
            } == 0
            {
                let code = io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or_default();
                format!("{name}:unavailable-native-{code}")
            } else if flags & !known_mask != 0 {
                format!(
                    "{name}:unavailable-reserved-bits-0x{:08x}",
                    flags & !known_mask
                )
            } else {
                format!("{name}:flags-0x{flags:08x}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn loader_snapshot_digest<T: Serialize>(
    domain: &[u8],
    snapshot: &T,
) -> Result<String, TargetDesktopLeaseCreateError> {
    let mut canonical = domain.to_vec();
    canonical.extend(
        serde_json::to_vec(snapshot)
            .map_err(|error| TargetDesktopLeaseCreateError::from(error.to_string()))?,
    );
    Ok(super::record::digest(&canonical))
}

fn loader_control_command_semantics_sha256(
    executable: &Path,
    action: &str,
    exact_desktop: &str,
    binary_sha256: &str,
) -> String {
    use std::os::windows::ffi::OsStrExt;

    let mut material = b"memcordon-loader-control-command-semantics-v1\0".to_vec();
    for unit in executable.as_os_str().encode_wide() {
        material.extend_from_slice(&unit.to_le_bytes());
    }
    material.push(0);
    material.extend_from_slice(action.as_bytes());
    material.push(0);
    material.extend_from_slice(b"dynamic:authenticated-private-pipe\0");
    material.extend_from_slice(b"dynamic:authenticated-nonce\0");
    for unit in exact_desktop.encode_utf16() {
        material.extend_from_slice(&unit.to_le_bytes());
    }
    material.push(0);
    material.extend_from_slice(binary_sha256.as_bytes());
    super::record::digest(&material)
}

fn launch_target_desktop_loader_control(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    loader_restriction_canary: Option<&LoaderRestrictionCanaryTokens>,
) -> Result<(), TargetDesktopLeaseCreateError> {
    if !super::loader_debug::enabled(TargetDesktopBootstrapRoleV1::LoaderControl) {
        return launch_target_desktop_loader_control_cell(
            target_token,
            target_envelope,
            target_snapshot,
            exact_desktop,
            launch_context,
            association_preflight,
            holder_identity,
            LoaderControlMatrixCellV4::PRODUCTION,
        )
        .map(|_| ());
    }

    let mut results = Vec::with_capacity(LoaderControlMatrixCellV4::CERTIFICATION.len());
    let mut selected_failure = None;
    let mut canonical_baseline = None;
    for cell in LoaderControlMatrixCellV4::CERTIFICATION {
        let result = launch_target_desktop_loader_control_cell(
            target_token,
            target_envelope,
            target_snapshot,
            exact_desktop,
            launch_context,
            association_preflight,
            holder_identity,
            cell,
        );
        if cell == LoaderControlMatrixCellV4::PRODUCTION {
            canonical_baseline = Some(clone_loader_control_result(&result));
        }
        match result {
            Ok(evidence) => results.push(LoaderControlMatrixOutcomeV6 {
                cell: cell.diagnostic(),
                outcome: LoaderControlMatrixOutcomeKindV6::Passed,
                native_status: None,
                failure_phase: "none",
                child_trace: false,
                detail_sha256: super::record::digest(evidence.as_bytes()),
            }),
            Err(error) => {
                let child_trace = error.detail.contains("loader_trace=v4");
                results.push(LoaderControlMatrixOutcomeV6 {
                    cell: cell.diagnostic(),
                    outcome: LoaderControlMatrixOutcomeKindV6::Failed,
                    native_status: error.os_code,
                    failure_phase: loader_failure_phase(&error),
                    child_trace,
                    detail_sha256: super::record::digest(error.detail.as_bytes()),
                });
                let rank = loader_failure_evidence_rank(cell, &error);
                if loader_failure_should_replace(
                    selected_failure
                        .as_ref()
                        .map(|(selected_rank, _, _)| *selected_rank),
                    rank,
                ) {
                    selected_failure = Some((rank, cell.diagnostic(), error));
                }
            }
        }
    }
    let restriction_canary = loader_restriction_canary_is_required(&results).then(|| {
        loader_restriction_canary.map_or_else(
            || {
                LoaderRestrictionCanaryEvaluationV1 {
                    diagnostic: "loader_init_prerequisite_canary=v1 state=invalid error=authenticated-control-derived-token-pair-unavailable"
                        .to_owned(),
                    target_environment_required: false,
                }
            },
            |tokens| {
                loader_restriction_canary_diagnostic(
                    tokens,
                    exact_desktop,
                    launch_context,
                    association_preflight,
                    holder_identity,
                )
            },
        )
    });
    let environment_canary = restriction_canary
        .as_ref()
        .filter(|evaluation| evaluation.target_environment_required)
        .and_then(
            |_| match (loader_restriction_canary, canonical_baseline.as_ref()) {
                (Some(tokens), Some(baseline)) => {
                    Some(loader_environment_prerequisite_canary_diagnostic(
                        target_token,
                        target_envelope,
                        target_snapshot,
                        exact_desktop,
                        launch_context,
                        association_preflight,
                        holder_identity,
                        tokens,
                        baseline,
                    ))
                }
                _ => None,
            },
        );
    let profile_canary = environment_canary
        .as_ref()
        .filter(|evaluation| evaluation.profile_required)
        .and_then(|environment| {
            loader_restriction_canary.map(|tokens| {
                loader_profile_prerequisite_canary_diagnostic(
                    exact_desktop,
                    launch_context,
                    association_preflight,
                    holder_identity,
                    tokens,
                    &environment.comparison,
                )
            })
        });
    let object_security_canary = profile_canary
        .as_ref()
        .filter(|evaluation| evaluation.object_security_required)
        .and_then(|profile| {
            loader_restriction_canary.and_then(|tokens| {
                profile.comparison.as_ref().map(|baseline| {
                    loader_object_security_prerequisite_canary_diagnostic(
                        exact_desktop,
                        launch_context,
                        association_preflight,
                        holder_identity,
                        tokens,
                        baseline,
                    )
                })
            })
        });
    let restriction_presence_canary = object_security_canary
        .as_ref()
        .filter(|evaluation| evaluation.restriction_presence_required)
        .and_then(|_| {
            loader_restriction_canary.map(|tokens| {
                loader_restriction_presence_prerequisite_canary_diagnostic(
                    exact_desktop,
                    launch_context,
                    association_preflight,
                    holder_identity,
                    tokens,
                )
            })
        });
    if let Some((rank, cell, mut failure)) = selected_failure {
        let matrix_detail = loader_control_matrix_failure_detail(
            cell,
            rank,
            failure.os_code,
            &results,
            &failure.detail,
        );
        let mut prerequisites = Vec::new();
        if let Some(restriction_presence) = restriction_presence_canary {
            prerequisites.push(restriction_presence.diagnostic);
        }
        if let Some(object_security) = object_security_canary {
            prerequisites.push(object_security.diagnostic);
        }
        if let Some(profile) = profile_canary {
            prerequisites.push(profile.diagnostic);
        }
        if let Some(environment) = environment_canary {
            prerequisites.push(environment.diagnostic);
        }
        if let Some(restriction) = restriction_canary {
            prerequisites.push(restriction.diagnostic);
        }
        failure.detail = if prerequisites.is_empty() {
            matrix_detail
        } else {
            format!("{} {matrix_detail}", prerequisites.join(" "))
        };
        Err(failure)
    } else {
        Ok(())
    }
}

fn launch_target_desktop_loader_control_cell(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    matrix_cell: LoaderControlMatrixCellV4,
) -> Result<String, TargetDesktopLeaseCreateError> {
    launch_target_desktop_loader_control_cell_with_environment_authority(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        matrix_cell,
        LoaderEnvironmentAuthorityV5::MatrixProjection,
        LoaderObjectSecurityAuthorityV1::LauncherExplicit,
    )
}

#[allow(clippy::too_many_arguments)]
fn launch_target_desktop_loader_control_cell_with_environment_authority(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    matrix_cell: LoaderControlMatrixCellV4,
    environment_authority: LoaderEnvironmentAuthorityV5,
    object_security_authority: LoaderObjectSecurityAuthorityV1,
) -> Result<String, TargetDesktopLeaseCreateError> {
    launch_target_desktop_loader_control_cell_with_environment_source(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        matrix_cell,
        LoaderCellEnvironmentSourceV6::Create(environment_authority),
        object_security_authority,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn launch_target_desktop_loader_control_cell_with_shared_environment(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    matrix_cell: LoaderControlMatrixCellV4,
    environment: &mut OwnedUserEnvironmentBlock,
    admitted_inventory: &UserEnvironmentInventoryV1,
    object_security_authority: LoaderObjectSecurityAuthorityV1,
    passive_access_localization: Option<(
        &super::access_trace::PassiveAccessLocalizationObserverV1,
        super::access_trace::PassiveAccessLocalizationCellV1,
    )>,
) -> Result<String, TargetDesktopLeaseCreateError> {
    launch_target_desktop_loader_control_cell_with_environment_source(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        holder_identity,
        matrix_cell,
        LoaderCellEnvironmentSourceV6::BorrowedUserenv {
            block: environment,
            inventory: admitted_inventory.clone(),
        },
        object_security_authority,
        passive_access_localization,
    )
}

#[allow(clippy::too_many_arguments)]
fn launch_target_desktop_loader_control_cell_with_environment_source(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    holder_identity: &WindowsProcessIdentityV1,
    matrix_cell: LoaderControlMatrixCellV4,
    environment_source: LoaderCellEnvironmentSourceV6<'_>,
    object_security_authority: LoaderObjectSecurityAuthorityV1,
    passive_access_localization: Option<(
        &super::access_trace::PassiveAccessLocalizationObserverV1,
        super::access_trace::PassiveAccessLocalizationCellV1,
    )>,
) -> Result<String, TargetDesktopLeaseCreateError> {
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopLeaseCreateError::from(format!(
            "loader-snaps authority handoff requires reverted launcher impersonation: {error}"
        ))
    })?;
    let target_token_sha256 =
        loader_snapshot_digest(b"memcordon-loader-snaps-target-token-v2\0", target_snapshot)?;
    let association_preflight_sha256 = loader_snapshot_digest(
        b"memcordon-loader-snaps-association-preflight-v2\0",
        association_preflight,
    )?;
    let contract = super::package::installed_target_desktop_bootstrap_contract()?;
    let image_path_sha256 = super::record::digest(
        super::package::installed_target_desktop_bootstrap()
            .to_string_lossy()
            .to_ascii_lowercase()
            .as_bytes(),
    );
    let mut admission = b"memcordon-loader-snaps-admission-v2\0".to_vec();
    admission.extend_from_slice(matrix_cell.diagnostic().as_bytes());
    admission.extend_from_slice(target_token_sha256.as_bytes());
    admission.extend_from_slice(association_preflight_sha256.as_bytes());
    admission.extend_from_slice(&holder_identity.process_id.to_le_bytes());
    admission.extend_from_slice(&holder_identity.creation_time_100ns.to_le_bytes());
    admission.extend_from_slice(super::record::digest(exact_desktop.as_bytes()).as_bytes());
    let binding = super::session_broker::LoaderSnapsRequestBindingV2 {
        admission_sha256: super::record::digest(&admission),
        matrix_cell: matrix_cell.diagnostic().to_owned(),
        image_path_sha256,
        image_sha256: contract.sha256,
        native_machine: contract.imports.machine,
        target_token_sha256,
        association_preflight_sha256,
        holder_identity: holder_identity.clone(),
    };
    let loader_snaps = matrix_cell
        .loader_snaps
        .then(|| super::session_broker::request_loader_snaps(binding))
        .transpose()
        .map_err(|failure| TargetDesktopLeaseCreateError {
            os_code: failure.native_code,
            detail: failure.diagnostic(),
            loader_phase: LoaderLaunchFailurePhaseV1::PreCreate,
        })?;
    let armed_diagnostic = loader_snaps
        .as_ref()
        .map(super::session_broker::LoaderSnapsControlLease::armed_diagnostic);
    let result = launch_target_desktop_loader_control_cell_inner(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        association_preflight,
        matrix_cell,
        environment_source,
        object_security_authority,
        passive_access_localization,
    );
    let child_outcome_sha256 = match &result {
        Ok(evidence) => {
            super::record::digest(format!("loader-cell-success-v2\0{evidence}").as_bytes())
        }
        Err(error) => super::record::digest(
            format!(
                "loader-cell-failure-v2\0native={:?}\0{}",
                error.os_code, error.detail
            )
            .as_bytes(),
        ),
    };
    let restoration = loader_snaps
        .map(|lease| lease.restore(child_outcome_sha256))
        .transpose();
    let restored = match restoration {
        Ok(restored) => restored,
        Err(restoration) => {
            return preserve_loader_snaps_primary(
                result,
                Some(TargetDesktopLeaseCreateError {
                    os_code: restoration.native_code,
                    detail: restoration.diagnostic(),
                    loader_phase: LoaderLaunchFailurePhaseV1::ExitDrain,
                }),
            );
        }
    };
    let evidence = preserve_loader_snaps_primary(result, None)?;
    Ok(format!(
        "{evidence} loader_snaps_armed={} loader_snaps_restored={}",
        armed_diagnostic.as_deref().unwrap_or("not-requested"),
        restored
            .as_ref()
            .map(super::session_broker::LoaderSnapsRestoredReceiptV2::diagnostic)
            .as_deref()
            .unwrap_or("not-requested")
    ))
}

fn preserve_loader_snaps_primary<T>(
    primary: Result<T, TargetDesktopLeaseCreateError>,
    secondary: Option<TargetDesktopLeaseCreateError>,
) -> Result<T, TargetDesktopLeaseCreateError> {
    match (primary, secondary) {
        (Ok(value), None) => Ok(value),
        (Ok(_), Some(secondary)) => Err(secondary),
        (Err(primary), None) => Err(primary),
        (Err(mut primary), Some(secondary)) => {
            primary.detail = format!(
                "{} secondary_loader_snaps_restoration_failure={}",
                primary.detail, secondary.detail
            );
            Err(primary)
        }
    }
}

#[cfg(test)]
pub(crate) fn loader_snaps_failure_precedence_for_test() -> Result<(), String> {
    let primary = TargetDesktopLeaseCreateError {
        os_code: Some(0xc000_0142_u32 as i32),
        detail: "primary-child-failure".to_owned(),
        loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
    };
    let secondary = TargetDesktopLeaseCreateError {
        os_code: Some(5),
        detail: "restore-failure".to_owned(),
        loader_phase: LoaderLaunchFailurePhaseV1::ExitDrain,
    };
    let failure = preserve_loader_snaps_primary::<()>(Err(primary), Some(secondary))
        .expect_err("primary failure must remain terminal");
    if failure.os_code != Some(0xc000_0142_u32 as i32)
        || !failure.detail.starts_with("primary-child-failure ")
        || !failure
            .detail
            .contains("secondary_loader_snaps_restoration_failure=restore-failure")
    {
        return Err(format!(
            "loader-snaps failure precedence changed: native={:?} detail={}",
            failure.os_code, failure.detail
        ));
    }
    Ok(())
}

fn launch_target_desktop_loader_control_cell_inner(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    exact_desktop: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    association_preflight: &TargetUserObjectOpenPreflightV1,
    matrix_cell: LoaderControlMatrixCellV4,
    environment_source: LoaderCellEnvironmentSourceV6<'_>,
    object_security_authority: LoaderObjectSecurityAuthorityV1,
    passive_access_localization: Option<(
        &super::access_trace::PassiveAccessLocalizationObserverV1,
        super::access_trace::PassiveAccessLocalizationCellV1,
    )>,
) -> Result<String, TargetDesktopLeaseCreateError> {
    let loader_debug_observer = matrix_cell.debugger.observer();
    let loader_debug_trace = loader_debug_observer.is_some();
    let target_source_before = super::token::token_attestation_snapshot(target_token)?;
    super::token::require_same_token_instance(
        "loader-control-target-request-preflight",
        target_snapshot,
        &target_source_before,
    )?;
    let nonce = target_desktop_nonce()?;
    let pipe_name = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        nonce,
    );
    let pipe_security = SecurityDescriptor::from_sddl(
        &super::security::target_desktop_bootstrap_pipe_sddl(target_token)?,
    )?;
    let prepared_pipe =
        super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
    clear_inherit(prepared_pipe.raw())?;
    verify_not_inheritable(prepared_pipe.raw())?;
    let control_job = Job::create(None, None, None)?;
    let environment_authority = environment_source.authority();
    let profile_lease_cell = matches!(
        environment_authority,
        LoaderEnvironmentAuthorityV5::TargetTokenUserenvBorrowedProfile
            | LoaderEnvironmentAuthorityV5::TargetTokenUserenvProfileLease
    );
    let mut cell_result = (|| -> Result<String, TargetDesktopLeaseCreateError> {
        let jobs = [control_job.handle()];
        let attributes = AttributeList::new(
            &[Attribute::new(
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                std::mem::size_of_val(&jobs),
            )],
            None,
        )?;
        let target_policy = object_security_authority
            .uses_target_policy()
            .then(|| super::security::TargetKernelObjectPolicyV1::capture(target_token))
            .transpose()?;
        let process_sddl = match object_security_authority {
            LoaderObjectSecurityAuthorityV1::TargetAwareProcess
            | LoaderObjectSecurityAuthorityV1::TargetAwareBoth => target_policy
                .as_ref()
                .expect("target-aware process policy is captured")
                .process_sddl()
                .to_owned(),
            LoaderObjectSecurityAuthorityV1::LauncherExplicit
            | LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary
            | LoaderObjectSecurityAuthorityV1::TargetAwareThread => {
                super::security::launcher_process_sddl()?
            }
        };
        let thread_sddl = match object_security_authority {
            LoaderObjectSecurityAuthorityV1::TargetAwareThread
            | LoaderObjectSecurityAuthorityV1::TargetAwareBoth => target_policy
                .as_ref()
                .expect("target-aware thread policy is captured")
                .thread_sddl()
                .to_owned(),
            LoaderObjectSecurityAuthorityV1::LauncherExplicit
            | LoaderObjectSecurityAuthorityV1::LauncherExplicitRestrictingSidCanary
            | LoaderObjectSecurityAuthorityV1::TargetAwareProcess => {
                super::security::launcher_thread_sddl()?
            }
        };
        let process_policy_sha256 = super::record::digest(process_sddl.as_bytes());
        let thread_policy_sha256 = super::record::digest(thread_sddl.as_bytes());
        let restricting_trustee_count = target_policy
            .as_ref()
            .map_or(0, |policy| policy.restricting_trustee_count);
        let target_logon_trustee = target_policy.is_some();
        let process_security = SecurityDescriptor::from_sddl(&process_sddl)?;
        let process_attributes = process_security.attributes(false);
        let thread_security = SecurityDescriptor::from_sddl(&thread_sddl)?;
        let thread_attributes = thread_security.attributes(false);
        let executable = super::package::installed_target_desktop_bootstrap();
        let bootstrap_image_sha256 =
            super::package::validate_installed_target_desktop_bootstrap_loader_control()?;
        let loader_control_action = "loader-control";
        let command_semantics_sha256 = loader_control_command_semantics_sha256(
            &executable,
            loader_control_action,
            exact_desktop,
            &bootstrap_image_sha256,
        );
        use std::os::windows::ffi::OsStrExt;
        let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
        application.push(0);
        let mut command_line = encode_command_line(&[
            executable.as_os_str().encode_wide().collect(),
            loader_control_action.encode_utf16().collect(),
            pipe_name.encode_utf16().collect(),
            nonce.encode_utf16().collect(),
            exact_desktop.encode_utf16().collect(),
        ]);
        command_line.push(0);
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        let mut loader_control_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();
        loader_control_desktop.push(0);
        startup.StartupInfo.lpDesktop = loader_control_desktop.as_mut_ptr();
        startup.lpAttributeList = attributes.raw();
        let mut environment =
            environment_source.into_environment(target_token, matrix_cell.environment)?;
        let install_root = super::package::install_root();
        let mut current_directory = install_root.as_os_str().encode_wide().collect::<Vec<_>>();
        current_directory.push(0);
        let mut process = PROCESS_INFORMATION::default();
        let creation_flags = if loader_debug_trace {
            CREATE_SUSPENDED
                | EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | DEBUG_ONLY_THIS_PROCESS
        } else {
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        };
        let created = unsafe {
            CreateProcessAsUserW(
                target_token,
                application.as_ptr(),
                command_line.as_mut_ptr(),
                &raw const process_attributes,
                &raw const thread_attributes,
                0,
                creation_flags,
                environment.pointer(),
                current_directory.as_ptr(),
                &raw const startup.StartupInfo,
                &raw mut process,
            )
        };
        let creation_error = (created == 0).then(io::Error::last_os_error);
        let environment_destruction = environment.destroy_userenv_after_create();
        if let Some(error) = creation_error {
            let destruction = environment_destruction
                .err()
                .map_or_else(|| "ok".to_owned(), |error| error.detail);
            return Err(TargetDesktopLeaseCreateError::from(format!(
                "CreateProcessAsUserW failed for exact-token loader-control: {error}; environment_destruction={destruction}",
            ))
            .at_loader_phase(LoaderLaunchFailurePhaseV1::CreateProcessReturn));
        }
        if let Err(error) = environment_destruction {
            let _control_process = OwnedHandle::new(process.hProcess)?;
            let _control_thread = OwnedHandle::new(process.hThread)?;
            return Err(error);
        }
        let control_process = OwnedHandle::new(process.hProcess)?;
        let control_thread = OwnedHandle::new(process.hThread)?;
        let mut debug_session = loader_debug_observer.map(|observer| {
            super::loader_debug::LoaderDebugSession::attach(
                control_process.raw(),
                &association_preflight.native_loader_access,
                observer,
            )
        });
        if let Some(session) = debug_session.as_mut() {
            if let Err(error) = session.assert_kill_on_exit() {
                let _ = session.terminate_and_drain(&control_job, control_process.raw());
                return Err(TargetDesktopLeaseCreateError::from(format!(
                    "loader-control certification debug setup failed: {error} {}",
                    session.trace().diagnostic()
                ))
                .at_loader_phase(LoaderLaunchFailurePhaseV1::PreResumeAttestation));
            }
        }
        let pre_resume_proof = (|| -> Result<_, TargetDesktopLeaseCreateError> {
            if !control_job.contains(control_process.raw())? {
                return Err("loader-control is absent from its atomic Job"
                    .to_owned()
                    .into());
            }
            process_security.verify_kernel_object(
                control_process.raw(),
                super::security::SecurityObjectKind::Process,
            )?;
            thread_security.verify_kernel_object(
                control_thread.raw(),
                super::security::SecurityObjectKind::Thread,
            )?;
            let process_object_security = SecurityDescriptor::live_kernel_object_security_evidence(
                control_process.raw(),
                super::security::SecurityObjectKind::Process,
                target_token,
                super::security::TARGET_KERNEL_PROCESS_DIAGNOSTIC_ACCESS,
            )?;
            let thread_object_security = SecurityDescriptor::live_kernel_object_security_evidence(
                control_thread.raw(),
                super::security::SecurityObjectKind::Thread,
                target_token,
                super::security::TARGET_KERNEL_THREAD_DIAGNOSTIC_ACCESS,
            )?;
            let observed_control_snapshot =
                super::token::process_token_query_attestation(control_process.raw())?;
            let target_source_after = super::token::token_attestation_snapshot(target_token)?;
            super::token::require_same_token_instance(
                "loader-control-target-request-invariance",
                &target_source_before,
                &target_source_after,
            )?;
            let _assignment = super::token::require_assigned_process_authority(
                "target-request-to-loader-control-process",
                &target_source_before,
                &observed_control_snapshot,
            )?;
            if observed_control_snapshot.behavior.envelope != *target_envelope {
                return Err("loader-control token envelope changed".to_owned().into());
            }
            let control_identity = process_identity(control_process.raw())?;
            verify_image_path(control_process.raw(), &executable)?;
            let target_pre_resume = super::token::token_attestation_snapshot(target_token)?;
            super::token::require_same_token_instance(
                "loader-control-target-request-pre-resume",
                target_snapshot,
                &target_pre_resume,
            )?;
            let launch_evidence = super::loader_debug::LoaderLaunchEvidenceV4 {
                matrix_cell: matrix_cell.diagnostic(),
                debug_mode: loader_debug_trace,
                environment_classification: environment.classification,
                environment_sha256: environment.sha256.clone(),
                environment_keys: environment.visible_keys.clone(),
                environment_keys_sha256: environment.keys_sha256.clone(),
                environment_units: environment.units,
                environment_entries: environment.entries,
                environment_profile_loaded: environment.profile_loaded,
                missing_required_environment: environment.missing_required.clone(),
                source_token_sha256: loader_snapshot_digest(
                    b"memcordon-loader-source-token-v4\0",
                    &target_source_before,
                )?,
                child_token_sha256: loader_snapshot_digest(
                    b"memcordon-loader-child-token-v4\0",
                    &observed_control_snapshot,
                )?,
                source_token_id: target_source_before.instance.token_id,
                child_token_id: observed_control_snapshot.instance.token_id,
                source_modified_id: target_source_before.instance.modified_id,
                child_modified_id: observed_control_snapshot.instance.modified_id,
                source_authentication_id: target_source_before.lineage.authentication_id,
                child_authentication_id: observed_control_snapshot.lineage.authentication_id,
                source_session_id: target_source_before.lineage.session_id,
                child_session_id: observed_control_snapshot.lineage.session_id,
                assigned_authority_attested: true,
                mitigation_diagnostic: mitigation_policy_diagnostic(control_process.raw()),
                job_membership_attested: true,
                desktop_sha256: super::record::digest(exact_desktop.as_bytes()),
                binary_sha256: bootstrap_image_sha256.clone(),
                current_directory_sha256: super::record::digest(
                    install_root
                        .to_string_lossy()
                        .to_ascii_lowercase()
                        .as_bytes(),
                ),
                command_semantics_sha256,
                creation_flags,
            };
            Ok((
                observed_control_snapshot,
                control_identity,
                launch_evidence,
                process_object_security,
                thread_object_security,
            ))
        })();
        let (
            observed_control_snapshot,
            control_identity,
            launch_evidence,
            process_object_security,
            thread_object_security,
        ) = match pre_resume_proof {
            Ok(proof) => proof,
            Err(error) => {
                if let Some(session) = debug_session.as_mut() {
                    let cleanup = session
                        .terminate_and_drain(&control_job, control_process.raw())
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| error);
                    return Err(format!(
                        "loader-control pre-resume proof failed detail={} cleanup={cleanup} {}",
                        error.detail,
                        session.trace().diagnostic()
                    )
                    .into());
                }
                return Err(error.at_loader_phase(LoaderLaunchFailurePhaseV1::PreResumeAttestation));
            }
        };
        if let Some(session) = debug_session.as_mut() {
            session.bind_launch_evidence(launch_evidence.clone());
        }
        let _passive_access_subject = passive_access_localization
            .map(|(observer, cell)| {
                observer.bind_suspended_child(
                    cell,
                    control_process.raw(),
                    control_identity.process_id,
                    control_identity.creation_time_100ns,
                )
            })
            .transpose()
            .map_err(|error| {
                TargetDesktopLeaseCreateError::from(error)
                    .at_loader_phase(LoaderLaunchFailurePhaseV1::PreResumeAttestation)
            })?;
        if unsafe { ResumeThread(control_thread.raw()) } != 1 {
            let error = format!(
                "loader-control primary thread did not resume exactly once: {}",
                io::Error::last_os_error(),
            );
            if let Some(session) = debug_session.as_mut() {
                let cleanup = session
                    .terminate_and_drain(&control_job, control_process.raw())
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error);
                return Err(TargetDesktopLeaseCreateError::from(format!(
                    "{error} cleanup={cleanup} {}",
                    session.trace().diagnostic()
                ))
                .at_loader_phase(LoaderLaunchFailurePhaseV1::PreResumeAttestation));
            }
            return Err(TargetDesktopLeaseCreateError::from(error)
                .at_loader_phase(LoaderLaunchFailurePhaseV1::PreResumeAttestation));
        }
        drop(control_thread);
        let deadline = Instant::now() + Duration::from_secs(30);
        let connection_result = if let Some(session) = debug_session.as_mut() {
            match super::pipe::PendingTargetDesktopBootstrapAccept::start(prepared_pipe) {
                Ok(pending) => {
                    match session.accept_pipe(pending, control_process.raw(), deadline) {
                        Ok(super::loader_debug::LoaderDebugAcceptOutcome::Connected(
                            connection,
                        )) => Ok(connection),
                        Ok(super::loader_debug::LoaderDebugAcceptOutcome::Exited(exit_code)) => {
                            Err(super::pipe::target_desktop_bootstrap_peer_exit_error(
                                super::pipe::TargetDesktopBootstrapPipeOperation::Accept,
                                "connect",
                                0,
                                exit_code,
                            ))
                        }
                        Err(detail) => {
                            let cleanup = session
                                .terminate_and_drain(&control_job, control_process.raw())
                                .err()
                                .map_or_else(|| "ok".to_owned(), |error| error);
                            Err(super::pipe::TargetDesktopBootstrapPipeError::protocol(
                                super::pipe::TargetDesktopBootstrapPipeOperation::Accept,
                                format!(
                                    "loader debug accept failed detail={detail} cleanup={cleanup} {}",
                                    session.trace().diagnostic()
                                ),
                            ))
                        }
                    }
                }
                Err(error) => {
                    let cleanup = session
                        .terminate_and_drain(&control_job, control_process.raw())
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| error);
                    Err(super::pipe::TargetDesktopBootstrapPipeError::protocol(
                        super::pipe::TargetDesktopBootstrapPipeOperation::Accept,
                        format!(
                            "pending debug accept failed detail={error} cleanup={cleanup} {}",
                            session.trace().diagnostic()
                        ),
                    ))
                }
            }
        } else {
            super::pipe::accept_target_desktop_bootstrap_pipe(
                prepared_pipe,
                control_process.raw(),
                deadline,
            )
        };
        let connection = connection_result.map_err(|error| {
            let outcome = error.native_code().map_or_else(
                || "pre-bootstrap-connect-exit:unavailable".to_owned(),
                |code| format!("pre-bootstrap-connect-exit:{:#010x}", code as u32),
            );
            launch_context.accept_error(
                TargetDesktopBootstrapRoleV1::LoaderControl,
                control_identity.process_id,
                &bootstrap_image_sha256,
                &format!(
                    "attested-private-sha256:{}",
                    super::record::digest(exact_desktop.as_bytes())
                ),
                &format!(
                    "loader_control={outcome} object_security_authority={} process_policy_sha256={} thread_policy_sha256={} target_logon_trustee={} restricting_trustee_count={} descriptor_readback=true {} {} {} {}{}",
                    object_security_authority.diagnostic(),
                    process_policy_sha256,
                    thread_policy_sha256,
                    target_logon_trustee,
                    restricting_trustee_count,
                    association_preflight.diagnostic(),
                    launch_evidence.diagnostic(),
                    process_object_security.diagnostic("process_object"),
                    thread_object_security.diagnostic("thread_object"),
                    debug_session
                        .as_ref()
                        .map_or_else(String::new, |session| format!(
                            " {}",
                            session.trace().diagnostic()
                        )),
                ),
                error,
            )
        })?;
        let protocol_result = (|| -> Result<(), TargetDesktopLeaseCreateError> {
            authenticate_target_desktop_bootstrap_client(
                connection.raw(),
                control_process.raw(),
                &control_job,
                &control_identity,
                target_envelope,
                &observed_control_snapshot,
                &executable,
            )?;
            let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
                connection.raw(),
                Some(control_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
            )?;
            match loader_ready {
                TargetDesktopBootstrapMessageV1::LoaderReady {
                    schema_version,
                    nonce: observed_nonce,
                    expected_desktop: observed_desktop,
                    bootstrap_identity,
                    process_envelope,
                    process_snapshot,
                } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                    && observed_nonce == nonce
                    && observed_desktop.as_deref() == Some(exact_desktop)
                    && bootstrap_identity == control_identity
                    && process_envelope == *target_envelope
                    && process_snapshot == observed_control_snapshot => {}
                _ => {
                    return Err("loader-control LoaderReady frame is invalid"
                        .to_owned()
                        .into());
                }
            }
            if object_security_authority.diagnostic_only() {
                control_job.terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS)?;
                return Ok(());
            }
            super::pipe::write_frame_bounded(
                connection.raw(),
                Some(control_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::LoaderControlReleaseWrite,
                &TargetDesktopBootstrapMessageV1::LoaderControlRelease {
                    schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
                    nonce,
                    expected_desktop: exact_desktop.to_owned(),
                },
            )?;
            Ok(())
        })();
        drop(connection);
        if let Err(error) = protocol_result {
            if let Some(session) = debug_session.as_mut() {
                let cleanup = session
                    .terminate_and_drain(&control_job, control_process.raw())
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error);
                return Err(format!(
                    "loader-control debug protocol failed detail={} cleanup={cleanup} {}",
                    error.detail,
                    session.trace().diagnostic()
                )
                .into());
            }
            return Err(error.at_loader_phase(LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady));
        }
        if object_security_authority.diagnostic_only() {
            if let Some(session) = debug_session.as_mut() {
                if let Err(error) = session.drain_until_exit(
                    control_process.raw(),
                    Instant::now() + Duration::from_secs(30),
                ) {
                    let cleanup = session
                        .terminate_and_drain(&control_job, control_process.raw())
                        .err()
                        .map_or_else(|| "ok".to_owned(), |error| error);
                    return Err(TargetDesktopLeaseCreateError::from(format!(
                        "diagnostic loader-control debug drain failed detail={error} cleanup={cleanup} {}",
                        session.trace().diagnostic()
                    ))
                    .at_loader_phase(LoaderLaunchFailurePhaseV1::PostLoaderReadyContainment));
                }
            } else if unsafe { WaitForSingleObject(control_process.raw(), 30_000) } != WAIT_OBJECT_0
            {
                return Err(TargetDesktopLeaseCreateError::from(
                    "object-security canary did not terminate after LoaderReady".to_owned(),
                )
                .at_loader_phase(LoaderLaunchFailurePhaseV1::PostLoaderReadyContainment));
            }
            if !control_job.wait_empty(Instant::now() + Duration::from_secs(30))? {
                return Err(TargetDesktopLeaseCreateError::from(
                    "object-security canary Job did not become empty".to_owned(),
                )
                .at_loader_phase(LoaderLaunchFailurePhaseV1::PostLoaderReadyContainment));
            }
            return Ok(format!(
                "loader_control_cell=v5 cell={} debug_observer={} object_security_authority={} process_policy_sha256={} thread_policy_sha256={} target_logon_trustee={} restricting_trustee_count={} phase=loader-ready-contained {} {} {} descriptor_readback=true job_empty=true workload_executed=false qualification_promoted=false{}",
                matrix_cell.diagnostic(),
                loader_debug_observer.map_or("none", |observer| observer.diagnostic()),
                object_security_authority.diagnostic(),
                process_policy_sha256,
                thread_policy_sha256,
                target_logon_trustee,
                restricting_trustee_count,
                launch_evidence.diagnostic(),
                process_object_security.diagnostic("process_object"),
                thread_object_security.diagnostic("thread_object"),
                debug_session.as_ref().map_or_else(String::new, |session| {
                    format!(" {}", session.trace().diagnostic())
                }),
            ));
        }
        if let Some(session) = debug_session.as_mut() {
            if let Err(error) = session.drain_until_exit(
                control_process.raw(),
                Instant::now() + Duration::from_secs(30),
            ) {
                let cleanup = session
                    .terminate_and_drain(&control_job, control_process.raw())
                    .err()
                    .map_or_else(|| "ok".to_owned(), |error| error);
                return Err(TargetDesktopLeaseCreateError::from(format!(
                    "loader-control debug exit drain failed detail={error} cleanup={cleanup} {}",
                    session.trace().diagnostic()
                ))
                .at_loader_phase(LoaderLaunchFailurePhaseV1::ExitDrain));
            }
        } else if unsafe { WaitForSingleObject(control_process.raw(), 30_000) } != WAIT_OBJECT_0 {
            return Err(TargetDesktopLeaseCreateError::from(
                "loader-control did not exit after release".to_owned(),
            )
            .at_loader_phase(LoaderLaunchFailurePhaseV1::ExitDrain));
        }
        let mut exit_code = 0_u32;
        if unsafe { GetExitCodeProcess(control_process.raw(), &raw mut exit_code) } == 0
            || exit_code != 0
        {
            return Err(TargetDesktopLeaseCreateError::from(format!(
                "loader-control exited unsuccessfully: {exit_code:#010x}"
            ))
            .at_loader_phase(LoaderLaunchFailurePhaseV1::ExitDrain));
        }
        if !control_job.wait_empty(Instant::now() + Duration::from_secs(30))? {
            return Err("loader-control Job did not become empty".to_owned().into());
        }
        Ok(format!(
            "loader_control_cell=v5 cell={} debug_observer={} object_security_authority={} process_policy_sha256={} thread_policy_sha256={} target_logon_trustee={} restricting_trustee_count={} phase=loader-ready-and-clean-exit exit=0x00000000 exit_status_symbol=STATUS_SUCCESS {} {} {}{}",
            matrix_cell.diagnostic(),
            loader_debug_observer.map_or("none", |observer| observer.diagnostic()),
            object_security_authority.diagnostic(),
            process_policy_sha256,
            thread_policy_sha256,
            target_logon_trustee,
            restricting_trustee_count,
            launch_evidence.diagnostic(),
            process_object_security.diagnostic("process_object"),
            thread_object_security.diagnostic("thread_object"),
            debug_session
                .as_ref()
                .map_or_else(String::new, |session| format!(
                    " {}",
                    session.trace().diagnostic()
                )),
        ))
    })();
    if profile_lease_cell && cell_result.is_err() {
        let mut cleanup = Vec::new();
        match control_job.wait_empty(Instant::now()) {
            Ok(true) => cleanup.push("job_empty_before_termination=true".to_owned()),
            Ok(false) => {
                cleanup.push("job_empty_before_termination=false".to_owned());
                if let Err(error) = control_job.terminate(TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) {
                    cleanup.push(format!("terminate_error={error}"));
                }
            }
            Err(error) => cleanup.push(format!("job_empty_query_error={error}")),
        }
        match control_job.wait_empty(Instant::now() + Duration::from_secs(30)) {
            Ok(true) => cleanup.push("job_empty_after_cleanup=true".to_owned()),
            Ok(false) => cleanup.push("job_empty_after_cleanup=false".to_owned()),
            Err(error) => cleanup.push(format!("job_empty_wait_error={error}")),
        }
        if let Err(error) = &mut cell_result {
            error.detail = preserve_loader_profile_primary_detail(&error.detail, &cleanup);
        }
    }
    cell_result
}

#[allow(clippy::too_many_arguments)]
fn launch_target_desktop_probe(
    target_token: HANDLE,
    target_envelope: &WindowsCallerTokenEnvelopeV1,
    launcher_token: &OwnedHandle,
    launcher_envelope: &WindowsCallerTokenEnvelopeV1,
    launcher_process_snapshot: &super::token::TokenAttestationSnapshot,
    broker_source_snapshot: &super::token::TokenAttestationSnapshot,
    holder_launch_snapshot: &super::token::TokenAttestationSnapshot,
    holder_process_snapshot: &super::token::TokenQueryAttestationSnapshot,
    target_snapshot: &super::token::TokenAttestationSnapshot,
    launcher_identity: &WindowsProcessIdentityV1,
    policy_role: super::security::TargetUserObjectPolicyRoleV1,
    exact_desktop: &str,
    expected_station_policy_sha256: &str,
    expected_desktop_policy_sha256: &str,
    launch_context: &TargetDesktopBootstrapLaunchContext,
    holder_lease: &TargetDesktopLease,
    loader_restriction_canary: Option<&LoaderRestrictionCanaryTokens>,
) -> Result<(), TargetDesktopLeaseCreateError> {
    let target_source_before = super::token::token_attestation_snapshot(target_token)?;
    super::token::require_same_token_instance(
        "probe-target-request-preflight",
        target_snapshot,
        &target_source_before,
    )?;
    holder_lease
        .attest_live()
        .map_err(TargetDesktopLeaseCreateError::from)?;
    let association_preflight = request_holder_target_association_preflight(
        holder_lease,
        target_snapshot,
        expected_station_policy_sha256,
        expected_desktop_policy_sha256,
    )?;
    holder_lease
        .attest_live()
        .map_err(TargetDesktopLeaseCreateError::from)?;
    launch_target_desktop_loader_control(
        target_token,
        target_envelope,
        target_snapshot,
        exact_desktop,
        launch_context,
        &association_preflight,
        &holder_lease.bootstrap_identity,
        loader_restriction_canary,
    )?;
    holder_lease
        .attest_live()
        .map_err(TargetDesktopLeaseCreateError::from)?;
    let nonce = target_desktop_nonce()?;
    let pipe_name = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        nonce,
    );
    let pipe_security = SecurityDescriptor::from_sddl(
        &super::security::target_desktop_bootstrap_pipe_sddl(target_token)?,
    )?;
    let prepared_pipe =
        super::pipe::prepare_target_desktop_bootstrap_pipe(&pipe_name, &pipe_security)?;
    clear_inherit(prepared_pipe.raw())?;
    verify_not_inheritable(prepared_pipe.raw())?;
    let probe_job = Job::create(None, None, None)?;
    let jobs = [probe_job.handle()];
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            jobs.as_ptr().cast(),
            std::mem::size_of_val(&jobs),
        )],
        None,
    )?;
    let process_security =
        SecurityDescriptor::from_sddl(&super::security::launcher_process_sddl()?)?;
    let process_attributes = process_security.attributes(false);
    let thread_security = SecurityDescriptor::from_sddl(&super::security::launcher_thread_sddl()?)?;
    let thread_attributes = thread_security.attributes(false);
    let executable = super::package::installed_target_desktop_bootstrap();
    let bootstrap_image_sha256 = super::package::validate_installed_target_desktop_bootstrap()?;
    use std::os::windows::ffi::OsStrExt;
    let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    application.push(0);
    let mut command_line = encode_command_line(&[
        executable.as_os_str().encode_wide().collect(),
        "probe".encode_utf16().collect(),
        pipe_name.encode_utf16().collect(),
        nonce.encode_utf16().collect(),
        exact_desktop.encode_utf16().collect(),
    ]);
    command_line.push(0);
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    let mut startup_desktop = exact_desktop.encode_utf16().collect::<Vec<_>>();
    startup_desktop.push(0);
    startup.StartupInfo.lpDesktop = startup_desktop.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut environment = [0_u16, 0_u16];
    let install_root = super::package::install_root();
    let mut current_directory = install_root.as_os_str().encode_wide().collect::<Vec<_>>();
    current_directory.push(0);
    let mut process = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessAsUserW(
            target_token,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            &raw const process_attributes,
            &raw const thread_attributes,
            0,
            CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
            environment.as_mut_ptr().cast(),
            current_directory.as_ptr(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(format!(
            "CreateProcessAsUserW failed for exact-token desktop probe: {}",
            io::Error::last_os_error(),
        )
        .into());
    }
    let probe_process = OwnedHandle::new(process.hProcess)?;
    let probe_thread = OwnedHandle::new(process.hThread)?;
    if !probe_job.contains(probe_process.raw())? {
        return Err("restricted desktop probe is absent from its atomic Job"
            .to_owned()
            .into());
    }
    process_security.verify_kernel_object(
        probe_process.raw(),
        super::security::SecurityObjectKind::Process,
    )?;
    thread_security.verify_kernel_object(
        probe_thread.raw(),
        super::security::SecurityObjectKind::Thread,
    )?;
    let observed_probe_snapshot =
        super::token::process_token_query_attestation(probe_process.raw())?;
    let target_source_after = super::token::token_attestation_snapshot(target_token)?;
    super::token::require_same_token_instance(
        "probe-target-request-invariance",
        &target_source_before,
        &target_source_after,
    )?;
    let probe_assignment = super::token::require_assigned_process_authority(
        "target-request-to-probe-process",
        &target_source_before,
        &observed_probe_snapshot,
    )?;
    if observed_probe_snapshot.behavior.envelope != *target_envelope {
        return Err("restricted desktop probe token envelope changed"
            .to_owned()
            .into());
    }
    let probe_identity = process_identity(probe_process.raw())?;
    verify_image_path(probe_process.raw(), &executable)?;
    let launcher_process_handle =
        duplicate_remote_process_query(unsafe { GetCurrentProcess() }, probe_process.raw())?;
    let launcher_token_handle =
        duplicate_remote_token_query(launcher_token.raw(), probe_process.raw())?;
    let binding = TargetDesktopBootstrapBindingV3 {
        schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
        role: TargetDesktopBootstrapRoleV1::Probe,
        target_user_object_policy_role: policy_role,
        nonce: nonce.clone(),
        binding_sha256: String::new(),
        bootstrap_image_sha256: bootstrap_image_sha256.clone(),
        launcher_identity: launcher_identity.clone(),
        launcher_session_id: launcher_envelope.session_id,
        launcher_envelope: launcher_envelope.clone(),
        launcher_process_snapshot: launcher_process_snapshot.clone(),
        broker_source_snapshot: broker_source_snapshot.clone(),
        holder_launch_snapshot: holder_launch_snapshot.clone(),
        holder_assignment: super::token::require_assigned_process_authority(
            "holder-launch-to-process",
            holder_launch_snapshot,
            holder_process_snapshot,
        )?,
        bootstrap_identity: probe_identity.clone(),
        bootstrap_envelope: target_envelope.clone(),
        bootstrap_process_snapshot: observed_probe_snapshot.clone(),
        bootstrap_assignment: probe_assignment,
        holder_process_snapshot: holder_process_snapshot.clone(),
        target_envelope: target_envelope.clone(),
        target_request_snapshot: target_snapshot.clone(),
    }
    .seal()?;
    let target_pre_resume = super::token::token_attestation_snapshot(target_token)?;
    super::token::require_same_token_instance(
        "probe-target-request-pre-resume",
        target_snapshot,
        &target_pre_resume,
    )?;
    let deadline = Instant::now() + Duration::from_secs(30);
    if unsafe { ResumeThread(probe_thread.raw()) } != 1 {
        return Err(format!(
            "restricted desktop probe primary thread did not resume exactly once: {}",
            io::Error::last_os_error(),
        )
        .into());
    }
    drop(probe_thread);
    let connection = super::pipe::accept_target_desktop_bootstrap_pipe(
        prepared_pipe,
        probe_process.raw(),
        deadline,
    )
    .map_err(|error| {
        launch_context.accept_error(
            TargetDesktopBootstrapRoleV1::Probe,
            probe_identity.process_id,
            &bootstrap_image_sha256,
            &format!(
                "nonce-private-sha256:{}",
                super::record::digest(exact_desktop.as_bytes())
            ),
            &format!(
                "loader_control=loader-ready loader_control_desktop_sha256={} {}",
                super::record::digest(exact_desktop.as_bytes()),
                association_preflight.diagnostic()
            ),
            error,
        )
    })?;
    authenticate_target_desktop_bootstrap_client(
        connection.raw(),
        probe_process.raw(),
        &probe_job,
        &probe_identity,
        target_envelope,
        &observed_probe_snapshot,
        &executable,
    )?;
    let loader_ready: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
        connection.raw(),
        Some(probe_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyRead,
    )?;
    match loader_ready {
        TargetDesktopBootstrapMessageV1::LoaderReady {
            schema_version,
            nonce: observed_nonce,
            expected_desktop: observed_desktop,
            bootstrap_identity,
            process_envelope,
            process_snapshot,
        } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
            && observed_nonce == nonce
            && observed_desktop.as_deref() == Some(exact_desktop)
            && bootstrap_identity == probe_identity
            && process_envelope == *target_envelope
            && process_snapshot == observed_probe_snapshot => {}
        _ => {
            return Err("restricted desktop probe LoaderReady frame is invalid"
                .to_owned()
                .into());
        }
    }
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(probe_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionWrite,
        &TargetDesktopBootstrapMessageV1::Admission {
            binding: binding.clone(),
            launcher_process_query_handle: launcher_process_handle,
            launcher_token_query_handle: launcher_token_handle,
            target_token_capability_handle: None,
        },
    )?;
    let frame = read_target_desktop_bootstrap_attestation(
        connection.raw(),
        probe_process.raw(),
        deadline,
        &binding,
        None,
    )?;
    let (expected_station, expected_desktop) = exact_desktop.split_once('\\').ok_or_else(|| {
        TargetDesktopLeaseCreateError::from("probe desktop is not qualified".to_owned())
    })?;
    if frame.bootstrap_identity != probe_identity
        || frame.target_envelope != *target_envelope
        || frame.window_station_name != expected_station
        || frame.desktop_name != expected_desktop
        || frame.window_station_policy_sha256 != expected_station_policy_sha256
        || frame.desktop_policy_sha256 != expected_desktop_policy_sha256
        || frame.window_station_policy_sha256 != holder_lease.window_station_policy_sha256
        || frame.desktop_policy_sha256 != holder_lease.desktop_policy_sha256
        || frame.window_station_live_equality_sha256
            != holder_lease.window_station_live_equality_sha256
        || frame.desktop_live_equality_sha256 != holder_lease.desktop_live_equality_sha256
        || !frame.private_station_assigned
        || !frame.private_desktop_assigned
        || !frame.window_station_policy_verified
        || !frame.desktop_policy_verified
        || !frame.noninteractive
    {
        return Err(
            "restricted desktop probe attestation is incomplete or mismatched"
                .to_owned()
                .into(),
        );
    }
    drop(connection);
    if unsafe { WaitForSingleObject(probe_process.raw(), 30_000) } != WAIT_OBJECT_0 {
        return Err("restricted desktop probe did not exit after attestation"
            .to_owned()
            .into());
    }
    let mut exit_code = 0_u32;
    if unsafe { GetExitCodeProcess(probe_process.raw(), &raw mut exit_code) } == 0 || exit_code != 0
    {
        return Err(
            format!("restricted desktop probe exited unsuccessfully: {exit_code:#010x}").into(),
        );
    }
    if !probe_job.wait_empty(Instant::now() + Duration::from_secs(30))? {
        return Err("restricted desktop probe Job did not become empty"
            .to_owned()
            .into());
    }
    Ok(())
}

fn read_target_desktop_bootstrap_attestation(
    pipe: HANDLE,
    process: HANDLE,
    deadline: Instant,
    expected_binding: &TargetDesktopBootstrapBindingV3,
    mut broker_control: Option<&mut super::session_broker::BrokerControlLease>,
) -> Result<TargetDesktopBootstrapFrameV1, TargetDesktopLeaseCreateError> {
    let first = super::pipe::read_frame_bounded(
        pipe,
        Some(process),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::StartedRead,
    )
    .map_err(TargetDesktopLeaseCreateError::from)?;
    match first {
        TargetDesktopBootstrapMessageV1::Failed {
            binding,
            phase,
            native_code,
            detail,
        } => Err(validate_target_desktop_bootstrap_failure(
            "await-started",
            binding,
            expected_binding,
            phase,
            native_code,
            detail,
        )),
        TargetDesktopBootstrapMessageV1::Started {
            binding,
            phase: TargetDesktopBootstrapPhaseV1::EndpointAdmission,
        } if binding == *expected_binding => {
            let mut pending = None;
            let mut completed = 0_u32;
            loop {
                match super::pipe::read_frame_bounded(
                    pipe,
                    Some(process),
                    Instant::now() + Duration::from_secs(30),
                    super::pipe::TargetDesktopBootstrapPipeOperation::TerminalRead,
                )
                .map_err(TargetDesktopLeaseCreateError::from)?
                {
                    TargetDesktopBootstrapMessageV1::Ready {
                        binding,
                        attestation,
                    } if binding == *expected_binding && pending.is_none() => {
                        if broker_control.is_some() && completed != 2 {
                            return Err(TargetDesktopLeaseCreateError::from(
                                "holder published Ready before both broker Cleared proofs"
                                    .to_owned(),
                            ));
                        }
                        return Ok(attestation);
                    }
                    TargetDesktopBootstrapMessageV1::Failed {
                        binding,
                        phase,
                        native_code,
                        detail,
                    } if pending.is_none() => {
                        return Err(validate_target_desktop_bootstrap_failure(
                            "after-started",
                            binding,
                            expected_binding,
                            phase,
                            native_code,
                            detail,
                        ));
                    }
                    TargetDesktopBootstrapMessageV1::CreationReady {
                        binding,
                        phase,
                        ordinal,
                        thread_id,
                        holder_primary,
                    } if binding == *expected_binding
                        && pending.is_none()
                        && target_desktop_creation_transition_is_expected(
                            completed, phase, ordinal, thread_id,
                        )
                        && holder_primary == expected_binding.holder_process_snapshot =>
                    {
                        let control = broker_control.as_deref_mut().ok_or_else(|| {
                            TargetDesktopLeaseCreateError::from(
                                "probe attempted a broker creation-arm transition".to_owned(),
                            )
                        })?;
                        let carrier = control.arm(
                            &expected_binding.binding_sha256,
                            phase,
                            ordinal,
                            thread_id,
                            &holder_primary,
                        )?;
                        super::pipe::write_frame_bounded(
                            pipe,
                            Some(process),
                            Instant::now() + Duration::from_secs(30),
                            super::pipe::TargetDesktopBootstrapPipeOperation::CreationArmedWrite,
                            &TargetDesktopBootstrapMessageV1::CreationArmed {
                                binding: expected_binding.clone(),
                                phase,
                                ordinal,
                                thread_id,
                                carrier,
                            },
                        )?;
                        pending = Some((phase, ordinal, thread_id));
                    }
                    TargetDesktopBootstrapMessageV1::CreationConsumed {
                        binding,
                        phase,
                        ordinal,
                        thread_id,
                        holder_primary,
                        native_code,
                        thread_token_absent,
                    } if binding == *expected_binding
                        && pending == Some((phase, ordinal, thread_id))
                        && holder_primary == expected_binding.holder_process_snapshot =>
                    {
                        let control = broker_control.as_deref_mut().ok_or_else(|| {
                            TargetDesktopLeaseCreateError::from(
                                "probe attempted a broker creation-consume transition".to_owned(),
                            )
                        })?;
                        control.consumed(
                            &expected_binding.binding_sha256,
                            phase,
                            ordinal,
                            thread_id,
                            &holder_primary,
                            native_code,
                            thread_token_absent,
                        )?;
                        super::pipe::write_frame_bounded(
                            pipe,
                            Some(process),
                            Instant::now() + Duration::from_secs(30),
                            super::pipe::TargetDesktopBootstrapPipeOperation::CreationClearedWrite,
                            &TargetDesktopBootstrapMessageV1::CreationCleared {
                                binding: expected_binding.clone(),
                                phase,
                                ordinal,
                                thread_id,
                            },
                        )?;
                        pending = None;
                        completed = ordinal;
                    }
                    _ => {
                        return Err(TargetDesktopLeaseCreateError::from(
                            "target desktop bootstrap frame is invalid or out of order".to_owned(),
                        ));
                    }
                }
            }
        }
        _ => Err(TargetDesktopLeaseCreateError::from(
            "target desktop bootstrap Started frame is invalid or out of order".to_owned(),
        )),
    }
}

fn target_desktop_creation_transition_is_expected(
    completed: u32,
    phase: super::session_broker::SessionCreationPhaseV1,
    ordinal: u32,
    thread_id: u32,
) -> bool {
    thread_id != 0
        && matches!(
            (completed, phase, ordinal),
            (
                0,
                super::session_broker::SessionCreationPhaseV1::WindowStation,
                1
            ) | (1, super::session_broker::SessionCreationPhaseV1::Desktop, 2)
        )
}

#[cfg(test)]
pub(crate) fn target_desktop_creation_transition_for_test(
    completed: u32,
    desktop: bool,
    ordinal: u32,
    thread_id: u32,
) -> bool {
    target_desktop_creation_transition_is_expected(
        completed,
        if desktop {
            super::session_broker::SessionCreationPhaseV1::Desktop
        } else {
            super::session_broker::SessionCreationPhaseV1::WindowStation
        },
        ordinal,
        thread_id,
    )
}

fn validate_target_desktop_bootstrap_failure(
    state: &'static str,
    binding: TargetDesktopBootstrapBindingV3,
    expected_binding: &TargetDesktopBootstrapBindingV3,
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
) -> TargetDesktopLeaseCreateError {
    validate_target_desktop_bootstrap_failure_evidence(
        state,
        binding == *expected_binding,
        phase,
        native_code,
        detail,
    )
}

fn validate_target_desktop_bootstrap_failure_evidence(
    state: &'static str,
    binding_matches: bool,
    phase: TargetDesktopBootstrapPhaseV1,
    native_code: Option<i32>,
    detail: String,
) -> TargetDesktopLeaseCreateError {
    if !binding_matches
        || detail.is_empty()
        || detail.len() > TARGET_DESKTOP_BOOTSTRAP_DETAIL_MAX_BYTES
    {
        return TargetDesktopLeaseCreateError::from(
            "target desktop bootstrap failure frame is invalid".to_owned(),
        );
    }
    TargetDesktopLeaseCreateError {
        detail: format!(
            "target desktop bootstrap rejected: state={state} phase={} native_code={native_code:?} detail={detail}",
            phase.diagnostic(),
        ),
        os_code: native_code,
        loader_phase: LoaderLaunchFailurePhaseV1::PostResumePreLoaderReady,
    }
}

#[cfg(test)]
pub(crate) fn target_desktop_bootstrap_failure_transition_for_test(
    state: &'static str,
    binding_matches: bool,
    native_code: Option<i32>,
    detail: String,
) -> (String, Option<i32>) {
    let error = validate_target_desktop_bootstrap_failure_evidence(
        state,
        binding_matches,
        TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
        native_code,
        detail,
    );
    (error.detail, error.os_code)
}

fn target_desktop_bootstrap_client_identity(pipe: HANDLE) -> Result<(u32, u32), String> {
    let mut process_id = 0_u32;
    let mut session_id = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut process_id) } == 0
        || unsafe { GetNamedPipeClientSessionId(pipe, &raw mut session_id) } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok((process_id, session_id))
}

fn authenticate_target_desktop_bootstrap_client(
    pipe: HANDLE,
    process: HANDLE,
    job: &Job,
    expected_identity: &WindowsProcessIdentityV1,
    expected_envelope: &WindowsCallerTokenEnvelopeV1,
    expected_snapshot: &super::token::TokenQueryAttestationSnapshot,
    executable: &Path,
) -> Result<(), String> {
    let before = target_desktop_bootstrap_client_identity(pipe)?;
    if before != (expected_identity.process_id, expected_envelope.session_id)
        || process_identity(process)? != *expected_identity
        || !job.contains(process)?
    {
        return Err("target desktop bootstrap pipe client identity is mismatched".to_owned());
    }
    let token = super::token::process_token(process)?;
    if super::token::envelope(token.raw())? != *expected_envelope
        || super::token::token_query_attestation_snapshot(token.raw())? != *expected_snapshot
    {
        return Err("target desktop bootstrap pipe client token is mismatched".to_owned());
    }
    verify_image_path(process, executable)?;
    if target_desktop_bootstrap_client_identity(pipe)? != before
        || process_identity(process)? != *expected_identity
        || !job.contains(process)?
    {
        return Err(
            "target desktop bootstrap pipe client changed during authentication".to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn validate_target_desktop_binding(
    window_station: &str,
    desktop: &str,
) -> Result<(), String> {
    validate_desktop_binding_names(window_station, desktop)?;
    let nonce = window_station
        .strip_prefix("MemCordonTarget-")
        .ok_or_else(|| "private target window station has the wrong role prefix".to_owned())?;
    if nonce.len() != TARGET_DESKTOP_NONCE_BYTES * 2
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("private target window station nonce is not 256-bit lowercase hex".to_owned());
    }
    if desktop != "Restricted" {
        return Err("private target desktop has the wrong fixed role name".to_owned());
    }
    Ok(())
}

pub(crate) fn validate_target_desktop_input_state(receives_input: bool) -> Result<(), String> {
    if receives_input {
        Err("private target desktop unexpectedly receives interactive input".to_owned())
    } else {
        Ok(())
    }
}

pub(super) fn target_desktop_bootstrap(
    pipe_name: &std::ffi::OsStr,
    nonce: &std::ffi::OsStr,
    role: TargetDesktopBootstrapRoleV1,
    expected_desktop: Option<&std::ffi::OsStr>,
) -> Result<(), String> {
    let pipe_name = pipe_name
        .to_str()
        .ok_or_else(|| "target desktop bootstrap pipe name is not UTF-8".to_owned())?;
    let nonce = nonce
        .to_str()
        .ok_or_else(|| "target desktop bootstrap nonce is not UTF-8".to_owned())?;
    validate_target_desktop_bootstrap_nonce(nonce)?;
    if pipe_name
        != format!(
            "{}{}",
            super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
            nonce
        )
    {
        return Err("target desktop bootstrap pipe name is not canonical".to_owned());
    }
    let expected_desktop_name = match (role, expected_desktop) {
        (TargetDesktopBootstrapRoleV1::Holder, None) => None,
        (
            TargetDesktopBootstrapRoleV1::LoaderControl | TargetDesktopBootstrapRoleV1::Probe,
            Some(exact_desktop),
        ) => {
            let exact_desktop = exact_desktop.to_str().ok_or_else(|| {
                "target desktop bootstrap expected desktop is not UTF-8".to_owned()
            })?;
            let (window_station, desktop) = exact_desktop.split_once('\\').ok_or_else(|| {
                "target desktop bootstrap expected desktop is not qualified".to_owned()
            })?;
            validate_target_desktop_binding(window_station, desktop)?;
            Some(exact_desktop.to_owned())
        }
        _ => {
            return Err(
                "target desktop bootstrap role has an invalid desktop selection".to_owned(),
            );
        }
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let process_token = match role {
        TargetDesktopBootstrapRoleV1::Holder => {
            super::token::current_process_token_for_access_check()
        }
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::token::current_process_token_for_attestation_and_access_check()
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            super::token::current_process_token_for_attestation_and_access_check()
        }
    }?;
    let connection = super::pipe::connect_target_desktop_bootstrap_pipe(pipe_name, deadline)?;
    clear_inherit(connection.raw())?;
    verify_not_inheritable(connection.raw())?;
    let bootstrap_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let process_envelope = super::token::envelope(process_token.raw())?;
    let process_snapshot = super::token::token_query_attestation_snapshot(process_token.raw())?;
    super::pipe::write_frame_bounded(
        connection.raw(),
        None,
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::LoaderReadyWrite,
        &TargetDesktopBootstrapMessageV1::LoaderReady {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            nonce: nonce.to_owned(),
            expected_desktop: expected_desktop_name.clone(),
            bootstrap_identity,
            process_envelope: process_envelope.clone(),
            process_snapshot: process_snapshot.clone(),
        },
    )
    .map_err(|error| error.to_string())?;
    if role == TargetDesktopBootstrapRoleV1::LoaderControl {
        let release: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
            connection.raw(),
            None,
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::LoaderControlReleaseRead,
        )
        .map_err(|error| error.to_string())?;
        return match release {
            TargetDesktopBootstrapMessageV1::LoaderControlRelease {
                schema_version,
                nonce: observed_nonce,
                expected_desktop: observed_desktop,
            } if schema_version == TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
                && observed_nonce == nonce
                && Some(observed_desktop.as_str()) == expected_desktop_name.as_deref() =>
            {
                Ok(())
            }
            _ => Err("loader-control received an invalid or out-of-order release frame".to_owned()),
        };
    }
    let admission: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
        connection.raw(),
        None,
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::AdmissionRead,
    )
    .map_err(|error| error.to_string())?;
    let (binding, launcher_process_handle, launcher_token_handle, target_token_handle) =
        match admission {
            TargetDesktopBootstrapMessageV1::Admission {
                binding,
                launcher_process_query_handle,
                launcher_token_query_handle,
                target_token_capability_handle,
            } => (
                binding,
                launcher_process_query_handle,
                launcher_token_query_handle,
                target_token_capability_handle,
            ),
            _ => return Err("target desktop bootstrap did not receive Admission first".to_owned()),
        };
    let target_token_handle = match (role, target_token_handle) {
        (TargetDesktopBootstrapRoleV1::Holder, Some(handle)) => Some(handle),
        (TargetDesktopBootstrapRoleV1::Probe, None) => None,
        (TargetDesktopBootstrapRoleV1::LoaderControl, _) => unreachable!(),
        _ => {
            return Err(
                "target desktop bootstrap admission capability shape is invalid".to_owned(),
            );
        }
    };
    if launcher_process_handle == launcher_token_handle
        || target_token_handle.is_some_and(|target_token_handle| {
            target_token_handle == launcher_process_handle
                || target_token_handle == launcher_token_handle
        })
    {
        return Err(
            "target desktop bootstrap Admission reused one handle value across capability roles"
                .to_owned(),
        );
    }
    binding.verify_digest()?;
    if binding.bootstrap_image_sha256
        != super::package::validate_installed_target_desktop_bootstrap()?
        || binding.role != role
        || binding.bootstrap_envelope != process_envelope
        || binding.bootstrap_process_snapshot != process_snapshot
    {
        return Err("target desktop bootstrap role or process envelope is mismatched".to_owned());
    }
    let launcher_process = OwnedHandle::new(launcher_process_handle as usize as HANDLE)?;
    let launcher_token = OwnedHandle::new(launcher_token_handle as usize as HANDLE)?;
    verify_not_inheritable(launcher_process.raw())?;
    verify_not_inheritable(launcher_token.raw())?;

    let target_token = target_token_handle
        .map(|handle| OwnedHandle::new(handle as usize as HANDLE))
        .transpose()?;
    if let Some(target_token) = &target_token {
        verify_not_inheritable(target_token.raw())?;
    }
    let authenticated_target_token = target_token
        .as_ref()
        .map_or(process_token.raw(), |token| token.raw());
    let bootstrap_pipe_sddl = match role {
        TargetDesktopBootstrapRoleV1::Holder => super::security::holder_bootstrap_pipe_sddl()?,
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::security::target_desktop_bootstrap_pipe_sddl(authenticated_target_token)?
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            super::security::target_desktop_bootstrap_pipe_sddl(authenticated_target_token)?
        }
    };
    SecurityDescriptor::from_sddl(&bootstrap_pipe_sddl)?
        .verify_named_pipe(connection.raw())
        .map_err(|error| error.to_string())?;
    match run_admitted_target_desktop_bootstrap(
        &connection,
        &launcher_process,
        &launcher_token,
        authenticated_target_token,
        &binding,
        nonce,
        role,
        expected_desktop,
        deadline,
    ) {
        Ok(()) => Ok(()),
        Err(failure) => {
            if !started_failure_frame_publication_is_safe(
                failure.started_publication_bytes_transferred,
            ) {
                drop(connection);
                return Err(format!(
                    "{failure}; failure-frame-publication=abandoned started_bytes_transferred={}",
                    failure.started_publication_bytes_transferred,
                ));
            }
            let publication = publish_target_desktop_bootstrap_failure(
                connection.raw(),
                launcher_process.raw(),
                &binding,
                &failure,
            );
            drop(connection);
            match publication {
                Ok(()) => Err(failure.to_string()),
                Err(error) => Err(format!(
                    "{failure}; failure-frame-publication-error={error}"
                )),
            }
        }
    }
}

fn started_failure_frame_publication_is_safe(bytes_transferred: usize) -> bool {
    bytes_transferred == 0
}

#[cfg(test)]
pub(crate) fn started_failure_frame_publication_is_safe_for_test(bytes_transferred: usize) -> bool {
    started_failure_frame_publication_is_safe(bytes_transferred)
}

fn validate_target_desktop_bootstrap_nonce(nonce: &str) -> Result<(), String> {
    if nonce.len() != TARGET_DESKTOP_NONCE_BYTES * 2
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("target desktop bootstrap nonce is not 256-bit lowercase hex".to_owned());
    }
    Ok(())
}

fn run_admitted_target_desktop_bootstrap(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    launcher_token: &OwnedHandle,
    target_token: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    expected_nonce: &str,
    role: TargetDesktopBootstrapRoleV1,
    expected_desktop: Option<&std::ffi::OsStr>,
    deadline: Instant,
) -> Result<(), TargetDesktopBootstrapFailure> {
    authenticate_target_desktop_bootstrap_server(
        connection.raw(),
        launcher_process.raw(),
        launcher_token.raw(),
        binding,
        expected_nonce,
        target_token,
    )?;
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::StartedWrite,
        &TargetDesktopBootstrapMessageV1::Started {
            binding: binding.clone(),
            phase: TargetDesktopBootstrapPhaseV1::EndpointAdmission,
        },
    )
    .map_err(|error| {
        let bytes_transferred = error.bytes_transferred();
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::StartedPublication,
            error,
        )
        .after_started_publication_error(bytes_transferred)
    })?;
    match role {
        TargetDesktopBootstrapRoleV1::Holder => {
            run_target_desktop_bootstrap(connection, launcher_process, binding, target_token)
        }
        TargetDesktopBootstrapRoleV1::Probe => serve_target_desktop_probe(
            connection,
            launcher_process,
            binding,
            target_token,
            expected_desktop.ok_or_else(|| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                    "restricted probe desktop argument is absent",
                )
            })?,
        ),
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::LoaderControl,
                "loader-control cannot enter admitted bootstrap service logic",
            ))
        }
    }
}

fn authenticate_target_desktop_bootstrap_server(
    pipe: HANDLE,
    launcher_process: HANDLE,
    launcher_token: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    expected_nonce: &str,
    target_token: HANDLE,
) -> Result<(), TargetDesktopBootstrapFailure> {
    binding.verify_digest().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            error,
        )
    })?;
    let installed_bootstrap_sha256 = super::package::validate_installed_target_desktop_bootstrap()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })?;
    let bootstrap_token =
        super::token::process_token(unsafe { GetCurrentProcess() }).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let bootstrap_envelope = super::token::envelope(bootstrap_token.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let bootstrap_snapshot = super::token::token_query_attestation_snapshot(bootstrap_token.raw())
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let target_snapshot =
        super::token::token_attestation_snapshot(target_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let target_binding_matches = match binding.role {
        TargetDesktopBootstrapRoleV1::Holder => {
            super::token::require_same_token_instance(
                "target-request-to-holder-capability",
                &binding.target_request_snapshot,
                &target_snapshot,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?;
            true
        }
        TargetDesktopBootstrapRoleV1::Probe => {
            let target_assignment = super::token::require_assigned_token_authority(
                "target-request-to-probe-self",
                &binding.target_request_snapshot,
                &target_snapshot,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?;
            target_snapshot.query_evidence() == binding.bootstrap_process_snapshot
                && target_assignment == binding.bootstrap_assignment
        }
        TargetDesktopBootstrapRoleV1::LoaderControl => false,
    };
    let holder_assignment = super::token::require_assigned_process_authority(
        "holder-launch-to-process",
        &binding.holder_launch_snapshot,
        &binding.holder_process_snapshot,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let bootstrap_assignment = match binding.role {
        TargetDesktopBootstrapRoleV1::Holder => super::token::require_assigned_process_authority(
            "holder-launch-to-process",
            &binding.holder_launch_snapshot,
            &binding.bootstrap_process_snapshot,
        ),
        TargetDesktopBootstrapRoleV1::Probe => super::token::require_assigned_process_authority(
            "target-request-to-probe-process",
            &binding.target_request_snapshot,
            &binding.bootstrap_process_snapshot,
        ),
        TargetDesktopBootstrapRoleV1::LoaderControl => {
            super::token::require_assigned_process_authority(
                "target-request-to-loader-control-process",
                &binding.target_request_snapshot,
                &binding.bootstrap_process_snapshot,
            )
        }
    }
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    if binding.schema_version != TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION
        || binding.nonce != expected_nonce
        || binding.bootstrap_image_sha256 != installed_bootstrap_sha256
        || binding.launcher_session_id != 0
        || binding.bootstrap_identity
            != process_identity(unsafe { GetCurrentProcess() }).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                    error,
                )
            })?
        || binding.bootstrap_envelope != bootstrap_envelope
        || binding.bootstrap_process_snapshot != bootstrap_snapshot
        || binding.holder_assignment != holder_assignment
        || binding.bootstrap_assignment != bootstrap_assignment
        || (binding.role == TargetDesktopBootstrapRoleV1::Holder
            && binding.bootstrap_process_snapshot != binding.holder_process_snapshot)
        || binding.target_envelope
            != super::token::envelope(target_token).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            })?
        || !target_binding_matches
        || binding.broker_source_snapshot.lineage.user_sid != "S-1-5-18"
        || binding.broker_source_snapshot.lineage.session_id != 0
        || binding.broker_source_snapshot.behavior.token_is_restricted
        || !binding
            .broker_source_snapshot
            .behavior
            .restricting_sids
            .is_empty()
        || binding.holder_launch_snapshot.lineage.user_sid != "S-1-5-18"
        || binding.holder_launch_snapshot.lineage.session_id != binding.target_envelope.session_id
        || binding.holder_launch_snapshot.behavior.token_is_restricted
        || !binding
            .holder_launch_snapshot
            .behavior
            .restricting_sids
            .is_empty()
        || binding
            .holder_launch_snapshot
            .behavior
            .enabled_sensitive_privilege_count
            != 0
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap Admission binding is mismatched",
        ));
    }
    let mut server_pid = 0_u32;
    let mut server_session_id = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut server_pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut server_session_id) } == 0
    {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server identity query failed",
        ));
    }
    if unsafe { GetProcessId(launcher_process) } != server_pid
        || server_pid != binding.launcher_identity.process_id
        || server_session_id != binding.launcher_session_id
        || process_identity(launcher_process).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })? != binding.launcher_identity
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server identity is mismatched",
        ));
    }
    let launcher_executable = super::package::installed_binary();
    verify_image_path(launcher_process, &launcher_executable).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            error,
        )
    })?;
    let launcher_envelope = super::token::envelope(launcher_token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            error,
        )
    })?;
    let launcher_snapshot =
        super::token::token_attestation_snapshot(launcher_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    let launcher_sid = super::security::service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })?;
    if launcher_envelope != binding.launcher_envelope
        || launcher_snapshot != binding.launcher_process_snapshot
        || launcher_envelope.session_id != binding.launcher_session_id
        || super::token::token_user_sid(launcher_token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                error,
            )
        })? != "S-1-5-18"
        || !super::token::token_is_restricted(launcher_token)
        || !super::token::token_has_enabled_group(launcher_token, &launcher_sid).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            },
        )?
        || !super::token::token_has_restricting_sid(launcher_token, &launcher_sid).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
                    error,
                )
            },
        )?
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerTokenAuthentication,
            "target desktop bootstrap pipe server token is not the sealed launcher",
        ));
    }
    let mut server_pid_after = 0_u32;
    let mut server_session_id_after = 0_u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut server_pid_after) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut server_session_id_after) } == 0
        || server_pid_after != server_pid
        || server_session_id_after != server_session_id
        || process_identity(launcher_process).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
                error,
            )
        })? != binding.launcher_identity
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::ServerProcessAuthentication,
            "target desktop bootstrap pipe server changed during authentication",
        ));
    }
    Ok(())
}

fn publish_target_desktop_bootstrap_failure(
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &TargetDesktopBootstrapBindingV3,
    failure: &TargetDesktopBootstrapFailure,
) -> Result<(), String> {
    super::pipe::write_frame_bounded(
        connection,
        Some(launcher_process),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::FailureWrite,
        &TargetDesktopBootstrapMessageV1::Failed {
            binding: binding.clone(),
            phase: failure.phase,
            native_code: failure.native_code,
            detail: failure.detail.clone(),
        },
    )
    .map_err(|error| error.to_string())
}

fn run_target_desktop_bootstrap(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let holder_token = super::token::current_process_token_for_access_check().map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            error,
        )
    })?;
    let target_envelope = super::token::envelope(target_token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            error,
        )
    })?;
    if target_envelope != binding.target_envelope {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetTokenCapture,
            "target desktop bootstrap token changed after Admission",
        ));
    }
    let target_user_object_policy = super::security::target_user_object_policy(
        target_token,
        binding.target_user_object_policy_role,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
            error,
        )
    })?;

    // LoaderReady and authenticated Started have already crossed the nonce
    // pipe without any USER32/GDI32 call. Do not inspect an implicit source
    // station here: even GetProcessWindowStation would trigger the ambient
    // binding whose restricted-token access check this helper exists to avoid.

    let window_station_name = format!("MemCordonTarget-{}", binding.nonce);
    let desktop_name = "Restricted".to_owned();
    validate_target_desktop_binding(&window_station_name, &desktop_name).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
            error,
        )
    })?;

    let window_station_sddl = target_user_object_policy.window_station_sddl();
    let window_station_security =
        SecurityDescriptor::from_sddl(&window_station_sddl).map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
                format!("cannot convert target window-station SDDL: {error}"),
            )
        })?;
    let window_station_creation_security = window_station_security
        .absolute_for_user_object_creation()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::WindowStationPolicyConstruction,
                format!("cannot prepare target window-station creation policy: {error}"),
            )
        })?;
    super::user_api::load().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::UserModuleResolution,
            error,
        )
    })?;
    let window_station_wide = super::pipe::wide_null(&window_station_name);
    let window_station_attributes = window_station_creation_security.attributes(false);
    let station_thread_id = unsafe { GetCurrentThreadId() };
    let station_primary_before =
        super::token::process_token_query_attestation(unsafe { GetCurrentProcess() }).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
                    error,
                )
            },
        )?;
    let station_carrier_guard = request_creator_arm(
        connection.raw(),
        launcher_process.raw(),
        binding,
        super::session_broker::SessionCreationPhaseV1::WindowStation,
        1,
        station_thread_id,
        &station_primary_before,
    )?;
    let private_window_station = unsafe {
        CreateWindowStationW(
            window_station_wide.as_ptr(),
            CWF_CREATE_ONLY_FLAG,
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
            &raw const window_station_attributes,
        )
    };
    let station_error = private_window_station
        .is_null()
        .then(|| io::Error::last_os_error());
    if let Err(error) = station_carrier_guard.revert() {
        eprintln!("station creator carrier reversion failed: {error}");
        unsafe { TerminateProcess(GetCurrentProcess(), TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS) };
        std::process::abort();
    }
    let station_primary_after =
        super::token::process_token_query_attestation(unsafe { GetCurrentProcess() }).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
                    error,
                )
            },
        )?;
    consume_creator_arm(
        connection.raw(),
        launcher_process.raw(),
        binding,
        super::session_broker::SessionCreationPhaseV1::WindowStation,
        1,
        station_thread_id,
        station_error.as_ref().and_then(io::Error::raw_os_error),
        &station_primary_after,
    )?;
    if let Some(error) = station_error {
        return Err(TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
            error.raw_os_error().unwrap_or_default(),
            format!("CreateWindowStationW failed in target-token bootstrap: {error}"),
        ));
    }
    let mut private_window_station = BootstrapWindowStation::new(private_window_station);
    verify_user_object_not_inheritable(private_window_station.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationCreation,
            error,
        )
    })?;
    if unsafe { SetProcessWindowStation(private_window_station.raw()) } == 0 {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
            "SetProcessWindowStation failed in dedicated target-token bootstrap",
        ));
    }
    private_window_station.mark_assigned();
    let current_private_window_station = unsafe { GetProcessWindowStation() };
    let private_station_assigned = !current_private_window_station.is_null()
        && user_object_name(current_private_window_station).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
                error,
            )
        })? == window_station_name;
    if !private_station_assigned {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationBinding,
            "target-token bootstrap did not retain the nonce private window station",
        ));
    }
    attest_target_user_object(
        private_window_station.raw(),
        &window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        holder_token.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
            format!("holder station attestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        private_window_station.raw(),
        &window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
            error,
        )
    })?;

    let desktop_sddl = target_user_object_policy.desktop_sddl();
    let desktop_security = SecurityDescriptor::from_sddl(&desktop_sddl).map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::DesktopPolicyConstruction,
            format!("cannot convert target desktop SDDL: {error}"),
        )
    })?;
    let desktop_creation_security = desktop_security
        .absolute_for_user_object_creation()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::DesktopPolicyConstruction,
                format!("cannot prepare target desktop creation policy: {error}"),
            )
        })?;
    let desktop_wide = super::pipe::wide_null(&desktop_name);
    let mut desktop = create_target_desktop_on_creator_thread(
        desktop_wide.clone(),
        desktop_creation_security,
        connection.raw(),
        launcher_process.raw(),
        binding.clone(),
    )?;
    if unsafe { SetThreadDesktop(desktop.raw()) } == 0 {
        return Err(TargetDesktopBootstrapFailure::native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopCreation,
            "SetThreadDesktop failed for nonce private desktop",
        ));
    }
    let private_desktop_assigned =
        unsafe { GetThreadDesktop(GetCurrentThreadId()) } == desktop.raw();
    if !private_desktop_assigned {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            "target desktop bootstrap thread did not retain the nonce private desktop",
        ));
    }
    desktop.mark_assigned();
    attest_target_user_object(
        desktop.raw(),
        &desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        holder_token.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            format!("holder desktop attestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        desktop.raw(),
        &desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::observed_native(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            error,
        )
    })?;
    validate_target_desktop_input_state(desktop_receives_input(desktop.raw()).map_err(
        |error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        },
    )?)
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
            error,
        )
    })?;
    verify_private_desktop_containment(private_window_station.raw(), &desktop_wide).map_err(
        |error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        },
    )?;
    // No ambient station or desktop handle was requested before the nonce-
    // private station was created. Every subsequent USER-object observation
    // refers to the explicitly bound private station or its Restricted desktop,
    // so this proof is constructional rather than a shared-object fingerprint.
    let source_objects_unmodified = true;
    let window_station_policy_sha256 = window_station_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
                error,
            )
        })?;
    let desktop_policy_sha256 = desktop_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                error,
            )
        })?;
    // Capture one final same-domain namespace baseline only after both USER
    // objects have completed creation, binding, semantic attestation, carrier
    // clearing, non-input validation, and containment validation.
    let window_station_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(private_window_station.raw())
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateWindowStationAttestation,
                    error,
                )
            })?;
    let desktop_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw()).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::PrivateDesktopAttestation,
                    error,
                )
            },
        )?;

    let frame = TargetDesktopBootstrapFrameV1 {
        schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
        bootstrap_identity: process_identity(unsafe { GetCurrentProcess() }).map_err(|error| {
            TargetDesktopBootstrapFailure::observed_native(
                TargetDesktopBootstrapPhaseV1::ProcessIdentityCapture,
                error,
            )
        })?,
        target_envelope,
        window_station_name,
        desktop_name,
        window_station_policy_sha256,
        desktop_policy_sha256,
        window_station_live_equality_sha256,
        desktop_live_equality_sha256,
        source_objects_unmodified,
        private_station_assigned,
        private_desktop_assigned,
        desktop_containment_verified: true,
        window_station_policy_verified: true,
        desktop_policy_verified: true,
        window_station_not_inheritable: true,
        desktop_not_inheritable: true,
        noninteractive: true,
    };
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,
        &TargetDesktopBootstrapMessageV1::Ready {
            binding: binding.clone(),
            attestation: frame.clone(),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::ResultPublication,
            error,
        )
    })?;

    let native_loader_access_lease = serve_holder_target_association_preflight(
        connection,
        launcher_process,
        binding,
        target_token,
        &frame.window_station_name,
        &frame.desktop_name,
        private_window_station.raw(),
        desktop.raw(),
        &window_station_security,
        &desktop_security,
        &frame.window_station_live_equality_sha256,
        &frame.desktop_live_equality_sha256,
    )?;

    // The USER-object handles and native-loader lease (source pins, exact-target
    // files, KnownDll directory, and present sections) remain live through this
    // wait. The launcher performs both child loader qualifications before it
    // releases the holder, closing the preflight-to-create mutation window.
    let wait_result = super::pipe::wait_for_target_desktop_bootstrap_release(
        connection.raw(),
        launcher_process.raw(),
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(TargetDesktopBootstrapPhaseV1::LifetimeHold, error)
    });
    wait_result?;
    drop(native_loader_access_lease);
    drop(desktop);
    drop(private_window_station);
    Ok(())
}

fn serve_target_desktop_probe(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
    expected_desktop: &std::ffi::OsStr,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let target_user_object_policy = super::security::target_user_object_policy(
        target_token,
        binding.target_user_object_policy_role,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    let exact_name = expected_desktop.to_str().ok_or_else(|| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe desktop is not UTF-8",
        )
    })?;
    let (window_station_name, desktop_name) = exact_name.split_once('\\').ok_or_else(|| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe desktop is not fully qualified",
        )
    })?;
    validate_target_desktop_binding(window_station_name, desktop_name).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    super::user_api::load().map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::UserModuleResolution,
            error,
        )
    })?;
    let current_station = unsafe { GetProcessWindowStation() };
    let current_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if current_station.is_null()
        || current_desktop.is_null()
        || user_object_name(current_station).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })? != window_station_name
        || user_object_name(current_desktop).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })? != desktop_name
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            "restricted probe did not initialize on the admitted private desktop",
        ));
    }
    let window_station_sddl = target_user_object_policy.window_station_sddl();
    let desktop_sddl = target_user_object_policy.desktop_sddl();
    let window_station_security =
        SecurityDescriptor::from_sddl(&window_station_sddl).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })?;
    let desktop_security = SecurityDescriptor::from_sddl(&desktop_sddl).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    attest_target_user_object(
        current_station,
        window_station_name,
        &window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    attest_target_user_object(
        current_desktop,
        desktop_name,
        &desktop_security,
        super::security::SecurityObjectKind::Desktop,
        target_token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    verify_private_desktop_containment(current_station, &super::pipe::wide_null(desktop_name))
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        })?;
    validate_target_desktop_input_state(desktop_receives_input(current_desktop).map_err(
        |error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                error,
            )
        },
    )?)
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })?;
    let frame =
        TargetDesktopBootstrapFrameV1 {
            schema_version: TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION,
            bootstrap_identity: binding.bootstrap_identity.clone(),
            target_envelope: binding.target_envelope.clone(),
            window_station_name: window_station_name.to_owned(),
            desktop_name: desktop_name.to_owned(),
            window_station_policy_sha256: window_station_security
                .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                        error,
                    )
                })?,
            desktop_policy_sha256: desktop_security
                .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                        error,
                    )
                })?,
            window_station_live_equality_sha256:
                SecurityDescriptor::user_object_security_equality_fingerprint(current_station)
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                            error,
                        )
                    })?,
            desktop_live_equality_sha256:
                SecurityDescriptor::user_object_security_equality_fingerprint(current_desktop)
                    .map_err(|error| {
                        TargetDesktopBootstrapFailure::contract(
                            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
                            error,
                        )
                    })?,
            source_objects_unmodified: true,
            private_station_assigned: true,
            private_desktop_assigned: true,
            desktop_containment_verified: true,
            window_station_policy_verified: true,
            desktop_policy_verified: true,
            window_station_not_inheritable: true,
            desktop_not_inheritable: true,
            noninteractive: true,
        };
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::ReadyWrite,
        &TargetDesktopBootstrapMessageV1::Ready {
            binding: binding.clone(),
            attestation: frame,
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::RestrictedProbeAttestation,
            error,
        )
    })
}

impl CapturedTargetDesktop {
    fn capture(token: HANDLE) -> Result<Self, String> {
        let window_station = unsafe { GetProcessWindowStation() };
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if window_station.is_null() || desktop.is_null() {
            return Err("cannot capture nested target USER binding".to_owned());
        }
        let window_station_name =
            user_object_name(window_station).map_err(|error| error.to_string())?;
        let desktop_name = user_object_name(desktop).map_err(|error| error.to_string())?;
        validate_target_desktop_binding(&window_station_name, &desktop_name)?;
        validate_target_desktop_input_state(
            desktop_receives_input(desktop).map_err(|error| error.to_string())?,
        )?;
        let read_handles = TargetUserBindingReadHandles::duplicate(window_station, desktop)
            .map_err(|error| {
                format!("cannot duplicate nested target USER readback handles: {error}")
            })?;
        let window_station_security_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(
                read_handles.window_station.raw(),
            )?;
        let desktop_security_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(
                read_handles.desktop.raw(),
            )?;
        let exact_name = format!("{window_station_name}\\{desktop_name}");
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let context = Self {
            read_handles,
            window_station_name,
            window_station_security_sha256,
            desktop_name,
            desktop_security_sha256,
            exact_name,
            startup_name,
            window_station_security: SecurityDescriptor::from_sddl(
                &super::security::target_window_station_sddl(token)?,
            )?,
            desktop_security: SecurityDescriptor::from_sddl(
                &super::security::target_desktop_sddl(token)?,
            )?,
        };
        context.attest(token)?;
        Ok(context)
    }

    fn attest(&self, token: HANDLE) -> Result<(), String> {
        let current_window_station = unsafe { GetProcessWindowStation() };
        let current_desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if current_window_station.is_null()
            || current_desktop.is_null()
            || user_object_name(current_window_station).map_err(|error| error.to_string())?
                != self.window_station_name
            || user_object_name(current_desktop).map_err(|error| error.to_string())?
                != self.desktop_name
        {
            return Err("nested target USER binding changed during child creation".to_owned());
        }
        let current_read_handles =
            TargetUserBindingReadHandles::duplicate(current_window_station, current_desktop)
                .map_err(|error| {
                    format!("cannot refresh nested target USER readback handles: {error}")
                })?;
        if SecurityDescriptor::user_object_security_equality_fingerprint(
            current_read_handles.window_station.raw(),
        )? != self.window_station_security_sha256
            || SecurityDescriptor::user_object_security_equality_fingerprint(
                self.read_handles.window_station.raw(),
            )? != self.window_station_security_sha256
        {
            return Err(
                "nested target private window-station binding changed during child creation"
                    .to_owned(),
            );
        }
        attest_target_user_object(
            current_read_handles.window_station.raw(),
            &self.window_station_name,
            &self.window_station_security,
            super::security::SecurityObjectKind::WindowStation,
            token,
        )
        .map_err(|error| format!("nested target window-station preflight failed: {error}"))?;
        if SecurityDescriptor::user_object_security_equality_fingerprint(
            current_read_handles.desktop.raw(),
        )? != self.desktop_security_sha256
            || SecurityDescriptor::user_object_security_equality_fingerprint(
                self.read_handles.desktop.raw(),
            )? != self.desktop_security_sha256
        {
            return Err(
                "nested target private desktop binding changed during child creation".to_owned(),
            );
        }
        attest_target_user_object(
            current_read_handles.desktop.raw(),
            &self.desktop_name,
            &self.desktop_security,
            super::security::SecurityObjectKind::Desktop,
            token,
        )
        .map_err(|error| format!("nested target desktop preflight failed: {error}"))?;
        let mut progress = NullAssociationPreflightProgress;
        let (_evidence, _native_loader_access_lease) = attest_target_user_object_opens_as_token(
            token,
            &self.window_station_name,
            &self.desktop_name,
            self.read_handles.window_station.raw(),
            self.read_handles.desktop.raw(),
            &self.window_station_security,
            &self.desktop_security,
            &self.window_station_security_sha256,
            &self.desktop_security_sha256,
            Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT,
            &mut progress,
        )
        .map_err(|error| {
            format!("nested target explicit-binding open preflight failed: {error}")
        })?;
        validate_target_desktop_input_state(
            desktop_receives_input(current_desktop).map_err(|error| error.to_string())?,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn serve_holder_target_association_preflight(
    connection: &OwnedHandle,
    launcher_process: &OwnedHandle,
    binding: &TargetDesktopBootstrapBindingV3,
    target_token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
) -> Result<super::loader_access::NativeLoaderAccessLeaseV1, TargetDesktopBootstrapFailure> {
    let request: TargetDesktopBootstrapMessageV1 = super::pipe::read_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        Instant::now() + Duration::from_secs(30),
        super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightRead,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    match request {
        TargetDesktopBootstrapMessageV1::AssociationPreflight {
            binding: observed_binding,
        } if observed_binding == *binding => {}
        _ => {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "holder association-preflight request is invalid or out of order",
            ));
        }
    }
    let overall_deadline = Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_OVERALL_TIMEOUT;
    let mut progress = AssociationPreflightProgressPublisher {
        connection: connection.raw(),
        launcher_process: launcher_process.raw(),
        binding,
        overall_deadline,
        cursor: AssociationPreflightProgressCursor::default(),
    };
    let (evidence, native_loader_access_lease) = attest_target_user_object_opens_as_token(
        target_token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
        overall_deadline,
        &mut progress,
    )?;
    super::pipe::write_frame_bounded(
        connection.raw(),
        Some(launcher_process.raw()),
        (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(overall_deadline),
        super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightReadyWrite,
        &TargetDesktopBootstrapMessageV1::AssociationPreflightReady {
            binding: binding.clone(),
            evidence: Box::new(evidence),
        },
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::from_pipe(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    Ok(native_loader_access_lease)
}

struct AssociationPreflightProgressPublisher<'a> {
    connection: HANDLE,
    launcher_process: HANDLE,
    binding: &'a TargetDesktopBootstrapBindingV3,
    overall_deadline: Instant,
    cursor: AssociationPreflightProgressCursor,
}

trait AssociationPreflightProgressSink {
    fn publish(
        &mut self,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure>;
}

struct NullAssociationPreflightProgress;

impl AssociationPreflightProgressSink for NullAssociationPreflightProgress {
    fn publish(
        &mut self,
        _stage: TargetAssociationPreflightStageV1,
        _completed: u32,
        _total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure> {
        Ok(())
    }
}

impl AssociationPreflightProgressSink for AssociationPreflightProgressPublisher<'_> {
    fn publish(
        &mut self,
        stage: TargetAssociationPreflightStageV1,
        completed: u32,
        total: Option<u32>,
    ) -> Result<(), TargetDesktopBootstrapFailure> {
        if Instant::now() >= self.overall_deadline {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                format!(
                    "stage={} completed={completed} total={} overall association-preflight deadline elapsed",
                    stage.diagnostic(),
                    total.map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                ),
            ));
        }
        let sequence = self.cursor.sequence.checked_add(1).ok_or_else(|| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                "association-preflight progress sequence overflowed",
            )
        })?;
        self.cursor
            .validate_next(sequence, stage, completed, total)
            .map_err(|detail| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                    detail,
                )
            })?;
        super::pipe::write_frame_bounded(
            self.connection,
            Some(self.launcher_process),
            (Instant::now() + TARGET_ASSOCIATION_PREFLIGHT_IDLE_TIMEOUT).min(self.overall_deadline),
            super::pipe::TargetDesktopBootstrapPipeOperation::AssociationPreflightProgressWrite,
            &TargetDesktopBootstrapMessageV1::AssociationPreflightProgress {
                binding: self.binding.clone(),
                sequence,
                stage,
                completed,
                total,
            },
        )
        .map_err(|error| {
            TargetDesktopBootstrapFailure::from_pipe(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
        self.cursor.commit(sequence, stage, completed, total);
        Ok(())
    }
}

fn association_stage_from_native_loader(
    stage: super::loader_access::NativeLoaderProgressStage,
) -> TargetAssociationPreflightStageV1 {
    match stage {
        super::loader_access::NativeLoaderProgressStage::SourceBootstrap => {
            TargetAssociationPreflightStageV1::SourceBootstrap
        }
        super::loader_access::NativeLoaderProgressStage::SourceSystemAncestry => {
            TargetAssociationPreflightStageV1::SourceSystemAncestry
        }
        super::loader_access::NativeLoaderProgressStage::SourceLoaderGraph => {
            TargetAssociationPreflightStageV1::SourceLoaderGraph
        }
        super::loader_access::NativeLoaderProgressStage::SourceKnownDlls => {
            TargetAssociationPreflightStageV1::SourceKnownDlls
        }
        super::loader_access::NativeLoaderProgressStage::TargetBootstrap => {
            TargetAssociationPreflightStageV1::TargetBootstrap
        }
        super::loader_access::NativeLoaderProgressStage::TargetKnownDlls => {
            TargetAssociationPreflightStageV1::TargetKnownDlls
        }
        super::loader_access::NativeLoaderProgressStage::TargetModules => {
            TargetAssociationPreflightStageV1::TargetModules
        }
    }
}

fn attest_target_user_object_opens_as_token(
    token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
    overall_deadline: Instant,
    progress: &mut dyn AssociationPreflightProgressSink,
) -> Result<
    (
        TargetUserObjectOpenPreflightV1,
        super::loader_access::NativeLoaderAccessLeaseV1,
    ),
    TargetDesktopBootstrapFailure,
> {
    progress.publish(
        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,
        0,
        Some(1),
    )?;
    let desktop_heap_kb = desktop_heap_kb(retained_desktop).map_err(|error| {
        TargetDesktopBootstrapFailure::from_user_object(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    if user_object_name(unsafe { GetProcessWindowStation() }).map_err(|error| {
        TargetDesktopBootstrapFailure::from_user_object(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })? != window_station_name
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            "explicit-binding open preflight is not running in the expected station",
        ));
    }
    let expected_window_station_policy_sha256 = window_station_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::WindowStation)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    let expected_desktop_policy_sha256 = desktop_security
        .user_object_policy_fingerprint(super::security::SecurityObjectKind::Desktop)
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    attest_retained_target_user_object_namespace(
        token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
    )?;
    progress.publish(
        TargetAssociationPreflightStageV1::RetainedNamespaceBefore,
        1,
        Some(1),
    )?;
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    // Resolve paths, PE imports, API-set hosts, and source identity/mutation
    // pins under the holder primary token before installing exact-target
    // impersonation. The effective-token phase performs only final-file and
    // native-object authorization opens; it never opens an ancestor directory.
    let native_loader_resources = {
        let mut publish = |native: super::loader_access::NativeLoaderProgress| {
            progress
                .publish(
                    association_stage_from_native_loader(native.stage),
                    native.completed,
                    native.total,
                )
                .map_err(|error| error.to_string())
        };
        let mut budget = super::loader_access::NativeLoaderAttestationBudget::new(
            overall_deadline,
            &mut publish,
        );
        super::loader_access::resolve_native_loader_resources(
            &super::package::installed_target_desktop_bootstrap(),
            &mut budget,
        )
        .map_err(TargetDesktopBootstrapFailure::from_native_loader)?
    };
    progress.publish(
        TargetAssociationPreflightStageV1::TargetTokenInstallation,
        0,
        Some(1),
    )?;
    let target_snapshot_before =
        super::token::token_attestation_snapshot(token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    let impersonation = duplicate_explicit_impersonation_token(token).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    let impersonation_snapshot = super::token::token_attestation_snapshot(impersonation.raw())
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
    super::token::require_primary_to_impersonation_authority(
        "holder-native-loader-preflight-impersonation",
        &target_snapshot_before,
        &impersonation_snapshot,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
            error,
        )
    })?;
    let guard = ThreadImpersonationGuard::install(impersonation.raw()).map_err(|error| {
        TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error.raw_os_error().unwrap_or_default(),
            format!(
                "object_kind=thread-token api=SetThreadToken desired_mode=security-impersonation detail={error}"
            ),
        )
    })?;
    progress.publish(
        TargetAssociationPreflightStageV1::TargetTokenInstallation,
        1,
        Some(1),
    )?;

    let open_result = (|| {
        progress.publish(
            TargetAssociationPreflightStageV1::TargetWindowStation,
            0,
            Some(1),
        )?;
        let window_station_wide = super::pipe::wide_null(window_station_name);
        let window_station =
            unsafe { OpenWindowStationW(window_station_wide.as_ptr(), 0, MAXIMUM_ALLOWED_ACCESS) };
        if window_station.is_null() {
            let error = io::Error::last_os_error();
            return Err(TargetDesktopBootstrapFailure::captured_native(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error.raw_os_error().unwrap_or_default(),
                format!(
                    "object_kind=window-station api=OpenWindowStationW desired_mode=maximum-allowed requested={MAXIMUM_ALLOWED_ACCESS:#010x} required={:#010x} detail={error}",
                    super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
                ),
            ));
        }
        let mut window_station = BootstrapWindowStation::new(window_station);
        let window_station_granted_access =
            super::token::granted_handle_access(window_station.raw()).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=window-station api=NtQueryObject desired_mode=maximum-allowed detail={error}"
                    ),
                )
            })?;
        if window_station_granted_access & super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
            != super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                format!(
                    "object_kind=window-station api=NtQueryObject desired_mode=maximum-allowed required={:#010x} granted={window_station_granted_access:#010x}",
                    super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS,
                ),
            ));
        }
        if user_object_name(window_station.raw()).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })? != window_station_name
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectInformationW resolved the wrong object",
            ));
        }
        let window_station_live_equality_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(window_station.raw())
                .map_err(|error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                        format!(
                            "object_kind=window-station api=GetUserObjectSecurity detail={error}"
                        ),
                    )
                })?;
        if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectSecurity live equality fingerprint changed",
            ));
        }
        let window_station_policy_sha256 = window_station_security
            .user_object_resultant_fingerprint(
                window_station.raw(),
                super::security::SecurityObjectKind::WindowStation,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=window-station api=GetUserObjectSecurity policy detail={error}"
                    ),
                )
            })?;
        if window_station_policy_sha256 != expected_window_station_policy_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=window-station api=GetUserObjectSecurity policy fingerprint changed",
            ));
        }
        // The opened handle names the process's currently assigned station, so
        // CloseWindowStation is forbidden. Retain this independently proven
        // access handle until the dedicated process exits.
        window_station.mark_assigned();
        progress.publish(
            TargetAssociationPreflightStageV1::TargetWindowStation,
            1,
            Some(1),
        )?;

        progress.publish(TargetAssociationPreflightStageV1::TargetDesktop, 0, Some(1))?;
        let desktop_wide = super::pipe::wide_null(desktop_name);
        let desktop = unsafe { OpenDesktopW(desktop_wide.as_ptr(), 0, 0, MAXIMUM_ALLOWED_ACCESS) };
        if desktop.is_null() {
            let error = io::Error::last_os_error();
            return Err(TargetDesktopBootstrapFailure::captured_native(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error.raw_os_error().unwrap_or_default(),
                format!(
                    "object_kind=desktop api=OpenDesktopW desired_mode=maximum-allowed requested={MAXIMUM_ALLOWED_ACCESS:#010x} required={:#010x} detail={error}",
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                ),
            ));
        }
        let mut desktop = OwnedDesktop::new(desktop);
        let desktop_granted_access =
            super::token::granted_handle_access(desktop.raw()).map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=desktop api=NtQueryObject desired_mode=maximum-allowed detail={error}"
                    ),
                )
            })?;
        if desktop_granted_access & super::security::TARGET_PRIVATE_DESKTOP_ACCESS
            != super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                format!(
                    "object_kind=desktop api=NtQueryObject desired_mode=maximum-allowed required={:#010x} granted={desktop_granted_access:#010x}",
                    super::security::TARGET_PRIVATE_DESKTOP_ACCESS,
                ),
            ));
        }
        if user_object_name(desktop.raw()).map_err(|error| {
            TargetDesktopBootstrapFailure::from_user_object(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })? != desktop_name
        {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectInformationW resolved the wrong object",
            ));
        }
        let desktop_live_equality_sha256 =
            SecurityDescriptor::user_object_security_equality_fingerprint(desktop.raw()).map_err(
                |error| {
                    TargetDesktopBootstrapFailure::contract(
                        TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                        format!("object_kind=desktop api=GetUserObjectSecurity detail={error}"),
                    )
                },
            )?;
        if desktop_live_equality_sha256 != expected_desktop_live_equality_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectSecurity live equality fingerprint changed",
            ));
        }
        let desktop_policy_sha256 = desktop_security
            .user_object_resultant_fingerprint(
                desktop.raw(),
                super::security::SecurityObjectKind::Desktop,
            )
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!("object_kind=desktop api=GetUserObjectSecurity policy detail={error}"),
                )
            })?;
        if desktop_policy_sha256 != expected_desktop_policy_sha256 {
            return Err(TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                "object_kind=desktop api=GetUserObjectSecurity policy fingerprint changed",
            ));
        }
        desktop.mark_assigned();
        progress.publish(TargetAssociationPreflightStageV1::TargetDesktop, 1, Some(1))?;
        let native_loader_access_lease = {
            let mut publish = |native: super::loader_access::NativeLoaderProgress| {
                progress
                    .publish(
                        association_stage_from_native_loader(native.stage),
                        native.completed,
                        native.total,
                    )
                    .map_err(|error| error.to_string())
            };
            let mut budget = super::loader_access::NativeLoaderAttestationBudget::new(
                overall_deadline,
                &mut publish,
            );
            super::loader_access::probe_native_loader_access_as_effective_thread(
                native_loader_resources,
                &mut budget,
            )
            .map_err(TargetDesktopBootstrapFailure::from_native_loader)?
        };
        Ok((
            window_station_granted_access,
            desktop_granted_access,
            window_station_policy_sha256,
            desktop_policy_sha256,
            window_station_live_equality_sha256,
            desktop_live_equality_sha256,
            native_loader_access_lease,
        ))
    })();

    if open_result.is_ok() {
        progress.publish(
            TargetAssociationPreflightStageV1::RevertAndFinalization,
            0,
            Some(1),
        )?;
    }
    guard.revert().map_err(|error| {
        TargetDesktopBootstrapFailure::captured_native(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error.raw_os_error().unwrap_or_default(),
            format!(
                "object_kind=thread-token api=RevertToSelf desired_mode=remove-impersonation detail={error}"
            ),
        )
    })?;
    super::token::require_thread_token_absent(unsafe { GetCurrentThread() }).map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    let (
        window_station_granted_access,
        desktop_granted_access,
        window_station_policy_sha256,
        desktop_policy_sha256,
        window_station_live_equality_sha256,
        desktop_live_equality_sha256,
        native_loader_access_lease,
    ) = open_result?;
    let target_snapshot_after =
        super::token::token_attestation_snapshot(token).map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                error,
            )
        })?;
    super::token::require_same_token_instance(
        "holder-target-association-preflight",
        &target_snapshot_before,
        &target_snapshot_after,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            error,
        )
    })?;
    attest_retained_target_user_object_namespace(
        token,
        window_station_name,
        desktop_name,
        retained_window_station,
        retained_desktop,
        window_station_security,
        desktop_security,
        expected_window_station_live_equality_sha256,
        expected_desktop_live_equality_sha256,
    )?;
    let native_loader_access_lease = native_loader_access_lease
        .mark_reverted_and_seal()
        .map_err(|error| {
            TargetDesktopBootstrapFailure::contract(
                TargetDesktopBootstrapPhaseV1::TargetNativeLoaderAccessPreflight,
                error,
            )
        })?;
    progress.publish(
        TargetAssociationPreflightStageV1::RevertAndFinalization,
        1,
        Some(1),
    )?;
    let native_loader_access = native_loader_access_lease.evidence().clone();
    Ok((
        TargetUserObjectOpenPreflightV1 {
            window_station_granted_access,
            desktop_granted_access,
            desktop_heap_kb,
            window_station_policy_sha256,
            desktop_policy_sha256,
            window_station_live_equality_sha256,
            desktop_live_equality_sha256,
            window_station_policy_verified_after_open: true,
            desktop_policy_verified_after_open: true,
            creator_live_baselines_unchanged: true,
            target_snapshot_before,
            target_snapshot_after,
            thread_token_absent: true,
            native_loader_access,
        },
        native_loader_access_lease,
    ))
}

#[allow(clippy::too_many_arguments)]
fn attest_retained_target_user_object_namespace(
    token: HANDLE,
    window_station_name: &str,
    desktop_name: &str,
    retained_window_station: HANDLE,
    retained_desktop: HANDLE,
    window_station_security: &SecurityDescriptor,
    desktop_security: &SecurityDescriptor,
    expected_window_station_live_equality_sha256: &str,
    expected_desktop_live_equality_sha256: &str,
) -> Result<(), TargetDesktopBootstrapFailure> {
    let window_station_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(retained_window_station)
            .map_err(|error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=retained-window-station api=GetUserObjectSecurity detail={error}"
                    ),
                )
            })?;
    let desktop_live_equality_sha256 =
        SecurityDescriptor::user_object_security_equality_fingerprint(retained_desktop).map_err(
            |error| {
                TargetDesktopBootstrapFailure::contract(
                    TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
                    format!(
                        "object_kind=retained-desktop api=GetUserObjectSecurity detail={error}"
                    ),
                )
            },
        )?;
    if window_station_live_equality_sha256 != expected_window_station_live_equality_sha256
        || desktop_live_equality_sha256 != expected_desktop_live_equality_sha256
    {
        return Err(TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            "retained USER-object live equality baseline changed",
        ));
    }
    attest_target_user_object(
        retained_window_station,
        window_station_name,
        window_station_security,
        super::security::SecurityObjectKind::WindowStation,
        token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            format!("retained window-station semantic reattestation failed: {error}"),
        )
    })?;
    attest_target_user_object(
        retained_desktop,
        desktop_name,
        desktop_security,
        super::security::SecurityObjectKind::Desktop,
        token,
    )
    .map_err(|error| {
        TargetDesktopBootstrapFailure::contract(
            TargetDesktopBootstrapPhaseV1::TargetAssociationPreflight,
            format!("retained desktop semantic reattestation failed: {error}"),
        )
    })
}

fn duplicate_explicit_impersonation_token(token: HANDLE) -> Result<OwnedHandle, String> {
    let mut impersonation = ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            token,
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_IMPERSONATE,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &raw mut impersonation,
        )
    } == 0
    {
        return Err(format!(
            "cannot duplicate explicit-binding preflight token: {}",
            io::Error::last_os_error()
        ));
    }
    OwnedHandle::new(impersonation)
}

#[cfg(test)]
pub(crate) fn attest_target_token_capability_for_test(token: HANDLE) -> Result<(), String> {
    let transferred =
        duplicate_remote_target_token_capability(token, unsafe { GetCurrentProcess() })?;
    let transferred = OwnedHandle::new(transferred as usize as HANDLE)?;
    verify_not_inheritable(transferred.raw())?;
    super::token::token_attestation_snapshot(transferred.raw())?;
    let _impersonation = duplicate_explicit_impersonation_token(transferred.raw())?;
    Ok(())
}

fn attest_target_user_object(
    handle: HANDLE,
    expected_name: &str,
    security: &SecurityDescriptor,
    kind: super::security::SecurityObjectKind,
    token: HANDLE,
) -> Result<(), String> {
    verify_user_object_not_inheritable(handle)?;
    if user_object_name(handle).map_err(|error| error.to_string())? != expected_name {
        return Err("private target USER-object name changed".to_owned());
    }
    security
        .verify_user_object(handle, kind)
        .map_err(|error| format!("private target USER-object readback failed: {error}"))?;
    let expected_policy_sha256 = security.user_object_policy_fingerprint(kind)?;
    let actual_policy_sha256 = security.user_object_resultant_fingerprint(handle, kind)?;
    if actual_policy_sha256 != expected_policy_sha256 {
        return Err("private target USER-object canonical policy fingerprint changed".to_owned());
    }
    let requested = match kind {
        super::security::SecurityObjectKind::WindowStation => {
            super::security::TARGET_PRIVATE_WINDOW_STATION_ACCESS
        }
        super::security::SecurityObjectKind::Desktop => {
            super::security::TARGET_PRIVATE_DESKTOP_ACCESS
        }
        _ => {
            return Err(
                "target USER-object attestation requires a private station or desktop".to_owned(),
            );
        }
    };
    let (allowed, granted) = match kind {
        super::security::SecurityObjectKind::WindowStation => {
            security.private_window_station_access_check(token)?
        }
        super::security::SecurityObjectKind::Desktop => {
            security.private_desktop_access_check(token)?
        }
        _ => unreachable!(),
    };
    if !allowed || granted & requested != requested {
        return Err(format!(
            "private target {kind:?} AccessCheck failed: requested={requested:#010x} granted={granted:#010x} allowed={allowed}"
        ));
    }
    Ok(())
}

fn verify_user_object_not_inheritable(handle: HANDLE) -> Result<(), String> {
    // SAFETY: zero is a valid initial representation for this output-only POD.
    let mut flags = unsafe { std::mem::zeroed::<USEROBJECTFLAGS>() };
    let mut needed = 0_u32;
    let expected = std::mem::size_of::<USEROBJECTFLAGS>() as u32;
    // SAFETY: handle denotes a live window station or desktop, flags is an
    // exact-sized writable output, and needed records the provider byte count.
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_FLAGS,
            (&raw mut flags).cast(),
            expected,
            &raw mut needed,
        )
    } == 0
    {
        return Err(format!(
            "cannot read private target USER-object flags: {}",
            io::Error::last_os_error()
        ));
    }
    if needed != expected {
        return Err(format!(
            "private target USER-object flags have unexpected size: expected={expected} actual={needed}"
        ));
    }
    if flags.fInherit != 0 {
        return Err("private target USER-object handle is inheritable".to_owned());
    }
    Ok(())
}

fn target_desktop_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; TARGET_DESKTOP_NONCE_BYTES];
    // SAFETY: system-preferred CNG fills the exact mutable byte array.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err("Windows CSPRNG failed for target desktop nonce".to_owned());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(crate) fn attest_current_target_desktop() -> Result<(String, String), String> {
    let mut token = ptr::null_mut();
    // SAFETY: the current process is live and output receives one owned token
    // handle used only for exact USER-object policy and AccessCheck readback.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,
            &raw mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let context = CapturedTargetDesktop::capture(token.raw())?;
    Ok((context.window_station_name, context.desktop_name))
}

impl From<String> for TargetCreateError {
    fn from(detail: String) -> Self {
        Self {
            detail,
            os_code: None,
            loader_context: false,
        }
    }
}

impl TargetCreateError {
    fn loader_context(detail: String) -> Self {
        Self::loader_context_with_os(detail, None)
    }

    fn loader_context_with_os(detail: String, os_code: Option<i32>) -> Self {
        Self {
            detail,
            os_code,
            loader_context: true,
        }
    }
}

impl SuspendedTarget {
    #[allow(clippy::too_many_arguments)] // Native creation requires each authority input explicitly.
    pub fn create(
        token: HANDLE,
        loader_restriction_canary: Option<&LoaderRestrictionCanaryTokens>,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
        launcher_pipe: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
    ) -> Result<Self, TargetCreateError> {
        Self::create_with_object_security(
            token,
            loader_restriction_canary,
            job,
            command,
            environment,
            current_directory,
            streams,
            launcher_pipe,
            certification_fault,
            certification_mutant,
            TargetObjectSecurity::LauncherService,
        )
    }

    pub(super) fn create_nested_canary(
        token: HANDLE,
        initial_thread_token: HANDLE,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
    ) -> Result<NestedSuspendedTarget, TargetCreateError> {
        verify_not_inheritable(initial_thread_token).map_err(TargetCreateError::from)?;
        let requested_before_install =
            super::token::token_attestation_snapshot(initial_thread_token)
                .map_err(TargetCreateError::from)?;
        let target = Self::create_with_object_security(
            token,
            None,
            job,
            command,
            environment,
            current_directory,
            streams,
            ptr::null_mut(),
            None,
            None,
            TargetObjectSecurity::NestedCanaryCreator,
        )?;
        let installed =
            super::token::install_thread_token(target.thread.raw(), initial_thread_token)
                .map_err(TargetCreateError::from)?;
        let requested_before_failures =
            super::token::nested_loader_behavior_failures(&requested_before_install.behavior);
        let requested_after_failures = super::token::nested_loader_behavior_failures(
            &installed.requested_after_install.behavior,
        );
        let observed_failures =
            super::token::nested_loader_behavior_failures(&installed.observed_thread.behavior);
        let requested_transition_fields = super::token::envelope_mismatch_fields(
            &requested_before_install.behavior.envelope,
            &installed.requested_after_install.behavior.envelope,
        );
        let observed_transition_fields = super::token::envelope_mismatch_fields(
            &requested_before_install.behavior.envelope,
            &installed.observed_thread.behavior.envelope,
        );
        if requested_before_install.instance.token_id == 0
            || installed.requested_after_install.instance.token_id == 0
            || installed.observed_thread.instance.token_id == 0
            || requested_before_install.instance != installed.requested_after_install.instance
            || requested_before_install.instance != installed.observed_thread.instance
            || requested_before_install.lineage != installed.requested_after_install.lineage
            || requested_before_install.lineage != installed.observed_thread.lineage
            || requested_before_install.behavior != installed.requested_after_install.behavior
            || requested_before_install.behavior != installed.observed_thread.behavior
            || !requested_before_failures.is_empty()
            || !requested_after_failures.is_empty()
            || !observed_failures.is_empty()
        {
            return Err(TargetCreateError::from(format!(
                "nested initial thread token attestation failed: requested_transition_fields=[{}] observed_transition_fields=[{}] requested_before_invariant_failures=[{}] requested_after_invariant_failures=[{}] observed_invariant_failures=[{}] requested_before={requested_before_install:?} requested_after={:?} observed_thread={:?}",
                requested_transition_fields.join(", "),
                observed_transition_fields.join(", "),
                requested_before_failures.join(", "),
                requested_after_failures.join(", "),
                observed_failures.join(", "),
                installed.requested_after_install,
                installed.observed_thread,
            )));
        }
        Ok(NestedSuspendedTarget {
            target,
            initial: installed,
        })
    }

    #[allow(clippy::too_many_arguments)] // Native creation requires each authority input explicitly.
    fn create_with_object_security(
        token: HANDLE,
        loader_restriction_canary: Option<&LoaderRestrictionCanaryTokens>,
        job: &Job,
        command: &NativeWindowsCommandV1,
        environment: &[WindowsEnvironmentEntryV1],
        current_directory: &[u16],
        streams: &StreamSet,
        launcher_pipe: HANDLE,
        certification_fault: Option<WindowsSealedFault>,
        certification_mutant: Option<WindowsSealedMutant>,
        object_security: TargetObjectSecurity,
    ) -> Result<Self, TargetCreateError> {
        validate_native_command(command)?;
        let requested_process_snapshot =
            super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
        let mut desktop_lease = None;
        let mut captured_desktop = None;
        match object_security {
            TargetObjectSecurity::LauncherService => {
                let policy_role = target_user_object_policy_role(command);
                desktop_lease = Some(
                    TargetDesktopLease::create(token, policy_role, loader_restriction_canary)
                        .map_err(|error| {
                            TargetCreateError::loader_context_with_os(error.detail, error.os_code)
                        })?,
                );
            }
            TargetObjectSecurity::NestedCanaryCreator => {
                captured_desktop = Some(
                    CapturedTargetDesktop::capture(token)
                        .map_err(TargetCreateError::loader_context)?,
                );
            }
        }
        let desktop_binding = desktop_lease
            .as_ref()
            .map(|desktop| desktop.exact_name.clone())
            .or_else(|| {
                captured_desktop
                    .as_ref()
                    .map(|desktop| desktop.exact_name.clone())
            })
            .ok_or_else(|| {
                TargetCreateError::from("target desktop binding is absent".to_owned())
            })?;
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
        let process_sddl = match object_security {
            TargetObjectSecurity::LauncherService => super::security::launcher_process_sddl()?,
            TargetObjectSecurity::NestedCanaryCreator => {
                super::security::nested_canary_process_sddl()?
            }
        };
        let process_security = super::security::SecurityDescriptor::from_sddl(&process_sddl)?;
        let process_attributes = process_security.attributes(false);
        let thread_sddl = match object_security {
            TargetObjectSecurity::LauncherService => super::security::launcher_thread_sddl()?,
            TargetObjectSecurity::NestedCanaryCreator => {
                super::security::nested_canary_thread_sddl()?
            }
        };
        let thread_security = super::security::SecurityDescriptor::from_sddl(&thread_sddl)?;
        let thread_attributes = thread_security.attributes(false);
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
        startup.StartupInfo.lpDesktop = desktop_lease.as_mut().map_or_else(
            || {
                captured_desktop
                    .as_mut()
                    .expect("captured target desktop must exist for nested creation")
                    .startup_name
                    .as_mut_ptr()
            },
            |desktop| desktop.startup_name.as_mut_ptr(),
        );
        startup.lpAttributeList = attributes.raw();
        let mut process = PROCESS_INFORMATION::default();
        reject_fault(certification_fault, WindowsSealedFault::CreateProcessAsUser)?;
        if let Some(lease) = desktop_lease.as_ref() {
            lease
                .attest_live()
                .map_err(TargetCreateError::loader_context)?;
        }
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
        let process_source_before =
            super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
        super::token::require_same_token_instance(
            "real-target-request-preflight",
            &requested_process_snapshot,
            &process_source_before,
        )
        .map_err(|error| TargetCreateError::from(error.to_string()))?;
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
                    &raw const thread_attributes,
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
                    &raw const thread_attributes,
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
                loader_context: false,
            });
        }
        let process_handle = OwnedHandle::new(process.hProcess).map_err(TargetCreateError::from)?;
        let thread_handle = OwnedHandle::new(process.hThread).map_err(TargetCreateError::from)?;
        let mut observed_process_snapshot = None;
        if !matches!(
            certification_mutant,
            Some(
                WindowsSealedMutant::UseCreateProcessW
                    | WindowsSealedMutant::CreateUnderServiceToken
                    | WindowsSealedMutant::TrustClientToken
                    | WindowsSealedMutant::SkipTargetTokenReadback
            )
        ) {
            let observed_snapshot =
                super::token::process_token_query_attestation(process_handle.raw())
                    .map_err(TargetCreateError::from)?;
            let process_source_after =
                super::token::token_attestation_snapshot(token).map_err(TargetCreateError::from)?;
            let relation = super::token::require_same_token_instance(
                "real-target-request-invariance",
                &process_source_before,
                &process_source_after,
            )
            .and_then(|()| {
                super::token::require_assigned_process_authority(
                    "target-request-to-real-process",
                    &process_source_before,
                    &observed_snapshot,
                )
                .map(|_| ())
            });
            if let Err(error) = relation {
                unsafe {
                    TerminateProcess(
                        process_handle.raw(),
                        TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS,
                    )
                };
                let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
                return Err(TargetCreateError::from(error.to_string()));
            }
            observed_process_snapshot = Some(observed_snapshot);
        }
        let desktop_attestation = desktop_lease.as_ref().map_or_else(
            || captured_desktop.as_ref().unwrap().attest(token),
            TargetDesktopLease::attest_live,
        );
        if let Err(error) = desktop_attestation {
            unsafe {
                TerminateProcess(
                    process_handle.raw(),
                    TARGET_DESKTOP_BOOTSTRAP_FAILURE_STATUS,
                )
            };
            let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
            return Err(TargetCreateError::loader_context(error));
        }
        if certification_mutant == Some(WindowsSealedMutant::AssignJobAfterCreate)
            && unsafe { AssignProcessToJobObject(job.handle(), process_handle.raw()) } == 0
        {
            return Err(TargetCreateError::from(
                io::Error::last_os_error().to_string(),
            ));
        }
        process_security
            .verify_kernel_object(
                process_handle.raw(),
                super::security::SecurityObjectKind::Process,
            )
            .map_err(TargetCreateError::from)?;
        thread_security
            .verify_kernel_object(
                thread_handle.raw(),
                super::security::SecurityObjectKind::Thread,
            )
            .map_err(TargetCreateError::from)?;
        Ok(Self {
            process: process_handle,
            thread: thread_handle,
            process_snapshot: observed_process_snapshot,
            _desktop_lease: desktop_lease,
            desktop_binding,
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

    pub fn desktop_binding(&self) -> &str {
        &self.desktop_binding
    }

    pub fn attest_process_token_snapshot(
        &self,
        observed: &super::token::TokenQueryAttestationSnapshot,
    ) -> Result<(), String> {
        let expected = self.process_snapshot.as_ref().ok_or_else(|| {
            "real-target process snapshot is absent from its creation transcript".to_owned()
        })?;
        super::token::require_same_process_token_query(
            "real-target-process-live",
            expected,
            observed,
        )
        .map_err(|error| error.to_string())
    }

    pub fn desktop_authority_live(&self) -> Result<bool, String> {
        match &self._desktop_lease {
            Some(lease) => match lease.attest_live() {
                Ok(()) => Ok(true),
                Err(_)
                    if unsafe { WaitForSingleObject(lease.bootstrap_process.raw(), 0) }
                        == WAIT_OBJECT_0 =>
                {
                    Ok(false)
                }
                Err(error) => Err(error),
            },
            None => Ok(true),
        }
    }

    pub fn resume(&self, certification_fault: Option<WindowsSealedFault>) -> Result<(), String> {
        reject_fault(certification_fault, WindowsSealedFault::Resume)?;
        if let Some(expected) = self.process_snapshot.as_ref() {
            let observed = super::token::process_token_query_attestation(self.process.raw())?;
            super::token::require_same_process_token_query(
                "real-target-process-before-resume",
                expected,
                &observed,
            )
            .map_err(|error| error.to_string())?;
        }
        if !self.desktop_authority_live()? {
            return Err("target desktop bootstrap exited before workload resume".to_owned());
        }
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

fn target_user_object_policy_role(
    command: &NativeWindowsCommandV1,
) -> super::security::TargetUserObjectPolicyRoleV1 {
    if command.arguments.first().is_some_and(|mode| {
        mode.iter()
            .copied()
            .eq("windows-certification-nested-target".encode_utf16())
    }) {
        super::security::TargetUserObjectPolicyRoleV1::NestedWriteRestrictedDelegation
    } else {
        super::security::TargetUserObjectPolicyRoleV1::DirectTarget
    }
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

#[derive(Debug)]
pub(crate) struct ProcessIdentityObservationError {
    process_id: u32,
    subphase: &'static str,
    service_os_code: Option<i32>,
    retry_os_code: Option<i32>,
    detail: String,
}

impl ProcessIdentityObservationError {
    fn new(
        process_id: u32,
        subphase: &'static str,
        service_os_code: Option<i32>,
        retry_os_code: Option<i32>,
        detail: impl std::fmt::Display,
    ) -> Self {
        Self {
            process_id,
            subphase,
            service_os_code,
            retry_os_code,
            detail: detail.to_string(),
        }
    }

    pub(crate) const fn os_code(&self) -> Option<i32> {
        match self.retry_os_code {
            Some(code) => Some(code),
            None => self.service_os_code,
        }
    }
}

impl std::fmt::Display for ProcessIdentityObservationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "subphase={} process_id={} service_os_code={} retry_os_code={} detail={}",
            self.subphase,
            self.process_id,
            self.service_os_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.retry_os_code
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            self.detail,
        )
    }
}

pub(crate) fn process_identity_for_pid_as_authenticated_caller(
    process_id: u32,
    authenticated_primary: HANDLE,
    job: &Job,
) -> Result<Option<WindowsProcessIdentityV1>, ProcessIdentityObservationError> {
    let mut service_os_code = None;
    let mut retry_os_code = None;
    // SAFETY: the PID came from a Job process-list kernel readback and the
    // returned handle is adopted immediately.
    let mut raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if raw.is_null() {
        let service_error = io::Error::last_os_error();
        service_os_code = service_error.raw_os_error();
        let service_code = service_os_code.and_then(|value| u32::try_from(value).ok());
        if service_code == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER) {
            return Ok(None);
        }
        if service_code != Some(windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED) {
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "service-context-process-open",
                service_os_code,
                None,
                service_error,
            ));
        }

        let mut impersonation = ptr::null_mut();
        // SAFETY: authenticated_primary is the launcher-owned primary token
        // admitted from the authenticated caller. The duplicate is local and
        // receives only query and thread-impersonation rights.
        if unsafe {
            DuplicateTokenEx(
                authenticated_primary,
                TOKEN_IMPERSONATE,
                ptr::null(),
                SecurityImpersonation,
                TokenImpersonation,
                &raw mut impersonation,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "caller-impersonation-token-duplicate",
                service_os_code,
                error.raw_os_error(),
                error,
            ));
        }
        let impersonation = OwnedHandle::new(impersonation).map_err(|detail| {
            ProcessIdentityObservationError::new(
                process_id,
                "caller-impersonation-token-adopt",
                service_os_code,
                None,
                detail,
            )
        })?;
        let impersonation_guard =
            ThreadImpersonationGuard::install(impersonation.raw()).map_err(|error| {
                ProcessIdentityObservationError::new(
                    process_id,
                    "caller-thread-impersonation",
                    service_os_code,
                    error.raw_os_error(),
                    error,
                )
            })?;
        // SAFETY: only this process-object open occurs under caller
        // impersonation. Identity query and every service operation execute
        // after the immediate RevertToSelf below.
        raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
        let retry_error = raw.is_null().then(io::Error::last_os_error);
        retry_os_code = retry_error.as_ref().and_then(io::Error::raw_os_error);
        if let Err(error) = impersonation_guard.revert() {
            if !raw.is_null() {
                // Adopt the successful retry before returning so it is closed.
                drop(OwnedHandle::new(raw));
            }
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "caller-thread-revert",
                service_os_code,
                retry_os_code.or_else(|| error.raw_os_error()),
                error,
            ));
        }
        drop(impersonation);
        if let Some(error) = retry_error {
            let retry_os_code = error.raw_os_error();
            if retry_os_code.and_then(|value| u32::try_from(value).ok())
                == Some(windows_sys::Win32::Foundation::ERROR_INVALID_PARAMETER)
            {
                return Ok(None);
            }
            return Err(ProcessIdentityObservationError::new(
                process_id,
                "authenticated-caller-process-open",
                service_os_code,
                retry_os_code,
                error,
            ));
        }
    }

    let process = OwnedHandle::new(raw).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-handle-adopt",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    let identity = process_identity(process.raw()).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-identity-readback",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    if identity.process_id != process_id {
        return Err(ProcessIdentityObservationError::new(
            process_id,
            "process-identity-pid-mismatch",
            service_os_code,
            retry_os_code,
            format!("opened_process_id={}", identity.process_id),
        ));
    }
    let still_contained = job.contains(process.raw()).map_err(|detail| {
        ProcessIdentityObservationError::new(
            process_id,
            "process-job-membership-readback",
            service_os_code,
            retry_os_code,
            detail,
        )
    })?;
    if !still_contained {
        return Ok(None);
    }
    Ok(Some(identity))
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

struct GuardianDesktopContext {
    window_station: HANDLE,
    desktop: HANDLE,
    window_station_name: String,
    desktop_name: String,
    exact_name: String,
    startup_name: Vec<u16>,
}

impl GuardianDesktopContext {
    fn capture() -> Result<Self, GuardianLoaderPreparationError> {
        // These assigned USER handles are borrowed and remain pinned by the
        // launcher process/current thread. They must not be closed as ordinary
        // kernel handles or replaced by a guessed interactive station.
        let window_station = unsafe { GetProcessWindowStation() };
        if window_station.is_null() {
            return Err(GuardianLoaderPreparationError::native(
                GuardianLoaderPreparationSubphase::DesktopStationCapture,
                "cannot capture launcher window station",
            ));
        }
        let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        if desktop.is_null() {
            return Err(GuardianLoaderPreparationError::native(
                GuardianLoaderPreparationSubphase::DesktopCapture,
                "cannot capture launcher thread desktop",
            ));
        }
        let window_station_name = user_object_name(window_station).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopNameReadback,
                error,
            )
        })?;
        let desktop_name = user_object_name(desktop).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopNameReadback,
                error,
            )
        })?;
        let receives_input = desktop_receives_input(desktop).map_err(|error| {
            GuardianLoaderPreparationError::from_user_object(
                GuardianLoaderPreparationSubphase::DesktopAttestation,
                error,
            )
        })?;
        validate_guardian_desktop_binding(&window_station_name, &desktop_name, receives_input)?;
        let exact_name = format!("{window_station_name}\\{desktop_name}");
        let mut startup_name = exact_name.encode_utf16().collect::<Vec<_>>();
        startup_name.push(0);
        let context = Self {
            window_station,
            desktop,
            window_station_name,
            desktop_name,
            exact_name,
            startup_name,
        };
        context.attest()?;
        Ok(context)
    }

    fn attest(&self) -> Result<(), GuardianLoaderPreparationError> {
        if unsafe { GetProcessWindowStation() } != self.window_station
            || unsafe { GetThreadDesktop(GetCurrentThreadId()) } != self.desktop
            || user_object_name(self.window_station).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopNameReadback,
                    error,
                )
            })? != self.window_station_name
            || user_object_name(self.desktop).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopNameReadback,
                    error,
                )
            })? != self.desktop_name
        {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::DesktopAttestation,
                "launcher window-station/desktop binding changed during guardian creation",
            ));
        }
        validate_guardian_desktop_binding(
            &self.window_station_name,
            &self.desktop_name,
            desktop_receives_input(self.desktop).map_err(|error| {
                GuardianLoaderPreparationError::from_user_object(
                    GuardianLoaderPreparationSubphase::DesktopAttestation,
                    error,
                )
            })?,
        )
    }

    fn exact_name(&self) -> &str {
        &self.exact_name
    }
}

fn user_object_name(handle: HANDLE) -> Result<String, UserObjectQueryError> {
    let mut needed = 0_u32;
    // SAFETY: this size query supplies no output buffer and writes the required
    // byte count for the live assigned USER object.
    let sized =
        unsafe { GetUserObjectInformationW(handle, UOI_NAME, ptr::null_mut(), 0, &raw mut needed) };
    let sizing_error = io::Error::last_os_error();
    if sized != 0 {
        return Err(UserObjectQueryError::contract(
            "USER object name sizing unexpectedly succeeded without a buffer",
        ));
    }
    let unit_bytes = std::mem::size_of::<u16>() as u32;
    if needed < unit_bytes || needed % unit_bytes != 0 {
        if sizing_error.raw_os_error().is_some_and(|code| code != 0) {
            return Err(UserObjectQueryError::from_io(
                "cannot size USER object name",
                sizing_error,
            ));
        }
        return Err(UserObjectQueryError::contract(format!(
            "USER object name sizing returned an invalid byte count without a native failure: {needed}"
        )));
    }
    let capacity_bytes = needed;
    let mut value = vec![0_u16; needed as usize / std::mem::size_of::<u16>()];
    // SAFETY: value has the exact API-requested byte capacity and the USER
    // object remains pinned by its process/thread assignment.
    if unsafe {
        GetUserObjectInformationW(
            handle,
            UOI_NAME,
            value.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native("cannot read USER object name"));
    }
    if needed < unit_bytes || needed > capacity_bytes || needed % unit_bytes != 0 {
        return Err(UserObjectQueryError::contract(format!(
            "USER object name read returned an invalid byte count: capacity={capacity_bytes} actual={needed}"
        )));
    }
    let returned_units = needed as usize / std::mem::size_of::<u16>();
    if value.get(returned_units - 1) != Some(&0) {
        return Err(UserObjectQueryError::contract(
            "USER object name read omitted its UTF-16 terminator",
        ));
    }
    String::from_utf16(&value[..returned_units - 1])
        .map_err(|_| UserObjectQueryError::contract("USER object name is not valid UTF-16"))
}

fn desktop_receives_input(desktop: HANDLE) -> Result<bool, UserObjectQueryError> {
    let mut receives_input = 0_i32;
    let mut needed = 0_u32;
    // SAFETY: receives_input is writable and desktop is the pinned current
    // thread desktop. UOI_IO returns a BOOL-sized observation.
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_IO,
            (&raw mut receives_input).cast(),
            std::mem::size_of_val(&receives_input) as u32,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native(
            "cannot query whether desktop receives interactive input",
        ));
    }
    Ok(receives_input != 0)
}

fn desktop_heap_kb(desktop: HANDLE) -> Result<u32, UserObjectQueryError> {
    let mut heap_kb = 0_u32;
    let mut needed = 0_u32;
    // SAFETY: heap_kb is a writable ULONG-sized buffer and desktop remains
    // pinned by the retained Holder handle. UOI_HEAPSIZE is read-only.
    if unsafe {
        GetUserObjectInformationW(
            desktop,
            UOI_HEAPSIZE_CLASS,
            (&raw mut heap_kb).cast(),
            std::mem::size_of_val(&heap_kb) as u32,
            &raw mut needed,
        )
    } == 0
    {
        return Err(UserObjectQueryError::native(
            "cannot query private desktop heap size",
        ));
    }
    if needed != std::mem::size_of_val(&heap_kb) as u32 || heap_kb == 0 {
        return Err(UserObjectQueryError::contract(format!(
            "private desktop heap query returned an invalid result: bytes={needed} heap_kb={heap_kb}"
        )));
    }
    Ok(heap_kb)
}

#[cfg(test)]
pub(crate) fn attest_current_user_binding_duplicates_for_test() -> Result<(), String> {
    let window_station = unsafe { GetProcessWindowStation() };
    let desktop = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
    if window_station.is_null() || desktop.is_null() {
        return Err("test process has no Windows-provisioned USER binding".to_owned());
    }
    let expected_station = user_object_name(window_station).map_err(|error| error.to_string())?;
    let expected_desktop = user_object_name(desktop).map_err(|error| error.to_string())?;
    let duplicates = TargetUserBindingReadHandles::duplicate(window_station, desktop)
        .map_err(|error| error.to_string())?;
    if user_object_name(duplicates.window_station.raw()).map_err(|error| error.to_string())?
        != expected_station
        || user_object_name(duplicates.desktop.raw()).map_err(|error| error.to_string())?
            != expected_desktop
    {
        return Err("reduced-access USER duplicates changed object identity".to_owned());
    }
    desktop_receives_input(duplicates.desktop.raw()).map_err(|error| error.to_string())?;
    SecurityDescriptor::user_object_security_equality_fingerprint(duplicates.window_station.raw())?;
    SecurityDescriptor::user_object_security_equality_fingerprint(duplicates.desktop.raw())?;
    let station_access = super::token::granted_handle_access(duplicates.window_station.raw())?;
    let desktop_access = super::token::granted_handle_access(duplicates.desktop.raw())?;
    if station_access != TARGET_STATION_ATTEST_ACCESS
        || desktop_access != TARGET_DESKTOP_ATTEST_ACCESS
    {
        return Err(format!(
            "USER duplicate access mismatch: station_expected={TARGET_STATION_ATTEST_ACCESS:#x} station_actual={station_access:#x} desktop_expected={TARGET_DESKTOP_ATTEST_ACCESS:#x} desktop_actual={desktop_access:#x}"
        ));
    }
    let TargetUserBindingReadHandles {
        window_station: station_duplicate,
        desktop: desktop_duplicate,
    } = duplicates;
    station_duplicate
        .close()
        .map_err(|error| format!("cannot close station attestation duplicate: {error}"))?;
    desktop_duplicate
        .close()
        .map_err(|error| format!("cannot close desktop attestation duplicate: {error}"))?;
    if user_object_name(window_station).map_err(|error| error.to_string())? != expected_station
        || user_object_name(desktop).map_err(|error| error.to_string())? != expected_desktop
    {
        return Err("closing USER duplicates changed the assigned binding handles".to_owned());
    }
    Ok(())
}

fn validate_desktop_binding_names(window_station: &str, desktop: &str) -> Result<(), String> {
    if window_station.is_empty()
        || desktop.is_empty()
        || window_station.contains('\\')
        || desktop.contains('\\')
    {
        Err("desktop names are empty or structurally ambiguous".to_owned())
    } else {
        Ok(())
    }
}

pub(crate) fn validate_guardian_desktop_binding(
    window_station: &str,
    desktop: &str,
    receives_input: bool,
) -> Result<(), GuardianLoaderPreparationError> {
    validate_desktop_binding_names(window_station, desktop).map_err(|error| {
        GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            format!("launcher {error}"),
        )
    })?;
    if window_station.eq_ignore_ascii_case("WinSta0") || receives_input {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            "launcher desktop is interactive; refusing to broaden guardian UI reachability",
        ));
    }
    Ok(())
}

struct GuardianStandardHandles {
    input: OwnedHandle,
    output: OwnedHandle,
    error: OwnedHandle,
}

impl GuardianStandardHandles {
    fn prepare() -> Result<Self, GuardianLoaderPreparationError> {
        Ok(Self {
            input: open_guardian_null_handle(
                GENERIC_READ,
                GuardianLoaderPreparationSubphase::StandardInput,
            )?,
            output: open_guardian_null_handle(
                GENERIC_WRITE,
                GuardianLoaderPreparationSubphase::StandardOutput,
            )?,
            error: open_guardian_null_handle(
                GENERIC_WRITE,
                GuardianLoaderPreparationSubphase::StandardError,
            )?,
        })
    }

    const fn raw(&self) -> [HANDLE; 3] {
        [self.input.raw(), self.output.raw(), self.error.raw()]
    }
}

fn open_guardian_null_handle(
    access: u32,
    subphase: GuardianLoaderPreparationSubphase,
) -> Result<OwnedHandle, GuardianLoaderPreparationError> {
    let nul = super::pipe::wide_null("NUL");
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    // SAFETY: NUL is a live NUL-terminated device name and attributes requests
    // inheritance while retaining the creator token's default descriptor.
    let raw = unsafe {
        CreateFileW(
            nul.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    let handle = OwnedHandle::new(raw)
        .map_err(|_| GuardianLoaderPreparationError::native(subphase, "cannot open NUL"))?;
    verify_inheritable(handle.raw())
        .map_err(|error| GuardianLoaderPreparationError::contract(subphase, error))?;
    // SAFETY: handle is a live NUL device handle.
    if unsafe { GetFileType(handle.raw()) } != FILE_TYPE_CHAR {
        return Err(GuardianLoaderPreparationError::contract(
            subphase,
            "NUL standard handle did not attest as a character device",
        ));
    }
    Ok(handle)
}

fn validate_guardian_loader_handle_list(
    handles: &[HANDLE],
) -> Result<(), GuardianLoaderPreparationError> {
    if handles.len() != 5 {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::HandleList,
            "guardian loader list must contain three standard handles and two bootstrap endpoints",
        ));
    }
    for (index, handle) in handles.iter().copied().enumerate() {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::HandleList,
                format!("guardian loader handle {index} is invalid"),
            ));
        }
        if handles[..index].contains(&handle) {
            return Err(GuardianLoaderPreparationError::contract(
                GuardianLoaderPreparationSubphase::HandleList,
                format!("guardian loader handle {index} aliases an earlier role"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn attest_current_guardian_desktop(
    expected: &str,
) -> Result<(), GuardianLoaderPreparationError> {
    let context = GuardianDesktopContext::capture()?;
    if context.exact_name() != expected {
        return Err(GuardianLoaderPreparationError::contract(
            GuardianLoaderPreparationSubphase::DesktopAttestation,
            "guardian desktop readback differs from launcher capture",
        ));
    }
    Ok(())
}

pub(crate) fn prepare_service_guardian_context() -> Result<([HANDLE; 3], String), String> {
    let desktop = GuardianDesktopContext::capture().map_err(|error| error.to_string())?;
    let handles = GuardianStandardHandles::prepare().map_err(|error| error.to_string())?;
    let raw = handles.raw();
    for (kind, handle) in [
        (STD_INPUT_HANDLE, raw[0]),
        (STD_OUTPUT_HANDLE, raw[1]),
        (STD_ERROR_HANDLE, raw[2]),
    ] {
        // SAFETY: the exact live NUL handle becomes the SCM guardian's loader
        // compatibility standard handle and remains owned until guardian::run.
        if unsafe { SetStdHandle(kind, handle) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
    }
    let exact_name = desktop.exact_name().to_owned();
    std::mem::forget(handles);
    Ok((raw, exact_name))
}

pub fn certify_guardian_loader_context_negatives() -> Result<(), String> {
    let handles = [
        1_usize as HANDLE,
        2_usize as HANDLE,
        3_usize as HANDLE,
        4_usize as HANDLE,
        5_usize as HANDLE,
    ];
    if validate_guardian_loader_handle_list(&handles).is_err()
        || validate_guardian_loader_handle_list(&handles[..4]).is_ok()
        || validate_guardian_loader_handle_list(&[
            handles[0], handles[1], handles[1], handles[3], handles[4],
        ])
        .is_ok()
        || validate_guardian_loader_handle_list(&[
            handles[0],
            ptr::null_mut(),
            handles[2],
            handles[3],
            handles[4],
        ])
        .is_ok()
        || validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", false).is_err()
        || validate_guardian_desktop_binding("WinSta0", "Default", false).is_ok()
        || validate_guardian_desktop_binding("Service-0x0-3e7$", "Default", true).is_ok()
    {
        Err("guardian loader-context negative certification failed".to_owned())
    } else {
        Ok(())
    }
}

static LEASED_GUARDIAN_SLOTS: LazyLock<Mutex<HashSet<usize>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn recover_guardian_slots() -> Result<(), String> {
    let manager = super::service_manager::manager_connect()?;
    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        let name = super::security::guardian_slot_name(index)?;
        let service = super::service_manager::open(
            &manager,
            &name,
            SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | READ_CONTROL_ACCESS,
        )?;
        let status = super::service_manager::status_process(&service)?;
        if status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0 {
            super::service_manager::stop(&service, &name)?;
        }
        let durable = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{index:03}.json"));
        if durable.exists() {
            std::fs::remove_file(&durable).map_err(|error| {
                format!(
                    "cannot retire stale guardian slot lease {}: {error}",
                    durable.display()
                )
            })?;
        }
    }
    Ok(())
}

struct GuardianSlotLease {
    index: usize,
    name: String,
    service: super::service_manager::ScHandle,
    durable: Option<GuardianSlotLeaseV1>,
    durable_path: Option<PathBuf>,
}

#[derive(Clone, Serialize)]
struct GuardianSlotLeaseV1 {
    schema_version: u32,
    slot_index: usize,
    service_name: String,
    attempt_id: String,
    nonce_sha256: String,
    launcher_identity: WindowsProcessIdentityV1,
    phase: &'static str,
}

impl GuardianSlotLease {
    fn bind(
        &mut self,
        attempt_id: &str,
        nonce: &str,
        launcher_identity: &WindowsProcessIdentityV1,
    ) -> Result<(), String> {
        let durable = GuardianSlotLeaseV1 {
            schema_version: 1,
            slot_index: self.index,
            service_name: self.name.clone(),
            attempt_id: attempt_id.to_owned(),
            nonce_sha256: super::record::digest(nonce.as_bytes()),
            launcher_identity: launcher_identity.clone(),
            phase: "reserved",
        };
        let path = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{:03}.json", self.index));
        self.durable = Some(durable);
        self.durable_path = Some(path);
        self.store_phase("reserved")
    }

    fn store_phase(&mut self, phase: &'static str) -> Result<(), String> {
        let record = self
            .durable
            .as_mut()
            .ok_or_else(|| "guardian slot durable binding is absent".to_owned())?;
        record.phase = phase;
        let path = self
            .durable_path
            .as_ref()
            .ok_or_else(|| "guardian slot durable path is absent".to_owned())?;
        let staged = path.with_extension("json.new");
        std::fs::write(
            &staged,
            serde_json::to_vec_pretty(record).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        super::record::replace_atomically(&staged, path)
    }
}

impl Drop for GuardianSlotLease {
    fn drop(&mut self) {
        let _ = super::service_manager::stop(&self.service, &self.name);
        if let Some(path) = self.durable_path.as_ref() {
            let _ = std::fs::remove_file(path);
        }
        LEASED_GUARDIAN_SLOTS
            .lock()
            .expect("guardian slot lease mutex")
            .remove(&self.index);
    }
}

pub struct GuardianProcess {
    process: OwnedHandle,
    _slot: GuardianSlotLease,
}

impl GuardianProcess {
    pub const fn raw(&self) -> HANDLE {
        self.process.raw()
    }
}

fn acquire_guardian_slot() -> Result<GuardianSlotLease, String> {
    let manager = super::service_manager::manager_connect()?;
    let mut leased = LEASED_GUARDIAN_SLOTS
        .lock()
        .map_err(|_| "guardian slot lease mutex poisoned".to_owned())?;
    for index in 0..memcordon_core::WINDOWS_GUARDIAN_SLOT_COUNT {
        if leased.contains(&index) {
            continue;
        }
        let name = super::security::guardian_slot_name(index)?;
        let durable_path = super::package::state_root()
            .join("guardian-slots")
            .join(format!("{index:03}.json"));
        if durable_path.exists() {
            continue;
        }
        let service = super::service_manager::open(
            &manager,
            &name,
            SERVICE_START
                | SERVICE_STOP
                | SERVICE_QUERY_STATUS
                | SERVICE_QUERY_CONFIG
                | READ_CONTROL_ACCESS,
        )?;
        let status = super::service_manager::status_process(&service)?;
        if status.dwCurrentState == SERVICE_STOPPED && status.dwProcessId == 0 {
            leased.insert(index);
            return Ok(GuardianSlotLease {
                index,
                name,
                service,
                durable: None,
                durable_path: None,
            });
        }
    }
    Err(
        "MCSEALED-WINDOWS-GUARDIAN-CAPACITY: every canonical guardian slot is leased or active"
            .to_owned(),
    )
}

fn guardian_nonce() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    // SAFETY: system-preferred CNG fills the exact mutable byte array and uses
    // no caller-provided algorithm handle.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } != 0
    {
        return Err("Windows CSPRNG failed for guardian slot nonce".to_owned());
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[allow(clippy::too_many_arguments)]
pub fn create_guardian(
    job: HANDLE,
    frontend: HANDLE,
    worker: HANDLE,
    disarm: HANDLE,
    ready: HANDLE,
    attempt_id: &str,
    cleanup_deadline_millis: u64,
    readiness_delay_millis: u64,
) -> Result<(GuardianProcess, u32), GuardianBootstrapError> {
    let mut slot = acquire_guardian_slot().map_err(GuardianBootstrapError::from)?;
    let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let nonce = guardian_nonce()?;
    slot.bind(attempt_id, &nonce, &launcher_identity)?;
    let pipe_name = format!("{}{}", memcordon_core::WINDOWS_GUARDIAN_PIPE_PREFIX, nonce);
    let listener = PipeListener::new(
        &pipe_name,
        SecurityDescriptor::from_sddl(&super::security::guardian_slot_pipe_sddl(slot.index)?)?,
    );
    let prepared = listener
        .prepare()
        .map_err(|error| GuardianBootstrapError::from(error.to_string()))?;
    let start_arguments = vec![
        super::guardian_service::SERVICE_BINDING_SCHEMA_VERSION.to_string(),
        slot.name.clone(),
        attempt_id.to_owned(),
        nonce.clone(),
        pipe_name,
        launcher_identity.process_id.to_string(),
        launcher_identity.creation_time_100ns.to_string(),
        cleanup_deadline_millis.to_string(),
        readiness_delay_millis.to_string(),
    ];
    super::service_manager::start_with_arguments(&slot.service, &slot.name, &start_arguments)?;
    slot.store_phase("starting")?;
    let bootstrap = listener.accept_prepared(prepared)?;
    let bootstrap_read = duplicate_owned(bootstrap.raw())?;
    let mut scm_status = super::service_manager::status_process(&slot.service)?;
    let status_deadline = Instant::now() + Duration::from_secs(10);
    while scm_status.dwCurrentState != SERVICE_RUNNING && Instant::now() < status_deadline {
        std::thread::sleep(Duration::from_millis(10));
        scm_status = super::service_manager::status_process(&slot.service)?;
    }
    if scm_status.dwCurrentState != SERVICE_RUNNING || scm_status.dwProcessId == 0 {
        return Err(GuardianBootstrapError::from(
            "guardian slot did not converge to RUNNING with a nonzero PID".to_owned(),
        ));
    }
    let mut pipe_pid = 0_u32;
    if unsafe { GetNamedPipeClientProcessId(bootstrap.raw(), &raw mut pipe_pid) } == 0
        || pipe_pid != scm_status.dwProcessId
    {
        return Err(GuardianBootstrapError::from(
            "guardian slot SCM and pipe process identities differ".to_owned(),
        ));
    }
    let process_handle = OwnedHandle::new(unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | 0x0040 | SYNCHRONIZE_ACCESS,
            0,
            pipe_pid,
        )
    })?;
    let guardian_identity = process_identity(process_handle.raw())?;
    authenticate_guardian_slot_process(process_handle.raw(), &slot.name, &guardian_identity)?;
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: attempt_id.to_owned(),
        nonce,
        guardian_service_name: slot.name.clone(),
        launcher_identity,
        guardian_identity: guardian_identity.clone(),
    };
    let mut cleanup = GuardianBootstrapCleanup::new(process_handle.raw());
    let hardened = read_guardian_bootstrap_frame(
        bootstrap_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match hardened {
        super::guardian::GuardianBootstrapMessageV1::Hardened {
            binding: observed,
            process_policy_attested: true,
            thread_policy_attested: true,
        } if observed == binding => {}
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian slot Hardened binding is invalid",
            ));
        }
    }
    slot.store_phase("hardened")?;
    let sources = [job, frontend, worker, disarm, ready];
    let expected = super::guardian::guardian_manifest_contract();
    let mut manifest = Vec::with_capacity(expected.len());
    for ((role, access), source) in expected.into_iter().zip(sources) {
        let remote = duplicate_remote_with_access(source, process_handle.raw(), access)?;
        cleanup.transferred.push(remote);
        manifest.push(super::guardian::GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: remote,
            access,
        });
    }
    super::pipe::write_frame(
        bootstrap.raw(),
        &super::guardian::GuardianBootstrapMessageV1::Capabilities {
            binding: binding.clone(),
            manifest,
        },
    )?;
    let ready_attestation = read_guardian_bootstrap_frame(
        bootstrap_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match ready_attestation {
        super::guardian::GuardianBootstrapMessageV1::Ready {
            binding: observed,
            roles,
            outside_target_job: true,
        } if observed == binding
            && roles
                == super::guardian::guardian_manifest_contract()
                    .map(|(role, _)| role.to_owned()) =>
        {
            cleanup.disarm();
            slot.store_phase("ready")?;
        }
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian slot Ready binding is invalid",
            ));
        }
    }
    let process_id = guardian_identity.process_id;
    Ok((
        GuardianProcess {
            process: process_handle,
            _slot: slot,
        },
        process_id,
    ))
}

fn authenticate_guardian_slot_process(
    process: HANDLE,
    slot_name: &str,
    expected_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if process_identity(process)? != *expected_identity {
        return Err("guardian slot process identity changed".to_owned());
    }
    verify_image_path(process, &super::package::installed_binary())?;
    let token = super::token::process_token(process)?;
    let slot_sid = super::security::service_sid(slot_name)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || !super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &slot_sid)?
        || !super::token::token_has_restricting_sid(token.raw(), &slot_sid)?
    {
        return Err("guardian slot token envelope is not canonical".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // The five exact inherited handles stay individually visible.
pub fn create_guardian_direct_negative(
    job: HANDLE,
    frontend: HANDLE,
    worker: HANDLE,
    disarm: HANDLE,
    ready: HANDLE,
    attempt_id: &str,
    cleanup_deadline_millis: u64,
    readiness_delay_millis: u64,
) -> Result<(OwnedHandle, u32), GuardianBootstrapError> {
    // Only three inert NUL standard handles and two bounded bootstrap-pipe
    // endpoints cross the loader boundary.
    // The five privileged workload capabilities are transferred after the
    // child has self-hardened and mutually authenticated this launcher.
    let mut desktop = GuardianDesktopContext::capture().map_err(GuardianBootstrapError::loader)?;
    let standard_handles =
        GuardianStandardHandles::prepare().map_err(GuardianBootstrapError::loader)?;
    let (child_read, parent_write) = pipe_pair(true)?;
    let (parent_read, child_write) = pipe_pair(true)?;
    clear_inherit(parent_write.raw())?;
    clear_inherit(parent_read.raw())?;
    let [standard_input, standard_output, standard_error] = standard_handles.raw();
    let inherited = [
        standard_input,
        standard_output,
        standard_error,
        child_read.raw(),
        child_write.raw(),
    ];
    validate_guardian_loader_handle_list(&inherited).map_err(GuardianBootstrapError::loader)?;
    for handle in inherited {
        verify_inheritable(handle)?;
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let launcher_identity = process_identity(unsafe { GetCurrentProcess() })?;
    let mut nonce_material = attempt_id.as_bytes().to_vec();
    nonce_material.extend_from_slice(&launcher_identity.process_id.to_le_bytes());
    nonce_material.extend_from_slice(&launcher_identity.creation_time_100ns.to_le_bytes());
    nonce_material.extend_from_slice(
        &unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }.to_le_bytes(),
    );
    let nonce = super::record::digest(&nonce_material);
    use std::os::windows::ffi::OsStrExt;
    let mut application_name = executable.as_os_str().encode_wide().collect::<Vec<_>>();
    application_name.push(0);
    let arguments = vec![
        executable.as_os_str().encode_wide().collect(),
        "windows-guardian".encode_utf16().collect(),
        (child_read.raw() as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (child_write.raw() as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_input as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_output as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        (standard_error as usize as u64)
            .to_string()
            .encode_utf16()
            .collect(),
        "direct-launch-negative".encode_utf16().collect(),
        desktop.exact_name().encode_utf16().collect(),
        attempt_id.encode_utf16().collect(),
        nonce.encode_utf16().collect(),
        cleanup_deadline_millis.to_string().encode_utf16().collect(),
        readiness_delay_millis.to_string().encode_utf16().collect(),
        launcher_identity
            .process_id
            .to_string()
            .encode_utf16()
            .collect(),
        launcher_identity
            .creation_time_100ns
            .to_string()
            .encode_utf16()
            .collect(),
        "0".encode_utf16().collect(),
    ];
    let mut command_line = encode_command_line(&arguments);
    command_line.push(0);
    let attributes = AttributeList::new(
        &[Attribute::new(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            std::mem::size_of_val(&inherited),
        )],
        None,
    )?;
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = standard_input;
    startup.StartupInfo.hStdOutput = standard_output;
    startup.StartupInfo.hStdError = standard_error;
    startup.StartupInfo.lpDesktop = desktop.startup_name.as_mut_ptr();
    startup.lpAttributeList = attributes.raw();
    let mut process = PROCESS_INFORMATION::default();
    // SAFETY: command, exact captured desktop, and attribute list remain live;
    // the exact five-handle loader list is inheritable; default process/thread
    // descriptors keep native startup OS-compatible. Guardian is outside the
    // target Job and no console creation/detachment mode is combined here.
    if unsafe {
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT,
            ptr::null(),
            ptr::null(),
            &raw const startup.StartupInfo,
            &raw mut process,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string().into());
    }
    let thread = OwnedHandle::new(process.hThread)?;
    let process_handle = OwnedHandle::new(process.hProcess)?;
    drop(thread);
    if let Err(error) = desktop.attest() {
        // SAFETY: process is the just-created owned guardian. A changed parent
        // desktop binding invalidates the exact launch contract before trust.
        unsafe { TerminateProcess(process_handle.raw(), 125) };
        let _ = unsafe { WaitForSingleObject(process_handle.raw(), 5_000) };
        return Err(GuardianBootstrapError::loader(error));
    }
    // Close the launcher's copies of child endpoints before any blocking read,
    // so pre-main child death produces EOF rather than an indefinite wait.
    drop(child_read);
    drop(child_write);
    // The child's three inherited copies exist only for native loader startup;
    // these launcher copies are revoked immediately after successful creation.
    drop(standard_handles);

    let guardian_identity = process_identity(process_handle.raw())?;
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: attempt_id.to_owned(),
        nonce,
        guardian_service_name: "direct-launch-negative".to_owned(),
        launcher_identity,
        guardian_identity: guardian_identity.clone(),
    };
    let mut cleanup = GuardianBootstrapCleanup::new(process_handle.raw());
    let hardened = read_guardian_bootstrap_frame(
        parent_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match hardened {
        super::guardian::GuardianBootstrapMessageV1::Hardened {
            binding: observed,
            process_policy_attested: true,
            thread_policy_attested: true,
        } if observed == binding => {}
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian bootstrap hardening attestation is invalid",
            ));
        }
    }
    authenticate_guardian_process(process_handle.raw(), &executable, &guardian_identity)?;

    let sources = [job, frontend, worker, disarm, ready];
    let expected = super::guardian::guardian_manifest_contract();
    let mut manifest = Vec::with_capacity(expected.len());
    for ((role, access), source) in expected.into_iter().zip(sources) {
        let remote = duplicate_remote_with_access(source, process_handle.raw(), access)?;
        cleanup.transferred.push(remote);
        manifest.push(super::guardian::GuardianCapabilityV1 {
            role: role.to_owned(),
            handle: remote,
            access,
        });
    }
    super::pipe::write_frame(
        parent_write.raw(),
        &super::guardian::GuardianBootstrapMessageV1::Capabilities {
            binding: binding.clone(),
            manifest,
        },
    )?;
    let ready_attestation = read_guardian_bootstrap_frame(
        parent_read.raw(),
        process_handle.raw(),
        &guardian_identity,
        &binding,
    )?;
    match ready_attestation {
        super::guardian::GuardianBootstrapMessageV1::Ready {
            binding: observed,
            roles,
            outside_target_job: true,
        } if observed == binding
            && roles
                == super::guardian::guardian_manifest_contract()
                    .map(|(role, _)| role.to_owned()) =>
        {
            cleanup.disarm();
        }
        _ => {
            return Err(GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::ProtocolViolation,
                &guardian_identity,
                Instant::now(),
                "guardian bootstrap Ready attestation is invalid",
            ));
        }
    }
    Ok((process_handle, process.dwProcessId))
}

fn read_guardian_bootstrap_frame(
    pipe: HANDLE,
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    expected_binding: &super::guardian::GuardianBootstrapBindingV1,
) -> Result<super::guardian::GuardianBootstrapMessageV1, GuardianBootstrapError> {
    let started = Instant::now();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        // SAFETY: process is the pinned guardian process. Observe it before
        // peeking the channel so an already-complete typed exit is authoritative.
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_OBJECT_0 => {
                return Err(guardian_bootstrap_exit(
                    process,
                    guardian_identity,
                    started,
                    "process-signaled-before-frame",
                ));
            }
            WAIT_TIMEOUT => {}
            WAIT_FAILED => {
                let mut error = GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::WaitFailed,
                    guardian_identity,
                    started,
                    "guardian process wait failed",
                );
                error.native_code = io::Error::last_os_error().raw_os_error();
                return Err(error);
            }
            result => {
                return Err(GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::ProtocolViolation,
                    guardian_identity,
                    started,
                    format!("unexpected guardian wait result {result}"),
                ));
            }
        }

        match super::pipe::frame_available_detailed(pipe) {
            Ok(true) => match super::pipe::read_frame_detailed(pipe) {
                Ok(super::guardian::GuardianBootstrapMessageV1::Rejected {
                    binding,
                    subphase,
                    role,
                    native_code,
                    detail_class,
                }) => {
                    if binding
                        .as_ref()
                        .is_some_and(|value| value != expected_binding)
                    {
                        return Err(GuardianBootstrapError::observed(
                            GuardianBootstrapOutcome::ProtocolViolation,
                            guardian_identity,
                            started,
                            "guardian rejection binding mismatch",
                        ));
                    }
                    let mut error = GuardianBootstrapError::observed(
                        GuardianBootstrapOutcome::ChildRejected,
                        guardian_identity,
                        started,
                        detail_class,
                    );
                    error.subphase = subphase;
                    error.role = role;
                    error.native_code = native_code;
                    return Err(error);
                }
                Ok(frame) => return Ok(frame),
                Err(error) if error.peer_closed => {
                    return Err(guardian_bootstrap_after_channel_close(
                        process,
                        guardian_identity,
                        started,
                        format!("partial-frame: {error}"),
                    ));
                }
                Err(error) => {
                    let mut failure = GuardianBootstrapError::observed(
                        GuardianBootstrapOutcome::ProtocolViolation,
                        guardian_identity,
                        started,
                        error.to_string(),
                    );
                    failure.native_code = error.native_code.map(|code| code as i32);
                    return Err(failure);
                }
            },
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(false) => {
                return Err(GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::Timeout,
                    guardian_identity,
                    started,
                    "guardian bootstrap frame timed out",
                ));
            }
            Err(super::pipe::FrameAvailabilityError::PeerClosed) => {
                return Err(guardian_bootstrap_after_channel_close(
                    process,
                    guardian_identity,
                    started,
                    "peer-closed-before-frame",
                ));
            }
            Err(super::pipe::FrameAvailabilityError::Native { code, detail }) => {
                let mut error = GuardianBootstrapError::observed(
                    GuardianBootstrapOutcome::ProtocolViolation,
                    guardian_identity,
                    started,
                    detail,
                );
                error.native_code = code;
                return Err(error);
            }
        }
    }
}

fn guardian_bootstrap_after_channel_close(
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    started: Instant,
    observation: impl Into<String>,
) -> GuardianBootstrapError {
    let observation = observation.into();
    // SAFETY: process is pinned and the grace is deliberately bounded. Pipe
    // closure can precede process signaling by a few scheduler instructions.
    match unsafe { WaitForSingleObject(process, GUARDIAN_PIPE_CLOSE_EXIT_GRACE_MILLIS) } {
        WAIT_OBJECT_0 => guardian_bootstrap_exit(
            process,
            guardian_identity,
            started,
            format!("{observation}; process-signaled-after-close"),
        ),
        WAIT_TIMEOUT => GuardianBootstrapError::observed(
            GuardianBootstrapOutcome::ChannelClosedWhileLive,
            guardian_identity,
            started,
            observation,
        ),
        WAIT_FAILED => {
            let mut error = GuardianBootstrapError::observed(
                GuardianBootstrapOutcome::WaitFailed,
                guardian_identity,
                started,
                format!("{observation}; process-wait-failed-after-close"),
            );
            error.native_code = io::Error::last_os_error().raw_os_error();
            error
        }
        result => GuardianBootstrapError::observed(
            GuardianBootstrapOutcome::ProtocolViolation,
            guardian_identity,
            started,
            format!("{observation}; unexpected-process-wait-result={result}"),
        ),
    }
}

fn guardian_bootstrap_exit(
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
    started: Instant,
    observation: impl Into<String>,
) -> GuardianBootstrapError {
    let mut error = GuardianBootstrapError::observed(
        GuardianBootstrapOutcome::ChildRejected,
        guardian_identity,
        started,
        observation,
    );
    let mut exit_code = 0_u32;
    // SAFETY: the process is signaled and exit_code is writable.
    if unsafe { GetExitCodeProcess(process, &raw mut exit_code) } == 0 {
        error.outcome = GuardianBootstrapOutcome::WaitFailed;
        error.native_code = io::Error::last_os_error().raw_os_error();
        error.detail = format!("{}; exit-code-read-failed", error.detail);
        return error;
    }
    let (subphase, role, native_code) = super::guardian::startup_detail_for_exit_code(exit_code);
    error.subphase = subphase;
    error.role = role;
    error.native_code = native_code;
    error.exit_code = Some(exit_code);
    error
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_frame_for_test(
    pipe: HANDLE,
    process: HANDLE,
    guardian_identity: &WindowsProcessIdentityV1,
) -> Result<super::guardian::GuardianBootstrapMessageV1, GuardianBootstrapError> {
    let binding = super::guardian::GuardianBootstrapBindingV1 {
        schema_version: super::guardian::GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
        attempt_id: "test-attempt".to_owned(),
        nonce: "test-nonce".to_owned(),
        guardian_service_name: "test-guardian-slot".to_owned(),
        launcher_identity: guardian_identity.clone(),
        guardian_identity: guardian_identity.clone(),
    };
    read_guardian_bootstrap_frame(pipe, process, guardian_identity, &binding)
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_pipe_pair_for_test() -> Result<(OwnedHandle, OwnedHandle), String>
{
    pipe_pair(false)
}

#[cfg(test)]
pub(crate) fn guardian_bootstrap_cleanup_for_test(process: HANDLE) {
    drop(GuardianBootstrapCleanup::new(process));
}

struct GuardianBootstrapCleanup {
    process: HANDLE,
    transferred: Vec<u64>,
    armed: bool,
}

impl GuardianBootstrapCleanup {
    const fn new(process: HANDLE) -> Self {
        Self {
            process,
            transferred: Vec::new(),
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
        self.transferred.clear();
    }
}

impl Drop for GuardianBootstrapCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for handle in self.transferred.drain(..).rev() {
            let _ = close_remote(handle, self.process);
        }
        // SAFETY: the process handle stays live for this guard's scope. A
        // failed or partial bootstrap must not leave an authority helper alive.
        unsafe { TerminateProcess(self.process, 0xED13_0000) };
    }
}

fn duplicate_remote_with_access(
    handle: HANDLE,
    process: HANDLE,
    access: u32,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: both processes and source are pinned; desired access is the
    // typed manifest contract and the duplicate is explicitly non-inheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            process,
            &raw mut remote,
            access,
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

fn authenticate_guardian_process(
    process: HANDLE,
    executable: &Path,
    expected_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if process_identity(process)? != *expected_identity {
        return Err("guardian bootstrap process identity changed".to_owned());
    }
    verify_image_path(process, executable)?;
    let child_token = super::token::process_token(process)?;
    let launcher_token = super::token::process_token(unsafe { GetCurrentProcess() })?;
    if super::token::envelope(child_token.raw())? != super::token::envelope(launcher_token.raw())? {
        return Err("guardian bootstrap token envelope differs from launcher".to_owned());
    }
    Ok(())
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
