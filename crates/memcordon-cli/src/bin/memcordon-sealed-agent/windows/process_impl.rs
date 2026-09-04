use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashSet};
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
use memcordon_windows_launch_core::{
    CleanupOutcomeV1, DesktopBindingV1, ExactHandleListV1, LoaderReadyChannel,
    LoaderReadyEndpointV1, LoaderReadyEvidenceV1, NativeSecurityDescriptorV1, NativeStatusV1,
    PreparedCurrentDirectoryV1, PreparedLoaderCommandV1, PreparedLoaderEnvironmentV1,
    ProcessCreateFailure, ProductionLoaderPlanInputV1,
    ProductionLoaderPlanV1 as ProductionLoaderPlan, ProductionNativeCreateRequestV1,
    ProductionQualificationDriver, SuspendedProcessAttestor, SuspendedProcessEvidenceV1,
    SuspendedProcessFactory, TargetTokenIdentityV1,
    WindowsLoaderQualificationOutcomeV2 as LaunchQualificationOutcomeV2,
    WindowsLoaderQualificationStageV2 as LaunchQualificationStageV2, build_package_loader_plan,
    create_process_as_user_native, create_process_native, create_suspended_in_job,
};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS, DuplicateHandle,
    ERROR_INVALID_HANDLE, FILETIME, GENERIC_READ, GENERIC_WRITE, GetHandleInformation, HANDLE,
    HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile,
};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, FreeSid, RevertToSelf, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
    SecurityImpersonation, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    TOKEN_QUERY_SOURCE, TokenImpersonation,
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
use windows_sys::Win32::System::Services::{
    SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STOP,
    SERVICE_STOPPED,
};
use windows_sys::Win32::System::StationsAndDesktops::{
    UOI_FLAGS, UOI_IO, UOI_NAME, USEROBJECTFLAGS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_PROCESS_GROUP, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateEventW,
    DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess,
    GetCurrentThread, GetCurrentThreadId, GetExitCodeProcess, GetProcessId, GetProcessIdOfThread,
    GetProcessTimes, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    OpenProcessToken, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST,
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
use super::{
    guardian, guardian_service, job, loader_access, package, pipe, record, security,
    service_manager, session_broker, token, user_api,
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
const TARGET_DESKTOP_BOOTSTRAP_SCHEMA_VERSION: u32 =
    memcordon_windows_launch_core::PRODUCTION_LOADER_READY_SCHEMA_VERSION;
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

mod desktop_loader;
mod guardian_process;
mod handles;
mod target;

pub(crate) use desktop_loader::*;
pub(crate) use guardian_process::*;
pub(crate) use handles::*;
pub(crate) use target::*;
