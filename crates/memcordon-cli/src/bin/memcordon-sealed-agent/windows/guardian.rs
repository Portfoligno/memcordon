use std::ffi::OsString;
use std::fmt;
use std::io;
use std::time::{Duration, Instant};

use memcordon_core::WindowsProcessIdentityV1;
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetStdHandle,
};
use windows_sys::Win32::System::JobObjects::{
    IsProcessInJob, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
    QueryInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessId, GetThreadId, INFINITE, OpenProcess,
    PROCESS_QUERY_LIMITED_INFORMATION, ResetEvent, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject,
};

use super::pipe::OwnedHandle;

const EXIT_MAGIC: u32 = 0xED00_0000;
const EXIT_ARGUMENT_SHAPE: u32 = 1;
const EXIT_ARGUMENT_DECODE: u32 = 2;
const EXIT_ATTEMPT_BINDING: u32 = 3;
const EXIT_HANDLE_ADOPTION: u32 = 4;
const EXIT_HANDLE_VALIDATION: u32 = 5;
const EXIT_READY_SIGNAL: u32 = 6;
const EXIT_JOB_VALIDATION: u32 = 11;
const EXIT_FRONTEND_VALIDATION: u32 = 12;
const EXIT_WORKER_VALIDATION: u32 = 13;
const EXIT_DISARM_VALIDATION: u32 = 14;
const EXIT_READY_VALIDATION: u32 = 15;
const EXIT_BOOTSTRAP_CHANNEL: u32 = 16;
const EXIT_SELF_HARDEN: u32 = 17;
const EXIT_LAUNCHER_AUTH: u32 = 18;
const EXIT_MANIFEST: u32 = 19;
const EXIT_PROCESS_POLICY_APPLY: u32 = 20;
const EXIT_PROCESS_POLICY_READBACK: u32 = 21;
const EXIT_THREAD_POLICY_APPLY: u32 = 22;
const EXIT_THREAD_POLICY_READBACK: u32 = 23;
const EXIT_BOOTSTRAP_READ_VALIDATION: u32 = 24;
const EXIT_BOOTSTRAP_WRITE_VALIDATION: u32 = 25;
const EXIT_LOADER_CONTEXT: u32 = 26;
const EXIT_SERVICE_STOP_VALIDATION: u32 = 27;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) const GUARDIAN_BOOTSTRAP_SCHEMA_VERSION: u32 = 1;
pub(crate) const GUARDIAN_JOB_ACCESS: u32 = 0x0010_0000 | 0x0004 | 0x0008;
pub(crate) const GUARDIAN_FRONTEND_ACCESS: u32 = 0x0010_0000 | 0x1000;
pub(crate) const GUARDIAN_WORKER_ACCESS: u32 = 0x0010_0000 | 0x0800;
pub(crate) const GUARDIAN_DISARM_ACCESS: u32 = 0x0010_0000;
pub(crate) const GUARDIAN_READY_ACCESS: u32 = 0x0010_0000 | 0x0002;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct GuardianBootstrapBindingV1 {
    pub schema_version: u32,
    pub attempt_id: String,
    pub nonce: String,
    pub guardian_service_name: String,
    pub launcher_identity: WindowsProcessIdentityV1,
    pub guardian_identity: WindowsProcessIdentityV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct GuardianCapabilityV1 {
    pub role: String,
    pub handle: u64,
    pub access: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) enum GuardianBootstrapMessageV1 {
    Hardened {
        binding: GuardianBootstrapBindingV1,
        process_policy_attested: bool,
        thread_policy_attested: bool,
    },
    Capabilities {
        binding: GuardianBootstrapBindingV1,
        manifest: Vec<GuardianCapabilityV1>,
    },
    Ready {
        binding: GuardianBootstrapBindingV1,
        roles: Vec<String>,
        outside_target_job: bool,
    },
    Rejected {
        binding: Option<GuardianBootstrapBindingV1>,
        subphase: GuardianStartupSubphase,
        role: Option<GuardianHandleRole>,
        native_code: Option<i32>,
        detail_class: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GuardianStartupSubphase {
    ArgumentShape,
    ArgumentDecode,
    AttemptBinding,
    HandleAdoption,
    HandleValidation,
    ReadySignal,
    BootstrapChannel,
    SelfHarden,
    ProcessPolicyApply,
    ProcessPolicyReadback,
    ThreadPolicyApply,
    ThreadPolicyReadback,
    LauncherAuthentication,
    CapabilityManifest,
    LoaderContext,
    ReadyWait,
    Runtime,
}

impl GuardianStartupSubphase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ArgumentShape => "argument-shape",
            Self::ArgumentDecode => "argument-decode",
            Self::AttemptBinding => "attempt-binding",
            Self::HandleAdoption => "handle-adoption",
            Self::HandleValidation => "handle-validation",
            Self::ReadySignal => "ready-signal",
            Self::BootstrapChannel => "bootstrap-channel",
            Self::SelfHarden => "self-harden",
            Self::ProcessPolicyApply => "process-policy-apply",
            Self::ProcessPolicyReadback => "process-policy-readback",
            Self::ThreadPolicyApply => "thread-policy-apply",
            Self::ThreadPolicyReadback => "thread-policy-readback",
            Self::LauncherAuthentication => "launcher-authentication",
            Self::CapabilityManifest => "capability-manifest",
            Self::LoaderContext => "loader-context",
            Self::ReadyWait => "ready-wait",
            Self::Runtime => "runtime",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GuardianHandleRole {
    BootstrapRead,
    BootstrapWrite,
    Job,
    Frontend,
    Worker,
    Disarm,
    Ready,
    ServiceStop,
}

impl GuardianHandleRole {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BootstrapRead => "bootstrap-read",
            Self::BootstrapWrite => "bootstrap-write",
            Self::Job => "job",
            Self::Frontend => "frontend",
            Self::Worker => "worker",
            Self::Disarm => "disarm",
            Self::Ready => "ready",
            Self::ServiceStop => "service-stop",
        }
    }
}

pub(crate) fn guardian_manifest_contract() -> [(&'static str, u32); 5] {
    [
        ("job", GUARDIAN_JOB_ACCESS),
        ("frontend", GUARDIAN_FRONTEND_ACCESS),
        ("worker", GUARDIAN_WORKER_ACCESS),
        ("disarm", GUARDIAN_DISARM_ACCESS),
        ("ready", GUARDIAN_READY_ACCESS),
    ]
}

fn validate_manifest(manifest: &[GuardianCapabilityV1]) -> Result<[HANDLE; 5], GuardianFailure> {
    if manifest.len() != 5 {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::CapabilityManifest,
            None,
            "capability-count",
        ));
    }
    let mut handles = [std::ptr::null_mut(); 5];
    for (index, ((expected_role, expected_access), capability)) in guardian_manifest_contract()
        .into_iter()
        .zip(manifest)
        .enumerate()
    {
        if capability.role != expected_role {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::CapabilityManifest,
                None,
                "capability-role",
            ));
        }
        if capability.access != expected_access {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::CapabilityManifest,
                None,
                "capability-access",
            ));
        }
        let handle = capability.handle as usize as HANDLE;
        if handle.is_null() || handles[..index].contains(&handle) {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::CapabilityManifest,
                None,
                "capability-value",
            ));
        }
        handles[index] = handle;
    }
    Ok(handles)
}

#[cfg(test)]
pub(crate) fn validate_manifest_for_test(
    manifest: &[GuardianCapabilityV1],
) -> Result<[HANDLE; 5], u32> {
    validate_manifest(manifest).map_err(|error| error.exit_code())
}

fn validate_bootstrap_pipe(
    handle: HANDLE,
    role: GuardianHandleRole,
) -> Result<(), GuardianFailure> {
    validate_handle(handle, role)?;
    // SAFETY: handle is an adopted live bootstrap handle.
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::BootstrapChannel,
            Some(role),
            "bootstrap-object-type",
        ));
    }
    Ok(())
}

fn adopt_loader_standard_handles(
    handles: [HANDLE; 3],
) -> Result<[OwnedHandle; 3], GuardianFailure> {
    if handles.iter().any(|handle| handle.is_null())
        || handles[0] == handles[1]
        || handles[0] == handles[2]
        || handles[1] == handles[2]
    {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LoaderContext,
            None,
            "standard-handle-shape",
        ));
    }
    Ok([
        OwnedHandle::new(handles[0]).map_err(|_| {
            GuardianFailure::native(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-input-adoption",
            )
        })?,
        OwnedHandle::new(handles[1]).map_err(|_| {
            GuardianFailure::native(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-output-adoption",
            )
        })?,
        OwnedHandle::new(handles[2]).map_err(|_| {
            GuardianFailure::native(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-error-adoption",
            )
        })?,
    ])
}

fn retire_loader_standard_handles(
    handles: &mut Option<[OwnedHandle; 3]>,
) -> Result<(), GuardianFailure> {
    let owned = handles
        .as_ref()
        .expect("loader stdio retained until retirement");
    let expected = [owned[0].raw(), owned[1].raw(), owned[2].raw()];
    let observed = unsafe {
        [
            GetStdHandle(STD_INPUT_HANDLE),
            GetStdHandle(STD_OUTPUT_HANDLE),
            GetStdHandle(STD_ERROR_HANDLE),
        ]
    };
    if observed != expected {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LoaderContext,
            None,
            "standard-handle-readback",
        ));
    }
    for handle in expected {
        let mut flags = 0_u32;
        // SAFETY: handle is one of the three adopted loader NUL handles.
        if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-handle-inheritance",
            ));
        }
        if flags & HANDLE_FLAG_INHERIT == 0 {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-handle-not-inheritable",
            ));
        }
        // SAFETY: every expected handle is a live inherited NUL device.
        if unsafe { GetFileType(handle) } != FILE_TYPE_CHAR {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-handle-object-type",
            ));
        }
    }
    // Remove the process-parameter references before closing the child's last
    // copies. The handles existed solely to make native loader initialization
    // explicit and carry no guardian runtime or workload authority.
    for kind in [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
        // SAFETY: each kind is one documented standard-stream slot and null
        // explicitly revokes that slot before the owned NUL handles are dropped.
        if unsafe { SetStdHandle(kind, std::ptr::null_mut()) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::LoaderContext,
                None,
                "standard-handle-revocation",
            ));
        }
    }
    drop(handles.take());
    Ok(())
}

fn authenticate_launcher(
    expected_identity: &WindowsProcessIdentityV1,
) -> Result<(), GuardianFailure> {
    // SAFETY: only query rights are requested for the command-bound launcher PID.
    let process = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            expected_identity.process_id,
        )
    };
    let process = OwnedHandle::new(process).map_err(|_| {
        GuardianFailure::native(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-process-open",
        )
    })?;
    let identity = super::process::process_identity(process.raw()).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-process-identity",
        )
    })?;
    if identity != *expected_identity {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-process-reused",
        ));
    }
    let executable = std::env::current_exe().map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "guardian-image-path",
        )
    })?;
    super::process::verify_image_path(process.raw(), &executable).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-image-path",
        )
    })?;
    let token = super::token::process_token(process.raw()).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-token-open",
        )
    })?;
    if super::token::token_user_sid(token.raw()).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-token-user",
        )
    })? != "S-1-5-18"
    {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-account",
        ));
    }
    let launcher_sid = super::security::service_sid(memcordon_core::WINDOWS_LAUNCHER_SERVICE_NAME)
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::LauncherAuthentication,
                None,
                "launcher-service-sid",
            )
        })?;
    if !super::token::token_has_enabled_group(token.raw(), &launcher_sid).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-ordinary-sid-query",
        )
    })? || !super::token::token_has_restricting_sid(token.raw(), &launcher_sid).map_err(
        |_| {
            GuardianFailure::new(
                GuardianStartupSubphase::LauncherAuthentication,
                None,
                "launcher-restricting-sid-query",
            )
        },
    )? {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LauncherAuthentication,
            None,
            "launcher-service-sid-mismatch",
        ));
    }
    Ok(())
}

#[derive(Debug)]
pub struct GuardianFailure {
    subphase: GuardianStartupSubphase,
    role: Option<GuardianHandleRole>,
    native_code: Option<i32>,
    detail_class: &'static str,
}

impl GuardianFailure {
    const fn new(
        subphase: GuardianStartupSubphase,
        role: Option<GuardianHandleRole>,
        detail_class: &'static str,
    ) -> Self {
        Self {
            subphase,
            role,
            native_code: None,
            detail_class,
        }
    }

    fn native(
        subphase: GuardianStartupSubphase,
        role: Option<GuardianHandleRole>,
        detail_class: &'static str,
    ) -> Self {
        Self {
            subphase,
            role,
            native_code: io::Error::last_os_error().raw_os_error(),
            detail_class,
        }
    }

    fn hardening(error: super::security::GuardianHardeningError) -> Self {
        use super::security::GuardianHardeningStage;
        let subphase = match error.stage {
            GuardianHardeningStage::ProcessApply => GuardianStartupSubphase::ProcessPolicyApply,
            GuardianHardeningStage::ProcessReadback => {
                GuardianStartupSubphase::ProcessPolicyReadback
            }
            GuardianHardeningStage::ThreadApply => GuardianStartupSubphase::ThreadPolicyApply,
            GuardianHardeningStage::ThreadReadback => GuardianStartupSubphase::ThreadPolicyReadback,
        };
        Self {
            subphase,
            role: None,
            native_code: error.native_code,
            detail_class: "policy-attestation",
        }
    }

    fn loader(error: super::process::GuardianLoaderPreparationError) -> Self {
        Self {
            subphase: GuardianStartupSubphase::LoaderContext,
            role: None,
            native_code: error.native_code,
            detail_class: error.subphase.name(),
        }
    }

    fn rejection_message(
        &self,
        binding: Option<GuardianBootstrapBindingV1>,
    ) -> GuardianBootstrapMessageV1 {
        GuardianBootstrapMessageV1::Rejected {
            binding,
            subphase: self.subphase,
            role: self.role,
            native_code: self.native_code,
            detail_class: self.detail_class.to_owned(),
        }
    }

    pub const fn exit_code(&self) -> u32 {
        let class = match self.subphase {
            GuardianStartupSubphase::ArgumentShape => EXIT_ARGUMENT_SHAPE,
            GuardianStartupSubphase::ArgumentDecode => EXIT_ARGUMENT_DECODE,
            GuardianStartupSubphase::AttemptBinding => EXIT_ATTEMPT_BINDING,
            GuardianStartupSubphase::HandleAdoption => EXIT_HANDLE_ADOPTION,
            GuardianStartupSubphase::HandleValidation => match self.role {
                Some(GuardianHandleRole::BootstrapRead) => EXIT_BOOTSTRAP_READ_VALIDATION,
                Some(GuardianHandleRole::BootstrapWrite) => EXIT_BOOTSTRAP_WRITE_VALIDATION,
                Some(GuardianHandleRole::Job) => EXIT_JOB_VALIDATION,
                Some(GuardianHandleRole::Frontend) => EXIT_FRONTEND_VALIDATION,
                Some(GuardianHandleRole::Worker) => EXIT_WORKER_VALIDATION,
                Some(GuardianHandleRole::Disarm) => EXIT_DISARM_VALIDATION,
                Some(GuardianHandleRole::Ready) => EXIT_READY_VALIDATION,
                Some(GuardianHandleRole::ServiceStop) => EXIT_SERVICE_STOP_VALIDATION,
                None => EXIT_HANDLE_VALIDATION,
            },
            GuardianStartupSubphase::ReadySignal => EXIT_READY_SIGNAL,
            GuardianStartupSubphase::BootstrapChannel => EXIT_BOOTSTRAP_CHANNEL,
            GuardianStartupSubphase::SelfHarden => EXIT_SELF_HARDEN,
            GuardianStartupSubphase::ProcessPolicyApply => EXIT_PROCESS_POLICY_APPLY,
            GuardianStartupSubphase::ProcessPolicyReadback => EXIT_PROCESS_POLICY_READBACK,
            GuardianStartupSubphase::ThreadPolicyApply => EXIT_THREAD_POLICY_APPLY,
            GuardianStartupSubphase::ThreadPolicyReadback => EXIT_THREAD_POLICY_READBACK,
            GuardianStartupSubphase::LauncherAuthentication => EXIT_LAUNCHER_AUTH,
            GuardianStartupSubphase::CapabilityManifest => EXIT_MANIFEST,
            GuardianStartupSubphase::LoaderContext => EXIT_LOADER_CONTEXT,
            GuardianStartupSubphase::ReadyWait => return 125,
            GuardianStartupSubphase::Runtime => return 125,
        };
        EXIT_MAGIC
            | (class << 16)
            | match self.native_code {
                Some(code) if code > 0 && code <= u16::MAX as i32 => code as u32,
                Some(_) | None => 0,
            }
    }
}

impl fmt::Display for GuardianFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-GUARDIAN-STARTUP: subphase={} outcome=child-rejection detail_class={}",
            self.subphase.name(),
            self.detail_class
        )?;
        if let Some(role) = self.role {
            write!(formatter, " role={}", role.name())?;
        }
        if let Some(native_code) = self.native_code {
            write!(formatter, " native_code={native_code}")?;
        }
        Ok(())
    }
}

pub fn startup_detail_for_exit_code(
    exit_code: u32,
) -> (
    GuardianStartupSubphase,
    Option<GuardianHandleRole>,
    Option<i32>,
) {
    if exit_code & 0xff00_0000 != EXIT_MAGIC {
        return (GuardianStartupSubphase::Runtime, None, None);
    }
    let native_code = match exit_code & 0xffff {
        0 => None,
        code => Some(code as i32),
    };
    let (subphase, role) = match (exit_code >> 16) & 0xff {
        EXIT_ARGUMENT_SHAPE => (GuardianStartupSubphase::ArgumentShape, None),
        EXIT_ARGUMENT_DECODE => (GuardianStartupSubphase::ArgumentDecode, None),
        EXIT_ATTEMPT_BINDING => (GuardianStartupSubphase::AttemptBinding, None),
        EXIT_HANDLE_ADOPTION => (GuardianStartupSubphase::HandleAdoption, None),
        EXIT_HANDLE_VALIDATION => (GuardianStartupSubphase::HandleValidation, None),
        EXIT_JOB_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Job),
        ),
        EXIT_FRONTEND_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Frontend),
        ),
        EXIT_WORKER_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Worker),
        ),
        EXIT_DISARM_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Disarm),
        ),
        EXIT_READY_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Ready),
        ),
        EXIT_READY_SIGNAL => (
            GuardianStartupSubphase::ReadySignal,
            Some(GuardianHandleRole::Ready),
        ),
        EXIT_BOOTSTRAP_CHANNEL => (GuardianStartupSubphase::BootstrapChannel, None),
        EXIT_SELF_HARDEN => (GuardianStartupSubphase::SelfHarden, None),
        EXIT_PROCESS_POLICY_APPLY => (GuardianStartupSubphase::ProcessPolicyApply, None),
        EXIT_PROCESS_POLICY_READBACK => (GuardianStartupSubphase::ProcessPolicyReadback, None),
        EXIT_THREAD_POLICY_APPLY => (GuardianStartupSubphase::ThreadPolicyApply, None),
        EXIT_THREAD_POLICY_READBACK => (GuardianStartupSubphase::ThreadPolicyReadback, None),
        EXIT_BOOTSTRAP_READ_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::BootstrapRead),
        ),
        EXIT_BOOTSTRAP_WRITE_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::BootstrapWrite),
        ),
        EXIT_SERVICE_STOP_VALIDATION => (
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::ServiceStop),
        ),
        EXIT_LAUNCHER_AUTH => (GuardianStartupSubphase::LauncherAuthentication, None),
        EXIT_MANIFEST => (GuardianStartupSubphase::CapabilityManifest, None),
        EXIT_LOADER_CONTEXT => (GuardianStartupSubphase::LoaderContext, None),
        _ => (GuardianStartupSubphase::Runtime, None),
    };
    (subphase, role, native_code)
}

#[cfg(test)]
pub(crate) fn startup_exit_code_for_test(
    subphase: GuardianStartupSubphase,
    role: Option<GuardianHandleRole>,
    native_code: Option<i32>,
) -> u32 {
    GuardianFailure {
        subphase,
        role,
        native_code,
        detail_class: "test",
    }
    .exit_code()
}

pub fn run(arguments: &[OsString]) -> Result<(), GuardianFailure> {
    // Only the two non-privileged bootstrap endpoints and the three inert NUL
    // loader handles are decoded before self-hardening. The latter are revoked
    // before Hardened can authorize any privileged capability transfer.
    let [
        bootstrap_read,
        bootstrap_write,
        standard_input,
        standard_output,
        standard_error,
        guardian_service_name,
        launcher_desktop,
        attempt_id,
        nonce,
        cleanup_deadline,
        readiness_delay,
        launcher_pid,
        launcher_creation_time,
        service_stop,
    ] = arguments
    else {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::ArgumentShape,
            None,
            "argument-count",
        ));
    };
    let bootstrap_handles = [bootstrap_read, bootstrap_write]
        .iter()
        .map(|argument| {
            argument
                .to_string_lossy()
                .parse::<u64>()
                .map(|value| value as usize as HANDLE)
                .map_err(|_| {
                    GuardianFailure::new(
                        GuardianStartupSubphase::ArgumentDecode,
                        None,
                        "handle-integer",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let [bootstrap_read, bootstrap_write] = bootstrap_handles.as_slice() else {
        unreachable!("fixed bootstrap handle array")
    };
    let loader_standard_handles = [standard_input, standard_output, standard_error]
        .map(|argument| {
            argument
                .to_string_lossy()
                .parse::<u64>()
                .map(|value| value as usize as HANDLE)
                .map_err(|_| {
                    GuardianFailure::new(
                        GuardianStartupSubphase::LoaderContext,
                        None,
                        "standard-handle-integer",
                    )
                })
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let [standard_input, standard_output, standard_error] = loader_standard_handles.as_slice()
    else {
        unreachable!("fixed loader standard-handle array")
    };
    let launcher_desktop = launcher_desktop.to_string_lossy();
    if launcher_desktop.is_empty() {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::LoaderContext,
            None,
            "desktop-argument",
        ));
    }
    let guardian_service_name = guardian_service_name.to_string_lossy();
    if guardian_service_name.is_empty() {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::AttemptBinding,
            None,
            "guardian-service-name",
        ));
    }
    let attempt_id = attempt_id.to_string_lossy();
    super::record::validate_attempt_id(&attempt_id).map_err(|_| {
        GuardianFailure::new(GuardianStartupSubphase::AttemptBinding, None, "attempt-id")
    })?;
    let nonce = nonce.to_string_lossy();
    super::record::validate_attempt_id(&nonce).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::AttemptBinding,
            None,
            "bootstrap-nonce",
        )
    })?;
    let cleanup_deadline = cleanup_deadline
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::ArgumentDecode,
                None,
                "cleanup-deadline",
            )
        })?;
    let readiness_delay = readiness_delay
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::ArgumentDecode,
                None,
                "readiness-delay",
            )
        })?;
    let launcher_pid = launcher_pid.to_string_lossy().parse::<u32>().map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::ArgumentDecode,
            None,
            "launcher-pid",
        )
    })?;
    let launcher_creation_time = launcher_creation_time
        .to_string_lossy()
        .parse::<u64>()
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::ArgumentDecode,
                None,
                "launcher-creation-time",
            )
        })?;
    let service_stop = service_stop.to_string_lossy().parse::<u64>().map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::ArgumentDecode,
            Some(GuardianHandleRole::ServiceStop),
            "service-stop-handle",
        )
    })? as usize as HANDLE;
    if bootstrap_read.is_null() || bootstrap_write.is_null() || bootstrap_read == bootstrap_write {
        return Err(GuardianFailure::new(
            GuardianStartupSubphase::BootstrapChannel,
            None,
            "invalid-bootstrap-handles",
        ));
    }
    let mut bootstrap_write = Some(adopt(*bootstrap_write, GuardianHandleRole::BootstrapWrite)?);
    let mut bootstrap_read = match adopt(*bootstrap_read, GuardianHandleRole::BootstrapRead) {
        Ok(handle) => Some(handle),
        Err(error) => {
            let _ = super::pipe::write_frame(
                bootstrap_write
                    .as_ref()
                    .expect("adopted bootstrap writer")
                    .raw(),
                &error.rejection_message(None),
            );
            return Err(error);
        }
    };
    let mut loader_standard_handles = Some(adopt_loader_standard_handles([
        *standard_input,
        *standard_output,
        *standard_error,
    ])?);
    let mut rejection_binding = None;
    let result = (|| {
        validate_bootstrap_pipe(
            bootstrap_write
                .as_ref()
                .expect("open bootstrap writer")
                .raw(),
            GuardianHandleRole::BootstrapWrite,
        )?;
        validate_bootstrap_pipe(
            bootstrap_read
                .as_ref()
                .expect("open bootstrap reader")
                .raw(),
            GuardianHandleRole::BootstrapRead,
        )?;

        super::process::attest_current_guardian_desktop(&launcher_desktop)
            .map_err(GuardianFailure::loader)?;
        retire_loader_standard_handles(&mut loader_standard_handles)?;

        // Native loader startup completed before this call. Converge and
        // attest both policies before authentication or capability transfer.
        super::security::protect_current_guardian().map_err(GuardianFailure::hardening)?;

        let launcher_identity = WindowsProcessIdentityV1 {
            process_id: launcher_pid,
            creation_time_100ns: launcher_creation_time,
        };
        authenticate_launcher(&launcher_identity)?;
        let guardian_identity = super::process::process_identity(unsafe { GetCurrentProcess() })
            .map_err(|_| {
                GuardianFailure::new(
                    GuardianStartupSubphase::LauncherAuthentication,
                    None,
                    "guardian-identity",
                )
            })?;
        let binding = GuardianBootstrapBindingV1 {
            schema_version: GUARDIAN_BOOTSTRAP_SCHEMA_VERSION,
            attempt_id: attempt_id.to_string(),
            nonce: nonce.to_string(),
            guardian_service_name: guardian_service_name.to_string(),
            launcher_identity,
            guardian_identity,
        };
        rejection_binding = Some(binding.clone());
        super::pipe::write_frame(
            bootstrap_write
                .as_ref()
                .expect("open bootstrap writer")
                .raw(),
            &GuardianBootstrapMessageV1::Hardened {
                binding: binding.clone(),
                process_policy_attested: true,
                thread_policy_attested: true,
            },
        )
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::BootstrapChannel,
                None,
                "hardened-attestation-write",
            )
        })?;
        let transfer = read_bootstrap_frame(
            bootstrap_read
                .as_ref()
                .expect("open bootstrap reader")
                .raw(),
        )?;
        let GuardianBootstrapMessageV1::Capabilities {
            binding: received_binding,
            manifest,
        } = transfer
        else {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::CapabilityManifest,
                None,
                "invalid-bootstrap-message",
            ));
        };
        if received_binding != binding {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::CapabilityManifest,
                None,
                "binding-mismatch",
            ));
        }
        let values = validate_manifest(&manifest)?;
        let [job, frontend, worker, disarm, ready] = values;
        let manifest = [
            (GuardianHandleRole::Job, job),
            (GuardianHandleRole::Frontend, frontend),
            (GuardianHandleRole::Worker, worker),
            (GuardianHandleRole::Disarm, disarm),
            (GuardianHandleRole::Ready, ready),
        ];
        if let Some((role, _)) = manifest.iter().find(|(_, handle)| handle.is_null()) {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::HandleAdoption,
                Some(*role),
                "null-handle",
            ));
        }
        for (index, (role, handle)) in manifest.iter().enumerate() {
            if manifest[..index].iter().any(|(_, prior)| prior == handle) {
                return Err(GuardianFailure::new(
                    GuardianStartupSubphase::HandleValidation,
                    Some(*role),
                    "duplicate-role-handle",
                ));
            }
        }
        let job = adopt(job, GuardianHandleRole::Job)?;
        let frontend = adopt(frontend, GuardianHandleRole::Frontend)?;
        let worker = adopt(worker, GuardianHandleRole::Worker)?;
        let disarm = adopt(disarm, GuardianHandleRole::Disarm)?;
        let ready = adopt(ready, GuardianHandleRole::Ready)?;
        let service_stop = if service_stop.is_null() {
            None
        } else {
            Some(adopt(service_stop, GuardianHandleRole::ServiceStop)?)
        };

        validate_handle(job.raw(), GuardianHandleRole::Job)?;
        validate_handle(frontend.raw(), GuardianHandleRole::Frontend)?;
        validate_handle(worker.raw(), GuardianHandleRole::Worker)?;
        validate_handle(disarm.raw(), GuardianHandleRole::Disarm)?;
        validate_handle(ready.raw(), GuardianHandleRole::Ready)?;
        validate_job(job.raw())?;
        validate_process(frontend.raw())?;
        validate_thread(worker.raw())?;
        validate_waitable(disarm.raw(), GuardianHandleRole::Disarm, false)?;
        if let Some(service_stop) = service_stop.as_ref() {
            validate_waitable(service_stop.raw(), GuardianHandleRole::ServiceStop, false)?;
        }
        // ResetEvent exercises EVENT_MODIFY_STATE without publishing readiness.
        // SAFETY: ready is the private inherited manual-reset event for this attempt.
        if unsafe { ResetEvent(ready.raw()) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::HandleValidation,
                Some(GuardianHandleRole::Ready),
                "event-modify-access",
            ));
        }
        let mut inside_job = 0;
        // SAFETY: current process pseudo-handle and the validated Job handle are live.
        if unsafe { IsProcessInJob(GetCurrentProcess(), job.raw(), &raw mut inside_job) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::HandleValidation,
                Some(GuardianHandleRole::Job),
                "outside-job-query",
            ));
        }
        if inside_job != 0 {
            return Err(GuardianFailure::new(
                GuardianStartupSubphase::HandleValidation,
                Some(GuardianHandleRole::Job),
                "guardian-inside-target-job",
            ));
        }
        super::pipe::write_frame(
            bootstrap_write
                .as_ref()
                .expect("open bootstrap writer")
                .raw(),
            &GuardianBootstrapMessageV1::Ready {
                binding,
                roles: guardian_manifest_contract()
                    .map(|(role, _)| role.to_owned())
                    .to_vec(),
                outside_target_job: true,
            },
        )
        .map_err(|_| {
            GuardianFailure::new(
                GuardianStartupSubphase::BootstrapChannel,
                None,
                "ready-attestation-write",
            )
        })?;
        drop(bootstrap_read.take());
        drop(bootstrap_write.take());
        if readiness_delay != 0 {
            std::thread::sleep(Duration::from_millis(readiness_delay));
        }
        // SAFETY: ready is a validated private inherited event dedicated to this guardian.
        if unsafe { SetEvent(ready.raw()) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::ReadySignal,
                Some(GuardianHandleRole::Ready),
                "ready-set-event",
            ));
        }
        let mut watched = vec![frontend.raw(), worker.raw(), disarm.raw()];
        if let Some(service_stop) = service_stop.as_ref() {
            watched.push(service_stop.raw());
        }
        // SAFETY: all three handles are live and the array remains valid throughout
        // the non-alertable wait.
        let result =
            unsafe { WaitForMultipleObjects(watched.len() as u32, watched.as_ptr(), 0, INFINITE) };
        if result == WAIT_OBJECT_0 + 2 {
            return Ok(());
        }
        if result != WAIT_OBJECT_0
            && result != WAIT_OBJECT_0 + 1
            && !(watched.len() == 4 && result == WAIT_OBJECT_0 + 3)
        {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::Runtime,
                None,
                "authority-wait",
            ));
        }
        // SAFETY: frontend or launcher died before disarm, and guardian owns a live
        // Job handle specifically for terminal cleanup authority.
        if unsafe { TerminateJobObject(job.raw(), 0xC000_013A) } == 0 {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::Runtime,
                Some(GuardianHandleRole::Job),
                "job-terminate",
            ));
        }
        wait_job_empty(
            job.raw(),
            Instant::now() + Duration::from_millis(cleanup_deadline),
        )?;
        super::record::write_guardian_receipt(&attempt_id).map_err(|_| {
            GuardianFailure::new(GuardianStartupSubphase::Runtime, None, "terminal-receipt")
        })
    })();
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            if let Some(writer) = bootstrap_write.as_ref() {
                let _ = super::pipe::write_frame(
                    writer.raw(),
                    &error.rejection_message(rejection_binding),
                );
            }
            Err(error)
        }
    }
}

fn read_bootstrap_frame(pipe: HANDLE) -> Result<GuardianBootstrapMessageV1, GuardianFailure> {
    let deadline = Instant::now() + BOOTSTRAP_TIMEOUT;
    loop {
        match super::pipe::frame_available(pipe) {
            Ok(true) => {
                return super::pipe::read_frame(pipe).map_err(|_| {
                    GuardianFailure::new(
                        GuardianStartupSubphase::BootstrapChannel,
                        None,
                        "bootstrap-frame-read",
                    )
                });
            }
            Ok(false) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(false) => {
                return Err(GuardianFailure::new(
                    GuardianStartupSubphase::BootstrapChannel,
                    None,
                    "bootstrap-frame-timeout",
                ));
            }
            Err(_) => {
                return Err(GuardianFailure::new(
                    GuardianStartupSubphase::BootstrapChannel,
                    None,
                    "bootstrap-peer-disconnected",
                ));
            }
        }
    }
}

fn adopt(handle: HANDLE, role: GuardianHandleRole) -> Result<OwnedHandle, GuardianFailure> {
    OwnedHandle::new(handle).map_err(|_| {
        GuardianFailure::new(
            GuardianStartupSubphase::HandleAdoption,
            Some(role),
            "owned-handle",
        )
    })
}

fn validate_handle(handle: HANDLE, role: GuardianHandleRole) -> Result<(), GuardianFailure> {
    let mut flags = 0;
    // SAFETY: handle was adopted from the exact inherited manifest; this call
    // validates that it names a live kernel handle in the guardian namespace.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        return Err(GuardianFailure::native(
            GuardianStartupSubphase::HandleValidation,
            Some(role),
            "handle-information",
        ));
    }
    Ok(())
}

fn validate_job(job: HANDLE) -> Result<(), GuardianFailure> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: output matches the requested class and the handle was validated.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(GuardianFailure::native(
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Job),
            "job-query-access",
        ));
    }
    Ok(())
}

fn validate_process(process: HANDLE) -> Result<(), GuardianFailure> {
    // SAFETY: a real frontend process handle has a nonzero process id.
    if unsafe { GetProcessId(process) } == 0 {
        return Err(GuardianFailure::native(
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Frontend),
            "process-query-access",
        ));
    }
    validate_waitable(process, GuardianHandleRole::Frontend, false)
}

fn validate_thread(thread: HANDLE) -> Result<(), GuardianFailure> {
    // SAFETY: only a real thread handle has a nonzero thread id. This both
    // validates the manifest's object type and exercises query access.
    if unsafe { GetThreadId(thread) } == 0 {
        return Err(GuardianFailure::native(
            GuardianStartupSubphase::HandleValidation,
            Some(GuardianHandleRole::Worker),
            "thread-query-access",
        ));
    }
    validate_waitable(thread, GuardianHandleRole::Worker, false)
}

fn validate_waitable(
    handle: HANDLE,
    role: GuardianHandleRole,
    allow_signaled: bool,
) -> Result<(), GuardianFailure> {
    // SAFETY: the handle remains owned throughout this zero-time probe.
    let result = unsafe { WaitForSingleObject(handle, 0) };
    match result {
        WAIT_TIMEOUT => Ok(()),
        WAIT_OBJECT_0 if allow_signaled => Ok(()),
        WAIT_OBJECT_0 => Err(GuardianFailure::new(
            GuardianStartupSubphase::HandleValidation,
            Some(role),
            "authority-already-lost",
        )),
        WAIT_FAILED => Err(GuardianFailure::native(
            GuardianStartupSubphase::HandleValidation,
            Some(role),
            "synchronization-access",
        )),
        _ => Err(GuardianFailure::new(
            GuardianStartupSubphase::HandleValidation,
            Some(role),
            "impossible-wait-result",
        )),
    }
}

fn wait_job_empty(job: HANDLE, deadline: Instant) -> Result<(), GuardianFailure> {
    while Instant::now() < deadline {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: job is a live inherited Job handle and the output structure
        // matches the requested information class.
        if unsafe {
            QueryInformationJobObject(
                job,
                JobObjectBasicAccountingInformation,
                (&raw mut accounting).cast(),
                std::mem::size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                std::ptr::null_mut(),
            )
        } == 0
        {
            return Err(GuardianFailure::native(
                GuardianStartupSubphase::Runtime,
                Some(GuardianHandleRole::Job),
                "job-accounting",
            ));
        }
        if accounting.ActiveProcesses == 0 {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(GuardianFailure::new(
        GuardianStartupSubphase::Runtime,
        Some(GuardianHandleRole::Job),
        "job-empty-timeout",
    ))
}
