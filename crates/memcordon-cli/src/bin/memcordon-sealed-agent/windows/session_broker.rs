use std::io;
use std::ptr;
use std::sync::{LazyLock, Mutex, TryLockError};
use std::time::{Duration, Instant};

use memcordon_core::{
    WINDOWS_LAUNCHER_SERVICE_NAME, WINDOWS_SESSION_BROKER_PIPE,
    WINDOWS_SESSION_BROKER_SERVICE_NAME, WindowsProcessIdentityV1,
};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeServerProcessId,
    GetNamedPipeServerSessionId,
};
use windows_sys::Win32::System::Services::{SERVICE_QUERY_STATUS, SERVICE_START, SERVICE_STOPPED};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessIdOfThread, OpenProcess, OpenThread, PROCESS_DUP_HANDLE,
    PROCESS_QUERY_LIMITED_INFORMATION, THREAD_QUERY_INFORMATION, THREAD_QUERY_LIMITED_INFORMATION,
    THREAD_RESUME, THREAD_SET_THREAD_TOKEN,
};

use super::pipe::OwnedHandle;

pub(crate) const SESSION_BROKER_SCHEMA_VERSION: u32 = 7;
const BROKER_ROLE: u8 = 3;
const BROKER_TRANSACTION_DEADLINE: Duration = Duration::from_secs(30);
const SYNCHRONIZE_ACCESS: u32 = 0x0010_0000;
const LAUNCHER_PROCESS_BROKER_ACCESS: u32 =
    SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_DUP_HANDLE;
pub(crate) const HOLDER_PROCESS_TRANSFER_ACCESS: u32 = 0x0010_1040;
pub(crate) const HOLDER_THREAD_LAUNCHER_ACCESS: u32 =
    THREAD_QUERY_LIMITED_INFORMATION | THREAD_RESUME;
pub(crate) const HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS: u32 =
    THREAD_QUERY_INFORMATION | THREAD_SET_THREAD_TOKEN;
pub(crate) const HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS: u32 =
    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS | THREAD_QUERY_LIMITED_INFORMATION;
pub(crate) const HOLDER_JOB_BROKER_ACCESS: u32 = 0x0000_0005;
pub(crate) const BROKER_PROCESS_LAUNCHER_ACCESS: u32 = 0x0010_1000;
const BROKER_FAILURE_TRANSACTION: u32 = 0x4d43_0701;
pub(crate) const BROKER_FAILURE_ARGUMENTS: u32 = 0x4d43_0711;
const BROKER_FAILURE_PROCESS_PROTECTION: u32 = 0x4d43_0712;
const BROKER_FAILURE_CERTIFICATION: u32 = 0x4d43_0713;
const BROKER_FAILURE_LISTENER_PREPARATION: u32 = 0x4d43_0714;
const BROKER_FAILURE_RUNNING_PUBLICATION: u32 = 0x4d43_0715;
const BROKER_FAILURE_NONCE_VALIDATION: u32 = 0x4d43_0716;
pub(crate) const BROKER_FAILURE_PROCESS_DESCRIPTOR: u32 = 0x4d43_0717;
pub(crate) const BROKER_FAILURE_PROCESS_APPLY: u32 = 0x4d43_0718;
pub(crate) const BROKER_FAILURE_PROCESS_READBACK: u32 = 0x4d43_0719;
pub(crate) const BROKER_FAILURE_TOKEN_OPEN: u32 = 0x4d43_071a;
pub(crate) const BROKER_FAILURE_TOKEN_DESCRIPTOR: u32 = 0x4d43_071b;
pub(crate) const BROKER_FAILURE_TOKEN_DACL_APPLY: u32 = 0x4d43_071c;
pub(crate) const BROKER_FAILURE_TOKEN_READBACK: u32 = 0x4d43_071d;
pub(crate) const BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION: u32 = 0x4d43_071e;
static BROKER_TRANSACTION_LEASE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SessionBrokerStartupStage {
    Arguments,
    SourcePrivilegeNormalization,
    ProcessProtection(super::security::SessionBrokerProtectionStage),
    Certification,
    ListenerPreparation,
    RunningPublication,
    NonceValidation,
    Transaction,
}

impl SessionBrokerStartupStage {
    const fn service_exit(self) -> u32 {
        match self {
            Self::Arguments => BROKER_FAILURE_ARGUMENTS,
            Self::SourcePrivilegeNormalization => BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION,
            Self::ProcessProtection(stage) => match stage {
                super::security::SessionBrokerProtectionStage::ProcessDescriptor => {
                    BROKER_FAILURE_PROCESS_DESCRIPTOR
                }
                super::security::SessionBrokerProtectionStage::ProcessApply => {
                    BROKER_FAILURE_PROCESS_APPLY
                }
                super::security::SessionBrokerProtectionStage::ProcessReadback => {
                    BROKER_FAILURE_PROCESS_READBACK
                }
                super::security::SessionBrokerProtectionStage::TokenOpen => {
                    BROKER_FAILURE_TOKEN_OPEN
                }
                super::security::SessionBrokerProtectionStage::TokenDescriptor => {
                    BROKER_FAILURE_TOKEN_DESCRIPTOR
                }
                super::security::SessionBrokerProtectionStage::TokenDaclApply => {
                    BROKER_FAILURE_TOKEN_DACL_APPLY
                }
                super::security::SessionBrokerProtectionStage::TokenReadback => {
                    BROKER_FAILURE_TOKEN_READBACK
                }
            },
            Self::Certification => BROKER_FAILURE_CERTIFICATION,
            Self::ListenerPreparation => BROKER_FAILURE_LISTENER_PREPARATION,
            Self::RunningPublication => BROKER_FAILURE_RUNNING_PUBLICATION,
            Self::NonceValidation => BROKER_FAILURE_NONCE_VALIDATION,
            Self::Transaction => BROKER_FAILURE_TRANSACTION,
        }
    }
}

struct SessionBrokerServiceError {
    stage: SessionBrokerStartupStage,
    detail: String,
}

struct LauncherHandleTransferRollback {
    launcher: windows_sys::Win32::Foundation::HANDLE,
    remote_process: Option<u64>,
    remote_close_armed: bool,
}

impl LauncherHandleTransferRollback {
    fn new(launcher: windows_sys::Win32::Foundation::HANDLE) -> Self {
        Self {
            launcher,
            remote_process: None,
            remote_close_armed: true,
        }
    }

    fn record_process(&mut self, remote_process: u64) {
        self.remote_process = Some(remote_process);
    }

    fn revoke_before_delivery(&mut self) -> Result<(), String> {
        if !self.remote_close_armed {
            return Ok(());
        }
        self.remote_close_armed = false;
        if let Some(remote) = self.remote_process.take() {
            super::process::revoke_remote_handle(remote, self.launcher).map_err(|error| {
                format!(
                    "session broker pre-delivery remote-handle rollback failed: holder-process: {error}"
                )
            })?;
        }
        Ok(())
    }

    fn failure_detail(&mut self, primary: impl Into<String>) -> String {
        let primary = primary.into();
        match self.revoke_before_delivery() {
            Ok(()) => primary,
            Err(cleanup) => format!("{primary}; {cleanup}"),
        }
    }

    fn disarm_after_launched_delivery(&mut self) {
        self.remote_close_armed = false;
        self.remote_process = None;
    }
}

impl Drop for LauncherHandleTransferRollback {
    fn drop(&mut self) {
        if let Err(error) = self.revoke_before_delivery() {
            eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: {error}");
        }
    }
}

impl SessionBrokerServiceError {
    fn startup(stage: SessionBrokerStartupStage, detail: impl Into<String>) -> Self {
        Self {
            stage,
            detail: detail.into(),
        }
    }

    fn process_protection(error: super::security::SessionBrokerProtectionError) -> Self {
        Self::startup(
            SessionBrokerStartupStage::ProcessProtection(error.stage),
            error.to_string(),
        )
    }
}

impl From<String> for SessionBrokerServiceError {
    fn from(detail: String) -> Self {
        Self::startup(SessionBrokerStartupStage::Transaction, detail)
    }
}

pub(crate) const fn startup_diagnostic_from_exit(
    exit: u32,
) -> Option<(&'static str, Option<&'static str>)> {
    match exit {
        BROKER_FAILURE_ARGUMENTS => Some(("arguments", None)),
        BROKER_FAILURE_SOURCE_PRIVILEGE_NORMALIZATION => {
            Some(("source-privilege-normalization", None))
        }
        BROKER_FAILURE_PROCESS_PROTECTION => Some(("process-protection", None)),
        BROKER_FAILURE_PROCESS_DESCRIPTOR => {
            Some(("process-protection", Some("process-descriptor")))
        }
        BROKER_FAILURE_PROCESS_APPLY => Some(("process-protection", Some("process-apply"))),
        BROKER_FAILURE_PROCESS_READBACK => Some(("process-protection", Some("process-readback"))),
        BROKER_FAILURE_TOKEN_OPEN => Some(("process-protection", Some("token-open"))),
        BROKER_FAILURE_TOKEN_DESCRIPTOR => Some(("process-protection", Some("token-descriptor"))),
        BROKER_FAILURE_TOKEN_DACL_APPLY => Some(("process-protection", Some("token-dacl-apply"))),
        BROKER_FAILURE_TOKEN_READBACK => Some(("process-protection", Some("token-readback"))),
        BROKER_FAILURE_CERTIFICATION => Some(("certification", None)),
        BROKER_FAILURE_LISTENER_PREPARATION => Some(("listener-preparation", None)),
        BROKER_FAILURE_RUNNING_PUBLICATION => Some(("running-publication", None)),
        BROKER_FAILURE_NONCE_VALIDATION => Some(("nonce-validation", None)),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SessionBrokerStageV1 {
    RequestValidation,
    HolderCreation,
    HandleTransfer,
    Acknowledgement,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SessionCreationPhaseV1 {
    WindowStation,
    Desktop,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerHelloV1 {
    schema_version: u32,
    service_name: String,
    broker_identity: WindowsProcessIdentityV1,
    broker_image_sha256: String,
    broker_source: super::token::TokenAttestationSnapshot,
    challenge: String,
    start_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerRequestV1 {
    schema_version: u32,
    start_nonce: String,
    challenge: String,
    launcher_identity: WindowsProcessIdentityV1,
    target_session_id: u32,
    holder_pipe_name: String,
    holder_nonce: String,
    launcher_job_handle: u64,
    holder_image_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionBrokerLaunchedV1 {
    schema_version: u32,
    start_nonce: String,
    challenge: String,
    broker_identity: WindowsProcessIdentityV1,
    holder_identity: WindowsProcessIdentityV1,
    broker_source: super::token::TokenAttestationSnapshot,
    holder_effective: super::token::TokenAttestationSnapshot,
    holder_query: super::token::TokenQueryAttestationSnapshot,
    holder_process_handle: u64,
    holder_thread_id: u32,
    binding_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, tag = "kind", rename_all = "kebab-case")]
enum SessionBrokerProductionFrameV1 {
    Hello(SessionBrokerHelloV1),
    Request(SessionBrokerRequestV1),
    Launched(SessionBrokerLaunchedV1),
    Ack {
        binding_sha256: String,
    },
    Arm {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
    },
    Armed {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        carrier: super::token::TokenAttestationSnapshot,
    },
    Consumed {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    },
    Cleared {
        binding_sha256: String,
        holder_binding_sha256: String,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
    },
    FinalAck {
        binding_sha256: String,
        holder_binding_sha256: String,
        completed_phases: u32,
    },
    Done {
        binding_sha256: String,
    },
    Failed {
        stage: SessionBrokerStageV1,
        detail: String,
    },
}

pub(crate) struct BrokeredHolder {
    pub process: OwnedHandle,
    pub thread: OwnedHandle,
    pub identity: WindowsProcessIdentityV1,
    pub broker_source: super::token::TokenAttestationSnapshot,
    pub holder_effective: super::token::TokenAttestationSnapshot,
    pub query: super::token::TokenQueryAttestationSnapshot,
    launch_binding_sha256: String,
    pub control: Option<BrokerControlLease>,
}

pub(crate) struct BrokerControlLease {
    pipe: Option<OwnedHandle>,
    service: super::service_manager::ScHandle,
    broker: super::service_manager::PinnedServiceProcess,
    launch_binding_sha256: String,
    holder_binding_sha256: Option<String>,
    completed_phases: u32,
    finalized: bool,
    _transaction_lease: std::sync::MutexGuard<'static, ()>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerClientOperation {
    Holder,
}

impl BrokerClientOperation {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Holder => "holder",
        }
    }

    fn startup_failure(
        self,
        stage: BrokerClientStartupStage,
        detail: impl ToString,
    ) -> BrokerClientStartupError {
        BrokerClientStartupError::new(self, stage, detail)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerClientStartupStage {
    TransactionLease,
    StartNonce,
    ManagerConnect,
    ServiceOpen,
    InitialStatus,
    DemandStart,
    PipeConnect,
    PeerAuthentication,
    ServicePin,
    HelloRead,
    HelloValidation,
    SourceValidation,
    SourceBinding,
}

impl BrokerClientStartupStage {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::TransactionLease => "transaction-lease",
            Self::StartNonce => "start-nonce",
            Self::ManagerConnect => "manager-connect",
            Self::ServiceOpen => "service-open",
            Self::InitialStatus => "initial-status",
            Self::DemandStart => "demand-start",
            Self::PipeConnect => "pipe-connect",
            Self::PeerAuthentication => "peer-authentication",
            Self::ServicePin => "service-pin",
            Self::HelloRead => "hello-read",
            Self::HelloValidation => "hello-validation",
            Self::SourceValidation => "source-validation",
            Self::SourceBinding => "source-binding",
        }
    }
}

#[derive(Debug)]
struct BrokerClientStartupError {
    operation: BrokerClientOperation,
    stage: BrokerClientStartupStage,
    detail: String,
}

impl BrokerClientStartupError {
    fn new(
        operation: BrokerClientOperation,
        stage: BrokerClientStartupStage,
        detail: impl ToString,
    ) -> Self {
        Self {
            operation,
            stage,
            detail: detail.to_string(),
        }
    }

    fn append_retirement(mut self, detail: impl ToString) -> Self {
        self.detail = bounded_broker_detail(format!(
            "{}; exact_broker_retirement_error={}",
            self.detail,
            detail.to_string(),
        ));
        self
    }

    fn holder_diagnostic(self) -> String {
        format!(
            "role=session-broker operation={} stage={} detail={}",
            self.operation.diagnostic(),
            self.stage.diagnostic(),
            self.detail,
        )
    }
}

struct AuthenticatedBrokerClient {
    pipe: Option<OwnedHandle>,
    service: Option<super::service_manager::ScHandle>,
    broker: Option<super::service_manager::PinnedServiceProcess>,
    hello: SessionBrokerHelloV1,
    broker_source_query: super::token::TokenQueryAttestationSnapshot,
    transaction_lease: Option<std::sync::MutexGuard<'static, ()>>,
}

impl AuthenticatedBrokerClient {
    fn pipe(&self) -> &OwnedHandle {
        self.pipe
            .as_ref()
            .expect("authenticated broker client pipe must remain owned")
    }

    fn broker(&self) -> &super::service_manager::PinnedServiceProcess {
        self.broker
            .as_ref()
            .expect("authenticated broker client process must remain owned")
    }

    fn retire(mut self) -> Result<(), String> {
        drop(self.pipe.take());
        let retirement = retire_authenticated_broker(
            self.service
                .as_ref()
                .expect("authenticated broker client service must remain owned"),
            self.broker(),
        );
        drop(self.broker.take());
        drop(self.service.take());
        drop(self.transaction_lease.take());
        retirement
    }

    fn into_holder_control(mut self, launch_binding_sha256: String) -> BrokerControlLease {
        BrokerControlLease {
            pipe: self.pipe.take(),
            service: self
                .service
                .take()
                .expect("authenticated broker client service must transfer"),
            broker: self
                .broker
                .take()
                .expect("authenticated broker client process must transfer"),
            launch_binding_sha256,
            holder_binding_sha256: None,
            completed_phases: 0,
            finalized: false,
            _transaction_lease: self
                .transaction_lease
                .take()
                .expect("authenticated broker transaction lease must transfer"),
        }
    }
}

impl Drop for AuthenticatedBrokerClient {
    fn drop(&mut self) {
        drop(self.pipe.take());
        if let (Some(service), Some(broker)) = (self.service.as_ref(), self.broker.as_ref()) {
            if let Err(error) = retire_authenticated_broker(service, broker) {
                eprintln!(
                    "MCSEALED-WINDOWS-SESSION-BROKER: authenticated bootstrap cleanup failed: {error}"
                );
            }
        }
        drop(self.broker.take());
        drop(self.service.take());
        drop(self.transaction_lease.take());
    }
}

impl BrokerControlLease {
    pub(crate) fn arm(
        &mut self,
        holder_binding_sha256: &str,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: &super::token::TokenQueryAttestationSnapshot,
    ) -> Result<super::token::TokenAttestationSnapshot, String> {
        if ordinal != self.completed_phases + 1 || thread_id == 0 {
            return Err("session broker arm request is out of order or has zero TID".to_owned());
        }
        match &self.holder_binding_sha256 {
            Some(expected) if expected != holder_binding_sha256 => {
                return Err("session broker holder binding changed between phases".to_owned());
            }
            None => self.holder_binding_sha256 = Some(holder_binding_sha256.to_owned()),
            _ => {}
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmWrite,
            &SessionBrokerProductionFrameV1::Arm {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                phase,
                ordinal,
                thread_id,
                holder_primary: holder_primary.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerProductionFrameV1::Armed {
                binding_sha256,
                holder_binding_sha256: observed_holder_binding,
                phase: observed_phase,
                ordinal: observed_ordinal,
                thread_id: observed_thread_id,
                carrier,
            } if binding_sha256 == self.launch_binding_sha256
                && observed_holder_binding == holder_binding_sha256
                && observed_phase == phase
                && observed_ordinal == ordinal
                && observed_thread_id == thread_id =>
            {
                Ok(carrier)
            }
            _ => Err("session broker returned an invalid Armed frame".to_owned()),
        }
    }

    pub(crate) fn consumed(
        &mut self,
        holder_binding_sha256: &str,
        phase: SessionCreationPhaseV1,
        ordinal: u32,
        thread_id: u32,
        holder_primary: &super::token::TokenQueryAttestationSnapshot,
        native_code: Option<i32>,
        thread_token_absent: bool,
    ) -> Result<(), String> {
        if self.holder_binding_sha256.as_deref() != Some(holder_binding_sha256)
            || ordinal != self.completed_phases + 1
        {
            return Err("session broker Consumed evidence is out of order".to_owned());
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerConsumedWrite,
            &SessionBrokerProductionFrameV1::Consumed {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                phase,
                ordinal,
                thread_id,
                holder_primary: holder_primary.clone(),
                native_code,
                thread_token_absent,
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerClearedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerProductionFrameV1::Cleared {
                binding_sha256,
                holder_binding_sha256: observed_holder_binding,
                phase: observed_phase,
                ordinal: observed_ordinal,
                thread_id: observed_thread_id,
            } if binding_sha256 == self.launch_binding_sha256
                && observed_holder_binding == holder_binding_sha256
                && observed_phase == phase
                && observed_ordinal == ordinal
                && observed_thread_id == thread_id =>
            {
                self.completed_phases = ordinal;
                Ok(())
            }
            _ => Err("session broker returned an invalid Cleared frame".to_owned()),
        }
    }

    pub(crate) fn finish(mut self, holder_binding_sha256: &str) -> Result<(), String> {
        if self.holder_binding_sha256.as_deref() != Some(holder_binding_sha256) {
            return Err("session broker final holder binding is mismatched".to_owned());
        }
        let pipe = self
            .pipe
            .as_ref()
            .ok_or_else(|| "session broker control pipe is absent".to_owned())?;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerFinalAckWrite,
            &SessionBrokerProductionFrameV1::FinalAck {
                binding_sha256: self.launch_binding_sha256.clone(),
                holder_binding_sha256: holder_binding_sha256.to_owned(),
                completed_phases: self.completed_phases,
            },
        )
        .map_err(|error| error.to_string())?;
        match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(self.broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerDoneRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerProductionFrameV1::Done { binding_sha256 }
                if binding_sha256 == self.launch_binding_sha256 => {}
            _ => return Err("session broker returned an invalid Done frame".to_owned()),
        }
        drop(self.pipe.take());
        retire_authenticated_broker(&self.service, &self.broker)?;
        self.finalized = true;
        Ok(())
    }
}

impl Drop for BrokerControlLease {
    fn drop(&mut self) {
        if !self.finalized {
            drop(self.pipe.take());
            if let Err(error) = retire_authenticated_broker(&self.service, &self.broker) {
                eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: control lease cleanup failed: {error}");
            }
        }
    }
}

pub fn run() -> Result<(), String> {
    super::service::dispatch(
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        BROKER_ROLE,
        service_main,
    )
}

unsafe extern "system" fn service_main(count: u32, arguments: *mut *mut u16) {
    if let Err(error) =
        unsafe { super::service::announce_starting(WINDOWS_SESSION_BROKER_SERVICE_NAME) }
    {
        eprintln!("{error}");
        return;
    }
    let result = unsafe { broker_service_transaction(count, arguments) };
    match result {
        Ok(()) => super::service::announce_stopped(0),
        Err(error) => {
            eprintln!("MCSEALED-WINDOWS-SESSION-BROKER: {}", error.detail);
            super::service::announce_startup_failed(error.stage.service_exit());
        }
    }
}

unsafe fn broker_service_transaction(
    count: u32,
    arguments: *mut *mut u16,
) -> Result<(), SessionBrokerServiceError> {
    let arguments = unsafe { decode_service_arguments(count, arguments) }.map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Arguments, error)
    })?;
    let start_nonce = validate_broker_service_arguments(&arguments).map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Arguments, error)
    })?;
    validate_broker_start_nonce(start_nonce).map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::NonceValidation, error)
    })?;
    let normalized_broker_source =
        super::token::normalize_current_session_broker_source_privileges().map_err(|error| {
            SessionBrokerServiceError::startup(
                SessionBrokerStartupStage::SourcePrivilegeNormalization,
                error.to_string(),
            )
        })?;
    super::security::protect_current_session_broker()
        .map_err(SessionBrokerServiceError::process_protection)?;
    certify_current_broker().map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::Certification, error)
    })?;
    let pipe_security = super::security::session_broker_pipe_sddl()
        .and_then(|sddl| super::security::SecurityDescriptor::from_sddl(&sddl))
        .map_err(|error| {
            SessionBrokerServiceError::startup(
                SessionBrokerStartupStage::ListenerPreparation,
                error,
            )
        })?;
    let listener = super::pipe::PipeListener::new(WINDOWS_SESSION_BROKER_PIPE, pipe_security);
    let prepared = listener.prepare().map_err(|error| {
        SessionBrokerServiceError::startup(
            SessionBrokerStartupStage::ListenerPreparation,
            error.to_string(),
        )
    })?;
    super::service::announce_running().map_err(|error| {
        SessionBrokerServiceError::startup(SessionBrokerStartupStage::RunningPublication, error)
    })?;
    let pipe = listener.accept_prepared(prepared)?;
    if super::service::stop_requested() {
        return Ok(());
    }
    let (launcher_process, launcher_identity) = authenticate_launcher_client(pipe.raw())?;
    let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
    let broker_identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
    let challenge = super::token::service_attestation_challenge("session-broker")
        .map_err(|error| error.to_string())?;
    let hello = SessionBrokerHelloV1 {
        schema_version: SESSION_BROKER_SCHEMA_VERSION,
        service_name: WINDOWS_SESSION_BROKER_SERVICE_NAME.to_owned(),
        broker_identity: broker_identity.clone(),
        broker_image_sha256: super::package::validate_installed_session_broker()?,
        broker_source: normalized_broker_source.clone(),
        challenge: challenge.clone(),
        start_nonce: start_nonce.to_owned(),
    };
    super::pipe::write_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerHelloWrite,
        &SessionBrokerProductionFrameV1::Hello(hello.clone()),
    )
    .map_err(|error| error.to_string())?;
    let request_frame = super::pipe::read_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerRequestRead,
    )
    .map_err(|error| error.to_string())?;
    let request = match request_frame {
        SessionBrokerProductionFrameV1::Request(request) => request,
        _ => {
            return Err("session broker expected Request after Hello"
                .to_owned()
                .into());
        }
    };
    if let Err(error) = validate_request(&request, &hello, &launcher_identity) {
        let _ = super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(launcher_process.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
            &SessionBrokerProductionFrameV1::Failed {
                stage: SessionBrokerStageV1::RequestValidation,
                detail: bounded_broker_detail(error.clone()),
            },
        );
        return Err(error.into());
    }
    let mut holder = match super::process::create_session_broker_holder(
        request.target_session_id,
        &request.holder_pipe_name,
        &request.holder_nonce,
        launcher_process.raw(),
        request.launcher_job_handle,
    ) {
        Ok(holder) if holder.broker_source == normalized_broker_source => holder,
        Ok(mut holder) => {
            holder.terminate();
            let error =
                "session broker source changed between startup normalization and holder derivation"
                    .to_owned();
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerProductionFrameV1::Failed {
                    stage: SessionBrokerStageV1::HolderCreation,
                    detail: bounded_broker_detail(error.clone()),
                },
            );
            return Err(error.into());
        }
        Err(error) => {
            let detail = bounded_broker_detail(error.clone());
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerProductionFrameV1::Failed {
                    stage: SessionBrokerStageV1::HolderCreation,
                    detail,
                },
            );
            return Err(error.into());
        }
    };
    let mut transfer_rollback = LauncherHandleTransferRollback::new(launcher_process.raw());
    let remote_process = match duplicate_into_launcher(
        holder.process.raw(),
        launcher_process.raw(),
        HOLDER_PROCESS_TRANSFER_ACCESS,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            holder.terminate();
            let _ = super::pipe::write_frame_bounded(
                pipe.raw(),
                Some(launcher_process.raw()),
                deadline,
                super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
                &SessionBrokerProductionFrameV1::Failed {
                    stage: SessionBrokerStageV1::HandleTransfer,
                    detail: bounded_broker_detail(error.clone()),
                },
            );
            return Err(error.into());
        }
    };
    transfer_rollback.record_process(remote_process);
    let mut launched = SessionBrokerLaunchedV1 {
        schema_version: SESSION_BROKER_SCHEMA_VERSION,
        start_nonce: start_nonce.to_owned(),
        challenge,
        broker_identity,
        holder_identity: holder.identity.clone(),
        broker_source: holder.broker_source.clone(),
        holder_effective: holder.holder_effective.clone(),
        holder_query: holder.query.clone(),
        holder_process_handle: remote_process,
        holder_thread_id: holder.primary_thread_id,
        binding_sha256: String::new(),
    };
    launched.binding_sha256 = match launched_binding_sha256(&request, &launched) {
        Ok(binding) => binding,
        Err(error) => {
            holder.terminate();
            return Err(transfer_rollback.failure_detail(error).into());
        }
    };
    if let Err(error) = super::pipe::write_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedWrite,
        &SessionBrokerProductionFrameV1::Launched(launched.clone()),
    ) {
        holder.terminate();
        return Err(transfer_rollback.failure_detail(error.to_string()).into());
    }
    transfer_rollback.disarm_after_launched_delivery();
    let acknowledgement = super::pipe::read_frame_bounded(
        pipe.raw(),
        Some(launcher_process.raw()),
        deadline,
        super::pipe::TargetDesktopBootstrapPipeOperation::BrokerAckRead,
    );
    match acknowledgement {
        Ok(SessionBrokerProductionFrameV1::Ack { binding_sha256 })
            if binding_sha256 == launched.binding_sha256 => {}
        Ok(_) => {
            holder.terminate();
            return Err("session broker received an invalid holder acknowledgement"
                .to_owned()
                .into());
        }
        Err(error) => {
            holder.terminate();
            return Err(error.to_string().into());
        }
    }
    run_creation_authority_transaction(pipe.raw(), launcher_process.raw(), &launched, &mut holder)?;
    Ok(())
}

fn run_creation_authority_transaction(
    pipe: HANDLE,
    launcher_process: HANDLE,
    launched: &SessionBrokerLaunchedV1,
    holder: &mut super::process::SessionBrokerCreatedHolder,
) -> Result<(), String> {
    let mut completed = 0_u32;
    let mut holder_binding: Option<String> = None;
    let mut failed = false;
    let mut station_tid = None;
    loop {
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        let frame: SessionBrokerProductionFrameV1 = super::pipe::read_frame_bounded(
            pipe,
            Some(launcher_process),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmRead,
        )
        .map_err(|error| error.to_string())?;
        match frame {
            SessionBrokerProductionFrameV1::Arm {
                binding_sha256,
                holder_binding_sha256,
                phase,
                ordinal,
                thread_id,
                holder_primary,
            } => {
                let expected_phase = match completed {
                    0 => SessionCreationPhaseV1::WindowStation,
                    1 => SessionCreationPhaseV1::Desktop,
                    _ => return Err("session broker rejected a third creation arm".to_owned()),
                };
                if failed
                    || binding_sha256 != launched.binding_sha256
                    || ordinal != completed + 1
                    || phase != expected_phase
                    || thread_id == 0
                    || holder_primary != holder.query
                    || holder_binding
                        .as_ref()
                        .is_some_and(|expected| expected != &holder_binding_sha256)
                {
                    return Err("session broker Arm evidence is mismatched or reordered".to_owned());
                }
                if completed == 0 {
                    if thread_id != holder.primary_thread_id {
                        return Err(
                            "station arm did not name the authenticated primary TID".to_owned()
                        );
                    }
                    holder_binding = Some(holder_binding_sha256.clone());
                    station_tid = Some(thread_id);
                } else if station_tid == Some(thread_id) {
                    return Err("desktop arm reused the station creator TID".to_owned());
                }
                // SAFETY: the digest-bound TID is opened only for exact remote
                // SetThreadToken and independent token readback.
                let thread = OwnedHandle::new(unsafe {
                    OpenThread(HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS, 0, thread_id)
                })?;
                verify_exact_handle(
                    thread.raw(),
                    HOLDER_THREAD_BROKER_ARM_REQUEST_ACCESS,
                    HOLDER_THREAD_BROKER_ARM_GRANTED_ACCESS,
                    "creator-thread",
                    "open",
                )?;
                if unsafe { GetProcessIdOfThread(thread.raw()) } != holder.identity.process_id {
                    return Err("creation TID is not owned by the authenticated holder".to_owned());
                }
                super::token::require_thread_token_absent(thread.raw())?;
                let (carrier, expected_evidence) = match phase {
                    SessionCreationPhaseV1::WindowStation => (
                        holder.station_creation_carrier.raw(),
                        &holder.station_creation_evidence,
                    ),
                    SessionCreationPhaseV1::Desktop => (
                        holder.desktop_creation_carrier.raw(),
                        &holder.desktop_creation_evidence,
                    ),
                };
                let attached =
                    super::token::attach_creation_carrier_to_thread(thread.raw(), carrier)?;
                if &attached != expected_evidence {
                    return Err("attached creation carrier evidence is mismatched".to_owned());
                }
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    deadline,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerArmedWrite,
                    &SessionBrokerProductionFrameV1::Armed {
                        binding_sha256: launched.binding_sha256.clone(),
                        holder_binding_sha256: holder_binding_sha256.clone(),
                        phase,
                        ordinal,
                        thread_id,
                        carrier: attached,
                    },
                )
                .map_err(|error| error.to_string())?;
                let consumed: SessionBrokerProductionFrameV1 = super::pipe::read_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    Instant::now() + BROKER_TRANSACTION_DEADLINE,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerConsumedRead,
                )
                .map_err(|error| error.to_string())?;
                let native_code = match consumed {
                    SessionBrokerProductionFrameV1::Consumed {
                        binding_sha256: consumed_binding,
                        holder_binding_sha256: consumed_holder_binding,
                        phase: consumed_phase,
                        ordinal: consumed_ordinal,
                        thread_id: consumed_thread,
                        holder_primary: consumed_primary,
                        native_code,
                        thread_token_absent,
                    } if consumed_binding == launched.binding_sha256
                        && consumed_holder_binding == holder_binding_sha256
                        && consumed_phase == phase
                        && consumed_ordinal == ordinal
                        && consumed_thread == thread_id
                        && consumed_primary == holder.query
                        && thread_token_absent =>
                    {
                        native_code
                    }
                    _ => return Err("session broker Consumed evidence is invalid".to_owned()),
                };
                super::token::require_thread_token_absent(thread.raw())?;
                completed = ordinal;
                failed = native_code.is_some();
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    Instant::now() + BROKER_TRANSACTION_DEADLINE,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerClearedWrite,
                    &SessionBrokerProductionFrameV1::Cleared {
                        binding_sha256: launched.binding_sha256.clone(),
                        holder_binding_sha256,
                        phase,
                        ordinal,
                        thread_id,
                    },
                )
                .map_err(|error| error.to_string())?;
            }
            SessionBrokerProductionFrameV1::FinalAck {
                binding_sha256,
                holder_binding_sha256,
                completed_phases,
            } if binding_sha256 == launched.binding_sha256
                && holder_binding.as_deref() == Some(holder_binding_sha256.as_str())
                && completed_phases == completed
                && (completed == 2 || failed) =>
            {
                holder.disarm();
                super::pipe::write_frame_bounded(
                    pipe,
                    Some(launcher_process),
                    deadline,
                    super::pipe::TargetDesktopBootstrapPipeOperation::BrokerDoneWrite,
                    &SessionBrokerProductionFrameV1::Done {
                        binding_sha256: launched.binding_sha256.clone(),
                    },
                )
                .map_err(|error| error.to_string())?;
                return Ok(());
            }
            _ => {
                return Err(
                    "session broker creation authority state machine rejected a frame".to_owned(),
                );
            }
        }
    }
}

fn start_authenticated_broker(
    operation: BrokerClientOperation,
) -> Result<AuthenticatedBrokerClient, BrokerClientStartupError> {
    let transaction_lease = match BROKER_TRANSACTION_LEASE.try_lock() {
        Ok(lease) => lease,
        Err(TryLockError::WouldBlock) => {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::TransactionLease,
                "result=busy another authenticated one-shot transaction owns the broker lifecycle",
            ));
        }
        Err(TryLockError::Poisoned(_)) => {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::TransactionLease,
                "result=poisoned one-shot transaction serialization invariant failed",
            ));
        }
    };
    let start_nonce = super::token::service_attestation_challenge("session-broker-start")
        .map_err(|error| operation.startup_failure(BrokerClientStartupStage::StartNonce, error))?;
    let manager = super::service_manager::manager_connect().map_err(|error| {
        operation.startup_failure(BrokerClientStartupStage::ManagerConnect, error)
    })?;
    let service = super::service_manager::open(
        &manager,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        SERVICE_START | SERVICE_QUERY_STATUS,
    )
    .map_err(|error| operation.startup_failure(BrokerClientStartupStage::ServiceOpen, error))?;
    let initial_status = super::service_manager::status_process(&service).map_err(|error| {
        operation.startup_failure(BrokerClientStartupStage::InitialStatus, error)
    })?;
    if initial_status.dwCurrentState != SERVICE_STOPPED {
        return Err(operation.startup_failure(
            BrokerClientStartupStage::InitialStatus,
            format!(
                "expected_state=stopped actual_state={} process_id={} win32_exit={} service_exit={}",
                initial_status.dwCurrentState,
                initial_status.dwProcessId,
                initial_status.dwWin32ExitCode,
                initial_status.dwServiceSpecificExitCode,
            ),
        ));
    }
    super::service_manager::start_with_arguments(
        &service,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        &[
            SESSION_BROKER_SCHEMA_VERSION.to_string(),
            start_nonce.clone(),
        ],
    )
    .map_err(|error| operation.startup_failure(BrokerClientStartupStage::DemandStart, error))?;
    let pipe = match super::pipe::connect_session_broker_pipe(
        WINDOWS_SESSION_BROKER_PIPE,
        Instant::now() + BROKER_TRANSACTION_DEADLINE,
    ) {
        Ok(pipe) => pipe,
        Err(endpoint_error) => {
            let detail = match super::service_manager::status_process(&service) {
                Ok(status) => format!(
                    "service_state={} process_id={} win32_exit={} service_exit={} endpoint_error={endpoint_error}",
                    status.dwCurrentState,
                    status.dwProcessId,
                    status.dwWin32ExitCode,
                    status.dwServiceSpecificExitCode,
                ),
                Err(status_error) => format!(
                    "service_state=query-failed status_error={status_error} endpoint_error={endpoint_error}"
                ),
            };
            return Err(operation.startup_failure(BrokerClientStartupStage::PipeConnect, detail));
        }
    };
    let (broker_process, broker_identity) =
        authenticate_broker_server(pipe.raw()).map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::PeerAuthentication, error)
        })?;
    let pinned_broker = super::service_manager::PinnedServiceProcess {
        handle: broker_process,
        identity: broker_identity,
    };
    let authenticated = (|| {
        let broker_source_query =
            super::token::process_token_query_attestation(pinned_broker.handle.raw()).map_err(
                |error| operation.startup_failure(BrokerClientStartupStage::SourceBinding, error),
            )?;
        let status = super::service_manager::status_process(&service).map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::ServicePin, error)
        })?;
        if status.dwCurrentState != windows_sys::Win32::System::Services::SERVICE_RUNNING
            || status.dwProcessId != pinned_broker.identity.process_id
        {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::ServicePin,
                format!(
                    "pipe peer is not the SCM-pinned broker instance: service_state={} service_pid={} peer_pid={}",
                    status.dwCurrentState, status.dwProcessId, pinned_broker.identity.process_id,
                ),
            ));
        }
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        let hello = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(pinned_broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerHelloRead,
        )
        .map_err(|error| operation.startup_failure(BrokerClientStartupStage::HelloRead, error))?
        {
            SessionBrokerProductionFrameV1::Hello(hello) => hello,
            _ => {
                return Err(operation.startup_failure(
                    BrokerClientStartupStage::HelloRead,
                    "session broker did not send Hello first",
                ));
            }
        };
        if hello.schema_version != SESSION_BROKER_SCHEMA_VERSION
            || hello.service_name != WINDOWS_SESSION_BROKER_SERVICE_NAME
            || hello.start_nonce != start_nonce
            || hello.broker_identity != pinned_broker.identity
            || hello.broker_image_sha256
                != super::package::validate_installed_session_broker().map_err(|error| {
                    operation.startup_failure(BrokerClientStartupStage::HelloValidation, error)
                })?
            || !memcordon_core::windows_service_attestation_challenge_is_valid(&hello.challenge)
        {
            return Err(operation.startup_failure(
                BrokerClientStartupStage::HelloValidation,
                "session broker Hello evidence is mismatched",
            ));
        }
        super::token::validate_normalized_session_broker_source_snapshot(&hello.broker_source)
            .map_err(|error| {
                operation.startup_failure(BrokerClientStartupStage::SourceValidation, error)
            })?;
        super::token::require_same_process_token_query(
            "session-broker-hello-source-to-authenticated-process",
            &hello.broker_source.query_evidence(),
            &broker_source_query,
        )
        .map_err(|error| {
            operation.startup_failure(BrokerClientStartupStage::SourceBinding, error)
        })?;
        Ok::<_, BrokerClientStartupError>((hello, broker_source_query))
    })();
    match authenticated {
        Ok((hello, broker_source_query)) => Ok(AuthenticatedBrokerClient {
            pipe: Some(pipe),
            service: Some(service),
            broker: Some(pinned_broker),
            hello,
            broker_source_query,
            transaction_lease: Some(transaction_lease),
        }),
        Err(primary) => {
            drop(pipe);
            match retire_authenticated_broker(&service, &pinned_broker) {
                Ok(()) => Err(primary),
                Err(retirement) => Err(primary.append_retirement(retirement)),
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn request_holder(
    job: &super::job::Job,
    target_session_id: u32,
    holder_pipe_name: &str,
    holder_nonce: &str,
) -> Result<BrokeredHolder, String> {
    let authenticated = start_authenticated_broker(BrokerClientOperation::Holder)
        .map_err(BrokerClientStartupError::holder_diagnostic)?;
    let transaction_result = (|| -> Result<BrokeredHolder, String> {
        let pipe = authenticated.pipe();
        let broker = authenticated.broker();
        let hello = &authenticated.hello;
        let deadline = Instant::now() + BROKER_TRANSACTION_DEADLINE;
        job.verify_session_holder_configuration()?;
        if job.active_processes()? != 0 {
            return Err("session-holder Job is not empty before broker request".to_owned());
        }
        let launcher_identity = super::process::process_identity(unsafe { GetCurrentProcess() })?;
        let request = SessionBrokerRequestV1 {
            schema_version: SESSION_BROKER_SCHEMA_VERSION,
            start_nonce: hello.start_nonce.clone(),
            challenge: hello.challenge.clone(),
            launcher_identity,
            target_session_id,
            holder_pipe_name: holder_pipe_name.to_owned(),
            holder_nonce: holder_nonce.to_owned(),
            launcher_job_handle: encode_protocol_handle(job.handle(), "launcher-job")?,
            holder_image_sha256: super::package::validate_installed_target_desktop_bootstrap()?,
        };
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerRequestWrite,
            &SessionBrokerProductionFrameV1::Request(request.clone()),
        )
        .map_err(|error| error.to_string())?;
        let launched = match super::pipe::read_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerLaunchedRead,
        )
        .map_err(|error| error.to_string())?
        {
            SessionBrokerProductionFrameV1::Launched(launched) => launched,
            SessionBrokerProductionFrameV1::Failed { stage, detail } => {
                return Err(format!(
                    "session broker failed: stage={stage:?} detail={detail}"
                ));
            }
            _ => return Err("session broker returned an invalid launch frame".to_owned()),
        };
        if launched.schema_version != SESSION_BROKER_SCHEMA_VERSION
            || launched.start_nonce != request.start_nonce
            || launched.challenge != request.challenge
            || launched.broker_identity != broker.identity
            || launched.broker_source != hello.broker_source
            || launched.binding_sha256 != launched_binding_sha256(&request, &launched)?
        {
            return Err("session broker launch binding is mismatched".to_owned());
        }
        let process = OwnedHandle::new(decode_protocol_handle(
            launched.holder_process_handle,
            "holder-process",
        )?)?;
        if launched.holder_thread_id == 0 {
            return Err("session broker returned a zero holder primary thread id".to_owned());
        }
        // SAFETY: the digest-bound nonzero TID names the broker-retained,
        // still-suspended primary thread. The protected thread DACL performs
        // the launcher access check and the resulting handle is local and
        // explicitly non-inheritable.
        let thread = OwnedHandle::new(unsafe {
            OpenThread(HOLDER_THREAD_LAUNCHER_ACCESS, 0, launched.holder_thread_id)
        })?;
        verify_exact_handle(
            process.raw(),
            HOLDER_PROCESS_TRANSFER_ACCESS,
            HOLDER_PROCESS_TRANSFER_ACCESS,
            "holder-process",
            "protocol-receive",
        )?;
        verify_exact_handle(
            thread.raw(),
            HOLDER_THREAD_LAUNCHER_ACCESS,
            HOLDER_THREAD_LAUNCHER_ACCESS,
            "holder-thread",
            "open",
        )?;
        // SAFETY: thread is the locally opened primary-thread capability and
        // carries THREAD_QUERY_LIMITED_INFORMATION for this association check.
        let actual_thread_process_id = unsafe { GetProcessIdOfThread(thread.raw()) };
        if actual_thread_process_id != launched.holder_identity.process_id {
            return Err(format!(
                "role=holder-thread operation=associate expected_pid={} actual_pid={} primary_thread_id={}",
                launched.holder_identity.process_id,
                actual_thread_process_id,
                launched.holder_thread_id,
            ));
        }
        if super::process::process_identity(process.raw())? != launched.holder_identity
            || super::token::process_token_query_attestation(process.raw())?
                != launched.holder_query
            || !job.contains(process.raw())?
            || job.active_processes()? != 1
            || job.total_processes()? != 1
            || job.process_ids()? != [launched.holder_identity.process_id]
        {
            return Err(
                "session broker holder evidence failed independent launcher readback".to_owned(),
            );
        }
        super::token::validate_normalized_session_broker_source_snapshot(&launched.broker_source)
            .map_err(|error| error.to_string())?;
        super::token::require_same_process_token_query(
            "session-broker-launched-source-to-authenticated-process",
            &launched.broker_source.query_evidence(),
            &authenticated.broker_source_query,
        )
        .map_err(|error| error.to_string())?;
        if launched.holder_effective.lineage.user_sid != "S-1-5-18"
            || launched.holder_effective.lineage.session_id != target_session_id
            || launched.holder_effective.behavior.token_is_restricted
            || !launched
                .holder_effective
                .behavior
                .restricting_sids
                .is_empty()
            || !snapshot_has_enabled_group(
                &launched.holder_effective,
                &super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?,
            )
        {
            return Err("session broker source or holder authority evidence is invalid".to_owned());
        }
        super::token::require_assigned_process_authority(
            "session-broker-holder-evidence-to-process",
            &launched.holder_effective,
            &launched.holder_query,
        )
        .map_err(|error| error.to_string())?;
        super::process::verify_image_path(
            process.raw(),
            &super::package::installed_target_desktop_bootstrap(),
        )?;
        super::pipe::write_frame_bounded(
            pipe.raw(),
            Some(broker.handle.raw()),
            deadline,
            super::pipe::TargetDesktopBootstrapPipeOperation::BrokerAckWrite,
            &SessionBrokerProductionFrameV1::Ack {
                binding_sha256: launched.binding_sha256.clone(),
            },
        )
        .map_err(|error| error.to_string())?;
        Ok(BrokeredHolder {
            process,
            thread,
            identity: launched.holder_identity,
            broker_source: launched.broker_source,
            holder_effective: launched.holder_effective,
            query: launched.holder_query,
            launch_binding_sha256: launched.binding_sha256,
            control: None,
        })
    })();
    match transaction_result {
        Ok(mut holder) => {
            holder.control =
                Some(authenticated.into_holder_control(holder.launch_binding_sha256.clone()));
            Ok(holder)
        }
        Err(transaction) => match authenticated.retire() {
            Ok(()) => Err(transaction),
            Err(retirement) => Err(format!(
                "{transaction}; exact_broker_retirement_error={retirement}"
            )),
        },
    }
}

fn retire_authenticated_broker(
    service: &super::service_manager::ScHandle,
    broker: &super::service_manager::PinnedServiceProcess,
) -> Result<(), String> {
    super::service_manager::wait_stopped(service, WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    let status = super::service_manager::status_process(service)?;
    if status.dwCurrentState != SERVICE_STOPPED || status.dwProcessId != 0 {
        return Err(format!(
            "role=session-broker operation=retire phase=scm-stopped expected_state={SERVICE_STOPPED} actual_state={} expected_pid=0 actual_pid={} pinned_pid={} pinned_creation_time_100ns={} win32_exit={} service_exit={}",
            status.dwCurrentState,
            status.dwProcessId,
            broker.identity.process_id,
            broker.identity.creation_time_100ns,
            status.dwWin32ExitCode,
            status.dwServiceSpecificExitCode,
        ));
    }
    super::service_manager::wait_service_process_exit(
        broker,
        WINDOWS_SESSION_BROKER_SERVICE_NAME,
        BROKER_TRANSACTION_DEADLINE,
    )?;
    let started = Instant::now();
    loop {
        if !super::pipe::endpoint_exists(WINDOWS_SESSION_BROKER_PIPE)? {
            return Ok(());
        }
        if started.elapsed() >= BROKER_TRANSACTION_DEADLINE {
            return Err(format!(
                "role=session-broker operation=retire phase=endpoint-disappearance pinned_pid={} pinned_creation_time_100ns={} elapsed_ms={} timed_out=true",
                broker.identity.process_id,
                broker.identity.creation_time_100ns,
                started.elapsed().as_millis(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn validate_request(
    request: &SessionBrokerRequestV1,
    hello: &SessionBrokerHelloV1,
    launcher_identity: &WindowsProcessIdentityV1,
) -> Result<(), String> {
    if request.schema_version != SESSION_BROKER_SCHEMA_VERSION
        || request.start_nonce != hello.start_nonce
        || request.challenge != hello.challenge
        || &request.launcher_identity != launcher_identity
        || request.target_session_id == 0
        || request.holder_image_sha256
            != super::package::validate_installed_target_desktop_bootstrap()?
    {
        return Err("session broker request evidence is mismatched".to_owned());
    }
    super::record::validate_attempt_id(&request.holder_nonce)?;
    let expected_pipe = format!(
        "{}{}",
        super::pipe::TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX,
        request.holder_nonce
    );
    if request.holder_pipe_name != expected_pipe || request.launcher_job_handle == 0 {
        return Err("session broker request surface is not canonical".to_owned());
    }
    Ok(())
}

fn authenticate_launcher_client(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(OwnedHandle, WindowsProcessIdentityV1), String> {
    let mut pid = 0_u32;
    let mut session = u32::MAX;
    // SAFETY: pipe is connected and outputs are writable.
    if unsafe { GetNamedPipeClientProcessId(pipe, &raw mut pid) } == 0
        || unsafe { GetNamedPipeClientSessionId(pipe, &raw mut session) } == 0
        || session != 0
    {
        return Err("session broker launcher pipe identity query failed".to_owned());
    }
    let process = OwnedHandle::new(unsafe { OpenProcess(LAUNCHER_PROCESS_BROKER_ACCESS, 0, pid) })?;
    verify_exact_handle(
        process.raw(),
        LAUNCHER_PROCESS_BROKER_ACCESS,
        LAUNCHER_PROCESS_BROKER_ACCESS,
        "launcher-process",
        "open",
    )?;
    let identity = super::process::process_identity(process.raw())?;
    super::process::verify_image_path(process.raw(), &super::package::installed_binary())?;
    let token = super::token::process_token(process.raw())?;
    let launcher_sid = super::security::service_sid(WINDOWS_LAUNCHER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || !super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &launcher_sid)?
        || !super::token::token_has_restricting_sid(token.raw(), &launcher_sid)?
    {
        return Err("session broker pipe client is not the restricted launcher".to_owned());
    }
    Ok((process, identity))
}

fn authenticate_broker_server(
    pipe: windows_sys::Win32::Foundation::HANDLE,
) -> Result<(OwnedHandle, WindowsProcessIdentityV1), String> {
    let mut pid = 0_u32;
    let mut session = u32::MAX;
    // SAFETY: pipe is connected and outputs are writable.
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut pid) } == 0
        || unsafe { GetNamedPipeServerSessionId(pipe, &raw mut session) } == 0
        || session != 0
    {
        return Err("session broker server pipe identity query failed".to_owned());
    }
    let process = OwnedHandle::new(unsafe { OpenProcess(BROKER_PROCESS_LAUNCHER_ACCESS, 0, pid) })?;
    verify_exact_handle(
        process.raw(),
        BROKER_PROCESS_LAUNCHER_ACCESS,
        BROKER_PROCESS_LAUNCHER_ACCESS,
        "broker-process",
        "open",
    )?;
    super::process::verify_image_path(process.raw(), &super::package::installed_session_broker())?;
    let token = super::token::process_token(process.raw())?;
    let broker_sid = super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &broker_sid)?
        || super::token::token_has_restricting_sid(token.raw(), &broker_sid)?
    {
        return Err(
            "session broker server token is not unrestricted broker LocalSystem".to_owned(),
        );
    }
    let identity = super::process::process_identity(process.raw())?;
    Ok((process, identity))
}

fn certify_current_broker() -> Result<(), String> {
    let process = unsafe { GetCurrentProcess() };
    super::process::verify_image_path(process, &super::package::installed_session_broker())?;
    let token = super::token::process_token(process)?;
    let broker_sid = super::security::service_sid(WINDOWS_SESSION_BROKER_SERVICE_NAME)?;
    if super::token::token_user_sid(token.raw())? != "S-1-5-18"
        || super::token::token_is_restricted(token.raw())
        || !super::token::token_has_enabled_group(token.raw(), &broker_sid)?
        || super::token::token_has_restricting_sid(token.raw(), &broker_sid)?
    {
        return Err("session broker live token certificate is invalid".to_owned());
    }
    Ok(())
}

fn duplicate_into_launcher(
    source: windows_sys::Win32::Foundation::HANDLE,
    launcher: windows_sys::Win32::Foundation::HANDLE,
    access: u32,
) -> Result<u64, String> {
    let mut remote = ptr::null_mut();
    // SAFETY: both processes and source are pinned; desired access is exact and
    // the launcher copy is explicitly noninheritable.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            launcher,
            &raw mut remote,
            access,
            0,
            0,
        )
    } == 0
    {
        Err(io::Error::last_os_error().to_string())
    } else {
        match encode_protocol_handle(remote, "transferred-holder") {
            Ok(remote) => Ok(remote),
            Err(error) => {
                let cleanup = super::process::revoke_remote_native_handle(remote, launcher);
                match cleanup {
                    Ok(()) => Err(error),
                    Err(cleanup) => {
                        Err(format!("{error}; remote-handle rollback failed: {cleanup}"))
                    }
                }
            }
        }
    }
}

fn encode_protocol_handle(handle: HANDLE, role: &str) -> Result<u64, String> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("{role} protocol handle is invalid"));
    }
    u64::try_from(handle as usize)
        .map_err(|_| format!("{role} protocol handle is not representable as u64"))
}

pub(crate) fn decode_protocol_handle(value: u64, role: &str) -> Result<HANDLE, String> {
    let native = usize::try_from(value)
        .map_err(|_| format!("{role} protocol handle exceeds native pointer width"))?;
    let handle = native as HANDLE;
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(format!("{role} protocol handle is invalid"));
    }
    Ok(handle)
}

fn verify_exact_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
    requested_access: u32,
    expected_granted_access: u32,
    role: &str,
    operation: &str,
) -> Result<(), String> {
    let mut flags = 0_u32;
    // SAFETY: handle is live and flags is writable.
    if unsafe { GetHandleInformation(handle, &raw mut flags) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let inherited = flags & HANDLE_FLAG_INHERIT != 0;
    let actual_granted_access = super::token::granted_handle_access(handle)?;
    if inherited || actual_granted_access != expected_granted_access {
        return Err(format!(
            "role={role} operation={operation} requested_access={requested_access:#010x} expected_granted_access={expected_granted_access:#010x} actual_granted_access={actual_granted_access:#010x} flags={flags:#010x} inherited={inherited}"
        ));
    }
    Ok(())
}

fn launched_binding_sha256(
    request: &SessionBrokerRequestV1,
    launched: &SessionBrokerLaunchedV1,
) -> Result<String, String> {
    let mut launched = launched.clone();
    launched.binding_sha256.clear();
    let bytes = serde_json::to_vec(&(request, launched)).map_err(|error| error.to_string())?;
    let mut domain = b"memcordon-session-broker-binding-v5\0".to_vec();
    domain.extend(bytes);
    Ok(super::record::digest(&domain))
}

fn snapshot_has_enabled_group(
    snapshot: &super::token::TokenAttestationSnapshot,
    sid: &str,
) -> bool {
    snapshot.behavior.groups.iter().any(|entry| {
        entry
            .split_once('@')
            .is_some_and(|(observed_sid, attributes)| {
                observed_sid == sid
                    && u32::from_str_radix(attributes, 16)
                        .is_ok_and(|attributes| attributes & 0x0000_0004 != 0)
            })
    })
}

fn bounded_broker_detail(mut detail: String) -> String {
    const LIMIT: usize = 1_024;
    if detail.len() > LIMIT {
        let mut boundary = LIMIT;
        while !detail.is_char_boundary(boundary) {
            boundary -= 1;
        }
        detail.truncate(boundary);
    }
    detail
}

pub(crate) fn validate_broker_service_arguments(arguments: &[String]) -> Result<&str, String> {
    let [service_name, schema, start_nonce] = arguments else {
        return Err("session broker received an unexpected service argument count".to_owned());
    };
    if service_name != WINDOWS_SESSION_BROKER_SERVICE_NAME
        || schema != &SESSION_BROKER_SCHEMA_VERSION.to_string()
    {
        return Err("session broker service identity or schema argument differs".to_owned());
    }
    Ok(start_nonce)
}

pub(crate) fn validate_broker_start_nonce(start_nonce: &str) -> Result<(), String> {
    super::record::validate_attempt_id(start_nonce)
}

unsafe fn decode_service_arguments(
    count: u32,
    arguments: *mut *mut u16,
) -> Result<Vec<String>, String> {
    if arguments.is_null() {
        return Err("session broker service argument vector is null".to_owned());
    }
    let mut decoded = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let value = unsafe { *arguments.add(index) };
        if value.is_null() {
            return Err("session broker service argument is null".to_owned());
        }
        let mut length = 0_usize;
        while unsafe { *value.add(length) } != 0 {
            length = length
                .checked_add(1)
                .ok_or_else(|| "session broker service argument overflowed".to_owned())?;
        }
        decoded.push(
            String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
                .map_err(|_| "session broker service argument is not Unicode".to_owned())?,
        );
    }
    Ok(decoded)
}
