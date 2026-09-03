use std::io;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde::Serialize;
use serde::de::DeserializeOwned;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
    ERROR_NO_DATA, ERROR_NOT_FOUND, ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_NONE, FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetExitCodeProcess, WaitForMultipleObjects, WaitForSingleObject,
};

use memcordon_core::{WINDOWS_MAX_FRAME_BYTES, WindowsSealedFault};

use super::security::{NamedPipeSecurityError, NamedPipeSecurityMismatch, SecurityDescriptor};

const PIPE_CLIENT_READ_WRITE: u32 = 0x0012_019b;

pub const TARGET_DESKTOP_BOOTSTRAP_PIPE_PREFIX: &str =
    r"\\.\pipe\memcordon-target-desktop-bootstrap-v2-";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetDesktopBootstrapPipeOperation {
    Accept,
    LoaderReadyRead,
    LoaderReadyWrite,
    LoaderControlReleaseRead,
    LoaderControlReleaseWrite,
    AdmissionRead,
    AdmissionWrite,
    StartedRead,
    StartedWrite,
    CreationReadyRead,
    CreationReadyWrite,
    CreationArmedRead,
    CreationArmedWrite,
    CreationConsumedRead,
    CreationConsumedWrite,
    CreationClearedRead,
    CreationClearedWrite,
    TerminalRead,
    ReadyWrite,
    AssociationPreflightRead,
    AssociationPreflightWrite,
    AssociationPreflightProgressWrite,
    AssociationPreflightReadyRead,
    AssociationPreflightReadyWrite,
    FailureWrite,
    LifetimeRead,
    BrokerHelloRead,
    BrokerHelloWrite,
    BrokerRequestRead,
    BrokerRequestWrite,
    BrokerLaunchedRead,
    BrokerLaunchedWrite,
    BrokerAckRead,
    BrokerAckWrite,
    BrokerArmRead,
    BrokerArmWrite,
    BrokerArmedRead,
    BrokerArmedWrite,
    BrokerConsumedRead,
    BrokerConsumedWrite,
    BrokerClearedRead,
    BrokerClearedWrite,
    BrokerFinalAckRead,
    BrokerFinalAckWrite,
    BrokerDoneRead,
    BrokerDoneWrite,
    BrokerLoaderSnapsRequestRead,
    BrokerLoaderSnapsRequestWrite,
    BrokerLoaderSnapsArmedRead,
    BrokerLoaderSnapsArmedWrite,
    BrokerLoaderSnapsRestoreRead,
    BrokerLoaderSnapsRestoreWrite,
    BrokerLoaderSnapsRestoredRead,
    BrokerLoaderSnapsRestoredWrite,
    BrokerTraceSessionCapabilityRequestRead,
    BrokerTraceSessionCapabilityRequestWrite,
    BrokerTraceSessionCapabilityReceiptRead,
    BrokerTraceSessionCapabilityReceiptWrite,
    BrokerPassiveTraceArmRead,
    BrokerPassiveTraceArmWrite,
    BrokerPassiveTraceReadyRead,
    BrokerPassiveTraceReadyWrite,
    BrokerPassiveTraceSubjectArmRead,
    BrokerPassiveTraceSubjectArmWrite,
    BrokerPassiveTraceSubjectReadyRead,
    BrokerPassiveTraceSubjectReadyWrite,
    BrokerPassiveTraceSubjectFinishRead,
    BrokerPassiveTraceSubjectFinishWrite,
    BrokerPassiveTraceSubjectFinishedRead,
    BrokerPassiveTraceSubjectFinishedWrite,
    BrokerPassiveTraceFinishRead,
    BrokerPassiveTraceFinishWrite,
    BrokerPassiveTraceFinalRead,
    BrokerPassiveTraceFinalWrite,
}

impl TargetDesktopBootstrapPipeOperation {
    const fn name(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::LoaderReadyRead => "loader-ready-read",
            Self::LoaderReadyWrite => "loader-ready-write",
            Self::LoaderControlReleaseRead => "loader-control-release-read",
            Self::LoaderControlReleaseWrite => "loader-control-release-write",
            Self::AdmissionRead => "admission-read",
            Self::AdmissionWrite => "admission-write",
            Self::StartedRead => "started-read",
            Self::StartedWrite => "started-write",
            Self::CreationReadyRead => "creation-ready-read",
            Self::CreationReadyWrite => "creation-ready-write",
            Self::CreationArmedRead => "creation-armed-read",
            Self::CreationArmedWrite => "creation-armed-write",
            Self::CreationConsumedRead => "creation-consumed-read",
            Self::CreationConsumedWrite => "creation-consumed-write",
            Self::CreationClearedRead => "creation-cleared-read",
            Self::CreationClearedWrite => "creation-cleared-write",
            Self::TerminalRead => "terminal-read",
            Self::ReadyWrite => "ready-write",
            Self::AssociationPreflightRead => "association-preflight-read",
            Self::AssociationPreflightWrite => "association-preflight-write",
            Self::AssociationPreflightProgressWrite => "association-preflight-progress-write",
            Self::AssociationPreflightReadyRead => "association-preflight-ready-read",
            Self::AssociationPreflightReadyWrite => "association-preflight-ready-write",
            Self::FailureWrite => "failure-write",
            Self::LifetimeRead => "lifetime-read",
            Self::BrokerHelloRead => "broker-hello-read",
            Self::BrokerHelloWrite => "broker-hello-write",
            Self::BrokerRequestRead => "broker-request-read",
            Self::BrokerRequestWrite => "broker-request-write",
            Self::BrokerLaunchedRead => "broker-launched-read",
            Self::BrokerLaunchedWrite => "broker-launched-write",
            Self::BrokerAckRead => "broker-ack-read",
            Self::BrokerAckWrite => "broker-ack-write",
            Self::BrokerArmRead => "broker-arm-read",
            Self::BrokerArmWrite => "broker-arm-write",
            Self::BrokerArmedRead => "broker-armed-read",
            Self::BrokerArmedWrite => "broker-armed-write",
            Self::BrokerConsumedRead => "broker-consumed-read",
            Self::BrokerConsumedWrite => "broker-consumed-write",
            Self::BrokerClearedRead => "broker-cleared-read",
            Self::BrokerClearedWrite => "broker-cleared-write",
            Self::BrokerFinalAckRead => "broker-final-ack-read",
            Self::BrokerFinalAckWrite => "broker-final-ack-write",
            Self::BrokerDoneRead => "broker-done-read",
            Self::BrokerDoneWrite => "broker-done-write",
            Self::BrokerLoaderSnapsRequestRead => "broker-loader-snaps-request-read",
            Self::BrokerLoaderSnapsRequestWrite => "broker-loader-snaps-request-write",
            Self::BrokerLoaderSnapsArmedRead => "broker-loader-snaps-armed-read",
            Self::BrokerLoaderSnapsArmedWrite => "broker-loader-snaps-armed-write",
            Self::BrokerLoaderSnapsRestoreRead => "broker-loader-snaps-restore-read",
            Self::BrokerLoaderSnapsRestoreWrite => "broker-loader-snaps-restore-write",
            Self::BrokerLoaderSnapsRestoredRead => "broker-loader-snaps-restored-read",
            Self::BrokerLoaderSnapsRestoredWrite => "broker-loader-snaps-restored-write",
            Self::BrokerTraceSessionCapabilityRequestRead => {
                "broker-trace-session-capability-request-read"
            }
            Self::BrokerTraceSessionCapabilityRequestWrite => {
                "broker-trace-session-capability-request-write"
            }
            Self::BrokerTraceSessionCapabilityReceiptRead => {
                "broker-trace-session-capability-receipt-read"
            }
            Self::BrokerTraceSessionCapabilityReceiptWrite => {
                "broker-trace-session-capability-receipt-write"
            }
            Self::BrokerPassiveTraceArmRead => "broker-passive-trace-arm-read",
            Self::BrokerPassiveTraceArmWrite => "broker-passive-trace-arm-write",
            Self::BrokerPassiveTraceReadyRead => "broker-passive-trace-ready-read",
            Self::BrokerPassiveTraceReadyWrite => "broker-passive-trace-ready-write",
            Self::BrokerPassiveTraceSubjectArmRead => "broker-passive-trace-subject-arm-read",
            Self::BrokerPassiveTraceSubjectArmWrite => "broker-passive-trace-subject-arm-write",
            Self::BrokerPassiveTraceSubjectReadyRead => "broker-passive-trace-subject-ready-read",
            Self::BrokerPassiveTraceSubjectReadyWrite => "broker-passive-trace-subject-ready-write",
            Self::BrokerPassiveTraceSubjectFinishRead => "broker-passive-trace-subject-finish-read",
            Self::BrokerPassiveTraceSubjectFinishWrite => {
                "broker-passive-trace-subject-finish-write"
            }
            Self::BrokerPassiveTraceSubjectFinishedRead => {
                "broker-passive-trace-subject-finished-read"
            }
            Self::BrokerPassiveTraceSubjectFinishedWrite => {
                "broker-passive-trace-subject-finished-write"
            }
            Self::BrokerPassiveTraceFinishRead => "broker-passive-trace-finish-read",
            Self::BrokerPassiveTraceFinishWrite => "broker-passive-trace-finish-write",
            Self::BrokerPassiveTraceFinalRead => "broker-passive-trace-final-read",
            Self::BrokerPassiveTraceFinalWrite => "broker-passive-trace-final-write",
        }
    }
}

#[derive(Debug)]
pub struct TargetDesktopBootstrapPipeError {
    detail: String,
    native_code: Option<i32>,
    bytes_transferred: usize,
}

impl TargetDesktopBootstrapPipeError {
    pub(crate) fn protocol(
        operation: TargetDesktopBootstrapPipeOperation,
        detail: impl ToString,
    ) -> Self {
        Self {
            detail: format!(
                "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment=protocol native_code=none detail={}",
                operation.name(),
                detail.to_string()
            ),
            native_code: None,
            bytes_transferred: 0,
        }
    }

    fn native(
        operation: TargetDesktopBootstrapPipeOperation,
        segment: &'static str,
        error: &io::Error,
    ) -> Self {
        Self {
            detail: format!(
                "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment={segment} native_code={} detail={error}",
                operation.name(),
                error
                    .raw_os_error()
                    .map_or_else(|| "unavailable".to_owned(), |code| code.to_string())
            ),
            native_code: error.raw_os_error(),
            bytes_transferred: 0,
        }
    }

    fn with_bytes_transferred(mut self, bytes_transferred: usize) -> Self {
        self.bytes_transferred = bytes_transferred;
        self
    }

    pub const fn native_code(&self) -> Option<i32> {
        self.native_code
    }

    pub const fn bytes_transferred(&self) -> usize {
        self.bytes_transferred
    }
}

impl std::fmt::Display for TargetDesktopBootstrapPipeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.detail)
    }
}

pub(crate) fn target_desktop_bootstrap_peer_exit_error(
    operation: TargetDesktopBootstrapPipeOperation,
    segment: &'static str,
    requested: u32,
    exit_code: u32,
) -> TargetDesktopBootstrapPipeError {
    TargetDesktopBootstrapPipeError {
        detail: format!(
            "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment={segment} requested={requested} native_code={} child_exit_code_decimal={exit_code} child_exit_code_hex=0x{exit_code:08X} detail=target desktop bootstrap peer exited during pipe operation",
            operation.name(),
            exit_code as i32,
        ),
        native_code: Some(exit_code as i32),
        bytes_transferred: 0,
    }
}

#[cfg(test)]
pub(crate) fn target_desktop_bootstrap_peer_exit_error_for_test(
    operation: TargetDesktopBootstrapPipeOperation,
    segment: &'static str,
    requested: u32,
    exit_code: u32,
) -> (String, Option<i32>) {
    let error = target_desktop_bootstrap_peer_exit_error(operation, segment, requested, exit_code);
    (error.to_string(), error.native_code())
}

#[derive(Debug)]
pub enum PipePreparationError {
    Certification(String),
    Creation(String),
    SecurityReadback(String),
    SecurityMismatch(NamedPipeSecurityMismatch),
}

impl std::fmt::Display for PipePreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certification(error) => formatter.write_str(error),
            Self::Creation(error) => write!(formatter, "MCSEALED-WINDOWS-PIPE-CREATE: {error}"),
            Self::SecurityReadback(error) => {
                write!(
                    formatter,
                    "MCSEALED-WINDOWS-PIPE-SECURITY-READBACK: {error}"
                )
            }
            Self::SecurityMismatch(error) => {
                write!(
                    formatter,
                    "MCSEALED-WINDOWS-PIPE-SECURITY-MISMATCH: {error}"
                )
            }
        }
    }
}

#[derive(Debug)]
pub struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    pub fn new(handle: HANDLE) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }

    pub const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: this type owns one valid kernel handle and closes it once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

pub fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn connect(name: &str) -> Result<OwnedHandle, String> {
    connect_with_fault(name, None)
}

pub fn connect_target_desktop_bootstrap_pipe(
    name: &str,
    deadline: std::time::Instant,
) -> Result<OwnedHandle, String> {
    connect_role_pipe(name, deadline, PipeConnectRole::TargetDesktopBootstrap)
}

pub fn connect_session_broker_pipe(
    name: &str,
    deadline: std::time::Instant,
) -> Result<OwnedHandle, String> {
    connect_role_pipe(name, deadline, PipeConnectRole::SessionBroker)
}

#[derive(Clone, Copy)]
enum PipeConnectRole {
    TargetDesktopBootstrap,
    SessionBroker,
}

impl PipeConnectRole {
    const fn label(self) -> &'static str {
        match self {
            Self::TargetDesktopBootstrap => "target-desktop-bootstrap",
            Self::SessionBroker => "session-broker",
        }
    }
}

fn connect_role_pipe(
    name: &str,
    deadline: std::time::Instant,
    role: PipeConnectRole,
) -> Result<OwnedHandle, String> {
    let name = wide_null(name);
    loop {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                PIPE_CLIENT_READ_WRITE,
                FILE_SHARE_NONE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return OwnedHandle::new(handle);
        }
        let error = io::Error::last_os_error();
        let code = error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok());
        if !matches!(code, Some(ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND)) {
            return Err(format!(
                "role={} operation=connect native_error={error}",
                role.label(),
            ));
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "role={} operation=connect timed_out=true",
                role.label(),
            ));
        }
        let wait = deadline.saturating_duration_since(now).as_millis().min(100) as u32;
        unsafe { WaitNamedPipeW(name.as_ptr(), wait.max(1)) };
    }
}

pub fn connect_with_fault(
    name: &str,
    certification_fault: Option<WindowsSealedFault>,
) -> Result<OwnedHandle, String> {
    let endpoint = name;
    let name = wide_null(endpoint);
    for _ in 0..100 {
        if certification_fault == Some(WindowsSealedFault::PrivatePipeConnect) {
            return Err(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected PrivatePipeConnect".to_owned(),
            );
        }
        // SAFETY: every pointer references a live, NUL-terminated UTF-16 buffer;
        // the returned handle is transferred into OwnedHandle.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                PIPE_CLIENT_READ_WRITE,
                FILE_SHARE_NONE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return OwnedHandle::new(handle);
        }
        let error = io::Error::last_os_error();
        let code = error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok());
        if !matches!(code, Some(ERROR_PIPE_BUSY | ERROR_FILE_NOT_FOUND)) {
            let native_code = error
                .raw_os_error()
                .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
            return Err(format!(
                "MCSEALED-WINDOWS-PIPE-CONNECT: api=CreateFileW endpoint={endpoint} native_code={native_code} detail={error}",
            ));
        }
        if code == Some(ERROR_FILE_NOT_FOUND) {
            std::thread::sleep(Duration::from_millis(10));
        } else {
            // SAFETY: name remains NUL-terminated for the call.
            unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
        }
    }
    Err("timed out waiting for the sealed provider pipe".to_owned())
}

pub fn endpoint_exists(name: &str) -> Result<bool, String> {
    let name = wide_null(name);
    // SAFETY: name is a live NUL-terminated pipe path; a successful handle is
    // immediately adopted and closed.
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            PIPE_CLIENT_READ_WRITE,
            FILE_SHARE_NONE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle != INVALID_HANDLE_VALUE {
        drop(OwnedHandle::new(handle)?);
        return Ok(true);
    }
    let error = io::Error::last_os_error();
    let code = error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok());
    if code == Some(ERROR_FILE_NOT_FOUND) {
        Ok(false)
    } else if code == Some(ERROR_PIPE_BUSY) {
        Ok(true)
    } else {
        Err(error.to_string())
    }
}

pub struct PipeListener {
    name: Vec<u16>,
    security: SecurityDescriptor,
    first_instance: AtomicBool,
}

impl PipeListener {
    pub fn new(name: &str, security: SecurityDescriptor) -> Self {
        Self {
            name: wide_null(name),
            security,
            first_instance: AtomicBool::new(true),
        }
    }

    pub fn accept(&self) -> Result<OwnedHandle, String> {
        self.accept_prepared(self.prepare().map_err(|error| error.to_string())?)
    }

    pub fn prepare(&self) -> Result<OwnedHandle, PipePreparationError> {
        self.prepare_with_fault(None)
    }

    pub fn prepare_with_fault(
        &self,
        certification_fault: Option<WindowsSealedFault>,
    ) -> Result<OwnedHandle, PipePreparationError> {
        let attributes = self.security.attributes(false);
        // SAFETY: name and security descriptor remain live for creation; the
        // pipe handle is transferred into OwnedHandle.
        let first_instance = self.first_instance.swap(false, Ordering::AcqRel);
        let open_mode = PIPE_ACCESS_DUPLEX
            | if first_instance {
                FILE_FLAG_FIRST_PIPE_INSTANCE
            } else {
                0
            };
        if certification_fault == Some(WindowsSealedFault::PublicPipeCreate) {
            return Err(PipePreparationError::Certification(
                "MCSEALED-WINDOWS-CERTIFICATION-FAULT: injected PublicPipeCreate".to_owned(),
            ));
        }
        let pipe = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                16,
                64 * 1024,
                64 * 1024,
                0,
                &raw const attributes,
            )
        };
        let pipe = OwnedHandle::new(pipe).map_err(PipePreparationError::Creation)?;
        self.security
            .verify_named_pipe(pipe.raw())
            .map_err(|error| match error {
                NamedPipeSecurityError::Readback(error) => {
                    PipePreparationError::SecurityReadback(error)
                }
                NamedPipeSecurityError::Mismatch(error) => {
                    PipePreparationError::SecurityMismatch(error)
                }
            })?;
        Ok(pipe)
    }

    pub fn accept_prepared(&self, pipe: OwnedHandle) -> Result<OwnedHandle, String> {
        // SAFETY: pipe is a fresh listening named-pipe instance and no
        // OVERLAPPED pointer is required for synchronous operation.
        if unsafe { ConnectNamedPipe(pipe.raw(), ptr::null_mut()) } == 0 {
            let error = io::Error::last_os_error();
            if error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok())
                != Some(ERROR_PIPE_CONNECTED)
            {
                return Err(error.to_string());
            }
        }
        Ok(pipe)
    }
}

pub fn prepare_target_desktop_bootstrap_pipe(
    name: &str,
    security: &SecurityDescriptor,
) -> Result<OwnedHandle, String> {
    let name = wide_null(name);
    let attributes = security.attributes(false);
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            64 * 1024,
            64 * 1024,
            0,
            &raw const attributes,
        )
    };
    let pipe = OwnedHandle::new(pipe)?;
    security
        .verify_named_pipe(pipe.raw())
        .map_err(|error| error.to_string())?;
    Ok(pipe)
}

fn cancel_and_drain(handle: HANDLE, overlapped: &mut OVERLAPPED) {
    unsafe {
        CancelIoEx(handle, overlapped);
        let mut transferred = 0_u32;
        GetOverlappedResult(handle, overlapped, &raw mut transferred, 1);
    }
}

fn wait_overlapped(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    overlapped: &mut OVERLAPPED,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
    segment: &'static str,
    requested: u32,
) -> Result<u32, TargetDesktopBootstrapPipeError> {
    let handles = [overlapped.hEvent, peer_process.unwrap_or(ptr::null_mut())];
    let handle_count = if peer_process.is_some() { 2 } else { 1 };
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            cancel_and_drain(handle, overlapped);
            return Err(TargetDesktopBootstrapPipeError::protocol(
                operation,
                format!(
                    "segment={segment} requested={requested} target desktop bootstrap pipe operation timed out"
                ),
            ));
        }
        let remaining = deadline.saturating_duration_since(now).as_millis();
        let timeout = u32::try_from(remaining).unwrap_or(u32::MAX).max(1);
        let wait = unsafe { WaitForMultipleObjects(handle_count, handles.as_ptr(), 0, timeout) };
        if wait == WAIT_OBJECT_0 {
            let mut transferred = 0_u32;
            if unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) } == 0 {
                let error = io::Error::last_os_error();
                return Err(TargetDesktopBootstrapPipeError::native(
                    operation, segment, &error,
                ));
            }
            return Ok(transferred);
        }
        if handle_count == 2 && wait == WAIT_OBJECT_0 + 1 {
            let peer_process = peer_process.expect("peer handle count proves peer presence");
            let mut transferred = 0_u32;
            // A final frame and process exit may race. Consume an already
            // completed operation before diagnosing peer termination.
            if unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) } != 0 {
                return Ok(transferred);
            }
            let completion_error = io::Error::last_os_error();
            if completion_error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32)
                && unsafe { WaitForSingleObject(overlapped.hEvent, 50) } == WAIT_OBJECT_0
                && unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) } != 0
            {
                return Ok(transferred);
            }
            cancel_and_drain(handle, overlapped);
            let mut exit_code = 0_u32;
            if unsafe { GetExitCodeProcess(peer_process, &raw mut exit_code) } == 0 {
                let error = io::Error::last_os_error();
                return Err(TargetDesktopBootstrapPipeError::native(
                    operation,
                    "peer-exit-query",
                    &error,
                ));
            }
            return Err(target_desktop_bootstrap_peer_exit_error(
                operation, segment, requested, exit_code,
            ));
        }
        if wait == WAIT_TIMEOUT {
            continue;
        }
        if wait == WAIT_FAILED {
            cancel_and_drain(handle, overlapped);
            let error = io::Error::last_os_error();
            return Err(TargetDesktopBootstrapPipeError::native(
                operation, segment, &error,
            ));
        }
        cancel_and_drain(handle, overlapped);
        return Err(TargetDesktopBootstrapPipeError::protocol(
            operation,
            format!("segment={segment} unexpected pipe wait result={wait}"),
        ));
    }
}

fn overlapped_event() -> Result<(OwnedHandle, OVERLAPPED), String> {
    let event = OwnedHandle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })?;
    let mut overlapped = OVERLAPPED::default();
    overlapped.hEvent = event.raw();
    Ok((event, overlapped))
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingAcceptState {
    Pending,
    Ready,
    Drained,
}

pub(crate) struct PendingTargetDesktopBootstrapAccept {
    pipe: Option<OwnedHandle>,
    _event: OwnedHandle,
    // ConnectNamedPipe retains this address until completion/cancellation, so
    // the OVERLAPPED storage must remain heap-stable when this owner moves.
    overlapped: Box<OVERLAPPED>,
    state: PendingAcceptState,
}

impl PendingTargetDesktopBootstrapAccept {
    pub(crate) fn start(pipe: OwnedHandle) -> Result<Self, TargetDesktopBootstrapPipeError> {
        let (event, mut overlapped) = overlapped_event().map_err(|detail| {
            TargetDesktopBootstrapPipeError::protocol(
                TargetDesktopBootstrapPipeOperation::Accept,
                detail,
            )
        })?;
        overlapped.hEvent = event.raw();
        let mut owner = Self {
            pipe: Some(pipe),
            _event: event,
            overlapped: Box::new(overlapped),
            state: PendingAcceptState::Pending,
        };
        let pipe = owner
            .pipe
            .as_ref()
            .expect("pending accept owns its pipe")
            .raw();
        if unsafe { ConnectNamedPipe(pipe, &raw mut *owner.overlapped) } != 0 {
            owner.state = PendingAcceptState::Ready;
            return Ok(owner);
        }
        let error = io::Error::last_os_error();
        match error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
        {
            Some(ERROR_IO_PENDING) => Ok(owner),
            Some(ERROR_PIPE_CONNECTED) => {
                owner.state = PendingAcceptState::Ready;
                Ok(owner)
            }
            _ => Err(TargetDesktopBootstrapPipeError::native(
                TargetDesktopBootstrapPipeOperation::Accept,
                "connect",
                &error,
            )),
        }
    }

    pub(crate) fn poll(&mut self) -> Result<bool, TargetDesktopBootstrapPipeError> {
        match self.state {
            PendingAcceptState::Ready => return Ok(true),
            PendingAcceptState::Drained => {
                return Err(TargetDesktopBootstrapPipeError::protocol(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "polled a drained pending accept",
                ));
            }
            PendingAcceptState::Pending => {}
        }
        let wait = unsafe { WaitForSingleObject(self.overlapped.hEvent, 0) };
        if wait == WAIT_TIMEOUT {
            return Ok(false);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(TargetDesktopBootstrapPipeError::native(
                TargetDesktopBootstrapPipeOperation::Accept,
                "connect-poll",
                &io::Error::last_os_error(),
            ));
        }
        let mut transferred = 0_u32;
        let pipe = self
            .pipe
            .as_ref()
            .expect("pending accept owns its pipe")
            .raw();
        if unsafe { GetOverlappedResult(pipe, &raw mut *self.overlapped, &raw mut transferred, 0) }
            == 0
        {
            return Err(TargetDesktopBootstrapPipeError::native(
                TargetDesktopBootstrapPipeOperation::Accept,
                "connect-completion",
                &io::Error::last_os_error(),
            ));
        }
        self.state = PendingAcceptState::Ready;
        Ok(true)
    }

    pub(crate) fn finish(mut self) -> Result<OwnedHandle, TargetDesktopBootstrapPipeError> {
        if !self.poll()? {
            return Err(TargetDesktopBootstrapPipeError::protocol(
                TargetDesktopBootstrapPipeOperation::Accept,
                "pending accept was finished before completion",
            ));
        }
        self.state = PendingAcceptState::Drained;
        self.pipe.take().ok_or_else(|| {
            TargetDesktopBootstrapPipeError::protocol(
                TargetDesktopBootstrapPipeOperation::Accept,
                "completed accept lost its pipe owner",
            )
        })
    }

    pub(crate) fn cancel_and_drain(&mut self) -> Result<(), TargetDesktopBootstrapPipeError> {
        if self.state != PendingAcceptState::Pending {
            self.state = PendingAcceptState::Drained;
            return Ok(());
        }
        let pipe = self
            .pipe
            .as_ref()
            .expect("pending accept owns its pipe")
            .raw();
        if unsafe { CancelIoEx(pipe, &raw const *self.overlapped) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "connect-cancel",
                    &error,
                ));
            }
        }
        let mut transferred = 0_u32;
        if unsafe { GetOverlappedResult(pipe, &raw mut *self.overlapped, &raw mut transferred, 1) }
            == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_OPERATION_ABORTED as i32) {
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "connect-drain",
                    &error,
                ));
            }
        }
        self.state = PendingAcceptState::Drained;
        Ok(())
    }
}

impl Drop for PendingTargetDesktopBootstrapAccept {
    fn drop(&mut self) {
        if self.state == PendingAcceptState::Pending {
            let pipe = self
                .pipe
                .as_ref()
                .expect("pending accept owns its pipe")
                .raw();
            cancel_and_drain(pipe, &mut self.overlapped);
            self.state = PendingAcceptState::Drained;
        }
    }
}

pub fn accept_target_desktop_bootstrap_pipe(
    pipe: OwnedHandle,
    peer_process: HANDLE,
    deadline: std::time::Instant,
) -> Result<OwnedHandle, TargetDesktopBootstrapPipeError> {
    let (_event, mut overlapped) = overlapped_event().map_err(|detail| {
        TargetDesktopBootstrapPipeError::protocol(
            TargetDesktopBootstrapPipeOperation::Accept,
            detail,
        )
    })?;
    if unsafe { ConnectNamedPipe(pipe.raw(), &raw mut overlapped) } == 0 {
        let code = io::Error::last_os_error().raw_os_error();
        match code.and_then(|value| u32::try_from(value).ok()) {
            Some(ERROR_IO_PENDING) => {
                wait_overlapped(
                    pipe.raw(),
                    Some(peer_process),
                    &mut overlapped,
                    deadline,
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "connect",
                    0,
                )?;
            }
            Some(ERROR_PIPE_CONNECTED) => {}
            _ => {
                let error = io::Error::last_os_error();
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "connect",
                    &error,
                ));
            }
        }
    }
    Ok(pipe)
}

fn overlapped_transfer(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    buffer: *mut u8,
    length: u32,
    write: bool,
    operation: TargetDesktopBootstrapPipeOperation,
    segment: &'static str,
) -> Result<u32, TargetDesktopBootstrapPipeError> {
    let (_event, mut overlapped) = overlapped_event()
        .map_err(|detail| TargetDesktopBootstrapPipeError::protocol(operation, detail))?;
    let mut immediate = 0_u32;
    let ok = unsafe {
        if write {
            WriteFile(
                handle,
                buffer.cast(),
                length,
                &raw mut immediate,
                &raw mut overlapped,
            )
        } else {
            ReadFile(
                handle,
                buffer.cast(),
                length,
                &raw mut immediate,
                &raw mut overlapped,
            )
        }
    };
    if ok != 0 {
        return Ok(immediate);
    }
    let error = io::Error::last_os_error();
    if error
        .raw_os_error()
        .and_then(|value| u32::try_from(value).ok())
        == Some(ERROR_IO_PENDING)
    {
        wait_overlapped(
            handle,
            peer_process,
            &mut overlapped,
            deadline,
            operation,
            segment,
            length,
        )
    } else {
        Err(TargetDesktopBootstrapPipeError::native(
            operation, segment, &error,
        ))
    }
}

pub fn write_frame_bounded<T: Serialize>(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
    value: &T,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| TargetDesktopBootstrapPipeError::protocol(operation, error))?;
    if payload.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err(TargetDesktopBootstrapPipeError::protocol(
            operation,
            "Windows provider frame exceeds the protocol bound",
        ));
    }
    let mut bytes = Vec::with_capacity(4 + payload.len());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&payload);
    let mut offset = 0;
    while offset < bytes.len() {
        let transferred = match overlapped_transfer(
            handle,
            peer_process,
            deadline,
            bytes[offset..].as_mut_ptr(),
            u32::try_from(bytes.len() - offset).map_err(|_| {
                TargetDesktopBootstrapPipeError::protocol(operation, "frame is not representable")
            })?,
            true,
            operation,
            "frame",
        ) {
            Ok(transferred) => transferred as usize,
            Err(error) => return Err(error.with_bytes_transferred(offset)),
        };
        if transferred == 0 {
            return Err(TargetDesktopBootstrapPipeError::protocol(
                operation,
                "target desktop bootstrap pipe write made no progress",
            )
            .with_bytes_transferred(offset));
        }
        offset += transferred;
    }
    Ok(())
}

fn read_exact_bounded(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    buffer: &mut [u8],
    operation: TargetDesktopBootstrapPipeOperation,
    segment: &'static str,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    let mut offset = 0;
    while offset < buffer.len() {
        let transferred = overlapped_transfer(
            handle,
            peer_process,
            deadline,
            buffer[offset..].as_mut_ptr(),
            u32::try_from(buffer.len() - offset).map_err(|_| {
                TargetDesktopBootstrapPipeError::protocol(operation, "frame is not representable")
            })?,
            false,
            operation,
            segment,
        )? as usize;
        if transferred == 0 {
            return Err(TargetDesktopBootstrapPipeError::protocol(
                operation,
                format!("segment={segment} target desktop bootstrap pipe closed during frame"),
            ));
        }
        offset += transferred;
    }
    Ok(())
}

pub fn read_frame_bounded<T: DeserializeOwned>(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
) -> Result<T, TargetDesktopBootstrapPipeError> {
    let mut length = [0_u8; 4];
    read_exact_bounded(
        handle,
        peer_process,
        deadline,
        &mut length,
        operation,
        "length",
    )?;
    let length = u32::from_le_bytes(length) as usize;
    if length > WINDOWS_MAX_FRAME_BYTES {
        return Err(TargetDesktopBootstrapPipeError::protocol(
            operation,
            "Windows provider frame exceeds the protocol bound",
        ));
    }
    let mut payload = vec![0_u8; length];
    read_exact_bounded(
        handle,
        peer_process,
        deadline,
        &mut payload,
        operation,
        "payload",
    )?;
    serde_json::from_slice(&payload)
        .map_err(|error| TargetDesktopBootstrapPipeError::protocol(operation, error))
}

pub fn target_desktop_bootstrap_pipe_is_quiet(handle: HANDLE) -> Result<bool, String> {
    let mut available = 0_u32;
    if unsafe {
        PeekNamedPipe(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &raw mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(available == 0)
}

pub fn wait_for_target_desktop_bootstrap_release(
    handle: HANDLE,
    launcher_process: HANDLE,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    let mut payload = [0_u8; 1];
    loop {
        match overlapped_transfer(
            handle,
            Some(launcher_process),
            std::time::Instant::now() + Duration::from_secs(30),
            payload.as_mut_ptr(),
            1,
            false,
            TargetDesktopBootstrapPipeOperation::LifetimeRead,
            "lifetime-byte",
        ) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(TargetDesktopBootstrapPipeError::protocol(
                    TargetDesktopBootstrapPipeOperation::LifetimeRead,
                    "target desktop bootstrap lifetime channel accepted unexpected data",
                ));
            }
            Err(error)
                if error.to_string().contains("timed out")
                    && unsafe {
                        windows_sys::Win32::System::Threading::WaitForSingleObject(
                            launcher_process,
                            0,
                        )
                    } == WAIT_TIMEOUT => {}
            Err(error) => {
                let code = error
                    .native_code()
                    .and_then(|value| u32::try_from(value).ok());
                if matches!(
                    code,
                    Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                ) {
                    return Ok(());
                }
                return Err(error);
            }
        }
    }
}

pub fn disconnect(handle: HANDLE) {
    // SAFETY: caller provides a connected named-pipe server handle; failure is
    // harmless during terminal cleanup.
    unsafe { DisconnectNamedPipe(handle) };
}

/// Completes a normal server response before releasing its named-pipe instance.
///
/// `DisconnectNamedPipe` discards unread bytes, so successful response writers
/// must use this helper rather than disconnecting directly. Certification paths
/// that deliberately model abrupt authority loss continue to call `disconnect`.
pub fn finish_server_response(handle: HANDLE) -> Result<(), String> {
    // SAFETY: caller provides a connected synchronous named-pipe server handle.
    // FlushFileBuffers blocks until the client consumes every buffered byte.
    let result = if unsafe { FlushFileBuffers(handle) } == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    };
    disconnect(handle);
    result
}

pub fn write_frame<T: Serialize>(handle: HANDLE, value: &T) -> Result<(), String> {
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if payload.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err("Windows provider frame exceeds the protocol bound".to_owned());
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| "Windows provider frame length is not representable".to_owned())?;
    write_all(handle, &length.to_le_bytes())?;
    write_all(handle, &payload)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameReadPhase {
    Length,
    Payload,
    Decode,
}

impl FrameReadPhase {
    const fn diagnostic(self) -> &'static str {
        match self {
            Self::Length => "length-read",
            Self::Payload => "payload-read",
            Self::Decode => "decode",
        }
    }
}

#[derive(Debug)]
pub struct FrameReadError {
    pub phase: FrameReadPhase,
    pub expected_bytes: usize,
    pub transferred_bytes: usize,
    pub native_code: Option<u32>,
    pub peer_closed: bool,
    detail: String,
}

impl std::fmt::Display for FrameReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-PIPE-READ: phase={} peer_closed={} expected_bytes={} transferred_bytes={} native_code={:?} detail={}",
            self.phase.diagnostic(),
            self.peer_closed,
            self.expected_bytes,
            self.transferred_bytes,
            self.native_code,
            self.detail,
        )
    }
}

pub fn read_frame<T: DeserializeOwned>(handle: HANDLE) -> Result<T, String> {
    read_frame_detailed(handle).map_err(|error| error.to_string())
}

pub fn read_frame_detailed<T: DeserializeOwned>(handle: HANDLE) -> Result<T, FrameReadError> {
    let mut length = [0_u8; 4];
    read_exact_detailed(handle, &mut length, FrameReadPhase::Length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > WINDOWS_MAX_FRAME_BYTES {
        return Err(FrameReadError {
            phase: FrameReadPhase::Length,
            expected_bytes: WINDOWS_MAX_FRAME_BYTES,
            transferred_bytes: length,
            native_code: None,
            peer_closed: false,
            detail: "Windows provider frame exceeds the protocol bound".to_owned(),
        });
    }
    let mut payload = vec![0_u8; length];
    read_exact_detailed(handle, &mut payload, FrameReadPhase::Payload)?;
    serde_json::from_slice(&payload).map_err(|error| FrameReadError {
        phase: FrameReadPhase::Decode,
        expected_bytes: length,
        transferred_bytes: length,
        native_code: None,
        peer_closed: false,
        detail: error.to_string(),
    })
}

#[derive(Debug)]
pub enum FrameAvailabilityError {
    PeerClosed,
    Native { code: Option<i32>, detail: String },
}

impl std::fmt::Display for FrameAvailabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerClosed => formatter.write_str("named-pipe peer disconnected"),
            Self::Native { detail, .. } => formatter.write_str(detail),
        }
    }
}

pub fn frame_available(handle: HANDLE) -> Result<bool, String> {
    frame_available_detailed(handle).map_err(|error| error.to_string())
}

pub fn frame_available_detailed(handle: HANDLE) -> Result<bool, FrameAvailabilityError> {
    let mut available = 0_u32;
    // SAFETY: available points to initialized storage and no data buffer is
    // requested. The named-pipe handle remains owned by the caller.
    if unsafe {
        PeekNamedPipe(
            handle,
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &raw mut available,
            ptr::null_mut(),
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            .is_some_and(|code| {
                matches!(
                    code,
                    ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
                )
            })
        {
            return Err(FrameAvailabilityError::PeerClosed);
        }
        return Err(FrameAvailabilityError::Native {
            code: error.raw_os_error(),
            detail: error.to_string(),
        });
    }
    // Any prefix is readable. Let the detailed frame reader distinguish a
    // complete length from a truncated length/payload if the peer closes.
    Ok(available != 0)
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let requested = u32::try_from(bytes.len().min(u32::MAX as usize))
            .expect("bounded write length is representable");
        let mut written = 0_u32;
        // SAFETY: bytes and written remain valid for the synchronous call; no
        // OVERLAPPED storage is used.
        if unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                requested,
                &raw mut written,
                ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            let native_code = error
                .raw_os_error()
                .map_or_else(|| "unavailable".to_owned(), |code| code.to_string());
            return Err(format!(
                "MCSEALED-WINDOWS-PIPE-WRITE: api=WriteFile native_code={native_code} detail={error}"
            ));
        }
        if written == 0 {
            return Err("zero-byte named-pipe write".to_owned());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_exact_detailed(
    handle: HANDLE,
    mut bytes: &mut [u8],
    phase: FrameReadPhase,
) -> Result<(), FrameReadError> {
    let expected_bytes = bytes.len();
    let mut transferred_bytes = 0_usize;
    while !bytes.is_empty() {
        let requested = u32::try_from(bytes.len().min(u32::MAX as usize))
            .expect("bounded read length is representable");
        let mut read = 0_u32;
        // SAFETY: bytes and read remain valid for the synchronous call; no
        // OVERLAPPED storage is used.
        if unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                requested,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            let native_code = error
                .raw_os_error()
                .and_then(|value| u32::try_from(value).ok());
            return Err(FrameReadError {
                phase,
                expected_bytes,
                transferred_bytes,
                native_code,
                peer_closed: matches!(
                    native_code,
                    Some(ERROR_BROKEN_PIPE) | Some(ERROR_NO_DATA) | Some(ERROR_PIPE_NOT_CONNECTED)
                ),
                detail: error.to_string(),
            });
        }
        if read == 0 {
            return Err(FrameReadError {
                phase,
                expected_bytes,
                transferred_bytes,
                native_code: None,
                peer_closed: true,
                detail: "unexpected end of Windows provider frame".to_owned(),
            });
        }
        transferred_bytes = transferred_bytes
            .checked_add(read as usize)
            .expect("bounded named-pipe read count cannot overflow");
        let (_, rest) = bytes.split_at_mut(read as usize);
        bytes = rest;
    }
    Ok(())
}

pub fn wait_poll_interval() {
    std::thread::sleep(Duration::from_millis(10));
}
