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

#[path = "pipe_connect_observation.rs"]
mod connect_observation;

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
        }
    }
}

#[derive(Debug)]
enum BootstrapPipeFailureSource {
    Protocol,
    Win32(Option<i32>),
    PeerExit(u32),
}

#[derive(Debug)]
pub struct TargetDesktopBootstrapPipeError {
    detail: String,
    source: BootstrapPipeFailureSource,
    bytes_transferred: usize,
}

impl TargetDesktopBootstrapPipeError {
    pub(crate) fn protocol(
        operation: TargetDesktopBootstrapPipeOperation,
        detail: impl ToString,
    ) -> Self {
        Self {
            detail: format!(
                "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment=protocol origin=protocol native_code=none detail={}",
                operation.name(),
                detail.to_string()
            ),
            source: BootstrapPipeFailureSource::Protocol,
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
                "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment={segment} origin=win32-api native_code={} detail={error}",
                operation.name(),
                error
                    .raw_os_error()
                    .map_or_else(|| "unavailable".to_owned(), |code| code.to_string())
            ),
            source: BootstrapPipeFailureSource::Win32(error.raw_os_error()),
            bytes_transferred: 0,
        }
    }

    fn with_bytes_transferred(mut self, bytes_transferred: usize) -> Self {
        self.bytes_transferred = bytes_transferred;
        self
    }

    pub const fn native_code(&self) -> Option<i32> {
        match self.source {
            BootstrapPipeFailureSource::Win32(code) => code,
            BootstrapPipeFailureSource::Protocol | BootstrapPipeFailureSource::PeerExit(_) => None,
        }
    }

    pub fn native_status(&self) -> Option<memcordon_windows_launch_core::NativeStatusV1> {
        use memcordon_windows_launch_core::NativeStatusV1;
        match self.source {
            BootstrapPipeFailureSource::Win32(Some(code)) => {
                Some(NativeStatusV1::Win32 { code: code as u32 })
            }
            BootstrapPipeFailureSource::PeerExit(code) => Some(NativeStatusV1::TargetExit { code }),
            BootstrapPipeFailureSource::Protocol | BootstrapPipeFailureSource::Win32(None) => None,
        }
    }

    fn is_lifetime_pipe_closure(&self) -> bool {
        matches!(self.source, BootstrapPipeFailureSource::Win32(Some(code))
            if matches!(code as u32, ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED))
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
            "MCSEALED-WINDOWS-BOOTSTRAP-PIPE: operation={} segment={segment} requested={requested} origin=held-peer-exit child_exit_code_decimal={exit_code} child_exit_code_hex=0x{exit_code:08X} detail=target desktop bootstrap peer exited during pipe operation",
            operation.name(),
        ),
        source: BootstrapPipeFailureSource::PeerExit(exit_code),
        bytes_transferred: 0,
    }
}

#[cfg(test)]
pub(crate) fn target_desktop_bootstrap_api_error_for_test(
    code: i32,
) -> TargetDesktopBootstrapPipeError {
    TargetDesktopBootstrapPipeError::native(
        TargetDesktopBootstrapPipeOperation::Accept,
        "connect",
        &io::Error::from_raw_os_error(code),
    )
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

    /// Explicitly closes an authority-bearing handle. A destructor remains
    /// the emergency fallback, but only this checked operation is positive
    /// evidence that native handle closure succeeded.
    pub fn close_checked(&mut self) -> Result<(), String> {
        let handle = self.0;
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err("retirement handle is not live".to_owned());
        }
        // SAFETY: this instance uniquely owns the live kernel handle.
        if unsafe { CloseHandle(handle) } == 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        self.0 = std::ptr::null_mut();
        Ok(())
    }

    pub fn close_for_retirement(mut self) -> Result<(), String> {
        self.close_checked()
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
    let mut observation = connect_observation::ConnectObservation::default();
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
        observation.record_create_failure(code);
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
            let available = unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
            // Last-error is meaningful only when this existing wait failed.
            let result = if available == 0 {
                Err(io::Error::last_os_error()
                    .raw_os_error()
                    .and_then(|value| u32::try_from(value).ok()))
            } else {
                Ok(())
            };
            observation.record_wait(result);
        }
    }
    Err(observation.timeout_error())
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
    BootstrapFrameProgress {
        peer_process,
        deadline,
        operation,
        pump: None,
    }
    .wait(handle, overlapped, segment, requested)
}

struct BootstrapFrameProgress<'a> {
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
    pump: Option<&'a mut dyn FnMut() -> Result<(), String>>,
}

impl BootstrapFrameProgress<'_> {
    fn wait(
        &mut self,
        handle: HANDLE,
        overlapped: &mut OVERLAPPED,
        segment: &'static str,
        requested: u32,
    ) -> Result<u32, TargetDesktopBootstrapPipeError> {
        let peer_process = self.peer_process;
        let deadline = self.deadline;
        let operation = self.operation;
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
            let pump_result = self.pump.as_mut().map(|pump| pump());
            if let Some(Err(detail)) = pump_result {
                cancel_and_drain(handle, overlapped);
                return Err(TargetDesktopBootstrapPipeError::protocol(
                    operation,
                    format!("segment={segment} debug event pump failed: {detail}"),
                ));
            }
            let now = if self.pump.is_some() {
                std::time::Instant::now()
            } else {
                now
            };
            if self.pump.is_some() && now >= deadline {
                cancel_and_drain(handle, overlapped);
                return Err(TargetDesktopBootstrapPipeError::protocol(
                    operation,
                    format!(
                        "segment={segment} requested={requested} target desktop bootstrap pipe operation timed out"
                    ),
                ));
            }
            let remaining = deadline.saturating_duration_since(now).as_millis();
            let mut timeout = u32::try_from(remaining).unwrap_or(u32::MAX).max(1);
            if self.pump.is_some() {
                timeout = timeout.min(1);
            }
            let wait =
                unsafe { WaitForMultipleObjects(handle_count, handles.as_ptr(), 0, timeout) };
            if wait == WAIT_OBJECT_0 {
                let mut transferred = 0_u32;
                if unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) } == 0
                {
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
                if unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) } != 0
                {
                    return Ok(transferred);
                }
                let completion_error = io::Error::last_os_error();
                if completion_error.raw_os_error() == Some(ERROR_IO_INCOMPLETE as i32)
                    && unsafe { WaitForSingleObject(overlapped.hEvent, 50) } == WAIT_OBJECT_0
                    && unsafe { GetOverlappedResult(handle, overlapped, &raw mut transferred, 0) }
                        != 0
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

    /// Support debug ownership cannot block while an outstanding debug event
    /// suspends the peer. On error the caller must retain this owner, not drop it.
    #[cfg(feature = "test-support")]
    pub(crate) fn cancel_and_poll(&mut self) -> Result<bool, TargetDesktopBootstrapPipeError> {
        if self.state != PendingAcceptState::Pending {
            self.state = PendingAcceptState::Drained;
            return Ok(true);
        }
        let pipe = self.pipe.as_ref().expect("pending accept owns pipe").raw();
        if unsafe { CancelIoEx(pipe, &raw const *self.overlapped) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "support-connect-cancel",
                    &error,
                ));
            }
        }
        let mut transferred = 0;
        if unsafe { GetOverlappedResult(pipe, &raw mut *self.overlapped, &raw mut transferred, 0) }
            != 0
        {
            self.state = PendingAcceptState::Drained;
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        match error.raw_os_error() {
            Some(code) if code == ERROR_OPERATION_ABORTED as i32 => {
                self.state = PendingAcceptState::Drained;
                Ok(true)
            }
            Some(code) if code == ERROR_IO_INCOMPLETE as i32 => Ok(false),
            _ => Err(TargetDesktopBootstrapPipeError::native(
                TargetDesktopBootstrapPipeOperation::Accept,
                "support-connect-drain",
                &error,
            )),
        }
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn cancel_and_drain_until(
        &mut self,
        cutoff: std::time::Instant,
    ) -> Result<(), TargetDesktopBootstrapPipeError> {
        if self.state != PendingAcceptState::Pending {
            self.state = PendingAcceptState::Drained;
            return Ok(());
        }
        let pipe = self.pipe.as_ref().expect("pending accept owns pipe").raw();
        if unsafe { CancelIoEx(pipe, &raw const *self.overlapped) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_NOT_FOUND as i32) {
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "support-connect-cancel",
                    &error,
                ));
            }
        }
        loop {
            let mut transferred = 0;
            if unsafe {
                GetOverlappedResult(pipe, &raw mut *self.overlapped, &raw mut transferred, 0)
            } != 0
            {
                self.state = PendingAcceptState::Drained;
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                self.state = PendingAcceptState::Drained;
                return Ok(());
            }
            if error.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
                return Err(TargetDesktopBootstrapPipeError::native(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "support-connect-drain",
                    &error,
                ));
            }
            let now = std::time::Instant::now();
            if now >= cutoff {
                return Err(TargetDesktopBootstrapPipeError::protocol(
                    TargetDesktopBootstrapPipeOperation::Accept,
                    "original support cleanup cutoff expired with pending accept",
                ));
            }
            std::thread::sleep(Duration::from_millis(1).min(cutoff - now));
        }
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
    transfer_with_progress(
        handle,
        buffer,
        length,
        write,
        segment,
        &mut BootstrapFrameProgress {
            peer_process,
            deadline,
            operation,
            pump: None,
        },
    )
}

fn transfer_with_progress(
    handle: HANDLE,
    buffer: *mut u8,
    length: u32,
    write: bool,
    segment: &'static str,
    progress: &mut BootstrapFrameProgress<'_>,
) -> Result<u32, TargetDesktopBootstrapPipeError> {
    let operation = progress.operation;
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
        progress.wait(handle, &mut overlapped, segment, length)
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
    write_frame_with_progress(
        handle,
        value,
        &mut BootstrapFrameProgress {
            peer_process,
            deadline,
            operation,
            pump: None,
        },
    )
}

#[cfg(feature = "test-support")]
pub fn write_frame_bounded_pumped<T: Serialize>(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
    value: &T,
    pump: &mut dyn FnMut() -> Result<(), String>,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    write_frame_with_progress(
        handle,
        value,
        &mut BootstrapFrameProgress {
            peer_process,
            deadline,
            operation,
            pump: Some(pump),
        },
    )
}

fn write_frame_with_progress<T: Serialize>(
    handle: HANDLE,
    value: &T,
    progress: &mut BootstrapFrameProgress<'_>,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    let operation = progress.operation;
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
        let transferred = match transfer_with_progress(
            handle,
            bytes[offset..].as_mut_ptr(),
            u32::try_from(bytes.len() - offset).map_err(|_| {
                TargetDesktopBootstrapPipeError::protocol(operation, "frame is not representable")
            })?,
            true,
            "frame",
            progress,
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

fn read_exact_with_progress(
    handle: HANDLE,
    buffer: &mut [u8],
    segment: &'static str,
    progress: &mut BootstrapFrameProgress<'_>,
) -> Result<(), TargetDesktopBootstrapPipeError> {
    let operation = progress.operation;
    let mut offset = 0;
    while offset < buffer.len() {
        let transferred = transfer_with_progress(
            handle,
            buffer[offset..].as_mut_ptr(),
            u32::try_from(buffer.len() - offset).map_err(|_| {
                TargetDesktopBootstrapPipeError::protocol(operation, "frame is not representable")
            })?,
            false,
            segment,
            progress,
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
    read_frame_with_progress(
        handle,
        &mut BootstrapFrameProgress {
            peer_process,
            deadline,
            operation,
            pump: None,
        },
    )
}

#[cfg(feature = "test-support")]
pub fn read_frame_bounded_pumped<T: DeserializeOwned>(
    handle: HANDLE,
    peer_process: Option<HANDLE>,
    deadline: std::time::Instant,
    operation: TargetDesktopBootstrapPipeOperation,
    pump: &mut dyn FnMut() -> Result<(), String>,
) -> Result<T, TargetDesktopBootstrapPipeError> {
    read_frame_with_progress(
        handle,
        &mut BootstrapFrameProgress {
            peer_process,
            deadline,
            operation,
            pump: Some(pump),
        },
    )
}

fn read_frame_with_progress<T: DeserializeOwned>(
    handle: HANDLE,
    progress: &mut BootstrapFrameProgress<'_>,
) -> Result<T, TargetDesktopBootstrapPipeError> {
    let operation = progress.operation;
    let mut length = [0_u8; 4];
    read_exact_with_progress(handle, &mut length, "length", progress)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > WINDOWS_MAX_FRAME_BYTES {
        return Err(TargetDesktopBootstrapPipeError::protocol(
            operation,
            "Windows provider frame exceeds the protocol bound",
        ));
    }
    let mut payload = vec![0_u8; length];
    read_exact_with_progress(handle, &mut payload, "payload", progress)?;
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
                if error.is_lifetime_pipe_closure() {
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
    write_frame_detailed(handle, value).map_err(|error| error.to_string())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameWritePhase {
    Serialize,
    Length,
    Payload,
}

#[derive(Debug)]
pub struct FrameWriteError {
    pub phase: FrameWritePhase,
    pub expected_bytes: usize,
    pub transferred_bytes: usize,
    pub native_code: Option<u32>,
    pub peer_closed: bool,
    detail: String,
}

impl std::fmt::Display for FrameWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "MCSEALED-WINDOWS-PIPE-WRITE: phase={:?} expected_bytes={} transferred_bytes={} native_code={:?} peer_closed={} detail={}",
            self.phase,
            self.expected_bytes,
            self.transferred_bytes,
            self.native_code,
            self.peer_closed,
            self.detail
        )
    }
}

fn frame_write_error(
    phase: FrameWritePhase,
    expected_bytes: usize,
    transferred_bytes: usize,
    native_code: Option<u32>,
    detail: String,
) -> FrameWriteError {
    FrameWriteError {
        phase,
        expected_bytes,
        transferred_bytes,
        native_code,
        peer_closed: native_code.is_some_and(|code| {
            matches!(
                code,
                ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED
            )
        }),
        detail,
    }
}

pub fn write_frame_detailed<T: Serialize>(
    handle: HANDLE,
    value: &T,
) -> Result<(), FrameWriteError> {
    write_frame_using(value, |bytes| {
        let requested = u32::try_from(bytes.len()).expect("bounded frame segment");
        let mut written = 0u32;
        // SAFETY: this synchronous call borrows live bytes and writable count;
        // native last-error is retained immediately, before formatting.
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
            Err((
                error
                    .raw_os_error()
                    .map(|code| u32::from_ne_bytes(code.to_ne_bytes())),
                written as usize,
                error.to_string(),
            ))
        } else {
            Ok(written as usize)
        }
    })
}

fn write_frame_using<T: Serialize>(
    value: &T,
    mut write: impl FnMut(&[u8]) -> Result<usize, (Option<u32>, usize, String)>,
) -> Result<(), FrameWriteError> {
    let payload = serde_json::to_vec(value).map_err(|error| {
        frame_write_error(FrameWritePhase::Serialize, 0, 0, None, error.to_string())
    })?;
    if let Ok(limit) = memcordon_core::windows_response_frame_limit(
        &payload[..payload
            .len()
            .min(memcordon_core::WINDOWS_RESPONSE_PREFIX_BYTES)],
    ) {
        if payload.len() > limit {
            return Err(frame_write_error(
                FrameWritePhase::Serialize,
                payload.len(),
                0,
                None,
                "diagnostic control frame exceeds its reserved bound".into(),
            ));
        }
    }
    if payload.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err(frame_write_error(
            FrameWritePhase::Serialize,
            payload.len(),
            0,
            None,
            "Windows provider frame exceeds the protocol bound".into(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        frame_write_error(
            FrameWritePhase::Serialize,
            payload.len(),
            0,
            None,
            "Windows provider frame length is not representable".into(),
        )
    })?;
    let header = length.to_le_bytes();
    for (phase, segment) in [
        (FrameWritePhase::Length, header.as_slice()),
        (FrameWritePhase::Payload, payload.as_slice()),
    ] {
        let mut transferred = 0;
        while transferred < segment.len() {
            let remaining = &segment[transferred..];
            match write(remaining) {
                Ok(written) if written > 0 && written <= remaining.len() => transferred += written,
                Ok(_) => {
                    return Err(frame_write_error(
                        phase,
                        segment.len(),
                        transferred,
                        None,
                        "zero-progress or invalid native write count".into(),
                    ));
                }
                Err((code, written, detail)) => {
                    return Err(frame_write_error(
                        phase,
                        segment.len(),
                        transferred.saturating_add(written),
                        code,
                        detail,
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/sealed_agent/windows_pipe_write.rs"]
mod frame_write_tests;

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
    read_frame_with_kind_limit(handle, None)
}

pub fn read_response_frame<T: memcordon_core::WindowsResponseFrame>(
    handle: HANDLE,
) -> Result<T, String> {
    read_response_frame_detailed(handle).map_err(|error| error.to_string())
}

pub fn read_response_frame_detailed<T: memcordon_core::WindowsResponseFrame>(
    handle: HANDLE,
) -> Result<T, FrameReadError> {
    read_frame_with_kind_limit(handle, Some(T::frame_limit))
}

type ResponseFrameLimit = fn(&[u8]) -> Result<usize, &'static str>;

fn read_frame_with_kind_limit<T: DeserializeOwned>(
    handle: HANDLE,
    response_limit: Option<ResponseFrameLimit>,
) -> Result<T, FrameReadError> {
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
    let mut prefix = [0_u8; memcordon_core::WINDOWS_RESPONSE_PREFIX_BYTES];
    let prefix_length = if response_limit.is_some() {
        length.min(prefix.len())
    } else {
        0
    };
    if let Some(response_limit) = response_limit {
        read_exact_detailed(
            handle,
            &mut prefix[..prefix_length],
            FrameReadPhase::Payload,
        )?;
        let limit = response_limit(&prefix[..prefix_length]).map_err(|detail| FrameReadError {
            phase: FrameReadPhase::Decode,
            expected_bytes: length,
            transferred_bytes: prefix_length,
            native_code: None,
            peer_closed: false,
            detail: detail.to_owned(),
        })?;
        if length > limit {
            return Err(FrameReadError {
                phase: FrameReadPhase::Length,
                expected_bytes: limit,
                transferred_bytes: length,
                native_code: None,
                peer_closed: false,
                detail: "diagnostic control frame exceeds its reserved bound".to_owned(),
            });
        }
    }
    let mut payload = vec![0_u8; length];
    payload[..prefix_length].copy_from_slice(&prefix[..prefix_length]);
    read_exact_detailed(
        handle,
        &mut payload[prefix_length..],
        FrameReadPhase::Payload,
    )?;
    memcordon_core::workload_contract::reject_duplicate_json_keys(&payload).map_err(|detail| {
        FrameReadError {
            phase: FrameReadPhase::Decode,
            expected_bytes: length,
            transferred_bytes: length,
            native_code: None,
            peer_closed: false,
            detail,
        }
    })?;
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
    PeerClosed { code: u32 },
    Native { code: Option<i32>, detail: String },
}

impl std::fmt::Display for FrameAvailabilityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PeerClosed { code } => write!(
                formatter,
                "named-pipe peer disconnected; native_code={code}"
            ),
            Self::Native { detail, .. } => formatter.write_str(detail),
        }
    }
}

pub fn frame_available(handle: HANDLE) -> Result<bool, String> {
    frame_available_detailed(handle).map_err(|error| error.to_string())
}

/// Read one small support release on a synchronous pipe owned by this sole reader.
#[cfg(feature = "test-support")]
pub fn read_control_release(
    handle: HANDLE,
    peer_process: HANDLE,
    deadline: std::time::Instant,
) -> Result<memcordon_core::WindowsProviderRequestV3, String> {
    const MAX_RELEASE_BYTES: u32 = 4096;
    loop {
        if std::time::Instant::now() >= deadline {
            return Err("support control release deadline expired".into());
        }
        // SAFETY: the original frontend handle remains held by relay_protocol.
        match unsafe { WaitForSingleObject(peer_process, 0) } {
            WAIT_TIMEOUT => {}
            WAIT_OBJECT_0 => return Err("support control release frontend retired".into()),
            _ => {
                return Err(format!(
                    "support control release frontend wait: {}",
                    io::Error::last_os_error()
                ));
            }
        }
        let mut prefix = [0_u8; 4];
        let mut copied = 0_u32;
        let mut available = 0_u32;
        // SAFETY: initialized output storage; Peek does not consume pipe bytes.
        if unsafe {
            PeekNamedPipe(
                handle,
                prefix.as_mut_ptr().cast(),
                4,
                &raw mut copied,
                &raw mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(format!(
                "support control release peek: {}",
                io::Error::last_os_error()
            ));
        }
        if copied == 4 {
            let length = u32::from_le_bytes(prefix);
            if length > MAX_RELEASE_BYTES {
                return Err("support control release exceeds fixed frame bound".into());
            }
            if available >= 4 + length {
                // This relay is the sole reader. The complete bounded frame is
                // already buffered, so synchronous reads cannot wait on a tail.
                return read_frame(handle);
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
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
            return Err(FrameAvailabilityError::PeerClosed {
                code: u32::try_from(error.raw_os_error().expect("matched native error"))
                    .expect("matched positive pipe error"),
            });
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
