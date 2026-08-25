use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::ptr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use memcordon_core::{
    BoundaryCapability, BoundaryClass, BoundaryRequirement, CommandSpec, Error, ErrorCategory,
    LaunchEvidence, NativeWindowsCommandV1, Policy, WINDOWS_CONTROL_PIPE, WINDOWS_MAX_FRAME_BYTES,
    WINDOWS_PUBLIC_PROTOCOL_VERSION, WindowsEnvironmentEntryV1, WindowsLaunchPolicyV1,
    WindowsLaunchRequestV1, WindowsLifetimeV1, WindowsProviderRequestV1, WindowsProviderResponseV1,
    WindowsQualificationReceiptV1, WindowsRemoteStreamV1, WindowsStreamRoleV1,
    validate_windows_stream_manifest,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, EqualSid, GetTokenInformation, LookupAccountNameW,
    PROTECTED_DACL_SECURITY_INFORMATION, SetKernelObjectSecurity, TOKEN_GROUPS, TOKEN_QUERY,
    TOKEN_USER, TokenGroups, TokenRestrictedSids, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, FILE_TYPE_PIPE, GetFileType,
    OPEN_EXISTING, ReadFile, WriteFile,
};
use windows_sys::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::IO::CancelSynchronousIo;
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, SetEvent,
    WaitForSingleObject,
};

use crate::backend::{
    BackendInfo, BoundaryQualification, BoundarySupport, Execution, SealedAvailability,
};

const PIPE_CLIENT_READ_WRITE: u32 = 0x0012_019b;
const TOKEN_GROUP_ENABLED: u32 = 0x0000_0004;
const TOKEN_GROUP_USE_FOR_DENY_ONLY: u32 = 0x0000_0010;

pub fn probe() -> Result<WindowsQualificationReceiptV1, String> {
    prepare_current_process_for_restricted_broker()?;
    let pipe = connect()?;
    authenticate_peer(pipe.raw())?;
    write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::Probe {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        },
    )?;
    match read_frame::<WindowsProviderResponseV1>(pipe.raw())? {
        WindowsProviderResponseV1::Probe {
            schema_version,
            qualification,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && qualification_is_advertisable(&qualification, None)
            && qualification.provider_identity
                == format!(
                    "memcordon-sealed-agent-windows-v1:{}",
                    env!("CARGO_PKG_VERSION")
                ) =>
        {
            Ok(qualification)
        }
        WindowsProviderResponseV1::Reject { rejection, .. } => {
            Err(format!("{}: {}", rejection.code, rejection.detail))
        }
        _ => Err("Windows sealed provider returned an invalid qualification receipt".to_owned()),
    }
}

fn qualification_is_advertisable(
    qualification: &WindowsQualificationReceiptV1,
    mutant: Option<memcordon_core::WindowsSealedMutant>,
) -> bool {
    qualification_fields_are_advertisable(
        qualification.qualified,
        qualification.is_consistent(),
        mutant,
    )
}

fn qualification_fields_are_advertisable(
    qualified: bool,
    consistent: bool,
    mutant: Option<memcordon_core::WindowsSealedMutant>,
) -> bool {
    (qualified || mutant == Some(memcordon_core::WindowsSealedMutant::AdvertiseWithoutCertificate))
        && consistent
}

pub(crate) fn certify_qualification_predicate_mutant(
    mutant: memcordon_core::WindowsSealedMutant,
) -> Option<memcordon_core::WindowsMutantNativeObservationV1> {
    // The mapped test supplies the contradictory state that the mutant would
    // advertise: a schema-consistent receipt cannot substitute for the native
    // certificate's qualified bit.
    Some(
        memcordon_core::WindowsMutantNativeObservationV1::UnqualifiedAdvertisement {
            ordinary_advertised: qualification_fields_are_advertisable(false, true, None),
            mutant_advertised: qualification_fields_are_advertisable(false, true, Some(mutant)),
        },
    )
}

fn prepare_current_process_for_restricted_broker() -> Result<(), String> {
    let process = unsafe { GetCurrentProcess() };
    let mut token = ptr::null_mut();
    // SAFETY: the current-process pseudo-handle is valid and token receives an
    // owned query handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let user = token_information(token.raw(), TokenUser)?;
    // SAFETY: token_information returned a complete TOKEN_USER allocation.
    let user = unsafe { ptr::read_unaligned(user.as_ptr().cast::<TOKEN_USER>()) };
    let user = sid_string(user.User.Sid)?;
    // The broker opens this process while impersonating the authenticated
    // caller. A restricted token must satisfy the normal user and restricting
    // SID checks, so RC receives only query, duplicate-handle and synchronize.
    let sddl = format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})(A;;0x00101040;;;RC)")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = ptr::null_mut();
    // SAFETY: sddl is NUL terminated and descriptor receives a LocalAlloc
    // allocation released below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: descriptor is a valid self-relative security descriptor and the
    // pseudo-handle identifies the current process.
    let applied = unsafe {
        SetKernelObjectSecurity(
            process,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    // SAFETY: the conversion API allocated descriptor with LocalAlloc.
    unsafe { LocalFree(descriptor as HLOCAL) };
    if applied == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn sid_string(sid: *mut core::ffi::c_void) -> Result<String, String> {
    let mut value = ptr::null_mut();
    // SAFETY: sid came from a TOKEN_USER buffer and value receives a
    // LocalAlloc string.
    if unsafe { ConvertSidToStringSidW(sid, &raw mut value) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut length = 0_usize;
    // SAFETY: value is a NUL-terminated string allocated by the conversion API.
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    // SAFETY: the measured code-unit range is initialized and excludes NUL.
    let result = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, length) });
    // SAFETY: the conversion API allocated value with LocalAlloc.
    unsafe { LocalFree(value as HLOCAL) };
    Ok(result)
}

pub fn info(qualification: WindowsQualificationReceiptV1) -> BackendInfo {
    let receipt = serde_json::to_vec(&qualification)
        .expect("qualification receipt always has a bounded serialization");
    let digest: String = Sha256::digest(receipt)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    BackendInfo {
        name: "windows-job-object",
        containment_supported: true,
        memory_supported: true,
        class: "hard",
        metric: "windows-job-commit",
        hard_limit: true,
        startup_containment:
            "target created suspended with creation-time Job and exact handle lists, then verified and resumed",
        limitations: vec![
            "standard streams are provider-owned pipes rather than direct console handles",
            "interactive console and desktop semantics are not certified",
            "AppContainer caller tokens are not supported by Windows sealed v2",
        ],
        boundary_support: BoundarySupport {
            standard: BoundaryCapability {
                class: BoundaryClass::Standard,
                mechanism: "suspended-job-assignment-v1".to_owned(),
                target_gated: true,
                boundary_verified_before_authorization: true,
                target_can_reconfigure_boundary: true,
                frontend_loss_cleanup_authority: false,
                workload_empty_proof: true,
                limitations: vec!["standard supervision is not a sealed boundary".to_owned()],
            },
            sealed: SealedAvailability::Available {
                capability: BoundaryCapability {
                    class: BoundaryClass::Sealed,
                    mechanism: "windows-job-object-v2".to_owned(),
                    target_gated: true,
                    boundary_verified_before_authorization: true,
                    target_can_reconfigure_boundary: false,
                    frontend_loss_cleanup_authority: true,
                    workload_empty_proof: true,
                    limitations: vec![
                        "standard streams are provider-owned pipes rather than direct console handles".to_owned(),
                        "interactive console and desktop semantics are not certified".to_owned(),
                        "AppContainer caller tokens are not supported by Windows sealed v2".to_owned(),
                    ],
                },
                qualification: BoundaryQualification {
                    provider_identity: qualification.provider_identity,
                    receipt_digest: digest,
                    mechanism: "windows-job-object-v2".to_owned(),
                },
            },
        },
    }
}

#[allow(clippy::result_large_err)]
pub fn run(
    policy: &Policy,
    command: &CommandSpec,
    console: &crate::windows_job::ConsoleControl,
    context: crate::supervisor::AttemptContext,
) -> Result<Execution, Error> {
    let qualification = probe().map_err(|detail| {
        Error::new(
            ErrorCategory::Setup,
            "MCSEALED-WINDOWS-QUALIFICATION",
            missing_provider_message(&detail),
        )
    })?;
    let pipe = connect().map_err(transport_error)?;
    authenticate_peer(pipe.raw()).map_err(transport_error)?;
    let nonce = launch_nonce(command);
    let request = WindowsLaunchRequestV1 {
        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
        nonce: nonce.clone(),
        command: encode_command(command).map_err(usage_error)?,
        environment: encode_environment().map_err(usage_error)?,
        current_directory: encode_current_directory().map_err(usage_error)?,
        policy: encode_policy(policy, context).map_err(usage_error)?,
    };
    let request_sha256 = Sha256::digest(
        serde_json::to_vec(&request).map_err(|error| transport_error(error.to_string()))?,
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    write_frame(pipe.raw(), &WindowsProviderRequestV1::Launch(request)).map_err(transport_error)?;
    let prepared = read_frame::<WindowsProviderResponseV1>(pipe.raw()).map_err(transport_error)?;
    let (attempt_id, streams, relay_retired_event_handle) = match prepared {
        WindowsProviderResponseV1::StreamsPrepared {
            schema_version,
            attempt_id,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            streams,
            relay_retired_event_handle,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && returned_nonce == nonce
            && returned_digest == request_sha256 =>
        {
            (attempt_id, streams, relay_retired_event_handle)
        }
        WindowsProviderResponseV1::Reject {
            schema_version,
            attempt_id,
            nonce: returned_nonce,
            request_sha256: returned_digest,
            rejection,
        } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
            && !attempt_id.is_empty()
            && returned_nonce == nonce
            && returned_digest == request_sha256 =>
        {
            return Err(rejection_error(rejection));
        }
        _ => {
            return Err(transport_error(
                "provider omitted stream preparation".to_owned(),
            ));
        }
    };
    let mut relays = Relays::start(streams, relay_retired_event_handle).map_err(transport_error)?;
    write_frame(
        pipe.raw(),
        &WindowsProviderRequestV1::RelaysReady {
            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
            attempt_id: attempt_id.clone(),
            nonce: nonce.clone(),
            request_sha256: request_sha256.clone(),
        },
    )
    .map_err(transport_error)?;

    let mut cancel_sent = false;
    let mut target_authorized = false;
    let mut target_retired = false;
    let terminal = loop {
        if frame_available(pipe.raw()).map_err(transport_error)? {
            match read_frame::<WindowsProviderResponseV1>(pipe.raw()).map_err(transport_error)? {
                WindowsProviderResponseV1::TargetAuthorized {
                    schema_version,
                    attempt_id: returned,
                    nonce: returned_nonce,
                    request_sha256: returned_digest,
                    ..
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && returned == attempt_id
                    && returned_nonce == nonce
                    && returned_digest == request_sha256
                    && !target_authorized
                    && !target_retired =>
                {
                    target_authorized = true;
                }
                WindowsProviderResponseV1::TargetRetired {
                    schema_version,
                    attempt_id: returned,
                    nonce: returned_nonce,
                    request_sha256: returned_digest,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && returned == attempt_id
                    && returned_nonce == nonce
                    && returned_digest == request_sha256
                    && target_authorized
                    && !target_retired =>
                {
                    relays.retire().map_err(transport_error)?;
                    write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::RelaysRetired {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                        },
                    )
                    .map_err(transport_error)?;
                    target_retired = true;
                }
                WindowsProviderResponseV1::RelaysAbort {
                    schema_version,
                    attempt_id: returned,
                    nonce: returned_nonce,
                    request_sha256: returned_digest,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && returned == attempt_id
                    && returned_nonce == nonce
                    && returned_digest == request_sha256
                    && !target_authorized
                    && !target_retired =>
                {
                    relays.retire().map_err(transport_error)?;
                    write_frame(
                        pipe.raw(),
                        &WindowsProviderRequestV1::RelaysRetired {
                            schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                            attempt_id: attempt_id.clone(),
                            nonce: nonce.clone(),
                            request_sha256: request_sha256.clone(),
                        },
                    )
                    .map_err(transport_error)?;
                    target_retired = true;
                }
                WindowsProviderResponseV1::Terminal(receipt)
                    if receipt.attempt_id == attempt_id
                        && receipt.nonce == nonce
                        && receipt.request_sha256 == request_sha256
                        && target_authorized
                        && target_retired
                        && receipt.process_identity_inventory_is_bounded() =>
                {
                    break receipt;
                }
                WindowsProviderResponseV1::Reject {
                    schema_version,
                    attempt_id: returned_attempt,
                    nonce: returned_nonce,
                    request_sha256: returned_digest,
                    rejection,
                } if schema_version == WINDOWS_PUBLIC_PROTOCOL_VERSION
                    && returned_attempt == attempt_id
                    && returned_nonce == nonce
                    && returned_digest == request_sha256 =>
                {
                    return Err(rejection_error(rejection));
                }
                _ => {
                    return Err(transport_error(
                        "provider response identity or phase mismatch".to_owned(),
                    ));
                }
            }
        }
        if !cancel_sent {
            if let Some(signal) = console
                .wait(Duration::from_millis(10))
                .map_err(|error| transport_error(error.to_string()))?
            {
                write_frame(
                    pipe.raw(),
                    &WindowsProviderRequestV1::Cancel {
                        schema_version: WINDOWS_PUBLIC_PROTOCOL_VERSION,
                        attempt_id: attempt_id.clone(),
                        nonce: nonce.clone(),
                        request_sha256: request_sha256.clone(),
                        signal,
                    },
                )
                .map_err(transport_error)?;
                cancel_sent = true;
            }
        } else {
            std::thread::sleep(Duration::from_millis(10));
        }
    };
    relays.retire().map_err(transport_error)?;
    if terminal.schema_version != 1
        || !terminal
            .restart_safety
            .is_safe_for(BoundaryRequirement::Sealed)
    {
        return Err(Error::new(
            ErrorCategory::Monitor,
            "MCSEALED-WINDOWS-TERMINAL-EVIDENCE",
            "provider terminal receipt is incomplete or restart-unsafe",
        ));
    }
    let launch = LaunchEvidence {
        mechanism: "windows-job-object-v2".to_owned(),
        target_released: true,
        containment_verified_before_authorization: true,
        guardian_started_before_authorization: true,
        target_spawn_error_reported: true,
        boundary_requested: BoundaryRequirement::Sealed,
        boundary_effective: BoundaryClass::Sealed,
        boundary_assignment_verified: true,
        boundary_reconfiguration_denied: true,
        inherited_resources_restricted: true,
        frontend_loss_cleanup_authority_verified: true,
    };
    if !memcordon_core::boundary_evidence_is_consistent(
        &launch,
        &terminal.restart_safety,
        &terminal.boundary_detail,
    ) {
        return Err(Error::new(
            ErrorCategory::Monitor,
            "MCSEALED-WINDOWS-EVIDENCE",
            "provider returned contradictory native Windows evidence",
        ));
    }
    Ok(Execution {
        outcome: terminal.outcome,
        backend: info(qualification),
        child_pid: terminal.child_pid,
        duration: Duration::from_millis(terminal.duration_millis),
        authorization_offset: Some(Duration::from_millis(terminal.authorization_offset_millis)),
        launch,
        restart_safety: terminal.restart_safety,
        boundary_detail: terminal.boundary_detail,
    })
}

struct OwnedHandle(HANDLE);

unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, String> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }
    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: wrapper owns one handle and closes it once.
            unsafe { CloseHandle(self.0) };
        }
    }
}

struct Relays {
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<Result<(), String>>>,
    handles: Vec<OwnedHandle>,
    relay_retired_event: OwnedHandle,
    retired: bool,
}

impl Relays {
    fn start(
        streams: Vec<WindowsRemoteStreamV1>,
        relay_retired_event_handle: u64,
    ) -> Result<Self, String> {
        let manifest = streams.clone();
        let mut adopted = std::collections::BTreeMap::new();
        for raw in streams
            .iter()
            .map(|stream| stream.remote_handle)
            .chain(std::iter::once(relay_retired_event_handle))
        {
            if raw != 0 && !adopted.contains_key(&raw) {
                adopted.insert(raw, OwnedHandle::new(raw as usize as HANDLE)?);
            }
        }
        validate_windows_stream_manifest(&manifest).map_err(str::to_owned)?;
        if relay_retired_event_handle == 0
            || manifest
                .iter()
                .any(|stream| stream.remote_handle == relay_retired_event_handle)
        {
            return Err("provider returned an invalid relay-retirement event".to_owned());
        }
        let mut prepared = Vec::with_capacity(streams.len());
        for stream in streams {
            let handle = adopted
                .remove(&stream.remote_handle)
                .ok_or_else(|| "provider stream handle was not adopted".to_owned())?;
            prepared.push((stream.role, handle));
        }
        let relay_retired_event = adopted
            .remove(&relay_retired_event_handle)
            .ok_or_else(|| "provider relay-retirement event was not adopted".to_owned())?;
        for (_, handle) in &prepared {
            // SAFETY: handle was duplicated by the provider and is queried only.
            if unsafe { GetFileType(handle.raw()) } != FILE_TYPE_PIPE {
                return Err("provider stream handle is not a pipe".to_owned());
            }
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = Vec::with_capacity(prepared.len());
        let mut threads = Vec::with_capacity(prepared.len());
        for (role, handle) in prepared {
            let raw = handle.raw() as usize;
            let stop_for_thread = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                relay(role, raw as HANDLE, &stop_for_thread)
            }));
            handles.push(handle);
        }
        Ok(Self {
            stop,
            threads,
            handles,
            relay_retired_event,
            retired: false,
        })
    }

    fn retire(&mut self) -> Result<(), String> {
        if self.retired {
            return Ok(());
        }
        self.stop.store(true, Ordering::SeqCst);
        let threads = std::mem::take(&mut self.threads);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let mut errors = Vec::new();
        for thread in &threads {
            // SAFETY: the raw handle belongs to this still-live JoinHandle and
            // is used only to cancel synchronous relay I/O before joining.
            if unsafe { CancelSynchronousIo(thread.as_raw_handle() as HANDLE) } == 0 {
                let error = io::Error::last_os_error();
                if error
                    .raw_os_error()
                    .and_then(|value| u32::try_from(value).ok())
                    != Some(ERROR_NOT_FOUND)
                {
                    errors.push(format!("failed to cancel stream relay I/O: {error}"));
                }
            }
        }
        for thread in &threads {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            let wait_millis = u32::try_from(remaining.as_millis()).unwrap_or(u32::MAX);
            // SAFETY: the JoinHandle owns a live Windows thread handle.
            match unsafe { WaitForSingleObject(thread.as_raw_handle() as HANDLE, wait_millis) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => {
                    // A stuck relay would otherwise keep the frontend and its
                    // provider-owned stream handles alive indefinitely. Exit
                    // the frontend so the guardian becomes cleanup authority.
                    std::process::abort();
                }
                WAIT_FAILED => errors.push(format!(
                    "failed while waiting for stream relay retirement: {}",
                    io::Error::last_os_error()
                )),
                status => errors.push(format!("unexpected stream relay wait status: {status}")),
            }
        }
        for thread in threads {
            match thread.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(error),
                Err(_) => errors.push("stream relay thread panicked".to_owned()),
            }
        }
        self.handles.clear();
        // SAFETY: this event is the exact launcher-created retirement channel
        // adopted before validating the transferred manifest.
        if unsafe { SetEvent(self.relay_retired_event.raw()) } == 0 {
            errors.push(format!(
                "failed to signal relay retirement: {}",
                io::Error::last_os_error()
            ));
        }
        self.retired = true;
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

impl Drop for Relays {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

fn relay(role: WindowsStreamRoleV1, remote: HANDLE, stop: &AtomicBool) -> Result<(), String> {
    let (source, destination) = match role {
        // SAFETY: standard handle selectors do not transfer ownership.
        WindowsStreamRoleV1::Stdin => (unsafe { GetStdHandle(STD_INPUT_HANDLE) }, remote),
        WindowsStreamRoleV1::Stdout => (remote, unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }),
        WindowsStreamRoleV1::Stderr => (remote, unsafe { GetStdHandle(STD_ERROR_HANDLE) }),
    };
    let mut buffer = [0_u8; 16 * 1024];
    while !stop.load(Ordering::SeqCst) {
        // SAFETY: source is a live standard/pipe handle used only for waiting.
        if unsafe { WaitForSingleObject(source, 20) } != WAIT_OBJECT_0 {
            continue;
        }
        let mut read = 0_u32;
        // SAFETY: buffer and count are live for synchronous IO.
        if unsafe {
            ReadFile(
                source,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            break;
        }
        if read == 0 {
            break;
        }
        let mut offset = 0_usize;
        while offset < read as usize {
            let mut written = 0_u32;
            // SAFETY: remaining buffer and count are live for synchronous IO.
            if unsafe {
                WriteFile(
                    destination,
                    buffer[offset..read as usize].as_ptr(),
                    (read as usize - offset) as u32,
                    &raw mut written,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Ok(());
            }
            if written == 0 {
                return Err("zero-byte stream relay write".to_owned());
            }
            offset += written as usize;
        }
    }
    Ok(())
}

fn connect() -> Result<OwnedHandle, String> {
    let name: Vec<u16> = WINDOWS_CONTROL_PIPE
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    for _ in 0..100 {
        // SAFETY: name is NUL-terminated and returned handle transfers to wrapper.
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
        if error
            .raw_os_error()
            .and_then(|value| u32::try_from(value).ok())
            != Some(ERROR_PIPE_BUSY)
        {
            return Err(error.to_string());
        }
        // SAFETY: name remains NUL-terminated.
        unsafe { WaitNamedPipeW(name.as_ptr(), 100) };
    }
    Err("Windows sealed provider pipe did not become available".to_owned())
}

fn authenticate_peer(pipe: HANDLE) -> Result<(), String> {
    let mut pid = 0_u32;
    // SAFETY: connected pipe and output storage are live.
    if unsafe { GetNamedPipeServerProcessId(pipe, &raw mut pid) } == 0 || pid == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    // SAFETY: kernel supplied PID; rights are query-only.
    let process =
        OwnedHandle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let mut path = vec![0_u16; 32 * 1024];
    let mut length = path.len() as u32;
    // SAFETY: path is writable and length supplies its element capacity.
    if unsafe {
        windows_sys::Win32::System::Threading::QueryFullProcessImageNameW(
            process.raw(),
            0,
            path.as_mut_ptr(),
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    path.truncate(length as usize);
    let actual = String::from_utf16_lossy(&path);
    let expected = std::env::var_os("ProgramFiles")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files"))
        .join("MemCordon")
        .join("memcordon-sealed-agent.exe");
    if !actual.eq_ignore_ascii_case(&expected.to_string_lossy()) {
        return Err(
            "connected Windows sealed provider is not the installed agent image".to_owned(),
        );
    }
    let mut token = ptr::null_mut();
    // SAFETY: process is a live query handle and token ownership transfers to
    // the local wrapper.
    if unsafe { OpenProcessToken(process.raw(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let token = OwnedHandle::new(token)?;
    let local_service = account_sid(r"NT AUTHORITY\LocalService")?;
    let control_service = account_sid(&format!(
        r"NT SERVICE\{}",
        memcordon_core::WINDOWS_CONTROL_SERVICE_NAME
    ))?;
    let user = token_information(token.raw(), TokenUser)?;
    // SAFETY: token_information returned a complete TOKEN_USER allocation.
    let user = unsafe { ptr::read_unaligned(user.as_ptr().cast::<TOKEN_USER>()) };
    if unsafe { EqualSid(user.User.Sid, local_service.as_ptr().cast_mut().cast()) } == 0
        || !token_groups_contain(token.raw(), TokenGroups, &control_service)?
        || !token_groups_contain(token.raw(), TokenRestrictedSids, &control_service)?
    {
        return Err(
            "connected Windows sealed provider lacks the restricted control-service identity"
                .to_owned(),
        );
    }
    Ok(())
}

fn account_sid(account: &str) -> Result<Vec<u32>, String> {
    let account = account
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid_bytes = 0_u32;
    let mut domain_chars = 0_u32;
    let mut use_kind = 0_i32;
    // SAFETY: documented sizing call with null output buffers.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &raw mut sid_bytes,
            ptr::null_mut(),
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    };
    if sid_bytes == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let mut sid = vec![0_u32; (sid_bytes as usize).div_ceil(std::mem::size_of::<u32>())];
    let mut domain = vec![0_u16; domain_chars as usize];
    // SAFETY: both buffers have the exact capacities returned by the sizing call.
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &raw mut sid_bytes,
            domain.as_mut_ptr(),
            &raw mut domain_chars,
            &raw mut use_kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(sid)
}

struct TokenInformationBuffer {
    words: Vec<usize>,
    byte_length: usize,
}

impl TokenInformationBuffer {
    fn as_ptr(&self) -> *const u8 {
        self.words.as_ptr().cast()
    }
}

fn token_information(token: HANDLE, class: i32) -> Result<TokenInformationBuffer, String> {
    let mut length = 0_u32;
    // SAFETY: null-buffer sizing query writes only the required length.
    unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut length) };
    if length == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    let requested = length as usize;
    let mut words = vec![0_usize; requested.div_ceil(std::mem::size_of::<usize>())];
    // SAFETY: word storage is native-aligned and has at least the requested
    // writable byte capacity.
    if unsafe {
        GetTokenInformation(
            token,
            class,
            words.as_mut_ptr().cast(),
            length,
            &raw mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().to_string());
    }
    Ok(TokenInformationBuffer {
        words,
        byte_length: length as usize,
    })
}

fn token_groups_contain(token: HANDLE, class: i32, expected: &[u32]) -> Result<bool, String> {
    let buffer = token_information(token, class)?;
    if buffer.byte_length < std::mem::size_of::<TOKEN_GROUPS>() {
        return Err("token group response is truncated".to_owned());
    }
    // SAFETY: buffer contains the requested TOKEN_GROUPS header and the count
    // describes its trailing SID_AND_ATTRIBUTES entries.
    let groups = unsafe { ptr::read_unaligned(buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
    let entries =
        unsafe { std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize) };
    Ok(entries.iter().any(|entry| {
        (unsafe { EqualSid(entry.Sid, expected.as_ptr().cast_mut().cast()) }) != 0
            && entry.Attributes & TOKEN_GROUP_ENABLED != 0
            && entry.Attributes & TOKEN_GROUP_USE_FOR_DENY_ONLY == 0
    }))
}

fn write_frame<T: Serialize>(handle: HANDLE, value: &T) -> Result<(), String> {
    let payload = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    if payload.len() > WINDOWS_MAX_FRAME_BYTES {
        return Err("provider frame exceeds bound".to_owned());
    }
    write_all(handle, &(payload.len() as u32).to_le_bytes())?;
    write_all(handle, &payload)
}

fn read_frame<T: DeserializeOwned>(handle: HANDLE) -> Result<T, String> {
    let mut length = [0_u8; 4];
    read_exact(handle, &mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > WINDOWS_MAX_FRAME_BYTES {
        return Err("provider frame exceeds bound".to_owned());
    }
    let mut payload = vec![0_u8; length];
    read_exact(handle, &mut payload)?;
    serde_json::from_slice(&payload).map_err(|error| error.to_string())
}

fn frame_available(handle: HANDLE) -> Result<bool, String> {
    let mut available = 0_u32;
    // SAFETY: output count is live and no read buffer is requested.
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
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(available >= 4)
    }
}

fn write_all(handle: HANDLE, mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let mut written = 0_u32;
        // SAFETY: slice and count remain live for synchronous IO.
        if unsafe {
            WriteFile(
                handle,
                bytes.as_ptr(),
                bytes.len().min(u32::MAX as usize) as u32,
                &raw mut written,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if written == 0 {
            return Err("zero-byte provider write".to_owned());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn read_exact(handle: HANDLE, mut bytes: &mut [u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        let mut read = 0_u32;
        // SAFETY: slice and count remain live for synchronous IO.
        if unsafe {
            ReadFile(
                handle,
                bytes.as_mut_ptr(),
                bytes.len().min(u32::MAX as usize) as u32,
                &raw mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error().to_string());
        }
        if read == 0 {
            return Err("unexpected end of provider frame".to_owned());
        }
        let (_, rest) = bytes.split_at_mut(read as usize);
        bytes = rest;
    }
    Ok(())
}

fn encode_command(command: &CommandSpec) -> Result<NativeWindowsCommandV1, String> {
    let program = command.program().encode_wide().collect::<Vec<_>>();
    let arguments = command
        .arguments()
        .iter()
        .map(|value| value.encode_wide().collect())
        .collect();
    if program.is_empty() || program.contains(&0) {
        return Err("Windows program is empty or contains NUL".to_owned());
    }
    Ok(NativeWindowsCommandV1 { program, arguments })
}

fn encode_environment() -> Result<Vec<WindowsEnvironmentEntryV1>, String> {
    std::env::vars_os()
        .map(|(name, value)| {
            let name = name.encode_wide().collect::<Vec<_>>();
            let value = value.encode_wide().collect::<Vec<_>>();
            if name.is_empty() || name.contains(&0) || value.contains(&0) {
                Err("Windows environment contains an invalid entry".to_owned())
            } else {
                Ok(WindowsEnvironmentEntryV1 { name, value })
            }
        })
        .collect()
}

fn encode_current_directory() -> Result<Vec<u16>, String> {
    std::env::current_dir()
        .map_err(|error| error.to_string())
        .map(|path| path.as_os_str().encode_wide().collect())
}

fn encode_policy(
    policy: &Policy,
    context: crate::supervisor::AttemptContext,
) -> Result<WindowsLaunchPolicyV1, String> {
    let local = policy.deadline.map(|deadline| deadline.duration());
    let budget = match (local, context.supervision_deadline_remaining) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    };
    let absolute_deadline_millis = budget
        .map(|duration| {
            let milliseconds = u64::try_from(duration.as_millis())
                .map_err(|_| "deadline exceeds protocol range".to_owned())?;
            // SAFETY: GetTickCount64 has no pointer preconditions.
            Ok::<_, String>(unsafe { GetTickCount64() }.saturating_add(milliseconds))
        })
        .transpose()?;
    Ok(WindowsLaunchPolicyV1 {
        memory_limit_bytes: policy.memory.map(memcordon_core::ByteSize::bytes),
        absolute_deadline_millis,
        lifetime: match policy.lifetime {
            memcordon_core::Lifetime::Command => WindowsLifetimeV1::Command,
            memcordon_core::Lifetime::Workload => WindowsLifetimeV1::Workload,
        },
        poll_interval_millis: millis(policy.poll_interval),
        signal_grace_millis: millis(policy.signal_grace),
        command_exit_grace_millis: millis(policy.command_exit_grace),
        limit_grace_millis: millis(policy.limit_grace),
    })
}

fn launch_nonce(command: &CommandSpec) -> String {
    let mut digest = Sha256::new();
    // SAFETY: tick-count call has no pointer preconditions.
    digest.update(unsafe { GetTickCount64() }.to_le_bytes());
    digest.update(std::process::id().to_le_bytes());
    digest.update(
        command
            .program()
            .encode_wide()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>(),
    );
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn rejection_error(rejection: memcordon_core::ProviderRejectionEvidence) -> Error {
    let (category, code, initial_spawn_failure) = match rejection.code.as_str() {
        "MCSPAWN-NOT-FOUND" => (
            ErrorCategory::Spawn,
            "MCSPAWN-NOT-FOUND",
            Some(memcordon_core::InitialSpawnFailure::NotFound),
        ),
        "MCSPAWN-NOT-EXECUTABLE" => (
            ErrorCategory::Spawn,
            "MCSPAWN-NOT-EXECUTABLE",
            Some(memcordon_core::InitialSpawnFailure::NotExecutable),
        ),
        "MCSPAWN-FAILED" => (ErrorCategory::Spawn, "MCSPAWN-FAILED", None),
        _ => (ErrorCategory::Setup, "MCSEALED-PROVIDER-REJECTION", None),
    };
    let mut error = Error::new(
        category,
        code,
        format!(
            "provider rejected launch [{}]: {}",
            rejection.code, rejection.detail
        ),
    )
    .with_boundary_setup_failure(memcordon_core::BoundarySetupFailure {
        requested: BoundaryRequirement::Sealed,
        mechanism: Some("windows-job-object-v2".to_owned()),
        phase: rejection.phase,
        target_created: rejection.target_created,
        target_released: rejection.target_released,
        cleanup_attempted: rejection.cleanup_attempted,
        restart_safety: rejection.restart_safety.clone(),
    })
    .with_provider_rejection(rejection.clone());
    error.os_code = rejection.os_code;
    if category == ErrorCategory::Spawn {
        error.launch_phase = Some("target-spawn-failed");
    } else {
        error.launch_phase = Some(boundary_phase_name(rejection.phase));
    }
    if let Some(failure) = initial_spawn_failure {
        error = error.with_initial_spawn_failure(failure);
    }
    error.workload_may_be_alive =
        rejection.target_created && rejection.restart_safety.workload_empty != Some(true);
    error
}

fn boundary_phase_name(phase: memcordon_core::BoundarySetupPhase) -> &'static str {
    match phase {
        memcordon_core::BoundarySetupPhase::RequestValidation => "request-validation",
        memcordon_core::BoundarySetupPhase::ProviderConnection => "provider-connection",
        memcordon_core::BoundarySetupPhase::ProviderIdentity => "provider-identity",
        memcordon_core::BoundarySetupPhase::CallerEnvelopeCapture => "caller-envelope-capture",
        memcordon_core::BoundarySetupPhase::LauncherServiceAuthentication => {
            "launcher-service-authentication"
        }
        memcordon_core::BoundarySetupPhase::CallerMountNamespaceAdoption => {
            "caller-mount-namespace-adoption"
        }
        memcordon_core::BoundarySetupPhase::CallerCapabilityEnvelope => {
            "caller-capability-envelope"
        }
        memcordon_core::BoundarySetupPhase::CredentialTransitionPolicy => {
            "credential-transition-policy"
        }
        memcordon_core::BoundarySetupPhase::BoundaryCreation => "boundary-creation",
        memcordon_core::BoundarySetupPhase::GuardianStartup => "guardian-startup",
        memcordon_core::BoundarySetupPhase::TargetCreation => "target-creation",
        memcordon_core::BoundarySetupPhase::AssignmentVerification => "assignment-verification",
        memcordon_core::BoundarySetupPhase::ResourceVerification => "resource-verification",
        memcordon_core::BoundarySetupPhase::Authorization => "authorization",
        memcordon_core::BoundarySetupPhase::Monitoring => "monitoring",
        memcordon_core::BoundarySetupPhase::Retirement => "retirement",
    }
}

fn transport_error(detail: String) -> Error {
    Error::new(ErrorCategory::Setup, "MCSEALED-WINDOWS-TRANSPORT", detail)
}
fn usage_error(detail: String) -> Error {
    Error::new(ErrorCategory::Usage, "MCSEALED-WINDOWS-REQUEST", detail)
}
fn missing_provider_message(detail: &str) -> String {
    format!(
        "Windows sealed provider is not installed or not qualified: {detail}\n\nInstall the companion memcordon-sealed-agent.exe from the same MemCordon version, then run package install from an elevated terminal."
    )
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
