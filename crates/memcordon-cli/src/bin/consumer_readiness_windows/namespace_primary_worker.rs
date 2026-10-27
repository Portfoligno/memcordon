//! Standalone native experiment; never participates in installed acceptance.
use std::io::{self, BufRead, Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::{
    ERROR_NO_TOKEN, HANDLE, LocalFree, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows_sys::Win32::Security::TOKEN_QUERY;
use windows_sys::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows_sys::Win32::System::Threading::{
    AddSIDToBoundaryDescriptor, ClosePrivateNamespace, CreateBoundaryDescriptorW,
    DeleteBoundaryDescriptor, EVENT_MODIFY_STATE, GetCurrentProcess, GetCurrentThread, OpenEventW,
    OpenPrivateNamespaceW, OpenProcessToken, OpenThreadToken, SYNCHRONIZATION_SYNCHRONIZE,
    WaitForSingleObject,
};

#[path = "../../../tests/private/fixture_namespace_primary_protocol.rs"]
pub(super) mod protocol;
use protocol::{Cell, Phase, Request, Response};
#[path = "namespace_primary_token.rs"]
mod token_readback;

fn owner(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful constructor transfers this unique kernel reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(super) fn remaining(request: &Request) -> io::Result<u32> {
    clock(request).map(|(_, millis)| millis)
}

fn clock(request: &Request) -> io::Result<(u64, u32)> {
    let mut now = 0;
    let mut frequency = 0;
    // SAFETY: both native outputs are initialized writable scalars.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if frequency <= 0
        || frequency as u64 != request.qpc_frequency
        || now < 0
        || now as u64 >= request.deadline_qpc
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original namespace experiment cutoff",
        ));
    }
    let millis =
        u128::from(request.deadline_qpc - now as u64) * 1000 / u128::from(request.qpc_frequency);
    Ok((now as u64, millis.min(u128::from(u32::MAX - 1)) as u32))
}

struct Boundary(HANDLE);
impl Drop for Boundary {
    fn drop(&mut self) {
        // SAFETY: dedicated boundary owner, not a kernel CloseHandle reference.
        unsafe { DeleteBoundaryDescriptor(self.0) };
    }
}
struct Namespace(HANDLE);
impl Namespace {
    fn close(&mut self) -> io::Result<()> {
        if !self.0.is_null() {
            // SAFETY: worker closes only its own opened reference, never destroys.
            if !unsafe { ClosePrivateNamespace(self.0, 0) } {
                return Err(io::Error::last_os_error());
            }
            self.0 = std::ptr::null_mut();
        }
        Ok(())
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        if self.close().is_err() {
            std::process::abort();
        }
    }
}

fn publish(
    request: &Request,
    phase: Phase,
    success: bool,
    error: Option<i32>,
    handle: Option<u64>,
    modify: Option<bool>,
    diagnostics: protocol::DiagnosticState,
) -> io::Result<()> {
    let mut response = Response {
        revision: protocol::REVISION,
        nonce: request.nonce.clone(),
        phase,
        success,
        raw_error: error,
        event_handle: handle,
        modify_denied: modify,
        diagnostics,
    };
    if response
        .diagnostics
        .validate_correspondence(request)
        .is_err()
    {
        response.diagnostics = protocol::DiagnosticState::Unavailable {
            reason: protocol::DiagnosticUnavailableReason::EncodingBoundOrRefused,
        };
    }
    let bytes = protocol::encode_response(&response)?;
    // Validate the exact bytes offered to the parent, including its closed phase.
    let offered = protocol::decode_response(&bytes)?;
    // Optional diagnostics may be replaced by a bounded explicit-unavailable
    // state, but the original native result must survive byte-for-byte in core.
    response.diagnostics = offered.diagnostics.clone();
    if offered != response {
        return Err(io::Error::other("experiment response encoding changed"));
    }
    if !success && matches!(phase, Phase::Namespace | Phase::Event) {
        // Independently retain/check the original failed core even when the
        // optional complete observation was replaced by an unavailable state.
        let core = protocol::decode_failure_core(&bytes)?;
        if Some(core.raw_error) != error || core.nonce != request.nonce || core.phase != phase {
            return Err(io::Error::other("original failed core encoding changed"));
        }
    }
    let mut output = io::stdout().lock();
    remaining(request)?;
    output.write_all(&bytes)?;
    output.flush()?;
    remaining(request)?;
    Ok(())
}

type SourceCapture =
    Result<protocol::SourceObservation, memcordon_windows_launch_core::ObservationUnavailable>;

fn source(
    request: &Request,
    token: &OwnedHandle,
    role: Option<protocol::SourceRole>,
) -> io::Result<SourceCapture> {
    let (started_qpc, _) = clock(request)?;
    let mut thread = std::ptr::null_mut();
    // SAFETY: query only this actual thread; any returned token is immediately owned.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread) };
    let error = io::Error::last_os_error();
    if opened != 0 {
        drop(owner(thread)?);
        return Err(io::Error::other("worker unexpectedly impersonates"));
    }
    if error.raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
        return Err(error);
    }
    let (actual, observation) = if role.is_some() {
        memcordon_windows_launch_core::query_token_envelope_with_observation(token.as_raw_handle())
            .map_err(io::Error::other)?
    } else {
        (
            memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle())
                .map_err(io::Error::other)?,
            Err(memcordon_windows_launch_core::ObservationUnavailable::NotRequested),
        )
    };
    if actual != request.expected_token
        || actual.token_type != 1
        || actual.user_sid != request.user_sid
    {
        return Err(io::Error::other(
            "restricted primary experiment token changed",
        ));
    }
    remaining(request)?;
    let default_acl = token_readback::collect(token.as_raw_handle())?;
    let default_acl_sha256 = default_acl.sha256;
    if default_acl_sha256 != request.expected_default_acl_sha256 {
        return Err(io::Error::other("restricted primary default ACL changed"));
    }
    let (finished_qpc, _) = clock(request)?;
    Ok(observation.map(|token| protocol::SourceObservation {
        role: role.expect("diagnostic observation only requested with a role"),
        started_qpc,
        finished_qpc,
        token,
        default_acl_sha256,
        no_thread_token_raw_error: error.raw_os_error().expect("admitted ERROR_NO_TOKEN"),
        default_acl_bytes: default_acl.bytes,
    }))
}

pub(super) fn run() -> io::Result<i32> {
    let mut input = io::stdin().lock();
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut input)
        .take(16 * 1024 + 1)
        .read_until(b'\n', &mut bytes)?;
    let request = protocol::decode_request(&bytes)?;
    if protocol::encode_request(&request)? != bytes {
        return Err(io::Error::other("experiment request is not canonical"));
    }
    remaining(&request)?;
    let mut token = std::ptr::null_mut();
    // SAFETY: actual process token is queried, never changed.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owner(token)?;
    let before = source(&request, &token, Some(protocol::SourceRole::BeforeOpen))?;
    let mut boundary = None;
    let mut namespace = None;
    if request.cell != Cell::Local {
        let boundary_name: Vec<u16> = request.boundary.encode_utf16().chain(Some(0)).collect();
        let alias: Vec<u16> = request.alias.encode_utf16().chain(Some(0)).collect();
        remaining(&request)?;
        // SAFETY: bounded terminated boundary name and documented flags zero.
        let raw = unsafe { CreateBoundaryDescriptorW(boundary_name.as_ptr(), 0) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut held = Boundary(raw);
        let sid_text: Vec<u16> = request.user_sid.encode_utf16().chain(Some(0)).collect();
        let mut sid = std::ptr::null_mut();
        // SAFETY: bounded canonical SID text; LocalFree owns the returned allocation.
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SID lives through this synchronous boundary update.
        let added = unsafe { AddSIDToBoundaryDescriptor(&mut held.0, sid) };
        let error = io::Error::last_os_error();
        // SAFETY: release only the ConvertStringSid allocation.
        unsafe { LocalFree(sid) };
        if added == 0 {
            return Err(error);
        }
        remaining(&request)?;
        // FIRST namespace registration in this fresh restricted-primary worker.
        // SAFETY: exact bounded alias and retained boundary; no inherited namespace.
        let raw = unsafe { OpenPrivateNamespaceW(held.0, alias.as_ptr()) };
        let error = io::Error::last_os_error();
        if raw.is_null() {
            let _ = source(&request, &token, None)?;
            publish(
                &request,
                Phase::Namespace,
                false,
                error.raw_os_error(),
                None,
                None,
                protocol::DiagnosticState::NotApplicable,
            )?;
            return Ok(0);
        }
        namespace = Some(Namespace(raw));
        boundary = Some(held);
        remaining(&request)?;
    }
    let mut name: Vec<u16> = if request.cell == Cell::Local {
        "Local\\".encode_utf16().collect()
    } else {
        request
            .alias
            .encode_utf16()
            .chain(Some(u16::from(b'\\')))
            .collect()
    };
    name.extend(request.event.encode_utf16());
    name.push(0);
    remaining(&request)?;
    // SAFETY: exact terminated name, synchronization only, noninheriting.
    let raw = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
    let error = io::Error::last_os_error();
    if raw.is_null() {
        let after = source(
            &request,
            &token,
            Some(protocol::SourceRole::AfterFailedOpen),
        )?;
        let diagnostics = match (before, after) {
            (Ok(before), Ok(after)) => protocol::DiagnosticState::Present { before, after },
            (Err(reason), _) => protocol::DiagnosticState::Unavailable {
                reason: protocol::DiagnosticUnavailableReason::Observation {
                    role: protocol::SourceRole::BeforeOpen,
                    reason,
                },
            },
            (_, Err(reason)) => protocol::DiagnosticState::Unavailable {
                reason: protocol::DiagnosticUnavailableReason::Observation {
                    role: protocol::SourceRole::AfterFailedOpen,
                    reason,
                },
            },
        };
        publish(
            &request,
            Phase::Event,
            false,
            error.raw_os_error(),
            None,
            None,
            diagnostics,
        )?;
        return Ok(0);
    }
    let event = owner(raw)?;
    let _ = source(&request, &token, None)?;
    // SAFETY: same live owner, zero-time observation must prove nonsignaled state.
    if unsafe { WaitForSingleObject(event.as_raw_handle(), 0) } != WAIT_TIMEOUT {
        return Err(io::Error::other("experiment gate was already signaled"));
    }
    remaining(&request)?;
    // SAFETY: distinct overbroad request; never use it for signaling or acceptance.
    let modify = unsafe { OpenEventW(EVENT_MODIFY_STATE, 0, name.as_ptr()) };
    let modify_error = io::Error::last_os_error();
    if !modify.is_null() {
        drop(owner(modify)?);
    }
    let denied = modify.is_null() && modify_error.raw_os_error() == Some(5);
    publish(
        &request,
        Phase::Held,
        true,
        None,
        Some(raw as usize as u64),
        Some(denied),
        protocol::DiagnosticState::NotApplicable,
    )?;
    let mut acknowledgement = Vec::new();
    std::io::Read::by_ref(&mut input)
        .take(128)
        .read_until(b'\n', &mut acknowledgement)?;
    if acknowledgement != protocol::encode_ack(&request.nonce)? {
        return Err(io::Error::other("experiment acknowledgement mismatch"));
    }
    let millis = remaining(&request)?;
    // SAFETY: finite original QPC budget and retained original event reference.
    if unsafe { WaitForSingleObject(event.as_raw_handle(), millis) } != WAIT_OBJECT_0 {
        return Err(io::Error::other("original experiment event did not signal"));
    }
    let _ = source(&request, &token, None)?;
    drop(event);
    if let Some(namespace) = &mut namespace {
        namespace.close()?;
    }
    drop(namespace);
    drop(boundary);
    publish(
        &request,
        Phase::Completed,
        true,
        None,
        None,
        Some(denied),
        protocol::DiagnosticState::NotApplicable,
    )?;
    Ok(0)
}
