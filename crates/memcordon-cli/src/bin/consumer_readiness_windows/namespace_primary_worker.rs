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
#[cfg(target_arch = "x86_64")]
#[path = "../../../tests/private/fixture_namespace_call_packet.rs"]
mod call_packet;
#[path = "../../../tests/private/fixture_namespace_ack.rs"]
mod diagnostic_ack;
#[path = "namespace_primary_modules.rs"]
mod module_readback;
#[path = "../../../tests/private/fixture_namespace_replay_protocol.rs"]
mod replay_wire;
#[cfg(target_arch = "x86_64")]
fn replay_marker(parameters: [u64; call_packet::PARAMETERS]) {
    let parameters = parameters.map(|value| value as usize);
    // SAFETY: public continuable application exception; bounded inline words.
    unsafe {
        windows_sys::Win32::System::Diagnostics::Debug::RaiseException(
            call_packet::CODE,
            0,
            parameters.len() as u32,
            parameters.as_ptr(),
        )
    };
}
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
        native_open: None,
    };
    publish_response(request, &mut response)
}

fn publish_response(request: &Request, response: &mut Response) -> io::Result<()> {
    let success = response.success;
    let phase = response.phase;
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
    if offered != *response {
        return Err(io::Error::other("experiment response encoding changed"));
    }
    if !success && matches!(phase, Phase::Namespace | Phase::Event) {
        // Independently retain/check the original failed core even when the
        // optional complete observation was replaced by an unavailable state.
        let core = protocol::decode_failure_core(&bytes)?;
        if Some(core.raw_error) != response.raw_error
            || core.nonce != request.nonce
            || core.phase != phase
        {
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
    run_request(request, None, &mut input)
}

pub(super) fn run_replay(encoded: &str) -> io::Result<i32> {
    let replay = replay_wire::decode_replay(encoded)?;
    use std::os::windows::ffi::OsStrExt;
    let argv = std::env::args_os()
        .map(|arg| arg.encode_wide().collect())
        .collect::<Vec<Vec<u16>>>();
    let mut command = memcordon_core::encode_windows_command_line(&argv);
    command.push(0);
    replay_wire::check_replay_command_line(&command)?;
    let request = replay.request.clone();
    run_request(request, Some(replay), &mut io::BufReader::new(io::empty()))
}

fn replay_result(
    replay: &replay_wire::ReplayEnvelope,
    outcome: replay_wire::ReplayOutcome,
) -> io::Result<i32> {
    let record = replay_wire::ReplayResult {
        format: "memcordon.namespace-debug-replay-result".into(),
        revision: 2,
        original_nonce: replay.original_nonce.clone(),
        replay_nonce: replay.replay_nonce.clone(),
        diagnostic_stop_qpc: replay.diagnostic_stop_qpc,
        request_sha256: replay.request_sha256.clone(),
        outcome,
        cleanup: replay_wire::ReplayCleanup::Closed,
        diagnostic_only: true,
        acceptance_authority: false,
    };
    let bytes = replay_wire::encode_replay_result(&record, replay)?;
    let _ = replay_wire::decode_replay_result(&bytes, replay)?;
    io::stdout().lock().write_all(&bytes)?;
    Ok(0)
}
fn close_replay(
    namespace: &mut Option<Namespace>,
    boundary: &mut Option<Boundary>,
) -> io::Result<()> {
    if let Some(namespace) = namespace {
        namespace.close()?;
    }
    drop(namespace.take());
    drop(boundary.take());
    Ok(())
}
fn replay_expired(
    replay: Option<&replay_wire::ReplayEnvelope>,
    request: &Request,
) -> io::Result<Option<u64>> {
    match replay {
        Some(replay) => {
            let now = clock(request)?.0;
            Ok((now >= replay.diagnostic_stop_qpc).then_some(now))
        }
        None => Ok(None),
    }
}
fn captured_before(before: Option<&SourceCapture>, stop: u64) -> Option<SourceCapture> {
    before
        .filter(|capture| match capture {
            Ok(source) => source.finished_qpc < stop,
            Err(_) => true,
        })
        .cloned()
}
fn replay_after_capture(capture: SourceCapture) -> replay_wire::ReplayAfter {
    match capture {
        Ok(observation) => replay_wire::ReplayAfter::Observed {
            observation: Box::new(observation),
        },
        Err(reason) => replay_wire::ReplayAfter::Unavailable { reason },
    }
}

fn run_request(
    request: Request,
    replay: Option<replay_wire::ReplayEnvelope>,
    mut input: &mut impl BufRead,
) -> io::Result<i32> {
    remaining(&request)?;
    let mut boundary = None;
    let mut namespace = None;
    macro_rules! before_pre_stop {
        ($before:expr) => {
            if let Some(now) = replay_expired(replay.as_ref(), &request)? {
                close_replay(&mut namespace, &mut boundary)?;
                let replay = replay.as_ref().expect("replay cutoff");
                return replay_result(
                    replay,
                    replay_wire::ReplayOutcome::CallNotAttempted {
                        reason: replay_wire::NotAttemptedReason::DiagnosticStopBeforePre,
                        observed_qpc: now,
                        before: captured_before($before, replay.diagnostic_stop_qpc),
                    },
                );
            }
        };
    }
    before_pre_stop!(None);
    let mut token = std::ptr::null_mut();
    // SAFETY: actual process token is queried, never changed.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owner(token)?;
    before_pre_stop!(None);
    let before = source(&request, &token, Some(protocol::SourceRole::BeforeOpen))?;
    before_pre_stop!(Some(&before));
    if request.cell != Cell::Local {
        let boundary_name: Vec<u16> = request.boundary.encode_utf16().chain(Some(0)).collect();
        let alias: Vec<u16> = request.alias.encode_utf16().chain(Some(0)).collect();
        remaining(&request)?;
        before_pre_stop!(Some(&before));
        // SAFETY: bounded terminated boundary name and documented flags zero.
        let raw = unsafe { CreateBoundaryDescriptorW(boundary_name.as_ptr(), 0) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        boundary = Some(Boundary(raw));
        before_pre_stop!(Some(&before));
        let sid_text: Vec<u16> = request.user_sid.encode_utf16().chain(Some(0)).collect();
        let mut sid = std::ptr::null_mut();
        // SAFETY: bounded canonical SID text; LocalFree owns the returned allocation.
        if unsafe { ConvertStringSidToSidW(sid_text.as_ptr(), &mut sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: SID lives through this synchronous boundary update.
        let added =
            unsafe { AddSIDToBoundaryDescriptor(&mut boundary.as_mut().expect("boundary").0, sid) };
        let error = io::Error::last_os_error();
        // SAFETY: release only the ConvertStringSid allocation.
        unsafe { LocalFree(sid) };
        if added == 0 {
            return Err(error);
        }
        remaining(&request)?;
        before_pre_stop!(Some(&before));
        // FIRST namespace registration in this fresh restricted-primary worker.
        // SAFETY: exact bounded alias and retained boundary; no inherited namespace.
        let raw = unsafe {
            OpenPrivateNamespaceW(boundary.as_ref().expect("boundary").0, alias.as_ptr())
        };
        let error = io::Error::last_os_error();
        if raw.is_null() {
            if let Some(replay) = &replay {
                close_replay(&mut namespace, &mut boundary)?;
                return replay_result(
                    replay,
                    replay_wire::ReplayOutcome::NamespaceFailed {
                        raw_error: error.raw_os_error().expect("native namespace error"),
                        before,
                    },
                );
            }
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
        remaining(&request)?;
    }
    before_pre_stop!(Some(&before));
    let name = replay_wire::event_name(&request)?;
    remaining(&request)?;
    let captured_name = name
        .strip_suffix(&[0])
        .expect("one owned terminator")
        .to_vec();
    let namespace_held = namespace.is_some() && boundary.is_some();
    if let Some(replay) = &replay {
        let measured: unsafe extern "system" fn(u32, i32, *const u16) -> HANDLE = OpenEventW;
        #[cfg(target_arch = "x86_64")]
        {
            let packet = call_packet::Packet::pre(&replay.replay_nonce, measured as usize as u64)?;
            before_pre_stop!(Some(&before));
            replay_marker(packet);
        }
        if let Some(now) = replay_expired(Some(replay), &request)? {
            close_replay(&mut namespace, &mut boundary)?;
            #[cfg(target_arch = "x86_64")]
            let reason = replay_wire::NotAttemptedReason::DiagnosticStopAfterPre;
            #[cfg(not(target_arch = "x86_64"))]
            let reason = replay_wire::NotAttemptedReason::DiagnosticStopBeforePre;
            return replay_result(
                replay,
                replay_wire::ReplayOutcome::CallNotAttempted {
                    reason,
                    observed_qpc: now,
                    before: Some(before),
                },
            );
        }
        // SAFETY: this is the same typed imported function whose address PRE reports.
        let raw = unsafe { measured(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
        let error = io::Error::last_os_error();
        let event = if raw.is_null() {
            None
        } else {
            Some(owner(raw)?)
        };
        let after = if replay_expired(Some(replay), &request)?.is_some() {
            replay_wire::ReplayAfter::SkippedDiagnosticStop
        } else {
            #[cfg(target_arch = "x86_64")]
            replay_marker(call_packet::Packet::post(
                &replay.replay_nonce,
                measured as usize as u64,
                !raw.is_null(),
                if raw.is_null() {
                    error.raw_os_error().expect("saved native last error") as u32
                } else {
                    0
                },
            )?);
            if replay_expired(Some(replay), &request)?.is_some() {
                replay_wire::ReplayAfter::SkippedDiagnosticStop
            } else {
                let captured = source(&request, &token, Some(protocol::SourceRole::ReplayAfter))?;
                if replay_expired(Some(replay), &request)?.is_some() {
                    replay_wire::ReplayAfter::SkippedDiagnosticStop
                } else {
                    replay_after_capture(captured)
                }
            }
        };
        drop(event);
        close_replay(&mut namespace, &mut boundary)?;
        return replay_result(
            replay,
            replay_wire::ReplayOutcome::EventReturned {
                event_open: !raw.is_null(),
                raw_error: if raw.is_null() {
                    error.raw_os_error()
                } else {
                    None
                },
                before,
                after,
            },
        );
    }
    // SAFETY: original uninstrumented path, synchronization only, noninheriting.
    let raw = unsafe { OpenEventW(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr()) };
    let error = io::Error::last_os_error();
    if raw.is_null() {
        let after = source(
            &request,
            &token,
            Some(protocol::SourceRole::AfterFailedOpen),
        )?;
        let diagnostics = match (before, after) {
            (Ok(before), Ok(after)) => protocol::DiagnosticState::Present {
                before: Box::new(before),
                after: Box::new(after),
            },
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
        let module_provenance = matches!(request.cell, Cell::Local | Cell::Private)
            .then(|| module_readback::observe(&request));
        let mut probe_owner = None;
        let mut root_owner = None;
        let native_open = if matches!(request.cell, Cell::Local | Cell::Private) {
            let probe = if remaining(&request).is_err() {
                protocol::ZeroProbe::Unavailable { deadline: true }
            } else {
                // SAFETY: exact same original terminated buffer, no rights, noninheriting.
                let probe = unsafe { OpenEventW(0, 0, name.as_ptr()) };
                let probe_error = io::Error::last_os_error();
                if probe.is_null() {
                    protocol::ZeroProbe::Failed {
                        raw_error: probe_error.raw_os_error().unwrap_or(0),
                    }
                } else {
                    probe_owner = Some(owner(probe)?);
                    protocol::ZeroProbe::Held {
                        handle: probe as usize as u64,
                    }
                }
            };
            let native_root = if request.cell == Cell::Private {
                if let Some(namespace) = namespace.as_ref() {
                    let (record, owner) =
                        super::namespace_primary_root::observe(namespace.0, &request);
                    root_owner = owner;
                    Some(record)
                } else {
                    None
                }
            } else {
                None
            };
            Some(protocol::NativeOpen {
                cell: request.cell,
                name_utf16: captured_name,
                desired_access: SYNCHRONIZATION_SYNCHRONIZE,
                inherit: false,
                probe_desired_access: 0,
                namespace_held,
                probe,
                native_root,
                module_provenance,
            })
        } else {
            None
        };
        let mut response = Response {
            revision: protocol::REVISION,
            nonce: request.nonce.clone(),
            phase: Phase::Event,
            success: false,
            raw_error: error.raw_os_error(),
            event_handle: None,
            modify_denied: None,
            diagnostics,
            native_open,
        };
        publish_response(&request, &mut response)?;
        if probe_owner.is_some() || root_owner.is_some() {
            // The controller cannot send this ACK until it receives the above
            // response, so request decoding cannot have prefetched ACK bytes.
            diagnostic_ack::read_ack(
                &mut input,
                &protocol::encode_probe_ack(&request.nonce)?,
                || {
                    let mut available = 0;
                    // SAFETY: original stdio pipe; read only after bytes are observed.
                    if unsafe {
                        windows_sys::Win32::System::Pipes::PeekNamedPipe(
                            io::stdin().as_raw_handle(),
                            std::ptr::null_mut(),
                            0,
                            std::ptr::null_mut(),
                            &mut available,
                            std::ptr::null_mut(),
                        )
                    } == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    if available == 0 {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                    Ok(available != 0)
                },
                || remaining(&request).map(|_| ()),
            )?;
            remaining(&request)?;
        }
        drop(probe_owner);
        drop(root_owner);
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
