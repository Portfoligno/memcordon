//! A standalone fresh-primary experiment, never installed gate acceptance.
#![cfg(windows)]
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Authorization::*;
use windows_sys::Win32::Security::*;
use windows_sys::Win32::System::Performance::*;
use windows_sys::Win32::System::Pipes::*;
use windows_sys::Win32::System::Threading::*;

#[path = "private/fixture_namespace_authz.rs"]
mod authz_diagnostic;
#[path = "private/fixture_namespace_debug_replay.rs"]
mod debug_replay;
#[path = "private/fixture_namespace_experiment.rs"]
mod experiment;
#[path = "../src/bin/consumer_readiness_windows/fixture_default_dacl.rs"]
mod fixture_default_dacl;
#[path = "private/fixture_namespace_module_bundle.rs"]
mod module_bundle;
#[path = "../src/bin/consumer_readiness_windows/native_fixture_default_dacl.rs"]
mod native_fixture_default_dacl;
#[path = "private/fixture_namespace_primary_protocol.rs"]
mod protocol;
#[cfg(target_arch = "x86_64")]
#[path = "private/fixture_namespace_replay_protocol.rs"]
mod replay_wire;
#[path = "private/fixture_namespace_security_evidence.rs"]
mod security_evidence;
#[path = "../src/bin/consumer_readiness_windows/namespace_primary_token.rs"]
mod token_readback;
use protocol::{Cell, Phase, Request, Response};

fn owned(raw: HANDLE) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful constructors transfer one original owned reference.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}
fn live(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original experiment cutoff",
        ))
    } else {
        Ok(())
    }
}
fn wait_millis(deadline: Instant) -> io::Result<u32> {
    live(deadline)?;
    Ok(deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(u128::from(u32::MAX - 1)) as u32)
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct LocalDescriptor(HLOCAL);
impl Drop for LocalDescriptor {
    fn drop(&mut self) {
        // SAFETY: sole allocation returned by the documented SDDL converter.
        unsafe { LocalFree(self.0) };
    }
}
fn descriptor(sddl: &str) -> io::Result<LocalDescriptor> {
    let text = wide(sddl);
    let mut raw = std::ptr::null_mut();
    // SAFETY: terminated SDDL and writable output; no host descriptor is modified.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut raw,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalDescriptor(raw))
}
struct Namespace {
    handle: HANDLE,
    boundary: HANDLE,
}
impl Namespace {
    fn close(&mut self) -> io::Result<()> {
        if !self.handle.is_null() {
            // SAFETY: this owner is established only after exclusive creation.
            if !unsafe { ClosePrivateNamespace(self.handle, PRIVATE_NAMESPACE_FLAG_DESTROY) } {
                return Err(io::Error::last_os_error());
            }
            self.handle = std::ptr::null_mut();
        }
        Ok(())
    }
}
impl Drop for Namespace {
    fn drop(&mut self) {
        if self.close().is_err() {
            std::process::abort();
        }
        // SAFETY: namespace closed before releasing its dedicated boundary owner.
        unsafe { DeleteBoundaryDescriptor(self.boundary) };
    }
}
fn namespace(alias: &str, user: &str, rc: bool, deadline: Instant) -> io::Result<Namespace> {
    live(deadline)?;
    let name = wide(alias);
    // SAFETY: bounded nonce name, flags zero.
    let boundary = unsafe { CreateBoundaryDescriptorW(name.as_ptr(), 0) };
    if boundary.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut result = Namespace {
        handle: std::ptr::null_mut(),
        boundary,
    };
    let mut sid = std::ptr::null_mut();
    // SAFETY: canonical native-observed user SID, returned LocalAlloc allocation.
    if unsafe { ConvertStringSidToSidW(wide(user).as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: complete native SID and owned mutable boundary descriptor.
    let added = unsafe { AddSIDToBoundaryDescriptor(&mut result.boundary, sid) };
    let error = io::Error::last_os_error();
    // SAFETY: sole converter allocation; boundary copied the SID.
    unsafe { LocalFree(sid) };
    if added == 0 {
        return Err(error);
    }
    // GENERIC_ALL is confined to this new test namespace. It is deliberately
    // NOT represented as a least-rights production namespace policy.
    let sddl = if rc {
        format!("D:P(A;;GA;;;{user})(A;;GA;;;RC)")
    } else {
        format!("D:P(A;;GA;;;{user})")
    };
    let sd = descriptor(&sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    live(deadline)?;
    // SAFETY: exact boundary, bounded name and descriptor live through creation.
    unsafe { SetLastError(0) };
    let raw = unsafe { CreatePrivateNamespaceW(&attributes, result.boundary, name.as_ptr()) };
    let error = io::Error::last_os_error();
    if raw.is_null() {
        return Err(error);
    }
    if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
        // SAFETY: returned collision reference is ours, namespace is NOT ours to destroy.
        if !unsafe { ClosePrivateNamespace(raw, 0) } {
            std::process::abort();
        }
        return Err(error);
    }
    result.handle = raw;
    live(deadline)?;
    Ok(result)
}
fn event(name: &str, user: &str, rc: bool, deadline: Instant) -> io::Result<OwnedHandle> {
    let sddl = if rc {
        format!("D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;0x00100000;;;{user})(A;;0x00100000;;;RC)")
    } else {
        format!("D:P(A;;GA;;;OW)(A;;GA;;;SY)(A;;0x00100000;;;{user})")
    };
    let sd = descriptor(&sddl)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    live(deadline)?;
    // SAFETY: original exclusive nonsignaled event, controller retains modify rights.
    unsafe { SetLastError(0) };
    let raw = unsafe {
        CreateEventExW(
            &attributes,
            wide(name).as_ptr(),
            CREATE_EVENT_MANUAL_RESET,
            SYNCHRONIZATION_SYNCHRONIZE | EVENT_MODIFY_STATE | SYNCHRONIZATION_READ_CONTROL,
        )
    };
    let error = io::Error::last_os_error();
    let result = owned(raw)?;
    if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
        return Err(error);
    }
    live(deadline)?;
    Ok(result)
}
fn pipe(parent_reads: bool) -> io::Result<(File, OwnedHandle)> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: std::ptr::null_mut(),
        bInheritHandle: 1,
    };
    let mut read = std::ptr::null_mut();
    let mut write = std::ptr::null_mut();
    // SAFETY: writable outputs, finite capacity exceeds the maximum single frame.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 64 * 1024) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let read = owned(read)?;
    let write = owned(write)?;
    let (parent, child) = if parent_reads {
        (read, write)
    } else {
        (write, read)
    };
    // SAFETY: parent endpoint must never be inherited by any child.
    if unsafe { SetHandleInformation(parent.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((File::from(parent), child))
}
struct Child {
    process: std::sync::Arc<OwnedHandle>,
    thread: Option<OwnedHandle>,
    #[cfg(target_arch = "x86_64")]
    pid: u32,
    #[cfg(target_arch = "x86_64")]
    tid: u32,
    deadline: Instant,
    settled: bool,
}
impl Drop for Child {
    fn drop(&mut self) {
        if !self.settled {
            // SAFETY: terminate ONLY the original test-created process, never a reopened PID.
            unsafe { TerminateProcess(self.process.as_raw_handle(), 125) };
            let millis = wait_millis(self.deadline).unwrap_or(0);
            // SAFETY: cleanup is bounded by the same original cutoff; unresolved means fatal.
            if unsafe { WaitForSingleObject(self.process.as_raw_handle(), millis) } != WAIT_OBJECT_0
            {
                std::process::abort();
            }
        }
    }
}
struct Attributes(LPPROC_THREAD_ATTRIBUTE_LIST);
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: initialized attribute list backed by the still-live launch allocation.
        unsafe { DeleteProcThreadAttributeList(self.0) };
    }
}
fn launch(token: HANDLE, deadline: Instant) -> io::Result<(Child, File, File)> {
    launch_mode(token, deadline, None)
}
fn launch_mode(
    token: HANDLE,
    deadline: Instant,
    replay: Option<&str>,
) -> io::Result<(Child, File, File)> {
    let (input, child_input) = pipe(false)?;
    let (output, child_output) = pipe(true)?;
    let handles = [child_input.as_raw_handle(), child_output.as_raw_handle()];
    let mut bytes = 0;
    // SAFETY: sizing call only.
    unsafe { InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut bytes) };
    let mut allocation = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let raw = allocation.as_mut_ptr().cast();
    // SAFETY: aligned allocation covers the requested native list size.
    if unsafe { InitializeProcThreadAttributeList(raw, 1, 0, &mut bytes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let attributes = Attributes(raw);
    // SAFETY: ONLY stdin/stdout pipe endpoints are inherited. No namespace/event handles.
    if unsafe {
        UpdateProcThreadAttribute(
            raw,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            handles.as_ptr().cast_mut().cast(),
            size_of_val(&handles),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = handles[0];
    startup.StartupInfo.hStdOutput = handles[1];
    startup.StartupInfo.hStdError = handles[1];
    startup.lpAttributeList = attributes.0;
    let image = OsStr::new(env!("CARGO_BIN_EXE_memcordon-test-fixture"));
    let application: Vec<u16> = image.encode_wide().chain(Some(0)).collect();
    let mut argv = vec![
        image.encode_wide().collect(),
        if replay.is_some() {
            "namespace-primary-debug-replay"
        } else {
            "namespace-primary-experiment"
        }
        .encode_utf16()
        .collect(),
    ];
    if let Some(replay) = replay {
        argv.push(replay.encode_utf16().collect());
    }
    let mut command = memcordon_core::encode_windows_command_line(&argv);
    command.push(0);
    #[cfg(target_arch = "x86_64")]
    if replay.is_some() {
        replay_wire::check_replay_command_line(&command)
            .map_err(|_| io::Error::other("unavailable-command-line-bound"))?;
    }
    let mut info = PROCESS_INFORMATION::default();
    live(deadline)?;
    // SAFETY: exact compiled fixture image, structured argv, original restricted PRIMARY,
    // explicit stdio list, suspended creation, no inherited namespace/event capability.
    if unsafe {
        memcordon_windows_launch_core::create_process_as_user_native(
            token,
            application.as_ptr(),
            command.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | EXTENDED_STARTUPINFO_PRESENT
                | if replay.is_some() {
                    DEBUG_ONLY_THIS_PROCESS
                } else {
                    0
                },
            std::ptr::null(),
            std::ptr::null(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // A successful debug creation must transfer both documented owners before
    // any fallible postcreation work. An impossible partial transfer is fatal;
    // the precreation watchdog/default debugger-death policy owns containment.
    if replay.is_some()
        && (info.hProcess.is_null()
            || info.hProcess == INVALID_HANDLE_VALUE
            || info.hThread.is_null()
            || info.hThread == INVALID_HANDLE_VALUE)
    {
        std::process::abort();
    }
    let mut child = Child {
        process: std::sync::Arc::new(owned(info.hProcess)?),
        thread: None,
        #[cfg(target_arch = "x86_64")]
        pid: info.dwProcessId,
        #[cfg(target_arch = "x86_64")]
        tid: info.dwThreadId,
        deadline,
        settled: false,
    };
    child.thread = Some(if replay.is_some() {
        // SAFETY: successful creation transferred this checked unique owner.
        unsafe { OwnedHandle::from_raw_handle(info.hThread) }
    } else {
        owned(info.hThread)?
    });
    if replay.is_none() {
        live(deadline)?;
    }
    // SAFETY: original creation-held thread, no thread/process reopen.
    if replay.is_none()
        && unsafe { ResumeThread(child.thread.as_ref().unwrap().as_raw_handle()) } == u32::MAX
    {
        return Err(io::Error::last_os_error());
    }
    drop(attributes);
    drop(child_input);
    drop(child_output);
    Ok((child, input, output))
}
#[derive(Debug)]
struct FailureWireRefused {
    core: protocol::FailureCore,
    refusal: io::Error,
}
impl std::fmt::Display for FailureWireRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original failed operation phase={:?}; native-error={}; nonce={}; secondary diagnostic wire refused kind={:?}; frame-bytes={}; frame-sha256={}",
            self.core.phase,
            self.core.raw_error,
            self.core.nonce,
            self.refusal.kind(),
            self.core.frame_bytes,
            self.core.frame_sha256
        )
    }
}
impl std::error::Error for FailureWireRefused {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.refusal)
    }
}
fn wire_refusal(frame: &[u8], request: &Request, refusal: io::Error) -> io::Error {
    if let Ok(core) = protocol::decode_failure_core(frame) {
        if core.nonce == request.nonce {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                FailureWireRefused { core, refusal },
            );
        }
    }
    refusal
}

fn response(child: &Child, output: &mut File, request: &Request) -> io::Result<Response> {
    let mut frame = Vec::new();
    loop {
        live(child.deadline)?;
        let mut available = 0;
        // SAFETY: original stdout pipe; no blocking read until bytes are observed.
        if unsafe {
            PeekNamedPipe(
                output.as_raw_handle(),
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
        if available != 0 {
            let mut byte = [0];
            output.read_exact(&mut byte)?;
            frame.push(byte[0]);
            if frame.len() > protocol::FRAME_BOUND {
                return Err(io::Error::other("child frame exceeds bound"));
            }
            if byte[0] == b'\n' {
                let observed = protocol::decode_response(&frame)
                    .map_err(|error| wire_refusal(&frame, request, error))?;
                if protocol::encode_response(&observed)? != frame {
                    return Err(wire_refusal(
                        &frame,
                        request,
                        io::Error::other("noncanonical child frame"),
                    ));
                }
                if observed.nonce != request.nonce {
                    return Err(io::Error::other("child challenge mismatch"));
                }
                observed
                    .diagnostics
                    .validate_correspondence(request)
                    .map_err(|error| wire_refusal(&frame, request, error))?;
                return Ok(observed);
            }
        } else {
            // SAFETY: zero-time check of original process owner, not a liveness guess.
            if unsafe { WaitForSingleObject(child.process.as_raw_handle(), 0) } == WAIT_OBJECT_0 {
                return Err(io::Error::other("original child retired before response"));
            }
            std::thread::yield_now();
        }
    }
}
fn child_identity(child: &Child) -> io::Result<(u32, u64)> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: query only original process handle and native full creation time.
    if unsafe {
        GetProcessTimes(
            child.process.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((
        unsafe { GetProcessId(child.process.as_raw_handle()) },
        (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
    ))
}

fn child_source(child: &Child, request: &Request) -> io::Result<()> {
    live(child.deadline)?;
    let mut token = std::ptr::null_mut();
    // SAFETY: query ONLY the retained original creation process, never reopen a PID.
    if unsafe { OpenProcessToken(child.process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned(token)?;
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle())
            .map_err(io::Error::other)?,
        request.expected_token
    );
    assert_eq!(
        default_acl_sha256(token.as_raw_handle())?,
        request.expected_default_acl_sha256
    );
    live(child.deadline)
}

fn native_open_probe(
    child: &mut Child,
    input: &mut File,
    request: &Request,
    call: &protocol::NativeOpen,
    original: &OwnedHandle,
    wrong: &OwnedHandle,
) -> serde_json::Value {
    let expected: Vec<u16> = if request.cell == Cell::Local {
        "Local\\"
            .encode_utf16()
            .chain(request.event.encode_utf16())
            .collect()
    } else {
        request
            .alias
            .encode_utf16()
            .chain(Some(u16::from(b'\\')))
            .chain(request.event.encode_utf16())
            .collect()
    };
    let mut value = serde_json::json!({"diagnostic_only":true,"acceptance_authority":false,
        "sampling":"sequential-non-atomic","worker_call":call,
        "call_matches_request":call.cell==request.cell && call.name_utf16==expected,
        "identity_observed":false,"cleanup_observed":false});
    let zero = match call.probe {
        protocol::ZeroProbe::Held { handle } => Some(handle),
        _ => None,
    };
    let native = call.native_root.as_ref().and_then(|root| root.handle);
    value["identities"] = serde_json::json!({});
    for (source, handle) in [("zero-win32", zero), ("native-relative", native)] {
        let Some(handle) = handle else {
            continue;
        };
        let comparison = (|| -> io::Result<(bool, bool)> {
            live(child.deadline)?;
            let mut duplicate = std::ptr::null_mut();
            // SAFETY: value is owned by this original live child until the distinct ack;
            // existing creation-held PROCESS_DUP_HANDLE authority, outward SAME_ACCESS only.
            if unsafe {
                DuplicateHandle(
                    child.process.as_raw_handle(),
                    handle as usize as HANDLE,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let duplicate = owned(duplicate)?;
            live(child.deadline)?;
            // SAFETY: all three handles remain owned and live; no access rights required.
            let same = unsafe {
                CompareObjectHandles(original.as_raw_handle(), duplicate.as_raw_handle())
            } != 0;
            let different =
                unsafe { CompareObjectHandles(wrong.as_raw_handle(), duplicate.as_raw_handle()) }
                    != 0;
            live(child.deadline)?;
            Ok((same, different))
        })();
        match comparison {
            Ok((same, wrong)) => {
                value["identity_observed"] = true.into();
                value["identities"][source] =
                    serde_json::json!({"state":"observed","same_original":same,"same_wrong":wrong});
            }
            Err(error) => {
                value["identities"][source] = serde_json::json!({"state":"unavailable","raw_error":error.raw_os_error(),"deadline":error.kind()==io::ErrorKind::TimedOut});
            }
        }
    }
    if zero.is_some() || native.is_some() {
        let ack = (|| -> io::Result<()> {
            live(child.deadline)?;
            input.write_all(&protocol::encode_probe_ack(&request.nonce)?)?;
            input.flush()?;
            live(child.deadline)
        })();
        value["acknowledged"] = ack.is_ok().into();
        if ack.is_err() {
            // SAFETY: retire only the same original owned child; never reopen a PID.
            unsafe {
                TerminateProcess(child.process.as_raw_handle(), 125);
            }
        }
    }
    let waited = wait_millis(child.deadline).ok().map(|millis| {
        // SAFETY: exact original creation owner and unchanged absolute deadline.
        unsafe { WaitForSingleObject(child.process.as_raw_handle(), millis) }
    });
    value["wait_result"] = serde_json::json!(waited);
    value["wait_deadline_unavailable"] = waited.is_none().into();
    if waited == Some(WAIT_OBJECT_0) {
        child.settled = true;
        value["cleanup_observed"] = true.into();
    }
    value
}

// Optional diagnostic custody is acquired while the exact original child is
// live. It never substitutes for child_source's mandatory query-only checks.
fn child_diagnostic_token(child: &Child, request: &Request) -> io::Result<OwnedHandle> {
    live(child.deadline)?;
    let mut token = std::ptr::null_mut();
    // SAFETY: only the retained creation process is queried; no numeric PID lookup.
    if unsafe { OpenProcessToken(child.process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = owned(token)?;
    let envelope = memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle())
        .map_err(io::Error::other)?;
    if envelope != request.expected_token {
        return Err(io::Error::other(
            "diagnostic child token source binding differs",
        ));
    }
    live(child.deadline)?;
    Ok(token)
}

fn default_acl_sha256(token: HANDLE) -> io::Result<String> {
    token_readback::collect(token).map(|value| value.sha256)
}

fn thread_identity(
    deadline: Instant,
) -> io::Result<Option<(u64, u64, memcordon_core::WindowsCallerTokenEnvelopeV1)>> {
    live(deadline)?;
    let mut raw = std::ptr::null_mut();
    // SAFETY: observe only this original test thread, never install or change identity.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut raw) };
    let error = io::Error::last_os_error();
    if result == 0 {
        if error.raw_os_error() == Some(ERROR_NO_TOKEN as i32) {
            live(deadline)?;
            return Ok(None);
        }
        return Err(error);
    }
    let token = owned(raw)?;
    let mut stats = TOKEN_STATISTICS::default();
    let mut length = 0;
    live(deadline)?;
    // SAFETY: initialized fixed native statistics output and retained original token.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenStatistics,
            (&mut stats as *mut TOKEN_STATISTICS).cast(),
            size_of::<TOKEN_STATISTICS>() as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length as usize != size_of::<TOKEN_STATISTICS>() {
        return Err(io::Error::other("thread statistics extent"));
    }
    let luid = |value: LUID| (u64::from(value.HighPart as u32) << 32) | u64::from(value.LowPart);
    live(deadline)?;
    let envelope = memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle())
        .map_err(io::Error::other)?;
    live(deadline)?;
    Ok(Some((
        luid(stats.TokenId),
        luid(stats.ModifiedId),
        envelope,
    )))
}

fn event_security(
    event: &OwnedHandle,
    deadline: Instant,
) -> io::Result<security_evidence::Snapshot> {
    live(deadline)?;
    let information =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut length = 0;
    // SAFETY: sizing read of only the SAME original test-owned event descriptor.
    let sized = unsafe {
        GetKernelObjectSecurity(
            event.as_raw_handle(),
            information,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    let error = io::Error::last_os_error();
    if sized != 0 || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if length == 0 || length > 64 * 1024 {
        return Err(io::Error::other("event security size bound"));
    }
    let capacity = length;
    let mut storage = vec![0usize; (capacity as usize).div_ceil(size_of::<usize>())];
    live(deadline)?;
    // SAFETY: aligned bounded storage, same retained owner and exact information7.
    if unsafe {
        GetKernelObjectSecurity(
            event.as_raw_handle(),
            information,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if length == 0 || length > capacity {
        return Err(io::Error::other("event security returned extent"));
    }
    // SAFETY: exact admitted returned native descriptor bytes, no pointer escapes.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) };
    let result = security_evidence::Snapshot::new(bytes.to_vec(), length)?;
    live(deadline)?;
    Ok(result)
}

fn event_label(event: &OwnedHandle, deadline: Instant) -> security_evidence::LabelObservation {
    use security_evidence::{LabelObservation as O, LabelStage as S, LabelUnavailable as U};
    if live(deadline).is_err() {
        return O::Unavailable(U::Deadline {
            stage: S::BeforeSize,
        });
    }
    let mut length = 0;
    // SAFETY: LABEL information16 only on the SAME original READ_CONTROL owner;
    // no SACL information8, privilege adjustment, new open or retry.
    let sized = unsafe {
        GetKernelObjectSecurity(
            event.as_raw_handle(),
            LABEL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            0,
            &mut length,
        )
    };
    let error = io::Error::last_os_error();
    if sized != 0 {
        return O::Unavailable(U::Bound { stage: S::Size });
    }
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return O::Unavailable(U::Native {
            stage: S::Size,
            raw_error: error.raw_os_error(),
        });
    }
    if length == 0 || length as usize > security_evidence::NATIVE_BOUND {
        return O::Unavailable(U::Bound {
            stage: S::SizeBound,
        });
    }
    let capacity = length;
    let mut storage = vec![0usize; (capacity as usize).div_ceil(size_of::<usize>())];
    if live(deadline).is_err() {
        return O::Unavailable(U::Deadline {
            stage: S::BeforeRead,
        });
    }
    // SAFETY: aligned bounded writable storage, same information16 and owner.
    let read = unsafe {
        GetKernelObjectSecurity(
            event.as_raw_handle(),
            LABEL_SECURITY_INFORMATION,
            storage.as_mut_ptr().cast(),
            capacity,
            &mut length,
        )
    };
    let error = io::Error::last_os_error();
    if read == 0 {
        return O::Unavailable(U::Native {
            stage: S::Read,
            raw_error: error.raw_os_error(),
        });
    }
    if length == 0 || length > capacity {
        return O::Unavailable(U::Bound { stage: S::Extent });
    }
    // SAFETY: copy exactly the admitted returned bytes while allocation is live.
    let bytes =
        unsafe { std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), length as usize) }
            .to_vec();
    let snapshot = match security_evidence::Snapshot::label(bytes, length) {
        Ok(value) => value,
        Err(_) => {
            return O::Unavailable(U::Bound {
                stage: S::Projection,
            });
        }
    };
    if live(deadline).is_err() {
        return O::Unavailable(U::Deadline {
            stage: S::AfterRead,
        });
    }
    O::Present(snapshot)
}

#[test]
fn original_event_label_query_uses_only_each_retained_handles_read_control() -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    // SAFETY: distinct anonymous test events, no inherited or named capability.
    let readable = owned(unsafe {
        CreateEventExW(
            std::ptr::null(),
            std::ptr::null(),
            0,
            SYNCHRONIZATION_READ_CONTROL,
        )
    })?;
    let sync_only = owned(unsafe {
        CreateEventExW(
            std::ptr::null(),
            std::ptr::null(),
            0,
            SYNCHRONIZATION_SYNCHRONIZE,
        )
    })?;
    assert!(matches!(
        event_label(&readable, deadline),
        security_evidence::LabelObservation::Present(_)
    ));
    assert!(matches!(event_label(&sync_only, deadline),
        security_evidence::LabelObservation::Unavailable(security_evidence::LabelUnavailable::Native {
            raw_error: Some(error), ..
        }) if error == ERROR_ACCESS_DENIED as i32));
    live(deadline)
}

#[test]
fn fresh_restricted_primary_namespace_access_is_observed_without_inherited_gate_capabilities()
-> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut counter = 0;
    let mut frequency = 0;
    // SAFETY: capture the single native cutoff before any fixture preparation.
    if unsafe { QueryPerformanceCounter(&mut counter) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    assert!(counter > 0 && frequency > 0);
    let cutoff = (counter as u64)
        .checked_add((frequency as u64).checked_mul(30).unwrap())
        .unwrap();
    let original_thread = thread_identity(deadline)?;
    let mut primary = std::ptr::null_mut();
    // SAFETY: source is never adjusted. CreateRestrictedToken preserves handle
    // access, so the derived-only ACL preparation and primary launch require
    // ADJUST_DEFAULT and ASSIGN_PRIMARY in addition to QUERY/DUPLICATE.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY,
            &mut primary,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let primary = owned(primary)?;
    let parent_before =
        memcordon_windows_launch_core::query_token_envelope(primary.as_raw_handle())
            .map_err(io::Error::other)?;
    let parent_acl_before = default_acl_sha256(primary.as_raw_handle())?;
    let mut rc = vec![
        0usize;
        fixture_default_dacl::RESTRICTED_CODE_SID
            .len()
            .div_ceil(size_of::<usize>())
    ];
    // SAFETY: aligned storage covers the complete canonical restricted-code SID.
    unsafe {
        std::ptr::copy_nonoverlapping(
            fixture_default_dacl::RESTRICTED_CODE_SID.as_ptr(),
            rc.as_mut_ptr().cast(),
            fixture_default_dacl::RESTRICTED_CODE_SID.len(),
        )
    };
    let restricting = SID_AND_ATTRIBUTES {
        Sid: rc.as_mut_ptr().cast(),
        Attributes: 0,
    };
    let mut restricted = std::ptr::null_mut();
    // SAFETY: same installed fixture restriction recipe; source token never adjusted.
    if unsafe {
        CreateRestrictedToken(
            primary.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            0,
            std::ptr::null(),
            0,
            std::ptr::null(),
            1,
            &restricting,
            &mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let restricted = owned(restricted)?;
    native_fixture_default_dacl::prepare(primary.as_raw_handle(), restricted.as_raw_handle())?;
    let (expected, parent_prelaunch_token) =
        memcordon_windows_launch_core::query_token_envelope_with_observation(
            restricted.as_raw_handle(),
        )
        .map_err(io::Error::other)?;
    let parent_prelaunch_default_acl = token_readback::collect(restricted.as_raw_handle())?;
    let expected_acl = parent_prelaunch_default_acl.sha256.clone();
    let mut summaries = Vec::with_capacity(5);
    for cell in [
        Cell::Local,
        Cell::Private,
        Cell::NamespaceDenied,
        Cell::EventDenied,
        Cell::WrongBoundary,
    ] {
        live(deadline)?;
        let temporary = tempfile::Builder::new().prefix("mc-primary-").tempdir()?;
        let alias = temporary
            .path()
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        // tempfile supplies the exclusive random nonce; hashing only bounds its encoding.
        let digest = Sha256::digest(alias.as_bytes());
        let nonce_bytes = &digest[..size_of::<[u8; 16]>()];
        let nonce: String = nonce_bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let mut namespace = if cell == Cell::Local {
            None
        } else {
            Some(namespace(
                &alias,
                &expected.user_sid,
                cell != Cell::NamespaceDenied,
                deadline,
            )?)
        };
        if namespace.is_some() {
            assert!(namespace_collision(&alias, &expected.user_sid, deadline));
        }
        let name = if cell == Cell::Local {
            format!("Local\\{alias}")
        } else {
            format!("{alias}\\self")
        };
        let original = event(
            &name,
            &expected.user_sid,
            cell != Cell::EventDenied,
            deadline,
        )?;
        let original_security = event_security(&original, deadline)?;
        let original_label = event_label(&original, deadline);
        let wrong = event(
            &format!("Local\\{nonce}"),
            &expected.user_sid,
            true,
            deadline,
        )?;
        let request = Request {
            revision: protocol::REVISION,
            nonce: nonce.clone(),
            cell,
            alias: alias.clone(),
            boundary: if cell == Cell::WrongBoundary {
                nonce.clone()
            } else {
                alias.clone()
            },
            event: if cell == Cell::Local {
                alias.clone()
            } else {
                "self".into()
            },
            user_sid: expected.user_sid.clone(),
            deadline_qpc: cutoff,
            qpc_frequency: frequency as u64,
            expected_token: expected.clone(),
            expected_default_acl_sha256: expected_acl.clone(),
        };
        let (mut child, mut input, mut output) = launch(restricted.as_raw_handle(), deadline)?;
        let identity = child_identity(&child)?;
        assert!(identity.0 != 0 && identity.1 != 0);
        child_source(&child, &request)?;
        let diagnostic_token = child_diagnostic_token(&child, &request);
        let frame = protocol::encode_request(&request)?;
        assert_eq!(protocol::decode_request(&frame)?, request);
        input.write_all(&frame)?;
        input.flush()?;
        let observed = response(&child, &mut output, &request)?;
        // The mandatory pre-request child_source readback established both
        // bindings; the worker also validates them before its original API.
        // Optional replay/diagnostic evidence never classifies this outcome.
        let outcome = experiment::classify_original(
            &request,
            &observed,
            experiment::Binding {
                initial_identity: identity,
                current_identity: child_identity(&child)?,
                token_matches: true,
                default_acl_matches: true,
            },
        )?;
        if !observed.success {
            // Read only the original READ_CONTROL owner after the unchanged
            // failed native open. Never reopen by name or replace its outcome.
            let post_failure = if observed.phase == Phase::Event {
                match event_security(&original, deadline) {
                    Ok(snapshot) => security_evidence::ReadbackObservation::Present(snapshot),
                    Err(error) => security_evidence::ReadbackObservation::Unavailable {
                        raw_error: error.raw_os_error(),
                        deadline: error.kind() == io::ErrorKind::TimedOut,
                    },
                }
            } else {
                security_evidence::ReadbackObservation::NotRequested
            };
            let native_probe = observed.native_open.as_ref().map(|call| {
                native_open_probe(&mut child, &mut input, &request, call, &original, &wrong)
            });
            // Passive disk provenance is optional and starts only after the
            // original child has released its diagnostic handles and settled.
            if child.settled {
                if let Some(provenance) = observed
                    .native_open
                    .as_ref()
                    .and_then(|call| call.module_provenance.as_ref())
                {
                    match module_bundle::capture(
                        provenance,
                        &request,
                        &observed,
                        std::path::Path::new(env!("CARGO_BIN_EXE_memcordon-test-fixture")),
                        deadline,
                    ) {
                        Ok(path) => eprintln!("passive module evidence: {}", path.display()),
                        Err(error) => eprintln!(
                            "passive module evidence unavailable: kind={:?}; raw={:?}",
                            error.kind(),
                            error.raw_os_error()
                        ),
                    }
                }
            }
            let retained = (|| -> io::Result<()> {
                live(deadline)?;
                let original_name: Vec<u16> = name.encode_utf16().collect();
                let association = security_evidence::Association {
                    request: &request,
                    response: &observed,
                    original_name: &original_name,
                    controller_handle: original.as_raw_handle() as usize as u64,
                    child_pid: identity.0,
                    child_birth: identity.1,
                    parent_prelaunch_token: &parent_prelaunch_token,
                    parent_default_acl_bytes: &parent_prelaunch_default_acl.bytes,
                    label: &original_label,
                    post_failure: &post_failure,
                };
                let mut record = security_evidence::failure(&association, &original_security)?;
                record["native_open_probe"] =
                    serde_json::to_value(&native_probe).map_err(io::Error::other)?;
                if observed.phase == Phase::Event {
                    let access = match (&diagnostic_token, &post_failure) {
                        (Ok(token), security_evidence::ReadbackObservation::Present(snapshot)) => {
                            authz_diagnostic::observe(token, &request, snapshot, deadline)
                        }
                        (Err(error), _) => {
                            security_evidence::AuthzObservation::unavailable("source-token", error)
                        }
                        _ => security_evidence::AuthzObservation::unavailable(
                            "descriptor-readback",
                            &io::Error::other("same-handle descriptor unavailable"),
                        ),
                    };
                    record["authz_descriptor_context"] =
                        serde_json::to_value(access).map_err(io::Error::other)?;
                }
                // Pretty framing preserves one typed record while keeping each
                // bounded hex chunk below the existing progress-line limit.
                let bytes = serde_json::to_vec_pretty(&record).map_err(io::Error::other)?;
                if bytes.len() > security_evidence::RECORD_BOUND {
                    return Err(io::Error::other(
                        "event security evidence record exceeds bound",
                    ));
                }
                let mut sink = io::stderr().lock();
                live(deadline)?;
                sink.write_all(&bytes)?;
                sink.write_all(b"\n")?;
                live(deadline)
            })();
            if let Err(error) = retained {
                // Diagnostic custody/render/sink failures never replace the
                // original response or bypass its unchanged strict assertions.
                // This result was already collected before rendering. Retain it
                // without a fresh live snapshot or another native call.
                if let Some(probe) = &native_probe {
                    #[derive(serde::Serialize)]
                    struct RetainedProbe<'a> {
                        format: &'static str,
                        revision: u32,
                        diagnostic_only: bool,
                        acceptance_authority: bool,
                        nonce: &'a str,
                        original_error: Option<i32>,
                        probe: &'a serde_json::Value,
                    }
                    let record = RetainedProbe {
                        format: "memcordon.native-probe-settlement",
                        revision: 1,
                        diagnostic_only: true,
                        acceptance_authority: false,
                        nonce: &request.nonce,
                        original_error: observed.raw_error,
                        probe,
                    };
                    if let Ok(bytes) = serde_json::to_vec(&record) {
                        if bytes.len() <= protocol::FRAME_BOUND {
                            let mut sink = io::stderr().lock();
                            let _ = sink.write_all(&bytes);
                            let _ = sink.write_all(b"\n");
                        }
                    }
                }
                let _ = writeln!(
                    io::stderr().lock(),
                    "fresh-primary security evidence unavailable: kind={:?}; raw={:?}",
                    error.kind(),
                    error.raw_os_error()
                );
            }
            if child.settled && matches!(cell, Cell::Private) {
                debug_replay::capture(restricted.as_raw_handle(), &request, &observed, deadline);
            }
        }
        let _ = writeln!(
            io::stderr().lock(),
            "fresh-primary cell={cell:?} original-pid={} birth={} phase={:?} success={} error={:?}",
            identity.0,
            identity.1,
            observed.phase,
            observed.success,
            observed.raw_error
        );
        let mut held_verified = false;
        if outcome == experiment::OriginalOutcome::HeldAwaitingIdentity {
            assert!(
                matches!(cell, Cell::Local | Cell::Private),
                "negative cell admitted original namespace/event"
            );
            assert_eq!(observed.modify_denied, Some(true));
            live(deadline)?;
            child_source(&child, &request)?;
            let mut duplicate = std::ptr::null_mut();
            // SAFETY: remote value comes ONLY from this original child's held live reference;
            // original creation process handle supplies PROCESS_DUP_HANDLE. No PID reopen.
            if unsafe {
                DuplicateHandle(
                    child.process.as_raw_handle(),
                    observed.event_handle.unwrap() as usize as HANDLE,
                    GetCurrentProcess(),
                    &mut duplicate,
                    0,
                    0,
                    DUPLICATE_SAME_ACCESS,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            let duplicate = owned(duplicate)?;
            assert!(
                unsafe {
                    CompareObjectHandles(original.as_raw_handle(), duplicate.as_raw_handle())
                } != 0
            );
            assert_eq!(
                unsafe { CompareObjectHandles(wrong.as_raw_handle(), duplicate.as_raw_handle()) },
                0
            );
            assert_eq!(child_identity(&child)?, identity);
            child_source(&child, &request)?;
            live(deadline)?;
            // SAFETY: only original controller event releases child; no duplicate modify rights.
            if unsafe { SetEvent(original.as_raw_handle()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            input.write_all(&protocol::encode_ack(&nonce)?)?;
            input.flush()?;
            let completed = response(&child, &mut output, &request)?;
            assert_eq!(completed.phase, Phase::Completed);
            assert!(completed.success);
            held_verified = true;
        } else {
            assert!(!observed.success);
            // Classification accepts only the exact named negative outcomes.
            // Event denial does not prove the target event DACL was reached.
            assert!(!matches!(
                outcome,
                experiment::OriginalOutcome::HeldAwaitingIdentity
            ));
        }
        // SAFETY: settle original owned process under the same absolute cutoff.
        assert_eq!(
            unsafe { WaitForSingleObject(child.process.as_raw_handle(), wait_millis(deadline)?) },
            WAIT_OBJECT_0
        );
        child.settled = true;
        live(deadline)?;
        let mut code = 0;
        if unsafe { GetExitCodeProcess(child.process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        assert_eq!(code, 0);
        assert_eq!(child_identity(&child)?, identity);
        assert_eq!(event_security(&original, deadline)?, original_security);
        assert_eq!(thread_identity(deadline)?, original_thread);
        drop(child);
        drop(input);
        drop(output);
        drop(wrong);
        drop(original);
        drop(diagnostic_token);
        if let Some(namespace) = &mut namespace {
            namespace.close()?;
        }
        drop(namespace);
        assert_eq!(
            memcordon_windows_launch_core::query_token_envelope(primary.as_raw_handle())
                .map_err(io::Error::other)?,
            parent_before
        );
        assert_eq!(
            default_acl_sha256(primary.as_raw_handle())?,
            parent_acl_before
        );
        assert_eq!(
            memcordon_windows_launch_core::query_token_envelope(restricted.as_raw_handle())
                .map_err(io::Error::other)?,
            expected
        );
        assert_eq!(
            default_acl_sha256(restricted.as_raw_handle())?,
            expected_acl
        );
        temporary.close()?;
        live(deadline)?;
        let settlement = experiment::Settlement {
            process_settled: true,
            exit_zero: true,
            identity_stable: true,
            token_and_acl_stable: true,
            event_sd_stable: true,
            thread_stable: true,
            resources_released: true,
            held_identity_and_release_verified: held_verified,
        };
        let final_outcome = experiment::complete_cell(outcome, &settlement)?;
        summaries.push(serde_json::json!({
            "cell":cell,"original_nonce":nonce,"original_pid":identity.0,"original_birth":identity.1,
            "original_phase":observed.phase,"original_success":observed.success,"original_error":observed.raw_error,
            "original_api":if observed.phase==Phase::Namespace {"OpenPrivateNamespaceW"}else{"OpenEventW"},
            "event_desired_access":if observed.phase==Phase::Namespace {None}else{Some(SYNCHRONIZATION_SYNCHRONIZE)},
            "outcome":final_outcome,"scenario_success":final_outcome.scenario_success(),
            "original_event_identity":if held_verified {"same-original-object-verified"}else{"not-reached"},
            "wrong_object_comparison":if held_verified {"distinct-original-object-verified"}else{"not-reached"},
            "event_modify_denied":observed.modify_denied,"held_release_completed":held_verified,
            "target_event_dacl_denial_cause":"unobserved","settlement":settlement
        }));
        assert!(summaries.len() <= 5);
    }
    assert_eq!(summaries.len(), 5);
    drop(restricted);
    drop(primary);
    let summary = serde_json::json!({"format":"memcordon.namespace-primary-experiment-summary","revision":1,"diagnostic_only":true,"acceptance_authority":false,"harness_integrity_verified":true,"shared_token_handles_released":true,"deadline_qpc":cutoff,"scenario_success_scope":"original event acquisition and live identity verified; every denial remains false","source_binding_scope":"creation-process token/default ACL before request; worker original-call validation; source/derived invariance at settlement","cells":summaries});
    // Keep each progress line short while retaining one bounded typed record.
    let bytes = serde_json::to_vec_pretty(&summary).map_err(io::Error::other)?;
    if bytes.len() > 8 * 1024 {
        return Err(io::Error::other(
            "five-cell experiment summary exceeds bound",
        ));
    }
    live(deadline)?;
    let mut sink = io::stderr().lock();
    sink.write_all(&bytes)?;
    sink.write_all(b"\n")?;
    live(deadline)
}
fn namespace_collision(alias: &str, user: &str, deadline: Instant) -> bool {
    namespace(alias, user, true, deadline)
        .is_err_and(|error| error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32))
}
