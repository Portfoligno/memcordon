//! Observe the original Rust constructor without transferring socket ownership.
use super::{listener_trace_record as record, native_file_trace_record, winsock_trace::Context};
use std::{
    ffi::c_void,
    fmt,
    fs::OpenOptions,
    io::{self, Read, Seek, Write},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError},
    Networking::WinSock::{WSAGetLastError, WSASetLastError},
};

unsafe extern "C" {
    fn memcordon_listener_native_file_trace_call(
        packet: *mut record::Packet,
        request: *const record::Request,
        invoke: unsafe extern "C" fn(*mut c_void, *mut record::Outcome),
        opaque: *mut c_void,
        native_files: *mut native_file_trace_record::Packet,
    );
    fn memcordon_listener_trace_mock(cutoff: u64, frequency: u64) -> u32;
    fn memcordon_native_file_trace_mock(cutoff: u64, frequency: u64) -> u32;
}

#[derive(Clone, Copy)]
pub(super) struct ErrorPair {
    pub(super) win32: u32,
    pub(super) wsa: i32,
}
impl ErrorPair {
    pub(super) fn capture() -> Self {
        // SAFETY: thread-local reads; explicit startup already succeeded here.
        let win32 = unsafe { GetLastError() };
        let wsa = unsafe { WSAGetLastError() };
        Self { win32, wsa }
    }
    pub(super) fn restore(self) {
        // SAFETY: restore reachable saved values, with no API after SetLastError.
        unsafe {
            WSASetLastError(self.wsa);
            SetLastError(self.win32);
        }
    }
}

#[derive(Default)]
struct Invocation {
    original: super::original_listener_result::Invocation<OriginalSocket>,
    connect: Option<SocketAddrV4>,
}

#[inline(never)]
unsafe extern "C" fn invoke_listener(opaque: *mut c_void, outcome: *mut record::Outcome) {
    // SAFETY: synchronous private ABI lends these two complete Rust-owned slots.
    let state = unsafe { &mut *opaque.cast::<Invocation>() };
    let outcome = unsafe { &mut *outcome };
    if state.original.invoked() {
        return; // Never repeat original work if the native contract is violated.
    }
    let connect = state.connect;
    let returned = state.original.invoke_once(|| {
        let result = match connect {
            Some(address) => TcpStream::connect(address).map(OriginalSocket::Stream),
            None => TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map(OriginalSocket::Listener),
        };
        let errors = ErrorPair::capture();
        (result, errors)
    });
    let errors = match returned {
        super::original_listener_result::InvokeOutcome::Returned(errors) => {
            let result = state.original.result_ref().expect("original result stored");
            outcome.kind = if result.is_ok() { 1 } else { 2 };
            if let Some(code) = result.as_ref().err().and_then(io::Error::raw_os_error) {
                outcome.raw_error_present = 1;
                outcome.raw_error = code;
            }
            errors
        }
        super::original_listener_result::InvokeOutcome::Panicked => {
            let errors = ErrorPair::capture();
            outcome.kind = 3;
            errors
        }
        super::original_listener_result::InvokeOutcome::AlreadyInvoked => return,
    };
    errors.restore();
}

enum OriginalSocket {
    Listener(TcpListener),
    Stream(TcpStream),
}

pub(super) fn live(clock: &super::descriptor::ControlClock) -> io::Result<()> {
    let mut now = 0i64;
    let mut frequency = 0i64;
    // SAFETY: initialized fixed outputs; no change to the original clock.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut now) } == 0
        || unsafe {
            windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut frequency)
        } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if now < 0 || frequency <= 0 || frequency as u64 != clock.qpc_frequency {
        return Err(io::Error::other("listener observation clock differs"));
    }
    if now as u64 >= clock.work_cutoff_qpc {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original listener cutoff exhausted",
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct QueryCutoff {
    original: io::Error,
    cutoff: io::Error,
}
impl fmt::Display for QueryCutoff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; original-cutoff-check={}",
            self.original, self.cutoff
        )
    }
}
impl std::error::Error for QueryCutoff {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn checked_token(clock: &super::descriptor::ControlClock, effective: bool) -> io::Result<Vec<u8>> {
    live(clock)?;
    let observed = if effective {
        super::native::effective_token_observation()
    } else {
        super::native::token_observation()
    };
    let ended = live(clock);
    match (observed, ended) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(original), Ok(())) => Err(original),
        (Ok(_), Err(error)) => Err(error),
        (Err(original), Err(cutoff)) => Err(io::Error::new(
            original.kind(),
            QueryCutoff { original, cutoff },
        )),
    }
}
fn token(clock: &super::descriptor::ControlClock, effective: bool) -> serde_json::Value {
    let observed = checked_token(clock, effective);
    match observed {
        Ok(bytes) => {
            serde_json::json!({"sha256":super::descriptor::controller_start::descriptor_digest(&bytes),"error":null,"observation":"before_original_call"})
        }
        Err(error) => {
            let text = error.to_string();
            let mut end = text.len().min(2048);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            serde_json::json!({"sha256":null,"error":&text[..end],"error_truncated":end!=text.len(),"observation":"unavailable_before_original_call"})
        }
    }
}

struct Captured {
    packet: record::Packet,
    native_files: native_file_trace_record::Packet,
    loader_policies: Option<serde_json::Value>,
    loader_context: Option<serde_json::Value>,
    invocation: Invocation,
    process_token: serde_json::Value,
    effective_token: serde_json::Value,
    outgoing: ErrorPair,
}
impl Captured {
    fn take_result(&mut self) -> io::Result<TcpListener> {
        if let Some(payload) = self.invocation.original.take_panic() {
            self.outgoing.restore();
            resume_unwind(payload);
        }
        if self.packet.called == 0 {
            return Err(
                if self.packet.setup_stage == 2 && self.packet.setup_error != 0 {
                    io::Error::from_raw_os_error(self.packet.setup_error as i32)
                } else {
                    io::Error::other(
                        "original listener callback was not invoked without an admitted clock failure",
                    )
                },
            );
        }
        self.invocation
            .original
            .take_result()
            .expect("native listener callback must publish its original result")
            .map(|socket| match socket {
                OriginalSocket::Listener(listener) => listener,
                OriginalSocket::Stream(_) => unreachable!("bind callback returned stream"),
            })
    }
}
fn capture(clock: &super::descriptor::ControlClock) -> Captured {
    capture_call(clock, None, false)
}
fn capture_call(
    clock: &super::descriptor::ControlClock,
    connect: Option<SocketAddrV4>,
    experiment: bool,
) -> Captured {
    // This must precede token queries, hashing, allocation and native setup.
    let incoming = ErrorPair::capture();
    let request = record::Request {
        cutoff_qpc: clock.work_cutoff_qpc,
        frequency: clock.qpc_frequency,
        incoming_win32: incoming.win32,
        incoming_wsa: incoming.wsa,
        experiment_flags: u32::from(experiment),
        reserved: 0,
    };
    let mut packet = record::Packet::default();
    let mut native_files = native_file_trace_record::Packet::default();
    let mut invocation = Invocation {
        connect,
        ..Invocation::default()
    };
    let process_token = token(clock, false);
    let effective_token = token(clock, true);
    let loader_policies = experiment.then(|| super::provider_loader_policy_native::capture(clock));
    let loader_context = experiment
        .then(|| super::provider_loader_context_native::capture(clock, connect.is_some()));
    // SAFETY: fixed asserted ABI, private non-unwinding callback and stack slots
    // live throughout this synchronous call. C++ never receives socket ownership.
    unsafe {
        memcordon_listener_native_file_trace_call(
            &mut packet,
            &request,
            invoke_listener,
            (&mut invocation as *mut Invocation).cast(),
            &mut native_files,
        );
    }
    let outgoing = ErrorPair::capture();
    Captured {
        packet,
        native_files,
        loader_policies,
        loader_context,
        invocation,
        process_token,
        effective_token,
        outgoing,
    }
}

struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > record::RECORD_BYTES.saturating_sub(self.0.len()) {
            return Err(io::Error::other("listener trace envelope exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn retain(
    context: &Context<'_>,
    capture: &Captured,
    security: Option<serde_json::Value>,
) -> io::Result<()> {
    // Each finite carrier gets its own publication attempt. A companion failure
    // must not hide the existing listener record, or replace the original call.
    let listener = retain_listener(context, capture, security);
    let native_files = retain_native_files(context, capture);
    match (listener, native_files) {
        (Err(listener), Err(native_files)) => Err(io::Error::new(
            listener.kind(),
            format!(
                "listener trace retention: {listener}; native file request retention: {native_files}"
            ),
        )),
        (Err(error), _) | (_, Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn retain_native_files(context: &Context<'_>, capture: &Captured) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    live(context.clock)?;
    let binding = context.binding;
    let bytes = native_file_trace_record::bounded(serde_json::json!({
        "format":"memcordon.original-native-file-requests","revision":1,
        "original_binding":{"pid":binding.pid,"creation_time_100ns":binding.birth,
            "descriptor_sha256":binding.descriptor_sha256,
            "challenge_sha256":super::descriptor::controller_start::descriptor_digest(&binding.challenge),
            "cutoff_qpc":context.clock.work_cutoff_qpc,"qpc_frequency":context.clock.qpc_frequency,
            "peer":context.peer,"authority":false},
        "trace":native_file_trace_record::diagnostic(&capture.native_files),
        "provider_loader_policies":capture.loader_policies.clone().map(|snapshot|super::provider_loader_policy::bind(snapshot,binding.pid,binding.birth)),
        "provider_loader_context":capture.loader_context.clone().map(|snapshot|super::provider_loader_context::bind(snapshot,binding.pid,binding.birth)),
        "acceptance_authority":false
    }))?;
    live(context.clock)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(context.output_root.join(if context.peer {
            "peer-listener-native-file-requests.json"
        } else {
            "listener-native-file-requests.json"
        }))?;
    file.write_all(&bytes)?;
    file.sync_all()
}

fn retain_listener(
    context: &Context<'_>,
    capture: &Captured,
    security: Option<serde_json::Value>,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    live(context.clock)?;
    let binding = context.binding;
    let mut trace = record::diagnostic(&capture.packet);
    trace["original_rust_operation"] = serde_json::json!(if context.peer {
        "TcpStream::connect"
    } else {
        "TcpListener::bind"
    });
    let envelope = record::bounded(serde_json::json!({
        "format":"memcordon.original-rust-listener-trace","revision":1,
        "original_binding":{"pid":binding.pid,"creation_time_100ns":binding.birth,
            "descriptor_sha256":binding.descriptor_sha256,
            "challenge_sha256":super::descriptor::controller_start::descriptor_digest(&binding.challenge),
            "prior_token_observation_sha256":super::descriptor::controller_start::descriptor_digest(context.token_envelope),
            "prior_token_observation_scope":if context.peer {"peer-before-authenticated-start"} else {"root-admitted-token-envelope"},
            "prior_admitted_token_envelope_sha256":(!context.peer).then(||super::descriptor::controller_start::descriptor_digest(context.token_envelope)),
            "current_process_token":capture.process_token,"current_effective_token":capture.effective_token,
            "cutoff_qpc":context.clock.work_cutoff_qpc,"qpc_frequency":context.clock.qpc_frequency,
            "authority":false},"trace":trace,"post_original_loader_security":security
    }));
    let mut bytes = Bounded(Vec::new());
    serde_json::to_writer(&mut bytes, &envelope).map_err(io::Error::other)?;
    live(context.clock)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(context.output_root.join(if context.peer {
            "peer-listener-call-trace.json"
        } else {
            "listener-call-trace.json"
        }))?;
    file.write_all(&bytes.0)?;
    file.sync_all()
}

#[derive(Debug)]
struct Failure {
    original: io::Error,
    refusal: Option<record::OriginalRefusal>,
    application: Option<super::original_listener_result::OriginalListenerIoFailure>,
    application_retention: Option<io::Error>,
    summary: serde_json::Value,
    retention: Option<io::Error>,
}

pub(super) fn original_application_failure(
    error: &(dyn std::error::Error + 'static),
) -> Option<super::original_listener_result::OriginalListenerIoFailure> {
    let mut source = Some(error);
    while let Some(error) = source {
        if let Some(failure) = error.downcast_ref::<Failure>() {
            return failure.application;
        }
        // io::Error::source skips its custom error itself; inspect get_ref so
        // the typed same-call capture cannot disappear from this traversal.
        source = error
            .downcast_ref::<io::Error>()
            .and_then(io::Error::get_ref)
            .map(|inner| inner as &(dyn std::error::Error + 'static))
            .or_else(|| error.source());
    }
    None
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; original-listener-trace={}; precise-native-refusal={:?}; trace-retention-error={:?}; original-application-observation-error={:?}",
            self.original, self.summary, self.refusal, self.retention, self.application_retention
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
fn summary(packet: &record::Packet) -> serde_json::Value {
    let first = &packet.first_failure;
    let name = match first.operation {
        1 => "WSAStartup",
        2 => "WSASocketW",
        3 => "SetHandleInformation",
        4 => "bind",
        5 => "listen",
        6 => "closesocket",
        7 => "WSACleanup",
        _ => "unobserved",
    };
    let mut value = serde_json::json!({"diagnostic_only":true,"acceptance_authority":false,"global_routes_complete":false,
        "packet_version":packet.version,"original_thread":packet.original_thread,"frequency":packet.frequency,"cutoff_qpc":packet.cutoff_qpc,
        "called":packet.called,"aggregate_outcome":packet.callback_outcome,"aggregate_raw_error":(packet.callback_raw_error_present==1).then_some(packet.callback_raw_error),
        "setup_stage":packet.setup_stage,"setup_error":packet.setup_error,"installed_mask":packet.published_mask,"entered_mask":packet.entered_mask,"returned_mask":packet.returned_mask,
        "calls":packet.total_calls,"failures":packet.total_failures,"dropped":packet.dropped,"overflow":packet.overflow,"incomplete":packet.incomplete,
        "returned_module":{"selected":packet.returned_module.selected,"armed":packet.returned_module.armed,"setup_stage":packet.returned_module.setup_stage,"setup_error":packet.returned_module.setup_error,"setup_reason":packet.returned_module.setup_reason,"calls":packet.returned_module.dependencies.total_calls,"failures":packet.returned_module.dependencies.total_failures,"incomplete":packet.returned_module.incomplete},
        "loader_owner":{"selected":packet.loader_owner.selected,"armed":packet.loader_owner.armed,"setup_stage":packet.loader_owner.setup_stage,"setup_error":packet.loader_owner.setup_error,"setup_reason":packet.loader_owner.setup_reason,"calls":packet.loader_owner.dependencies.total_calls,"failures":packet.loader_owner.dependencies.total_failures,"incomplete":packet.loader_owner.incomplete,"scope":"verified original LoadLibraryExW owner normal imports during the original call only","acceptance_authority":false},
        "first_observed_failure":{"present":packet.first_failure_present,"operation":name,"result":first.result,"domain":first.error_domain,"win32_error":first.outgoing_win32,"wsa_error":first.outgoing_wsa},
        "first_observed_failure_is_decisive_cause":false,"full_record":"listener-call-trace.json"});
    let timing = record::loader_window_summary(packet);
    value["loader_owner"]
        .as_object_mut()
        .expect("loader summary object")
        .extend(timing.as_object().expect("loader timing object").clone());
    value
}

fn retain_original_observation(
    context: &Context<'_>,
    captured: &Captured,
    witness: super::original_listener_result::OriginalListenerIoFailure,
) -> io::Result<()> {
    use super::descriptor::original_listener_observation as observation;
    use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_RENAME_INFO, FileRenameInfo,
        SetFileInformationByHandle,
    };
    if context.peer {
        return Err(io::Error::other(
            "original listener observation requires root context",
        ));
    }
    // This is the only runtime producer: the error comes from the retained
    // original invocation, never a trace aggregate, string or process status.
    let value = observation::Observation {
        format: observation::FORMAT.into(),
        revision: observation::REVISION,
        operation: observation::Operation::TcpListenerBind,
        domain: observation::ErrorDomain::RustIoRawOsErrorOnWindows,
        raw_os_error: witness.raw_os_error(),
        binding: observation::Binding {
            pid: context.binding.pid,
            birth: context.binding.birth,
            descriptor_sha256: context.binding.descriptor_sha256,
            challenge_sha256: super::descriptor::controller_start::descriptor_digest(
                &context.binding.challenge,
            ),
            token_sha256: super::descriptor::controller_start::descriptor_digest(
                context.token_envelope,
            ),
            thread: captured.packet.original_thread,
            started_qpc: captured.packet.started_qpc,
            finished_qpc: captured.packet.finished_qpc,
            cutoff_qpc: context.clock.work_cutoff_qpc,
            frequency: context.clock.qpc_frequency,
        },
        ipv4: [127, 0, 0, 1],
        port: 0,
    };
    let bytes = observation::encode(&value)?;
    let final_path = context.output_root.join(observation::LEAF);
    let wide: Vec<_> = final_path.as_os_str().encode_wide().collect();
    if !final_path.is_absolute() || wide.len() > 32767 || wide.contains(&0) {
        return Err(io::Error::other(
            "original listener final path is not bounded native UTF16",
        ));
    }
    let name_bytes = wide
        .len()
        .checked_mul(2)
        .ok_or_else(|| io::Error::other("original listener rename length overflow"))?;
    let extent = std::mem::offset_of!(FILE_RENAME_INFO, FileName)
        .checked_add(name_bytes)
        .ok_or_else(|| io::Error::other("original listener rename extent overflow"))?;
    let mut rename = vec![0usize; extent.div_ceil(std::mem::size_of::<usize>())];
    let info = rename.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: owned pointer-aligned storage covers the complete bounded native
    // filename. Zero initialization selects no replacement and no root handle.
    unsafe {
        (*info).FileNameLength = u32::try_from(name_bytes).map_err(io::Error::other)?;
        std::ptr::copy_nonoverlapping(
            wide.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            wide.len(),
        );
    }
    live(context.clock)?;
    let mut owner = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | 0x0001_0000)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(final_path.with_extension("observation-pending"))?;
    owner.write_all(&bytes)?;
    owner.sync_all()?;
    live(context.clock)?;
    owner.rewind()?;
    let mut readback = Vec::new();
    (&mut owner)
        .take(observation::MAX_BYTES as u64 + 1)
        .read_to_end(&mut readback)?;
    if readback != bytes {
        return Err(io::Error::other(
            "original listener observation owned readback differs",
        ));
    }
    live(context.clock)?;
    // Final visibility is the commit. Every fallible data/clock/readback step
    // precedes it; a known failed publication cannot leave an accepted leaf.
    // SAFETY: original owned file handle and the complete live native buffer.
    if unsafe {
        SetFileInformationByHandle(
            owner.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            u32::try_from(extent).map_err(io::Error::other)?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn bind(context: Option<&Context<'_>>) -> io::Result<TcpListener> {
    let Some(context) = context else {
        return TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(super::native::tcp_bind_failure);
    };
    let mut captured = capture_call(context.clock, None, context.provider_input_experiment);
    // Freeze only the owned original result, before optional diagnostics. The
    // callback packet supplies context agreement, not an internal-call census.
    // SAFETY: this no-argument query observes only the current calling thread.
    let expected_thread = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
    let application = captured.invocation.original.freeze_listener_failure(
        &super::original_listener_result::CallbackProof {
            operation: if captured.invocation.connect.is_some() {
                super::original_listener_result::Operation::TcpStreamConnect
            } else {
                super::original_listener_result::Operation::TcpListenerBind
            },
            version: captured.packet.version,
            called: captured.packet.called,
            clock_live: captured.packet.clock_live,
            callback_outcome: captured.packet.callback_outcome,
            raw_error_present: captured.packet.callback_raw_error_present,
            raw_error: captured.packet.callback_raw_error,
            original_thread: captured.packet.original_thread,
            expected_thread,
            started_qpc: captured.packet.started_qpc,
            finished_qpc: captured.packet.finished_qpc,
            cutoff_qpc: captured.packet.cutoff_qpc,
            expected_cutoff_qpc: context.clock.work_cutoff_qpc,
            frequency: captured.packet.frequency,
            expected_frequency: context.clock.qpc_frequency,
        },
    );
    let application_retention = application
        .map(|witness| retain_original_observation(context, &captured, witness))
        .transpose()
        .err();
    let security = if captured
        .invocation
        .original
        .result_ref()
        .is_some_and(|result| result.is_err())
    {
        // All native scopes are disarmed. A diagnostic panic cannot replace
        // the original Rust error or transfer its socket/result ownership.
        Some(catch_unwind(AssertUnwindSafe(||super::loader_security::observe(context,&captured.packet,&captured.effective_token)))
            .unwrap_or_else(|_|serde_json::json!({"state":"unavailable","stage":"diagnostic-panicked","diagnostic_only":true,"acceptance_authority":false,"denied_object_proved":false})))
    } else {
        None
    };
    let retention = retain(context, &captured, security).err();
    let result = captured.take_result();
    if let (true, Some(error)) = (result.is_ok(), &retention) {
        let _ = writeln!(
            io::stderr().lock(),
            "listener trace retention unavailable (diagnostic only): {error}"
        );
    }
    let result = result.map_err(|original| {
        // Catalog readbacks happen only after both native collectors disarm.
        let original = super::native::tcp_bind_failure(original);
        io::Error::new(
            original.kind(),
            Failure {
                original,
                refusal: record::original_refusal(&captured.packet),
                application,
                application_retention,
                summary: summary(&captured.packet),
                retention,
            },
        )
    });
    captured.outgoing.restore();
    result
}

pub fn connect(context: &Context<'_>, address: SocketAddrV4) -> io::Result<TcpStream> {
    let mut captured = capture_call(
        context.clock,
        Some(address),
        context.provider_input_experiment,
    );
    let retention = retain(context, &captured, None).err();
    if let Some(payload) = captured.invocation.original.take_panic() {
        captured.outgoing.restore();
        resume_unwind(payload);
    }
    let result = captured
        .invocation
        .original
        .take_result()
        .unwrap_or_else(|| {
            Err(
                if captured.packet.setup_stage == 2 && captured.packet.setup_error != 0 {
                    io::Error::from_raw_os_error(captured.packet.setup_error as i32)
                } else {
                    io::Error::other("original connect callback was not invoked")
                },
            )
        })
        .map(|socket| match socket {
            OriginalSocket::Stream(stream) => stream,
            OriginalSocket::Listener(_) => unreachable!("connect callback returned listener"),
        });
    if let (true, Some(error)) = (result.is_ok(), &retention) {
        let _ = writeln!(
            io::stderr().lock(),
            "peer trace retention unavailable (diagnostic only): {error}"
        );
    }
    let result = result.map_err(|original| {
        io::Error::new(
            original.kind(),
            Failure {
                original,
                summary: summary(&captured.packet),
                refusal: None,
                application: None,
                application_retention: None,
                retention,
            },
        )
    });
    captured.outgoing.restore();
    result
}

/// Production listener setup only: no competing fixture native-file mock.
pub(super) fn composition_listener(
    clock: &super::descriptor::ControlClock,
) -> io::Result<TcpListener> {
    live(clock)?;
    let mut observed = capture(clock);
    let listener = observed.take_result().map_err(|original| {
        io::Error::new(
            original.kind(),
            Failure {
                original,
                summary: summary(&observed.packet),
                refusal: None,
                application: None,
                application_retention: None,
                retention: None,
            },
        )
    })?;
    live(clock)?;
    if observed.packet.setup_stage != 1
        || observed.packet.setup_error != 0
        || observed.packet.called != 1
        || observed.packet.armed != 1
        || observed.packet.callback_outcome != 1
        || observed.packet.protections_restored != 1
        || observed.packet.rollback_error != 0
        || observed.packet.owner_pinned != 1
        || observed.packet.returned_mask & 0x1A != 0x1A
        || record::diagnostic(&observed.packet)["invalid_packet"] != false
    {
        return Err(io::Error::other(
            "listener-before-spawn actual listener route incomplete",
        ));
    }
    Ok(listener)
}

pub fn self_check() -> io::Result<i32> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut now = 0i64;
    let mut frequency = 0i64;
    // SAFETY: fixed writable outputs for the original finite native check clock.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let frequency = u64::try_from(frequency).map_err(io::Error::other)?;
    let cutoff = u64::try_from(now)
        .map_err(io::Error::other)?
        .checked_add(
            frequency
                .checked_mul(5)
                .ok_or_else(|| io::Error::other("listener selfcheck clock overflow"))?,
        )
        .ok_or_else(|| io::Error::other("listener selfcheck cutoff overflow"))?;
    let clock = super::descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: cutoff,
        qpc_frequency: frequency,
    };
    live(&clock)?;
    let _startup = super::native::winsock_startup(None)?;
    live(&clock)?;
    let saved_errors = ErrorPair::capture();
    // SAFETY: sentinel values affect only this explicit native selfcheck thread.
    unsafe {
        WSASetLastError(29991);
        SetLastError(29992);
    }
    let expected_errors = ErrorPair::capture();
    let _policy_snapshot = super::provider_loader_policy_native::capture(&clock);
    let restored_errors = ErrorPair::capture();
    saved_errors.restore();
    if restored_errors.win32 != expected_errors.win32 || restored_errors.wsa != expected_errors.wsa
    {
        return Err(io::Error::other(
            "provider policy snapshot changed caller error state",
        ));
    }
    live(&clock)?;
    // SAFETY: private mock originals are tested before any real listener IAT publication.
    let failed = unsafe { memcordon_listener_trace_mock(cutoff, frequency) };
    if failed != 0 {
        return Err(io::Error::other(format!(
            "listener native forwarding selfcheck {failed}"
        )));
    }
    live(&clock)?;
    // SAFETY: private finite native mocks, including admitted owned-image IAT
    // routes, run only in this explicit selfcheck, never the real workload.
    let failed = unsafe { memcordon_native_file_trace_mock(cutoff, frequency) };
    if failed != 0 {
        return Err(io::Error::other(format!(
            "native file request forwarding selfcheck {failed}"
        )));
    }
    let before = checked_token(&clock, false)?;
    live(&clock)?;
    let mut first = capture(&clock);
    let listener = first.take_result().map_err(|original| {
        io::Error::new(
            original.kind(),
            Failure {
                original,
                summary: summary(&first.packet),
                refusal: None,
                retention: None,
                application: None,
                application_retention: None,
            },
        )
    })?;
    live(&clock)?;
    let address = listener.local_addr()?;
    live(&clock)?;
    let frozen = record::diagnostic(&first.packet);
    let ready = first.packet.setup_stage == 1
        && first.packet.setup_error == 0
        && first.packet.called == 1
        && first.packet.armed == 1
        && first.packet.callback_outcome == 1
        && first.packet.clock_live == 1
        && first.packet.protections_restored == 1
        && first.packet.rollback_error == 0
        && first.packet.owner_pinned == 1
        && (first.packet.returned_mask & 0x1A) == 0x1A
        && frozen["invalid_packet"] == false;
    if !ready {
        return Err(io::Error::other(format!(
            "actual listener normal-IAT route incomplete: {frozen}"
        )));
    }
    live(&clock)?;
    let duplicate = TcpListener::bind(address);
    live(&clock)?;
    if duplicate.is_ok() {
        return Err(io::Error::other("listener ownership lost after disarm"));
    }
    live(&clock)?;
    let mut second = capture(&clock);
    let second_listener = second.take_result().map_err(|original| {
        io::Error::new(
            original.kind(),
            Failure {
                original,
                summary: summary(&second.packet),
                refusal: None,
                retention: None,
                application: None,
                application_retention: None,
            },
        )
    })?;
    live(&clock)?;
    if second.packet.setup_stage != 1
        || second.packet.callback_outcome != 1
        || second.packet.returned_mask & 0x1A != 0x1A
        || record::diagnostic(&first.packet) != frozen
    {
        return Err(io::Error::other(
            "listener route reuse or disarmed packet changed",
        ));
    }
    drop(second_listener);
    drop(listener);
    live(&clock)?;
    if before != checked_token(&clock, false)? {
        return Err(io::Error::other("listener observer changed original token"));
    }
    live(&clock)?;
    Ok(0)
}
