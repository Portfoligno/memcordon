//! Observe the original Rust constructor without transferring socket ownership.
use super::{listener_trace_record as record, winsock_trace::Context};
use std::{
    any::Any,
    ffi::c_void,
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    net::{Ipv4Addr, TcpListener},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, SetLastError},
    Networking::WinSock::{WSAGetLastError, WSASetLastError},
};

unsafe extern "C" {
    fn memcordon_listener_trace_call(
        packet: *mut record::Packet,
        request: *const record::Request,
        invoke: unsafe extern "C" fn(*mut c_void, *mut record::Outcome),
        opaque: *mut c_void,
    );
    fn memcordon_listener_trace_mock(cutoff: u64, frequency: u64) -> u32;
}

#[derive(Clone, Copy)]
struct ErrorPair {
    win32: u32,
    wsa: i32,
}
impl ErrorPair {
    fn capture() -> Self {
        // SAFETY: thread-local reads; explicit startup already succeeded here.
        let win32 = unsafe { GetLastError() };
        let wsa = unsafe { WSAGetLastError() };
        Self { win32, wsa }
    }
    fn restore(self) {
        // SAFETY: restore reachable saved values, with no API after SetLastError.
        unsafe {
            WSASetLastError(self.wsa);
            SetLastError(self.win32);
        }
    }
}

#[derive(Default)]
struct Invocation {
    result: Option<io::Result<TcpListener>>,
    panic: Option<Box<dyn Any + Send>>,
    invoked: bool,
}

#[inline(never)]
unsafe extern "C" fn invoke_listener(opaque: *mut c_void, outcome: *mut record::Outcome) {
    // SAFETY: synchronous private ABI lends these two complete Rust-owned slots.
    let state = unsafe { &mut *opaque.cast::<Invocation>() };
    let outcome = unsafe { &mut *outcome };
    if state.invoked {
        return; // Never repeat original work if the native contract is violated.
    }
    state.invoked = true;
    let returned = catch_unwind(AssertUnwindSafe(|| {
        let result = TcpListener::bind((Ipv4Addr::LOCALHOST, 0));
        let errors = ErrorPair::capture();
        (result, errors)
    }));
    let errors = match returned {
        Ok((result, errors)) => {
            outcome.kind = if result.is_ok() { 1 } else { 2 };
            if let Some(code) = result.as_ref().err().and_then(io::Error::raw_os_error) {
                outcome.raw_error_present = 1;
                outcome.raw_error = code;
            }
            state.result = Some(result); // The original Rust listener/error, never raw adoption.
            errors
        }
        Err(payload) => {
            let errors = ErrorPair::capture();
            outcome.kind = 3;
            state.panic = Some(payload);
            errors
        }
    };
    errors.restore();
}

fn live(clock: &super::descriptor::ControlClock) -> io::Result<()> {
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
    invocation: Invocation,
    process_token: serde_json::Value,
    effective_token: serde_json::Value,
    outgoing: ErrorPair,
}
impl Captured {
    fn take_result(&mut self) -> io::Result<TcpListener> {
        if let Some(payload) = self.invocation.panic.take() {
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
            .result
            .take()
            .expect("native listener callback must publish its original result")
    }
}
fn capture(clock: &super::descriptor::ControlClock) -> Captured {
    // This must precede token queries, hashing, allocation and native setup.
    let incoming = ErrorPair::capture();
    let request = record::Request {
        cutoff_qpc: clock.work_cutoff_qpc,
        frequency: clock.qpc_frequency,
        incoming_win32: incoming.win32,
        incoming_wsa: incoming.wsa,
    };
    let mut packet = record::Packet::default();
    let mut invocation = Invocation::default();
    let process_token = token(clock, false);
    let effective_token = token(clock, true);
    // SAFETY: fixed asserted ABI, private non-unwinding callback and stack slots
    // live throughout this synchronous call. C++ never receives socket ownership.
    unsafe {
        memcordon_listener_trace_call(
            &mut packet,
            &request,
            invoke_listener,
            (&mut invocation as *mut Invocation).cast(),
        );
    }
    let outgoing = ErrorPair::capture();
    Captured {
        packet,
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
fn retain(context: &Context<'_>, capture: &Captured) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    live(context.clock)?;
    let binding = context.binding;
    let envelope = record::bounded(serde_json::json!({
        "format":"memcordon.original-rust-listener-trace","revision":1,
        "original_binding":{"pid":binding.pid,"creation_time_100ns":binding.birth,
            "descriptor_sha256":binding.descriptor_sha256,
            "challenge_sha256":super::descriptor::controller_start::descriptor_digest(&binding.challenge),
            "prior_admitted_token_envelope_sha256":super::descriptor::controller_start::descriptor_digest(context.token_envelope),
            "current_process_token":capture.process_token,"current_effective_token":capture.effective_token,
            "cutoff_qpc":context.clock.work_cutoff_qpc,"qpc_frequency":context.clock.qpc_frequency,
            "authority":false},"trace":record::diagnostic(&capture.packet)
    }));
    let mut bytes = Bounded(Vec::new());
    serde_json::to_writer(&mut bytes, &envelope).map_err(io::Error::other)?;
    live(context.clock)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(context.output_root.join("listener-call-trace.json"))?;
    file.write_all(&bytes.0)?;
    file.sync_all()
}

#[derive(Debug)]
struct Failure {
    original: io::Error,
    summary: serde_json::Value,
    retention: Option<io::Error>,
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}; original-listener-trace={}; trace-retention-error={:?}",
            self.original, self.summary, self.retention
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

pub fn bind(context: Option<&Context<'_>>) -> io::Result<TcpListener> {
    let Some(context) = context else {
        return TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(super::native::tcp_bind_failure);
    };
    let mut captured = capture(context.clock);
    let retention = retain(context, &captured).err();
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
                summary: summary(&captured.packet),
                retention,
            },
        )
    });
    captured.outgoing.restore();
    result
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
    // SAFETY: private mock originals are tested before any real listener IAT publication.
    let failed = unsafe { memcordon_listener_trace_mock(cutoff, frequency) };
    if failed != 0 {
        return Err(io::Error::other(format!(
            "listener native forwarding selfcheck {failed}"
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
                retention: None,
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
                retention: None,
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
