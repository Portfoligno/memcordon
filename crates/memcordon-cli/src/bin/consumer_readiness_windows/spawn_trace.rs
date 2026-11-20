//! Observe the existing original fixture spawn; Rust retains every result.
use super::{
    descriptor::{
        ControlClock, controller_start, original_listener_observation,
        original_peer_spawn_observation,
    },
    listener_trace::ErrorPair,
    listener_trace_record::{Outcome, Request},
    spawn_trace_record as record,
    winsock_trace::Context,
};
use std::{
    any::Any,
    ffi::c_void,
    fs::OpenOptions,
    io::{self, Write},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    process::{Child, Command},
};

unsafe extern "C" {
    fn memcordon_spawn_trace_call(
        packet: *mut record::Packet,
        request: *const Request,
        invoke: unsafe extern "C" fn(*mut c_void, *mut Outcome),
        opaque: *mut c_void,
    );
    fn memcordon_spawn_trace_mock(cutoff: u64, frequency: u64) -> u32;
    fn memcordon_spawn_trace_composition_check(
        cutoff: u64,
        frequency: u64,
        packet: *mut record::Packet,
    ) -> u32;
}
struct Invocation<'a> {
    command: &'a mut Command,
    invoked: bool,
    result: Option<io::Result<Child>>,
    panic: Option<Box<dyn Any + Send>>,
    outcome: Outcome,
}

#[inline(never)]
unsafe extern "C" fn invoke(opaque: *mut c_void, outcome: *mut Outcome) {
    // SAFETY: private synchronous native call borrows these two Rust slots;
    // it never receives ownership of Command, Child, stdio or any raw handle.
    let invocation = unsafe { &mut *opaque.cast::<Invocation<'_>>() };
    let outcome = unsafe { &mut *outcome };
    if invocation.invoked {
        return;
    }
    invocation.invoked = true;
    let returned = catch_unwind(AssertUnwindSafe(|| {
        // This is the one baseline call, with unchanged command and stdio.
        // Diagnostic availability/cutoff introduces no new workload guard.
        let result = invocation.command.spawn();
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
            invocation.result = Some(result);
            errors
        }
        Err(payload) => {
            let errors = ErrorPair::capture();
            outcome.kind = 3;
            invocation.panic = Some(payload);
            errors
        }
    };
    invocation.outcome.kind = outcome.kind;
    invocation.outcome.raw_error_present = outcome.raw_error_present;
    invocation.outcome.raw_error = outcome.raw_error;
    errors.restore();
}

fn retain(
    context: &Context<'_>,
    packet: &record::Packet,
    invocation: &Invocation<'_>,
) -> io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    super::listener_trace::live(context.clock)?;
    let binding = context.binding;
    let bytes = record::bounded(serde_json::json!({
        "format":"memcordon.original-peer-spawn-trace","revision":1,
        "original_binding":{"pid":binding.pid,"creation_time_100ns":binding.birth,
            "descriptor_sha256":binding.descriptor_sha256,
            "challenge_sha256":super::descriptor::controller_start::descriptor_digest(&binding.challenge),
            "cutoff_qpc":context.clock.work_cutoff_qpc,"qpc_frequency":context.clock.qpc_frequency,"authority":false},
        "original_operation":"Command::spawn","original_call_attempted":invocation.invoked,
        "original_outcome_kind":invocation.outcome.kind,
        "original_native_error":(invocation.outcome.raw_error_present==1).then_some(invocation.outcome.raw_error),
        "original_child_returned":invocation.result.as_ref().is_some_and(Result::is_ok),
        "child_identity_or_controller_admission_proved":false,"acceptance_authority":false,
        "trace":record::diagnostic(packet)
    }))?;
    super::listener_trace::live(context.clock)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(context.output_root.join("peer-spawn-call-trace.json"))?;
    file.write_all(&bytes)?;
    super::listener_trace::live(context.clock)?;
    file.sync_all()?;
    super::listener_trace::live(context.clock)
}

fn retain_original_failure(
    context: &Context<'_>,
    packet: &record::Packet,
    invocation: &Invocation<'_>,
    grant: original_peer_spawn_observation::Grant,
    thread: u32,
) -> io::Result<()> {
    use original_peer_spawn_observation as observation;
    if !context.provider_input_experiment || context.peer {
        return Err(io::Error::other(
            "original peer spawn grant differs from private root",
        ));
    }
    let token: super::descriptor::gate_precondition::TokenObservation =
        serde_json::from_slice(context.token_envelope).map_err(io::Error::other)?;
    if !token.restricted || !invocation.invoked || invocation.panic.is_some() {
        return Ok(());
    }
    let actual = invocation
        .result
        .as_ref()
        .and_then(|result| result.as_ref().err());
    let callback = (invocation.outcome.kind == 2 && invocation.outcome.raw_error_present == 1)
        .then_some(invocation.outcome.raw_error);
    let Some(raw_os_error) = observation::original_raw_error(actual, callback) else {
        return Ok(());
    };
    if packet.version != 2
        || packet.packet_bytes as usize != record::PACKET_BYTES
        || packet.scope_attempted != 1
        || packet.scope_returned != 1
        || packet.scope_reentry != 0
        || packet.unmatched_scope != 0
        || packet.original_thread != thread
        || packet.cutoff_qpc != context.clock.work_cutoff_qpc
        || packet.frequency != context.clock.qpc_frequency
    {
        return Err(io::Error::other(
            "original peer spawn callback or clock differs",
        ));
    }
    let value = observation::Observation {
        format: observation::FORMAT.into(),
        revision: 1,
        operation: observation::Operation::CommandSpawn,
        domain: observation::ErrorDomain::RustIoRawOsErrorOnWindows,
        raw_os_error,
        binding: original_listener_observation::Binding {
            pid: context.binding.pid,
            birth: context.binding.birth,
            descriptor_sha256: context.binding.descriptor_sha256,
            challenge_sha256: controller_start::descriptor_digest(&context.binding.challenge),
            token_sha256: controller_start::descriptor_digest(context.token_envelope),
            thread,
            started_qpc: packet.started_qpc,
            finished_qpc: packet.finished_qpc,
            cutoff_qpc: packet.cutoff_qpc,
            frequency: packet.frequency,
        },
        grant,
    };
    super::listener_trace::publish_original_observation(
        context.output_root,
        context.clock,
        observation::LEAF,
        observation::MAX_BYTES,
        &observation::encode(&value)?,
    )
}

pub fn spawn(
    command: &mut Command,
    context: Option<&Context<'_>>,
    grant: Option<original_peer_spawn_observation::Grant>,
) -> io::Result<Child> {
    let Some(context) = context else {
        return command.spawn();
    };
    let (invocation, packet, thread, outgoing) = capture(
        command,
        context.clock,
        u32::from(context.provider_input_experiment),
    );
    let observation =
        grant.map(|grant| retain_original_failure(context, &packet, &invocation, grant, thread));
    if let Some(Err(error)) = observation {
        let _ = writeln!(
            io::stderr().lock(),
            "original peer spawn observation unavailable: {error}"
        );
    }
    let retained = retain(context, &packet, &invocation);
    if let Err(error) = retained {
        // A diagnostic publication failure never replaces an original io::Error
        // or drops an original successful Child before the existing owner flow.
        let _ = writeln!(
            io::stderr().lock(),
            "peer spawn trace retention unavailable (diagnostic only): {error}"
        );
    }
    finish(invocation, outgoing)
}

pub(super) fn compiler_spawn(
    command: &mut Command,
    binding: &controller_start::Binding,
    clock: &ControlClock,
) -> (io::Result<Child>, Option<u32>) {
    let (mut invocation, packet, thread, outgoing) = capture(command, clock, 0);
    let mut denied_at_flags = None;
    if let Some(Err(error)) = invocation.result.as_mut() {
        if let Some(raw) = error.raw_os_error() {
            let recorded = (invocation.outcome.kind == 2
                && invocation.outcome.raw_error_present == 1
                && invocation.outcome.raw_error == raw)
                .then(|| {
                    record::compiler_routes(
                        &packet,
                        thread,
                        clock.work_cutoff_qpc,
                        clock.qpc_frequency,
                    )
                })
                .flatten();
            let (routes, returned) = recorded.unzip();
            denied_at_flags = returned
                .flatten()
                .filter(|row| raw == 5 && row.win32_error == Some(5))
                .map(|row| row.flags);
            let marker = serde_json::json!({
                "pid":binding.pid,"birth":binding.birth,
                "descriptor_sha256":binding.descriptor_sha256,
                "challenge_sha256":controller_start::descriptor_digest(&binding.challenge),
                "cutoff_qpc":clock.work_cutoff_qpc,"frequency":clock.qpc_frequency,
                "raw_os_error":raw,"routes":routes,
            });
            let original = std::mem::replace(error, io::ErrorKind::Other.into());
            *error = super::operation_context::with_secondary(
                original,
                format!("\ncompiler-spawn-routes-v1 {marker}\n"),
            );
        }
    }
    (finish(invocation, outgoing), denied_at_flags)
}

pub(super) fn comparison_compiler_spawn(
    command: &mut Command,
    clock: &ControlClock,
) -> (io::Result<Child>, Option<record::CompilerCreateReturn>) {
    let (invocation, packet, thread, outgoing) = capture(command, clock, 0);
    let returned =
        record::compiler_routes(&packet, thread, clock.work_cutoff_qpc, clock.qpc_frequency)
            .and_then(|(_, returned)| returned);
    (finish(invocation, outgoing), returned)
}

fn capture<'a>(
    command: &'a mut Command,
    clock: &ControlClock,
    experiment_flags: u32,
) -> (Invocation<'a>, record::Packet, u32, ErrorPair) {
    // Save before allocation, setup or hashing, as for the listener observer.
    let incoming = ErrorPair::capture();
    // SAFETY: no parameters and only observes the calling thread's identity.
    let thread = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
    let request = Request {
        cutoff_qpc: clock.work_cutoff_qpc,
        frequency: clock.qpc_frequency,
        incoming_win32: incoming.win32,
        incoming_wsa: incoming.wsa,
        experiment_flags,
        reserved: 0,
    };
    let mut packet = record::Packet::default();
    let mut invocation = Invocation {
        command,
        invoked: false,
        result: None,
        panic: None,
        outcome: Outcome::default(),
    };
    // SAFETY: fixed asserted separate ABI; Rust slots remain borrowed for this
    // synchronous call and the private callback never unwinds across FFI.
    unsafe {
        memcordon_spawn_trace_call(
            &mut packet,
            &request,
            invoke,
            (&mut invocation as *mut Invocation<'_>).cast(),
        );
    }
    (invocation, packet, thread, ErrorPair::capture())
}

fn finish(mut invocation: Invocation<'_>, outgoing: ErrorPair) -> io::Result<Child> {
    if let Some(payload) = invocation.panic.take() {
        outgoing.restore();
        resume_unwind(payload);
    }
    let result = invocation.result.take().unwrap_or_else(|| {
        Err(io::Error::other(
            "original peer spawn callback was not invoked",
        ))
    });
    outgoing.restore();
    result
}

pub fn self_check(clock: &super::descriptor::ControlClock) -> io::Result<()> {
    super::listener_trace::live(clock)?;
    // SAFETY: selected private native mocks only; no extra spawn is requested.
    let failed = unsafe { memcordon_spawn_trace_mock(clock.work_cutoff_qpc, clock.qpc_frequency) };
    if failed != 0 {
        return Err(io::Error::other(format!(
            "peer spawn forwarding selfcheck {failed}"
        )));
    }
    super::listener_trace::live(clock)
}

/// Run only this observer's permanent-IAT checks in a fresh fixture process.
pub fn standalone_self_check() -> io::Result<i32> {
    self_check(&self_check_clock()?)?;
    Ok(0)
}

fn self_check_clock() -> io::Result<super::descriptor::ControlClock> {
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut now = 0i64;
    let mut frequency = 0i64;
    // SAFETY: fixed writable outputs for this finite native selfcheck clock.
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
                .ok_or_else(|| io::Error::other("peer spawn selfcheck clock overflow"))?,
        )
        .ok_or_else(|| io::Error::other("peer spawn selfcheck cutoff overflow"))?;
    Ok(super::descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: cutoff,
        qpc_frequency: frequency,
    })
}

/// A fresh process exercises the real listener-then-spawn publication order.
pub fn composition_self_check() -> io::Result<i32> {
    let clock = self_check_clock()?;
    super::listener_trace::live(&clock)?;
    let _startup = super::native::winsock_startup(None)?;
    let listener = super::listener_trace::composition_listener(&clock)?;
    super::listener_trace::live(&clock)?;
    // SAFETY: native checks only import publication and unchanged listener
    // routes; its one empty callback creates no additional application process.
    let mut packet = record::Packet::default();
    let failed = unsafe {
        memcordon_spawn_trace_composition_check(
            clock.work_cutoff_qpc,
            clock.qpc_frequency,
            &mut packet,
        )
    };
    if failed != 0 {
        let observed = record::diagnostic(&packet);
        return Err(io::Error::other(format!(
            "listener-before-spawn selfcheck {failed}; owner-stage={}; owner-error={}; first-refusal={}",
            packet.owners[0].stage, packet.owners[0].error, observed["first_setup_refusal"]
        )));
    }
    drop(listener);
    super::listener_trace::live(&clock)?;
    Ok(0)
}
