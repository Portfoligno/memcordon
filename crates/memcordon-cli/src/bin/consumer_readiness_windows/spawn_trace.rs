//! Observe exactly the existing original peer spawn; Rust retains every result.
use super::{
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

pub fn spawn(command: &mut Command, context: Option<&Context<'_>>) -> io::Result<Child> {
    let Some(context) = context else {
        return command.spawn();
    };
    // Save before allocation, setup or hashing, as for the listener observer.
    let incoming = ErrorPair::capture();
    let request = Request {
        cutoff_qpc: context.clock.work_cutoff_qpc,
        frequency: context.clock.qpc_frequency,
        incoming_win32: incoming.win32,
        incoming_wsa: incoming.wsa,
        experiment_flags: u32::from(context.provider_input_experiment),
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
    let outgoing = ErrorPair::capture();
    let retained = retain(context, &packet, &invocation);
    if let Err(error) = retained {
        // A diagnostic publication failure never replaces an original io::Error
        // or drops an original successful Child before the existing owner flow.
        let _ = writeln!(
            io::stderr().lock(),
            "peer spawn trace retention unavailable (diagnostic only): {error}"
        );
    }
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
