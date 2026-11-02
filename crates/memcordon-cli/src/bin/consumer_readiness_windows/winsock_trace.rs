//! Diagnostic-only capture of the original checked WSAStartup call.
use super::winsock_trace_record::{self, Packet};
use std::{
    fmt,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

unsafe extern "C" {
    fn memcordon_wsa_trace_call(
        packet: *mut Packet,
        original: usize,
        requested: u16,
        cutoff: u64,
        frequency: u64,
    );
    fn memcordon_wsa_trace_mock(cutoff: u64, frequency: u64) -> u32;
}
#[derive(Clone, Copy)]
pub struct Context<'a> {
    pub clock: &'a super::descriptor::ControlClock,
    pub output_root: &'a Path,
    pub binding: &'a super::descriptor::controller_start::Binding,
    pub token_envelope: &'a [u8],
}
pub struct Observed {
    pub packet: Packet,
    retention: Option<io::Error>,
    binding: serde_json::Value,
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
            "{}; original-call-trace={}; trace-retention-error={:?}",
            self.original, self.summary, self.retention
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.original)
    }
}
impl Observed {
    pub fn context(self, original: io::Error) -> io::Error {
        let packet = &self.packet;
        let first = &packet.first_failure;
        let summary = serde_json::json!({
            "diagnostic_only":true,"acceptance_authority":false,"all_native_routes_observed":false,
            "original_binding":self.binding,
            "scope":"verified-original-WSAStartup-owner-normal-IAT","postcall_SPI_excluded":true,
            "stage":packet.setup_stage,"setup_error":packet.setup_error,"scope_flags":packet.scope_flags,
            "called":packet.called,"original_return":(packet.called==1).then_some(packet.original_return),"incoming_last_error":packet.incoming_error,"outgoing_last_error":packet.outgoing_error,
            "armed":packet.armed,"slots":packet.slot_count,"calls":packet.total_calls,"failures":packet.total_failures,"dropped":packet.dropped,"incomplete":packet.incomplete,
            "first_observed_failure_is_not_a_cause_claim":true,"first_failure_present":packet.first_failure_present,
            "first_failure":{"sequence":first.sequence,"operation":first.operation,"status_or_marker":first.native_status,"outgoing_error":first.outgoing_error,"access_or_memory_protection":first.desired_access,"raw_size":first.requested_size,"scalar_flags":first.scalar_flags,"name_prefix_units":&first.name[..(first.copied_name_units as usize).min(32)],"name_reported_bytes":first.reported_name_bytes,"name_flags":first.name_flags},
            "full_record":"winsock-startup-trace.json"
        });
        io::Error::new(
            original.kind(),
            Failure {
                original,
                summary,
                retention: self.retention,
            },
        )
    }
    pub fn retain(&mut self, context: &Context<'_>) {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::{
            Foundation::SetLastError, Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
        };
        // Capture is already disarmed. No catalog call is included in these records.
        let binding = context.binding;
        self.binding = serde_json::json!({"pid":binding.pid,"creation_time_100ns":binding.birth,"descriptor_sha256":binding.descriptor_sha256,
        "challenge_sha256":super::descriptor::controller_start::descriptor_digest(&binding.challenge),
        "prior_admitted_token_envelope_sha256":super::descriptor::controller_start::descriptor_digest(context.token_envelope),
        "cutoff_qpc":context.clock.work_cutoff_qpc,"qpc_frequency":context.clock.qpc_frequency,"authority":false});
        let retention=(||->io::Result<()> {
        let value=serde_json::json!({"format":"memcordon.original-winsock-startup-trace","revision":1,"original_binding":self.binding,"trace":winsock_trace_record::diagnostic(&self.packet)});
        let bytes=match bounded_bytes(&value) {
            Ok(bytes)=>bytes,
            Err(_)=>bounded_bytes(&serde_json::json!({"format":"memcordon.original-winsock-startup-trace","revision":1,"original_binding":self.binding,
                "trace_omitted_for_envelope_bound":true,"authority":false,"all_native_routes_observed":false,"called":self.packet.called,
                "original_return":(self.packet.called==1).then_some(self.packet.original_return),"setup_stage":self.packet.setup_stage,"setup_error":self.packet.setup_error,
                "incoming_last_error":self.packet.incoming_error,"outgoing_last_error":self.packet.outgoing_error,"first_failure_present":self.packet.first_failure_present,
                "first_failure_operation":self.packet.first_failure.operation,"first_failure_status_or_marker":self.packet.first_failure.native_status}))?,
        };
        let mut file=OpenOptions::new().write(true).create_new(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(context.output_root.join("winsock-startup-trace.json"))?;
        file.write_all(&bytes)?;file.sync_all()?;Ok(())
    })().err();
        self.packet.retention_error = retention
            .as_ref()
            .and_then(io::Error::raw_os_error)
            .map(|code| code as u32)
            .unwrap_or(0);
        // Restore the original API's outgoing value after all diagnostic file I/O.
        unsafe {
            SetLastError(if self.packet.called == 1 {
                self.packet.outgoing_error
            } else {
                self.packet.incoming_error
            })
        };
        self.retention = retention;
    }
}
pub fn call(original: usize, cutoff: u64, frequency: u64) -> Observed {
    let mut packet = Packet::default();
    // SAFETY: fixed private ABI checked by C/Rust layouts; immutable original
    // function address is supplied by the actual WSAStartup import.
    unsafe { memcordon_wsa_trace_call(&mut packet, original, 0x0202, cutoff, frequency) };
    Observed {
        packet,
        retention: None,
        binding: serde_json::Value::Null,
    }
}
struct Bounded(Vec<u8>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > winsock_trace_record::RECORD_BYTES - self.0.len() {
            return Err(io::Error::other("trace envelope exceeds bound"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn bounded_bytes(value: &serde_json::Value) -> io::Result<Vec<u8>> {
    let mut output = Bounded(Vec::new());
    serde_json::to_writer(&mut output, value).map_err(io::Error::other)?;
    Ok(output.0)
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
fn selfcheck_live(cutoff: u64) -> io::Result<()> {
    let mut now = 0_i64;
    // SAFETY: initialized scalar output and the same original monotonic cutoff.
    if unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut now) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if now < 0 || now as u64 >= cutoff {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original Winsock trace self-check cutoff exhausted",
        ));
    }
    Ok(())
}
fn selfcheck_token(cutoff: u64) -> io::Result<Vec<u8>> {
    selfcheck_live(cutoff)?;
    let observed = super::native::token_observation();
    let ended = selfcheck_live(cutoff);
    match (observed, ended) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(original), Ok(())) => Err(original),
        (Ok(_), Err(cutoff)) => Err(cutoff),
        (Err(original), Err(cutoff)) => Err(io::Error::new(
            original.kind(),
            QueryCutoff { original, cutoff },
        )),
    }
}
pub fn mock() -> io::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSAStartup};
    use windows_sys::Win32::System::Performance::{
        QueryPerformanceCounter, QueryPerformanceFrequency,
    };
    let mut now = 0_i64;
    let mut frequency = 0_i64;
    // SAFETY: initialized scalar outputs for this one isolated self-check clock.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0
        || unsafe { QueryPerformanceFrequency(&mut frequency) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let now = u64::try_from(now).map_err(io::Error::other)?;
    let frequency = u64::try_from(frequency).map_err(io::Error::other)?;
    if frequency == 0 {
        return Err(io::Error::other("self-check clock frequency is zero"));
    }
    let cutoff = frequency
        .checked_mul(5)
        .and_then(|ticks| now.checked_add(ticks))
        .ok_or_else(|| io::Error::other("self-check cutoff overflow"))?;
    let before = selfcheck_token(cutoff)?;
    // SAFETY: isolated CI child checks private owned functions/data only.
    let failed = unsafe { memcordon_wsa_trace_mock(cutoff, frequency) };
    if failed != 0 {
        return Err(io::Error::other(format!(
            "original WSA trace forwarding self-check {failed}"
        )));
    }
    // This is the FIRST real WSAStartup in this isolated restricted child,
    // under the same original self-check cutoff. Owned mock calls above never
    // initialize Winsock or install a process-global real IAT route.
    let observed = call(WSAStartup as *const () as usize, cutoff, frequency);
    let packet = &observed.packet;
    // Adopt a successful reference before any diagnostic allocation/query.
    let _owned = if packet.called == 1 && packet.original_return == 0 {
        Some(super::winsock_startup::acquire(
            0,
            packet.negotiated_version as u16,
            || {
                // SAFETY: owns exactly the one successful real startup reference.
                unsafe {
                    WSACleanup();
                }
            },
        )?)
    } else {
        None
    };
    let after = match selfcheck_token(cutoff) {
        Ok(value) => value,
        Err(error) => return Err(observed.context(error)),
    };
    let mut diagnostic = winsock_trace_record::diagnostic(packet);
    let intercepted = diagnostic["recent_entries"]
        .as_array()
        .is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["returned"] == 1
                    && entry["observation_incomplete"] == false
                    && entry["invalid_record"] == false
            })
        });
    let ready = packet.setup_stage == 1
        && packet.setup_error == 0
        && packet.called == 1
        && packet.armed == 1
        && packet.callbacks_complete == 1
        && packet.protections_restored == 1
        && packet.rollback_error == 0
        && packet.owner_pinned == 1
        && packet.clock_live == 1
        && diagnostic["invalid_packet"] == false
        && intercepted
        && before == after;
    if !ready {
        if serde_json::to_vec(&diagnostic)
            .map_err(io::Error::other)?
            .len()
            > 60 * 1024
        {
            diagnostic["recent_entries"] = serde_json::Value::Null;
            diagnostic["recent_entries_omitted_for_stderr_bound"] = true.into();
        }
        return Err(io::Error::other(format!(
            "actual normal-IAT Winsock forwarding self-check unavailable: {diagnostic}"
        )));
    }
    // A diagnostic-forwarding pass is deliberately NOT positive Joint/network
    // admission. The real startup return remains visible even when it is 10107.
    println!(
        "{}",
        serde_json::json!({"verified_normal_iat_boundary_observed":true,"actual_startup_return":packet.original_return,
        "workload_success_asserted":false,"all_native_routes_observed":false,"observed_entries_complete":diagnostic["observed_entries_complete"]})
    );
    Ok(())
}
