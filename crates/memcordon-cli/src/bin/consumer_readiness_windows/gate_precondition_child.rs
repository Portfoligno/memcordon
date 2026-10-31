//! A read-only named-open comparison using the retained caller token input.
//! This observation never grants target admission or proves event identity.
use super::descriptor::gate_precondition::{Input, Observation, RECORD_BYTES, TokenObservation};
use memcordon_core::WindowsCallerTokenEnvelopeV1;
use std::io::{self, Write};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::System::{
    Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
    Threading::OpenEventW,
};

fn check(input: &Input) -> io::Result<()> {
    let mut frequency = 0_i64;
    let mut now = 0_i64;
    // SAFETY: both clock functions receive writable scalar output locations.
    if unsafe { QueryPerformanceFrequency(&mut frequency) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: now is a writable scalar output location.
    if unsafe { QueryPerformanceCounter(&mut now) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if frequency <= 0
        || frequency as u64 != input.qpc_frequency
        || now < 0
        || now as u64 >= input.work_cutoff_qpc
    {
        return Err(io::Error::other(
            "gate control original cutoff expired or clock differs",
        ));
    }
    Ok(())
}

pub fn run(path: &Path, expected_envelope: &WindowsCallerTokenEnvelopeV1) -> io::Result<i32> {
    let descriptor = super::read_descriptor(path)?;
    let input = descriptor
        .gate_precondition
        .as_ref()
        .ok_or_else(|| io::Error::other("gate control input missing"))?;
    input.validate().map_err(io::Error::other)?;
    check(input)?;
    let name = descriptor
        .start_gate
        .as_ref()
        .ok_or_else(|| io::Error::other("gate control original name missing"))?;
    let mut wide: Vec<u16> = name.encode_utf16().collect();
    if wide.is_empty() || wide.len() > 32767 || wide.contains(&0) {
        return Err(io::Error::other(
            "gate control original name exceeds native bound",
        ));
    }
    let name_bytes: Vec<u8> = wide.iter().flat_map(|unit| unit.to_le_bytes()).collect();
    wide.push(0);
    let token: TokenObservation =
        serde_json::from_slice(&super::native::token_observation()?).map_err(io::Error::other)?;
    check(input)?;
    // GetCurrentProcessToken's query-only pseudo-handle observes this actual
    // primary process. It is neither owned nor duplicated into the scenario.
    let current_token = -4_isize as windows_sys::Win32::Foundation::HANDLE;
    let envelope =
        memcordon_windows_launch_core::query_token_envelope_bounded(current_token, &mut || {
            check(input).map_err(|error| error.to_string())
        })
        .map_err(io::Error::other)?;
    if token != input.expected_token || envelope != *expected_envelope {
        return Err(io::Error::other(
            "gate control actual caller token differs from retained input",
        ));
    }
    check(input)?;
    // SAFETY: exact validated original name, NUL terminated. No event handle is
    // inherited or substituted; this single request only asks for synchronize.
    let handle = unsafe { OpenEventW(0x0010_0000, 0, wide.as_ptr()) };
    let native_error = if handle.is_null() {
        // Capture the original failing call before any diagnostic or clock API.
        Some(
            io::Error::last_os_error()
                .raw_os_error()
                .ok_or_else(|| io::Error::other("gate control native error unavailable"))?,
        )
    } else {
        // SAFETY: successful OpenEventW transfers this owned reference once.
        // Close without waiting, resetting or signaling the original event.
        drop(unsafe { OwnedHandle::from_raw_handle(handle) });
        None
    };
    check(input)?;
    let observation = Observation {
        format: "memcordon.fixture-gate-precondition".into(),
        revision: 1,
        diagnostic_only: true,
        case: serde_json::to_value(descriptor.case).map_err(io::Error::other)?,
        challenge_sha256: super::descriptor::gate_precondition::sha256(&descriptor.challenge),
        gate_name_utf16_sha256: super::descriptor::gate_precondition::sha256(&name_bytes),
        operation: "OpenEventW-pre-handoff-control".into(),
        desired_access: 0x0010_0000,
        attempted: true,
        opened: native_error.is_none(),
        native_error,
        token,
        token_envelope: envelope,
        same_original_event_identity_proved: false,
        acceptance_authority: false,
    };
    observation
        .validate(
            input,
            &observation.case,
            &observation.challenge_sha256,
            &observation.gate_name_utf16_sha256,
            expected_envelope,
        )
        .map_err(io::Error::other)?;
    let bytes = serde_json::to_vec(&observation).map_err(io::Error::other)?;
    if bytes.len() > RECORD_BYTES {
        return Err(io::Error::other("gate control observation exceeds bound"));
    }
    check(input)?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(descriptor.output_root.join("gate-precondition-child.json"))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    check(input)?;
    // Access denial is a retained diagnostic, never a passing target result.
    Ok(0)
}
