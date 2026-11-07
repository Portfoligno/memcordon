//! Fixed-size self queries only; no process policy setter or alternate workload.
use super::provider_loader_policy::{Observation, Policy, diagnostic};
use serde_json::{Value, json};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Performance::QueryPerformanceCounter,
        SystemServices::{
            PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        },
        Threading::{
            GetCurrentProcess, GetCurrentThreadId, GetProcessMitigationPolicy,
            ProcessImageLoadPolicy, ProcessSignaturePolicy,
        },
    },
};

fn qpc() -> Result<u64, u32> {
    let mut value = 0i64;
    // SAFETY: one initialized QPC output, no external object access.
    if unsafe { QueryPerformanceCounter(&mut value) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(87)
}

fn query<T>(
    clock: &super::descriptor::ControlClock,
    policy: i32,
    value: &mut T,
    flags: impl FnOnce(&T) -> u32,
) -> Observation {
    let mut result = Observation::default();
    let before = match qpc() {
        Ok(value) => value,
        Err(error) => {
            result.clock_error = Some(error);
            return result;
        }
    };
    result.started_qpc = Some(before);
    if clock.qpc_frequency == 0 || before >= clock.work_cutoff_qpc {
        result.cutoff_reached = true;
        return result;
    }
    result.attempted = true;
    // SAFETY: callers provide this policy's documented structure and actual
    // extent. The pseudo handle addresses only the currently running process.
    let success = unsafe {
        GetProcessMitigationPolicy(
            GetCurrentProcess(),
            policy,
            std::ptr::from_mut(value).cast(),
            std::mem::size_of::<T>(),
        )
    };
    let native_error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    result.success = Some(success != 0);
    result.native_error = native_error;
    if success != 0 {
        result.flags = Some(flags(value));
    }
    match qpc() {
        Ok(after) => {
            result.finished_qpc = Some(after);
            result.cutoff_reached = after >= clock.work_cutoff_qpc || after < before;
        }
        Err(error) => result.clock_error = Some(error),
    }
    result
}

pub fn capture(clock: &super::descriptor::ControlClock) -> Value {
    let incoming = super::listener_trace::ErrorPair::capture();
    let mut image = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    let identity_before = qpc();
    let (identity, thread) = match identity_before {
        Ok(before) if clock.qpc_frequency != 0 && before < clock.work_cutoff_qpc => {
            // SAFETY: a scalar self observation inside the checked original budget.
            let thread = unsafe { GetCurrentThreadId() };
            let identity = super::native::current_identity();
            let after = qpc();
            let identity = match identity {
                Ok(identity) => {
                    json!({"pid":identity.process_id,"creation_time_100ns":identity.creation_time_100ns,
                    "started_qpc":before,"finished_qpc":after.ok(),"available_before_original_cutoff":after.is_ok_and(|after|after>=before&&after<clock.work_cutoff_qpc)})
                }
                Err(error) => {
                    json!({"available_before_original_cutoff":false,"native_error":error.raw_os_error(),"started_qpc":before,"finished_qpc":after.ok()})
                }
            };
            (identity, Some(thread))
        }
        state => (
            json!({"available_before_original_cutoff":false,"clock_error":state.err(),"original_cutoff_reached":true}),
            None,
        ),
    };
    let image = query(clock, ProcessImageLoadPolicy, &mut image, |value| unsafe {
        value.Anonymous.Flags
    });
    let signature = query(
        clock,
        ProcessSignaturePolicy,
        &mut signature,
        |value| unsafe { value.Anonymous.Flags },
    );
    let value = json!({"scope":"provider-experiment-before-original-Rust-socket-call-after-startup","actual_self":identity,"thread_id":thread,
        "image_load":diagnostic(Policy::ImageLoad,&image),"signature":diagnostic(Policy::Signature,&signature),
        "original_cutoff_qpc":clock.work_cutoff_qpc,"qpc_frequency":clock.qpc_frequency,
        "continuous_state_attestation":false,"acceptance_authority":false,
        "loader_policy_precedence_or_cause_proved":false});
    incoming.restore();
    value
}
