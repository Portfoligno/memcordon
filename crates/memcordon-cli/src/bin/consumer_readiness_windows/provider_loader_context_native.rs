//! Read-only original-thread context snapshots, outside the original loader call.
use super::provider_loader_context::{self as record, Observation};
use serde_json::{Value, json};
use windows_sys::Win32::{
    Foundation::{APPMODEL_ERROR_NO_PACKAGE, ERROR_INSUFFICIENT_BUFFER, GetLastError},
    Storage::Packaging::Appx::GetCurrentPackageFullName,
    System::{
        ApplicationInstallationAndServicing::{
            ACTIVATION_CONTEXT_DETAILED_INFORMATION, QueryActCtxW,
        },
        Performance::QueryPerformanceCounter,
        SystemServices::ActivationContextDetailedInformation,
        Threading::GetCurrentThreadId,
        WindowsProgramming::QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX,
    },
};

const _: () = {
    assert!(
        std::mem::size_of::<ACTIVATION_CONTEXT_DETAILED_INFORMATION>() == record::DETAILS_BYTES
    );
    assert!(
        std::mem::offset_of!(ACTIVATION_CONTEXT_DETAILED_INFORMATION, lpRootManifestPath) == 40
    );
    assert!(
        std::mem::offset_of!(
            ACTIVATION_CONTEXT_DETAILED_INFORMATION,
            lpRootConfigurationPath
        ) == 48
    );
    assert!(std::mem::offset_of!(ACTIVATION_CONTEXT_DETAILED_INFORMATION, lpAppDirPath) == 56);
};

fn qpc() -> Result<u64, u32> {
    let mut value = 0i64;
    // SAFETY: initialized scalar output for the calling thread's fixed budget.
    if unsafe { QueryPerformanceCounter(&mut value) } == 0 {
        return Err(unsafe { GetLastError() });
    }
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(87)
}

fn activation_context(clock: &super::descriptor::ControlClock) -> Observation {
    let mut observed = Observation {
        available_bytes: record::BUFFER_BYTES,
        cutoff_qpc: clock.work_cutoff_qpc,
        qpc_frequency: clock.qpc_frequency,
        ..Default::default()
    };
    let before = match qpc() {
        Ok(value) => value,
        Err(error) => {
            observed.clock_error = Some(error);
            return observed;
        }
    };
    observed.started_qpc = Some(before);
    if clock.qpc_frequency == 0 || before >= clock.work_cutoff_qpc {
        observed.cutoff_reached = clock.qpc_frequency != 0 && before >= clock.work_cutoff_qpc;
        return observed;
    }
    // u64 storage supplies the SDK structure's 8-byte alignment. Every byte is
    // initialized; no pointer supplied by the API is dereferenced by this code.
    let mut storage = [0u64; record::BUFFER_BYTES / std::mem::size_of::<u64>()];
    let mut required = 0usize;
    observed.attempted = true;
    // SAFETY: one aligned fixed buffer with its actual byte extent. ACTIVE
    // queries the current thread without acquiring/changing a context handle.
    let success = unsafe {
        QueryActCtxW(
            QUERY_ACTCTX_FLAG_USE_ACTIVE_ACTCTX,
            std::ptr::null_mut(),
            std::ptr::null(),
            ActivationContextDetailedInformation as u32,
            storage.as_mut_ptr().cast(),
            record::BUFFER_BYTES,
            &mut required,
        )
    };
    let native_error = if success == 0 {
        Some(unsafe { GetLastError() })
    } else {
        None
    };
    observed.success = Some(success != 0);
    observed.native_error = native_error;
    observed.required_bytes =
        (success != 0 || native_error == Some(ERROR_INSUFFICIENT_BUFFER)).then_some(required);
    match qpc() {
        Ok(after) => {
            observed.finished_qpc = Some(after);
            observed.cutoff_reached = after >= clock.work_cutoff_qpc;
        }
        Err(error) => observed.clock_error = Some(error),
    }
    if success != 0 {
        // SAFETY: this view covers only our initialized live allocation, never
        // an API-provided pointer. The pure decoder bounds all reported spans
        // within both the returned byte extent and this slice before copying.
        let buffer = unsafe {
            std::slice::from_raw_parts(storage.as_ptr().cast::<u8>(), record::BUFFER_BYTES)
        };
        observed.details = Some(record::decode_details(
            buffer,
            buffer.as_ptr() as usize,
            required,
        ));
    }
    observed
}

fn package_status(clock: &super::descriptor::ControlClock) -> Value {
    let before = match qpc() {
        Ok(before) if clock.qpc_frequency != 0 && before < clock.work_cutoff_qpc => before,
        Ok(before) => {
            return json!({"attempted":false,"started_qpc":before,"clock_error":null,"available_before_original_cutoff":false,
            "original_cutoff_reached":(clock.qpc_frequency!=0).then_some(before>=clock.work_cutoff_qpc)});
        }
        Err(error) => {
            return json!({"attempted":false,"clock_error":error,"available_before_original_cutoff":false,"original_cutoff_reached":null});
        }
    };
    let mut required = 0u32;
    // SAFETY: documented size-only query. No package-name allocation, load,
    // context activation or second call is performed. Status is returned
    // directly by the API rather than obtained from GetLastError.
    let status = unsafe { GetCurrentPackageFullName(&mut required, std::ptr::null_mut()) };
    let after = qpc();
    let live = after.is_ok_and(|after| after >= before && after < clock.work_cutoff_qpc);
    let identity = if live {
        match status {
            APPMODEL_ERROR_NO_PACKAGE => Some(false),
            ERROR_INSUFFICIENT_BUFFER => Some(true),
            _ => None,
        }
    } else {
        None
    };
    json!({"attempted":true,"native_status":status,"required_characters_including_terminator":matches!(status,0|ERROR_INSUFFICIENT_BUFFER).then_some(required),
        "package_identity_present":identity,"package_name_captured":false,"started_qpc":before,
        "finished_qpc":after.ok(),"clock_error":after.err(),"available_before_original_cutoff":live,
        "clock_regressed":after.ok().map(|after|after<before),
        "original_cutoff_reached":after.ok().filter(|after|*after>=before).map(|after|after>=clock.work_cutoff_qpc),
        "unexpected_status":!matches!(status,APPMODEL_ERROR_NO_PACKAGE|ERROR_INSUFFICIENT_BUFFER),
        "acceptance_authority":false})
}

pub fn capture(clock: &super::descriptor::ControlClock, connect: bool) -> Value {
    let incoming = super::listener_trace::ErrorPair::capture();
    let phase = if connect {
        "before-original-Rust-TcpStream-connect"
    } else {
        "before-original-Rust-TcpListener-bind"
    };
    let identity_before = qpc();
    let (identity, thread) = match identity_before {
        Ok(before) if clock.qpc_frequency != 0 && before < clock.work_cutoff_qpc => {
            // SAFETY: scalar self-thread query under the existing original cutoff.
            let thread = unsafe { GetCurrentThreadId() };
            let identity = super::native::current_identity();
            let after = qpc();
            let value = match identity {
                Ok(identity) => {
                    json!({"pid":identity.process_id,"creation_time_100ns":identity.creation_time_100ns,
                    "started_qpc":before,"finished_qpc":after.ok(),"clock_error":after.err(),"clock_regressed":after.ok().map(|after|after<before),
                    "available_before_original_cutoff":after.is_ok_and(|after|after>=before&&after<clock.work_cutoff_qpc)})
                }
                Err(error) => {
                    json!({"native_error":error.raw_os_error(),"started_qpc":before,"finished_qpc":after.ok(),
                    "clock_error":after.err(),"clock_regressed":after.ok().map(|after|after<before),"available_before_original_cutoff":false})
                }
            };
            (value, Some(thread))
        }
        Ok(before) => (
            json!({"available_before_original_cutoff":false,"started_qpc":before,"clock_error":null,
            "original_cutoff_reached":(clock.qpc_frequency!=0).then_some(before>=clock.work_cutoff_qpc)}),
            None,
        ),
        Err(error) => (
            json!({"available_before_original_cutoff":false,"clock_error":error,"original_cutoff_reached":null}),
            None,
        ),
    };
    let context = activation_context(clock);
    let package = package_status(clock);
    let snapshot = json!({"scope":"provider-experiment-after-startup-before-listener-observer-setup","sampled_before":phase,
        "actual_self":identity,"thread_id":thread,"activation_context":record::diagnostic(&context),"package_identity":package,
        "original_cutoff_qpc":clock.work_cutoff_qpc,"qpc_frequency":clock.qpc_frequency,
        "no_active_context_separately_measured":false,"inside_original_Ldr_scope":false,
        "continuous_state_attestation":false,"loader_context_precedence_or_cause_proved":false,"acceptance_authority":false});
    let snapshot = if record::bounded(snapshot.clone()).is_ok() {
        snapshot
    } else {
        json!({"scope":"provider-experiment-after-startup-before-listener-observer-setup","sampled_before":phase,
            "state":"context-record-exceeds8KiB","details_omitted":true,"original_cutoff_qpc":clock.work_cutoff_qpc,
            "qpc_frequency":clock.qpc_frequency,"no_active_context_separately_measured":false,"acceptance_authority":false})
    };
    incoming.restore();
    snapshot
}
