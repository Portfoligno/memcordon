//! Read-only observations of the original loader process, never launch authority.
pub(crate) use memcordon_core::{
    WindowsLoaderMitigationObservationV1 as LoaderMitigations,
    WindowsLoaderMitigationPolicyObservationV1 as PolicyObservation,
};

#[cfg(windows)]
pub(crate) fn capture(
    process: windows_sys::Win32::Foundation::HANDLE,
    identity: memcordon_core::WindowsProcessIdentityV1,
    executable_sha256: &str,
    launch_plan_sha256: &str,
    cutoff: std::time::Instant,
) -> LoaderMitigations {
    use windows_sys::Win32::System::SystemServices::{
        PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY, PROCESS_MITIGATION_IMAGE_LOAD_POLICY,
        PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY,
    };
    use windows_sys::Win32::System::Threading::{
        ProcessImageLoadPolicy, ProcessSignaturePolicy, ProcessSystemCallDisablePolicy,
    };
    let mut system = PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY::default();
    let mut signature = PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY::default();
    let mut image = PROCESS_MITIGATION_IMAGE_LOAD_POLICY::default();
    LoaderMitigations {
        process: identity,
        executable_sha256: executable_sha256.into(),
        launch_plan_sha256: launch_plan_sha256.into(),
        system_call_disable: query(
            process,
            ProcessSystemCallDisablePolicy,
            &mut system,
            cutoff,
            |value| unsafe { value.Anonymous.Flags },
        ),
        binary_signature: query(
            process,
            ProcessSignaturePolicy,
            &mut signature,
            cutoff,
            |value| unsafe { value.Anonymous.Flags },
        ),
        image_load: query(
            process,
            ProcessImageLoadPolicy,
            &mut image,
            cutoff,
            |value| unsafe { value.Anonymous.Flags },
        ),
    }
}

#[cfg(windows)]
fn query<T>(
    process: windows_sys::Win32::Foundation::HANDLE,
    policy: windows_sys::Win32::System::Threading::PROCESS_MITIGATION_POLICY,
    value: &mut T,
    cutoff: std::time::Instant,
    flags: impl FnOnce(&T) -> u32,
) -> PolicyObservation {
    if std::time::Instant::now() >= cutoff {
        return PolicyObservation::CutoffExhausted;
    }
    // SAFETY: callers supply the documented native structure for this policy;
    // its actual size and the original held process handle are passed unchanged.
    let success = unsafe {
        windows_sys::Win32::System::Threading::GetProcessMitigationPolicy(
            process,
            policy,
            std::ptr::from_mut(value).cast(),
            std::mem::size_of::<T>(),
        )
    };
    if success == 0 {
        // Capture the native error before any other API call can overwrite it.
        return PolicyObservation::Unavailable {
            native_code: unsafe { windows_sys::Win32::Foundation::GetLastError() },
        };
    }
    PolicyObservation::Observed {
        flags: flags(value),
    }
}
