#![cfg(windows)]

use memcordon_windows_launch_core::{
    NativeKernelObjectKindV1, NativeSecurityDescriptorV1, ProductionJobV1,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

#[test]
fn job_readback_normalizes_generic_all_and_omitted_group() {
    let job = ProductionJobV1::create("D:P(A;;GA;;;WD)")
        .expect("generic Job policy must survive semantic kernel readback");
    assert!(!job.handle().is_null());

    let read_only = NativeSecurityDescriptorV1::from_sddl("D:P(A;;GR;;;WD)")
        .expect("mutated Job policy must parse");
    let mismatch = read_only
        .verify_kernel_object(job.handle(), NativeKernelObjectKindV1::Job)
        .expect_err("mapped generic read must differ from mapped generic all");
    assert_eq!(mismatch.stable_code, "job-security-mismatch");
    assert!(mismatch.detail.starts_with("Job security descriptor"));
}

#[test]
fn kernel_security_mismatches_name_the_actual_object_kind() {
    let impossible = NativeSecurityDescriptorV1::from_sddl("O:AND:P(A;;GA;;;AN)")
        .expect("mismatch descriptor must parse");

    let process = impossible
        .verify_kernel_object(
            unsafe { GetCurrentProcess() },
            NativeKernelObjectKindV1::Process,
        )
        .expect_err("current process cannot have the anonymous mismatch policy");
    assert_eq!(process.stable_code, "process-security-mismatch");
    assert!(process.detail.starts_with("Process security descriptor"));
    assert!(!process.detail.contains("Job security descriptor"));

    let thread = impossible
        .verify_kernel_object(
            unsafe { GetCurrentThread() },
            NativeKernelObjectKindV1::Thread,
        )
        .expect_err("current thread cannot have the anonymous mismatch policy");
    assert_eq!(thread.stable_code, "thread-security-mismatch");
    assert!(thread.detail.starts_with("Thread security descriptor"));
    assert!(!thread.detail.contains("Job security descriptor"));

    let job = ProductionJobV1::create("D:P(A;;GA;;;WD)")
        .expect("test Job must be created with a semantic readback");
    let job_error = impossible
        .verify_kernel_object(job.handle(), NativeKernelObjectKindV1::Job)
        .expect_err("test Job cannot have the anonymous mismatch policy");
    assert_eq!(job_error.stable_code, "job-security-mismatch");
    assert!(job_error.detail.starts_with("Job security descriptor"));
}
