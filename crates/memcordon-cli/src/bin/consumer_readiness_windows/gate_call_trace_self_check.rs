//! Native CI regression in a separate fixture process, never a workload gate.
use super::gate_call_trace;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::{CompareObjectHandles, GetLastError},
    System::{
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::{CreateEventW, OpenEventW},
    },
};

pub(super) fn run() -> io::Result<i32> {
    assert!(gate_call_trace::mock_forwarding());
    let mut now = 0;
    let mut frequency = 0;
    // SAFETY: writable clock scalars; this CI self-check has its own fixed
    // original deadline. Installed case work/cleanup budgets are untouched.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut now) }, 0);
    assert_ne!(unsafe { QueryPerformanceFrequency(&mut frequency) }, 0);
    let cutoff = u64::try_from(now + frequency * 5).unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!(
        "Local\\memcordon-control-trace-{}-{nonce}",
        std::process::id()
    );
    let wide = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // SAFETY: fresh bounded test name and no inherited/substituted handle.
    let handle = unsafe { CreateEventW(std::ptr::null(), 1, 0, wide.as_ptr()) };
    let error = unsafe { GetLastError() };
    assert!(!handle.is_null() && error != 183);
    let owner = unsafe { OwnedHandle::from_raw_handle(handle) };
    let missing = format!("{name}-missing")
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // SAFETY: the exact missing-name baseline precedes any hook installation.
    // Save the original error before any further native or diagnostic call.
    let baseline = unsafe { OpenEventW(0x0010_0000, 0, missing.as_ptr()) };
    let baseline_error = unsafe { GetLastError() };
    let baseline_owner =
        (!baseline.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(baseline) });
    assert!(baseline_owner.is_none());
    assert_ne!(baseline_error, 0);
    for (selected, should_open) in [(wide, true), (missing, false)] {
        let mut prepared = gate_call_trace::Prepared::new(cutoff, frequency as u64);
        let call = prepared.call(&selected)?;
        let returned_error = unsafe { GetLastError() };
        // Adopt the successful reference before any assertion can unwind.
        let returned_owner =
            (!call.handle.is_null()).then(|| unsafe { OwnedHandle::from_raw_handle(call.handle) });
        assert_eq!(returned_error, call.native_error);
        assert_eq!(!call.handle.is_null(), should_open);
        if call.handle.is_null() {
            assert_eq!(call.native_error, baseline_error);
        } else {
            // SAFETY: both references are live and owned within this self-check.
            // This test-local comparison never grants workload identity authority.
            assert_ne!(
                unsafe {
                    CompareObjectHandles(
                        owner.as_raw_handle(),
                        returned_owner
                            .as_ref()
                            .expect("returned event owned")
                            .as_raw_handle(),
                    )
                },
                0
            );
        }
        let trace = prepared.diagnostic();
        assert_eq!(
            trace["setup_stage"],
            1,
            "case={}; bounded_trace={trace}",
            if should_open {
                "owned-event"
            } else {
                "missing-event"
            }
        );
        assert_eq!(trace["attached_directory"], 1);
        assert_eq!(trace["attached_event"], 1);
        assert_eq!(trace["coverage_inconclusive"], false);
        assert_eq!(trace["invalid_record"], false);
        assert_eq!(trace["overflow"], 0);
        assert_eq!(trace["incomplete"], 0);
        assert_eq!(trace["clock_live"], 1);
        assert_eq!(trace["armed_call_count"], 1);
        assert_eq!(trace["called"], 1);
        assert_eq!(trace["outer_opened"], u32::from(should_open));
        assert_eq!(trace["outer_error"], call.native_error);
        assert_eq!(trace["acceptance_authority"], false);
        assert_eq!(trace["target_identity_proved"], false);
        assert!(trace["entries"].as_array().unwrap().iter().any(|entry| {
            entry["operation_code"] == 2
                && entry["entered"] == 1
                && entry["returned"] == 1
                && entry["desired_access"] == 0x0010_0000
                && entry["native_status"]
                    .as_i64()
                    .is_some_and(|status| (status >= 0) == should_open)
                && entry["output_handle_returned"] == u32::from(should_open)
        }));
        assert!(prepared.call(&selected).is_err());
        assert_eq!(
            prepared.diagnostic(),
            trace,
            "refused second call changed original trace"
        );
    }
    // The original start tick is now expired; no sleep, new budget, or native
    // event attempt is needed to exercise the actual bridge refusal boundary.
    let mut expired = gate_call_trace::Prepared::new(u64::try_from(now).unwrap(), frequency as u64);
    let name = name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let error = expired.call(&name).err().expect("expired call must refuse");
    assert_eq!(error.raw_os_error(), Some(1460));
    let trace = expired.diagnostic();
    assert_eq!(trace["setup_stage"], 2);
    assert_eq!(trace["setup_error"], 1460);
    assert_eq!(trace["called"], 0);
    assert_eq!(trace["armed_call_count"], 0);
    assert_eq!(trace["reported_count"], 0);
    assert_eq!(trace["clock_live"], 0);
    assert_eq!(trace["coverage_inconclusive"], true);
    assert_eq!(trace["acceptance_authority"], false);
    assert_eq!(trace["target_identity_proved"], false);
    Ok(0)
}
