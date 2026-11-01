//! Native CI regression in a separate fixture process, never a workload gate.
use super::gate_call_trace;
use std::io;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Foundation::GetLastError,
    System::{
        Performance::{QueryPerformanceCounter, QueryPerformanceFrequency},
        Threading::CreateEventW,
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
    let _owner = unsafe { OwnedHandle::from_raw_handle(handle) };
    for (selected, should_open) in [
        (wide, true),
        (
            format!("{name}-missing")
                .encode_utf16()
                .chain(Some(0))
                .collect(),
            false,
        ),
    ] {
        let mut prepared = gate_call_trace::Prepared::new(cutoff, frequency as u64);
        let call = prepared.call(&selected)?;
        let returned_error = unsafe { GetLastError() };
        assert_eq!(returned_error, call.native_error);
        assert_eq!(!call.handle.is_null(), should_open);
        if call.handle.is_null() {
            assert_ne!(call.native_error, 0);
        } else {
            drop(unsafe { OwnedHandle::from_raw_handle(call.handle) });
        }
        let trace = prepared.diagnostic();
        assert_eq!(trace["setup_stage"], 1);
        assert_eq!(trace["armed_call_count"], 1);
        assert_eq!(trace["called"], 1);
        assert_eq!(trace["outer_opened"], u32::from(should_open));
        assert_eq!(trace["outer_error"], call.native_error);
        assert_eq!(trace["acceptance_authority"], false);
        assert_eq!(trace["target_identity_proved"], false);
        assert!(
            trace["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["operation_code"] == 2 && entry["returned"] == 1)
        );
    }
    Ok(0)
}
