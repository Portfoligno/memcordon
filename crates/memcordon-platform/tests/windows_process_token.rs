#![cfg(all(windows, feature = "test-support"))]

use memcordon_platform::test_support::{WindowsImageProcess, windows_processes_for_image_until};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Security::TOKEN_QUERY,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

fn current(deadline: Instant) -> WindowsImageProcess {
    windows_processes_for_image_until(&std::env::current_exe().unwrap(), deadline)
        .unwrap()
        .into_iter()
        .find(|owner| owner.identity.pid == std::process::id())
        .unwrap()
}

#[test]
fn original_process_query_returns_the_complete_canonical_envelope() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let owner = current(deadline);
    let mut raw = std::ptr::null_mut();
    // SAFETY: query only this process's existing primary token; no policy or privilege changes.
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
        0
    );
    // SAFETY: successful token query transfers exactly one native handle owner.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let expected =
        memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle()).unwrap();
    assert_eq!(owner.original_token_envelope(deadline).unwrap(), expected);
    assert!(!owner.has_exited().unwrap());
}

#[test]
fn original_cutoff_and_full_native_birth_cannot_be_replaced_by_expected_facts() {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut owner = current(deadline);
    assert_eq!(
        owner
            .original_token_envelope(Instant::now())
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let actual = owner.identity;
    owner.identity.birth = u128::MAX;
    assert_eq!(
        owner.original_token_envelope(deadline).unwrap_err().kind(),
        io::ErrorKind::InvalidData
    );
    owner.identity = actual;
    assert!(owner.original_token_envelope(deadline).is_ok());
}
