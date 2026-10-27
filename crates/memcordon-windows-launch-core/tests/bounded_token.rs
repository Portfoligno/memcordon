#![cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::{
    Security::TOKEN_QUERY,
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

#[test]
fn bounded_entry_uses_the_identical_canonical_model_without_mutating_source() {
    let mut raw = std::ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
        0
    );
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let original =
        memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle()).unwrap();
    let mut checks = 0;
    let bounded = memcordon_windows_launch_core::query_token_envelope_bounded(
        token.as_raw_handle(),
        &mut || {
            checks += 1;
            Ok(())
        },
    )
    .unwrap();
    assert!(checks > 0);
    assert_eq!(bounded, original);
    assert_eq!(
        memcordon_windows_launch_core::query_token_envelope(token.as_raw_handle()).unwrap(),
        original
    );
}

#[test]
fn original_expiry_refuses_before_even_an_invalid_native_handle_is_queried() {
    let mut checks = 0;
    let result = memcordon_windows_launch_core::query_token_envelope_bounded(
        std::ptr::null_mut(),
        &mut || {
            checks += 1;
            Err("original cutoff elapsed".into())
        },
    );
    assert_eq!(result.unwrap_err(), "original cutoff elapsed");
    assert_eq!(checks, 1);
}
