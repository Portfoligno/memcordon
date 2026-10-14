#![cfg(feature = "test-support")]

#[path = "support/windows_cold_runtime.rs"]
pub mod cold_runtime;

#[test]
fn fixture_dispatch_requires_exactly_one_known_mode() {
    use std::ffi::OsString;
    assert!(
        cold_runtime::validate_cold_runtime_mode(&[OsString::from("cold-runtime-probe")]).is_ok()
    );
    for arguments in [
        vec![],
        vec![OsString::new()],
        vec![OsString::from("unknown")],
        vec![
            OsString::from("cold-runtime-probe"),
            OsString::from("extra"),
        ],
    ] {
        assert!(cold_runtime::validate_cold_runtime_mode(&arguments).is_err());
    }
}
