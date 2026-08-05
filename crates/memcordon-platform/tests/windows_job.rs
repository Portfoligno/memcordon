#![cfg(all(windows, feature = "test-support"))]

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use memcordon_platform::test_support::{
    windows_assignment_failure, windows_encode_command_line, windows_kill_on_job_close,
    windows_nested_assignment, windows_target_remains_suspended_until_assignment,
};

#[test]
fn windows_native_encoder_quotes_without_shell_interpretation() {
    let encoded = windows_encode_command_line(
        OsString::from("program.exe"),
        vec![
            OsString::from("plain"),
            OsString::from("two words"),
            OsString::from("a\"b"),
            OsString::new(),
        ],
    );
    let expected: Vec<u16> = OsStr::new("program.exe plain \"two words\" \"a\\\"b\" \"\"")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    assert_eq!(encoded, expected);
}

#[test]
fn windows_native_encoder_preserves_unpaired_wide_units() {
    let native = OsString::from_wide(&[b'a'.into(), 0xd800, b'b'.into()]);
    let encoded = windows_encode_command_line(OsString::from("program.exe"), vec![native]);
    assert!(encoded.contains(&0xd800));
    assert!(!encoded.contains(&0xfffd));
}

#[test]
fn target_remains_suspended_until_successful_job_assignment() {
    assert!(
        windows_target_remains_suspended_until_assignment()
            .expect("suspended assignment scenario should complete")
    );
}

#[test]
fn kill_on_job_close_terminates_a_running_member() {
    assert!(windows_kill_on_job_close().expect("kill-on-close scenario should complete"));
}

#[test]
fn nested_assignment_is_accounted_by_the_memcordon_job() {
    assert!(windows_nested_assignment().expect("nested assignment scenario should complete"));
}

#[test]
fn assignment_failure_terminates_suspended_target_before_execution() {
    assert!(windows_assignment_failure().expect("assignment failure scenario should complete"));
}
