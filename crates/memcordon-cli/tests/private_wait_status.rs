#![cfg(unix)]

#[path = "../src/bin/memcordon-sealed-agent/linux/private_wait_status.rs"]
mod private_wait_status;

use private_wait_status::require_target_status;
use std::fs::File;
use std::io::Write;
use std::os::fd::FromRawFd;
use std::os::unix::process::ExitStatusExt;
use std::process::Command;
use std::time::{Duration, Instant};

fn status_pipe(bytes: &[u8]) -> File {
    let mut descriptors = [-1; 2];
    // SAFETY: pipe initializes two fresh descriptors in the supplied slots.
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned uniquely owned read and write ends.
    let (reader, mut writer) = unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    };
    writer.write_all(bytes).unwrap();
    drop(writer);
    reader
}

#[test]
#[ignore = "bounded native child invoked by actual wait-status evidence regression"]
fn native_exit_child() {
    std::process::exit(7);
}

#[test]
fn actual_wait_status_is_required_and_cached_before_completed() {
    let mut child = Command::new(std::env::current_exe().unwrap());
    child.args(["--exact", "--ignored", "native_exit_child"]);
    let output = memcordon_testkit::run_with_deadline(&mut child, Duration::from_secs(2)).unwrap();
    assert_eq!(output.status.code(), Some(7));
    let actual = output.status.into_raw();
    let mut channel = Some(status_pipe(&actual.to_be_bytes()));
    let mut observed = None;
    require_target_status(
        &mut observed,
        &mut channel,
        Some(Instant::now() + Duration::from_secs(1)),
    )
    .unwrap();
    assert_eq!(observed, Some(actual));
    assert!(channel.is_none());
    // A second completion check retains the already-read native proof and
    // cannot require another channel or renew its observation budget.
    require_target_status(&mut observed, &mut channel, Some(Instant::now())).unwrap();
    assert_eq!(observed, Some(actual));
}

#[test]
fn lost_or_partial_init_status_cannot_qualify_completed() {
    for (bytes, expected_error) in [
        (Vec::new(), "without actual target wait status"),
        (vec![0, 0], "partial target status"),
        (
            0x7f_i32.to_be_bytes().to_vec(),
            "not a native terminal wait status",
        ),
    ] {
        let mut channel = Some(status_pipe(&bytes));
        let mut observed = None;
        let error = require_target_status(
            &mut observed,
            &mut channel,
            Some(Instant::now() + Duration::from_secs(1)),
        )
        .unwrap_err();
        assert!(error.contains(expected_error), "{error}");
        assert!(observed.is_none());
        assert!(channel.is_none());
        assert!(require_target_status(&mut observed, &mut channel, None).is_err());
    }
}

#[test]
fn expired_original_budget_does_not_admit_queued_status() {
    let mut channel = Some(status_pipe(&0_i32.to_be_bytes()));
    let mut observed = None;
    let expired = Instant::now();
    let error = require_target_status(&mut observed, &mut channel, Some(expired)).unwrap_err();
    assert!(error.contains("status deadline expired"), "{error}");
    assert!(observed.is_none());
    assert!(channel.is_none());
}
