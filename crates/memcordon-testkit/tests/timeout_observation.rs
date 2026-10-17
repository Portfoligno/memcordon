use std::process::Command;
use std::sync::mpsc;
use std::time::Duration;

use memcordon_testkit::{ProcessTestError, run_with_deadline, run_with_deadline_after};

fn fixture(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([name, "--exact", "--ignored", "--test-threads=1"]);
    command
}

#[test]
fn timeout_distinguishes_an_exited_child_from_a_pending_callback() {
    let (release, gate) = mpsc::channel();
    let error = run_with_deadline_after(
        &mut fixture("exits_successfully"),
        Duration::from_secs(1),
        move |_| {
            let _ = gate.recv();
            Ok(())
        },
    )
    .unwrap_err();
    // Release before assertions so an assertion failure cannot strand the callback.
    let _ = release.send(());
    let diagnostic = error.to_string();
    let ProcessTestError::Timeout {
        observation,
        cleanup,
        deadline,
        ..
    } = error
    else {
        panic!("unexpected failure: {diagnostic}");
    };
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(observation.observed_status.unwrap().success());
    assert!(!observation.callback_completed);
    assert!(!observation.settlement_complete);
    assert!(observation.child_id > 0);
    assert!(observation.spawn_returned <= observation.boundary_admitted);
    assert!(observation.boundary_admitted <= observation.timeout_observed);
    assert!(observation.timeout_observed >= deadline);
    assert!(diagnostic.contains("observation=TimeoutObservation"));
}

#[test]
fn timeout_does_not_report_the_cleanup_exit_as_an_observed_exit() {
    let error = run_with_deadline(&mut fixture("waits_for_retirement"), Duration::from_secs(1))
        .unwrap_err();
    let ProcessTestError::Timeout {
        observation,
        cleanup,
        ..
    } = error
    else {
        panic!("unexpected failure: {error}");
    };
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(observation.observed_status.is_none());
    assert!(observation.callback_completed);
    assert!(observation.settlement_complete);
}

#[test]
fn callback_failure_retains_original_exit_and_settled_streams() {
    let error = memcordon_testkit::run_with_deadline_after_output_limit(
        &mut fixture("exits_with_original_error"),
        Duration::from_secs(5),
        4096,
        |_| {
            std::thread::sleep(Duration::from_millis(300));
            Err(std::io::Error::other("original callback refusal"))
        },
    )
    .unwrap_err();
    let ProcessTestError::Callback {
        error,
        stdout,
        stderr,
        capture_complete,
        observed_status,
        termination,
        cleanup,
    } = error
    else {
        panic!("unexpected failure: {error}");
    };
    assert_eq!(error.to_string(), "original callback refusal");
    assert_eq!(observed_status.unwrap().code(), Some(23));
    assert_eq!(termination.unwrap().code(), Some(23));
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(capture_complete);
    assert!(
        stdout
            .windows(b"original stdout".len())
            .any(|bytes| bytes == b"original stdout")
    );
    assert!(
        stderr
            .windows(b"original stderr".len())
            .any(|bytes| bytes == b"original stderr")
    );
}

#[test]
#[ignore = "exact child fixture for callback failure observations"]
fn exits_with_original_error() {
    use std::io::Write;
    std::io::stdout().write_all(b"original stdout").unwrap();
    std::io::stderr().write_all(b"original stderr").unwrap();
    std::process::exit(23);
}

#[test]
#[ignore = "exact child fixture for parent timeout observations"]
fn exits_successfully() {}

#[test]
#[ignore = "exact child fixture retired by the parent deadline"]
fn waits_for_retirement() {
    std::thread::sleep(Duration::from_secs(30));
}
