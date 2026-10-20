use memcordon_testkit::{ProcessTestError, run_with_deadline_external_stop_output_limit};
use std::{
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

#[test]
fn external_interruption_retires_owned_child_without_a_peer_failure() {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "waits_for_external_stop",
        "--exact",
        "--ignored",
        "--test-threads=1",
    ]);
    let started = Instant::now();
    let error = run_with_deadline_external_stop_output_limit(
        &mut command,
        Duration::from_secs(5),
        4096,
        None,
        None,
        None,
        Some(Arc::new(move || {
            started.elapsed() >= Duration::from_millis(100)
        })),
    )
    .unwrap_err();
    let ProcessTestError::Cancelled {
        cleanup,
        observation,
        ..
    } = error
    else {
        panic!("expected external cancellation, got {error}");
    };
    assert!(observation.external_interruption);
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(observation.callback_completed);
    assert!(observation.stdout_reader_finished && observation.stderr_reader_finished);
}

#[test]
#[ignore = "bounded owned child selected by the parent test"]
fn waits_for_external_stop() {
    std::thread::sleep(Duration::from_secs(5));
}
