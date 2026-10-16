use std::process::Command;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc,
};
use std::time::Duration;

use memcordon_testkit::{
    ProcessTestError, ProgressOutput, run_with_deadline_controlled_output_limit,
};

fn fixture(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        name,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command
}

#[test]
fn progress_precedes_exit_and_peer_cancellation_settles_owned_readers() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let child_cancelled = cancelled.clone();
    let (sender, receiver) = mpsc::sync_channel(8);
    let progress = ProgressOutput {
        sender,
        omitted: Arc::new(AtomicU64::new(0)),
    };
    let worker = std::thread::spawn(move || {
        run_with_deadline_controlled_output_limit(
            &mut fixture("waits_after_progress"),
            Duration::from_secs(10),
            64 * 1024,
            Some(child_cancelled),
            Some(progress),
        )
    });
    let mut received = Vec::new();
    while !received
        .windows(b"ready-for-peer".len())
        .any(|bytes| bytes == b"ready-for-peer")
    {
        match receiver.recv_timeout(Duration::from_secs(5)) {
            Ok(chunk) => received.extend(chunk.bytes),
            Err(error) => {
                cancelled.store(true, Ordering::Release);
                let _ = worker.join();
                panic!("progress not observed: {error}");
            }
        }
    }
    assert!(
        !worker.is_finished(),
        "progress must be delivered before exit"
    );
    cancelled.store(true, Ordering::Release);
    let error = worker.join().unwrap().unwrap_err();
    let ProcessTestError::Cancelled {
        cleanup,
        termination,
        observation,
        stdout,
        ..
    } = error
    else {
        panic!("unexpected failure: {error}");
    };
    assert!(cleanup.is_ok(), "{cleanup:?}");
    assert!(termination.is_some());
    assert!(observation.child_id > 0);
    assert!(observation.observed_status.is_none());
    assert!(observation.callback_completed);
    assert!(observation.stdout_reader_finished && observation.stderr_reader_finished);
    assert!(observation.cancellation_observed < Duration::from_secs(10));
    assert!(
        stdout
            .windows(b"ready-for-peer".len())
            .any(|bytes| bytes == b"ready-for-peer")
    );
}

#[test]
fn slow_logger_does_not_block_output_capture_or_retirement() {
    let (sender, _receiver) = mpsc::sync_channel(0);
    let omitted = Arc::new(AtomicU64::new(0));
    let output = run_with_deadline_controlled_output_limit(
        &mut fixture("writes_many_chunks"),
        Duration::from_secs(10),
        512 * 1024,
        None,
        Some(ProgressOutput {
            sender,
            omitted: omitted.clone(),
        }),
    )
    .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.len() >= 256 * 1024);
    assert!(omitted.load(Ordering::Relaxed) > 0);
}

#[test]
fn actual_failure_notifies_even_with_a_full_progress_queue() {
    let observed = Arc::new(AtomicU64::new(0));
    let notifications = observed.clone();
    let (sender, _receiver) = mpsc::sync_channel(0);
    let output = memcordon_testkit::run_with_deadline_notified_output_limit(
        &mut fixture("fails_without_failure_text"),
        Duration::from_secs(10),
        64 * 1024,
        None,
        Some(ProgressOutput {
            sender,
            omitted: Arc::new(AtomicU64::new(0)),
        }),
        Some(Arc::new(move || {
            notifications.fetch_add(1, Ordering::AcqRel);
        })),
    )
    .unwrap();
    assert!(!output.status.success());
    assert!(observed.load(Ordering::Acquire) > 0);
    assert!(
        output
            .stdout
            .windows(b"ordinary output".len())
            .any(|part| part == b"ordinary output")
    );
}

#[test]
fn spawn_failure_notifies_before_return() {
    let observed = Arc::new(AtomicBool::new(false));
    let notified = observed.clone();
    let error = memcordon_testkit::run_with_deadline_notified_output_limit(
        &mut Command::new("memcordon-nonexistent-observation-fixture"),
        Duration::from_secs(10),
        1024,
        None,
        None,
        Some(Arc::new(move || {
            notified.store(true, Ordering::Release);
        })),
    )
    .unwrap_err();
    assert!(matches!(error, ProcessTestError::Spawn(_)));
    assert!(observed.load(Ordering::Acquire));
}

#[test]
#[ignore = "nonzero native status observation fixture"]
fn fails_without_failure_text() {
    use std::io::Write;
    std::io::stdout().write_all(b"ordinary output\n").unwrap();
    std::io::stdout().flush().unwrap();
    std::process::exit(19);
}

#[test]
#[ignore = "owned subprocess progress and cancellation fixture"]
fn waits_after_progress() {
    use std::io::Write;
    std::io::stdout().write_all(b"ready-for-peer\n").unwrap();
    std::io::stdout().flush().unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "bounded output saturation fixture"]
fn writes_many_chunks() {
    use std::io::Write;
    std::io::stdout()
        .write_all(&vec![b'x'; 256 * 1024])
        .unwrap();
    std::io::stdout().flush().unwrap();
}
