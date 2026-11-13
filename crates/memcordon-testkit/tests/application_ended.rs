use memcordon_testkit::{
    OutputSnapshot, OwnedCallbackOutcome, ProcessTestError,
    run_until_owned_spawn_with_io_output_limit_outcome,
};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

fn child(name: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            name,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .stdin(Stdio::piped());
    command
}

fn ready(snapshot: &OutputSnapshot, cutoff: Instant) -> std::io::Result<()> {
    while Instant::now() < cutoff {
        if snapshot
            .stdout()?
            .windows(17)
            .any(|bytes| bytes == b"application-ended")
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "helper readiness",
    ))
}

#[test]
fn application_failure_keeps_frontend_alive_through_its_terminal_barrier() {
    let budget = Duration::from_secs(5);
    let cutoff = Instant::now() + budget;
    let (send, receive) = mpsc::sync_channel(1);
    let release = std::thread::spawn(move || {
        let mut input: std::process::ChildStdin = receive
            .recv_timeout(cutoff.saturating_duration_since(Instant::now()))
            .unwrap();
        // The callback has returned before the controlled terminal barrier opens.
        std::thread::sleep(Duration::from_millis(100));
        input.write_all(b"T").unwrap();
    });
    let error = run_until_owned_spawn_with_io_output_limit_outcome(
        child("terminal_barrier"),
        cutoff,
        4096,
        |mut command| command.spawn(),
        move |_, input, snapshot| {
            if let Err(error) = ready(&snapshot, cutoff) {
                return OwnedCallbackOutcome::Abort(error);
            }
            send.send(input.unwrap()).unwrap();
            OwnedCallbackOutcome::ApplicationEnded(std::io::Error::from_raw_os_error(5))
        },
    )
    .unwrap_err();
    release.join().unwrap();
    let summary = error.to_string();
    assert!(summary.contains("natural status="));
    assert!(!summary.contains("terminal-completed"));
    let ProcessTestError::ApplicationEnded { error, settlement } = error else {
        panic!("application failure must remain primary");
    };
    assert_eq!(error.raw_os_error(), Some(5));
    let observed = settlement.unwrap();
    assert_eq!(observed.status.code(), Some(7));
    assert!(
        observed
            .stdout
            .windows(18)
            .any(|bytes| bytes == b"terminal-completed")
    );
    assert!(observed.stderr.is_empty());
}

#[test]
fn application_failure_retains_original_cutoff_and_timeout_as_secondary() {
    let budget = Duration::from_secs(1);
    let started = Instant::now();
    let cutoff = started + budget;
    let (send, receive) = mpsc::sync_channel(1);
    let result = run_until_owned_spawn_with_io_output_limit_outcome(
        child("terminal_barrier"),
        cutoff,
        4096,
        |mut command| command.spawn(),
        move |_, input, snapshot| {
            if let Err(error) = ready(&snapshot, cutoff) {
                return OwnedCallbackOutcome::Abort(error);
            }
            send.send(input.unwrap()).unwrap();
            OwnedCallbackOutcome::ApplicationEnded(std::io::Error::from_raw_os_error(5))
        },
    );
    let _held_input = receive.try_recv().unwrap();
    let Err(ProcessTestError::ApplicationEnded { error, settlement }) = result else {
        panic!("expected retained application failure");
    };
    assert_eq!(error.raw_os_error(), Some(5));
    let ProcessTestError::Timeout {
        deadline,
        observation,
        cleanup,
        ..
    } = *settlement.unwrap_err()
    else {
        panic!("original cutoff must terminate the unreleased frontend");
    };
    assert!(deadline <= budget);
    assert!(observation.timeout_observed >= deadline);
    assert!(observation.callback_completed);
    assert!(observation.observed_status.is_none());
    assert!(cleanup.is_ok());
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn abort_and_callback_panic_retain_immediate_cleanup() {
    for panic_callback in [false, true] {
        let budget = Duration::from_secs(5);
        let cutoff = Instant::now() + budget;
        let started = Instant::now();
        let result = run_until_owned_spawn_with_io_output_limit_outcome(
            child("terminal_barrier"),
            cutoff,
            4096,
            |mut command| command.spawn(),
            move |_, input, snapshot| {
                ready(&snapshot, cutoff).unwrap();
                // Keep the original pipe held until callback completion.
                let _input = input.unwrap();
                assert!(!panic_callback, "callback panic remains abort");
                OwnedCallbackOutcome::Abort(std::io::Error::from_raw_os_error(5))
            },
        );
        assert!(matches!(result, Err(ProcessTestError::Callback { .. })));
        assert!(started.elapsed() < budget);
    }
}

#[test]
fn output_overflow_remains_secondary_to_frozen_application_failure() {
    let budget = Duration::from_secs(5);
    let cutoff = Instant::now() + budget;
    let (send, receive) = mpsc::sync_channel(1);
    let release = std::thread::spawn(move || {
        let mut input: std::process::ChildStdin = receive
            .recv_timeout(cutoff.saturating_duration_since(Instant::now()))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        input.write_all(b"O").unwrap();
    });
    let result = run_until_owned_spawn_with_io_output_limit_outcome(
        child("terminal_barrier"),
        cutoff,
        256,
        |mut command| command.spawn(),
        move |_, input, snapshot| {
            ready(&snapshot, cutoff).unwrap();
            send.send(input.unwrap()).unwrap();
            OwnedCallbackOutcome::ApplicationEnded(std::io::Error::from_raw_os_error(5))
        },
    );
    release.join().unwrap();
    let Err(ProcessTestError::ApplicationEnded { error, settlement }) = result else {
        panic!("expected retained application error");
    };
    assert_eq!(error.raw_os_error(), Some(5));
    assert!(matches!(
        *settlement.unwrap_err(),
        ProcessTestError::OutputLimit { .. }
    ));
}

#[test]
#[ignore]
fn terminal_barrier() {
    println!("application-ended");
    std::io::stdout().flush().unwrap();
    let mut release = [0];
    std::io::stdin().read_exact(&mut release).unwrap();
    if release == *b"O" {
        std::io::stdout().write_all(&[b'x'; 4096]).unwrap();
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
    assert_eq!(release, *b"T");
    println!("terminal-completed");
    std::io::stdout().flush().unwrap();
    std::process::exit(7);
}
