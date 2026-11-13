use memcordon_testkit::{
    ProcessTestError, run_until_owned_spawn_with_io_controlled_output_limit,
    run_until_owned_spawn_with_io_output_limit,
};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
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
#[test]
fn absolute_owned_io_uses_the_original_pipe_and_settles_readers() {
    let observed = run_until_owned_spawn_with_io_output_limit(
        child("echo_input"),
        Instant::now() + Duration::from_secs(5),
        4096,
        |mut command| command.spawn(),
        |_, input, _| {
            let mut input = input.unwrap();
            input.write_all(b"exact-owned-pipe")?;
            drop(input);
            Ok(())
        },
    )
    .unwrap();
    assert!(observed.status.success());
    assert!(
        observed
            .stdout
            .windows(b"echo:exact-owned-pipe".len())
            .any(|value| value == b"echo:exact-owned-pipe")
    );
}
#[test]
fn expired_absolute_io_never_spawns_and_cancelled_owner_settles_its_exact_helper() {
    let spawned = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&spawned);
    let result = run_until_owned_spawn_with_io_output_limit(
        child("echo_input"),
        Instant::now(),
        4096,
        move |mut command| {
            seen.store(true, Ordering::Release);
            command.spawn()
        },
        |_, _, _| Ok(()),
    );
    assert!(matches!(result, Err(ProcessTestError::Spawn(_))));
    assert!(!spawned.load(Ordering::Acquire));
    let cancelled = Arc::new(AtomicBool::new(false));
    let stop = Arc::clone(&cancelled);
    let cutoff = Instant::now() + Duration::from_secs(5);
    let result = run_until_owned_spawn_with_io_controlled_output_limit(
        child("wait_for_owned_stop"),
        cutoff,
        4096,
        Some(cancelled),
        |mut command| command.spawn(),
        move |_, _, snapshot| {
            while Instant::now() < cutoff {
                if snapshot
                    .stdout()?
                    .windows(b"owned-ready".len())
                    .any(|value| value == b"owned-ready")
                {
                    stop.store(true, Ordering::Release);
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "helper readiness",
            ))
        },
    );
    let Err(ProcessTestError::Cancelled {
        cleanup,
        observation,
        ..
    }) = result
    else {
        panic!("expected exact owned cancellation");
    };
    assert!(cleanup.is_ok());
    assert!(observation.callback_completed);
    assert!(observation.stdout_reader_finished && observation.stderr_reader_finished);
}
#[test]
#[ignore]
fn echo_input() {
    let mut bytes = Vec::new();
    std::io::stdin().read_to_end(&mut bytes).unwrap();
    println!("echo:{}", String::from_utf8(bytes).unwrap());
}
#[test]
#[ignore]
fn wait_for_owned_stop() {
    println!("owned-ready");
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
