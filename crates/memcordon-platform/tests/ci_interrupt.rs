#![cfg(all(feature = "test-support", unix))]
use memcordon_platform::test_support::{CiInterrupt, CiInterruptRegistration};
use std::{
    io::{BufRead, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn isolated_native_interrupt_is_observed() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "signal_child", "--ignored", "--nocapture"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = std::io::BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    loop {
        assert_ne!(
            reader.read_line(&mut line).unwrap(),
            0,
            "signal child exited before ready"
        );
        if line.lines().any(|line| line == "interrupt-ready") {
            break;
        }
        line.clear();
    }
    assert!(
        Command::new("kill")
            .args(["-INT", &child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    assert!(child.wait().unwrap().success());
}

#[test]
#[ignore = "isolated child selected by the parent test"]
fn signal_child() {
    let registration = CiInterruptRegistration::install().unwrap();
    let token = registration.token();
    assert!(
        CiInterruptRegistration::install().is_err(),
        "second owner must not reset handlers or signal"
    );
    println!("interrupt-ready");
    std::io::stdout().flush().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while token.observed().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(token.observed(), Some(CiInterrupt::UnixInterrupt));
    assert!(CiInterruptRegistration::install().is_err());
    assert_eq!(token.observed(), Some(CiInterrupt::UnixInterrupt));
    drop(registration);
    assert_eq!(
        token.observed(),
        None,
        "observer does not retain registration"
    );
    let replacement = CiInterruptRegistration::install().unwrap();
    assert_eq!(replacement.token().observed(), None);
    assert_eq!(
        token.observed(),
        None,
        "expired token must not observe a later scope"
    );
}
