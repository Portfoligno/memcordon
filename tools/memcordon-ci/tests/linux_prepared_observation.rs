#![cfg(unix)]
//! These tests exercise retained-child sequencing. Production authenticates
//! every candidate through its unchanged PreparedLinuxObserver acquisition.
#[path = "../src/release/linux_prepared_observation.rs"]
mod prepared;

use std::{
    cell::Cell,
    io::{self, Read, Write},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

struct Fixture {
    child: Child,
    cleanup: Instant,
}
impl Fixture {
    fn start() -> Self {
        let cleanup = Instant::now() + Duration::from_secs(10);
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "prepared_child_worker",
                "--nocapture",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let child = command.spawn().unwrap();
        let fixture = Self { child, cleanup };
        drop(command);
        fixture
    }
    fn release(&mut self, code: u8) {
        self.child.stdin.take().unwrap().write_all(&[code]).unwrap();
    }
    fn observe_retirement(&mut self) -> ExitStatus {
        loop {
            assert!(
                Instant::now() < self.cleanup,
                "original fixture cleanup cutoff expired"
            );
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            std::thread::yield_now();
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.child.stdin.take();
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let _ = self.child.kill();
        while Instant::now() < self.cleanup {
            if self.child.try_wait().ok().flatten().is_some() {
                return;
            }
            std::thread::yield_now();
        }
        // Never detach an unretired test child or turn a kill request into proof.
        // Process shutdown is the failure-only ownership boundary.
        std::process::abort();
    }
}

#[test]
#[ignore = "isolated child invoked only by the retained-owner parent tests"]
fn prepared_child_worker() {
    let mut value = [0];
    if std::io::stdin().read_exact(&mut value).is_err() {
        std::process::exit(98);
    }
    std::process::exit(match value[0] {
        0 => 0,
        1 => 23,
        _ => 99,
    });
}

#[test]
fn original_child_retirement_is_observed_each_sweep_without_waiting_for_cutoff() {
    for (command, expected) in [(0, 0), (1, 23)] {
        let mut fixture = Fixture::start();
        let mut release = fixture.child.stdin.take().unwrap();
        let scans = Cell::new(0);
        let mut retained = None;
        let outcome = prepared::wait::<(), io::Error>(
            &mut fixture.child,
            &mut retained,
            fixture.cleanup,
            || {
                scans.set(scans.get() + 1);
                if scans.get() == 1 {
                    release.write_all(&[command])?;
                }
                Ok(None)
            },
        )
        .unwrap();
        let status = match outcome {
            prepared::Outcome::Retired(status) => status,
            _ => panic!("neither exit0 nor failure may manufacture prepared proof"),
        };
        assert_eq!(status.code(), Some(expected));
        assert_eq!(retained, Some(status));
        assert_eq!(fixture.child.try_wait().unwrap(), Some(status));
        assert!(
            scans.get() >= 2,
            "retirement requires a final candidate scan"
        );
        assert!(Instant::now() < fixture.cleanup);
    }
}

#[test]
fn final_scan_remains_under_caller_validation_after_original_exit() {
    let mut fixture = Fixture::start();
    fixture.release(0);
    let actual = fixture.observe_retirement();
    let mut retained = None;
    let scans = Cell::new(0);
    let result = prepared::wait(&mut fixture.child, &mut retained, fixture.cleanup, || {
        scans.set(scans.get() + 1);
        Ok::<_, io::Error>((scans.get() == 2).then_some("caller-validated-candidate"))
    })
    .unwrap();
    assert!(matches!(
        result,
        prepared::Outcome::Prepared("caller-validated-candidate")
    ));
    assert_eq!(scans.get(), 2);
    assert_eq!(retained, Some(actual));

    let scans = Cell::new(0);
    let error =
        prepared::wait::<(), io::Error>(&mut fixture.child, &mut retained, fixture.cleanup, || {
            scans.set(scans.get() + 1);
            if scans.get() == 2 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            Ok(None)
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(retained, Some(actual));
}

#[test]
fn original_expired_cutoff_never_scans_or_turns_live_child_into_success() {
    let mut fixture = Fixture::start();
    let mut retained = None;
    let outcome =
        prepared::wait::<(), io::Error>(&mut fixture.child, &mut retained, Instant::now(), || {
            panic!("expired operation must not renew observation work")
        })
        .unwrap();
    assert!(matches!(outcome, prepared::Outcome::Expired));
    assert!(retained.is_none());
    assert!(fixture.child.try_wait().unwrap().is_none());
    fixture.release(0);
    assert_eq!(fixture.observe_retirement().code(), Some(0));
}
