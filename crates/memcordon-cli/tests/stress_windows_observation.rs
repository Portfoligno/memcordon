#[path = "support/stress_windows_observation.rs"]
mod observation;

use observation::*;
use std::{
    cell::Cell,
    rc::Rc,
    time::{Duration, Instant},
};

fn cli() -> Identity {
    Identity {
        pid: 10,
        birth: 100,
    }
}
fn cli_live() -> Sample {
    Sample {
        identity: cli(),
        status: None,
    }
}
fn fixture(status: Option<u32>) -> FixtureSample {
    FixtureSample {
        process: Sample {
            identity: Identity {
                pid: 11,
                birth: 101,
            },
            status,
        },
        parent_pid: cli().pid,
        image_matches: true,
    }
}

#[test]
fn an_expired_original_cutoff_performs_no_query() {
    let calls = Cell::new(0);
    let result = guarded_query(Instant::now(), || {
        calls.set(calls.get() + 1);
        Ok(17)
    });
    assert_eq!(result, Err(Stop::Deadline));
    assert_eq!(calls.get(), 0);
}

#[test]
fn a_late_owned_query_result_is_dropped_without_committing_candidate_observations() {
    struct ReturnedOwner(Rc<Cell<usize>>);
    impl Drop for ReturnedOwner {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    let dropped = Rc::new(Cell::new(0));
    let entered = Cell::new(false);
    let mut retained = Observation::default();
    let before = retained.clone();
    let cutoff = Instant::now() + Duration::from_millis(100);
    let result = guarded_query(cutoff, || {
        entered.set(true);
        let owner = ReturnedOwner(Rc::clone(&dropped));
        let mut candidate = retained.clone();
        record_fixture(&mut candidate, cli(), fixture(Some(1)), cli_live(), 7)?;
        std::thread::sleep(
            cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
        );
        Ok((owner, candidate))
    });
    match result {
        Ok((_owner, candidate)) => retained = candidate,
        Err(error) => assert_eq!(error, Stop::Deadline),
    }
    assert!(
        entered.get(),
        "post-query cutoff path must actually execute"
    );
    assert_eq!(dropped.get(), 1);
    assert_eq!(retained, before);
}

#[test]
fn observed_fixture_exit_retains_native_status_without_claiming_product_cleanup() {
    let mut value = Observation::default();
    record_fixture(&mut value, cli(), fixture(None), cli_live(), 3).unwrap();
    assert_eq!(value.phase, Phase::ObservedFixtureLiveWhileCliLive);
    assert_eq!(value.fixture_status, None);
    record_fixture(&mut value, cli(), fixture(Some(1)), cli_live(), 7).unwrap();
    assert_eq!(value.phase, Phase::ObservedFixtureExitedWhileCliLive);
    assert_eq!(value.fixture_status, Some(1));
    assert_eq!(value.cli_status, None, "a fixture exit is not the CLI exit");
    assert_eq!(value.observed_at_ms, Some(7));
    assert_eq!(value.fixture, Some(fixture(None).process.identity));
    value.stop = Some(Stop::QueryUnavailable {
        operation: "native query",
        native_code: Some(5),
    });
    let summary = format!("{value:?}");
    assert!(summary.contains("fixture_status: Some(1)"));
    assert!(summary.contains("native_code: Some(5)"));
    for forbidden in [
        "handle:",
        "HANDLE",
        "environment",
        "command:",
        "SID",
        "\\Device\\",
    ] {
        assert!(
            !summary.contains(forbidden),
            "diagnostic summary exposed an unapproved field"
        );
    }
}

#[test]
fn wrong_native_binding_ambiguity_and_quick_cli_exit_never_mint_fixture_facts() {
    let invalid: &[fn(&mut FixtureSample, &mut Sample)] = &[
        |f, _| f.parent_pid += 1,
        |f, _| f.image_matches = false,
        |f, _| f.process.identity.pid = 0,
        |f, _| f.process.identity.pid = cli().pid,
        |f, _| f.process.identity.birth = cli().birth - 1,
        |_, c| c.identity.birth += 1,
        |_, c| c.identity.pid += 1,
    ];
    for mutate in invalid {
        let mut value = Observation::default();
        let before = value.clone();
        let mut child = fixture(None);
        let mut after = cli_live();
        mutate(&mut child, &mut after);
        assert_eq!(
            record_fixture(&mut value, cli(), child, after, 4),
            Err(Stop::IdentityMismatch)
        );
        assert_eq!(value, before);
    }
    for status in [0, 1] {
        let mut value = Observation::default();
        assert_eq!(
            record_fixture(
                &mut value,
                cli(),
                fixture(Some(1)),
                Sample {
                    identity: cli(),
                    status: Some(status)
                },
                4
            ),
            Err(Stop::CliExited)
        );
        assert_eq!(value.phase, Phase::Unknown);
        assert!(value.fixture.is_none() && value.fixture_status.is_none());
    }
    let mut value = Observation::default();
    record_fixture(&mut value, cli(), fixture(None), cli_live(), 3).unwrap();
    let before = value.clone();
    let mut reused = fixture(None);
    reused.process.identity.birth += 1;
    assert_eq!(
        record_fixture(&mut value, cli(), reused, cli_live(), 4),
        Err(Stop::Ambiguous)
    );
    assert_eq!(value, before);
    for identity in [Identity { pid: 0, birth: 1 }, Identity { pid: 1, birth: 0 }] {
        assert_eq!(
            validate_held(
                identity,
                Sample {
                    identity,
                    status: None
                }
            ),
            Err(Stop::IdentityMismatch)
        );
    }
}

#[cfg(windows)]
#[test]
fn actual_quick_original_cli_keeps_its_status_without_inventing_a_fixture_stage() {
    let image = std::env::current_exe().unwrap();
    let mut command = std::process::Command::new(&image);
    command.args([
        "--exact",
        "native_observation_child_requires_the_existing_outer_job",
        "--ignored",
        "--nocapture",
    ]);
    let (result, monitor) = observation::Observer::global().run(
        command,
        &image,
        Instant::now() + Duration::from_secs(5),
        || {},
    );
    let value = monitor.snapshot();
    let output =
        result.expect("original native self-child must settle in its existing test boundary");
    assert!(
        output.status.success(),
        "native self-child did not return its original zero status"
    );
    assert_eq!(value.phase, Phase::Unknown);
    assert!(value.fixture.is_none() && value.fixture_status.is_none());
    if let Some(status) = value.cli_status {
        assert_eq!(status, 0);
    }
    // A diagnostic miss/loss is unknown, not evidence that no process ran or
    // permission to alter the original command's result.
    assert!(value.stop.is_some());
}

#[cfg(windows)]
fn binary_child_command() -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "native_observation_binary_child",
        "--ignored",
        "--nocapture",
    ]);
    command
}

#[cfg(windows)]
#[test]
fn a_pending_diagnostic_cannot_gate_original_status_capture_or_cleanup() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    let mut baseline_command = binary_child_command();
    let baseline =
        memcordon_testkit::run_with_deadline(&mut baseline_command, Duration::from_secs(5))
            .expect("baseline original child must settle");
    assert_eq!(baseline.status.code(), Some(37));
    let observer = observation::Observer::default();
    let started = Instant::now();
    let cutoff = started + Duration::from_secs(5);
    // Test-only cleanup for the deliberately blocked diagnostic is fixed at
    // test entry. It never extends either original command's cutoff or wait.
    let test_cleanup = started + Duration::from_secs(10);
    let (ready_send, ready_receive) = mpsc::sync_channel(1);
    let (release_send, release_receive) = mpsc::sync_channel(1);
    let image = std::env::current_exe().unwrap();
    let (result, monitor) = observer.run(binary_child_command(), &image, cutoff, move || {
        ready_send
            .try_send(())
            .expect("signal bounded diagnostic work entry");
        release_receive
            .recv()
            .expect("release test-owned diagnostic work");
    });
    let output = result.expect("pending diagnostics must not gate original completion");
    assert!(
        Instant::now() < cutoff,
        "original command must complete while diagnostic work remains pending"
    );
    assert_eq!(output.status.code(), Some(37));
    assert_eq!(output.stdout, baseline.stdout);
    assert_eq!(output.stderr, baseline.stderr);
    ready_receive
        .recv_timeout(cutoff.saturating_duration_since(Instant::now()))
        .expect("diagnostic must really enter its owned blocked step");
    let pending = monitor.snapshot();
    assert_eq!(pending.observer_state, ObserverState::Pending);
    assert_eq!(pending.phase, Phase::Unknown);
    assert!(pending.fixture.is_none() && pending.fixture_status.is_none());

    let second_worker_started = Arc::new(AtomicBool::new(false));
    let second_flag = Arc::clone(&second_worker_started);
    let (second, skipped) = observer.run(binary_child_command(), &image, cutoff, move || {
        second_flag.store(true, Ordering::Release);
    });
    let second = second.expect("a busy diagnostic slot must not gate another original command");
    assert_eq!(second.status.code(), Some(37));
    assert_eq!(second.stdout, baseline.stdout);
    assert_eq!(second.stderr, baseline.stderr);
    let skipped = skipped.snapshot();
    assert_eq!(skipped.stop, Some(Stop::ObserverBusy));
    assert!(skipped.cli.is_none() && skipped.fixture.is_none());
    assert!(!second_worker_started.load(Ordering::Acquire));

    // Keep the worker in flight beyond the ORIGINAL cutoff, then let its
    // guarded late return close references without any new process query.
    std::thread::sleep(cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
    release_send
        .send(())
        .expect("release only our diagnostic worker");
    loop {
        let closed = monitor.snapshot();
        if closed.observer_state == ObserverState::QueryReferencesClosed {
            assert_eq!(closed.phase, Phase::Unknown);
            assert!(closed.fixture.is_none() && closed.fixture_status.is_none());
            break;
        }
        assert!(
            Instant::now() < test_cleanup,
            "test-owned diagnostic references did not close"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[cfg(windows)]
#[test]
#[ignore = "owned binary-output child invoked by the pending diagnostic regression"]
fn native_observation_binary_child() {
    use std::io::Write;
    native_observation_child_requires_the_existing_outer_job();
    std::io::stdout().write_all(&[0, 255, 1]).unwrap();
    std::io::stdout().flush().unwrap();
    std::io::stderr().write_all(&[4, 0, 128]).unwrap();
    std::io::stderr().flush().unwrap();
    std::process::exit(37);
}

#[cfg(windows)]
#[test]
#[ignore = "owned self-child invoked only by the native observation test"]
fn native_observation_child_requires_the_existing_outer_job() {
    use windows_sys::Win32::System::{JobObjects::IsProcessInJob, Threading::GetCurrentProcess};
    let mut in_job = 0;
    // SAFETY: current process pseudo-handle and one initialized Boolean output.
    let queried = unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) };
    assert_ne!(queried, 0, "native child Job membership query failed");
    assert_ne!(
        in_job, 0,
        "native self-child escaped the existing outer Job"
    );
}
