#![cfg(all(target_os = "macos", feature = "test-support"))]
use memcordon_platform::MacosLaunchRuntime;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

fn drain(runtime: &MacosLaunchRuntime) {
    let limit = Instant::now() + Duration::from_secs(5);
    while runtime.outstanding() != 0 {
        assert!(
            Instant::now() < limit,
            "native obligations did not actually retire"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn bounded_drop<T>(value: T) -> bool {
    let started = Instant::now();
    drop(value);
    started.elapsed() < Duration::from_millis(50)
}

#[test]
fn completed_runtime_shutdown_restores_actual_native_threads_and_descriptors() {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "isolated_runtime_resource_baseline",
        "--ignored",
        "--test-threads=1",
    ]);
    let output =
        memcordon_testkit::run_with_deadline(&mut command, Duration::from_secs(15)).unwrap();
    assert!(
        output.status.success(),
        "isolated resource baseline failed: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .contains("test isolated_runtime_resource_baseline ... ok")
    );
}

#[test]
#[ignore = "invoked in an isolated native process by completed_runtime_shutdown_restores_actual_native_threads_and_descriptors"]
fn isolated_runtime_resource_baseline() {
    use memcordon_platform::{
        DeliveryLimits, DeliveryOutcome, DeliveryRequest, MacosDeliveryRuntime, WriterImage,
    };
    let descriptors = || std::fs::read_dir("/dev/fd").unwrap().count();
    let threads = || MacosLaunchRuntime::test_process_thread_count().unwrap();
    let initial_descriptors = descriptors();
    let initial_threads = threads();
    for _ in 0..4 {
        let launch = MacosLaunchRuntime::new(1).unwrap();
        let child = launch.test_native_child(true).unwrap();
        assert!(bounded_drop(child));
        drain(&launch);
        drop(launch);
        let delivery = MacosDeliveryRuntime::new(
            DeliveryLimits::default(),
            WriterImage::Installed(env!("CARGO_BIN_EXE_memcordon").into()),
        )
        .unwrap();
        assert!(matches!(
            delivery.deliver(DeliveryRequest::new(vec![b'\n'], None, None, None)),
            DeliveryOutcome::Completed { .. }
        ));
        assert!(bounded_drop(delivery));
        let deadline = Instant::now() + Duration::from_secs(3);
        while threads() != initial_threads || descriptors() != initial_descriptors {
            assert!(
                Instant::now() < deadline,
                "quiescent native resources did not return: threads={} expected={}, descriptors={} expected={}",
                threads(),
                initial_threads,
                descriptors(),
                initial_descriptors
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

#[test]
fn native_terminal_observation_does_not_reap_and_repeated_wait_is_cached() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let mut child = runtime.test_native_child(false).unwrap();
    let limit = Instant::now() + Duration::from_secs(5);
    while child.observe().unwrap().is_none() {
        assert!(Instant::now() < limit);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(runtime.outstanding(), 1);
    assert_eq!(
        runtime.test_native_child(false).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let first = child.reaped_within(Duration::from_secs(5)).unwrap();
    assert!(first.success());
    assert_eq!(child.try_wait().unwrap().unwrap(), first);
    assert_eq!(runtime.outstanding(), 0);
    let mut reused = runtime.test_native_child(false).unwrap();
    assert!(
        !child.retirement_pending(),
        "old generation must not observe the reused slot's obligation"
    );
    drop(child);
    assert!(
        reused
            .reaped_within(Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn live_child_drop_returns_promptly_and_native_reaper_recovers_capacity() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let child = runtime.test_native_child(true).unwrap();
    assert!(bounded_drop(child), "Drop blocked on native cancellation");
    drain(&runtime);
    let mut next = runtime.test_native_child(false).unwrap();
    assert!(
        next.reaped_within(Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn native_drop_return_oracle_detects_deliberate_blocking_drop_mutation() {
    struct BlockingDrop<T>(Option<T>);
    impl<T> Drop for BlockingDrop<T> {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(200));
            drop(self.0.take());
        }
    }
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let child = runtime.test_native_child(true).unwrap();
    assert!(
        !bounded_drop(BlockingDrop(Some(child))),
        "same native return-bound oracle must fail the blocking Drop mutation"
    );
    drain(&runtime);
}

#[test]
fn external_waiter_loss_stays_charged_and_refuses_pid_signalling() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let mut child = runtime.test_native_child(false).unwrap();
    child.consume_by_external_waiter().unwrap();
    assert_eq!(
        child.terminate().unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(child.try_wait().is_err());
    drop(child);
    assert_eq!(
        runtime.outstanding(),
        1,
        "lost ownership fabricated a clean reap"
    );
    assert_eq!(
        runtime.test_native_child(false).err().unwrap().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let independent = MacosLaunchRuntime::new(1).unwrap();
    let mut ordinary = independent.test_native_child(false).unwrap();
    assert!(
        ordinary
            .reaped_within(Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn shutdown_during_delayed_creation_is_nonblocking_and_late_child_is_not_discarded() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let observer = runtime.observer();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let response = runtime
        .test_delayed_native_creation(entered.clone(), release.clone())
        .unwrap();
    let limit = Instant::now() + Duration::from_secs(5);
    while !entered.load(Ordering::Acquire) {
        assert!(Instant::now() < limit);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(runtime.outstanding(), 1);
    drop(response); // Caller cancellation while actual child publication is late.
    let started = Instant::now();
    drop(runtime);
    assert!(started.elapsed() < Duration::from_millis(50));
    release.store(true, Ordering::Release);
    let limit = Instant::now() + Duration::from_secs(5);
    while observer.outstanding() != 0 {
        assert!(
            Instant::now() < limit,
            "closed runtime discarded rather than reaped its late native child"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    // Subsequent runtime independence exercises closure without a global gate.
    let independent = MacosLaunchRuntime::new(1).unwrap();
    let mut child = independent.test_native_child(false).unwrap();
    assert!(
        child
            .reaped_within(Duration::from_secs(5))
            .unwrap()
            .success()
    );
}

#[test]
fn pending_creation_observation_requires_exact_retirement_with_fixed_expiry() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let entered = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (response, observation) = runtime
        .test_observed_delayed_native_creation(entered.clone(), release.clone())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while !entered.load(Ordering::Acquire) {
        if Instant::now() >= deadline {
            release.store(true, Ordering::Release);
            panic!("owned child creation did not reach the publication gate");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    drop(response); // Force late publication into the owned native reaper.
    let expired = Instant::now();
    let pending_at_expiry = !observation.settled_until(expired);
    release.store(true, Ordering::Release);
    assert!(pending_at_expiry);
    assert!(observation.settled_until(deadline));
    let mut next = runtime.test_native_child(true).unwrap();
    assert!(
        observation.settled_until(expired),
        "later generation is independent"
    );
    next.terminate().unwrap();
    next.reaped_within(Duration::from_secs(1)).unwrap();
}

#[test]
fn no_child_completion_and_ownership_loss_have_distinct_cleanup_proof() {
    let runtime = MacosLaunchRuntime::new(1).unwrap();
    let no_child = runtime.test_observed_no_child_completion().unwrap();
    let mut child = runtime.test_native_child(false).unwrap();
    let owned = child.creation_observation();
    assert!(no_child.settled_until(Instant::now()));
    child.consume_by_external_waiter().unwrap();
    assert!(child.try_wait().is_err());
    drop(child);
    let deadline = Instant::now() + Duration::from_millis(10);
    assert!(
        !owned.settled_until(deadline),
        "OwnershipLost is never clean"
    );
    assert!(
        !owned.settled_until(deadline),
        "expired bound is not renewed"
    );
}
