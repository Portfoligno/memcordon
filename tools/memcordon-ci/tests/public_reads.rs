use memcordon_ci::{CiError, public_reads::map_public_reads_ordered};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[test]
fn preserves_input_order_and_caps_workers_even_when_requested_limit_is_larger() {
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_secs(10);
    let output = map_public_reads_ordered(
        &[0, 1, 2, 3, 4, 5],
        NonZeroUsize::new(99).unwrap(),
        deadline,
        |index, input, shared| {
            assert_eq!(deadline, shared);
            let count = active.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(count, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(10));
            active.fetch_sub(1, Ordering::SeqCst);
            assert_eq!(index, *input);
            Ok(*input)
        },
    )
    .unwrap();
    assert_eq!(output, [0, 1, 2, 3, 4, 5]);
    assert!(peak.load(Ordering::SeqCst) <= 4);
}

#[test]
fn joins_all_workers_and_returns_first_input_order_failure_including_panics() {
    let completed = AtomicUsize::new(0);
    let error = map_public_reads_ordered(
        &[0, 1, 2, 3, 4],
        NonZeroUsize::new(4).unwrap(),
        Instant::now() + Duration::from_secs(10),
        |_, input, _| {
            completed.fetch_add(1, Ordering::SeqCst);
            match input {
                0 => Err(CiError::Message("first".into())),
                1 => panic!("worker panic"),
                _ => Ok(()),
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "first");
    assert_eq!(completed.load(Ordering::SeqCst), 5);
}

#[test]
fn expired_phase_does_not_execute_reads() {
    let called = AtomicUsize::new(0);
    assert!(
        map_public_reads_ordered(
            &[0],
            NonZeroUsize::new(1).unwrap(),
            Instant::now(),
            |_, _, _| {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(called.load(Ordering::SeqCst), 0);
}

#[test]
fn refills_slots_before_the_first_read_retires() {
    let (started, starts) = std::sync::mpsc::channel();
    let release = std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
    let gate = release.clone();
    let reader = std::thread::spawn(move || {
        map_public_reads_ordered(
            &[0, 1, 2, 3, 4, 5, 6, 7],
            NonZeroUsize::new(4).unwrap(),
            Instant::now() + Duration::from_secs(10),
            |ordinal, input, _| {
                started.send(ordinal).unwrap();
                if ordinal == 0 {
                    let (lock, wake) = &*gate;
                    let mut ready = lock.lock().unwrap();
                    while !*ready {
                        ready = wake.wait(ready).unwrap();
                    }
                }
                Ok(*input)
            },
        )
    });
    let mut observed = Vec::new();
    while !observed.contains(&4) {
        match starts.recv_timeout(Duration::from_secs(5)) {
            Ok(ordinal) => observed.push(ordinal),
            Err(_) => break,
        }
    }
    let (lock, wake) = &*release;
    *lock.lock().unwrap() = true;
    wake.notify_all();
    let result = reader.join().unwrap().unwrap();
    assert!(
        observed.contains(&4),
        "rolling reader did not refill an idle slot"
    );
    assert_eq!(result, [0, 1, 2, 3, 4, 5, 6, 7]);
}

#[test]
fn explicit_stop_closes_admission_and_collect_all_keeps_destination_values() {
    use memcordon_ci::{failure_mode::FailureMode, public_reads::map_public_reads_with_failure};
    let called = AtomicUsize::new(0);
    let error = map_public_reads_with_failure(
        &[0, 1, 2, 3, 4],
        NonZeroUsize::new(1).unwrap(),
        Instant::now() + Duration::from_secs(10),
        FailureMode::StopAfterFailure,
        |ordinal, _, _| {
            called.fetch_add(1, Ordering::SeqCst);
            if ordinal == 1 {
                Err(CiError::Message("observed".into()))
            } else {
                Ok(())
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "observed");
    assert_eq!(called.load(Ordering::SeqCst), 2);
    let values = map_public_reads_ordered(
        &["unknown", "conflicting"],
        NonZeroUsize::new(4).unwrap(),
        Instant::now() + Duration::from_secs(10),
        |_, value, _| Ok(*value),
    )
    .unwrap();
    assert_eq!(values, ["unknown", "conflicting"]);
}

#[test]
fn reads_inherit_the_operation_deadline_stop_state_and_mode() {
    use memcordon_ci::{failure_mode::FailureMode, preparation};
    let deadline = Instant::now() + Duration::from_secs(10);
    preparation::with_operation(FailureMode::CollectAll, deadline, || {
        let root = preparation::active_group().unwrap();
        let values = map_public_reads_ordered(
            &[0, 1],
            NonZeroUsize::new(4).unwrap(),
            deadline + Duration::from_secs(90),
            |_, input, actual| {
                assert_eq!(actual, deadline);
                let callback = preparation::active_group().expect("inherited read owner");
                assert!(std::sync::Arc::ptr_eq(&root.requested, &callback.requested));
                assert_eq!(callback.mode(), FailureMode::CollectAll);
                Ok(*input)
            },
        )?;
        assert_eq!(values, [0, 1]);
        root.close_admission();
        let called = AtomicUsize::new(0);
        assert!(
            map_public_reads_ordered(&[0], NonZeroUsize::new(4).unwrap(), deadline, |_, _, _| {
                called.fetch_add(1, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        assert_eq!(called.load(Ordering::SeqCst), 0);
        Ok(())
    })
    .unwrap();
}

#[test]
fn peer_not_started_observation_cannot_replace_a_required_read_failure() {
    use memcordon_ci::{failure_mode::FailureMode, public_reads::map_public_reads_with_failure};
    let error = map_public_reads_with_failure(
        &[0, 1],
        NonZeroUsize::new(1).unwrap(),
        Instant::now() + Duration::from_secs(10),
        FailureMode::CollectAll,
        |ordinal, _, _| {
            if ordinal == 0 {
                Err(CiError::NotStartedAfterFailure)
            } else {
                Err::<(), _>(CiError::Message("actual read failure".into()))
            }
        },
    )
    .unwrap_err();
    match error {
        CiError::LaneFailures { primary, secondary } => {
            assert_eq!(primary.to_string(), "actual read failure");
            assert!(matches!(*secondary, CiError::NotStartedAfterFailure));
        }
        _ => panic!("required cause or secondary cancellation was lost"),
    }
}
