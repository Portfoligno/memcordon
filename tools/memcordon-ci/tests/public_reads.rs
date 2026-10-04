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
