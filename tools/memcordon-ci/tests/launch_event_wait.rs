use memcordon_ci::{CiError, launch_event_wait::wait_for_event};
use std::{
    cell::Cell,
    time::{Duration, Instant},
};

#[test]
fn published_event_wins_before_terminal_poll_and_is_rechecked_after_exit() {
    let cutoff = Instant::now() + Duration::from_secs(1);
    wait_for_event(
        cutoff,
        "prepared",
        || Ok(true),
        || panic!("already published event needs no exit poll"),
    )
    .unwrap();
    let published = Cell::new(false);
    wait_for_event(
        cutoff,
        "prepared",
        || Ok(published.get()),
        || {
            published.set(true);
            Ok(true)
        },
    )
    .unwrap();
}

#[test]
fn ended_prerequisite_fails_without_waiting_for_the_suite_deadline() {
    let observations = Cell::new(0);
    let terminal_polls = Cell::new(0);
    let error = wait_for_event(
        Instant::now() + Duration::from_secs(3600),
        "locator",
        || {
            observations.set(observations.get() + 1);
            Ok(false)
        },
        || {
            terminal_polls.set(terminal_polls.get() + 1);
            Ok(true)
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("ended before locator"));
    assert_eq!(observations.get(), 2);
    assert_eq!(terminal_polls.get(), 1);
}

#[test]
fn expired_work_cannot_accept_an_event_or_consume_the_capture_owner() {
    assert!(
        wait_for_event(
            Instant::now(),
            "prepared",
            || panic!("expired work cannot inspect events"),
            || panic!("settlement belongs to caller")
        )
        .is_err()
    );
    let cutoff = Instant::now() + Duration::from_millis(1);
    assert!(
        wait_for_event(
            cutoff,
            "late event",
            || {
                while Instant::now() < cutoff {
                    std::hint::spin_loop();
                }
                Ok(true)
            },
            || panic!("late publication cannot poll the owner")
        )
        .is_err()
    );
}

#[test]
fn observation_and_terminal_errors_keep_their_original_typed_cause() {
    let error = wait_for_event(
        Instant::now() + Duration::from_secs(1),
        "locator",
        || Err(CiError::Io(std::io::Error::from_raw_os_error(5))),
        || panic!("observation error must propagate first"),
    )
    .unwrap_err();
    assert!(matches!(error, CiError::Io(error) if error.raw_os_error() == Some(5)));
    let error = wait_for_event(
        Instant::now() + Duration::from_secs(1),
        "locator",
        || Ok(false),
        || Err(CiError::Cancelled("original owner cancellation".into())),
    )
    .unwrap_err();
    assert!(matches!(error, CiError::Cancelled(detail) if detail == "original owner cancellation"));
}
