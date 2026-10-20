use memcordon_ci::{
    CiError,
    command::CommandSpec,
    work_outcome::{WorkOutcome, WriterSettlement},
};
use std::time::Duration;

#[test]
fn settlement_join_has_unknown_dominance() {
    use WriterSettlement::{NotStarted as N, Settled as S, Unknown as U};
    for (left, right, expected) in [
        (N, N, N),
        (N, S, S),
        (N, U, U),
        (S, N, S),
        (S, S, S),
        (S, U, U),
        (U, N, U),
        (U, S, U),
        (U, U, U),
    ] {
        assert_eq!(left.join(right), expected);
    }
}

#[test]
fn synchronous_validation_preserves_settlement_and_primary_error() {
    let outcome = WorkOutcome::from_result(Ok(()))
        .validate_after(|_| Err(CiError::Message("lock changed".into())));
    assert_eq!(outcome.writers(), WriterSettlement::Settled);
    let outcome = outcome.postcondition(Err(CiError::Message("output failed".into())));
    assert!(
        outcome
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("primary lane: lock changed; secondary lane: output failed")
    );
    assert_eq!(
        WorkOutcome::<()>::from_result(Err(CiError::Message("unknown owner".into()))).writers(),
        WriterSettlement::Unknown
    );
}

#[test]
fn native_finalization_preserves_later_unknown_after_an_earlier_output_error() {
    let actual = child("child_fails", Duration::from_secs(10))
        .run_owned()
        .map(|_| ());
    assert_eq!(actual.writers(), WriterSettlement::Settled);
    let retention = Err(CiError::LaneFailures {
        primary: Box::new(CiError::Io(std::io::Error::other("output append failed"))),
        secondary: Box::new(CiError::Process(
            memcordon_testkit::ProcessTestError::Output(std::io::Error::other(
                "native cache reader ownership unresolved",
            )),
        )),
    });
    let finalization = actual.post_finalization(retention);
    assert_eq!(finalization.writers(), WriterSettlement::Unknown);
    let error = finalization.into_result().unwrap_err();
    assert!(memcordon_ci::work_outcome::has_unresolved_owner(&error));
    let message = error.to_string();
    assert!(message.contains("output append failed"));
    assert!(message.contains("native cache reader ownership unresolved"));
}

#[test]
fn joined_unknown_lane_dominates_and_failed_sequence_never_starts_next_work() {
    use memcordon_ci::work_outcome::join_completed;
    let first = WorkOutcome::<()>::from_result(Err(CiError::SettledCommandFailure(
        "first actual failure".into(),
    )));
    let second = WorkOutcome::from_result(Err(CiError::Message("peer owner unresolved".into())));
    let joined = join_completed(first, second);
    assert_eq!(joined.writers(), WriterSettlement::Unknown);
    let mut started = false;
    let failed = joined.then_owned(|_| {
        started = true;
        WorkOutcome::from_result(Ok(()))
    });
    assert!(!started);
    let text = failed.into_result().unwrap_err().to_string();
    assert!(
        text.starts_with(
            "primary lane: first actual failure; secondary lane: peer owner unresolved"
        )
    );
}

fn child(test: &str, timeout: Duration) -> CommandSpec {
    CommandSpec::new(
        std::env::current_exe().unwrap(),
        &std::env::current_dir().unwrap(),
        timeout,
    )
    .args(["--ignored", "--exact", test, "--nocapture"])
}

#[test]
fn actual_nonzero_child_is_failed_and_settled() {
    let outcome = child("child_fails", Duration::from_secs(10)).run_owned();
    assert!(!outcome.is_ok());
    assert_eq!(outcome.writers(), WriterSettlement::Settled);
    assert!(outcome.into_result().is_err());
}

#[test]
fn actual_timeout_reaps_child_and_readers_without_passing_work() {
    // Match the testkit's settled-timeout oracle: a hosted native spawn took
    // 262ms, exceeding the former 200ms before its callback could be admitted.
    let outcome = child("child_waits", Duration::from_secs(1)).run_owned();
    assert!(!outcome.is_ok());
    let writers = outcome.writers();
    let error = outcome.into_result().unwrap_err();
    assert_eq!(
        writers,
        WriterSettlement::Settled,
        "inner command: {error:?}"
    );
    assert!(
        error.to_string().contains("exceeded"),
        "inner command: {error:?}"
    );
}

#[test]
fn actual_output_cap_preserves_failed_settled_observation() {
    let outcome = child("child_floods", Duration::from_secs(10))
        .output_limit(1024)
        .run_owned();
    assert!(!outcome.is_ok());
    assert_eq!(outcome.writers(), WriterSettlement::Settled);
    assert!(
        outcome
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("output exceeds")
    );
}

#[test]
fn spawn_failure_is_truthfully_not_started() {
    let outcome = CommandSpec::new(
        "/nonexistent/memcordon-owned-child",
        &std::env::current_dir().unwrap(),
        Duration::from_secs(1),
    )
    .run_owned();
    assert!(!outcome.is_ok());
    assert_eq!(outcome.writers(), WriterSettlement::NotStarted);
}

#[test]
fn actual_peer_cancellation_is_failed_after_owned_settlement() {
    use memcordon_ci::{command::PeerStopPolicy, failure_mode::FailureMode, preparation};
    let directory = tempfile::tempdir().unwrap();
    let signal = directory.path().join("child-started");
    preparation::with_operation(
        FailureMode::StopAfterFailure,
        std::time::Instant::now() + Duration::from_secs(30),
        || {
            let group = preparation::active_group().unwrap();
            std::thread::scope(|scope| {
                scope.spawn(move || {
                    let cutoff = std::time::Instant::now() + Duration::from_secs(5);
                    while !signal.exists() {
                        assert!(
                            std::time::Instant::now() < cutoff,
                            "native child did not publish its start"
                        );
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    group.close_admission();
                });
                let outcome = CommandSpec::new(
                    std::env::current_exe().unwrap(),
                    directory.path(),
                    Duration::from_secs(5),
                )
                .args([
                    "--ignored",
                    "--exact",
                    "child_signals_and_waits",
                    "--nocapture",
                ])
                .peer_stop_policy(PeerStopPolicy::CancelAndSettle)
                .run_owned();
                assert!(!outcome.is_ok());
                let writers = outcome.writers();
                let error = outcome.into_result().unwrap_err();
                assert_eq!(writers, WriterSettlement::Settled, "{error}");
                assert!(error.to_string().contains("cause=peer-failure"));
            });
            Ok(())
        },
    )
    .unwrap();
}

#[cfg(unix)]
#[test]
fn creation_observation_failure_keeps_original_error_and_real_settlement() {
    let record = tempfile::NamedTempFile::new().unwrap();
    let readonly = std::fs::File::open(record.path()).unwrap();
    let result = child("child_succeeds", Duration::from_secs(5))
        .output_quiet_with_stdin_and_creation(&readonly, |_| {
            Err(CiError::Message("creation observation failed".into()))
        });
    let outcome = WorkOutcome::from_result(result);
    assert!(!outcome.is_ok());
    assert_eq!(outcome.writers(), WriterSettlement::Settled);
    assert_eq!(
        outcome.into_result().unwrap_err().to_string(),
        "creation observation failed"
    );
}

#[test]
#[ignore = "native argv child fixture"]
fn child_succeeds() {}

#[test]
#[ignore = "native argv child fixture"]
fn child_signals_and_waits() {
    std::fs::write("child-started", b"actual child started\n").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "native argv child fixture"]
fn child_fails() {
    panic!("deliberate child failure after output");
}

#[test]
#[ignore = "native argv child fixture"]
fn child_waits() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "native argv child fixture"]
fn child_floods() {
    use std::io::Write;
    let payload = [b'x'; 64 * 1024];
    let _ = std::io::stdout().write_all(&payload);
    std::thread::sleep(Duration::from_secs(30));
}
