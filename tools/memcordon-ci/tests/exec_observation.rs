use memcordon_ci::{
    CiError,
    exec_observation::{cutoff, observe},
};
use std::{
    cell::RefCell,
    time::{Duration, Instant},
};

#[test]
fn held_capture_precedes_release_and_dependent_event_observation() {
    let phases = RefCell::new(Vec::new());
    observe(
        Instant::now() + Duration::from_secs(30),
        || {
            phases.borrow_mut().push("held-image-and-identity");
            Ok(())
        },
        || {
            assert_eq!(*phases.borrow(), ["held-image-and-identity"]);
            phases.borrow_mut().push("exec-released");
            Ok(())
        },
        || {
            assert_eq!(
                *phases.borrow(),
                ["held-image-and-identity", "exec-released"]
            );
            phases.borrow_mut().push("source-permission");
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        *phases.borrow(),
        [
            "held-image-and-identity",
            "exec-released",
            "source-permission"
        ]
    );
}

#[test]
fn errors_and_expired_cutoffs_never_admit_later_phases() {
    let failure = || Err(CiError::Io(std::io::Error::from_raw_os_error(5)));
    let error = observe(
        Instant::now() + Duration::from_secs(30),
        failure,
        || panic!("failed custody cannot release"),
        || panic!("failed custody cannot wait"),
    )
    .unwrap_err();
    assert!(matches!(error,CiError::Io(ref native) if native.raw_os_error()==Some(5)));
    let error = observe(
        Instant::now() + Duration::from_secs(30),
        || Ok(()),
        failure,
        || panic!("failed release cannot wait"),
    )
    .unwrap_err();
    assert!(matches!(error,CiError::Io(ref native) if native.raw_os_error()==Some(5)));
    assert!(
        observe(
            Instant::now(),
            || panic!("expired capture"),
            || panic!("expired release"),
            || panic!("expired wait")
        )
        .is_err()
    );
}

#[test]
fn original_outer_and_local_deadlines_clip_the_same_absolute_operation() {
    let started = Instant::now();
    let local = Duration::from_secs(300);
    let outer = started + Duration::from_secs(7576);
    assert_eq!(cutoff(started, local, outer).unwrap(), started + local);
    let outer = started + Duration::from_secs(40);
    assert_eq!(cutoff(started, local, outer).unwrap(), outer);
    assert_eq!(
        cutoff(started + Duration::from_secs(20), local, outer).unwrap(),
        outer
    );
    assert!(cutoff(started, Duration::ZERO, outer).is_err());
    assert!(cutoff(outer, local, outer).is_err());
    let budget = memcordon_ci::command::remaining_budget(
        local,
        Duration::from_secs(40),
        Duration::from_secs(10),
    )
    .unwrap();
    assert_eq!(
        cutoff(started, budget, outer).unwrap(),
        started + Duration::from_secs(30)
    );
}

#[test]
fn exhausted_absolute_supervision_refuses_before_any_spawn_or_callback() {
    let error = memcordon_testkit::run_until_owned_spawn_after_output_limit(
        std::process::Command::new("must-not-spawn"),
        Instant::now(),
        1024,
        |_| panic!("expired original deadline must not spawn"),
        |_| panic!("expired original deadline must not admit callback"),
    )
    .unwrap_err();
    assert!(
        matches!(error, memcordon_testkit::ProcessTestError::Spawn(ref error) if error.kind() == std::io::ErrorKind::TimedOut)
    );
}
