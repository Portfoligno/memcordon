use super::*;

#[test]
fn second_spawn_failure_is_primary_when_neither_callback_was_admitted() {
    let mut root = new_group(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
    );
    root.compiler_jobs = 2;
    root.close_admission();
    let _guard = GroupGuard::install(root);
    FAILED_OWNER_SPAWN.with(|slot| slot.set(Some(1)));
    let pair = complete_owned_pair(
        Layout::Parallel,
        [1, 1],
        || -> crate::work_outcome::WorkOutcome<()> { panic!("first callback must not start") },
        || -> crate::work_outcome::WorkOutcome<()> { panic!("second callback must not exist") },
    );
    FAILED_OWNER_SPAWN.with(|slot| slot.set(None));
    assert_eq!(pair.first_cause, Some(LaneId::Second));
    assert!(matches!(
        pair.first.into_result(),
        Err(CiError::NotStartedAfterFailure)
    ));
    assert!(
        pair.second
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("injected owner spawn failure")
    );
}

#[test]
fn actual_spawn_error_is_retained_beside_the_other_lane_failure() {
    let mut root = new_group(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
    );
    root.compiler_jobs = 2;
    let _guard = GroupGuard::install(root);
    FAILED_OWNER_SPAWN.with(|slot| slot.set(Some(0)));
    let pair = complete_owned_pair(
        Layout::Parallel,
        [1, 1],
        || crate::work_outcome::WorkOutcome::from_result(Ok(())),
        || {
            crate::work_outcome::WorkOutcome::<()>::from_result(Err(
                CiError::SettledCommandFailure("second actual error".into()),
            ))
        },
    );
    FAILED_OWNER_SPAWN.with(|slot| slot.set(None));
    assert_eq!(pair.first_cause, Some(LaneId::First));
    assert_eq!(
        pair.first.writers(),
        crate::work_outcome::WriterSettlement::NotStarted
    );
    assert!(
        pair.first
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("injected owner spawn failure")
    );
    assert!(
        pair.second
            .into_result()
            .unwrap_err()
            .to_string()
            .contains("second actual error")
    );
}

#[test]
fn failure_notice_arrives_before_the_owned_peer_is_released() {
    let (notices, received) = std::sync::mpsc::sync_channel(1);
    let mut root = new_group(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
    );
    root.compiler_jobs = 2;
    root.notice_sender = Some(notices);
    let _guard = GroupGuard::install(root);
    let (entered, ready) = std::sync::mpsc::sync_channel(1);
    let (release, held) = std::sync::mpsc::sync_channel(1);
    std::thread::scope(|scope| {
        let controller = scope.spawn(move || {
            ready.recv_timeout(Duration::from_secs(5)).unwrap();
            let notice = received.recv_timeout(Duration::from_secs(5)).unwrap();
            assert_eq!(notice.lane, 2);
            release.send(()).unwrap();
        });
        let pair = complete_owned_pair(
            Layout::Parallel,
            [1, 1],
            move || {
                entered.send(()).unwrap();
                held.recv_timeout(Duration::from_secs(5)).unwrap();
                crate::work_outcome::WorkOutcome::from_result(Ok(()))
            },
            || {
                active_group().unwrap().request_after_failure();
                crate::work_outcome::WorkOutcome::<()>::from_result(Err(
                    CiError::SettledCommandFailure("required assertion".into()),
                ))
            },
        );
        assert_eq!(pair.first_cause, Some(LaneId::Second));
        assert!(pair.first.is_ok());
        controller.join().unwrap();
    });
}

#[test]
fn root_notice_survives_later_pairs_and_finalization_has_a_separate_gate() {
    with_operation(
        crate::failure_mode::FailureMode::StopAfterFailure,
        Instant::now() + Duration::from_secs(20),
        || {
            let group = active_group().unwrap();
            group.request_after_failure();
            let notice = group.first_notice().unwrap();
            assert!(!group.may_start());
            with_finalization(Instant::now() + Duration::from_secs(5), || {
                assert!(active_group().unwrap().may_start());
                Ok(())
            })?;
            assert_eq!(active_group().unwrap().first_notice(), Some(notice));
            assert!(!active_group().unwrap().may_start());
            Ok(())
        },
    )
    .unwrap();
}

#[test]
fn finalization_preserves_nested_compiler_allocation() {
    let mut root = new_group(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
    );
    root.compiler_jobs = 2;
    root.inside_parallel_lane = true;
    let _guard = GroupGuard::install(root);
    with_finalization(Instant::now() + Duration::from_secs(5), || {
        let current = active_group().unwrap();
        assert_eq!(current.compiler_jobs(), 2);
        assert!(current.inside_parallel_lane());
        Ok(())
    })
    .unwrap();
    assert!(active_group().unwrap().inside_parallel_lane());
}

#[test]
fn nested_serial_pair_selects_its_own_second_cause_and_retains_root_cause() {
    let mut root = new_group(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(20),
    );
    root.compiler_jobs = 2;
    let _guard = GroupGuard::install(root.clone());
    let first = complete_owned_pair(
        Layout::Serial,
        [2, 2],
        || {
            crate::work_outcome::WorkOutcome::<()>::from_result(Err(
                CiError::SettledCommandFailure("original cause".into()),
            ))
        },
        || crate::work_outcome::WorkOutcome::from_result(Ok(())),
    );
    assert!(first.into_result().is_err());
    let original = root.first_notice();
    complete_lanes(
        Layout::Parallel,
        || {
            let pair = complete_owned_pair(
                Layout::Parallel,
                [1, 1],
                || crate::work_outcome::WorkOutcome::from_result(Ok(())),
                || {
                    active_group().unwrap().request_after_failure();
                    crate::work_outcome::WorkOutcome::<()>::from_result(Err(
                        CiError::SettledCommandFailure("nested second".into()),
                    ))
                },
            );
            assert_eq!(pair.first_cause, Some(LaneId::Second));
            assert!(pair.first.is_ok());
            Ok(())
        },
        || Ok(()),
    )
    .unwrap();
    assert_eq!(root.first_notice(), original);
}
