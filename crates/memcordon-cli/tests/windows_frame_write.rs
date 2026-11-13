#[path = "../src/bin/memcordon-sealed-agent/windows/frame_write.rs"]
mod frame;
use frame::{
    FrameWriteError, FrameWritePhase, ProgressOutcome as Outcome, ProgressPhase as Phase,
    WriteProgress, complete_frame_using, write_frame_using,
};
use std::cell::{Cell, RefCell};

fn error(
    phase: FrameWritePhase,
    expected: usize,
    transferred: usize,
    code: Option<u32>,
    detail: String,
) -> FrameWriteError {
    FrameWriteError::new(phase, expected, transferred, code, false, detail)
}

#[test]
fn partial_writes_preserve_exact_wire_and_cumulative_observed_bytes() {
    let value = "native response";
    let payload = serde_json::to_vec(value).unwrap();
    let mut wire = Vec::new();
    let mut updates = Vec::new();
    write_frame_using(
        &value,
        |remaining| {
            wire.push(remaining[0]);
            Ok(1)
        },
        &mut |update| updates.push(update),
        error,
    )
    .unwrap();
    let mut expected = (payload.len() as u32).to_le_bytes().to_vec();
    expected.extend(&payload);
    assert_eq!(wire, expected);
    assert_eq!(updates[0].phase, Phase::Serialize);
    assert_eq!(updates[0].outcome, Outcome::Attempted);
    assert_eq!(updates[0].expected_bytes, None);
    assert_eq!(updates[1].outcome, Outcome::ReturnedOk);
    assert_eq!(updates[1].expected_bytes, Some(payload.len()));
    assert!(
        updates[..2]
            .iter()
            .all(|update| update.native_call_succeeded.is_none())
    );
    for (phase, bytes) in [
        (Phase::HeaderWrite, 4),
        (Phase::PayloadWrite, payload.len()),
    ] {
        let returns = updates
            .iter()
            .filter(|update| update.phase == phase && update.outcome == Outcome::ReturnedOk)
            .collect::<Vec<_>>();
        assert_eq!(returns.len(), bytes);
        for (index, update) in returns.into_iter().enumerate() {
            assert_eq!(update.expected_bytes, Some(bytes));
            assert_eq!(update.transferred_bytes, index + 1);
            assert_eq!(update.observed_write_count, Some(1));
            assert_eq!(update.native_call_succeeded, Some(true));
        }
    }
}

#[test]
fn native_failure_preserves_primary_and_finishes_without_drain_or_replay() {
    let mut calls = 0;
    let mut updates = Vec::new();
    let finishes = Cell::new(0);
    let failure = complete_frame_using(
        &"response",
        |remaining| {
            calls += 1;
            match calls {
                1 => Ok(remaining.len()),
                2 => Ok(2),
                3 => Err((Some(5), 1, "actual native failure".into())),
                _ => panic!("replayed native write"),
            }
        },
        &mut |update| updates.push(update),
        error,
        || panic!("failed frame must not drain"),
        || {
            finishes.set(finishes.get() + 1);
            Err("original watcher error".into())
        },
    )
    .unwrap_err();
    assert_eq!(calls, 3);
    assert_eq!(finishes.get(), 1);
    assert_eq!(failure.phase, FrameWritePhase::Payload);
    assert_eq!(failure.transferred_bytes, 3);
    assert_eq!(failure.native_code, Some(5));
    assert!(!failure.peer_closed);
    assert!(
        failure.to_string().ends_with(
            "detail=actual native failure; transport settlement: original watcher error"
        )
    );
    assert!(!updates.iter().any(|update| update.phase == Phase::Drain));
    let native = updates
        .iter()
        .find(|update| update.native_code == Some(5))
        .unwrap();
    assert_eq!(native.outcome, Outcome::ReturnedError);
    assert_eq!(native.observed_write_count, Some(1));
    assert_eq!(native.native_call_succeeded, Some(false));
    assert_eq!(updates.last().unwrap().phase, Phase::WatcherFinish);
    assert_eq!(updates.last().unwrap().outcome, Outcome::ReturnedError);
    assert_eq!(updates.last().unwrap().native_call_succeeded, None);
}

#[test]
fn zero_or_invalid_reported_count_is_distinct_from_native_return_failure() {
    for count in [0, 5, usize::MAX] {
        let mut calls = 0;
        let mut updates = Vec::new();
        let failure = write_frame_using(
            &"response",
            |_| {
                calls += 1;
                Ok(count)
            },
            &mut |update| updates.push(update),
            error,
        )
        .unwrap_err();
        assert_eq!(calls, 1);
        assert_eq!(failure.phase, FrameWritePhase::Length);
        assert_eq!(failure.expected_bytes, 4);
        assert_eq!(failure.transferred_bytes, 0);
        assert_eq!(failure.native_code, None);
        let update = updates.last().unwrap();
        assert_eq!(update.outcome, Outcome::ReturnedError);
        assert_eq!(update.observed_write_count, Some(count));
        assert_eq!(update.native_call_succeeded, Some(true));
        assert!(
            !updates
                .iter()
                .any(|update| update.phase == Phase::PayloadWrite)
        );
    }
}

#[test]
fn serialize_failure_and_reserved_bound_do_not_invent_write_or_drain() {
    struct Fail;
    impl serde::Serialize for Fail {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("actual serializer failure"))
        }
    }
    let mut updates = Vec::new();
    let finishes = Cell::new(0);
    let failure = complete_frame_using(
        &Fail,
        |_| panic!("serializer failure must not write"),
        &mut |update| updates.push(update),
        error,
        || panic!("serializer failure must not drain"),
        || {
            finishes.set(1);
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(finishes.get(), 1);
    assert_eq!(failure.phase, FrameWritePhase::Serialize);
    assert_eq!(updates[1].expected_bytes, None);
    assert!(
        failure
            .to_string()
            .ends_with("detail=actual serializer failure")
    );
    assert_eq!(
        updates
            .iter()
            .map(|update| update.phase)
            .collect::<Vec<_>>(),
        vec![
            Phase::Serialize,
            Phase::Serialize,
            Phase::WatcherFinish,
            Phase::WatcherFinish
        ]
    );
    #[derive(serde::Serialize)]
    struct Diagnostic {
        kind: &'static str,
        detail: String,
    }
    let diagnostic = Diagnostic {
        kind: "attempt-retained-v2",
        detail: "x".repeat(memcordon_core::MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES),
    };
    updates.clear();
    let failure = write_frame_using(
        &diagnostic,
        |_| panic!("oversize diagnostic must not write"),
        &mut |update| updates.push(update),
        error,
    )
    .unwrap_err();
    assert_eq!(failure.phase, FrameWritePhase::Serialize);
    assert!(failure.expected_bytes > memcordon_core::MAX_DIAGNOSTIC_CONTROL_FRAME_BYTES);
    assert!(
        failure
            .to_string()
            .ends_with("detail=diagnostic control frame exceeds its reserved bound")
    );
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[1].outcome, Outcome::ReturnedError);
    assert_eq!(updates[1].expected_bytes, Some(failure.expected_bytes));
}

#[test]
fn drain_and_watcher_keep_original_result_precedence_and_exact_order() {
    for (drain_failed, watcher_failed) in
        [(false, false), (true, false), (false, true), (true, true)]
    {
        let events = RefCell::new(Vec::new());
        let mut updates = Vec::new();
        let result = complete_frame_using(
            &"response",
            |remaining| {
                events.borrow_mut().push("write");
                Ok(remaining.len())
            },
            &mut |update| updates.push(update),
            error,
            || {
                events.borrow_mut().push("drain");
                if drain_failed {
                    Err(error(
                        FrameWritePhase::Drain,
                        0,
                        0,
                        Some(5),
                        "actual drain error".into(),
                    ))
                } else {
                    Ok(())
                }
            },
            || {
                events.borrow_mut().push("watcher");
                if watcher_failed {
                    Err("watcher settlement".into())
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(*events.borrow(), vec!["write", "write", "drain", "watcher"]);
        assert_eq!(result.is_ok(), !drain_failed && !watcher_failed);
        if let Err(failure) = result {
            assert_eq!(failure.phase, FrameWritePhase::Drain);
            assert_eq!(
                failure.native_code,
                if drain_failed { Some(5) } else { None }
            );
            let detail = failure.to_string();
            if drain_failed {
                assert!(detail.contains("detail=actual drain error"));
            }
            if watcher_failed {
                assert!(detail.ends_with("watcher settlement"));
            }
        }
        let phases = updates
            .iter()
            .map(|update| (update.phase, update.outcome))
            .collect::<Vec<_>>();
        assert_eq!(
            &phases[phases.len() - 4..],
            &[
                (Phase::Drain, Outcome::Attempted),
                (
                    Phase::Drain,
                    if drain_failed {
                        Outcome::ReturnedError
                    } else {
                        Outcome::ReturnedOk
                    }
                ),
                (Phase::WatcherFinish, Outcome::Attempted),
                (
                    Phase::WatcherFinish,
                    if watcher_failed {
                        Outcome::ReturnedError
                    } else {
                        Outcome::ReturnedOk
                    }
                )
            ]
        );
    }
}

#[test]
fn attempted_write_without_return_has_no_synthetic_completion_or_later_phase() {
    let updates = RefCell::new(Vec::<WriteProgress>::new());
    let calls = Cell::new(0);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        write_frame_using(
            &"response",
            |_| {
                calls.set(calls.get() + 1);
                panic!("original callback did not return")
            },
            &mut |update| updates.borrow_mut().push(update),
            error,
        )
    }));
    assert!(result.is_err());
    assert_eq!(calls.get(), 1);
    let updates = updates.borrow();
    assert_eq!(updates.last().unwrap().phase, Phase::HeaderWrite);
    assert_eq!(updates.last().unwrap().outcome, Outcome::Attempted);
    assert_eq!(updates.last().unwrap().observed_write_count, None);
    assert!(!updates.iter().any(|update| matches!(
        update.phase,
        Phase::PayloadWrite | Phase::Drain | Phase::WatcherFinish
    )));
}
