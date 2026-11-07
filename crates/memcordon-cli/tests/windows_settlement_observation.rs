#[path = "../src/bin/memcordon-sealed-agent/windows/frame_write.rs"]
pub mod frame_write;
#[path = "../src/bin/memcordon-sealed-agent/windows/settlement_observation.rs"]
mod observation;
#[path = "../src/bin/memcordon-sealed-agent/windows/settlement.rs"]
mod settlement;
#[path = "../src/bin/memcordon-sealed-agent/windows/writer_lifecycle.rs"]
pub mod writer_lifecycle;
use observation::{Observation, WriterStatus};
use std::{
    cell::Cell,
    sync::Mutex,
    time::{Duration, Instant},
};

#[test]
fn local_lifecycle_detail_is_one_bounded_historical_sample_without_changing_quiescence() {
    let mut observed = Observation::default();
    let calls = Cell::new(0);
    let deadline = Instant::now() + Duration::from_secs(1);
    for _ in 0..3 {
        assert!(!observed.observe(false, deadline, || {
            calls.set(calls.get() + 1);
            WriterStatus::LocalSnapshot {
                snapshot: Box::default(),
                detail: "界".repeat(10000),
            }
        }));
    }
    assert_eq!(calls.get(), 1);
    let detail = observed.detail().unwrap();
    assert!(detail.contains("historical-filename-correlation-only=true"));
    assert!(detail.contains("detail-truncated=true"));
    assert!(detail.contains("retirement-proof=false"));
    assert!(detail.len() < 8700);
    assert!(observed.observe(true, Instant::now(), || panic!(
        "must not retry or block true"
    )));
}

#[test]
fn true_quiescence_is_unchanged_and_false_queries_only_once() {
    let mut observation = Observation::default();
    let calls = Cell::new(0);
    let cutoff = Instant::now() + Duration::from_secs(1);
    assert!(observation.observe(true, cutoff, || {
        panic!("quiescent must not query");
    }));
    assert!(observation.detail().is_none());
    for _ in 0..4 {
        assert!(!observation.observe(false, cutoff, || {
            calls.set(calls.get() + 1);
            WriterStatus::LocalSnapshot {
                snapshot: Box::default(),
                detail: "no-quarantined-lane-observed".into(),
            }
        }));
    }
    assert_eq!(calls.get(), 1);
    let text = observation.detail().unwrap();
    assert!(text.contains("no-quarantined-lane-observed"));
    assert!(text.contains("retirement-proof=false"));
    assert!(text.contains("admission-binding=unavailable"));
}

#[test]
fn expired_cutoff_refuses_query_and_does_not_admit_recovery() {
    let mut observation = Observation::default();
    let cutoff = Instant::now();
    let gate = settlement::SettlementGate::default();
    let _writer = gate.enter().unwrap();
    let error = gate
        .settle_until(cutoff, || {
            Ok(observation.observe(false, cutoff, || panic!("expired query")))
        })
        .unwrap_err();
    assert!(error.contains("last-quiesce=false"));
    assert!(error.contains("last-exclusive-attempted=false"));
    assert!(
        observation
            .detail()
            .unwrap()
            .contains("unavailable-original-cutoff")
    );
}

#[test]
fn contended_owned_registry_is_unavailable_without_waiting_or_reclassification() {
    let registry = Mutex::new(());
    let _held = registry.lock().unwrap();
    let mut observation = Observation::default();
    assert!(
        !observation.observe(false, Instant::now() + Duration::from_secs(1), || {
            match registry.try_lock() {
                Ok(_) => panic!("registry should remain held"),
                Err(_) => WriterStatus::LocalSnapshot {
                    snapshot: Box::default(),
                    detail: "unavailable-nonblocking-query".into(),
                },
            }
        })
    );
    assert!(
        observation
            .detail()
            .unwrap()
            .contains("unavailable-nonblocking-query")
    );
    assert!(observation.observe(true, Instant::now(), || panic!("no retry")));
}

#[test]
fn actual_native_error_and_unicode_detail_are_bounded_and_never_retirement_proof() {
    let mut observation = Observation::default();
    assert!(
        !observation.observe(false, Instant::now() + Duration::from_secs(1), || {
            WriterStatus::LocalSnapshot {
                snapshot: Box::default(),
                detail: format!("publisher_native_code=5; {}", "界".repeat(10000)),
            }
        })
    );
    let text = observation.detail().unwrap();
    assert!(text.contains("publisher_native_code=5"));
    assert!(text.contains("detail-truncated=true"));
    assert!(text.contains("retirement-proof=false"));
    assert!(text.len() < 8700);
}

#[test]
fn later_sample_is_separate_bounded_and_never_collected_after_original_cutoff() {
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(20);
    let mut observation = Observation::default();
    let calls = Cell::new(0);
    let query = || {
        calls.set(calls.get() + 1);
        WriterStatus::LocalSnapshot {
            detail: format!("query={}", calls.get()),
            snapshot: Box::default(),
        }
    };
    assert!(!observation.observe_at(now, false, cutoff, query));
    assert!(!observation.observe_at(now + Duration::from_secs(14), false, cutoff, query));
    assert_eq!(calls.get(), 1);
    assert!(!observation.observe_at(now + Duration::from_secs(15), false, cutoff, query));
    assert_eq!(calls.get(), 2);
    for sampled in [now + Duration::from_secs(19), cutoff] {
        assert!(!observation.observe_at(sampled, false, cutoff, || panic!("only two queries")));
    }
    let text = observation.detail().unwrap();
    assert!(text.contains("first-false-quiescence=[sample-ordinal=1"));
    assert!(text.contains("later-pre-cutoff=[sample-ordinal=2; sampled-after-first-ms=15000"));
    assert!(text.contains("query=1"));
    assert!(text.contains("query=2"));
    assert!(text.contains("temporal-comparison="));
    assert!(text.len() < 26 * 1024);
    let final_names = observation.final_name_detail(&[]).unwrap();
    assert!(final_names.contains("last-successful-admission-name-sample"));
    assert!(final_names.contains("current-file-binding=false"));

    let mut missed = Observation::default();
    assert!(!missed.observe_at(now, false, cutoff, query));
    assert!(!missed.observe_at(cutoff, false, cutoff, || panic!("post-cutoff query")));
    let text = missed.detail().unwrap();
    assert!(text.contains("query=3"));
    assert!(text.contains("later-pre-cutoff=[sample-ordinal=2; sampled-after-first-ms=20000; owned-writer-registry=unavailable-original-cutoff"));
    assert!(!text.contains("temporal-comparison="));
    assert!(
        missed
            .final_name_detail(&[])
            .unwrap()
            .contains("unavailable-original-cutoff")
    );
}

#[test]
fn a_changed_cutoff_cannot_renew_the_diagnostic_window() {
    let now = Instant::now();
    let cutoff = now + Duration::from_secs(20);
    let mut observation = Observation::default();
    assert!(
        !observation.observe_at(now, false, cutoff, || WriterStatus::LocalSnapshot {
            detail: "first".into(),
            snapshot: Box::default()
        })
    );
    assert!(!observation.observe_at(
        now + Duration::from_secs(16),
        false,
        cutoff + Duration::from_secs(20),
        || panic!("renewed window")
    ));
    assert!(
        observation
            .detail()
            .unwrap()
            .contains("unavailable-cutoff-changed")
    );
}
