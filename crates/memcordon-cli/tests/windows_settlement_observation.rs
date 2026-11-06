#[path = "../src/bin/memcordon-sealed-agent/windows/settlement_observation.rs"]
mod observation;
#[path = "../src/bin/memcordon-sealed-agent/windows/settlement.rs"]
mod settlement;
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
