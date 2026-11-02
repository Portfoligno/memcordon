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
            WriterStatus::NoQuarantinedObserved
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
                Err(_) => WriterStatus::Unavailable,
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
            WriterStatus::Unconfirmed {
                native_code: Some(5),
                detail: "界".repeat(10000),
            }
        })
    );
    let text = observation.detail().unwrap();
    assert!(text.contains("recorded-publisher-win32-code=Some(5)"));
    assert!(text.contains("detail-truncated=true"));
    assert!(text.contains("retirement-proof=false"));
    assert!(text.len() < 4600);
}
