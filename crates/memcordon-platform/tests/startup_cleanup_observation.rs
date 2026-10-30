#![cfg(feature = "test-support")]

use memcordon_core::ReleaseEvidence;
use memcordon_platform::startup_cleanup_observation::{
    CreationSettlement, RECORD_BOUND, cutoff_nanos, error_record,
};
use serde_json::{Value, json};
use std::{
    io,
    time::{Duration, Instant},
};

#[test]
fn exact_creation_samples_preserve_original_failure_and_never_claim_retirement() {
    let samples = CreationSettlement {
        before: json!({"expected_index":3,"expected_generation":7,"generation_before":7,"generation_after":7,
            "state_before":"Spawning","state_after":"Spawning","pid":0,"cleanup_errno":0,"cancellation":true}),
        after: json!({"expected_index":3,"expected_generation":7,"generation_before":7,"generation_after":7,
            "state_before":"OwnershipLost","state_after":"OwnershipLost","pid":81,"cleanup_errno":5,"cancellation":true}),
        observed_before: Some(101),
        observed_after: Some(3101),
        original_cutoff: Some(3100),
        settled: false,
    };
    let timeout = io::Error::new(io::ErrorKind::TimedOut, "original creation wait expired");
    let record = error_record(
        "helper-spawn",
        &timeout,
        false,
        false,
        &ReleaseEvidence::NotIssued,
        Some(&samples),
    );
    let value: Value = serde_json::from_str(&record.message).unwrap();
    assert_eq!(record.operation, "startup-creation-observation");
    assert_eq!(value["original_error_kind"], "TimedOut");
    assert_eq!(value["original_message"], timeout.to_string());
    assert_eq!(
        value["release"],
        serde_json::to_value(ReleaseEvidence::NotIssued).unwrap()
    );
    assert_eq!(value["acceptance_authority"], false);
    assert_eq!(value["diagnostic_only"], true);
    assert_eq!(value["sampling"], "sequential-non-atomic");
    assert_eq!(value["exact_creation"]["before"], samples.before);
    assert_eq!(value["exact_creation"]["after"], samples.after);
    assert_eq!(value["exact_creation"]["settled"], false);
    assert_eq!(value["exact_creation"]["original_cutoff"], 3100);
    assert!(value.get("cleanup_complete").is_none());
    assert!(record.message.len() <= RECORD_BOUND);
    let native = io::Error::from_raw_os_error(5);
    let record = error_record::<Value>(
        "helper-spawn",
        &native,
        true,
        false,
        &ReleaseEvidence::NotIssued,
        None,
    );
    let value: Value = serde_json::from_str(&record.message).unwrap();
    assert_eq!(value["original_raw_errno"], 5);
    assert_eq!(value["guardian_child_returned"], true);
}

#[test]
fn oversize_or_unserializable_telemetry_has_a_bounded_non_authoritative_fallback() {
    struct Refuses;
    impl serde::Serialize for Refuses {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("diagnostic unavailable"))
        }
    }
    let sample = CreationSettlement {
        before: Refuses,
        after: Refuses,
        observed_before: None,
        observed_after: None,
        original_cutoff: None,
        settled: false,
    };
    for record in [
        error_record(
            "helper-spawn",
            &io::Error::from_raw_os_error(5),
            false,
            false,
            &ReleaseEvidence::NotIssued,
            Some(&sample),
        ),
        error_record::<Value>(
            "helper-spawn",
            &io::Error::other("x".repeat(RECORD_BOUND)),
            false,
            false,
            &ReleaseEvidence::NotIssued,
            None,
        ),
    ] {
        assert!(record.message.len() <= RECORD_BOUND);
        let value: Value = serde_json::from_str(&record.message).unwrap();
        assert_eq!(value["state"], "unavailable");
        assert_eq!(value["acceptance_authority"], false);
    }
}

#[test]
fn original_cutoff_conversion_keeps_past_deadlines_and_refuses_clock_range_loss() {
    let now = Instant::now();
    let allowance = Duration::from_millis(3);
    let tick = 10_000_000;
    assert_eq!(
        cutoff_nanos(tick, now, now + allowance),
        Some(tick + 3_000_000)
    );
    assert_eq!(
        cutoff_nanos(tick, now, now - allowance),
        Some(tick - 3_000_000)
    );
    assert_eq!(cutoff_nanos(u64::MAX, now, now + allowance), None);
    assert_eq!(cutoff_nanos(0, now, now - allowance), None);
}
