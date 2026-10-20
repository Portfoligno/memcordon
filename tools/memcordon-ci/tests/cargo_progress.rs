#[path = "../src/cargo_progress.rs"]
mod cargo_progress;

use cargo_progress::CargoProgress;
use memcordon_testkit::OutputStream::{Stderr, Stdout};
use std::time::Duration;

#[test]
fn records_first_lock_first_compile_and_last_consumed_progress_without_liveness_claims() {
    let mut progress = CargoProgress::new(Duration::from_secs(10));
    progress.observe_line(
        Duration::from_secs(1),
        Stderr,
        "   Blocking waiting for file lock on package cache",
    );
    progress.observe_line(
        Duration::from_secs(2),
        Stderr,
        "Blocking waiting for file lock on package cache",
    );
    progress.observe_line(
        Duration::from_secs(3),
        Stdout,
        "   Compiling example v1.0.0",
    );
    progress.observe_line(Duration::from_secs(4), Stderr, "Checking dependency v1.0.0");
    // Consumption can continue during settlement; this is not a child emission
    // time or evidence of whether the native work deadline was reached.
    progress.observe_line(Duration::from_secs(15), Stderr, "Finished release profile");
    assert_eq!(progress.first_lock.as_ref().unwrap().elapsed_us, 1_000_000);
    assert_eq!(
        progress.first_compile.as_ref().unwrap().elapsed_us,
        3_000_000
    );
    assert_eq!(progress.first_compile.as_ref().unwrap().stream, "stdout");
    assert_eq!(
        progress.last_progress.as_ref().unwrap().elapsed_us,
        15_000_000
    );
    assert_eq!(progress.last_progress.as_ref().unwrap().kind, "finished");
    assert_eq!(progress.records.len(), 5);
    let wire = serde_json::to_value(&progress).unwrap();
    assert_eq!(wire["clock_domain"], "command-start-monotonic");
    assert_eq!(
        wire["timestamp_meaning"],
        "logger-consumption-not-child-emission"
    );
    assert_eq!(wire["work_budget_us"], 10_000_000);
    assert!(
        wire["records"]
            .as_array()
            .unwrap()
            .iter()
            .all(|record| record.get("consumed_after_work_cutoff").is_none())
    );
}

#[test]
fn recent_ring_and_utf8_text_bounds_preserve_first_observations_and_omissions() {
    let mut progress = CargoProgress::new(Duration::from_secs(1));
    progress.observe_line(
        Duration::ZERO,
        Stderr,
        "Blocking waiting for file lock on package cache",
    );
    let long = format!("Compiling {}", "界".repeat(300));
    progress.observe_line(Duration::from_micros(1), Stderr, &long);
    for tick in 2..42 {
        progress.observe_line(
            Duration::from_micros(tick),
            Stdout,
            &format!("Checking crate-{tick}"),
        );
    }
    progress.finish(17, 19);
    assert_eq!(progress.records.len(), 32);
    assert_eq!(progress.omitted_records, 10);
    assert_eq!(progress.records.front().unwrap().elapsed_us, 10);
    assert_eq!(progress.records.back().unwrap().elapsed_us, 41);
    assert_eq!(progress.first_lock.as_ref().unwrap().elapsed_us, 0);
    let first = progress.first_compile.as_ref().unwrap();
    assert!(first.text_truncated);
    assert!(first.text.len() <= 512);
    assert!(long.starts_with(&first.text));
    assert_eq!(progress.truncated_texts, 1);
    assert_eq!(progress.omitted_lines, 17);
    assert_eq!(progress.omitted_chunks, 19);
    assert!(!progress.counter_saturated);
}

#[test]
fn unrelated_lines_leave_absent_progress_and_counter_overflow_is_explicit() {
    let mut progress = CargoProgress::new(Duration::ZERO);
    for line in [
        "",
        "error: compile failed",
        "text mentioning Compiling elsewhere",
        "Checking",
        "Blocking unrelated",
    ] {
        progress.observe_line(Duration::from_secs(1), Stderr, line);
    }
    assert!(progress.first_lock.is_none());
    assert!(progress.first_compile.is_none());
    assert!(progress.last_progress.is_none());
    assert!(progress.records.is_empty());
    progress.finish(0, u64::MAX);
    assert!(progress.counter_saturated);
    let wire = serde_json::to_value(&progress).unwrap();
    assert!(wire["first_lock"].is_null());
    assert!(wire["last_progress"].is_null());

    let mut bounded = CargoProgress::new(Duration::from_secs(1));
    for tick in 0..32 {
        bounded.observe_line(Duration::from_micros(tick), Stderr, "Compiling crate");
    }
    bounded.omitted_records = u64::MAX;
    bounded.truncated_texts = u64::MAX;
    bounded.observe_line(
        Duration::from_secs(2),
        Stderr,
        &format!("Compiling {}", "a".repeat(600)),
    );
    assert_eq!(bounded.records.len(), 32);
    assert_eq!(bounded.omitted_records, u64::MAX);
    assert_eq!(bounded.truncated_texts, u64::MAX);
    assert!(bounded.counter_saturated);
}
