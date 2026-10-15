#[path = "../src/windows_loader_event_diagnostics.rs"]
mod diagnostics;

use std::time::{Duration, Instant};

#[test]
fn event_query_is_read_only_finite_and_keeps_faulting_identity_unclassified() {
    let arguments = diagnostics::QUERY_ARGUMENTS;
    assert_eq!(&arguments[..2], ["qe", "Application"]);
    assert_eq!(arguments.len(), 7);
    assert!(arguments[2].starts_with("/q:*[System["));
    for provider in ["Application Error", "Windows Error Reporting", "SideBySide"] {
        assert!(arguments[2].contains(provider));
    }
    assert!(arguments[2].contains("timediff(@SystemTime) <= 60000"));
    assert!(!arguments[2].contains("Execution"));
    assert_eq!(
        &arguments[3..],
        ["/c:64", "/rd:true", "/f:xml", "/e:Events"]
    );
    assert_eq!(diagnostics::MAX_CAPTURE_BYTES, 256 * 1024);
}

#[test]
fn diagnostic_allowance_never_extends_the_original_caller_cutoff() {
    let now = Instant::now();
    assert!(diagnostics::query_budget(now, now).is_none());
    assert!(diagnostics::query_budget(now, now + Duration::from_secs(1)).is_none());
    let short = Duration::from_millis(17);
    assert_eq!(diagnostics::query_budget(now + short, now), Some(short));
    assert_eq!(
        diagnostics::query_budget(now + Duration::from_secs(60), now),
        Some(diagnostics::MAX_QUERY_DURATION)
    );
    assert_eq!(diagnostics::MAX_QUERY_DURATION, Duration::from_secs(5));
}

#[cfg(windows)]
#[test]
fn exhausted_caller_cutoff_never_starts_an_os_query() {
    let capture = diagnostics::observe(Instant::now());
    assert_eq!(capture.state["state"], "unavailable");
    assert_eq!(
        capture.state["reason"],
        "original caller deadline exhausted"
    );
    assert!(capture.program.is_none());
    assert!(capture.stdout.is_empty());
    assert!(capture.stderr.is_empty());
}
