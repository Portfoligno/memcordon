use memcordon_ci::{cargo_progress::CargoProgress, command_progress_line::observe_complete_line};
use memcordon_testkit::OutputStream::{Stderr, Stdout};
use std::time::Duration;

#[test]
fn exhausted_console_quota_still_observes_later_invocations_and_artifacts() {
    let mut progress = CargoProgress::new(Duration::from_secs(10));
    let mut quota = 1;
    assert!(
        observe_complete_line(
            b"Compiling first",
            &[],
            &mut quota,
            Some(&mut progress),
            Duration::ZERO,
            Stderr
        )
        .is_some()
    );
    assert_eq!(quota, 0);
    assert!(
        observe_complete_line(
            b"Running `rustc --crate-name later`",
            &[],
            &mut quota,
            Some(&mut progress),
            Duration::from_secs(2),
            Stderr
        )
        .is_none()
    );
    let artifact = br#"{"reason":"compiler-artifact","package_id":"later 1.0.0","target":{"name":"later","kind":["test"]},"profile":{"opt_level":"3"},"features":[],"fresh":false}"#;
    assert!(
        observe_complete_line(
            artifact,
            &[],
            &mut quota,
            Some(&mut progress),
            Duration::from_secs(3),
            Stdout
        )
        .is_none()
    );
    assert_eq!(quota, 0);
    assert_eq!(progress.records.len(), 3);
    assert_eq!(progress.records[1].kind, "invocation");
    assert_eq!(
        progress.last_progress.as_ref().unwrap().elapsed_us,
        3_000_000
    );
    assert!(
        progress
            .last_progress
            .as_ref()
            .unwrap()
            .text
            .contains("later")
    );
}

#[test]
fn post_quota_observations_still_redact_secrets_and_preserve_ring_bounds() {
    let mut progress = CargoProgress::new(Duration::from_secs(1));
    let mut quota = 0;
    for tick in 0..50 {
        assert!(
            observe_complete_line(
                b"Running `rustc --crate-name secret-value`",
                &["secret-value".into()],
                &mut quota,
                Some(&mut progress),
                Duration::from_micros(tick),
                Stderr
            )
            .is_none()
        );
    }
    assert_eq!(progress.records.len(), 32);
    assert_eq!(progress.omitted_records, 18);
    assert!(
        observe_complete_line(
            b"Running password=private-value",
            &[],
            &mut quota,
            Some(&mut progress),
            Duration::from_secs(1),
            Stderr
        )
        .is_none()
    );
    let wire = serde_json::to_string(&progress).unwrap();
    assert!(!wire.contains("secret-value"));
    assert!(!wire.contains("private-value"));
    assert!(wire.contains("redacted"));
}

#[test]
fn oversized_lines_cannot_enter_console_or_observation() {
    let mut progress = CargoProgress::new(Duration::from_secs(1));
    let mut quota = 100;
    let oversized = vec![b'a'; 8193];
    assert!(
        observe_complete_line(
            &oversized,
            &[],
            &mut quota,
            Some(&mut progress),
            Duration::ZERO,
            Stderr
        )
        .is_none()
    );
    assert_eq!(quota, 100);
    assert!(progress.records.is_empty());
}
