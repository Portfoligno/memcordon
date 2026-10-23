use memcordon_windows_loader_lab::resume_thread::{Outcome, classify};
use std::cell::Cell;

#[test]
fn prior_counts_never_consume_ambient_last_error() {
    for (raw, outcome) in [
        (0, Outcome::AlreadyUnsuspended),
        (1, Outcome::Released),
        (2, Outcome::StillSuspended { previous_count: 2 }),
        (
            u32::MAX - 1,
            Outcome::StillSuspended {
                previous_count: u32::MAX - 1,
            },
        ),
    ] {
        let calls = Cell::new(0);
        let observed = classify(raw, || {
            calls.set(calls.get() + 1);
            122
        });
        assert_eq!(calls.get(), 0, "successful count read stale Win32 error");
        assert_eq!(observed.raw_return, raw);
        assert_eq!(observed.outcome, outcome);
        assert_eq!(observed.native_error, None);
        assert_eq!(observed.require_exact_one().is_ok(), raw == 1);
        let wire = serde_json::to_value(observed).unwrap();
        assert!(wire["native_error"].is_null());
        if raw != 1 {
            assert!(
                observed
                    .require_exact_one()
                    .unwrap_err()
                    .contains("count mismatch")
            );
        }
    }
}

#[test]
fn only_failure_sentinel_captures_authentic_error_once() {
    for code in [0, 6, 122] {
        let calls = Cell::new(0);
        let observed = classify(u32::MAX, || {
            calls.set(calls.get() + 1);
            code
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(observed.raw_return, u32::MAX);
        assert_eq!(observed.outcome, Outcome::NativeFailure { code });
        assert_eq!(observed.native_error, Some(code));
        assert!(
            observed
                .require_exact_one()
                .unwrap_err()
                .contains(&format!("native_code={code}"))
        );
    }
}
