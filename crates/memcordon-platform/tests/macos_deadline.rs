#![cfg(all(target_os = "macos", feature = "test-support"))]

use memcordon_platform::test_support::macos_retirement_mutation_probe as probe;
use std::time::Duration;

#[test]
fn mutation_expired_work_cleanup_clamp_is_detected() {
    // Detection is delayed by one second after work/force expiry. The original
    // retirement reserve still has two seconds; it cannot become zero or renew.
    let work = 10_000_000_000;
    let observed = 11_000_000_000;
    let expected = Duration::from_secs(2);
    assert_eq!(probe(work, observed, work, false).unwrap(), expected);
    assert_ne!(probe(work, observed, work, true).unwrap(), expected);
    assert_eq!(
        probe(work, 13_000_000_000, work, false).unwrap(),
        Duration::ZERO
    );
    assert!(probe(u64::MAX, observed, work, false).is_err());
}
