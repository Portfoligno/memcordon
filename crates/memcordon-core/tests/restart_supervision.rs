use memcordon_core::BackoffMultiplier;
use memcordon_core::test_support::{controller_scenario, deadline_scenario, logistic_scenario};

#[test]
fn controller_certification_covers_limits_circuit_waits_and_cleanup() {
    let result = controller_scenario().expect("deterministic controller scenario");
    assert!(result.window_equality_opened);
    assert!(result.burst_one_half_opened);
    assert!(result.noneligible_stopped);
    assert!(result.finite_exhausted);
    assert!(result.unsafe_cleanup_stopped);
    assert_eq!(result.interrupted_launches, 0);
    assert_eq!(result.deadline_launches, 0);
    assert!(result.launches >= 2);
    assert!(result.logistic_waits >= 1);
    assert!(result.cooldowns >= 1);
    assert!(result.circuit_opens >= 1);
}

#[test]
fn deadline_tracker_certifies_attempt_reset_total_scope_and_precedence() {
    let result = deadline_scenario(100, 50).expect("deadline scenario");
    assert_eq!(result.attempt_one_expiry_ms, 150);
    assert_eq!(result.attempt_two_expiry_ms, 225);
    assert_eq!(result.supervision_expiry_ms, 150);
    assert!(result.equality_expires);
    assert!(result.completion_wins);
    assert!(result.memory_wins);
    assert!(result.interruption_preserves_limit);
    assert!(result.backoff_charged_to_supervision);
    assert!(result.setup_charged_to_supervision);
    assert!(deadline_scenario(u64::MAX, 1).is_err());
}

#[test]
fn logistic_facade_preserves_exact_bounded_sequence() {
    let result = logistic_scenario(
        1_000,
        "2".parse::<BackoffMultiplier>().expect("multiplier"),
        30_000,
        12,
    )
    .expect("logistic scenario");
    assert_eq!(
        result.scheduled_millis,
        [
            1_000, 1_936, 3_638, 6_490, 10_672, 15_744, 20_651, 24_463, 26_951, 28_394, 29_175,
            29_582
        ]
    );
}
