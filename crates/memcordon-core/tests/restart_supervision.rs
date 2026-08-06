use memcordon_core::BackoffMultiplier;
use memcordon_core::test_support::{
    controller_scenario, deadline_scenario, half_life_logistic_scenario,
};

#[test]
fn controller_certification_covers_limits_circuit_waits_and_cleanup() {
    let result = controller_scenario().expect("deterministic controller scenario");
    assert!(result.decayed_threshold_opened);
    assert!(result.threshold_one_half_opened);
    assert!(result.cooldown_preserved_backoff);
    assert!(result.noneligible_stopped);
    assert!(result.finite_exhausted);
    assert!(result.unsafe_cleanup_stopped);
    assert_eq!(result.interrupted_launches, 0);
    assert_eq!(result.deadline_launches, 0);
    assert!(result.launches >= 2);
    assert!(result.half_life_logistic_waits >= 1);
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
fn zero_deadline_expires_at_each_scope_origin() {
    let result = deadline_scenario(100, 0).expect("zero deadline scenario");
    assert_eq!(result.attempt_one_expiry_ms, 100);
    assert_eq!(result.attempt_two_expiry_ms, 125);
    assert_eq!(result.supervision_expiry_ms, 100);
    assert!(result.equality_expires);
    assert!(result.backoff_charged_to_supervision);
    assert!(result.setup_charged_to_supervision);
}

#[test]
fn half_life_logistic_facade_preserves_event_convergence_and_time_recovery() {
    let rapid = half_life_logistic_scenario(
        1_000,
        "2".parse::<BackoffMultiplier>().expect("multiplier"),
        30_000,
        30_000,
        &[0, 0, 0, 0, 0],
    )
    .expect("rapid half-life logistic scenario");
    assert_eq!(
        rapid.scheduled_millis,
        [1_936, 3_638, 6_490, 10_672, 15_744]
    );

    let recovered = half_life_logistic_scenario(
        1_000,
        "2".parse::<BackoffMultiplier>().expect("multiplier"),
        30_000,
        30_000,
        &[0, 0, 300_000],
    )
    .expect("recovered half-life logistic scenario");
    assert!(recovered.scheduled_millis[2] < recovered.scheduled_millis[1]);
    assert!(recovered.scheduled_millis[2] >= recovered.scheduled_millis[0]);
}
