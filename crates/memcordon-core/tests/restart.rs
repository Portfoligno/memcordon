use std::time::Duration;

use memcordon_core::test_support::half_life_logistic_scenario;
use memcordon_core::{
    BackoffMultiplier, CircuitBreakerPolicy, HalfLifeLogisticBackoffPolicy,
    HalfLifeLogisticBackoffState, half_life_logistic_next_millis,
};

#[test]
fn multiplier_is_exact_reduced_and_bounded() {
    let multiplier: BackoffMultiplier = "2.50".parse().expect("valid multiplier");
    assert_eq!(multiplier.numerator(), 5);
    assert_eq!(multiplier.denominator(), 2);
    for invalid in ["", "1", "0.9", "100.1", "2e1", "+2", "-2", "2."] {
        assert!(invalid.parse::<BackoffMultiplier>().is_err(), "{invalid}");
    }
    assert!(BackoffMultiplier::new(2, 0).is_err());
    assert_eq!(
        "100"
            .parse::<BackoffMultiplier>()
            .expect("upper bound")
            .numerator(),
        100
    );
}

#[test]
fn default_policy_is_exact_serialized_and_backward_compatible() {
    let policy = HalfLifeLogisticBackoffPolicy::default();
    assert_eq!(policy.base_interval(), Duration::from_millis(250));
    assert_eq!(policy.multiplier().numerator(), 4);
    assert_eq!(policy.multiplier().denominator(), 1);
    assert_eq!(policy.asymptote_interval(), Duration::from_secs(15 * 60));
    assert_eq!(policy.recovery_half_life(), Duration::from_secs(15 * 60));
    policy.validate().expect("default policy");

    let value = serde_json::to_value(policy).expect("serialize default policy");
    assert_eq!(
        value,
        serde_json::json!({
            "base_interval_ms": 250,
            "multiplier": { "numerator": 4, "denominator": 1 },
            "asymptote_interval_ms": 900_000,
            "recovery_half_life_ms": 900_000
        })
    );
    assert_eq!(
        serde_json::from_value::<HalfLifeLogisticBackoffPolicy>(value)
            .expect("deserialize default policy"),
        policy
    );

    let legacy = serde_json::json!({
        "base_interval_ms": 1_000,
        "multiplier": { "numerator": 2, "denominator": 1 },
        "asymptote_interval_ms": 30_000,
        "recovery_half_life_ms": 30_000
    });
    let explicit_legacy = serde_json::from_value::<HalfLifeLogisticBackoffPolicy>(legacy.clone())
        .expect("deserialize explicit legacy policy");
    assert_eq!(
        serde_json::to_value(explicit_legacy).expect("serialize explicit legacy policy"),
        legacy
    );
}

#[test]
fn circuit_policy_serializes_the_decayed_score_contract_exactly() {
    let policy =
        CircuitBreakerPolicy::new(2.5, Duration::from_secs(30), Duration::from_secs(5 * 60))
            .expect("valid circuit policy");
    assert_eq!(policy.threshold(), 2.5);
    assert_eq!(policy.half_life(), Duration::from_secs(30));
    assert_eq!(policy.cooldown(), Duration::from_secs(5 * 60));

    let value = serde_json::to_value(policy).expect("serialize circuit policy");
    assert_eq!(
        value,
        serde_json::json!({
            "threshold": 2.5,
            "half_life_ms": 30_000,
            "cooldown_ms": 300_000
        })
    );
    assert_eq!(
        serde_json::from_value::<CircuitBreakerPolicy>(value).expect("deserialize circuit policy"),
        policy
    );
}

#[test]
fn circuit_policy_rejects_invalid_thresholds_and_durations() {
    for threshold in [0.0, -1.0, f64::INFINITY, f64::NEG_INFINITY, f64::NAN] {
        assert!(
            CircuitBreakerPolicy::new(threshold, Duration::from_secs(1), Duration::from_secs(1),)
                .is_err(),
            "threshold={threshold}"
        );
    }
    assert!(CircuitBreakerPolicy::new(2.0, Duration::ZERO, Duration::ZERO).is_err());
}

#[test]
fn circuit_policy_accepts_one_millisecond_half_life_and_zero_cooldown() {
    let policy = CircuitBreakerPolicy::new(2.0, Duration::from_millis(1), Duration::ZERO)
        .expect("duration boundaries are valid");
    assert_eq!(policy.half_life(), Duration::from_millis(1));
    assert_eq!(policy.cooldown(), Duration::ZERO);
}

#[test]
fn default_first_event_ignores_prior_wall_time_and_pulses_the_resting_base() {
    let policy = HalfLifeLogisticBackoffPolicy::default();
    let mut at_origin = HalfLifeLogisticBackoffState::new(policy).expect("state");
    let mut after_hours = HalfLifeLogisticBackoffState::new(policy).expect("state");

    let first_at_origin = at_origin.on_backoff(Duration::ZERO).expect("first event");
    let first_after_hours = after_hours
        .on_backoff(Duration::from_secs(4 * 60 * 60))
        .expect("first event after wall time");
    assert_eq!(first_at_origin, Duration::from_secs(1));
    assert_eq!(first_after_hours, first_at_origin);
    assert_ne!(first_at_origin, policy.base_interval());
}

#[test]
fn default_self_delayed_failures_escalate_to_the_multi_minute_fixed_point() {
    let mut state =
        HalfLifeLogisticBackoffState::new(HalfLifeLogisticBackoffPolicy::default()).expect("state");
    let mut event_time = Duration::ZERO;
    for expected in [
        1_000, 3_985, 15_687, 58_960, 189_768, 424_136, 605_954, 670_646, 685_868, 689_016,
    ] {
        let wait = state.on_backoff(event_time).expect("backoff event");
        assert_eq!(wait, Duration::from_millis(expected));
        event_time = event_time.checked_add(wait).expect("bounded timeline");
    }
}

fn default_hot_state() -> HalfLifeLogisticBackoffState {
    let mut state =
        HalfLifeLogisticBackoffState::new(HalfLifeLogisticBackoffPolicy::default()).expect("state");
    let mut event_time = Duration::ZERO;
    for _ in 0..15 {
        let wait = state.on_backoff(event_time).expect("backoff event");
        event_time = event_time.checked_add(wait).expect("bounded timeline");
    }
    assert_eq!(state.current_interval(), Duration::from_millis(689_806));
    state
}

#[test]
fn default_quiet_recovery_precedes_the_pulse_without_intermediate_rounding() {
    let mut one_half_life = default_hot_state();
    let last_event = one_half_life.last_backoff_at().expect("hot state event");
    let after_half_life = last_event + Duration::from_secs(15 * 60);
    assert_eq!(
        one_half_life
            .effective_interval(after_half_life)
            .expect("recovered preview"),
        Duration::from_millis(345_028)
    );
    assert_eq!(
        one_half_life
            .on_backoff(after_half_life)
            .expect("recovered pulse"),
        Duration::from_millis(641_885)
    );

    for (quiet, expected) in [(2 * 60 * 60, 11_660), (4 * 60 * 60, 1_042)] {
        let mut state = default_hot_state();
        let event = state.last_backoff_at().expect("hot state event") + Duration::from_secs(quiet);
        assert_eq!(
            state.on_backoff(event).expect("quiet recovery pulse"),
            Duration::from_millis(expected)
        );
    }

    let mut fractional_recovery = default_hot_state();
    let event = fractional_recovery
        .last_backoff_at()
        .expect("hot state event")
        + Duration::from_millis(7);
    let preview = fractional_recovery
        .effective_interval(event)
        .expect("rounded preview");
    assert_eq!(preview, Duration::from_millis(689_803));
    assert_eq!(
        fractional_recovery
            .on_backoff(event)
            .expect("unrounded recovery pulse"),
        Duration::from_millis(836_291)
    );
    assert_eq!(
        half_life_logistic_next_millis(
            250,
            preview.as_millis().try_into().expect("preview range"),
            900_000,
            "4".parse().expect("multiplier"),
            900_000,
            0,
        )
        .expect("pulse from rounded preview"),
        836_292
    );
}

#[test]
fn half_life_logistic_extreme_valid_values_remain_representable() {
    let multiplier = BackoffMultiplier::new(100, 1).expect("upper-bound multiplier");
    for current in [1, u64::MAX] {
        let next = half_life_logistic_next_millis(1, current, u64::MAX, multiplier, 1, u64::MAX)
            .expect("extreme valid transition");
        assert_ne!(next, 0);
    }
    assert!(
        HalfLifeLogisticBackoffPolicy::new(
            Duration::from_millis(1),
            multiplier,
            Duration::from_millis(u64::MAX),
            Duration::from_millis(1),
        )
        .is_ok()
    );
    assert!(
        HalfLifeLogisticBackoffPolicy::new(
            Duration::from_secs(u64::MAX),
            multiplier,
            Duration::from_secs(u64::MAX),
            Duration::from_millis(1),
        )
        .is_err()
    );
}

fn assert_recovery_pulse_between_endpoints(
    base: u64,
    asymptote: u64,
    recovery_half_life: u64,
    multiplier: BackoffMultiplier,
    current: u64,
) {
    let immediate =
        half_life_logistic_next_millis(base, current, asymptote, multiplier, recovery_half_life, 0)
            .expect("immediate pulse");
    let after_max_elapsed = half_life_logistic_next_millis(
        base,
        current,
        asymptote,
        multiplier,
        recovery_half_life,
        u64::MAX,
    )
    .expect("pulse after maximum elapsed time");
    let pulse_from_base =
        half_life_logistic_next_millis(base, base, asymptote, multiplier, recovery_half_life, 0)
            .expect("pulse from base");

    if current >= base {
        assert!(pulse_from_base <= after_max_elapsed);
        assert!(after_max_elapsed <= immediate);
    } else {
        assert!(immediate <= after_max_elapsed);
        assert!(after_max_elapsed <= pulse_from_base);
    }
}

#[test]
fn near_equal_extreme_bounds_preserve_recovery_monotonicity() {
    let base = 108_086_391_090_380_800;
    let asymptote = 108_086_391_090_380_906;
    let recovery_half_life = 12_610_080_608_852_371_968;
    let multiplier = BackoffMultiplier::new(110_336, 98_304).expect("valid multiplier");
    let sequence =
        half_life_logistic_scenario(base, multiplier, asymptote, recovery_half_life, &[0])
            .expect("valid near-equal extreme scenario");
    let current = sequence.scheduled_millis[0];

    assert!(current >= base);
    assert_recovery_pulse_between_endpoints(
        base,
        asymptote,
        recovery_half_life,
        multiplier,
        current,
    );
}

#[test]
fn reverse_extreme_bounds_preserve_recovery_monotonicity() {
    let base = 18_235_074_891_223_138_305;
    let asymptote = 361_842_908_157_261_109;
    let recovery_half_life = 361_700_864_190_383_365;
    let multiplier =
        BackoffMultiplier::new(4_294_967_295, 2_256_963_327).expect("valid multiplier");
    let sequence = half_life_logistic_scenario(
        base,
        multiplier,
        asymptote,
        recovery_half_life,
        &[361_700_864_190_383_365, 9_693_440_767_078_761_733],
    )
    .expect("valid reverse extreme scenario");

    assert_eq!(sequence.scheduled_millis.len(), 2);
    for current in sequence.scheduled_millis {
        assert!(current < base);
        assert_recovery_pulse_between_endpoints(
            base,
            asymptote,
            recovery_half_life,
            multiplier,
            current,
        );
    }
}

#[test]
fn half_life_logistic_state_accepts_a_rounded_interval_below_the_base() {
    let base = 6_944_656_592_455_360_608;
    let asymptote = 6_944_656_592_455_375_263;
    let multiplier =
        BackoffMultiplier::new(2_678_087_776, 2_678_038_431).expect("valid multiplier");
    let policy = HalfLifeLogisticBackoffPolicy::new(
        Duration::from_millis(base),
        multiplier,
        Duration::from_millis(asymptote),
        Duration::from_millis(base),
    )
    .expect("valid policy");
    let mut state = HalfLifeLogisticBackoffState::new(policy).expect("valid state");

    let first = state.on_backoff(Duration::ZERO).expect("first transition");
    assert!(first < policy.base_interval());
    assert_eq!(state.current_interval(), first);

    let recovered = state
        .effective_interval(policy.recovery_half_life())
        .expect("recovery preview from below the base");
    assert!(recovered >= first);
    assert!(recovered <= policy.base_interval());

    let second = state
        .on_backoff(policy.recovery_half_life())
        .expect("stored below-base interval remains valid");
    assert_eq!(state.current_interval(), second);
    assert!(second < policy.base_interval());
}

#[test]
fn half_life_logistic_state_accepts_a_rounded_interval_above_the_asymptote() {
    let base = 18_428_459_430_802_632_028;
    let asymptote = 18_428_459_430_802_635_881;
    let multiplier = BackoffMultiplier::new(1_218_886_999, 302_975_755).expect("valid multiplier");
    let policy = HalfLifeLogisticBackoffPolicy::new(
        Duration::from_millis(base),
        multiplier,
        Duration::from_millis(asymptote),
        Duration::from_millis(1),
    )
    .expect("valid policy");
    let mut state = HalfLifeLogisticBackoffState::new(policy).expect("valid state");

    let first = state.on_backoff(Duration::ZERO).expect("first transition");
    assert!(first > policy.asymptote_interval());
    assert_eq!(state.current_interval(), first);

    let recovered = state
        .effective_interval(policy.recovery_half_life())
        .expect("recovery preview from above the asymptote");
    assert!(recovered < first);
    assert!(recovered >= policy.base_interval());

    let second = state
        .on_backoff(policy.recovery_half_life())
        .expect("stored above-asymptote interval remains valid");
    assert_eq!(state.current_interval(), second);
}

#[test]
fn half_life_logistic_policy_validation_and_event_time_order_are_certified() {
    let multiplier = "2".parse().expect("multiplier");
    assert!(half_life_logistic_scenario(0, multiplier, 30_000, 30_000, &[0]).is_err());
    assert!(half_life_logistic_scenario(1_000, multiplier, 0, 30_000, &[0]).is_err());
    assert!(half_life_logistic_scenario(1_000, multiplier, 30_000, 0, &[0]).is_err());
    let equal = half_life_logistic_scenario(1_000, multiplier, 1_000, 30_000, &[0])
        .expect("equal base and asymptote interval");
    assert_eq!(equal.scheduled_millis, [1_000]);
    let reverse = half_life_logistic_scenario(2_000, multiplier, 1_000, 30_000, &[0])
        .expect("base above asymptote interval");
    assert_eq!(reverse.scheduled_millis, [1_334]);
    assert!(half_life_logistic_scenario(1_000, multiplier, 30_000, 30_000, &[10, 9]).is_err());
}

#[test]
fn half_life_logistic_formula_matches_the_definitive_worked_example() {
    let multiplier = "2".parse().expect("multiplier");
    let cases = [
        (0, 48_000),
        (15_000, 38_715),
        (30_000, 30_560),
        (60_000, 18_234),
        (120_000, 6_503),
        (300_000, 2_041),
    ];
    for (elapsed, expected) in cases {
        assert_eq!(
            half_life_logistic_next_millis(1_000, 40_000, 60_000, multiplier, 30_000, elapsed)
                .expect("valid transition"),
            expected
        );
    }
}

#[test]
fn state_recovers_lazily_toward_base_and_applies_the_event_pulse_afterward() {
    let policy = HalfLifeLogisticBackoffPolicy::new(
        Duration::from_secs(1),
        "2".parse().expect("multiplier"),
        Duration::from_secs(60),
        Duration::from_secs(30),
    )
    .expect("policy");
    let mut state = HalfLifeLogisticBackoffState::new(policy).expect("state");
    assert_eq!(state.current_interval(), Duration::from_secs(1));
    assert_eq!(state.last_backoff_at(), None);

    let first = state
        .on_backoff(Duration::from_secs(10))
        .expect("first event");
    assert_eq!(first, Duration::from_millis(1_968));
    assert_eq!(state.last_backoff_at(), Some(Duration::from_secs(10)));
    assert_eq!(
        state
            .effective_interval(Duration::from_secs(40))
            .expect("effective interval"),
        Duration::from_millis(1_484)
    );
    assert_eq!(state.current_interval(), first);

    let second = state
        .on_backoff(Duration::from_secs(40))
        .expect("second event");
    assert_eq!(second, Duration::from_millis(2_897));
}
