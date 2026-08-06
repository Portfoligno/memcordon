#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: (u64, u32, u32, u64, u64, Vec<u64>)| {
    let (base, numerator, denominator, asymptote, recovery_half_life, spacings) = data;
    let Ok(multiplier) = memcordon_core::BackoffMultiplier::new(numerator, denominator) else {
        return;
    };
    if base == 0 || asymptote == 0 || recovery_half_life == 0 {
        return;
    }
    let mut event_times = Vec::with_capacity(spacings.len().min(64));
    let mut event_time = 0_u64;
    for spacing in spacings.into_iter().take(64) {
        let Some(next_event_time) = event_time.checked_add(spacing) else {
            return;
        };
        event_time = next_event_time;
        event_times.push(event_time);
    }
    let sequence = memcordon_core::test_support::half_life_logistic_scenario(
        base,
        multiplier,
        asymptote,
        recovery_half_life,
        &event_times,
    )
    .expect("nonzero intervals must be valid in any order");
    assert_eq!(sequence.scheduled_millis.len(), event_times.len());
    for current in sequence.scheduled_millis {
        let immediate = memcordon_core::half_life_logistic_next_millis(
            base,
            current,
            asymptote,
            multiplier,
            recovery_half_life,
            0,
        )
        .expect("validated state must remain valid");
        let after_max_elapsed = memcordon_core::half_life_logistic_next_millis(
            base,
            current,
            asymptote,
            multiplier,
            recovery_half_life,
            u64::MAX,
        )
        .expect("validated state must remain valid");
        let pulse_from_base = memcordon_core::half_life_logistic_next_millis(
            base,
            base,
            asymptote,
            multiplier,
            recovery_half_life,
            0,
        )
        .expect("validated base must remain valid");
        if current >= base {
            assert!(pulse_from_base <= after_max_elapsed);
            assert!(after_max_elapsed <= immediate);
        } else {
            assert!(immediate <= after_max_elapsed);
            assert!(after_max_elapsed <= pulse_from_base);
        }
    }
});
