#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: (u64, u32, u32, u64, u8)| {
    let (initial, numerator, denominator, maximum, steps) = data;
    let Ok(multiplier) = memcordon_core::BackoffMultiplier::new(numerator, denominator) else {
        return;
    };
    let Ok(sequence) = memcordon_core::test_support::logistic_scenario(
        initial,
        multiplier,
        maximum,
        usize::from(steps.min(64)),
    ) else {
        return;
    };
    assert!(sequence.scheduled_millis.iter().all(|value| *value <= maximum));
    assert!(sequence.scheduled_millis.windows(2).all(|pair| pair[0] <= pair[1]));
});
