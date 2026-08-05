#![no_main]
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: (u32, u32)| {
    let (numerator, denominator) = data;
    if let Ok(multiplier) = memcordon_core::BackoffMultiplier::new(numerator, denominator) {
        assert!(multiplier.numerator() > multiplier.denominator());
        assert!(u64::from(multiplier.numerator()) <= u64::from(multiplier.denominator()) * 100);
    }
});
