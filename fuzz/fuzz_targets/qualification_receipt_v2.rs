#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = memcordon_core::runtime_readiness::ReadinessObservation::parse(data);
});
