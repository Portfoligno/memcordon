#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(mask) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        let _ = memcordon_sealed_agent::linux::envelope::parse_capability_mask(mask);
        #[cfg(not(target_os = "linux"))]
        let _ = u64::from_str_radix(mask, 16);
    }
});
