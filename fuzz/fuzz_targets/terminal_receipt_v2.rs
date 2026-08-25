#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    #[cfg(target_os = "linux")]
    let _ = memcordon_platform::test_support::sealed_terminal_v2_is_valid(data);
    #[cfg(not(target_os = "linux"))]
    let _ = serde_json::from_slice::<memcordon_core::MemcordonReport>(data);
});
