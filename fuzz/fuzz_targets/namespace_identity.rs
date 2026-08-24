#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(identity) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        let _ = memcordon_sealed_agent::linux::envelope::parse_namespace_identity(identity, "pid");
        #[cfg(not(target_os = "linux"))]
        let _ = identity
            .strip_prefix("pid:[")
            .and_then(|value| value.strip_suffix(']'));
    }
});
