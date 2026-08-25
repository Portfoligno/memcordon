#![no_main]

use libfuzzer_sys::fuzz_target;

#[cfg(target_os = "linux")]
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/linux/envelope.rs"]
mod envelope;
#[cfg(target_os = "linux")]
#[path = "../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/request.rs"]
mod request;

fuzz_target!(|data: &[u8]| {
    if let Ok(status) = std::str::from_utf8(data) {
        #[cfg(target_os = "linux")]
        let _ = envelope::parse_proc_status(status);
        #[cfg(not(target_os = "linux"))]
        let _ = status.lines().count();
    }
});
