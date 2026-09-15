#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        for text in std::iter::once(text).chain(text.strip_suffix('\n')) {
            if let Ok(duration) = memcordon::parse_duration(text) {
                let canonical = format!("{}ms", duration.as_millis());
                assert_eq!(memcordon::parse_duration(&canonical).unwrap(), duration);
            }
        }
    }
});
