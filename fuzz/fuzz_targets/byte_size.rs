#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        // Preserve raw-input coverage and also decode newline-terminated seed records.
        for text in std::iter::once(text).chain(text.strip_suffix('\n')) {
            if let Ok(size) = text.parse::<memcordon_core::ByteSize>() {
                assert_eq!(
                    size.to_string()
                        .parse::<memcordon_core::ByteSize>()
                        .unwrap(),
                    size
                );
            }
        }
    }
});
