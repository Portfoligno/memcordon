#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::sealed_provider::envelope::parse_capability_mask;

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        // Preserve the raw-input check and also exercise newline-terminated seed records.
        for mask in [Some(input), input.strip_suffix('\n')]
            .into_iter()
            .flatten()
        {
            let parsed = parse_capability_mask(mask);
            assert_eq!(
                parsed.is_ok(),
                !mask.is_empty()
                    && mask.bytes().all(|byte| byte.is_ascii_hexdigit())
                    && u64::from_str_radix(mask, 16).is_ok()
            );
            if let Ok(value) = parsed {
                assert_eq!(parse_capability_mask(&format!("{value:x}")), Ok(value));
                assert_eq!(parse_capability_mask(&mask.to_ascii_uppercase()), Ok(value));
                assert!(parse_capability_mask(&format!("{mask}g")).is_err());
            }
        }
    }
});
