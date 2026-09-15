#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(release) = toml::from_str::<memcordon_ci::config::Release>(text) {
            let value: toml::Value = toml::from_str(text).unwrap();
            let normalized = toml::to_string(&value).unwrap();
            let reparsed: memcordon_ci::config::Release = toml::from_str(&normalized).unwrap();
            assert_eq!(format!("{release:?}"), format!("{reparsed:?}"));
        }
    }
});
