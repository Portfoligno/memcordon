#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = memcordon_ci::config::parse_policy(data) {
        let text = std::str::from_utf8(data).unwrap();
        let value: toml::Value = toml::from_str(text).unwrap();
        let normalized = toml::to_string(&value).unwrap();
        let reparsed = memcordon_ci::config::parse_policy(normalized.as_bytes()).unwrap();
        assert_eq!(format!("{policy:?}"), format!("{reparsed:?}"));
    }
});
