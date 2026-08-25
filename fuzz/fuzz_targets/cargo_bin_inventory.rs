#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(manifest) = toml::from_str::<toml::Value>(text) {
            let _ = manifest
                .get("bin")
                .and_then(toml::Value::as_array)
                .map(|bins| {
                    bins.iter()
                        .filter_map(|bin| bin.get("name").and_then(toml::Value::as_str))
                        .collect::<Vec<_>>()
                });
        }
    }
});
