#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(names) = memcordon_ci::fuzz_targets::targets(text, None) {
            assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
            let mut document = toml::from_str::<toml::Value>(text).unwrap();
            let bins = document.get_mut("bin").unwrap().as_array_mut().unwrap();
            assert_eq!(bins.len(), names.len());
            bins.push(bins[0].clone());
            assert!(
                memcordon_ci::fuzz_targets::targets(&toml::to_string(&document).unwrap(), None)
                    .is_err()
            );
        }
    }
});
