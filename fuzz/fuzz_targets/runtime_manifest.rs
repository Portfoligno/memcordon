#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    memcordon_ci::runtime_manifest::fuzz_runtime_manifest(data);
});
