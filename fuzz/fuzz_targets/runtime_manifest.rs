#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(data) {
        assert!(manifest.validate().is_ok());
    }
    memcordon_ci::runtime_manifest::fuzz_runtime_manifest(data);
});
