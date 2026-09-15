#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::runtime_manifest::RuntimeManifestV2;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = RuntimeManifestV2::parse(data) {
        let encoded = serde_json::to_vec(&manifest).expect("accepted manifest serializes");
        assert_eq!(
            RuntimeManifestV2::parse(&encoded).expect("canonical manifest parses"),
            manifest
        );
    }
});
