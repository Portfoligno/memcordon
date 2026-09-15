pub use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeManifestV2, SealedRuntimeV2,
};

pub fn fuzz_runtime_manifest(data: &[u8]) {
    if let Ok(manifest) = RuntimeManifestV2::parse(data) {
        let encoded = serde_json::to_vec(&manifest).expect("accepted manifest serializes");
        assert_eq!(
            RuntimeManifestV2::parse(&encoded).expect("canonical manifest parses"),
            manifest
        );
    }
}
