pub use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeManifestV2, SealedRuntimeV2,
};

pub fn fuzz_runtime_manifest(data: &[u8]) {
    let _ = RuntimeManifestV2::parse(data);
}
