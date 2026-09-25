pub use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeManifestV2, SealedRuntimeV2,
};
pub use memcordon_core::runtime_manifest_v3::{RuntimeManifestV3, VersionedRuntimeManifest};

pub fn fuzz_runtime_manifest(data: &[u8]) {
    let _ = VersionedRuntimeManifest::parse(data);
}
