pub use memcordon_core::runtime_components::RuntimeComponentRecord;
pub use memcordon_core::runtime_manifest_v2::RuntimeManifestV2;

pub fn fuzz_runtime_manifest(data: &[u8]) {
    let _ = RuntimeManifestV2::parse(data);
}
