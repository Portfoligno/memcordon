pub use memcordon_core::runtime_manifest::{
    RuntimeComponentRecord, RuntimeManifest, SealedRuntime,
};

pub fn fuzz_runtime_manifest(data: &[u8]) {
    let _ = RuntimeManifest::parse(data);
}
