#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = memcordon_core::discovery::CapabilitiesV3::parse(data) {
        let bytes=serde_json::to_vec(&value).unwrap();
        assert!(memcordon_core::discovery::CapabilitiesV3::parse(&bytes).is_ok());
    }
    if let Ok(mut value) = memcordon_core::discovery::PlanV3::parse(data) {
        value.authorizes_launch=true;
        assert!(memcordon_core::discovery::PlanV3::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let _=memcordon_core::workload_bundle::SnapshotManifestV1::parse(data);
});
