#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_registry::PolicyRegistryV1;
use memcordon_core::workload_registry_v2::PolicyRegistryV2;

fuzz_target!(|data: &[u8]| {
    if let Ok(registry) = PolicyRegistryV1::parse(data) {
        assert!(registry.validate().is_ok());
        let digest = registry.canonical_digest().unwrap();
        let json = serde_json::to_vec(&registry).unwrap();
        let decoded = PolicyRegistryV1::parse(&json).unwrap();
        assert_eq!(decoded.canonical_digest().unwrap(), digest);
    }
    if let Ok(registry) = PolicyRegistryV2::parse(data) {
        assert!(registry.validate().is_ok());
        let digest = registry.canonical_digest().unwrap();
        let json = serde_json::to_vec(&registry).unwrap();
        let decoded = PolicyRegistryV2::parse(&json).unwrap();
        assert_eq!(decoded.canonical_digest().unwrap(), digest);
    }
});
