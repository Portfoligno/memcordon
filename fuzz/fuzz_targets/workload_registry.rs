#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_registry::RuntimePolicyRegistry;
use memcordon_core::workload_registry_v2::RuntimePrivatePolicyRegistry;

fuzz_target!(|data: &[u8]| {
    if let Ok(registry) = RuntimePolicyRegistry::parse(data) {
        assert!(registry.validate().is_ok());
        let digest = registry.canonical_digest().unwrap();
        let json = serde_json::to_vec(&registry).unwrap();
        let decoded = RuntimePolicyRegistry::parse(&json).unwrap();
        assert_eq!(decoded.canonical_digest().unwrap(), digest);
    }
    if let Ok(registry) = RuntimePrivatePolicyRegistry::parse(data) {
        assert!(registry.validate().is_ok());
        let digest = registry.canonical_digest().unwrap();
        let json = serde_json::to_vec(&registry).unwrap();
        let decoded = RuntimePrivatePolicyRegistry::parse(&json).unwrap();
        assert_eq!(decoded.canonical_digest().unwrap(), digest);
    }
});
