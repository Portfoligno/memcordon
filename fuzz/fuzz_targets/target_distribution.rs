#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_ci::release::distribution::TargetDistribution;

// Selected binaries/units are an ordinary archive graph, not release approval.
fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || memcordon_core::canonical_json::reject_duplicate_json_keys(data).is_err()
    {
        return;
    }
    if let Ok(distribution) = serde_json::from_slice::<TargetDistribution>(data) {
        let valid = distribution.validate().is_ok();
        let bytes = serde_json::to_vec(&distribution).unwrap();
        let decoded: TargetDistribution = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.validate().is_ok(), valid);
        if valid {
            let mut changed = distribution;
            changed.units.push("unexpected.service".into());
            assert!(changed.validate().is_err());
        }
    }
});
