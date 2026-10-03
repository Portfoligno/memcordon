#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::WindowsProviderProbeV1;

// Descriptive live probe bytes are fuzz input, never provider permission.
fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || memcordon_core::canonical_json::reject_duplicate_json_keys(data).is_err()
    {
        return;
    }
    if let Ok(observation) = serde_json::from_slice::<WindowsProviderProbeV1>(data) {
        let valid = observation.validate().is_ok();
        let bytes = serde_json::to_vec(&observation).unwrap();
        let decoded: WindowsProviderProbeV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.validate().is_ok(), valid);
        if valid {
            let mut foreign = observation.clone();
            foreign.format = "memcordon.retired-qualification".into();
            assert!(foreign.validate().is_err());
            let mut unauthenticated = observation;
            unauthenticated.launcher_authenticated = false;
            assert!(unauthenticated.validate().is_err());
        }
    }
});
