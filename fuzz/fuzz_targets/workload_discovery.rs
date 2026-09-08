#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use memcordon_core::workload_discovery::DiscoveryReportV1;
use memcordon_core::workload_registry::BaselineProfile;

fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || reject_duplicate_json_keys(data).is_err()
    {
        return;
    }
    let Ok(report) = serde_json::from_slice::<DiscoveryReportV1>(data) else {
        return;
    };
    if let DiscoveryReportV1::Authenticated { discovery } = report {
        for profile in [
            BaselineProfile::LinuxUnixCreate,
            BaselineProfile::WindowsHostNetworkExternal,
        ] {
            if discovery.validate(profile) {
                let json = serde_json::to_vec(&discovery).unwrap();
                let decoded: memcordon_core::workload_discovery::WorkloadDiscoveryV1 =
                    serde_json::from_slice(&json).unwrap();
                assert!(decoded.validate(profile));
                let mut substituted = decoded;
                substituted.profile.semantic_digest =
                    memcordon_core::DiagnosticSha256::from_bytes([0; 32]);
                assert!(!substituted.validate(profile));
            }
        }
    }
});
