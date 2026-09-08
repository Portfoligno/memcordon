#![no_main]
use libfuzzer_sys::fuzz_target;
use memcordon_core::workload_contract::reject_duplicate_json_keys;
use memcordon_core::workload_evidence::*;

fuzz_target!(|data: &[u8]| {
    if data.len() > memcordon_core::workload_limits::PUBLIC_OBJECT_BYTES
        || reject_duplicate_json_keys(data).is_err()
    {
        return;
    }
    let Ok(receipt) = serde_json::from_slice::<AttemptPolicyEnforcementV1>(data) else {
        return;
    };
    if receipt.terminal_success() {
        assert!(receipt.is_consistent());
        assert!(matches!(
            receipt.resolution(),
            Some(WorkloadResolutionReportV1::Admitted { .. })
        ));
        let mut unavailable = receipt.clone();
        if let AttemptPolicyEnforcementV1::Authorized { terminal, .. } = &mut unavailable {
            *terminal = PolicyTerminalEvidenceV1::Unavailable {
                reason: AdmissionAvailabilityFailure::TerminalUnavailable,
            };
        }
        assert!(!unavailable.terminal_success());
        let json = serde_json::to_vec(&receipt).unwrap();
        assert!(
            serde_json::from_slice::<AttemptPolicyEnforcementV1>(&json)
                .unwrap()
                .terminal_success()
        );
    }
});
