use memcordon_core::{
    BoundaryRequirement, DeadlinePolicyReport, DeadlineScope, RequestedMemoryPolicyReport,
    RequestedPolicyReport, RequestedRestartPolicyReport, RestartConditions, RestartLimit,
    SwapReport,
};
use memcordon_readiness_verifier::{current::windows::special_resource_digest, sha256};

#[test]
fn independent_special_resource_commitment_matches_exact_requested_native_policy_codec() {
    let mut value = RequestedPolicyReport {
        boundary: BoundaryRequirement::Sealed,
        memory: Some(RequestedMemoryPolicyReport {
            limit_bytes: 4 * 1024 * 1024 * 1024,
            enforcement: "auto".into(),
            metric: "native".into(),
            poll_interval_ms: 50,
            swap: SwapReport::Bytes { bytes: 0 },
        }),
        deadline: Some(DeadlinePolicyReport {
            duration_ms: 120000,
            scope: DeadlineScope::Attempt,
            origin: None,
            clock: "rust-instant".into(),
        }),
        wait_for: "command".into(),
        signal_grace_ms: 2000,
        command_exit_grace_ms: 0,
        limit_grace_ms: 0,
        restart: RequestedRestartPolicyReport {
            enabled: false,
            enablement_source: None,
            configured_conditions: RestartConditions::NONE,
            limit: RestartLimit::Unlimited,
            backoff: None,
            circuit_breaker: None,
        },
    };
    assert_eq!(
        special_resource_digest(),
        sha256(&serde_json::to_vec(&value).unwrap())
    );
    value.wait_for = "workload".into();
    assert_ne!(
        special_resource_digest(),
        sha256(&serde_json::to_vec(&value).unwrap())
    );
    value.wait_for = "command".into();
    value.deadline.as_mut().unwrap().duration_ms = 120001;
    assert_ne!(
        special_resource_digest(),
        sha256(&serde_json::to_vec(&value).unwrap())
    );
}
