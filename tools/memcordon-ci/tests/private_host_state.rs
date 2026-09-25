#[cfg(target_os = "linux")]
use memcordon_ci::private_host_state::HostNetworkStateV1;
use memcordon_ci::private_host_state::{
    HOST_PRESERVATION_SELECTOR, validate_host_preservation_observer,
};
use serde_json::json;

#[test]
fn owner_host_claim_requires_independent_snapshots_and_exact_selector() {
    let ordinary = serde_json::to_vec(&json!({"schema_version":1})).unwrap();
    validate_host_preservation_observer(
        "private_tcp::native_tcp_bind_listen_connect",
        &ordinary,
        None,
        None,
    )
    .unwrap();
    assert!(
        validate_host_preservation_observer(HOST_PRESERVATION_SELECTOR, &ordinary, None, None)
            .is_err()
    );
    let substituted = serde_json::to_vec(&json!({
        "host_network_preservation": {"schema_version":1}
    }))
    .unwrap();
    assert!(
        validate_host_preservation_observer(
            "private_tcp::native_tcp_bind_listen_connect",
            &substituted,
            None,
            None
        )
        .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn native_before_after_must_match_separate_ci_proc_observation() {
    let before = HostNetworkStateV1::capture().unwrap();
    let after = HostNetworkStateV1::capture().unwrap();
    assert_eq!(before, after);
    let exact = serde_json::to_vec(&json!({
        "host_network_preservation": {
            "schema_version": 1,
            "before": before,
            "after": after,
        }
    }))
    .unwrap();
    validate_host_preservation_observer(
        HOST_PRESERVATION_SELECTOR,
        &exact,
        Some(&before),
        Some(&after),
    )
    .unwrap();
    let mut changed: serde_json::Value = serde_json::from_slice(&exact).unwrap();
    changed["host_network_preservation"]["after"]["namespace_inode"] = json!(1);
    assert!(
        validate_host_preservation_observer(
            HOST_PRESERVATION_SELECTOR,
            &serde_json::to_vec(&changed).unwrap(),
            Some(&before),
            Some(&after)
        )
        .is_err()
    );
    assert!(
        validate_host_preservation_observer(HOST_PRESERVATION_SELECTOR, &exact, None, Some(&after))
            .is_err()
    );
}
