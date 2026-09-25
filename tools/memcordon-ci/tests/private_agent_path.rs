use memcordon_ci::private_agent_path::{
    AGENT_PATH_SELECTOR, AgentPathSnapshotV1, validate_agent_path_observer,
};
use serde_json::json;

fn snapshot() -> AgentPathSnapshotV1 {
    serde_json::from_value(json!({
        "schema_version": 1,
        "nodes": [
            {"component":"/","device":1,"inode":2,"owner_uid":0,"mode":16877},
            {"component":"usr","device":1,"inode":3,"owner_uid":0,"mode":16877},
            {"component":"libexec","device":1,"inode":4,"owner_uid":0,"mode":16877},
            {"component":"memcordon-sealed-agent","device":1,"inode":5,"owner_uid":0,"mode":33261}
        ]
    }))
    .unwrap()
}

#[test]
fn protected_agent_path_claim_must_match_three_independent_ci_snapshots() {
    let before = snapshot();
    let after = snapshot();
    let current = snapshot();
    let observer = serde_json::to_vec(&json!({
        "agent_path_preservation": {
            "schema_version": 1,
            "before": before,
            "after": after
        }
    }))
    .unwrap();
    validate_agent_path_observer(
        AGENT_PATH_SELECTOR,
        &observer,
        Some(&before),
        Some(&after),
        Some(&current),
    )
    .unwrap();
    assert!(
        validate_agent_path_observer(
            "private_tcp::target_exec_and_fd_leak_observed",
            &observer,
            None,
            None,
            None,
        )
        .is_err()
    );
    let mut writable: serde_json::Value = serde_json::from_slice(&observer).unwrap();
    writable["agent_path_preservation"]["before"]["nodes"][1]["mode"] = json!(16895);
    assert!(
        validate_agent_path_observer(
            AGENT_PATH_SELECTOR,
            &serde_json::to_vec(&writable).unwrap(),
            Some(&before),
            Some(&after),
            Some(&current),
        )
        .is_err()
    );
    let mut changed: serde_json::Value = serde_json::from_slice(&observer).unwrap();
    changed["agent_path_preservation"]["after"]["nodes"][3]["inode"] = json!(6);
    assert!(
        validate_agent_path_observer(
            AGENT_PATH_SELECTOR,
            &serde_json::to_vec(&changed).unwrap(),
            Some(&before),
            Some(&after),
            Some(&current),
        )
        .is_err()
    );
    assert!(
        validate_agent_path_observer(
            AGENT_PATH_SELECTOR,
            &observer,
            Some(&before),
            Some(&after),
            None,
        )
        .is_err()
    );
}
