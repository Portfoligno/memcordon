#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_limits_case.rs"]
mod linux_limits_case;
#[path = "support/linux_policy_case.rs"]
mod linux_policy_case;
#[path = "support/linux_policy_running_case.rs"]
mod linux_policy_running_case;
#[path = "support/linux_positive_case.rs"]
mod linux_positive_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

#[test]
fn original_drain_and_revoke_running_full_routes() {
    for scenario in ["drain-running", "revoke-running"] {
        let case = linux_policy_running_case::baseline(scenario);
        case.validate()
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[test]
fn original_running_cohort_and_fresh_refusal_rehashed_hostiles() {
    let mut case = linux_policy_running_case::baseline("drain-running");
    case.validate().unwrap();
    case.mutate("running/policy-running-after-revocation.json", |after| {
        after["target"]["birth"] = json!(303)
    });
    assert!(case.validate().is_err());
    let mut case = linux_policy_running_case::baseline("revoke-running");
    case.validate().unwrap();
    case.mutate("running/policy-fresh-native-census.json", |census| {
        census["tasks"][0]["uids"] = json!([61001, 61001, 61001, 61001])
    });
    assert!(case.validate().is_err());
}

#[test]
fn original_restart_native_generation_and_rehashed_epoch_hostile() {
    let mut case = linux_policy_running_case::baseline("restart-fresh-admission");
    case.validate().unwrap();
    case.mutate(
        "running/policy-control-generation-settlement.json",
        |generation| generation["current"]["birth"] = json!(600),
    );
    assert!(case.validate().is_err());
    let mut case = linux_policy_running_case::baseline("restart-fresh-admission");
    case.validate().unwrap();
    case.mutate("running/policy-activation-json", |activation| {
        activation["epoch"]["service_instance"] = json!(vec![8u8; 16])
    });
    assert!(case.validate().is_err());
}

#[test]
fn original_running_cooperation_namespace_and_completion_hostiles() {
    let mut case = linux_policy_running_case::baseline("drain-running");
    case.validate().unwrap();
    case.mutate("running/policy-running-native-held.json", |running| {
        running["native_descendants"][0]["pid"]["inode"] = json!(999)
    });
    assert!(case.validate().is_err());
    let mut case = linux_policy_running_case::baseline("drain-running");
    case.validate().unwrap();
    let bytes = std::fs::read(case.root.path().join("transcript.bin")).unwrap();
    let mut rows = bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    rows[1]["observation"]["server_received"] = json!(b"foreign".as_slice());
    let mut changed = Vec::new();
    for row in rows {
        changed.extend(serde_json::to_vec(&row).unwrap());
        changed.push(b'\n');
    }
    case.write("transcript.bin", &changed);
    assert!(case.validate().is_err());
}
