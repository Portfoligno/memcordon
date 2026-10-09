#[path = "support/linux_image_entrypoint_case.rs"]
mod linux_image_entrypoint_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_lifecycle_case.rs"]
mod linux_lifecycle_case;
#[path = "support/linux_policy_case.rs"]
mod linux_policy_case;
#[path = "support/linux_positive_case.rs"]
mod linux_positive_case;
#[path = "support/linux_prepared_case.rs"]
mod linux_prepared_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

#[test]
fn nine_original_no_target_policy_routes() {
    for scenario in [
        "wrong-caller",
        "wrong-plan",
        "wrong-image",
        "wrong-profile",
        "wrong-identity",
        "wrong-digest",
        "wrong-epoch",
        "disabled-grant",
        "changed-grant",
    ] {
        let case = linux_policy_case::baseline(scenario);
        case.validate()
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[test]
fn original_policy_frontend_and_census_rehashed_hostiles() {
    let mut case = linux_policy_case::baseline("wrong-caller");
    case.validate().unwrap();
    case.mutate("policy/wrong-caller/frontend-invocation.json", |command| {
        command["caller_uid"] = json!(65534)
    });
    let digest = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == "policy/wrong-caller/frontend-invocation.json")
        .unwrap()
        .sha256
        .clone();
    case.mutate("policy/wrong-caller/frontend-exit.json", |exit| {
        exit["invocation_sha256"] = json!(digest)
    });
    assert!(case.validate().is_err());
    let mut case = linux_policy_case::baseline("disabled-grant");
    case.validate().unwrap();
    case.mutate("policy/disabled-grant/census.json", |census| {
        census["tasks"][0]["uids"][0] = json!(61001)
    });
    assert!(case.validate().is_err());
}

#[test]
fn original_policy_requires_independent_positive_and_restoration() {
    let mut case = linux_policy_case::baseline("changed-grant");
    case.validate().unwrap();
    case.index.records.clear();
    assert!(case.validate().is_err());
    let mut case = linux_policy_case::baseline("wrong-epoch");
    case.validate().unwrap();
    case.mutate("policy/disabled-grant/restoration.json", |restoration| {
        restoration["epoch"]["revision"] = json!(4)
    });
    assert!(case.validate().is_err());
}

#[test]
fn three_original_discovery_preparation_release_refusal_routes() {
    for scenario in ["revoke-discovery", "revoke-preparation", "revoke-release"] {
        let case = linux_policy_case::baseline(scenario);
        case.validate()
            .unwrap_or_else(|error| panic!("{scenario}: {error}"));
    }
}

#[test]
fn original_policy_gate_and_discovery_rehashed_hostiles() {
    let mut case = linux_policy_case::baseline("revoke-release");
    case.validate().unwrap();
    case.mutate("policy/revoke-release/release-ack.json", |ack| {
        ack["observer"]["birth"] = json!(306)
    });
    assert!(case.validate().is_err());
    let mut case = linux_policy_case::baseline("revoke-discovery");
    case.validate().unwrap();
    case.mutate("policy/revoke-discovery/discovery-stdout.json", |caps| {
        caps["plan"]["authorizes_launch"] = json!(true)
    });
    let digest = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == "policy/revoke-discovery/discovery-stdout.json")
        .unwrap()
        .sha256
        .clone();
    case.mutate("policy/revoke-discovery/discovery-exit.json", |exit| {
        exit["stdout_sha256"] = json!(digest)
    });
    assert!(case.validate().is_err());
}
