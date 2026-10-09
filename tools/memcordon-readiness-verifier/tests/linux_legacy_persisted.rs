#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/linux_legacy_case.rs"]
mod linux_legacy_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;
#[test]
fn frozen_unix_original_contract_and_native_activation_route() {
    let mut case = linux_legacy_case::baseline();
    case.validate().unwrap();
    case.mutate(
        "installed/installed/frozen-legacy/v1/request.json",
        |request| request["expected_epoch"]["revision"] = json!(10),
    );
    assert!(case.validate().is_err());
}
#[test]
fn frozen_unix_rehashed_native_effect_and_checkpoint_hostiles() {
    let mut case = linux_legacy_case::baseline();
    case.validate().unwrap();
    let path = "installed/installed/frozen-legacy/v1/result/result.json";
    case.mutate(path, |result| {
        result["attempts"][0]["policy_enforcement"]["before_authorization"]["digest"] =
            json!("f".repeat(64))
    });
    assert!(case.validate().is_err());
    let mut case = linux_legacy_case::baseline();
    case.validate().unwrap();
    let path = "installed/installed/frozen-legacy/v1/result/stdout.bin";
    case.mutate(path, |result| {
        result["denials"][0]["native_errno"] = json!(13)
    });
    let digest = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == path)
        .unwrap()
        .sha256
        .clone();
    case.mutate(
        "installed/installed/frozen-legacy/v1/result/exit.json",
        |exit| exit["stdout_sha256"] = json!(digest),
    );
    assert!(case.validate().is_err());
}

#[test]
fn frozen_private_tcp_original_restoration_and_request_route() {
    let mut case = linux_legacy_case::baseline_v2();
    case.validate().unwrap();
    case.mutate("installed/installed/frozen-legacy/v2/request.json",|request|request["execution_identity"]=json!({"kind":"administrator-profile","reference":{"id":"other-account","semantic_digest":"c".repeat(64)}}));
    assert!(case.validate().is_err());
}

#[test]
fn frozen_private_tcp_rehashed_runtime_and_capture_hostiles() {
    let mut case = linux_legacy_case::baseline_v2();
    case.validate().unwrap();
    case.mutate(
        "installed/installed/frozen-legacy/v2/result/result.json",
        |result| result["runtime"]["activation_epoch"] = json!(9),
    );
    assert!(case.validate().is_err());
    let mut case = linux_legacy_case::baseline_v2();
    case.validate().unwrap();
    let path = "installed/installed/frozen-legacy/v2/result/stdout.bin";
    case.mutate(path, |fixture| fixture["groups"] = json!([65533]));
    let digest = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == path)
        .unwrap()
        .sha256
        .clone();
    case.mutate(
        "installed/installed/frozen-legacy/v2/result/exit.json",
        |exit| exit["stdout_sha256"] = json!(digest),
    );
    assert!(case.validate().is_err());
}
