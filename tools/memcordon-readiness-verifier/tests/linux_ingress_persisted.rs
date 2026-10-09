#[path = "support/linux_ingress_case.rs"]
mod linux_ingress_case;
#[path = "support/linux_installed_case.rs"]
mod linux_installed_case;
#[path = "support/persisted_case.rs"]
mod persisted_case;
use serde_json::json;

#[test]
fn v3_preserve_caller_original_native_refusal_route() {
    let case = linux_ingress_case::baseline();
    case.validate().unwrap();
}

#[test]
fn v3_preserve_caller_rehashed_original_peer_and_cutoff_hostiles() {
    let prefix = "installed/mixed-cases/policy-cases/v3-preserve-caller";
    let mut case = linux_ingress_case::baseline();
    case.validate().unwrap();
    case.mutate(&format!("{prefix}/invocation.json"), |command| {
        command["work_deadline_unix_millis"] = json!(101)
    });
    let hash = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == format!("{prefix}/invocation.json"))
        .unwrap()
        .sha256
        .clone();
    case.mutate(&format!("{prefix}/exit.json"), |exit| {
        exit["invocation_sha256"] = json!(hash)
    });
    assert!(case.validate().is_err());
    let mut case = linux_ingress_case::baseline();
    case.validate().unwrap();
    case.mutate(&format!("{prefix}/receipt.json"), |receipt| {
        receipt["transport"]["peer_uid"] = json!(65534)
    });
    let hash = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == format!("{prefix}/receipt.json"))
        .unwrap()
        .sha256
        .clone();
    case.mutate(&format!("{prefix}/census.json"), |census| {
        census["result_sha256"] = json!(hash)
    });
    assert!(case.validate().is_err());
}

#[test]
fn v3_preserve_caller_rehashed_original_account_and_source_hostiles() {
    let mut case = linux_ingress_case::baseline();
    case.validate().unwrap();
    case.write(
        "installed/mixed-cases/exclusive-group-getent.bin",
        b"foreign:x:61001:\n",
    );
    assert!(case.validate().is_err());
    let mut case = linux_ingress_case::baseline();
    case.validate().unwrap();
    case.mutate("installed/mixed-cases/policy-cases/restart-fresh-admission/frontend/observations/07070707070707070707070707070707.provider-request.bin",|original|original["attempt_deadline_millis"]=json!(300001));
    assert!(case.validate().is_err());
    let mut case = linux_ingress_case::baseline();
    case.validate().unwrap();
    case.mutate("installed/mixed-cases/policy-cases/restart-fresh-admission/frontend/frontend-invocation.json",|command|command["environment_cleared"]=json!(false));
    assert!(case.validate().is_err());
}
