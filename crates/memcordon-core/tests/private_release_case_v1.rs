use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{
    PrivateReleaseCaseResultV1, PrivateReleaseStageV1, private_release_case_key_v1,
};

fn result() -> serde_json::Value {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    serde_json::json!({
        "schema_version": 1,
        "selector": "private_tcp::native_tcp_bind_listen_connect",
        "challenge": "ab".repeat(32),
        "target": "x86_64-unknown-linux-gnu",
        "native_machine": "x86_64",
        "installed": {
            "stage": "candidate-capability",
            "installation_epoch": digest,
            "candidate_manifest_sha256": digest,
            "installed_inspection_sha256": digest,
        },
        "observation": {
            "phase": "allocated-retired",
            "outcome": "target-completed",
            "attempt_id": "ab".repeat(16),
            "checkpoint_sha256": digest,
            "terminal_sha256": digest,
            "retirement_sha256": digest,
            "release_knowledge": "exec-observed",
            "exec": "succeeded",
            "native_observer_sha256": digest,
        },
        "attachments": [
            {"role":"request", "size":1, "sha256":digest},
            {"role":"report", "size":1, "sha256":digest},
            {"role":"stdio", "size":1, "sha256":digest},
            {"role":"observer", "size":1, "sha256":digest},
            {"role":"cleanup", "size":1, "sha256":digest},
        ],
    })
}

fn parse(value: &serde_json::Value) -> Result<PrivateReleaseCaseResultV1, String> {
    PrivateReleaseCaseResultV1::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn candidate_raw_result_is_structural_only_and_has_fixed_inventory() {
    let value = result();
    let parsed = parse(&value).unwrap();
    assert_eq!(parsed.challenge_bytes().unwrap(), [0xab; 32]);
    assert_eq!(parsed.attachments.len(), 5);
    let mut missing = value.clone();
    missing["attachments"].as_array_mut().unwrap().pop();
    assert!(parse(&missing).is_err());
    let mut reordered = value.clone();
    reordered["attachments"].as_array_mut().unwrap().swap(0, 1);
    assert!(parse(&reordered).is_err());
    let mut unknown = value.clone();
    unknown["trusted"] = serde_json::json!(true);
    assert!(parse(&unknown).is_err());
}

#[test]
fn denial_cannot_claim_an_allocated_success_or_cross_stages() {
    let mut value = result();
    value["selector"] = serde_json::json!("private_tcp::wrong_grant_profile_and_port_rejected");
    assert!(parse(&value).is_err());
    value["observation"] = serde_json::json!({
        "phase": "preallocation-rejected",
        "rejection_code": "MCSEALED-GRANT-DENIED",
        "observer_sha256": DiagnosticSha256::from_bytes([7; 32]),
    });
    assert!(parse(&value).is_ok());
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    value["installed"] = serde_json::json!({
        "stage": "final-public",
        "installation_epoch": digest,
        "qualified_manifest_sha256": digest,
        "release_qualification_sha256": digest,
        "active_host_receipt_sha256": digest,
        "public_plan_sha256": digest,
        "public_grant_sha256": digest,
    });
    assert!(parse(&value).is_ok());
    value["installed"]["candidate_manifest_sha256"] = serde_json::json!(digest);
    assert!(parse(&value).is_err());
}

#[test]
fn duplicate_keys_and_missing_retirement_are_rejected() {
    let value = result();
    let mut missing = value.clone();
    missing["observation"]
        .as_object_mut()
        .unwrap()
        .remove("retirement_sha256");
    assert!(parse(&missing).is_err());
    let bytes = serde_json::to_vec(&value).unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = format!("{},\"schema_version\":1}}", text.strip_suffix('}').unwrap());
    assert!(PrivateReleaseCaseResultV1::parse(duplicate.as_bytes()).is_err());
    assert!(PrivateReleaseCaseResultV1::parse(&vec![b' '; 64 * 1024 + 1]).is_err());
}

#[test]
fn abi_composite_is_candidate_only_and_architecture_exact() {
    let mut value = result();
    value["selector"] = serde_json::json!("private_tcp::abi_alternate_entry_denied");
    value["observation"] = serde_json::json!({
        "phase": "abi-composite",
        "attempt_id": "ab".repeat(16),
        "checkpoint_sha256": DiagnosticSha256::from_bytes([1; 32]),
        "terminal_sha256": DiagnosticSha256::from_bytes([2; 32]),
        "retirement_sha256": DiagnosticSha256::from_bytes([3; 32]),
        "abi_raw": {
            "native_abi": "x86-64",
            "x32_sha256": DiagnosticSha256::from_bytes([4; 32]),
            "i386_sha256": DiagnosticSha256::from_bytes([5; 32]),
        },
        "independent_interval_sha256": DiagnosticSha256::from_bytes([6; 32]),
        "native_observer_sha256": DiagnosticSha256::from_bytes([7; 32]),
    });
    assert!(parse(&value).is_ok());
    let mut alias = value.clone();
    alias["observation"]["abi_raw"]["i386_sha256"] =
        alias["observation"]["abi_raw"]["x32_sha256"].clone();
    assert!(parse(&alias).is_err());
    let mut wrong_arch = value.clone();
    wrong_arch["target"] = serde_json::json!("aarch64-unknown-linux-gnu");
    wrong_arch["native_machine"] = serde_json::json!("aarch64");
    assert!(parse(&wrong_arch).is_err());
    let mut wrong_stage = value;
    wrong_stage["installed"]["stage"] = serde_json::json!("final-public");
    assert!(parse(&wrong_stage).is_err());
}

#[test]
fn dual_retirement_requires_two_distinct_completed_attempts_and_exact_selector() {
    let mut value = result();
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let first = serde_json::json!({
        "attempt_id": "ab".repeat(16),
        "checkpoint_sha256": DiagnosticSha256::from_bytes([1; 32]),
        "terminal_sha256": DiagnosticSha256::from_bytes([2; 32]),
        "retirement_sha256": DiagnosticSha256::from_bytes([3; 32]),
        "release_knowledge": "exec-observed",
        "exec": "succeeded",
    });
    let second = serde_json::json!({
        "attempt_id": "cd".repeat(16),
        "checkpoint_sha256": DiagnosticSha256::from_bytes([4; 32]),
        "terminal_sha256": DiagnosticSha256::from_bytes([5; 32]),
        "retirement_sha256": DiagnosticSha256::from_bytes([6; 32]),
        "release_knowledge": "exec-observed",
        "exec": "succeeded",
    });
    value["selector"] = serde_json::json!("private_tcp::dual_attempt_namespace_isolation");
    value["observation"] = serde_json::json!({
        "phase": "dual-attempts-retired",
        "first": first,
        "second": second,
        "native_observer_sha256": digest,
    });
    assert!(parse(&value).is_ok());
    let mut reused = value.clone();
    reused["observation"]["second"]["attempt_id"] =
        reused["observation"]["first"]["attempt_id"].clone();
    assert!(parse(&reused).is_err());
    let mut missing = value.clone();
    missing["observation"]["second"]
        .as_object_mut()
        .unwrap()
        .remove("retirement_sha256");
    assert!(parse(&missing).is_err());
    let mut wrong_selector = value;
    wrong_selector["selector"] = serde_json::json!("private_tcp::native_tcp_bind_listen_connect");
    assert!(parse(&wrong_selector).is_err());
}

#[test]
fn fixed_result_key_matches_the_native_and_ci_domains() {
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        "private_tcp::abi_alternate_entry_denied",
        &[0xab; 32],
    )
    .unwrap();
    assert_eq!(
        String::from(key),
        "2fd68a0c106ed6322f1b3494812268015c9634b5bf1dabcab3e1b5d78ce41944"
    );
}
