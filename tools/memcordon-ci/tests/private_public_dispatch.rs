use memcordon_ci::private_public_dispatch::validate_public_dispatch_intent_bytes;
use memcordon_core::private_release_branch_v1::{
    PolicyOperationBranchV1, policy_branch_challenge_v1,
};
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;
use memcordon_core::workload_codec::hash_bytes;
use serde_json::{Value, json};

fn fixture() -> Value {
    let digest = String::from(hash_bytes(b"pinned public fixture"));
    let cases: Vec<_> = REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .enumerate()
        .map(|(index, selector)| {
            let root = format!("/run/memcordon-final-public/case-{index}");
            json!({
                "selector": selector,
                "challenge": hex::encode([index as u8 + 1; 32]),
                "contract_path": format!("{root}/contract.json"),
                "contract_sha256": digest,
                "fixture_path": format!("{root}/fixture"),
                "fixture_sha256": digest,
                "expected_plan_path": format!("{root}/plan.json"),
                "expected_plan_sha256": digest,
                "report_path": format!("{root}/report.json"),
                "outcome": "exit-zero"
            })
        })
        .collect();
    let policy_base = cases
        .iter()
        .find(|case| case["selector"] == "private_tcp::wrong_grant_profile_and_port_rejected")
        .unwrap();
    let base: [u8; 32] = hex::decode(policy_base["challenge"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let policy_branches: Vec<_> = PolicyOperationBranchV1::ALL.into_iter().enumerate()
        .map(|(index, branch)| {
            let root = format!("/run/memcordon-final-public/policy-{index}");
            let needs_plan = matches!(branch, PolicyOperationBranchV1::AcceptedControl | PolicyOperationBranchV1::CommittedPortTamper);
            let tampered = branch == PolicyOperationBranchV1::CommittedPortTamper;
            json!({
                "selector": "private_tcp::wrong_grant_profile_and_port_rejected",
                "challenge": hex::encode(policy_branch_challenge_v1(&base, branch).unwrap()),
                "contract_path": format!("{root}/contract.json"),
                "contract_sha256": digest,
                "fixture_path": format!("{root}/fixture"),
                "fixture_sha256": digest,
                "expected_plan_path": needs_plan.then(|| format!("{root}/plan.json")),
                "expected_plan_sha256": needs_plan.then(|| digest.clone()),
                "report_path": format!("{root}/report.json"),
                "outcome": if branch == PolicyOperationBranchV1::AcceptedControl { "exit-zero" } else { "preallocation-rejected" },
                "policy_branch": branch,
                "tampered_contract_path": tampered.then(|| format!("{root}/tampered-contract.json")),
                "tampered_contract_sha256": tampered.then(|| digest.clone()),
            })
        }).collect();
    json!({
        "schema_version": 1,
        "source_commit": hex::encode([1_u8; 20]),
        "target": "x86_64-unknown-linux-gnu",
        "archive_sha256": digest,
        "manifest_sha256": digest,
        "qualification_sha256": digest,
        "public_cli_sha256": digest,
        "build_context_sha256": digest,
        "release_catalogue_sha256": digest,
        "public_uid": 1001,
        "public_gid": 1001,
        "observer": {
            "boot_id": "00000000-0000-4000-8000-000000000001",
            "kernel_release": "6.8.0-review",
            "btf_sha256": digest,
            "probe_map_sha256": digest,
            "control_result_key": digest,
            "probe_bundle": {
                "bpf_source_sha256": digest,
                "loader_source_sha256": digest,
                "object_sha256": digest,
                "loader_sha256": digest,
                "agent_sha256": digest,
                "agent_build_id": vec![1_u8; 20],
                "request_entry_offset": 1,
                "request_exit_offset": 2,
                "allocation_entry_offset": 3,
            },
        },
        "historical_e0": {
            "selector": "private_tcp::caller_identity_and_epoch_bound",
            "challenge": "ee".repeat(32),
            "contract_path": "/run/memcordon-final-public/historical-e0/contract.json",
            "contract_sha256": digest,
            "fixture_path": "/run/memcordon-final-public/historical-e0/fixture",
            "fixture_sha256": digest,
            "expected_plan_path": "/run/memcordon-final-public/historical-e0/plan.json",
            "expected_plan_sha256": digest,
            "report_path": "/run/memcordon-final-public/historical-e0/report.json",
            "outcome": "exit-zero",
            "e0_installation_epoch_sha256": digest,
            "e0_h1_receipt_sha256": digest,
            "upgrade_archive_path": "/run/memcordon-final-public/historical-e0/archive.tar.gz",
        },
        "historical_spoof": {
            "selector": "private_tcp::caller_identity_and_epoch_bound",
            "challenge": "dd".repeat(32),
            "contract_path": "/run/memcordon-final-public/historical-spoof/contract.json",
            "contract_sha256": digest,
            "fixture_path": "/run/memcordon-final-public/historical-spoof/fixture",
            "fixture_sha256": digest,
            "report_path": "/run/memcordon-final-public/historical-spoof/report.json",
            "outcome": "preallocation-rejected",
            "unauthorized_uid": 1002,
            "unauthorized_gid": 1002,
        },
        "cases": cases,
        "policy": {
            "base_challenge": hex::encode(base),
            "branches": policy_branches,
        },
    })
}

fn accepts(value: &Value) -> bool {
    validate_public_dispatch_intent_bytes(
        &serde_json::to_vec(value).unwrap(),
        "x86_64-unknown-linux-gnu",
    )
    .is_ok()
}

#[test]
fn public_dispatch_intent_requires_exact_ordered_cases_and_pinned_distinct_inputs() {
    let mut value = fixture();
    assert!(accepts(&value));
    value["cases"][8]["selector"] = value["cases"][7]["selector"].clone();
    assert!(!accepts(&value));
    let mut value = fixture();
    value["cases"][2]["contract_path"] = value["cases"][1]["contract_path"].clone();
    assert!(!accepts(&value));
    let mut value = fixture();
    value["cases"][3]["expected_plan_path"] = Value::Null;
    assert!(!accepts(&value));
    let mut value = fixture();
    value["cases"][4]["challenge"] = Value::String("0".repeat(64));
    assert!(!accepts(&value));
    let mut value = fixture();
    value["cases"][5]["outcome"] = Value::String("success-even-if-missing".into());
    assert!(!accepts(&value));
    let mut value = fixture();
    value["cases"][REQUIRED_PRIVATE_RELEASE_SELECTORS_V1
        .iter()
        .position(|selector| *selector == "private_tcp::frontend_loss_retired")
        .unwrap()]["outcome"] = Value::String("frontend-lost".into());
    assert!(accepts(&value));
    let mut value = fixture();
    value["cases"][6]["fixture_path"] =
        Value::String("/run/memcordon-final-public/../etc/passwd".into());
    assert!(!accepts(&value));
    let mut value = fixture();
    value["observer"]["control_result_key"] = Value::String("0".repeat(64));
    assert!(!accepts(&value));
    let mut value = fixture();
    value["historical_e0"]["challenge"] = value["cases"][4]["challenge"].clone();
    assert!(!accepts(&value));
    let mut value = fixture();
    value["historical_spoof"]["challenge"] = value["historical_e0"]["challenge"].clone();
    assert!(!accepts(&value));
    let mut value = fixture();
    value["historical_spoof"]["unauthorized_uid"] = value["public_uid"].clone();
    assert!(!accepts(&value));
    let mut value = fixture();
    value["historical_spoof"]["contract_path"] = value["historical_e0"]["contract_path"].clone();
    assert!(!accepts(&value));
}

#[test]
fn public_dispatch_intent_rejects_duplicate_unknown_and_unbounded_json() {
    let mut bytes = serde_json::to_vec(&fixture()).unwrap();
    assert!(validate_public_dispatch_intent_bytes(&bytes, "aarch64-unknown-linux-gnu").is_err());
    let mut value = fixture();
    value["unreviewed"] = json!(true);
    assert!(!accepts(&value));
    bytes = serde_json::to_vec(&fixture()).unwrap();
    let duplicate = String::from_utf8(bytes).unwrap().replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":1",
        1,
    );
    assert!(
        validate_public_dispatch_intent_bytes(duplicate.as_bytes(), "x86_64-unknown-linux-gnu")
            .is_err()
    );
    let oversized = vec![b' '; 128 * 1024 + 1];
    assert!(validate_public_dispatch_intent_bytes(&oversized, "x86_64-unknown-linux-gnu").is_err());
}
