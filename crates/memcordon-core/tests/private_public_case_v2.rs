use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_case_v2::FinalPublicCaseEvidenceV2;
use memcordon_core::workload_codec::hash_bytes;

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

fn case() -> serde_json::Value {
    let report = b"public report";
    let observed = digest(9);
    serde_json::json!({
        "schema_version": 2,
        "selector": "private_tcp::native_tcp_bind_listen_connect",
        "challenge": Vec::from([7_u8; 32]),
        "source_commit": "a".repeat([0_u8; 20].len() * 2),
        "release_version": "0.5.7",
        "target": "x86_64-unknown-linux-gnu",
        "native_machine": "x86_64",
        "build_context_sha256": digest(22),
        "release_catalogue_sha256": digest(23),
        "installed": {
            "installation_epoch": digest(1),
            "archive_sha256": digest(2),
            "qualified_manifest_sha256": digest(3),
            "release_qualification_sha256": digest(4),
            "active_host_receipt_sha256": digest(5),
            "component_sha256": digest(24),
            "unit_sha256": digest(25),
            "filter_sha256": digest(26),
            "public_plan_sha256": digest(6),
            "public_grant_sha256": digest(7),
        },
        "child": {
            "pid": 42,
            "start_time_ticks": 123,
            "boot_identity": "boot-1",
            "uid": 1000,
            "gid": 1000,
            "supplementary_groups_empty": true,
            "executable_sha256": digest(10),
            "argv_sha256": digest(11),
            "working_directory_sha256": digest(12),
        },
        "observation": {
            "phase": "allocated-retired",
            "outcome": "target-completed",
            "attempt_id": "ab".repeat([0_u8; 16].len()),
            "checkpoint_sha256": digest(13),
            "terminal_sha256": digest(14),
            "retirement_sha256": digest(15),
            "release_knowledge": "exec-observed",
            "exec": "succeeded",
            "native_observer_sha256": observed,
        },
        "positive_control_terminal_sha256": null,
        "report": {
            "state": "present",
            "size": report.len(),
            "sha256": hash_bytes(report),
        },
        "attachments": [
            {"role":"request", "size":1, "sha256":digest(16)},
            {"role":"report", "size":report.len(), "sha256":hash_bytes(report)},
            {"role":"stdio", "size":1, "sha256":digest(17)},
            {"role":"observer", "size":1, "sha256":observed},
            {"role":"cleanup", "size":1, "sha256":digest(18)},
        ],
    })
}

fn parse(value: &serde_json::Value) -> Result<FinalPublicCaseEvidenceV2, String> {
    FinalPublicCaseEvidenceV2::parse(&serde_json::to_vec(value).unwrap())
}

#[test]
fn final_public_case_binds_installed_nonroot_child_and_exact_report() {
    let value = case();
    let case = parse(&value).unwrap();
    case.validate_report_bytes(Some(b"public report")).unwrap();
    assert!(case.validate_report_bytes(None).is_err());
    assert!(case.validate_report_bytes(Some(b"changed report")).is_err());
    assert_ne!(case.result_key().unwrap(), digest(0));

    let mut root_child = value.clone();
    root_child["child"]["uid"] = serde_json::json!(0);
    assert!(parse(&root_child).is_err());
    let mut changed_report = value;
    changed_report["attachments"][1]["sha256"] = serde_json::json!(digest(20));
    assert!(parse(&changed_report).is_err());
}

#[test]
fn frontend_loss_can_omit_report_only_with_durable_replacement() {
    let mut value = case();
    value["selector"] = serde_json::json!("private_tcp::frontend_loss_retired");
    value["observation"]["outcome"] = serde_json::json!("frontend-lost");
    value["report"] = serde_json::json!({
        "state": "absent-frontend-loss",
        "authenticated_terminal_sha256": digest(14),
        "supervised_transport_sha256": digest(19),
        "independent_recovery_sha256": digest(20),
    });
    value["attachments"].as_array_mut().unwrap().remove(1);
    let parsed = parse(&value).unwrap();
    parsed.validate_report_bytes(None).unwrap();
    assert!(parsed.validate_report_bytes(Some(b"")).is_err());

    let mut fake_success = value.clone();
    fake_success["selector"] = serde_json::json!("private_tcp::native_tcp_bind_listen_connect");
    fake_success["observation"]["outcome"] = serde_json::json!("target-completed");
    assert!(parse(&fake_success).is_err());
    let mut fake_report = value;
    fake_report["attachments"].as_array_mut().unwrap().insert(
        1,
        serde_json::json!({"role":"report", "size":0, "sha256":hash_bytes(b"")}),
    );
    assert!(parse(&fake_report).is_err());
    let mut false_terminal = case();
    false_terminal["selector"] = serde_json::json!("private_tcp::frontend_loss_retired");
    false_terminal["observation"]["outcome"] = serde_json::json!("frontend-lost");
    false_terminal["report"] = serde_json::json!({
        "state": "absent-frontend-loss",
        "authenticated_terminal_sha256": digest(99),
        "supervised_transport_sha256": digest(19),
        "independent_recovery_sha256": digest(20),
    });
    false_terminal["attachments"]
        .as_array_mut()
        .unwrap()
        .remove(1);
    assert!(parse(&false_terminal).is_err());
}

#[test]
fn public_grant_rejection_requires_positive_control_and_exact_code() {
    let mut value = case();
    value["selector"] = serde_json::json!("private_tcp::wrong_grant_profile_and_port_rejected");
    value["observation"] = serde_json::json!({
        "phase": "preallocation-rejected",
        "rejection_code": "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
        "observer_sha256": digest(9),
    });
    assert!(parse(&value).is_err());
    value["positive_control_terminal_sha256"] = serde_json::json!(digest(21));
    assert!(parse(&value).is_ok());
    value["observation"]["rejection_code"] = serde_json::json!("host-unavailable");
    assert!(parse(&value).is_err());
}

#[test]
fn final_public_decoder_rejects_ambiguous_or_oversized_records() {
    let bytes = serde_json::to_vec(&case()).unwrap();
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"schema_version\":2}");
    assert!(FinalPublicCaseEvidenceV2::parse(&duplicate).is_err());
    let mut unknown = bytes;
    unknown.pop();
    unknown.extend_from_slice(b",\"trusted\":true}");
    assert!(FinalPublicCaseEvidenceV2::parse(&unknown).is_err());
    assert!(
        FinalPublicCaseEvidenceV2::parse(&vec![
            b' ';
            memcordon_core::private_release_case_v1::MAX_PRIVATE_RELEASE_RESULT_BYTES_V1
                + 1
        ])
        .is_err()
    );
}
