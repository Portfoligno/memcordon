use memcordon_ci::private_public_dispatch::{
    ExpectedHistoricalPublicEpochReplayV1, canonical_public_stdio_v1,
    validate_detached_public_provider_sources, validate_historical_public_epoch_replay_v1,
    validate_provider_frame_record_v2,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

fn digest(byte: u8) -> DiagnosticSha256 {
    DiagnosticSha256::from_bytes([byte; 32])
}

#[test]
fn detached_provider_map_restores_protocol_order_without_accepting_extra_roles() {
    let (record, leaves) = fixture(0);
    let mut mapped = leaves
        .into_iter()
        .rev()
        .collect::<std::collections::BTreeMap<_, _>>();
    validate_detached_public_provider_sources(&record, &mapped).unwrap();
    mapped.insert("unreviewed-extra.bin".into(), b"not a frame".to_vec());
    assert!(validate_detached_public_provider_sources(&record, &mapped).is_err());
    mapped.remove("unreviewed-extra.bin");
    mapped.remove("request.bin");
    assert!(validate_detached_public_provider_sources(&record, &mapped).is_err());
}

fn fixture(cap: u8) -> (Vec<u8>, Vec<(String, Vec<u8>)>) {
    let selector = match cap {
        0 => "private_tcp::wrong_grant_profile_and_port_rejected",
        1 => "private_tcp::native_tcp_bind_listen_connect",
        _ => "private_tcp::dual_attempt_namespace_isolation",
    };
    let mut leaves = vec![
        ("plan-request.bin".into(), b"request".to_vec()),
        ("request.bin".into(), b"request".to_vec()),
        (
            "plan-response.bin".into(),
            if cap == 0 {
                b"rejected".to_vec()
            } else {
                b"receipt".to_vec()
            },
        ),
    ];
    let decision = serde_json::json!({
        "schema_version": 1,
        "evidence_scope": "lease-bound-v2-grant-decision",
        "selector": selector,
        "challenge": "11".repeat(32),
        "result_key": digest(1),
        "contract_digest": digest(2),
        "peer_pid": 42,
        "peer_start_time_ticks": 100,
        "peer_uid": 1000,
        "peer_gid": 1000,
        "installation_epoch": digest(3),
        "active_h1_receipt_sha256": digest(6),
        "registry_digest": digest(7),
        "policy_epoch": {"service_instance": vec![1u8; 16], "revision": 1},
        "plan_request_sha256": hash_bytes(&leaves[0].1),
        "plan_response_sha256": hash_bytes(&leaves[2].1),
        "plan_response_kind": if cap == 0 { 106 } else { 111 },
        "outcome": if cap == 0 {
            serde_json::json!({"kind": "rejected", "rejection": {
                "code": "profile-not-authorized", "conflicts": [], "remaining_conflicts": 0
            }})
        } else {
            serde_json::json!({"kind": "granted", "grant": {
                "id": "test-grant", "revision": 1,
                "profile": {"id": "test-profile", "semantic_digest": digest(8)},
                "ceiling": {
                    "direct_socket_authority": "attempt-private-ipv4-stack-all-ports",
                    "unix_authority": "no-named-endpoints-socket-pairs-only",
                    "external_socket_custody": "no-socket-at-target-entry",
                    "credential_gains": "no-gain",
                    "mediated_communication": "require-no-external-communication"
                },
                "enabled": true,
                "callers": [{"platform": "linux", "uid": 1000}],
                "approved_plans": [digest(9)],
                "execution_identity": {"kind": "preserve-caller"}
            }})
        },
    });
    leaves.push((
        "grant-decision.json".into(),
        serde_json::to_vec(&decision).unwrap(),
    ));
    if cap == 0 {
        leaves.push(("terminal.bin".into(), b"rejected".to_vec()));
    }
    let mut attempts = Vec::new();
    for ordinal in 0..cap {
        let attempt_id = format!("{:02x}", ordinal + 0x22).repeat(16);
        let prefix = format!("{ordinal}-{attempt_id}/");
        let request = format!("launch-{ordinal}").into_bytes();
        let response = format!("terminal-{ordinal}").into_bytes();
        leaves.push((format!("{prefix}request.bin"), request.clone()));
        leaves.push((format!("{prefix}response.bin"), response.clone()));
        leaves.push((format!("{prefix}terminal.bin"), response.clone()));
        let cleanup = format!("cleanup-{ordinal}").into_bytes();
        leaves.push((format!("{prefix}cleanup.bin"), cleanup.clone()));
        let target_identity = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "evidence_scope": "durable-live-target-gated",
            "attempt_id": attempt_id,
            "request_sha256": hash_bytes(&request),
            "durable_attempt_record_sha256": digest(20 + ordinal),
            "target": {"pid": 200 + u32::from(ordinal), "start_time": 300 + u64::from(ordinal)},
            "namespace_init": {"pid": 400 + u32::from(ordinal), "start_time": 500 + u64::from(ordinal)},
            "network_namespace_inode": 600 + u64::from(ordinal),
            "entrypoint_sha256": digest(40 + ordinal),
            "entrypoint_device": 700 + u64::from(ordinal),
            "entrypoint_inode": 800 + u64::from(ordinal),
            "entrypoint_path": "/usr/bin/memcordon-test-target",
        })).unwrap();
        leaves.push((
            format!("{prefix}target-identity.json"),
            target_identity.clone(),
        ));
        attempts.push(serde_json::json!({
            "ordinal": ordinal,
            "attempt_id": attempt_id,
            "launch_request_sha256": hash_bytes(&request),
            "launch_response_sha256": hash_bytes(&response),
            "launch_response_kind": 105,
            "terminal_sha256": hash_bytes(&response),
            "cleanup_sha256": hash_bytes(&cleanup),
            "target_identity_sha256": hash_bytes(&target_identity),
            "phase": "terminal-observed",
        }));
    }
    let value = serde_json::json!({
        "schema_version": 2,
        "evidence_scope": "provider-frames-only",
        "selector": selector,
        "challenge": "11".repeat(32),
        "result_key": digest(1),
        "contract_digest": digest(2),
        "peer_pid": 42,
        "peer_start_time_ticks": 100,
        "peer_uid": 1000,
        "peer_gid": 1000,
        "installation_epoch": digest(3),
        "manifest_sha256": digest(4),
        "qualification_sha256": digest(5),
        "active_h1_receipt_sha256": digest(6),
        "plan_request_sha256": hash_bytes(&leaves[0].1),
        "plan_response_sha256": hash_bytes(&leaves[2].1),
        "grant_decision_sha256": hash_bytes(&leaves[3].1),
        "plan_response_kind": if cap == 0 { 106 } else { 111 },
        "expected_launch_exchanges": cap,
        "attempts": attempts,
        "inflight": null,
        "terminal_sha256": if cap == 0 { Some(hash_bytes(&leaves[4].1)) } else { None },
        "phase": if cap == 0 { "plan-rejected" } else { "launch-exchanges-complete" },
    });
    (serde_json::to_vec(&value).unwrap(), leaves)
}

fn verify(bytes: &[u8], leaves: &[(String, Vec<u8>)], cap: u8) -> memcordon_ci::Result<()> {
    let borrowed: Vec<_> = leaves
        .iter()
        .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
        .collect();
    validate_provider_frame_record_v2(
        bytes,
        &borrowed,
        match cap {
            0 => "private_tcp::wrong_grant_profile_and_port_rejected",
            1 => "private_tcp::native_tcp_bind_listen_connect",
            _ => "private_tcp::dual_attempt_namespace_isolation",
        },
        &"11".repeat(32),
        &digest(1),
        &digest(2),
        (42, 100, 1000, 1000),
        (&digest(3), &digest(4), &digest(5), &digest(6)),
    )
}

#[test]
fn recovered_reuse_provider_requires_exact_first_cleanup_and_blocked_second() {
    let (record_bytes, mut original) = fixture(2);
    let mut record: serde_json::Value = serde_json::from_slice(&record_bytes).unwrap();
    let selector = "private_tcp::retirement_failure_blocks_reuse";
    record["selector"] = serde_json::json!(selector);
    let mut decision: serde_json::Value = serde_json::from_slice(&original[3].1).unwrap();
    decision["selector"] = serde_json::json!(selector);
    original[3].1 = serde_json::to_vec(&decision).unwrap();
    record["grant_decision_sha256"] = serde_json::json!(hash_bytes(&original[3].1));
    let attempts = record["attempts"].as_array_mut().unwrap();
    let first_id = attempts[0]["attempt_id"].as_str().unwrap().to_owned();
    let first_response = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "code": "MCSEALED-PRIVATE-REUSE-CLEANUP-INCOMPLETE",
        "phase": "retirement", "detail": "held namespace", "os_code": null,
        "target_created": true, "target_released": true,
        "cleanup": {"attempted": true, "direct_child_reaped": false,
            "workload_empty": null, "helpers_reaped": false,
            "containment_removed": false, "sealed_boundary_retired": false,
            "errors": ["namespace fd held"]}
    }))
    .unwrap();
    let cleanup = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "result_key": digest(1),
        "first_attempt_id": first_id, "namespace_inode": 71,
        "holder_closed_boot_nanos": 100, "recovery_boot_nanos": 200,
        "durable_attempt_record_absent": true
    }))
    .unwrap();
    attempts[0]["launch_response_sha256"] = serde_json::json!(hash_bytes(&first_response));
    attempts[0]["launch_response_kind"] = serde_json::json!(106);
    attempts[0]["terminal_sha256"] = serde_json::Value::Null;
    attempts[0]["cleanup_sha256"] = serde_json::json!(hash_bytes(&cleanup));
    attempts[0]["phase"] = serde_json::json!("recovered-after-incomplete");
    let second_response = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1, "code": "MCSEALED-PRIVATE-REUSE-BLOCKED",
        "phase": "request-validation", "detail": "incomplete predecessor", "os_code": null,
        "target_created": false, "target_released": false,
        "cleanup": {"attempted": false, "direct_child_reaped": false,
            "workload_empty": null, "helpers_reaped": false,
            "containment_removed": false, "sealed_boundary_retired": false,
            "errors": []}
    }))
    .unwrap();
    attempts[1]["launch_response_sha256"] = serde_json::json!(hash_bytes(&second_response));
    attempts[1]["launch_response_kind"] = serde_json::json!(106);
    attempts[1]["terminal_sha256"] = serde_json::Value::Null;
    attempts[1]["cleanup_sha256"] = serde_json::Value::Null;
    attempts[1]["target_identity_sha256"] = serde_json::Value::Null;
    attempts[1]["phase"] = serde_json::json!("reuse-blocked-observed");
    let mut leaves = original[..4].to_vec();
    leaves.push(original[4].clone());
    leaves.push((original[5].0.clone(), first_response));
    leaves.push((original[7].0.clone(), cleanup));
    leaves.push(original[8].clone());
    leaves.push(original[9].clone());
    leaves.push((original[10].0.clone(), second_response));
    let bytes = serde_json::to_vec(&record).unwrap();
    let borrowed: Vec<_> = leaves
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    let expected = (&digest(3), &digest(4), &digest(5), &digest(6));
    validate_provider_frame_record_v2(
        &bytes,
        &borrowed,
        selector,
        &"11".repeat(32),
        &digest(1),
        &digest(2),
        (42, 100, 1000, 1000),
        expected,
    )
    .unwrap();
    let mut bad = record.clone();
    bad["attempts"][0]["phase"] = serde_json::json!("terminal-observed");
    assert!(
        validate_provider_frame_record_v2(
            &serde_json::to_vec(&bad).unwrap(),
            &borrowed,
            selector,
            &"11".repeat(32),
            &digest(1),
            &digest(2),
            (42, 100, 1000, 1000),
            expected
        )
        .is_err()
    );
    let mut missing_cleanup = leaves.clone();
    missing_cleanup.remove(6);
    let missing: Vec<_> = missing_cleanup
        .iter()
        .map(|(path, bytes)| (path.as_str(), bytes.as_slice()))
        .collect();
    assert!(
        validate_provider_frame_record_v2(
            &bytes,
            &missing,
            selector,
            &"11".repeat(32),
            &digest(1),
            &digest(2),
            (42, 100, 1000, 1000),
            expected
        )
        .is_err()
    );
}

#[test]
fn provider_only_transcript_accepts_exact_frames_and_rejects_tamper() {
    for cap in [0, 1, 2] {
        let (bytes, leaves) = fixture(cap);
        verify(&bytes, &leaves, cap).unwrap();
        let mut changed = leaves.clone();
        changed[0].1 = b"altered".to_vec();
        assert!(verify(&bytes, &changed, cap).is_err());
        let mut changed = leaves.clone();
        changed[3].1.push(b' ');
        assert!(verify(&bytes, &changed, cap).is_err());
        let mut changed = leaves.clone();
        let mut decision: serde_json::Value = serde_json::from_slice(&changed[3].1).unwrap();
        decision["peer_uid"] = serde_json::json!(1001);
        changed[3].1 = serde_json::to_vec(&decision).unwrap();
        let mut changed_record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed_record["grant_decision_sha256"] = serde_json::json!(hash_bytes(&changed[3].1));
        assert!(verify(&serde_json::to_vec(&changed_record).unwrap(), &changed, cap).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        value["peer_start_time_ticks"] = serde_json::json!(101);
        assert!(verify(&serde_json::to_vec(&value).unwrap(), &leaves, cap).is_err());
        value["peer_start_time_ticks"] = serde_json::json!(100);
        value["evidence_scope"] = serde_json::json!("full-case");
        assert!(verify(&serde_json::to_vec(&value).unwrap(), &leaves, cap).is_err());
    }
}

#[test]
fn provider_transcript_rejects_missing_and_extra_leaves() {
    let (bytes, leaves) = fixture(2);
    assert!(verify(&bytes, &leaves[..3], 2).is_err());
    let mut extra = leaves.clone();
    extra.push(("report.bin".into(), b"self-claimed".to_vec()));
    assert!(verify(&bytes, &extra, 2).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["attempts"][1]["attempt_id"] = value["attempts"][0]["attempt_id"].clone();
    assert!(verify(&serde_json::to_vec(&value).unwrap(), &leaves, 2).is_err());
    let mut pending: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    pending["inflight"] = serde_json::json!({"ordinal": 1});
    assert!(verify(&serde_json::to_vec(&pending).unwrap(), &leaves, 2).is_err());
    let mut changed = leaves.clone();
    let identity = changed
        .iter_mut()
        .find(|(name, _)| name.ends_with("target-identity.json"))
        .unwrap();
    let mut target: serde_json::Value = serde_json::from_slice(&identity.1).unwrap();
    target["request_sha256"] = serde_json::json!(digest(77));
    identity.1 = serde_json::to_vec(&target).unwrap();
    assert!(verify(&bytes, &changed, 2).is_err());
}

#[test]
fn policy_branch_denials_require_exact_typed_codes() {
    for (branch, code) in [
        ("wrong-grant", "profile-not-authorized"),
        ("wrong-profile", "profile-digest-mismatch"),
        ("unapproved-changed-port-plan", "plan-not-approved"),
    ] {
        let (bytes, mut leaves) = fixture(0);
        let mut record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        record["policy_branch"] = serde_json::json!(branch);
        record["policy_base_challenge_sha256"] = serde_json::json!(digest(90));
        let mut decision: serde_json::Value = serde_json::from_slice(&leaves[3].1).unwrap();
        decision["outcome"]["rejection"]["code"] = serde_json::json!(code);
        leaves[3].1 = serde_json::to_vec(&decision).unwrap();
        record["grant_decision_sha256"] = serde_json::json!(hash_bytes(&leaves[3].1));
        let valid = serde_json::to_vec(&record).unwrap();
        verify(&valid, &leaves, 0).unwrap();

        decision["outcome"]["rejection"]["code"] = serde_json::json!("policy-drift");
        leaves[3].1 = serde_json::to_vec(&decision).unwrap();
        record["grant_decision_sha256"] = serde_json::json!(hash_bytes(&leaves[3].1));
        assert!(verify(&serde_json::to_vec(&record).unwrap(), &leaves, 0).is_err());
    }
}

#[test]
fn public_stdio_framing_is_binary_unambiguous_and_bounded() {
    let first = canonical_public_stdio_v1(42, 100, 0, b"a\0b", b"c").unwrap();
    let second = canonical_public_stdio_v1(42, 100, 0, b"a", b"\0bc").unwrap();
    assert_ne!(first, second);
    assert!(canonical_public_stdio_v1(0, 100, 0, b"", b"").is_err());
    assert!(canonical_public_stdio_v1(42, 0, 0, b"", b"").is_err());
    assert!(canonical_public_stdio_v1(42, 100, 0, &vec![0; 1024 * 1024 + 1], b"").is_err());
}

#[test]
fn historical_replay_joins_exact_rejection_and_two_epochs() {
    let rejection = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "code": "MCSEALED-PRIVATE-EXPECTED-PLAN",
        "phase": "request-validation",
        "detail": "stale generation",
        "os_code": null,
        "target_created": false,
        "target_released": false,
        "cleanup": {
            "attempted": false,
            "direct_child_reaped": false,
            "workload_empty": null,
            "helpers_reaped": false,
            "containment_removed": false,
            "sealed_boundary_retired": false,
            "errors": []
        }
    }))
    .unwrap();
    let original = b"E0 exact launch request";
    let record = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "selector": "private_tcp::caller_identity_and_epoch_bound",
        "result_key": digest(1),
        "original_request_sha256": hash_bytes(original),
        "e0_installation_epoch_sha256": digest(2),
        "e0_h1_receipt_sha256": digest(3),
        "e1_installation_epoch_sha256": digest(4),
        "e1_h1_receipt_sha256": digest(5),
        "rejection_sha256": hash_bytes(&rejection),
        "rejection_code": "MCSEALED-PRIVATE-EXPECTED-PLAN",
        "durable_attempt_record_absent": true
    }))
    .unwrap();
    let expected = ExpectedHistoricalPublicEpochReplayV1 {
        selector: "private_tcp::caller_identity_and_epoch_bound",
        result_key: &digest(1),
        original_request_bytes: original,
        e0_installation_epoch_sha256: &digest(2),
        e0_h1_receipt_sha256: &digest(3),
        e1_installation_epoch_sha256: &digest(4),
        e1_h1_receipt_sha256: &digest(5),
    };
    validate_historical_public_epoch_replay_v1(&record, &rejection, &expected).unwrap();
    let mut changed = rejection.clone();
    changed.push(b' ');
    assert!(validate_historical_public_epoch_replay_v1(&record, &changed, &expected).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&record).unwrap();
    value["e1_installation_epoch_sha256"] = value["e0_installation_epoch_sha256"].clone();
    assert!(
        validate_historical_public_epoch_replay_v1(
            &serde_json::to_vec(&value).unwrap(),
            &rejection,
            &expected
        )
        .is_err()
    );
}
