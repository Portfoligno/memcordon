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
#[test]
fn candidate_response_codec_requires_independent_dynamic_operands() {
    use memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1 as response;
    let challenge = [7; 32];
    assert!(
        response(
            "x86_64-unknown-linux-gnu",
            "private_tcp::private_namespace_topology_exact",
            &challenge,
            None,
            None
        )
        .is_err()
    );
    let topology = response(
        "x86_64-unknown-linux-gnu",
        "private_tcp::private_namespace_topology_exact",
        &challenge,
        Some(8765),
        None,
    )
    .unwrap();
    assert_eq!(
        &topology[topology.len() - std::mem::size_of::<u64>()..],
        &8765_u64.to_le_bytes()
    );
    assert!(
        response(
            "x86_64-unknown-linux-gnu",
            "private_tcp::target_exec_and_fd_leak_observed",
            &challenge,
            None,
            None
        )
        .is_err()
    );
    let image = response(
        "x86_64-unknown-linux-gnu",
        "private_tcp::target_exec_and_fd_leak_observed",
        &challenge,
        None,
        Some((19, 23)),
    )
    .unwrap();
    let mut suffix = 19_u64.to_le_bytes().to_vec();
    suffix.extend_from_slice(&23_u64.to_le_bytes());
    suffix.extend_from_slice(&[3, 1, 1, 1]);
    assert!(image.ends_with(&suffix));
    assert!(
        response(
            "x86_64-unknown-linux-gnu",
            "private_tcp::authorization_uncertainty_retired",
            &challenge,
            None,
            None
        )
        .is_err()
    );
    assert!(
        response(
            "x86_64-unknown-linux-gnu",
            "private_tcp::native_tcp_bind_listen_connect",
            &[0; 32],
            None,
            None
        )
        .is_err()
    );
}

#[test]
fn candidate_response_codec_retains_exact_native_suffixes_and_abi() {
    use memcordon_core::private_release_case_v1::candidate_fixture_expected_response_v1 as response;
    let challenge = [11; 32];
    let x64 = response(
        "x86_64-unknown-linux-gnu",
        "private_tcp::native_filter_digest_and_abi_bound",
        &challenge,
        None,
        None,
    )
    .unwrap();
    let arm = response(
        "aarch64-unknown-linux-gnu",
        "private_tcp::native_filter_digest_and_abi_bound",
        &challenge,
        None,
        None,
    )
    .unwrap();
    assert!(x64.ends_with(&[2, 1]));
    assert!(arm.ends_with(&[2, 2]));
    let denied = response(
        "aarch64-unknown-linux-gnu",
        "private_tcp::af_unix_socketpair_denied",
        &challenge,
        None,
        None,
    )
    .unwrap();
    let mut suffix = 97_i32.to_le_bytes().to_vec();
    suffix.extend_from_slice(&1_i32.to_le_bytes());
    assert!(denied.ends_with(&suffix));
    let other = response(
        "aarch64-unknown-linux-gnu",
        "private_tcp::af_unix_socketpair_denied",
        &[12; 32],
        None,
        None,
    )
    .unwrap();
    assert_ne!(denied, other);
}
#[test]
fn candidate_prepared_port_matches_reviewed_challenge_domain() {
    use sha2::{Digest, Sha256};
    for seed in 0..=u8::MAX {
        let challenge = [seed; 32];
        let mut hash = Sha256::new();
        hash.update(b"memcordon-private-release-dual-port-v1\0");
        hash.update(challenge);
        let digest = hash.finalize();
        let expected = 20_000 + u16::from_le_bytes([digest[0], digest[1]]) % 30_000;
        let actual = memcordon_core::private_release_case_v1::candidate_fixture_port_v1(&challenge);
        assert_eq!(actual, expected);
        assert!((20_000..50_000).contains(&actual));
    }
}

#[test]
fn candidate_dual_codec_requires_independent_namespace_and_retains_real_frame() {
    use memcordon_core::private_release_case_v1::{
        candidate_fixture_expected_response_v1 as response, candidate_fixture_port_v1,
    };
    use sha2::{Digest, Sha256};
    let challenge = [17; 32];
    let selector = "private_tcp::dual_attempt_namespace_isolation";
    assert!(response("x86_64-unknown-linux-gnu", selector, &challenge, None, None).is_err());
    assert!(
        response(
            "x86_64-unknown-linux-gnu",
            selector,
            &challenge,
            Some(0),
            None
        )
        .is_err()
    );
    let actual = response(
        "x86_64-unknown-linux-gnu",
        selector,
        &challenge,
        Some(907),
        None,
    )
    .unwrap();
    let mut hash = Sha256::new();
    hash.update(b"memcordon-private-release-dual-ready-v1\0");
    hash.update(challenge);
    let mut expected = hash.finalize().to_vec();
    expected.extend_from_slice(&candidate_fixture_port_v1(&challenge).to_le_bytes());
    expected.extend_from_slice(&907u64.to_le_bytes());
    assert_eq!(actual, expected);
    assert_ne!(
        actual,
        response(
            "aarch64-unknown-linux-gnu",
            selector,
            &challenge,
            Some(908),
            None
        )
        .unwrap()
    );
}
