//! Protocol-vector decoder checks, without native execution or resource claims.
use memcordon_readiness_verifier::*;
#[test]
fn independent_v1_v2_anchors_match_actual_codec_and_reject_substitution() {
    let fixed = include_str!(
        "../../../crates/memcordon-core/tests/fixtures/workload_independent/contract.hex"
    );
    let v1 = hex::decode(fixed.split_whitespace().collect::<String>()).unwrap();
    let request = include_bytes!("../../../fuzz/corpus/workload-request/baseline-v2.json");
    let parsed = memcordon_core::workload_contract::WorkloadContractV2::parse(request).unwrap();
    let v2 = memcordon_core::workload_codec::encode_contract_v2(&parsed).unwrap();
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "L-VER-01".into(),
        scenario: "v2-vectors".into(),
    };
    let receipt = LinuxVersionReceipt {
        format: "memcordon.linux-version-component".into(),
        revision: 1,
        run_id: "1".into(),
        recipe_id: "native-linux-x64".into(),
        native_target: key.target.clone(),
        test_name: "native_versions::native_version_vectors_emit_actual_component_receipts".into(),
        executable_sha256: "11".repeat(32),
        challenge_sha256: "22".repeat(32),
        operation: "actual-version-codec-and-projection-vectors".into(),
        fixture_resource_claims: true,
        v1_canonical: "v1.bin".into(),
        v2_request: "v2.json".into(),
        v2_canonical: "v2.bin".into(),
        v3_request: "v3.json".into(),
        v3_canonical: "v3.bin".into(),
        projection: "projection.json".into(),
        projection_refusal: "structural component vector".into(),
        old_parser_refusal: "structural component vector".into(),
    };
    validate_linux_version_vector(&receipt, &key, &v1, request, &v2).unwrap();
    let mut changed = v2.clone();
    *changed.last_mut().unwrap() = 2;
    assert!(validate_linux_version_vector(&receipt, &key, &v1, request, &changed).is_err());
    let mut changed = v1.clone();
    changed[0] ^= 1;
    assert!(validate_linux_version_vector(&receipt, &key, &changed, request, &v2).is_err());
    let mut changed: serde_json::Value = serde_json::from_slice(request).unwrap();
    changed["unknown_authority"] = true.into();
    assert!(
        validate_linux_version_vector(
            &receipt,
            &key,
            &v1,
            &serde_json::to_vec(&changed).unwrap(),
            &v2
        )
        .is_err()
    );
    let mut changed = receipt.clone();
    changed.fixture_resource_claims = false;
    assert!(validate_linux_version_vector(&changed, &key, &v1, request, &v2).is_err());
    let object =
        |name: &str, marker: u8| serde_json::json!({"id":name,"digest":hex::encode([marker;32])});
    let mixed = serde_json::json!({"schema_version":3,"workload_plan_digest":"01".repeat(32),
        "authorized_profile":{"id":"linux-tcp4-unix-private-v1","semantic_digest":"02".repeat(32)},
        "authorization":{"grant_id":"combined-grant","grant_revision":1,"approved_plan_digest":"01".repeat(32)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain",
        "requirements":[{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}},{"kind":"unix_stream_pair","id":"unix"}],
        "execution_identity":{"identity":object("account",3),"exclusive_use_policy":object("exclusive",4)},
        "runtime_image":object("toolchain",5),"input_image":object("fixture",6),"root_layout":object("build-root",7),
        "launch":{"entrypoint":"build-driver","working_directory":"work"},"expected_epoch":{"service_instance":vec![8u8;16],"revision":1}});
    let mixed_bytes = serde_json::to_vec(&mixed).unwrap();
    let actual: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_slice(&mixed_bytes).unwrap();
    actual.validate().unwrap();
    let canonical = actual.canonical_bytes().unwrap();
    assert_eq!(canonical.len(), 463);
    let mut projection = mixed.clone();
    projection["schema_version"] = 2.into();
    let projection_bytes = serde_json::to_vec(&projection).unwrap();
    let mut mixed_receipt = receipt.clone();
    mixed_receipt.old_parser_refusal =
        memcordon_core::workload_contract::WorkloadContractV2::parse(&mixed_bytes).unwrap_err();
    mixed_receipt.projection_refusal =
        memcordon_core::workload_contract::WorkloadContract::parse(&projection_bytes).unwrap_err();
    let mut mixed_key = key.clone();
    mixed_key.scenario = "v3-vectors".into();
    validate_linux_mixed_version_vector(
        &mixed_receipt,
        &mixed_key,
        &v1,
        request,
        &v2,
        &mixed_bytes,
        &canonical,
        &projection_bytes,
    )
    .unwrap();
    let mut changed = projection.clone();
    changed["authorization"]["grant_revision"] = 2.into();
    assert!(
        validate_linux_mixed_version_vector(
            &mixed_receipt,
            &mixed_key,
            &v1,
            request,
            &v2,
            &mixed_bytes,
            &canonical,
            &serde_json::to_vec(&changed).unwrap()
        )
        .is_err()
    );
    let mut changed = canonical.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(
        validate_linux_mixed_version_vector(
            &mixed_receipt,
            &mixed_key,
            &v1,
            request,
            &v2,
            &mixed_bytes,
            &changed,
            &projection_bytes
        )
        .is_err()
    );
}
