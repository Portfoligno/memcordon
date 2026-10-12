#[path = "support/original_fixture_recovery_case.rs"]
mod fixture_case;
use fixture_case::fixture;
use memcordon_readiness_verifier::{
    original_fixture_recovery_contract as contract, validate_embedded_original_fixture_recovery,
};
use serde_json::{Value, json};
#[test]
fn original_fixture_binds_actual_process_result_and_compiler() {
    let (invocation, process, capture, compiler) = fixture();
    validate_embedded_original_fixture_recovery(&invocation, &process, &capture, &compiler)
        .unwrap();
    for field in ["pidfd_retirement_observed", "status", "native_wait_status"] {
        let mut changed = process.clone();
        changed[field] = json!(false);
        assert!(
            validate_embedded_original_fixture_recovery(&invocation, &changed, &capture, &compiler)
                .is_err(),
            "{field}"
        );
    }
    let mut replaced = compiler.clone();
    replaced.insert("acquisition-2.bin".into(), b"replacement compiler".to_vec());
    assert!(
        validate_embedded_original_fixture_recovery(&invocation, &process, &capture, &replaced)
            .is_err()
    );
    let mut changed = capture.clone();
    changed["stdout"] = json!([65]);
    assert!(
        validate_embedded_original_fixture_recovery(&invocation, &process, &changed, &compiler)
            .is_err()
    );
    let mut changed = invocation.clone();
    changed["program"] = json!("/usr/libexec/memcordon-sealed-agent");
    assert!(
        validate_embedded_original_fixture_recovery(&changed, &process, &capture, &compiler)
            .is_err()
    );
    for field in [
        "outstanding",
        "within_original_cleanup",
        "scope_id",
        "completed_unix_millis",
    ] {
        let mut changed = invocation.clone();
        let raw: Vec<u8> =
            serde_json::from_value(changed["original_fixture"]["result_bytes"].clone()).unwrap();
        let mut result: Value = serde_json::from_slice(&raw).unwrap();
        result[field] = match field {
            "outstanding" => json!(["actual unresolved obligation"]),
            "within_original_cleanup" => json!(false),
            "scope_id" => json!("another lease"),
            _ => json!(200),
        };
        changed["original_fixture"]["result_bytes"] = json!(serde_json::to_vec(&result).unwrap());
        assert!(
            validate_embedded_original_fixture_recovery(&changed, &process, &capture, &compiler)
                .is_err(),
            "{field}"
        );
    }
}

#[test]
fn recovery_input_refuses_duplicates_unknown_fields_and_linux_traversal() {
    let (invocation, _, _, _) = fixture();
    let bytes: Vec<u8> =
        serde_json::from_value(invocation["original_fixture"]["input_bytes"].clone()).unwrap();
    let input = contract::Input::decode(&bytes).unwrap();
    for path in [
        "/var/lib/../other",
        "/var/./lib/case",
        "/var//lib/case",
        "C:\\case",
    ] {
        let mut changed = input.clone();
        changed.artifact_root = path.into();
        assert!(changed.validate(&changed.artifact_root, 150).is_err());
    }
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    value["runtime_authority_switch"] = json!(true);
    assert!(contract::Input::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(contract::Input::decode(br#"{"format":"one","format":"two"}"#).is_err());
    assert!(contract::Input::decode(&vec![b' '; contract::INPUT_BOUND + 1]).is_err());
}
