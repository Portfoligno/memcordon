#[path = "../../../crates/memcordon-core/tests/support/windows_current_frontend_guardian.rs"]
mod support;
use memcordon_ci::windows_component_diagnostics::{
    ALLOWED_RECORDS, INPUT_BYTES, PROJECTION_BYTES, project,
};
use memcordon_core::*;
use serde_json::json;
use sha2::{Digest, Sha256};

#[test]
fn same_evaluation_false_null_and_missing_remain_distinct_without_private_values() {
    let secret = "not-for-artifact-nonce-or-challenge";
    let input = json!({"revision":1,"selected_fault":WindowsSealedFault::ControlServiceKilledAfterAuthorization,
        "attempt_id":"ab".repeat(32),"request_sha256":"cd".repeat(32),"final_rejected":false,
        "nonce":secret,"challenge":secret,"unknown_private":secret,
        "loss":{"state":"assessed","process_retired":true,"frontend_retired":false,"process_status":3221225786u32,"thread_status":null,"loss_observation_present":null,"query_phase":"thread-status","query_failed":false,"private":secret},
        "recovery":{"state":"command-returned","command_attempted":true,"command_success":true,"native_status":0,"response_variant":"reject","delivery_present":true,"delivery_parsed":false,"delivery_parse_error":"Data","receipt_present":true,"selected_control_guardian_original":false,"private":secret}});
    let bytes = serde_json::to_vec(&input).unwrap();
    let result = project("control-service-assessment.json", &bytes).unwrap();
    assert_eq!(result["source_sha256"], hex::encode(Sha256::digest(&bytes)));
    assert_eq!(result["source_bytes"], bytes.len());
    let fields = &result["fields"];
    assert_eq!(fields["/final_rejected"]["value"], false);
    assert_eq!(
        fields["/loss/thread_status"]["value"],
        serde_json::Value::Null
    );
    assert_eq!(fields["/loss/frontend_status"]["state"], "missing");
    assert_eq!(
        fields["/loss/loss_observation_present"]["value"],
        serde_json::Value::Null
    );
    assert_eq!(fields["/loss/query_phase"]["value"], "thread-status");
    assert_eq!(fields["/loss/query_failed"]["value"], false);
    assert_eq!(fields["/recovery/delivery_parse_error"]["value"], "Data");
    assert_eq!(result["acceptance_authority"], false);
    assert_eq!(result["receipt_authority"], false);
    assert!(!serde_json::to_string(&result).unwrap().contains(secret));
    assert!(serde_json::to_vec(&result).unwrap().len() <= PROJECTION_BYTES);
}

#[test]
fn actual_public_response_preserves_causal_facts_but_cannot_be_a_receipt() {
    let (rejection, live, _, _) = support::fixture();
    let terminal = rejection.terminal_receipt().unwrap();
    let nonce = terminal.nonce.clone();
    let response = WindowsProviderResponseV4::Reject {
        schema_version: WINDOWS_CURRENT_PUBLIC_PROTOCOL_VERSION,
        attempt_id: terminal.attempt_id.clone(),
        nonce: nonce.clone(),
        request_sha256: terminal.request_sha256.clone(),
        rejection,
    };
    let value = json!({"schema_version":2,"provider_response":response,"frontend_delivery":{"attempt_id":"ab".repeat(32),"nonce":nonce,"request_sha256":"cd".repeat(32),"terminal_validated":true,"acknowledgement_observed":false}});
    let projected = project(
        "terminal-recovery.json",
        &serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
    let fields = &projected["fields"];
    assert_eq!(fields["/provider_response/kind"]["value"], "reject");
    assert_eq!(fields["terminal_receipt_present"], true);
    assert_eq!(
        fields["terminal_receipt"]["/payload/outcome/outcome"]["value"],
        "monitor-failed"
    );
    assert_eq!(
        fields["provider_failure"]["original"],
        value["provider_response"]["rejection"]["provider_failure"]["original"]
    );
    assert_eq!(
        fields["provider_failure"]["secondary"],
        value["provider_response"]["rejection"]["provider_failure"]["secondary"]
    );
    assert_eq!(
        fields["guardian_receipt"]["/guardian_identity"]["value"],
        serde_json::to_value(&live.guardian_identity).unwrap()
    );
    assert!(!serde_json::to_string(&projected).unwrap().contains(&nonce));
    assert!(serde_json::from_value::<WindowsProviderResponseV4>(projected.clone()).is_err());
    assert!(serde_json::to_vec(&projected).unwrap().len() <= PROJECTION_BYTES);
    let held = project(
        "held-before-fault.json",
        &serde_json::to_vec(&live).unwrap(),
    )
    .unwrap();
    assert_eq!(
        held["omitted_private_field_references"]["/live_nonce"]["serialized_value_sha256"],
        projected["omitted_private_field_references"]["/provider_response/nonce"]["serialized_value_sha256"]
    );
}

#[test]
fn closed_filename_and_value_shapes_refuse_private_or_ambiguous_inputs() {
    for name in [
        "../actor-exit.json",
        "actor-invocation.json",
        "challenge.bin",
        "provider-request.bin",
        "stdout.bin",
    ] {
        assert!(project(name, b"{}").is_err());
    }
    assert!(
        project(
            "actor-exit.json",
            br#"{"native_status":1,"native_status":0}"#
        )
        .is_err()
    );
    assert!(project("actor-exit.json", &[255, 254]).is_err());
    assert!(project("actor-exit.json", &vec![0; INPUT_BYTES + 1]).is_err());
    let secret = "credential-with-unicode-🦀";
    let projected=project("control-service-assessment.json",&serde_json::to_vec(&json!({"loss":{"state":secret},"recovery":{"delivery_parse_error":secret},"attempt_id":secret})).unwrap()).unwrap();
    assert_eq!(
        projected["fields"]["/loss/state"]["state"],
        "not-public-shape"
    );
    assert!(!serde_json::to_string(&projected).unwrap().contains(secret));
    let opaque = project("terminal-recovery.stderr.bin", secret.as_bytes()).unwrap();
    assert_eq!(opaque["content_state"], "opaque-content-not-exported");
    assert!(!serde_json::to_string(&opaque).unwrap().contains(secret));
}

#[test]
fn bounded_source_projection_never_exports_unknown_trees_or_invents_missing_observations() {
    let input = json!({"revision":1,"native_status":0,"capture_complete":true,"unexpected_private_tree":{"payload":"x".repeat(1024*1024)}});
    let projected = project("actor-exit.json", &serde_json::to_vec(&input).unwrap()).unwrap();
    assert_eq!(projected["fields"]["/native_status"]["value"], 0);
    assert_eq!(
        projected["fields"]["/retirement_observed"]["state"],
        "missing"
    );
    assert!(serde_json::to_vec(&projected).unwrap().len() < 8192);
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("unexpected_private_tree")
    );
    for name in ALLOWED_RECORDS {
        let raw = if name.ends_with(".json") {
            b"{}".as_slice()
        } else {
            b"private bytes".as_slice()
        };
        let value = project(name, raw).unwrap();
        assert_eq!(value["acceptance_authority"], false);
        assert!(serde_json::to_vec(&value).unwrap().len() <= PROJECTION_BYTES);
    }
}
