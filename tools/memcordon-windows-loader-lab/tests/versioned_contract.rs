use memcordon_windows_launch_core::{
    CleanupOutcomeV1, HandshakeOutcomeV1, PRODUCTION_LOADER_READY_SCHEMA_VERSION,
};
use memcordon_windows_loader_lab::scenario::{
    DiagnosticObserverV1, DiagnosticTokenVariantV1, HarnessStatusV1, LoaderLabRunV1,
    LoaderLabStageV1,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

fn vectors() -> Value {
    let value: Value = serde_json::from_str(include_str!(
        "../../../spec/vectors/windows-loader-lab-v1.json"
    ))
    .unwrap();
    assert_eq!(value["vector_version"], 1);
    value
}

fn run() -> LoaderLabRunV1 {
    serde_json::from_value(vectors()["run"].clone()).unwrap()
}

fn variants<T: DeserializeOwned + Serialize>(name: &str) {
    for value in vectors()[name].as_array().unwrap() {
        let decoded: T = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(decoded).unwrap(), *value);
    }
    assert!(serde_json::from_value::<T>(json!("unknown-authority")).is_err());
}

#[test]
fn diagnostic_scenario_labels_preserve_version_one_wire_names() {
    variants::<LoaderLabStageV1>("stages");
    variants::<HarnessStatusV1>("harness_statuses");
    variants::<DiagnosticTokenVariantV1>("token_variants");
    variants::<DiagnosticObserverV1>("observers");
}

#[test]
fn reviewed_run_preserves_shared_production_evidence_contracts() {
    let run = run();
    run.validate().unwrap();
    assert_eq!(serde_json::to_value(&run).unwrap(), vectors()["run"]);
    assert_eq!(
        run.scenarios[0].handshake,
        HandshakeOutcomeV1::Authenticated {
            protocol_version: PRODUCTION_LOADER_READY_SCHEMA_VERSION
        }
    );
    assert_eq!(run.scenarios[0].cleanup, CleanupOutcomeV1::complete());
    assert_eq!(run.scenarios[0].attachments, run.artifacts);
}

#[test]
fn reviewed_run_rejects_unknown_fields_and_authority_drift() {
    for pointer in ["", "/os", "/scenarios/0", "/scenarios/0/process_create"] {
        let mut altered = vectors()["run"].clone();
        altered.pointer_mut(pointer).unwrap()["unknown-authority"] = json!(true);
        assert!(
            serde_json::from_value::<LoaderLabRunV1>(altered).is_err(),
            "{pointer}"
        );
    }
    for (pointer, value) in [
        ("/schema_version", json!(2)),
        ("/harness_status", json!("cleanup-failed")),
        ("/scenarios/0/perturbed", json!(true)),
        ("/scenarios/0/production_equivalent", json!(false)),
        ("/scenarios/0/attachments", json!([])),
        ("/artifacts", json!([])),
        ("/package_sha256", json!("unknown")),
    ] {
        let mut altered = vectors()["run"].clone();
        *altered.pointer_mut(pointer).unwrap() = value;
        let decoded: LoaderLabRunV1 = serde_json::from_value(altered).unwrap();
        assert!(decoded.validate().is_err(), "{pointer}");
    }
}

#[test]
fn failed_target_is_diagnostic_but_failed_cleanup_invalidates_harness() {
    let mut run = run();
    run.scenarios[0].handshake = HandshakeOutcomeV1::Failed {
        stable_code: "reviewed-loader-failure".into(),
    };
    run.scenarios[0].target_exit_code = None;
    run.validate().unwrap();
    run.scenarios[0].cleanup = CleanupOutcomeV1::failed("reviewed-cleanup-failure");
    assert!(run.validate().is_err());
}
