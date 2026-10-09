//! Full generic original admission graph, retained separately from refusal.
use super::{
    linux_image_entrypoint_case as image, linux_installed_case as installed,
    persisted_case::PersistedCase,
};
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn baseline() -> PersistedCase {
    let requirements = json!([{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}}]);
    let mut case = image::baseline_with_requirements(requirements);
    case.record.key.family = "C-ADMISSION".into();
    case.record.key.scenario = "positive".into();
    case.index.fixture_cases = vec![case.record.key.clone()];
    let key = json!(case.record.key);
    case.mutate("input.json", |input| input["key"] = key.clone());
    let native: NativeObservation =
        serde_json::from_value(installed::read(&case, "native.json")).unwrap();
    let semantic = SemanticObservation {
        format: "memcordon.consumer-readiness.semantic".into(),
        revision: 1,
        run_id: case.record.run_id.clone(),
        key: case.record.key.clone(),
        challenge: "challenge.bin".into(),
        operations: vec![OperationObservation {
            operation: "admission-granted".into(),
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-admission".into(),
            native_receipt: "result.json".into(),
        }],
        comparisons: vec![],
        counters: Default::default(),
        negative_probe: None,
        component_test: None,
        component_actors: None,
        windows_capacity: None,
        windows_refusal: None,
        fixture_behavior: None,
    };
    case.json("semantic.json", &json!(semantic));
    let mut evidence: CaseEvidence =
        serde_json::from_value(installed::read(&case, "case-evidence.json")).unwrap();
    evidence.key = case.record.key.clone();
    evidence.input_sha256 = case
        .index
        .artifacts
        .iter()
        .find(|a| a.path == "input.json")
        .unwrap()
        .sha256
        .clone();
    case.json("case-evidence.json", &json!(evidence));
    case
}

pub fn read(case: &PersistedCase, path: &str) -> Value {
    installed::read(case, path)
}

/// Retain the original positive files before creating another full attempt.
/// Only artifact references move; native operands and semantic digests stay fixed.
pub fn freeze(case: &mut PersistedCase) -> CaseRecord {
    let original = case.index.artifacts.clone();
    let paths = original
        .iter()
        .filter(|artifact| !artifact.path.starts_with("installed/"))
        .map(|artifact| artifact.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    fn references(value: &mut Value, paths: &std::collections::BTreeSet<String>) {
        match value {
            Value::String(path) if paths.contains(path) => {
                *path = format!("original-positive/{path}")
            }
            Value::Array(values) => {
                for value in values {
                    references(value, paths)
                }
            }
            Value::Object(fields) => {
                for value in fields.values_mut() {
                    references(value, paths)
                }
            }
            _ => {}
        }
    }
    for artifact in &original {
        if !paths.contains(&artifact.path) {
            continue;
        }
        let bytes = std::fs::read(case.root.path().join(&artifact.path)).unwrap();
        let destination = format!("original-positive/{}", artifact.path);
        if ["case-evidence.json", "invocation.json", "semantic.json"]
            .contains(&artifact.path.as_str())
        {
            let mut value: Value = serde_json::from_slice(&bytes).unwrap();
            references(&mut value, &paths);
            case.json(&destination, &value);
        } else {
            case.write(&destination, &bytes);
        }
    }
    let mut record = case.record.clone();
    record.evidence = Some("original-positive/case-evidence.json".into());
    record
}
