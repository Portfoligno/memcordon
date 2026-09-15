use memcordon_core::runtime_evidence::RuntimeEvidenceV1;
use serde_json::{Value, json};

fn vectors() -> Vec<Value> {
    let document: Value = serde_json::from_str(include_str!(
        "../../../spec/vectors/runtime-evidence-v1.json"
    ))
    .unwrap();
    assert_eq!(document["schema_version"], 1);
    document["cases"].as_array().unwrap().clone()
}

#[test]
fn canonical_runtime_evidence_vectors_preserve_exact_json() {
    for case in vectors() {
        let wire = case["evidence"].as_str().unwrap();
        let evidence: RuntimeEvidenceV1 = serde_json::from_str(wire).unwrap();
        assert!(evidence.is_consistent(), "{}", case["name"]);
        assert_eq!(serde_json::to_string(&evidence).unwrap(), wire);
    }
}

#[test]
fn runtime_evidence_rejects_unknown_fields_at_each_authority_boundary() {
    for case in vectors() {
        let source: Value = serde_json::from_str(case["evidence"].as_str().unwrap()).unwrap();
        for boundary in ["", "/clock", "/release", "/retirement"] {
            let mut altered = source.clone();
            altered.pointer_mut(boundary).unwrap()["unknown-authority"] = json!(true);
            assert!(
                serde_json::from_value::<RuntimeEvidenceV1>(altered).is_err(),
                "{} accepts unknown field at {boundary}",
                case["name"]
            );
        }
        if source["delivery"].is_object() {
            let mut altered = source.clone();
            altered["delivery"]["prepared-by"]["unknown-authority"] = json!(true);
            assert!(serde_json::from_value::<RuntimeEvidenceV1>(altered).is_err());
        }
        if source["retirement"]["owner"].is_object() {
            let mut altered = source;
            altered["retirement"]["owner"]["unknown-authority"] = json!(true);
            assert!(serde_json::from_value::<RuntimeEvidenceV1>(altered).is_err());
        }
    }
}

#[test]
fn delivery_variants_preserve_grammar_without_claiming_persistence() {
    use memcordon_core::runtime_evidence::DeliveryEvidence;
    for wire in [
        "\"not-submitted\"",
        "\"prepared\"",
        "{\"prepared-by\":{\"writer_pid\":456}}",
        "\"unknown\"",
    ] {
        let value: DeliveryEvidence = serde_json::from_str(wire).unwrap();
        assert_eq!(serde_json::to_string(&value).unwrap(), wire);
    }
    for wire in [
        "{\"not-submitted\":{\"unknown-authority\":true}}",
        "{\"prepared\":{\"unknown-authority\":true}}",
        "{\"unknown\":{\"unknown-authority\":true}}",
        "{\"prepared-by\":{\"writer_pid\":456,\"unknown-authority\":true}}",
    ] {
        assert!(
            serde_json::from_str::<DeliveryEvidence>(wire).is_err(),
            "{wire}"
        );
    }
}

#[test]
fn runtime_evidence_vectors_reject_cross_field_contradictions() {
    let cases = vectors();
    let complete: Value = serde_json::from_str(cases[0]["evidence"].as_str().unwrap()).unwrap();
    for (pointer, value) in [
        ("/release/at", json!(80)),
        ("/retirement/at", json!(131)),
        ("/retirement/native_obligations_settled", json!(false)),
        ("/force_expires", json!(131)),
        ("/delivery_expires", json!(129)),
        ("/target_pid", json!(0)),
        ("/release", json!({"state":"unknown"})),
    ] {
        let mut altered = complete.clone();
        *altered.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<RuntimeEvidenceV1>(altered).is_err(),
            "{pointer}"
        );
    }
    let mut pending: Value = serde_json::from_str(cases[2]["evidence"].as_str().unwrap()).unwrap();
    pending["retirement"]["obligations"] = json!(vec![
        "control-transport";
        memcordon_core::runtime_evidence::MAX_RETIREMENT_OBLIGATIONS
            + 1
    ]);
    assert!(serde_json::from_value::<RuntimeEvidenceV1>(pending).is_err());
}
