//! Structural acquisition association tests, without an installed product claim.
use memcordon_readiness_verifier::validate_acquisition_payload_shape;
use serde_json::json;
#[test]
fn acquisition_shape_rejects_unknown_provider_and_non_native_path_shapes() {
    let artifact = json!({"path":"owned/component.exe","sha256":"11".repeat(32)});
    let payload = json!({"channel":"native-bundle","source_commit":"22".repeat(20),"version":"0.5.8-dev","target":"x86_64-pc-windows-msvc","artifacts":[artifact.clone()],"cli":artifact.clone(),"agent":artifact.clone(),"components":[artifact.clone(),artifact.clone(),artifact.clone(),artifact.clone()],"installed_components":[artifact.clone(),artifact.clone(),artifact.clone(),artifact.clone()],"fixture":artifact.clone(),"installed_agent":artifact.clone(),"installed_manifest":artifact,"provider":{"generation":"owned-vector","source_commit":"22".repeat(20),"runtime_manifest_sha256":"33".repeat(32)},"output_directory":"owned/output"});
    validate_acquisition_payload_shape(&payload).unwrap();
    let mut changed = payload.clone();
    changed["provider"]["qualification_authority"] = true.into();
    assert!(validate_acquisition_payload_shape(&changed).is_err());
    let mut changed = payload.clone();
    changed["components"][0]["path"] = serde_json::Value::Null;
    assert!(validate_acquisition_payload_shape(&changed).is_err());
    let mut changed = payload.clone();
    changed["installed_components"][0]["path"] = 123.into();
    assert!(validate_acquisition_payload_shape(&changed).is_err());
    let mut changed = payload.clone();
    changed["artifacts"] = json!({"self_reported":"measured"});
    assert!(validate_acquisition_payload_shape(&changed).is_err());
    let mut changed = payload.clone();
    changed["artifacts"][0]["sha256"] = "claimed".into();
    assert!(validate_acquisition_payload_shape(&changed).is_err());
}
