//! WIN-04: public root exports preserve exact V1 DTO bytes and strict decoding.
use memcordon_windows_launch_core::{
    DesktopBindingV1, ExactHandleListV1, HandleRoleV1, PreparedEnvironmentIdentityV1,
    ProductionLoaderPlanInputV1, ProductionLoaderPlanV1, TargetTokenIdentityV1,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

fn vectors() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../spec/vectors/windows-launch/dto-v1.json"
    ))
    .unwrap();
    assert_eq!(vectors["version"], 1);
    vectors
}

fn vector(name: &str) -> String {
    vectors()[name].as_str().unwrap().to_owned()
}

fn round_trip<T: DeserializeOwned + Serialize>(bytes: &str) {
    let decoded: T = serde_json::from_str(bytes).unwrap();
    assert_eq!(serde_json::to_string(&decoded).unwrap(), bytes);
}

fn strict_object<T: DeserializeOwned>(bytes: &str) {
    let original: Value = serde_json::from_str(bytes).unwrap();
    let mut extra = original.clone();
    extra
        .as_object_mut()
        .unwrap()
        .insert("unreviewed_authority".into(), Value::Bool(true));
    assert!(serde_json::from_value::<T>(extra).is_err());
    for field in original.as_object().unwrap().keys() {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<T>(missing).is_err(),
            "missing {field} was accepted"
        );
        let mut wrong_type = original.clone();
        wrong_type[field] = Value::Bool(true);
        assert!(
            serde_json::from_value::<T>(wrong_type).is_err(),
            "wrong {field} type was accepted"
        );
    }
}

#[test]
fn launch_dto_v1_golden_round_trips_are_exact() {
    round_trip::<PreparedEnvironmentIdentityV1>(&vector("environment"));
    round_trip::<DesktopBindingV1>(&vector("desktop"));
    round_trip::<TargetTokenIdentityV1>(&vector("token"));
    round_trip::<ExactHandleListV1>(&vector("handles"));
    let roles = [
        HandleRoleV1::StandardInput,
        HandleRoleV1::StandardOutput,
        HandleRoleV1::StandardError,
        HandleRoleV1::LoaderReady,
    ];
    assert_eq!(roles.len(), vectors()["roles"].as_array().unwrap().len());
    for (role, expected) in roles
        .into_iter()
        .zip(vectors()["roles"].as_array().unwrap())
    {
        let expected = expected.as_str().unwrap();
        round_trip::<HandleRoleV1>(expected);
        assert_eq!(serde_json::to_string(&role).unwrap(), expected);
    }
}

#[test]
fn launch_dto_v1_rejects_unknown_missing_and_mistyped_fields() {
    strict_object::<PreparedEnvironmentIdentityV1>(&vector("environment"));
    strict_object::<DesktopBindingV1>(&vector("desktop"));
    strict_object::<TargetTokenIdentityV1>(&vector("token"));
    strict_object::<ExactHandleListV1>(&vector("handles"));
    assert!(serde_json::from_str::<HandleRoleV1>("\"unreviewed-role\"").is_err());
    assert!(
        serde_json::from_str::<ExactHandleListV1>("{\"roles\":[\"unreviewed-role\"]}").is_err()
    );
}

fn input() -> ProductionLoaderPlanInputV1 {
    let environment: PreparedEnvironmentIdentityV1 =
        serde_json::from_str(&vector("environment")).unwrap();
    ProductionLoaderPlanInputV1 {
        executable_path_utf16: "C:\\MemCordon\\bootstrap.exe".encode_utf16().collect(),
        executable_sha256: environment.sha256.clone(),
        command_line_sha256: environment.sha256.clone(),
        current_directory_sha256: environment.sha256.clone(),
        environment,
        desktop: serde_json::from_str(&vector("desktop")).unwrap(),
        process_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        thread_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        job_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        loader_ready_pipe_security_descriptor_sddl: "D:P(A;;GA;;;SY)".into(),
        target_token: serde_json::from_str(&vector("token")).unwrap(),
        inherited_handles: serde_json::from_str(&vector("handles")).unwrap(),
        job_at_creation: true,
    }
}

#[test]
fn decoded_dtos_do_not_bypass_production_plan_admission() {
    assert!(ProductionLoaderPlanV1::new(input()).is_ok());
    let mut malformed = input();
    malformed.environment.encoding = "unreviewed-encoding".into();
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
    let mut malformed = input();
    malformed.environment.sha256.clear();
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
    let mut malformed = input();
    malformed.desktop.exact_name.push('\0');
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
    let mut malformed = input();
    malformed.desktop.security_descriptor_sha256.clear();
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
    let mut malformed = input();
    malformed.target_token.envelope_sha256.clear();
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
    let mut malformed = input();
    malformed.inherited_handles = serde_json::from_str("{\"roles\":[\"loader-ready\"]}").unwrap();
    assert!(ProductionLoaderPlanV1::new(malformed).is_err());
}

#[test]
fn prepared_material_rejects_invalid_encodings_before_native_creation() {
    use memcordon_windows_launch_core::{
        LoaderReadyEndpointV1, PreparedCurrentDirectoryV1, PreparedLoaderCommandV1,
        PreparedLoaderEnvironmentV1,
    };
    let identity: PreparedEnvironmentIdentityV1 =
        serde_json::from_str(&vector("environment")).unwrap();
    let endpoint = LoaderReadyEndpointV1::new(identity.sha256).unwrap();
    let executable: Vec<u16> = "C:\\MemCordon\\bootstrap.exe".encode_utf16().collect();
    let desktop: Vec<u16> = "MemCordon\\Qualification".encode_utf16().collect();
    assert!(PreparedLoaderCommandV1::loader_control(&executable, &endpoint, &desktop).is_ok());
    assert!(PreparedLoaderCommandV1::loader_control(&[], &endpoint, &desktop).is_err());
    assert!(PreparedLoaderCommandV1::loader_control(&executable, &endpoint, &[0]).is_err());
    assert!(PreparedCurrentDirectoryV1::new(Vec::new()).is_err());
    assert!(PreparedCurrentDirectoryV1::new(vec![0]).is_err());
    assert!(PreparedCurrentDirectoryV1::new(desktop).is_ok());
    for malformed in [vec![], vec![0], vec![1, 0]] {
        assert!(PreparedLoaderEnvironmentV1::new(malformed).is_err());
    }
    assert!(PreparedLoaderEnvironmentV1::new(vec![0, 0]).is_ok());
    assert!(LoaderReadyEndpointV1::new(String::new()).is_err());
    assert!(LoaderReadyEndpointV1::new("unreviewed-nonce".into()).is_err());
}

#[test]
fn ready_evidence_round_trip_rejects_unreviewed_version_and_handshake() {
    use memcordon_windows_launch_core::LoaderReadyEvidenceV1;
    let plan = ProductionLoaderPlanV1::new(input()).unwrap();
    let evidence = LoaderReadyEvidenceV1::authenticated(&plan, 7);
    let bytes = serde_json::to_string(&evidence).unwrap();
    round_trip::<LoaderReadyEvidenceV1>(&bytes);
    strict_object::<LoaderReadyEvidenceV1>(&bytes);
    let mut invalid = serde_json::to_value(&evidence).unwrap();
    invalid["schema_version"] = Value::from(u64::MAX);
    assert!(serde_json::from_value::<LoaderReadyEvidenceV1>(invalid).is_err());
    let mut invalid = serde_json::to_value(&evidence).unwrap();
    invalid["handshake"] = Value::String("unauthenticated".into());
    assert!(serde_json::from_value::<LoaderReadyEvidenceV1>(invalid).is_err());
}

#[test]
fn diagnostic_artifact_and_native_call_records_keep_strict_contracts() {
    use memcordon_windows_launch_core::{ArtifactRefV1, NativeCallOutcomeV1, RedactionClassV1};
    let identity: PreparedEnvironmentIdentityV1 =
        serde_json::from_str(&vector("environment")).unwrap();
    let artifact = ArtifactRefV1::new(
        "evidence.json".into(),
        identity.sha256,
        7,
        "application/json".into(),
        RedactionClassV1::RedactedSummary,
    )
    .unwrap();
    let bytes = serde_json::to_string(&artifact).unwrap();
    round_trip::<ArtifactRefV1>(&bytes);
    strict_object::<ArtifactRefV1>(&bytes);
    let mut invalid = serde_json::to_value(&artifact).unwrap();
    invalid["redaction"] = Value::String("unreviewed-redaction".into());
    assert!(serde_json::from_value::<ArtifactRefV1>(invalid).is_err());
    let call = NativeCallOutcomeV1 {
        completed: false,
        status: None,
    };
    let bytes = serde_json::to_string(&call).unwrap();
    round_trip::<NativeCallOutcomeV1>(&bytes);
    let mut invalid = serde_json::to_value(&call).unwrap();
    invalid["unreviewed_authority"] = Value::Bool(true);
    assert!(serde_json::from_value::<NativeCallOutcomeV1>(invalid).is_err());
    assert!(serde_json::from_str::<NativeCallOutcomeV1>("{\"completed\":\"yes\"}").is_err());
}
