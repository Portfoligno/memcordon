#[path = "../src/bin/memcordon-sealed-agent/windows/process_impl/loader_mitigations.rs"]
mod diagnostics;

#[test]
fn unavailable_policy_is_distinct_from_observed_disabled_flags() {
    use diagnostics::{LoaderMitigations, PolicyObservation};
    let observation = LoaderMitigations {
        process: memcordon_core::WindowsProcessIdentityV1 {
            process_id: 7,
            creation_time_100ns: 11,
        },
        executable_sha256: "ab".repeat(32),
        launch_plan_sha256: "cd".repeat(32),
        system_call_disable: PolicyObservation::Observed { flags: 0 },
        binary_signature: PolicyObservation::Unavailable { native_code: 5 },
        image_load: PolicyObservation::CutoffExhausted,
    };
    let bytes = serde_json::to_vec(&observation).unwrap();
    assert_eq!(
        serde_json::to_vec(&Box::new(observation.clone())).unwrap(),
        bytes
    );
    assert!(bytes.len() < 1024);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["process"]["creation_time_100ns"], 11);
    assert_eq!(value["system_call_disable"]["flags"], 0);
    assert_eq!(value["binary_signature"]["native_code"], 5);
    assert!(value["binary_signature"].get("flags").is_none());
    assert_eq!(value["image_load"]["observation"], "cutoff-exhausted");
    assert!(value["image_load"].get("flags").is_none());
}

#[test]
fn diagnostic_roundtrip_preserves_original_failure_and_rejects_foreign_plan() {
    use memcordon_core::*;
    let original = "original native loader failure".repeat(10);
    let mut failure = WindowsLoaderQualificationFailureV2 {
        schema_version: 2,
        stable_code: "loader-control-pipe-accept".into(),
        stage: WindowsLoaderQualificationStageV2::LoaderReadyHandshake,
        native_status: Some(WindowsLoaderNativeStatusV1::TargetExit { code: 0xc0000142 }),
        elapsed_millis: 68,
        launch_plan_sha256: Some("ab".repeat(32)),
        launch_plan_json: None,
        qualification_id: "original-loader".into(),
        cleanup: WindowsLoaderCleanupOutcomeV1 {
            status: WindowsLoaderCleanupStatusV1::Complete,
            stable_code: None,
        },
        diagnostic_id: None,
        detail: original.clone(),
        support_debug_observation: None,
        mitigation_observation: Some(Box::new(WindowsLoaderMitigationObservationV1 {
            process: WindowsProcessIdentityV1 {
                process_id: 7,
                creation_time_100ns: 11,
            },
            executable_sha256: "cd".repeat(32),
            launch_plan_sha256: "ab".repeat(32),
            system_call_disable: WindowsLoaderMitigationPolicyObservationV1::Observed { flags: 0 },
            binary_signature: WindowsLoaderMitigationPolicyObservationV1::Unavailable {
                native_code: 5,
            },
            image_load: WindowsLoaderMitigationPolicyObservationV1::CutoffExhausted,
        })),
    };
    let outcome = WindowsLoaderQualificationOutcomeV2::Failed(failure.clone());
    assert!(outcome.is_consistent());
    let bytes = serde_json::to_vec(&outcome).unwrap();
    let decoded: WindowsLoaderQualificationOutcomeV2 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, outcome);
    assert_eq!(failure.detail, original);
    failure
        .mitigation_observation
        .as_mut()
        .unwrap()
        .launch_plan_sha256 = "ef".repeat(32);
    assert!(!WindowsLoaderQualificationOutcomeV2::Failed(failure.clone()).is_consistent());
    failure.mitigation_observation = None;
    let legacy = serde_json::to_vec(&WindowsLoaderQualificationOutcomeV2::Failed(failure)).unwrap();
    let decoded: WindowsLoaderQualificationOutcomeV2 = serde_json::from_slice(&legacy).unwrap();
    assert!(decoded.is_consistent());
}

#[cfg(windows)]
#[test]
fn expired_original_cutoff_does_not_query_an_invalid_process_handle() {
    let observation = diagnostics::capture(
        std::ptr::null_mut(),
        memcordon_core::WindowsProcessIdentityV1 {
            process_id: 0,
            creation_time_100ns: 0,
        },
        &"ab".repeat(32),
        &"cd".repeat(32),
        std::time::Instant::now(),
    );
    assert!(matches!(
        observation.system_call_disable,
        diagnostics::PolicyObservation::CutoffExhausted
    ));
    assert!(matches!(
        observation.binary_signature,
        diagnostics::PolicyObservation::CutoffExhausted
    ));
    assert!(matches!(
        observation.image_load,
        diagnostics::PolicyObservation::CutoffExhausted
    ));
}
