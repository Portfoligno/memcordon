use memcordon_ci::windows_consumer_readiness::descriptor::{
    CHURN_CREATIONS, CHURN_LIVE, Case, Descriptor, Toolchain,
};
use memcordon_ci::windows_consumer_readiness::{
    CaseAssessment, SuiteInput, accepted, positive_keys, validate_suite,
};

fn descriptor() -> Descriptor {
    let root = std::env::temp_dir().join("memcordon-readiness-input-oracle");
    Descriptor {
        format: "memcordon.fixture-workload".into(),
        revision: 1,
        case: Case::Churn,
        transcript: root.join("events.bin"),
        output_root: root.clone(),
        challenge: vec![0, 255, 128, 1],
        stdout: Vec::new(),
        stderr: Vec::new(),
        arguments: Vec::new(),
        application_status: 0,
        churn_creations: CHURN_CREATIONS,
        churn_live: CHURN_LIVE,
        denied_write_paths: Vec::new(),
        sentinel_handles: Vec::new(),
        descendant_gate: None,
        start_gate: Some("Local\\memcordon-readiness-test-start".into()),
        completion_gate: None,
        cohort_gate: Some("Local\\memcordon-readiness-test-cohort".into()),
        generation_gate: Some("Local\\memcordon-readiness-test-generation".into()),
        toolchain: Some(Toolchain {
            rustc: root.join("rustc.exe"),
            native_linker: root.join("link.exe"),
            native_library_directories: ["vc", "ucrt", "um"]
                .into_iter()
                .map(|name| root.join(name))
                .collect(),
            library_source: root.join("library.rs"),
            test_source: root.join("tests.rs"),
            child_source: root.join("child.rs"),
            dll_source: root.join("dll.rs"),
            loader_source: root.join("loader.rs"),
            target: "x86_64-pc-windows-msvc".into(),
        }),
    }
}

#[test]
fn workload_cannot_narrow_churn_or_hide_invalid_native_argv() {
    let valid = descriptor();
    valid.validate().unwrap();
    let mut missing_toolchain = valid.clone();
    missing_toolchain.toolchain = None;
    assert!(missing_toolchain.validate().is_err());
    let mut insufficient = valid.clone();
    insufficient.churn_creations = 4095;
    assert!(insufficient.validate().is_err());
    let mut excessive_live = valid.clone();
    excessive_live.churn_live = 64;
    assert!(excessive_live.validate().is_err());
    let mut missing_barrier = valid.clone();
    missing_barrier.cohort_gate = None;
    assert!(missing_barrier.validate().is_err());
    let mut native_nul = valid.clone();
    native_nul.arguments.push("before\0after".into());
    assert!(native_nul.validate().is_err());
    let mut traversal = valid;
    traversal.output_root = traversal.output_root.join("..");
    assert!(traversal.validate().is_err());
}

#[test]
fn fixture_descriptor_rejects_duplicate_and_unknown_fields() {
    let bytes = serde_json::to_string(&descriptor()).unwrap();
    let duplicate = bytes.replacen('{', "{\"revision\":1,", 1);
    assert!(serde_json::from_str::<Descriptor>(&duplicate).is_err());
    let unknown = bytes.replacen('{', "{\"pretend_success\":true,", 1);
    assert!(serde_json::from_str::<Descriptor>(&unknown).is_err());
}

#[test]
fn required_windows_rows_and_terminal_custody_cannot_be_omitted() {
    let suite = SuiteInput {
        format: "memcordon.windows-readiness-input".into(),
        revision: 1,
        local_policy: std::env::temp_dir().join("policy.json"),
        cases: Vec::new(),
    };
    assert!(validate_suite(&suite).is_err());
    let measured = "a".repeat(64);
    let mut records: Vec<_> = positive_keys()
        .into_iter()
        .map(|key| CaseAssessment {
            key,
            behavior: Ok(()),
            collection: Ok(()),
            retirement: Ok(()),
            descriptor_sha256: measured.clone(),
            result_sha256: Some(measured.clone()),
            stdout_sha256: Some(measured.clone()),
            stderr_sha256: Some(measured.clone()),
            transcript_sha256: Some(measured.clone()),
            contract_sha256: Some(measured.clone()),
            policy_activation_sha256: Some(measured.clone()),
            terminal_observation_sha256: Some(measured.clone()),
        })
        .collect();
    assert!(accepted(&records));
    records[0].terminal_observation_sha256 = None;
    assert!(!accepted(&records));
    records[0].terminal_observation_sha256 = Some(measured);
    records.pop();
    assert!(!accepted(&records));
}
