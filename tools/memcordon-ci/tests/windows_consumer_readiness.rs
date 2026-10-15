use memcordon_ci::windows_consumer_readiness::descriptor::{
    CHURN_CREATIONS, CHURN_LIVE, Case, Descriptor, Toolchain,
};
use memcordon_ci::windows_consumer_readiness::{
    CaseAssessment, SuiteInput, accepted, check_positive_barrier_result, positive_keys,
    validate_suite,
};

#[test]
fn completed_restricted_launch_failure_cannot_wait_for_a_positive_fixture() {
    let bytes = include_bytes!("fixtures/windows_restricted_launch_failure.json");
    let result = memcordon_core::ResultV1::parse(bytes).unwrap();
    let provider = &result.provider_association.as_ref().unwrap().provider;
    let failure = check_positive_barrier_result(bytes, provider)
        .unwrap_err()
        .to_string();
    assert!(failure.contains("positive fixture launch already failed"));
    assert!(failure.contains("MCSPAWN-FAILED"));
    assert!(failure.contains("0xC0000142"));
    assert!(failure.contains("wrapper-status=125"));
    let mut foreign = provider.clone();
    foreign.generation = memcordon_core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        check_positive_barrier_result(bytes, &foreign)
            .unwrap_err()
            .to_string()
            .contains("provider binding")
    );
    assert!(check_positive_barrier_result(&bytes[..bytes.len() / 2], provider).is_err());
    let unbound = include_bytes!("fixtures/private_worker_loss_result.json");
    assert!(check_positive_barrier_result(unbound, provider).is_err());
}

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
            native_work_cutoff_ticks: 1,
            native_work_frequency: 1,
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
fn separate_loader_command_selects_only_the_restricted_envelope_route() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, TokenObservation, support_loader_command,
    };
    let root = std::env::temp_dir().join("support-loader-argv-oracle");
    let mut descriptor = descriptor();
    descriptor.case = Case::Envelope;
    let mut case = CaseInput {
        key: CaseKey {
            family: "W-ENVELOPE".into(),
            scenario: "restricted".into(),
        },
        descriptor,
        descriptor_path: root.join("input.json"),
        workload_contract: root.join("contract.json"),
        expected_token: TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    };
    let build = |case: &CaseInput| {
        support_loader_command(
            &root.join("measured-cli.exe"),
            &root.join("measured-wrapper.exe"),
            &root,
            &root.join("result.json"),
            case,
            &root.join("selection.json"),
            &root.join("observation.json"),
        )
    };
    let command = build(&case).unwrap().materialize().unwrap();
    let args: Vec<_> = command.get_args().map(std::ffi::OsStr::to_owned).collect();
    assert_eq!(command.get_program(), root.join("measured-wrapper.exe"));
    assert!(args.starts_with(&[
        "consumer-readiness-windows".into(),
        "restricted-frontend".into(),
        root.join("measured-cli.exe").into_os_string(),
        "__windows-loader-diagnostic".into(),
        root.join("selection.json").into_os_string(),
        root.join("observation.json").into_os_string()
    ]));
    assert!(!args.iter().any(|arg| arg == "__windows-certification"));
    for field in ["scenario", "restricted", "workload", "arguments"] {
        let original = case.clone();
        match field {
            "scenario" => case.key.scenario = "ordinary".into(),
            "restricted" => case.expected_token.restricted = false,
            "workload" => case.descriptor.case = Case::Churn,
            "arguments" => case.descriptor.arguments.push("foreign".into()),
            _ => unreachable!(),
        }
        assert!(build(&case).is_err(), "accepted {field}");
        case = original;
    }
}

#[test]
fn workload_cannot_narrow_churn_or_hide_invalid_native_argv() {
    let valid = descriptor();
    valid.validate().unwrap();
    let mut missing_toolchain = valid.clone();
    missing_toolchain.toolchain = None;
    assert!(missing_toolchain.validate().is_err());
    let mut missing_cutoff = valid.clone();
    missing_cutoff
        .toolchain
        .as_mut()
        .unwrap()
        .native_work_cutoff_ticks = 0;
    assert!(missing_cutoff.validate().is_err());
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
