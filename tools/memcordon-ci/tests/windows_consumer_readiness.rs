use memcordon_ci::windows_consumer_readiness::descriptor::{
    self, CHURN_CREATIONS, CHURN_LIVE, Case, Descriptor, Toolchain,
};
use memcordon_ci::windows_consumer_readiness::{
    CaseAssessment, SuiteInput, accepted, check_positive_barrier_result, positive_keys,
    validate_suite, validate_toolchain_inventory,
};
#[path = "private/windows_current_result_fixture.rs"]
mod current_fixture;

#[test]
fn completed_released_native_failure_cannot_wait_for_a_positive_fixture() {
    let result = current_fixture::completed_loader_failure();
    let provider = result.provider.clone().unwrap();
    let bytes = serde_json::to_vec(&result).unwrap();
    let failure = check_positive_barrier_result(&bytes, &provider)
        .unwrap_err()
        .to_string();
    assert!(failure.contains("wrapper-status=125"));
    assert!(failure.contains("outcome=Completed"));
    assert!(failure.contains("windows-status=3221225794 (0xC0000142)"));
    assert!(failure.contains("release=Released"));
    assert!(failure.contains("no original provider failure observed"));
    let mut foreign = provider;
    foreign.generation = memcordon_core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        check_positive_barrier_result(&bytes, &foreign)
            .unwrap_err()
            .to_string()
            .contains("provider binding")
    );
}

#[test]
fn completed_restricted_launch_failure_cannot_wait_for_a_positive_fixture() {
    let result = current_fixture::launch_failure();
    let bytes = serde_json::to_vec(&result).unwrap();
    let provider = result.provider.as_ref().unwrap();
    let failure = check_positive_barrier_result(&bytes, provider)
        .unwrap_err()
        .to_string();
    assert!(failure.contains("positive fixture launch already failed"));
    assert!(failure.contains("MCSPAWN-FAILED"));
    assert!(failure.contains("0xC0000142"));
    assert!(failure.contains("wrapper-status=125"));
    let mut foreign = provider.clone();
    foreign.generation = memcordon_core::BoundedText::new("foreign-generation").unwrap();
    assert!(
        check_positive_barrier_result(&bytes, &foreign)
            .unwrap_err()
            .to_string()
            .contains("provider binding")
    );
    assert!(check_positive_barrier_result(&bytes[..bytes.len() / 2], provider).is_err());
}

#[test]
fn released_loader_event_context_requires_exact_failure_and_retirement() {
    use memcordon_ci::windows_consumer_readiness::released_target_loader_event_candidate;
    let result = current_fixture::completed_loader_failure();
    assert!(released_target_loader_event_candidate(&result));
    let refusal = current_fixture::launch_failure();
    assert!(!released_target_loader_event_candidate(&refusal));
    let mut missing_retirement = result.clone();
    let memcordon_core::result_v3::RuntimeExecutionV3::WindowsSealed { native, .. } =
        &mut missing_retirement.runtime
    else {
        panic!("current native fixture absent");
    };
    native.guardian_reaped = false;
    assert!(!released_target_loader_event_candidate(&missing_retirement));
    let mut cleanup_error = result.clone();
    cleanup_error.cleanup.state = memcordon_core::execution_facts::CleanupStateV1::Incomplete;
    assert!(!released_target_loader_event_candidate(&cleanup_error));
    let mut different_status = result;
    different_status.outcome.wrapper_status = 0;
    assert!(!released_target_loader_event_candidate(&different_status));
    different_status.outcome.wrapper_status = 125;
    different_status.outcome.native_termination =
        Some(memcordon_core::ChildTermination::WindowsStatus { status: 1 });
    assert!(!released_target_loader_event_candidate(&different_status));
}

#[test]
fn unsupported_format_header_cannot_satisfy_current_barrier() {
    let provider = current_fixture::completed_loader_failure()
        .provider
        .unwrap();
    assert!(
        check_positive_barrier_result(br#"{"format":"unsupported","revision":99}"#, &provider)
            .is_err()
    );
}

fn descriptor() -> Descriptor {
    let root = std::env::temp_dir().join("memcordon-readiness-input-oracle");
    let inputs = root.join("locked-inputs");
    let rustc = inputs.join("toolchain").join("bin").join("rustc.exe");
    let linker = inputs
        .join("toolchain")
        .join("lib")
        .join("rustlib")
        .join("x86_64-pc-windows-msvc")
        .join("bin")
        .join("rust-lld.exe");
    Descriptor {
        format: "memcordon.fixture-workload".into(),
        revision: descriptor::DESCRIPTOR_REVISION,
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
        gate_access_diagnostic: None,
        completion_gate: None,
        cohort_gate: Some("Local\\memcordon-readiness-test-cohort".into()),
        generation_gate: Some("Local\\memcordon-readiness-test-generation".into()),
        toolchain: Some(Toolchain {
            native_work_cutoff_ticks: 1,
            native_work_frequency: 1,
            linker_mode: descriptor::LinkerMode::BundledLldLink,
            input_root: inputs.clone(),
            rustc: rustc.clone(),
            native_linker: linker.clone(),
            selected_images: descriptor::project_toolchain_images([rustc, linker].into_iter().map(
                |path| {
                    (
                        path,
                        String::from(memcordon_core::DiagnosticSha256::from_bytes([7; 32])),
                    )
                },
            ))
            .unwrap(),
            native_library_directories: ["msvc-lib", "sdk-ucrt", "sdk-um"]
                .into_iter()
                .map(|name| inputs.join(name))
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
fn compiler_creation_uses_the_exact_frozen_measured_executable_inventory() {
    let mut input = descriptor();
    input.validate().unwrap();
    let toolchain = input.toolchain.as_mut().unwrap();
    let root = toolchain.rustc.parent().unwrap().to_owned();
    let helper = root.join("compiler-helper.exe");
    let helper_digest = String::from(memcordon_core::DiagnosticSha256::from_bytes([9; 32]));
    let mut measured: Vec<_> = toolchain
        .selected_images
        .iter()
        .map(|image| (image.path.clone(), image.sha256.clone()))
        .collect();
    measured.push((helper.clone(), helper_digest.clone()));
    measured.push((root.join("library.rs"), helper_digest.clone()));
    let frozen = descriptor::project_toolchain_images(measured).unwrap();
    toolchain.selected_images = frozen.clone();
    validate_toolchain_inventory(toolchain, &frozen).unwrap();
    assert!(toolchain.admits_created_image(&helper, &helper_digest));
    let changed_digest = String::from(memcordon_core::DiagnosticSha256::from_bytes([10; 32]));
    assert!(!toolchain.admits_created_image(&helper, &changed_digest));
    assert!(!toolchain.admits_created_image(&root.join("foreign.exe"), &helper_digest));
    let mut omitted = frozen.clone();
    omitted.retain(|image| image.path != helper);
    assert!(validate_toolchain_inventory(toolchain, &omitted).is_err());
    let mut rehashed = frozen.clone();
    rehashed
        .iter_mut()
        .find(|image| image.path == helper)
        .unwrap()
        .sha256 = changed_digest;
    assert!(validate_toolchain_inventory(toolchain, &rehashed).is_err());
    let valid = toolchain.clone();
    for malformed in [
        Vec::new(),
        vec![frozen[0].clone(), frozen[0].clone()],
        frozen
            .iter()
            .filter(|image| image.path != valid.rustc)
            .cloned()
            .collect(),
        frozen
            .iter()
            .filter(|image| image.path != valid.native_linker)
            .cloned()
            .collect(),
    ] {
        toolchain.selected_images = malformed;
        assert!(toolchain.validate_selected_images().is_err());
    }
    toolchain.selected_images = frozen;
    toolchain.selected_images[0].sha256 = "invalid".into();
    assert!(toolchain.validate_selected_images().is_err());
    let overflow = (0..=descriptor::MAX_TOOLCHAIN_IMAGES).map(|index| {
        (
            root.join(index.to_string()).with_extension("exe"),
            helper_digest.clone(),
        )
    });
    assert!(descriptor::project_toolchain_images(overflow).is_err());
    assert!(
        descriptor::project_toolchain_images([(
            root.join("..").join("foreign.exe"),
            helper_digest.clone()
        ),])
        .is_err()
    );
}

#[test]
fn separate_loader_command_selects_only_the_restricted_envelope_route() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseInput, CaseKey, TokenObservation, installed_support_loader_command,
        support_loader_command,
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
        workload_request: root.join("request.json"),
        expected_token: TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    };
    let build = |case: &CaseInput, installed: bool| {
        let builder = if installed {
            installed_support_loader_command
        } else {
            support_loader_command
        };
        builder(
            &root.join("measured-cli.exe"),
            &root.join("measured-wrapper.exe"),
            &root,
            &root.join("result.json"),
            case,
            &root.join("selection.json"),
            &root.join("observation.json"),
        )
    };
    let command = build(&case, false).unwrap().materialize().unwrap();
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
    let installed = build(&case, true).unwrap().materialize().unwrap();
    assert_eq!(installed.get_program(), command.get_program());
    assert_eq!(installed.get_current_dir(), command.get_current_dir());
    let installed_args: Vec<_> = installed
        .get_args()
        .map(std::ffi::OsStr::to_owned)
        .collect();
    let mut expected_installed = args.clone();
    let route = expected_installed
        .iter_mut()
        .find(|arg| *arg == "restricted-frontend")
        .unwrap();
    *route = "system-restricted-frontend".into();
    assert_eq!(installed_args, expected_installed);
    assert!(installed_args.ends_with(&[
        root.join("measured-wrapper.exe").into_os_string(),
        "consumer-readiness-windows".into(),
        case.descriptor_path.clone().into_os_string()
    ]));
    for field in ["scenario", "restricted", "workload", "arguments"] {
        let original = case.clone();
        match field {
            "scenario" => case.key.scenario = "ordinary".into(),
            "restricted" => case.expected_token.restricted = false,
            "workload" => case.descriptor.case = Case::Churn,
            "arguments" => case.descriptor.arguments.push("foreign".into()),
            _ => unreachable!(),
        }
        for installed in [false, true] {
            assert!(
                build(&case, installed).is_err(),
                "accepted {field}, installed={installed}"
            );
        }
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
fn production_fixture_vectors_fit_the_private_wire_bound_and_round_trip_exactly() {
    use memcordon_ci::windows_consumer_readiness::{fixture_parameters, validate_descriptor};
    let mut full_stream_cases = 0;
    let mut backpressure_cases = 0;
    for key in positive_keys() {
        let parameters = fixture_parameters(&key).unwrap();
        let mut input = descriptor();
        input.case = parameters.case;
        input.stdout = parameters.stdout;
        input.stderr = parameters.stderr;
        input.arguments = parameters.arguments;
        input.application_status = parameters.application_status;
        if matches!(input.case, Case::RootFirst | Case::IntermediateFirst) {
            input.descendant_gate = Some("Local\\memcordon-readiness-portable-descendant".into());
        }
        validate_descriptor(&key, &input).unwrap();
        let bytes = serde_json::to_vec(&input).unwrap();
        assert!(bytes.len() <= descriptor::MAX_DESCRIPTOR_BYTES, "{key:?}");
        let parsed = Descriptor::parse(&bytes).unwrap();
        assert_eq!(parsed.stdout, input.stdout, "{key:?}");
        assert_eq!(parsed.stderr, input.stderr, "{key:?}");
        assert_eq!(parsed.arguments, input.arguments, "{key:?}");
        assert_eq!(parsed.application_status, input.application_status);
        if (key.family == "C-IO" && key.scenario == "bounded-large-output")
            || (key.family == "W-RETIREMENT" && key.scenario == "output-backpressure")
        {
            assert_eq!(parsed.stdout.len(), descriptor::MAX_STREAM_BYTES);
            assert_eq!(parsed.stderr.len(), descriptor::MAX_STREAM_BYTES);
            assert_ne!(parsed.stdout, parsed.stderr);
            full_stream_cases += 1;
        }
        if key.family == "W-IO" && key.scenario == "backpressure-separated-streams" {
            assert_eq!(parsed.stdout.len(), 8192);
            assert_eq!(parsed.stderr.len(), 8192);
            assert_ne!(parsed.stdout, parsed.stderr);
            backpressure_cases += 1;
        }
    }
    assert_eq!(full_stream_cases, 2);
    assert_eq!(backpressure_cases, 1);
}

#[test]
fn compact_stream_codec_preserves_binary_empty_and_maximum_bytes() {
    for bytes in [
        Vec::new(),
        vec![0, 255, 128, 1],
        (0..=255).collect(),
        vec![255; descriptor::MAX_STREAM_BYTES],
    ] {
        let mut input = descriptor();
        input.stdout = bytes.clone();
        input.stderr = bytes.clone();
        let wire = serde_json::to_vec(&input).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        assert!(json["stdout_base64"].is_string());
        assert!(json.get("stdout").is_none());
        let parsed = Descriptor::parse(&wire).unwrap();
        assert_eq!(parsed.stdout, bytes);
        assert_eq!(parsed.stderr, bytes);
    }
}

#[test]
fn stream_encoding_rejects_noncanonical_and_over_limit_input_before_admission() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    let valid = serde_json::to_value(descriptor()).unwrap();
    for field in ["stdout_base64", "stderr_base64"] {
        for encoded in [
            "@AAA", "Zg", "Zg=", "Zg===", "Zh==", "Zm9=", "AAAA\n", "====", "A===",
        ] {
            let mut changed = valid.clone();
            changed[field] = encoded.into();
            assert!(
                serde_json::from_value::<Descriptor>(changed).is_err(),
                "{field}: {encoded:?}"
            );
        }
        let mut changed = valid.clone();
        changed[field] = STANDARD
            .encode(vec![0; descriptor::MAX_STREAM_BYTES + 1])
            .into();
        assert!(serde_json::from_value::<Descriptor>(changed).is_err());
    }
    for stdout in [true, false] {
        let mut input = descriptor();
        if stdout {
            input.stdout.resize(descriptor::MAX_STREAM_BYTES + 1, 0);
        } else {
            input.stderr.resize(descriptor::MAX_STREAM_BYTES + 1, 0);
        }
        assert!(serde_json::to_vec(&input).is_err());
        assert!(input.validate().is_err());
    }
    let mut old = valid.clone();
    old["revision"] = 1.into();
    assert!(Descriptor::parse(&serde_json::to_vec(&old).unwrap()).is_err());
    let mut unknown = valid;
    unknown["stdout"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Descriptor>(unknown).is_err());
    let wire = serde_json::to_string(&descriptor()).unwrap();
    let duplicate = format!(
        "{{\"stdout_base64\":\"\",{}",
        wire.strip_prefix('{').unwrap()
    );
    assert!(Descriptor::parse(duplicate.as_bytes()).is_err());
}

#[test]
fn compact_streams_do_not_relax_the_aggregate_descriptor_bound() {
    use memcordon_ci::windows_consumer_readiness::{CaseKey, validate_descriptor};
    let mut input = descriptor();
    input.arguments = vec!["x".repeat(4096); 16];
    let wire = serde_json::to_vec(&input).unwrap();
    assert!(wire.len() > descriptor::MAX_DESCRIPTOR_BYTES);
    assert!(Descriptor::parse(&wire).is_err());
    assert!(input.validate().is_err());
    let key = CaseKey {
        family: "C-IO".into(),
        scenario: "bounded-large-output".into(),
    };
    let error = validate_descriptor(&key, &input).unwrap_err().to_string();
    assert!(error.contains("C-IO/bounded-large-output"));
    assert!(error.contains(&format!("encoded-bytes={}", wire.len())));
    assert!(error.contains(&format!("limit={}", descriptor::MAX_DESCRIPTOR_BYTES)));
}

#[test]
fn required_windows_rows_and_terminal_custody_cannot_be_omitted() {
    let suite = SuiteInput {
        format: "memcordon.windows-readiness-input".into(),
        revision: 2,
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
            request_sha256: Some(measured.clone()),
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
