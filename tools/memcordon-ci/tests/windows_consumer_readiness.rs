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
fn natural_frontend_settlement_preserves_the_exact_failed_application_and_retirement_checks() {
    use memcordon_ci::windows_consumer_readiness::{
        current_association, current_native, validate_ended_application_settlement,
    };
    use memcordon_ci::windows_listener_wait::{ApplicationEnd, Identity};
    let result = current_fixture::completed_loader_failure();
    let target = current_native(&result)
        .unwrap()
        .target_identity
        .as_ref()
        .unwrap();
    let ended = ApplicationEnd {
        identity: Identity {
            pid: target.process_id,
            birth: target.creation_time_100ns.into(),
        },
        status: 0xC0000142,
    };
    let association = current_association(&result).unwrap().clone();
    let bytes = serde_json::to_vec(&result).unwrap();
    validate_ended_application_settlement(&bytes, 125, ended, &association).unwrap();
    assert!(check_positive_barrier_result(&bytes, &association.provider).is_err());
    assert!(validate_ended_application_settlement(&bytes, 2, ended, &association).is_err());
    assert!(
        validate_ended_application_settlement(
            &bytes,
            125,
            ApplicationEnd { status: 2, ..ended },
            &association
        )
        .is_err()
    );
    assert!(
        validate_ended_application_settlement(
            &bytes,
            125,
            ApplicationEnd {
                identity: Identity {
                    birth: ended.identity.birth + 1,
                    ..ended.identity
                },
                ..ended
            },
            &association
        )
        .is_err()
    );
    let mut other = association.clone();
    other.request_sha256 = memcordon_core::hash_bytes(b"different request");
    assert!(validate_ended_application_settlement(&bytes, 125, ended, &other).is_err());
    assert!(
        validate_ended_application_settlement(
            &serde_json::to_vec(&current_fixture::launch_failure()).unwrap(),
            125,
            ended,
            &association
        )
        .is_err()
    );
    for field in ["retirement", "ack"] {
        let mut incomplete = result.clone();
        let memcordon_core::result_v3::RuntimeExecutionV3::WindowsSealed { native, .. } =
            &mut incomplete.runtime
        else {
            panic!("native fixture")
        };
        match field {
            "retirement" => native.guardian_reaped = false,
            "ack" => {
                native
                    .frontend_delivery
                    .as_mut()
                    .unwrap()
                    .acknowledgement_observed = false
            }
            _ => unreachable!(),
        }
        assert!(
            validate_ended_application_settlement(
                &serde_json::to_vec(&incomplete).unwrap(),
                125,
                ended,
                &association
            )
            .is_err(),
            "{field}"
        );
    }
}

#[test]
fn fileio_capture_keeps_restricted_joint_and_only_adds_ordinary_provider_joint() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, loader_fileio_requested, loader_fileio_retention,
    };
    use memcordon_platform::windows_fileio_record::RetentionMode;
    for (family, scenario, case, experiment, expected) in [
        ("W-JOINT", "restricted", Case::Joint, false, true),
        ("W-JOINT", "restricted", Case::Joint, true, true),
        ("W-JOINT", "ordinary", Case::Joint, true, true),
        ("W-JOINT", "ordinary", Case::Joint, false, false),
        ("W-JOINT", "ordinary", Case::Toolchain, true, false),
        ("W-JOINT", "ordinary", Case::Churn, true, false),
        ("W-JOINT", "restricted", Case::Toolchain, true, false),
        ("W-OTHER", "ordinary", Case::Joint, true, false),
        ("W-OTHER", "restricted", Case::Joint, false, false),
        ("W-JOINT", "future-experiment", Case::Joint, true, false),
    ] {
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        assert_eq!(
            loader_fileio_requested(&key, case, experiment),
            expected,
            "{family}/{scenario}/{case:?}/experiment={experiment}"
        );
        let expected_mode =
            if (family, scenario, case, experiment) == ("W-JOINT", "ordinary", Case::Joint, true) {
                RetentionMode::RollingCompleted
            } else {
                RetentionMode::Prefix
            };
        assert_eq!(
            loader_fileio_retention(&key, case, experiment),
            expected_mode
        );
    }
}

#[test]
fn provider_facts_follow_physical_producer_roots_and_ignore_writable_decoys() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, ProviderExperimentRecord as Record, controller_case_directory,
        retain_provider_experiment_facts,
    };
    use std::{collections::BTreeSet, fs};

    let temporary = tempfile::tempdir().unwrap();
    let controller = temporary.path().join("controller");
    let key = CaseKey {
        family: "W-JOINT".into(),
        scenario: "ordinary".into(),
    };
    // These are the actual execute report parent and descriptor output layouts.
    let native = controller.join("W-JOINT/ordinary");
    let fixture = controller.join("candidate-outputs/W-JOINT/ordinary");
    fs::create_dir_all(&native).unwrap();
    fs::create_dir_all(&fixture).unwrap();
    assert_eq!(controller_case_directory(&controller, &key), native);
    let mut leaves = BTreeSet::new();
    for record in Record::ALL {
        assert!(leaves.insert(record.leaf()));
        let (producer, decoy, expected) = match record {
            Record::NativeListener
            | Record::NativeTcpPeer
            | Record::LoaderFileIo
            | Record::CallbackFailure
            | Record::CallbackStdout
            | Record::CallbackStderr
            | Record::GuardianQuery
            | Record::GuardianStdout
            | Record::GuardianStderr => (&native, &fixture, b"controller".as_slice()),
            _ => (&fixture, &native, b"fixture".as_slice()),
        };
        fs::write(producer.join(record.leaf()), expected).unwrap();
        fs::write(decoy.join(record.leaf()), b"wrong trust domain").unwrap();
        let selected = record.source_path(&controller, &key, &fixture);
        assert_eq!(selected.parent().unwrap(), producer);
        assert_eq!(fs::read(selected).unwrap(), expected);
    }
    assert!(leaves.contains("winsock-startup-trace.json"));
    assert!(leaves.contains("peer-winsock-startup-trace.json"));
    assert!(leaves.contains("listener-native-file-requests.json"));
    assert!(leaves.contains("peer-listener-native-file-requests.json"));
    assert!(leaves.contains("peer-spawn-call-trace.json"));
    assert!(leaves.contains("tcp-peer-stdout.json"));
    assert!(leaves.contains("tcp-peer-stdout.bin"));
    assert!(leaves.contains("result.loader-fileio.json"));
    assert!(leaves.contains("result.callback-failure.json"));
    assert!(leaves.contains("result.guardian-query.stderr.bin"));

    let original_stderr = vec![b'x'; 4984];
    fs::write(native.join("result.stderr.bin"), &original_stderr).unwrap();
    fs::write(native.join("result.stdout.bin"), vec![0; 64 * 1024]).unwrap();
    fs::write(
        native.join("result.guardian-query.stderr.bin"),
        vec![0; 64 * 1024 + 1],
    )
    .unwrap();
    fs::remove_file(native.join("result.guardian-query.stdout.bin")).unwrap();
    fs::write(fixture.join("tcp-peer-stdout.bin"), vec![1; 64 * 1024 + 1]).unwrap();
    let facts = temporary.path().join("facts");
    let mut copied = Vec::new();
    retain_provider_experiment_facts(
        &controller,
        &key,
        &fixture,
        &facts,
        |source, destination, maximum| {
            let bytes = fs::read(source)?;
            assert!(bytes.len() as u64 <= maximum);
            copied.push(source.to_owned());
            fs::write(destination, &bytes)?;
            Ok(bytes)
        },
        |path, bytes| {
            fs::write(path, bytes)?;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(
        fs::read(facts.join("result.stderr.bin")).unwrap(),
        original_stderr
    );
    assert_eq!(
        fs::metadata(facts.join("result.stdout.bin")).unwrap().len(),
        64 * 1024
    );
    assert!(!facts.join("result.guardian-query.stderr.bin").exists());
    assert!(!facts.join("result.guardian-query.stdout.bin").exists());
    assert!(!copied.contains(&native.join("result.guardian-query.stderr.bin")));
    let index_bytes = fs::read(facts.join("controller-capture-retention.json")).unwrap();
    assert!(index_bytes.len() <= 8 * 1024);
    let index: serde_json::Value = serde_json::from_slice(&index_bytes).unwrap();
    let captures = index["captures"].as_array().unwrap();
    assert_eq!(captures.len(), 7);
    assert!(!facts.join("tcp-peer-stdout.bin").exists());
    assert!(!copied.contains(&fixture.join("tcp-peer-stdout.bin")));
    for (leaf, state) in [
        ("result.stderr.bin", "copied"),
        ("result.stdout.bin", "copied"),
        ("result.guardian-query.stderr.bin", "oversize-not-copied"),
        ("result.guardian-query.stdout.bin", "not-present"),
        ("tcp-peer-stdout.bin", "oversize-not-copied"),
    ] {
        assert_eq!(
            captures.iter().find(|row| row["leaf"] == leaf).unwrap()["state"],
            state
        );
    }
}

#[test]
fn controller_capture_metadata_distinguishes_complete_files_oversize_and_producer_unknown() {
    use memcordon_ci::windows_consumer_readiness::ProviderExperimentRecord as Record;
    let captures = [
        Record::CallbackFailure,
        Record::CallbackStdout,
        Record::CallbackStderr,
        Record::GuardianQuery,
        Record::GuardianStdout,
        Record::GuardianStderr,
        Record::PeerStdout,
    ];
    let original_stderr = vec![b'x'; 4984];
    let mut index = Vec::new();
    for record in captures {
        assert_eq!(record.capture_ceiling(), Some(64 * 1024));
        let copied =
            record.capture_retention(Some(original_stderr.len() as u64), Some(&original_stderr));
        assert_eq!(copied["state"], "copied");
        assert_eq!(copied["retained_bytes"], original_stderr.len());
        assert_eq!(copied["file_copy_complete"], true);
        assert_eq!(copied["retained_sha256"].as_str().unwrap().len(), 64);
        assert!(copied["producer_capture_complete"].is_null());
        assert_eq!(copied["acceptance_authority"], false);
        let limit = vec![0; 64 * 1024];
        assert_eq!(
            record.capture_retention(Some(limit.len() as u64), Some(&limit))["file_copy_complete"],
            true
        );
        let oversized = record.capture_retention(Some(64 * 1024 + 1), None);
        assert_eq!(oversized["state"], "oversize-not-copied");
        assert_eq!(oversized["file_copy_complete"], false);
        assert!(oversized["retained_sha256"].is_null());
        assert!(oversized["retained_bytes"].is_null());
        let oversized_bytes = vec![0; 64 * 1024 + 1];
        let rejected_copy =
            record.capture_retention(Some(oversized_bytes.len() as u64), Some(&oversized_bytes));
        assert!(rejected_copy["retained_sha256"].is_null());
        assert!(rejected_copy["retained_bytes"].is_null());
        index.push(oversized);
        let absent = record.capture_retention(None, None);
        assert_eq!(absent["state"], "not-present");
        assert!(!absent["file_copy_complete"].as_bool().unwrap());
        let changed = record.capture_retention(Some(1), Some(&original_stderr));
        assert_eq!(changed["state"], "not-completely-copied");
    }
    assert!(serde_json::to_vec(&index).unwrap().len() < 8 * 1024);
}

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
        matched_control: None,
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
        start_transport: descriptor::StartTransport::NamedEvent,
        control_clock: None,
        winsock_registry: None,
        provider_input_experiment: false,
        provider_input_paths: Vec::new(),
        provider_input_binding: None,
        gate_access_diagnostic: None,
        gate_precondition: None,
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

fn experiment_descriptor() -> Descriptor {
    let mut value = descriptor();
    value.case = Case::Joint;
    value.cohort_gate = None;
    value.generation_gate = None;
    value.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_VERSION,
    };
    value.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 1000,
        qpc_frequency: 10,
    });
    value.winsock_registry = Some(descriptor::winsock_registry::Declaration {
        version: descriptor::winsock_registry::VERSION,
        view: descriptor::winsock_registry::View::Native,
        sha256: [3; 32],
    });
    let parent = value.output_root.with_file_name("private-fixture-inputs");
    let fixture = parent.join("fixture.exe");
    let local = parent.join("fixture.exe.local");
    let directory = |path, index| descriptor::PrivateFixtureAncestor {
        path,
        volume_serial: 7,
        file_index: index,
        attributes: 0x10,
    };
    let ancestors = fixture
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, path)| directory(path.to_owned(), index as u64 + 1))
        .collect();
    let output_ancestors = value
        .output_root
        .ancestors()
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, path)| directory(path.to_owned(), 200 + index as u64))
        .collect();
    value.provider_input_experiment = true;
    value.provider_input_paths = vec![fixture.clone(), local.join("provider.dll")];
    value.provider_input_binding = Some(descriptor::PrivateFixtureBinding {
        revision: 2,
        fixture,
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links: 1,
        bytes: 1000,
        sha256: "ab".repeat(32),
        native_path_utf16: r"\Device\Volume\private-fixture-inputs\fixture.exe"
            .encode_utf16()
            .collect(),
        ancestors,
        local_input: memcordon_platform::windows_private_fixture_binding::DotLocalInput::Directory(
            directory(local, 100),
        ),
        output_ancestors,
    });
    value
}

#[test]
fn fixture_binding_is_experiment_only_and_part_of_the_original_bounded_descriptor() {
    let valid = experiment_descriptor();
    let bytes = serde_json::to_vec(&valid).unwrap();
    let parsed = Descriptor::parse(&bytes).unwrap();
    assert_eq!(parsed.provider_input_binding, valid.provider_input_binding);
    let mut legacy = valid.clone();
    legacy.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::REGISTRY_VERSION,
    };
    assert!(Descriptor::parse(&serde_json::to_vec(&legacy).unwrap()).is_err());
    let ordinary = serde_json::to_value(descriptor()).unwrap();
    assert!(ordinary.get("provider_input_binding").is_none());
    let mut missing = valid.clone();
    missing.provider_input_binding = None;
    assert!(Descriptor::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut unexpected = valid.clone();
    unexpected.provider_input_experiment = false;
    assert!(Descriptor::parse(&serde_json::to_vec(&unexpected).unwrap()).is_err());
    let mut changed = valid.clone();
    changed.provider_input_paths.swap(0, 1);
    assert!(Descriptor::parse(&serde_json::to_vec(&changed).unwrap()).is_err());
    let mut oversized = valid;
    oversized.arguments = vec!["x".repeat(4096); 64];
    assert!(Descriptor::parse(&serde_json::to_vec(&oversized).unwrap()).is_err());

    use memcordon_platform::windows_private_fixture_binding::{DotLocalInput, PrivateFixtureFile};
    use sha2::Digest;
    let mut file = experiment_descriptor();
    let binding = file.provider_input_binding.as_mut().unwrap();
    let DotLocalInput::Directory(local) = &binding.local_input else {
        unreachable!()
    };
    let marker = PrivateFixtureFile {
        path: local.path.clone(),
        volume_serial: local.volume_serial,
        file_index: local.file_index,
        attributes: 0x20,
        links: 1,
        bytes: 0,
        sha256: hex::encode(sha2::Sha256::digest([])),
        native_path_utf16: r"\Device\Volume\private-fixture-inputs\fixture.exe.local"
            .encode_utf16()
            .collect(),
    };
    file.provider_input_paths = vec![
        binding.fixture.clone(),
        marker.path.clone(),
        binding.fixture.parent().unwrap().join("provider.dll"),
    ];
    binding.revision = 3;
    binding.local_input = DotLocalInput::File(marker);
    file.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_FILE_VERSION,
    };
    let bytes = serde_json::to_vec(&file).unwrap();
    let parsed = Descriptor::parse(&bytes).unwrap();
    assert_eq!(parsed.provider_input_binding, file.provider_input_binding);
    let digest = descriptor::controller_start::descriptor_digest(&bytes);
    Descriptor::parse_authenticated_peer(
        &bytes,
        digest,
        &file.challenge,
        &file.output_root,
        file.control_clock.as_ref().unwrap(),
    )
    .unwrap();
    let mut downgraded = file.clone();
    downgraded.start_transport = descriptor::StartTransport::ControllerStdin {
        version: descriptor::controller_start::PRIVATE_VERSION,
    };
    assert!(Descriptor::parse(&serde_json::to_vec(&downgraded).unwrap()).is_err());
    let mut mixed = file;
    mixed.provider_input_binding.as_mut().unwrap().revision = 2;
    assert!(Descriptor::parse(&serde_json::to_vec(&mixed).unwrap()).is_err());
}

#[test]
fn peer_rehashes_exact_original_bytes_and_rejects_forwarded_context_substitution() {
    let input = experiment_descriptor();
    let bytes = serde_json::to_vec(&input).unwrap();
    let digest = descriptor::controller_start::descriptor_digest(&bytes);
    let clock = input.control_clock.as_ref().unwrap();
    let (parsed, fresh) = Descriptor::parse_authenticated_peer(
        &bytes,
        digest,
        &input.challenge,
        &input.output_root,
        clock,
    )
    .unwrap();
    assert_eq!(
        fresh,
        descriptor::controller_start::descriptor_digest(&bytes)
    );
    assert_eq!(parsed.provider_input_binding, input.provider_input_binding);
    assert_eq!(parsed.provider_input_paths, input.provider_input_paths);
    // Even identical parsed content must match the original exact bytes.
    let mut whitespace = bytes.clone();
    whitespace.push(b'\n');
    assert!(Descriptor::parse(&whitespace).is_ok());
    assert!(
        Descriptor::parse_authenticated_peer(
            &whitespace,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let mut changed = input.clone();
    changed.provider_input_binding.as_mut().unwrap().file_index += 1;
    let forged_bytes = serde_json::to_vec(&changed).unwrap();
    let forged_digest = descriptor::controller_start::descriptor_digest(&forged_bytes);
    // A forged envelope can be internally consistent. It is still not the
    // descriptor authenticated by the controller's original root START.
    Descriptor::parse_authenticated_peer(
        &forged_bytes,
        forged_digest,
        &input.challenge,
        &input.output_root,
        clock,
    )
    .unwrap();
    let authentic_binding = descriptor::controller_start::Binding {
        challenge: input.challenge.clone(),
        descriptor_sha256: digest,
        pid: 77,
        birth: 88,
    };
    let registry = descriptor::controller_start::Capability {
        version: 1,
        handle: 0x320,
        manifest_sha256: input.winsock_registry.as_ref().unwrap().sha256,
    };
    let mut wire = Vec::new();
    descriptor::controller_start::Sender::with_registry(registry, false)
        .send(
            &mut wire,
            &authentic_binding,
            descriptor::controller_start::Phase::Start,
            || Ok(()),
        )
        .unwrap();
    let mut expected_forged = authentic_binding.clone();
    expected_forged.descriptor_sha256 = forged_digest;
    let mut receiver =
        descriptor::controller_start::Receiver::with_registry(registry.manifest_sha256, false);
    assert!(
        receiver
            .receive(
                &mut std::io::Cursor::new(&wire),
                &expected_forged,
                || Ok(())
            )
            .is_err()
    );
    assert!(receiver.registry_capability().is_none());
    let mut actual_receiver =
        descriptor::controller_start::Receiver::with_registry(registry.manifest_sha256, false);
    actual_receiver
        .receive(&mut std::io::Cursor::new(&wire), &authentic_binding, || {
            Ok(())
        })
        .unwrap();
    assert!(actual_receiver.registry_capability().is_some());
    assert!(
        Descriptor::parse_authenticated_peer(
            &forged_bytes,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let mut wrong_clock = clock.clone();
    wrong_clock.work_cutoff_qpc += 1;
    for (challenge, output, clock) in [
        (
            &b"other challenge"[..],
            input.output_root.clone(),
            clock.clone(),
        ),
        (
            input.challenge.as_slice(),
            input.output_root.join("other"),
            clock.clone(),
        ),
        (
            input.challenge.as_slice(),
            input.output_root.clone(),
            wrong_clock,
        ),
    ] {
        assert!(
            Descriptor::parse_authenticated_peer(&bytes, digest, challenge, &output, &clock)
                .is_err()
        );
    }
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(
        Descriptor::parse_authenticated_peer(
            &bytes,
            wrong_digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
    let oversized = vec![b' '; descriptor::MAX_DESCRIPTOR_BYTES + 1];
    assert!(
        Descriptor::parse_authenticated_peer(
            &oversized,
            digest,
            &input.challenge,
            &input.output_root,
            clock
        )
        .is_err()
    );
}

#[test]
fn restricted_envelopes_select_framed_start_and_wire_requires_original_clock() {
    use descriptor::StartTransport;
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, TokenObservation, expected_start_transport, validate_descriptor,
    };
    let mut input = descriptor();
    input.case = Case::Envelope;
    input.toolchain = None;
    input.cohort_gate = None;
    input.generation_gate = None;
    for (family, scenario) in [
        ("W-ENVELOPE", "restricted"),
        ("W-BINDING", "restricted-token-preserved"),
    ] {
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        input.start_transport = expected_start_transport(&key);
        assert_eq!(
            input.start_transport,
            StartTransport::ControllerStdin {
                version: descriptor::controller_start::VERSION
            }
        );
        validate_descriptor(&key, &input).unwrap(); // Declared plan, before clock preparation.
        assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
        input.gate_precondition = Some(descriptor::gate_precondition::Input {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
            expected_token: TokenObservation {
                user_sid: vec![1],
                restricted: true,
                integrity_rid: 12288,
                elevated: true,
                restricting_sids: vec![vec![2]],
            },
        });
        input.control_clock = Some(descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
        });
        let bytes = serde_json::to_vec(&input).unwrap();
        Descriptor::parse(&bytes).unwrap();
        for (field, value) in [
            ("version", serde_json::json!(99)),
            ("transport", serde_json::json!("unknown")),
        ] {
            let mut value_descriptor = serde_json::to_value(&input).unwrap();
            value_descriptor["start_transport"][field] = value;
            assert!(Descriptor::parse(&serde_json::to_vec(&value_descriptor).unwrap()).is_err());
        }
        let text = String::from_utf8(bytes).unwrap();
        let duplicated = text.replacen(
            "\"start_transport\":",
            "\"start_transport\":{\"transport\":\"named-event\"},\"start_transport\":",
            1,
        );
        assert!(Descriptor::parse(duplicated.as_bytes()).is_err());
        let mut wrong = input.clone();
        wrong.start_transport = StartTransport::NamedEvent;
        assert!(validate_descriptor(&key, &wrong).is_err());
        input.gate_precondition = None;
        input.control_clock = None;
    }
    for (family, scenario) in [
        ("W-ENVELOPE", "ordinary"),
        ("C-IO", "empty-input"),
        ("W-BINDING", "ordinary"),
    ] {
        assert_eq!(
            expected_start_transport(&CaseKey {
                family: family.into(),
                scenario: scenario.into()
            }),
            StartTransport::NamedEvent
        );
    }
    let key = CaseKey {
        family: "W-ENVELOPE".into(),
        scenario: "restricted".into(),
    };
    input.stdout = vec![0; descriptor::MAX_STREAM_BYTES];
    input.stderr = vec![0; descriptor::MAX_STREAM_BYTES];
    input.arguments = vec!["R".repeat(4096); 16];
    assert!(input.validate().is_err());
    assert!(serde_json::to_vec(&input).unwrap().len() > descriptor::MAX_DESCRIPTOR_BYTES);
    assert!(validate_descriptor(&key, &input).is_err());
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
fn restricted_joint_keeps_native_compiler_observation_with_a_separate_control_clock() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, needs_toolchain_observer, validate_descriptor,
    };
    let mut input = descriptor();
    input.case = Case::Joint;
    input.cohort_gate = None;
    input.generation_gate = None;
    let key = CaseKey {
        family: "W-JOINT".into(),
        scenario: "restricted".into(),
    };
    input.start_transport = expected_start_transport(&key);
    input.control_clock = Some(descriptor::ControlClock {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
    });
    assert!(input.gate_precondition.is_none());
    validate_descriptor(&key, &input).unwrap();
    let parsed = Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
    assert!(needs_toolchain_observer(parsed.case));
    assert!(parsed.gate_precondition.is_none());
    for (field, value) in [
        ("revision", 2),
        ("work_cutoff_qpc", 0),
        ("qpc_frequency", 0),
    ] {
        let mut invalid = serde_json::to_value(&input).unwrap();
        invalid["control_clock"][field] = value.into();
        assert!(Descriptor::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    let mut missing = input.clone();
    missing.control_clock = None;
    assert!(Descriptor::parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    let mut diagnostic = input.clone();
    diagnostic.gate_precondition = Some(descriptor::gate_precondition::Input {
        revision: 1,
        work_cutoff_qpc: 999,
        qpc_frequency: 10,
        expected_token: memcordon_ci::windows_consumer_readiness::TokenObservation {
            user_sid: vec![1],
            restricted: true,
            integrity_rid: 12288,
            elevated: true,
            restricting_sids: vec![vec![2]],
        },
    });
    assert!(Descriptor::parse(&serde_json::to_vec(&diagnostic).unwrap()).is_err());
    for case in [Case::Toolchain, Case::Joint, Case::Churn] {
        assert!(needs_toolchain_observer(case));
    }
    for case in [Case::Envelope, Case::EndpointMismatch, Case::EmptyInput] {
        assert!(!needs_toolchain_observer(case));
    }
    for (family, scenario) in [
        ("W-JOINT", "ordinary"),
        ("W-CHURN", "restricted"),
        ("W-JOINT", "endpoint-mismatch"),
    ] {
        assert_eq!(
            expected_start_transport(&CaseKey {
                family: family.into(),
                scenario: scenario.into()
            }),
            descriptor::StartTransport::NamedEvent
        );
    }
    let mut named = input.clone();
    named.start_transport = descriptor::StartTransport::NamedEvent;
    assert!(named.validate().is_err()); // A stdin clock is not another named authority.
}

#[test]
fn explicit_native_registry_dependency_requires_bound_version_three_joint_control() {
    use memcordon_ci::windows_consumer_readiness::{
        CaseKey, expected_start_transport, fixture_parameters, needs_registry_input,
        validate_descriptor,
    };
    let rows = [
        (Case::Joint, "C-IO", "empty-message"),
        (Case::Joint, "W-IO", "empty-message"),
        (Case::Joint, "W-JOINT", "ordinary"),
        (Case::Joint, "W-JOINT", "restricted"),
        (Case::EndpointMismatch, "W-JOINT", "endpoint-mismatch"),
        (Case::Churn, "W-CHURN", "natural-4096-three-generations"),
    ];
    let eligible = positive_keys()
        .into_iter()
        .filter(|key| needs_registry_input(key, fixture_parameters(key).unwrap().case))
        .collect::<std::collections::BTreeSet<_>>();
    let intended = rows
        .iter()
        .map(|(_, family, scenario)| CaseKey {
            family: (*family).into(),
            scenario: (*scenario).into(),
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(eligible, intended);
    for (case, family, scenario) in rows {
        let mut input = descriptor();
        input.case = case;
        if case != Case::Churn {
            input.cohort_gate = None;
            input.generation_gate = None;
        }
        let key = CaseKey {
            family: family.into(),
            scenario: scenario.into(),
        };
        input.start_transport = expected_start_transport(&key);
        validate_descriptor(&key, &input).unwrap(); // Original unprepared plan.
        assert!(needs_registry_input(&key, case));
        input.start_transport = descriptor::StartTransport::ControllerStdin {
            version: descriptor::controller_start::REGISTRY_VERSION,
        };
        input.winsock_registry = Some(descriptor::winsock_registry::Declaration {
            version: descriptor::winsock_registry::VERSION,
            view: descriptor::winsock_registry::View::Native,
            sha256: [42; 32],
        });
        validate_descriptor(&key, &input).unwrap(); // Explicit prepared plan.
        assert!(Descriptor::parse(&serde_json::to_vec(&input).unwrap()).is_err());
        input.control_clock = Some(descriptor::ControlClock {
            revision: 1,
            work_cutoff_qpc: 999,
            qpc_frequency: 10,
        });
        validate_descriptor(&key, &input).unwrap();
        Descriptor::parse(&serde_json::to_vec(&input).unwrap()).unwrap();
        let foreign = CaseKey {
            family: "W-BINDING".into(),
            scenario: "restricted-token-preserved".into(),
        };
        assert!(validate_descriptor(&foreign, &input).is_err());
        for (family, scenario, claimed) in [
            ("W-JOINT", "not-in-the-positive-catalog", Case::Joint),
            ("W-CHURN", "not-in-the-positive-catalog", Case::Churn),
        ] {
            let unknown = CaseKey {
                family: family.into(),
                scenario: scenario.into(),
            };
            assert!(!needs_registry_input(&unknown, claimed));
            assert!(validate_descriptor(&unknown, &input).is_err());
        }
        for other in [Case::Joint, Case::EndpointMismatch, Case::Churn] {
            if other == case {
                continue;
            }
            let mut substituted = input.clone();
            substituted.case = other;
            if other == Case::Churn {
                let churn = descriptor();
                substituted.cohort_gate = churn.cohort_gate;
                substituted.generation_gate = churn.generation_gate;
            } else {
                substituted.cohort_gate = None;
                substituted.generation_gate = None;
            }
            // Wire has no case key: a structurally valid registry kind is not
            // sufficient for admission under a different catalog key.
            Descriptor::parse(&serde_json::to_vec(&substituted).unwrap()).unwrap();
            assert!(!needs_registry_input(&key, other));
            assert!(validate_descriptor(&key, &substituted).is_err());
        }
        for mutation in 0..4 {
            let mut bad = input.clone();
            match mutation {
                0 => bad.start_transport = descriptor::StartTransport::NamedEvent,
                1 => {
                    bad.start_transport = descriptor::StartTransport::ControllerStdin {
                        version: descriptor::controller_start::VERSION,
                    }
                }
                2 => bad.winsock_registry.as_mut().unwrap().version = 3,
                3 => bad.case = Case::Envelope,
                _ => unreachable!(),
            }
            assert!(validate_descriptor(&key, &bad).is_err());
            assert!(Descriptor::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
        }
    }
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
    case.descriptor.gate_precondition = Some(
        memcordon_ci::windows_consumer_readiness::descriptor::gate_precondition::Input {
            revision: 1,
            expected_token: case.expected_token.clone(),
            work_cutoff_qpc: 1,
            qpc_frequency: 1,
        },
    );
    let controlled = memcordon_ci::windows_consumer_readiness::public_command(
        &root.join("measured-cli.exe"),
        &root.join("measured-wrapper.exe"),
        &root,
        &root.join("result.json"),
        &case,
    )
    .unwrap()
    .materialize()
    .unwrap();
    let controlled_args: Vec<_> = controlled
        .get_args()
        .map(std::ffi::OsStr::to_owned)
        .collect();
    assert!(controlled_args.starts_with(&[
        "consumer-readiness-windows".into(),
        "system-restricted-gate-control-frontend".into(),
        case.descriptor_path.clone().into_os_string(),
        root.join("measured-cli.exe").into_os_string(),
    ]));
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
        input.start_transport =
            memcordon_ci::windows_consumer_readiness::expected_start_transport(&key);
        if matches!(
            input.start_transport,
            descriptor::StartTransport::ControllerStdin { .. }
        ) {
            input.control_clock = Some(descriptor::ControlClock {
                revision: 1,
                work_cutoff_qpc: 999,
                qpc_frequency: 10,
            });
        }
        if matches!(
            (key.family.as_str(), key.scenario.as_str()),
            ("W-ENVELOPE", "restricted") | ("W-BINDING", "restricted-token-preserved")
        ) {
            input.gate_precondition = Some(descriptor::gate_precondition::Input {
                revision: 1,
                work_cutoff_qpc: 999,
                qpc_frequency: 10,
                expected_token: memcordon_ci::windows_consumer_readiness::TokenObservation {
                    user_sid: vec![1],
                    restricted: true,
                    integrity_rid: 12288,
                    elevated: true,
                    restricting_sids: vec![vec![2]],
                },
            });
        }
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
