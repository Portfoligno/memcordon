use memcordon_ci::windows_provider_projection_record::{
    BindingExpectation, CatalogProvider, CatalogSnapshot, OriginalSelectionState, PrivateInput,
    image_witness, mutation_witness, mutation_witness_for_layout, observe_original_selection,
    select, verify_expansion,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn image_record(peer: bool) -> (Value, BindingExpectation, Vec<PrivateInput>) {
    let token = memcordon_ci::windows_consumer_readiness::TokenObservation {
        user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        restricted: true,
        integrity_rid: 8192,
        elevated: false,
        restricting_sids: vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]],
    };
    let token_sha256: [u8; 32] =
        Sha256::digest(serde_json::to_vec(&serde_json::to_value(token).unwrap()).unwrap()).into();
    let expected = BindingExpectation {
        pid: if peer { 200 } else { 100 },
        birth: 134383953057150605,
        descriptor_sha256: [3; 32],
        challenge_sha256: [4; 32],
        token_sha256,
        peer,
    };
    let input = PrivateInput {
        original_path: r"C:\Windows\system32\provider.dll".encode_utf16().collect(),
        private_native_path: r"\Device\HarddiskVolume4\owned\inputs\fixture.exe.local\provider.dll"
            .encode_utf16()
            .collect(),
        volume_serial: 348031910,
        file_index: 42,
        bytes: 4096,
        sha256: "ab".repeat(32),
    };
    let original = json!({"complete":true,"operation_code":12,"sequence":if peer{1}else{2},"thread_id":7,
        "raw_root":0,"raw_flags":0,"raw_output":65536,"name_utf16":input.original_path,
        "name_flags":1,"reported_name_bytes":input.original_path.len()*2,"copied_name_units":input.original_path.len(),"entered":1,"returned":1,"output_flags":3,
        "native_status_or_adapter_marker":0});
    let binding = json!({"pid":expected.pid,"creation_time_100ns":expected.birth,
            "descriptor_sha256":expected.descriptor_sha256,"challenge_sha256":expected.challenge_sha256,
            "prior_token_observation_sha256":token_sha256,"prior_token_observation_scope":if peer{"peer-before-authenticated-start"}else{"root-admitted-token-envelope"},
            "prior_admitted_token_envelope_sha256":(!peer).then_some(token_sha256),
            "current_process_token":{"sha256":token_sha256,"error":null},"current_effective_token":{"sha256":token_sha256,"error":null}});
    let image = json!({"complete":true,"invalid_row":false,"dependency_sequence":if peer{1}else{2},"parent_listener_sequence":42,"original_thread":7,"domain":0,"state":1,"flags":7,"started_qpc":3,"finished_qpc":4,"virtual_query_error":0,"mapped_name_error":0,
                "returned_base":65536,"allocation_base":65536,"memory_type":0x0100_0000u32,
                "mapped_path_utf16":input.private_native_path,"original_load":original.clone()});
    let returned_images = json!({"version":1,"enabled":true,"count":1,"attempts":1,"dropped":0,"invalid_record":false,"observation_incomplete":false,"complete":true,"rows":[image]});
    let trace = json!({"packet_version":5,"invalid_packet":false,"original_thread":7,"started_qpc":1,"finished_qpc":99,"cutoff_qpc":100,"frequency":10,"original_rust_operation":if peer{"TcpStream::connect"}else{"TcpListener::bind"},
            "dependencies":{"recent_entries":[original]},"returned_images":returned_images});
    let value = json!({"format":"memcordon.original-rust-listener-trace","revision":1,"original_binding":binding,"trace":trace});
    (value, expected, vec![input])
}

#[test]
fn experiment_selection_requires_exact_scenarios_and_roles_and_retains_nonprivate_rows() {
    use memcordon_ci::windows_provider_projection_record::{
        ExperimentSelectionAssessment, PrivateAvailability, ProviderScenario,
        ScenarioSelectionAssessment,
    };
    let selection = |peer: bool, private: bool| {
        let (mut value, expected, inputs) = image_record(peer);
        if !private {
            value["trace"]["returned_images"]["rows"][0]["mapped_path_utf16"] = json!(
                r"\Device\HarddiskVolume4\Windows\system32\provider.dll"
                    .encode_utf16()
                    .collect::<Vec<_>>()
            );
        }
        observe_original_selection(&value, &expected, &inputs).unwrap()
    };
    for roles in [
        vec![],
        vec![selection(false, true)],
        vec![selection(false, true), selection(false, false)],
        vec![selection(true, true), selection(true, true)],
    ] {
        assert!(ScenarioSelectionAssessment::assess(ProviderScenario::Ordinary, roles).is_err());
    }
    let ordinary = ScenarioSelectionAssessment::assess(
        ProviderScenario::Ordinary,
        vec![selection(false, false), selection(true, true)],
    )
    .unwrap();
    assert_eq!(
        ordinary.private_availability(),
        PrivateAvailability::Unavailable
    );
    // An unavailable observation can advance only after actual settlement.
    // A later failed restricted scenario cannot consume or erase this record.
    use memcordon_ci::windows_consumer_readiness::settle_provider_scenario;
    for obligation in [
        "original operation",
        "collection",
        "retirement",
        "mutation denial",
        "custody",
        "retention",
        "namespace cleanup",
        "publication",
    ] {
        let error = settle_provider_scenario(
            Some(ordinary.clone()),
            Err(memcordon_ci::CiError::Message(obligation.into())),
        )
        .unwrap_err();
        assert!(error.to_string().contains(obligation));
    }
    let settled = settle_provider_scenario(Some(ordinary.clone()), Ok(())).unwrap();
    let prior_record = serde_json::to_value(&settled).unwrap();
    assert!(
        settle_provider_scenario(
            None,
            Err(memcordon_ci::CiError::Message(
                "restricted peer debt".into()
            ))
        )
        .is_err()
    );
    assert_eq!(prior_record, serde_json::to_value(&ordinary).unwrap());
    let retained = serde_json::to_value(&ordinary).unwrap();
    assert_eq!(
        retained["original_selections"][0]["rows"][0]["private_input"]["file_index"],
        42
    );
    assert_eq!(
        retained["original_selections"][0]["rows"][0]["state"],
        "complete-non-private-mapping"
    );
    assert!(ExperimentSelectionAssessment::assess(vec![]).is_err());
    assert!(ExperimentSelectionAssessment::assess(vec![ordinary.clone()]).is_err());
    assert!(
        ExperimentSelectionAssessment::assess(vec![ordinary.clone(), ordinary.clone()]).is_err()
    );
    let restricted = ScenarioSelectionAssessment::assess(
        ProviderScenario::Restricted,
        vec![selection(false, true), selection(true, true)],
    )
    .unwrap();
    assert_eq!(
        restricted.private_availability(),
        PrivateAvailability::Available
    );
    let assessed = ExperimentSelectionAssessment::assess(vec![ordinary, restricted]).unwrap();
    assert_eq!(
        assessed.private_availability(),
        PrivateAvailability::Unavailable
    );
}

#[test]
fn complete_nonprivate_mapping_is_observed_without_becoming_a_private_image_witness() {
    for peer in [false, true] {
        let (mut value, expected, mut inputs) = image_record(peer);
        let actual: Vec<u16> = r"\Device\HarddiskVolume4\Windows\system32\provider.dll"
            .encode_utf16()
            .collect();
        value["trace"]["returned_images"]["rows"][0]["mapped_path_utf16"] = json!(actual);
        let observed = observe_original_selection(&value, &expected, &inputs).unwrap();
        assert_eq!(observed.pid(), expected.pid);
        assert_eq!(observed.birth(), expected.birth);
        assert_eq!(observed.peer(), peer);
        assert_eq!(
            observed.rows()[0].state,
            OriginalSelectionState::CompleteNonPrivateMapping
        );
        assert_eq!(observed.rows()[0].mapped_path_utf16, actual);
        assert_eq!(observed.rows()[0].private_input.file_index, 42);
        assert_eq!(observed.rows()[0].returned_base, 65536);
        assert!(image_witness(&value, &expected, &inputs).is_err());
        // Configuration is an allowed input set, not a promise that every
        // configured provider is invoked by this one original operation.
        let mut uninvoked = inputs[0].clone();
        uninvoked.original_path.push(b'2' as u16);
        uninvoked.private_native_path.push(b'2' as u16);
        uninvoked.file_index += 1;
        inputs.push(uninvoked);
        assert_eq!(
            observe_original_selection(&value, &expected, &inputs)
                .unwrap()
                .rows()
                .len(),
            1
        );
    }
}

#[test]
fn nonprivate_classification_cannot_hide_invalid_source_mapping_capture_or_original_binding() {
    let (original, expected, inputs) = image_record(false);
    for (pointer, replacement) in [
        (
            "/original_binding/current_effective_token/sha256",
            json!(vec![0; 32]),
        ),
        ("/trace/returned_images/complete", json!(false)),
        (
            "/trace/returned_images/rows/0/original_load/sequence",
            json!(999),
        ),
        (
            "/trace/returned_images/rows/0/original_load/thread_id",
            json!(99),
        ),
        (
            "/trace/returned_images/rows/0/original_load/output_flags",
            json!(1),
        ),
        (
            "/trace/returned_images/rows/0/original_load/native_status_or_adapter_marker",
            json!(-1),
        ),
        (
            "/trace/returned_images/rows/0/allocation_base",
            json!(65537),
        ),
        ("/trace/returned_images/rows/0/memory_type", json!(0)),
        ("/trace/returned_images/rows/0/flags", json!(0)),
        (
            "/trace/returned_images/rows/0/virtual_query_error",
            json!(5),
        ),
        ("/trace/returned_images/rows/0/mapped_name_error", json!(5)),
        ("/trace/returned_images/rows/0/finished_qpc", json!(100)),
        ("/trace/returned_images/rows/0/mapped_path_utf16", json!([])),
        (
            "/trace/returned_images/rows/0/mapped_path_utf16",
            json!([0]),
        ),
        (
            "/trace/returned_images/rows/0/mapped_path_utf16",
            json!(vec![65; 2049]),
        ),
    ] {
        let mut value = original.clone();
        value["trace"]["returned_images"]["rows"][0]["mapped_path_utf16"] = json!(vec![65; 20]);
        *value.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            observe_original_selection(&value, &expected, &inputs).is_err(),
            "{pointer}"
        );
    }
    let mut duplicate = original.clone();
    let row = duplicate["trace"]["returned_images"]["rows"][0].clone();
    duplicate["trace"]["returned_images"]["rows"]
        .as_array_mut()
        .unwrap()
        .push(row);
    assert!(observe_original_selection(&duplicate, &expected, &inputs).is_err());
    let mut unrelated = inputs.clone();
    unrelated[0].original_path.push(b'x' as u16);
    assert!(observe_original_selection(&original, &expected, &unrelated).is_err());
    let mut aliases = inputs.clone();
    aliases.push(inputs[0].clone());
    assert!(observe_original_selection(&original, &expected, &aliases).is_err());
}

#[test]
fn original_root_and_peer_returns_require_bound_tokens_names_and_private_backing() {
    for peer in [false, true] {
        let (value, expected, inputs) = image_record(peer);
        let result = image_witness(&value, &expected, &inputs).unwrap();
        assert_eq!(result["pid"], expected.pid);
        assert_eq!(result["selected"][0]["private_input"]["file_index"], 42);
        assert_eq!(
            result["selected"][0]["private_input"]["sha256"],
            inputs[0].sha256
        );
        assert_eq!(result["continuous_token_equality_proved"], false);
        let mut fallback = value.clone();
        fallback["trace"]
            .as_object_mut()
            .unwrap()
            .remove("dependencies");
        image_witness(&fallback, &expected, &inputs).unwrap();
        let mut mismatched_fallback = fallback.clone();
        mismatched_fallback["trace"]["returned_images"]["rows"][0]["original_load"]["sequence"] =
            json!(999);
        assert!(image_witness(&mismatched_fallback, &expected, &inputs).is_err());
        fallback["trace"]["returned_images"]["rows"][0]
            .as_object_mut()
            .unwrap()
            .remove("original_load");
        assert!(image_witness(&fallback, &expected, &inputs).is_err());
        for (pointer, replacement) in [
            ("/original_binding/pid", json!(999)),
            ("/original_binding/creation_time_100ns", json!(1)),
            (
                "/original_binding/current_effective_token/sha256",
                json!(vec![9u8; 32]),
            ),
            ("/original_binding/current_process_token/error", json!(5)),
            ("/trace/invalid_packet", json!(true)),
            ("/trace/returned_images/complete", json!(false)),
            (
                "/trace/returned_images/rows/0/mapped_path_utf16",
                json!(
                    r"\Device\HarddiskVolume4\Windows\system32\provider.dll"
                        .encode_utf16()
                        .collect::<Vec<_>>()
                ),
            ),
            (
                "/trace/returned_images/rows/0/original_load/name_flags",
                json!(5),
            ),
            (
                "/trace/returned_images/rows/0/original_load/raw_flags",
                json!(8),
            ),
            (
                "/trace/returned_images/rows/0/original_load/output_flags",
                json!(1),
            ),
        ] {
            let mut changed = value.clone();
            *changed.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                image_witness(&changed, &expected, &inputs).is_err(),
                "{pointer}"
            );
        }
        let mut ambiguous = value.clone();
        let original = ambiguous["trace"]["dependencies"]["recent_entries"][0].clone();
        ambiguous["trace"]["dependencies"]["recent_entries"]
            .as_array_mut()
            .unwrap()
            .push(original);
        assert!(image_witness(&ambiguous, &expected, &inputs).is_err());
    }
}

#[test]
fn restricted_mutations_need_every_exact_owned_input_and_security_authority_denial() {
    let paths = [
        r"C:\owned\inputs\fixture.exe",
        r"C:\owned\inputs\fixture.exe.local\provider.dll",
    ]
    .iter()
    .map(|path| {
        hex::encode(Sha256::digest(
            path.encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        ))
    })
    .collect::<Vec<_>>();
    let rows=paths.iter().map(|path|json!({"path_sha256":path,"write_dac_error":5,"write_owner_error":5,
        "write_error":5,"delete_error":32,"rename_error":32,"substitution_error":5,"all_mutations_refused":true})).collect::<Vec<_>>();
    let value = json!({"format":"memcordon.private-provider-input-mutation-probes","revision":1,"pid":100,"peer":false,
        "restricted":true,"performed":true,"complete":true,"rows":rows,
        "directory_authority":[{"write_dac_error":5,"write_owner_error":5},{"write_dac_error":5,"write_owner_error":5}]});
    mutation_witness(&value, 100, false, true, &paths).unwrap();
    for (pointer, replacement) in [
        ("/pid", json!(101)),
        ("/peer", json!(true)),
        ("/complete", json!(false)),
        ("/rows/0/substitution_error", json!(183)),
        ("/rows/0/write_dac_error", json!(32)),
        ("/directory_authority/1/write_owner_error", json!(0)),
        ("/rows/1/path_sha256", json!(paths[0])),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            mutation_witness(&changed, 100, false, true, &paths).is_err(),
            "{pointer}"
        );
    }
    let ordinary = json!({"format":"memcordon.private-provider-input-mutation-probes","revision":1,"pid":100,"peer":false,
        "restricted":false,"performed":false,"complete":false,"state":"not-required-for-ordinary-baseline"});
    mutation_witness(&ordinary, 100, false, false, &paths).unwrap();
    assert!(mutation_witness(&ordinary, 100, false, true, &paths).is_err());
    let file_paths = (0..10)
        .map(|index| hex::encode(Sha256::digest(format!("owned-file-target-{index}"))))
        .collect::<Vec<_>>();
    let mut file_value = value.clone();
    file_value["rows"] = json!(file_paths.iter().map(|path| json!({"path_sha256":path,"write_dac_error":5,"write_owner_error":5,"write_error":5,"delete_error":32,"rename_error":32,"substitution_error":5,"all_mutations_refused":true})).collect::<Vec<_>>());
    file_value["directory_authority"] = json!([{"write_dac_error":5,"write_owner_error":5}]);
    mutation_witness_for_layout(&file_value, 100, false, true, &file_paths, true).unwrap();
    assert!(mutation_witness(&file_value, 100, false, true, &file_paths).is_err());
    let mut missing_marker = file_value.clone();
    missing_marker["rows"].as_array_mut().unwrap().remove(1);
    assert!(
        mutation_witness_for_layout(&missing_marker, 100, false, true, &file_paths, true).is_err()
    );
}

fn provider(id: u32, path: &str) -> CatalogProvider {
    CatalogProvider {
        catalog_id: id,
        provider_id: [id as u8; 16],
        address_family: 2,
        socket_type: 1,
        protocol: 6,
        chain_length: 1,
        chain_entries: vec![id],
        configured_path: "%SystemRoot%\\system32\\provider.dll"
            .encode_utf16()
            .collect(),
        expanded_path: path.encode_utf16().collect(),
    }
}

#[test]
fn expansion_must_equal_the_eventual_declared_system_root_without_ambient_inputs() {
    let mut input = snapshot();
    let root = r"C:\Windows".encode_utf16().collect::<Vec<_>>();
    verify_expansion(&input, &root).unwrap();
    input.matching_providers[0].configured_path =
        "%windir%\\system32\\provider.dll".encode_utf16().collect();
    assert!(verify_expansion(&input, &root).is_err());
    input = snapshot();
    input.matching_providers[0].expanded_path =
        r"D:\Windows\system32\provider.dll".encode_utf16().collect();
    assert!(verify_expansion(&input, &root).is_err());
}
fn snapshot() -> CatalogSnapshot {
    CatalogSnapshot {
        version: 1,
        declaration_sha256: "a".repeat(64),
        complete: true,
        catalog_entries: 14,
        matching_providers: vec![
            provider(1003, r"C:\Windows\system32\provider.dll"),
            provider(1010, r"C:\Windows\system32\provider.dll"),
        ],
    }
}

#[test]
fn complete_same_capability_catalog_coalesces_exact_sources_and_preserves_provider_ids() {
    let input = snapshot();
    let files = select(&input, &input.declaration_sha256).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(
        files[0].expanded_path,
        input.matching_providers[0].expanded_path
    );
    assert_eq!(files[0].catalog_ids, vec![1003, 1010]);
    assert_eq!(files[0].provider_ids.len(), 2);
    assert_eq!(files[0].basename, "provider.dll");
}

#[test]
fn incomplete_foreign_duplicate_and_basename_alias_sets_are_refused() {
    let mut input = snapshot();
    input.complete = false;
    assert!(select(&input, &input.declaration_sha256).is_err());
    input.complete = true;
    assert!(select(&input, &"b".repeat(64)).is_err());
    input.matching_providers[1].catalog_id = 1003;
    assert!(select(&input, &input.declaration_sha256).is_err());
    let mut input = snapshot();
    input.matching_providers[1].expanded_path = r"D:\Other\PROVIDER.dll".encode_utf16().collect();
    assert!(select(&input, &input.declaration_sha256).is_err());
    for path in [
        r"provider.dll",
        r"\\host\share\provider.dll",
        r"C:\Windows\..\provider.dll",
        r"C:\Windows\provider.dll:stream",
        r"C:\Windows\provider.dll.",
        r"C:\Windows\provider.exe",
    ] {
        let mut input = snapshot();
        input.matching_providers = vec![provider(1, path)];
        assert!(select(&input, &input.declaration_sha256).is_err(), "{path}");
    }
    let mut input = snapshot();
    input.matching_providers[0].expanded_path = vec![0xd800];
    assert!(select(&input, &input.declaration_sha256).is_err());
}
