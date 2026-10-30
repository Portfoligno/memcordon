#[path = "private/fixture_namespace_primary_protocol.rs"]
mod protocol;
#[path = "private/fixture_namespace_root_bounds.rs"]
mod root_bounds;
use protocol::*;
#[path = "private/fixture_namespace_replay_protocol.rs"]
mod replay_wire;
use replay_wire::*;
use serde_json::json;
#[path = "private/fixture_namespace_experiment.rs"]
mod experiment;
#[path = "private/fixture_namespace_replay_outcomes.rs"]
mod replay_outcomes;

fn experiment_binding() -> experiment::Binding {
    experiment::Binding {
        initial_identity: (123, 456),
        current_identity: (123, 456),
        token_matches: true,
        default_acl_matches: true,
    }
}
fn experiment_settlement() -> experiment::Settlement {
    experiment::Settlement {
        process_settled: true,
        exit_zero: true,
        identity_stable: true,
        token_and_acl_stable: true,
        event_sd_stable: true,
        thread_stable: true,
        resources_released: true,
        held_identity_and_release_verified: false,
    }
}
#[test]
fn experiment_denial_is_an_original_negative_outcome_not_a_held_capability() {
    let request = request();
    let original = failed(DiagnosticState::NotApplicable);
    let bytes = encode_response(&original).unwrap();
    let outcome = experiment::classify_original(&request, &original, experiment_binding()).unwrap();
    assert_eq!(
        outcome,
        experiment::OriginalOutcome::OriginalEventAccessDenied
    );
    let settled = experiment::complete_cell(outcome, &experiment_settlement()).unwrap();
    assert_eq!(settled, experiment::FinalOutcome::OriginalEventAccessDenied);
    assert!(!settled.scenario_success());
    assert_eq!(encode_response(&original).unwrap(), bytes);
    assert!(!original.success && original.event_handle.is_none());
    // Optional replay/diagnostic availability is never needed to classify original error5.
    let mut unavailable = original.clone();
    unavailable.diagnostics = DiagnosticState::Unavailable {
        reason: DiagnosticUnavailableReason::EncodingBoundOrRefused,
    };
    assert_eq!(
        experiment::classify_original(&request, &unavailable, experiment_binding()).unwrap(),
        outcome
    );
}
#[test]
fn experiment_held_requires_unchanged_live_identity_release_and_settlement_proofs() {
    let mut held = failed(DiagnosticState::NotApplicable);
    held.phase = Phase::Held;
    held.success = true;
    held.raw_error = None;
    held.event_handle = Some(91);
    held.modify_denied = Some(true);
    let outcome = experiment::classify_original(&request(), &held, experiment_binding()).unwrap();
    assert_eq!(outcome, experiment::OriginalOutcome::HeldAwaitingIdentity);
    assert!(experiment::complete_cell(outcome, &experiment_settlement()).is_err());
    let settlement = experiment::Settlement {
        held_identity_and_release_verified: true,
        ..experiment_settlement()
    };
    assert!(
        experiment::complete_cell(outcome, &settlement)
            .unwrap()
            .scenario_success()
    );
    for cell in [
        Cell::NamespaceDenied,
        Cell::EventDenied,
        Cell::WrongBoundary,
    ] {
        let mut request = request();
        request.cell = cell;
        assert!(experiment::classify_original(&request, &held, experiment_binding()).is_err());
    }
}
#[test]
fn experiment_unexpected_errors_and_unbound_responses_remain_fatal() {
    let request = request();
    let original = failed(DiagnosticState::NotApplicable);
    for mutation in 0..9 {
        let mut response = original.clone();
        let mut binding = experiment_binding();
        match mutation {
            0 => response.phase = Phase::Namespace,
            1 => response.raw_error = Some(2),
            2 => response.nonce = "b".repeat(32),
            3 => response.success = true,
            4 => response.event_handle = Some(91),
            5 => binding.current_identity.0 += 1,
            6 => binding.current_identity.1 += 1,
            7 => binding.token_matches = false,
            _ => binding.default_acl_matches = false,
        }
        assert!(experiment::classify_original(&request, &response, binding).is_err());
    }
    let (request, mut diagnostic) = diagnostic_fixture(1);
    if let DiagnosticState::Present { after, .. } = &mut diagnostic {
        after.token.envelope.session_id += 1;
    }
    assert!(
        experiment::classify_original(&request, &failed(diagnostic), experiment_binding()).is_err()
    );
    let mut wrong_boundary = request.clone();
    wrong_boundary.cell = Cell::WrongBoundary;
    let mut zero_error = original;
    zero_error.phase = Phase::Namespace;
    zero_error.raw_error = Some(0);
    assert!(
        experiment::classify_original(&wrong_boundary, &zero_error, experiment_binding()).is_err()
    );
}
#[test]
fn experiment_all_five_cell_results_preserve_controls_and_harness_failure_is_not_an_outcome() {
    for cell in [
        Cell::Local,
        Cell::Private,
        Cell::NamespaceDenied,
        Cell::EventDenied,
        Cell::WrongBoundary,
    ] {
        let mut request = request();
        request.cell = cell;
        let mut response = failed(DiagnosticState::NotApplicable);
        if matches!(cell, Cell::NamespaceDenied | Cell::WrongBoundary) {
            response.phase = Phase::Namespace;
        }
        let outcome =
            experiment::classify_original(&request, &response, experiment_binding()).unwrap();
        assert!(
            !experiment::complete_cell(outcome, &experiment_settlement())
                .unwrap()
                .scenario_success()
        );
        for failed_check in 0..7 {
            let mut settlement = experiment_settlement();
            *match failed_check {
                0 => &mut settlement.process_settled,
                1 => &mut settlement.exit_zero,
                2 => &mut settlement.identity_stable,
                3 => &mut settlement.token_and_acl_stable,
                4 => &mut settlement.event_sd_stable,
                5 => &mut settlement.thread_stable,
                _ => &mut settlement.resources_released,
            } = false;
            assert!(experiment::complete_cell(outcome, &settlement).is_err());
        }
    }
    assert!(
        experiment::complete_cell(
            experiment::OriginalOutcome::OriginalEventAccessDenied,
            &experiment::Settlement {
                held_identity_and_release_verified: true,
                ..experiment_settlement()
            }
        )
        .is_err()
    );
}

fn replay_envelope(request: Request) -> ReplayEnvelope {
    ReplayEnvelope {
        format: "memcordon.namespace-debug-replay".into(),
        revision: 2,
        original_nonce: request.nonce.clone(),
        replay_nonce: "b".repeat(32),
        request_sha256: replay_digest(&request).unwrap(),
        diagnostic_stop_qpc: request.deadline_qpc - 1,
        request,
        source_commit: None,
        run: None,
        attempt: None,
    }
}

#[test]
fn explicit_replay_argv_transport_keeps_original_request_and_deadline_immutable() {
    let request = request();
    let original = encode_request(&request).unwrap();
    let envelope = replay_envelope(request.clone());
    let encoded = encode_replay(&envelope).unwrap();
    assert_eq!(decode_replay(&encoded).unwrap(), envelope);
    assert_eq!(
        encode_request(&decode_replay(&encoded).unwrap().request).unwrap(),
        original
    );
    assert_eq!(
        event_name(&request).unwrap(),
        "owned-alias\\original-event\0"
            .encode_utf16()
            .collect::<Vec<_>>()
    );
    for bad in [
        "".to_owned(),
        "0".to_owned(),
        encoded.to_uppercase(),
        format!("{encoded}00"),
    ] {
        assert!(decode_replay(&bad).is_err());
    }
    for field in 0..5 {
        let mut bad = envelope.clone();
        match field {
            0 => bad.request.deadline_qpc -= 1,
            1 => bad.request_sha256 = "0".repeat(64),
            2 => bad.original_nonce = "c".repeat(32),
            3 => bad.replay_nonce = bad.original_nonce.clone(),
            _ => bad.revision = 1,
        };
        assert!(encode_replay(&bad).is_err());
    }
    let mut exact = vec![65; 32766];
    exact.push(0);
    check_replay_command_line(&exact).unwrap();
    exact.insert(0, 65);
    assert!(check_replay_command_line(&exact).is_err());
    assert!(check_replay_command_line(&[65, 0, 66, 0]).is_err());
}

#[test]
fn replay_result_is_separate_and_never_changes_original_failure_or_ack_semantics() {
    let (request, diagnostics) = diagnostic_fixture(2);
    let original = failed(diagnostics.clone());
    let original_bytes = encode_response(&original).unwrap();
    let envelope = replay_envelope(request);
    let DiagnosticState::Present { before, mut after } = diagnostics else {
        unreachable!()
    };
    after.role = SourceRole::ReplayAfter;
    let result = ReplayResult {
        format: "memcordon.namespace-debug-replay-result".into(),
        revision: 2,
        original_nonce: envelope.original_nonce.clone(),
        replay_nonce: envelope.replay_nonce.clone(),
        diagnostic_stop_qpc: envelope.diagnostic_stop_qpc,
        request_sha256: envelope.request_sha256.clone(),
        outcome: ReplayOutcome::EventReturned {
            event_open: false,
            raw_error: Some(5),
            before: Ok(*before),
            after: ReplayAfter::Observed { observation: after },
        },
        cleanup: ReplayCleanup::Closed,
        diagnostic_only: true,
        acceptance_authority: false,
    };
    let frame = encode_replay_result(&result, &envelope).unwrap();
    let offered = decode_replay_result(&frame, &envelope).unwrap();
    assert!(matches!(
        offered.outcome,
        ReplayOutcome::EventReturned {
            event_open: false,
            raw_error: Some(5),
            ..
        }
    ));
    assert!(decode_response(&frame).is_err());
    assert_eq!(encode_response(&original).unwrap(), original_bytes);
    for changed in 0..4 {
        let mut bad = result.clone();
        match changed {
            0 => bad.acceptance_authority = true,
            1 => bad.replay_nonce = envelope.original_nonce.clone(),
            2 => {
                if let ReplayOutcome::EventReturned { event_open, .. } = &mut bad.outcome {
                    *event_open = true;
                }
            }
            _ => bad.diagnostic_stop_qpc += 1,
        };
        assert!(encode_replay_result(&bad, &envelope).is_err());
    }
    let mut divergence = result;
    if let ReplayOutcome::EventReturned {
        event_open,
        raw_error,
        ..
    } = &mut divergence.outcome
    {
        *event_open = true;
        *raw_error = None;
    }
    assert!(matches!(
        decode_replay_result(
            &encode_replay_result(&divergence, &envelope).unwrap(),
            &envelope
        )
        .unwrap()
        .outcome,
        ReplayOutcome::EventReturned {
            event_open: true,
            ..
        }
    ));
    assert_eq!(encode_response(&original).unwrap(), original_bytes);
}

#[test]
fn replay_source_role_is_rejected_by_original_observation_contract() {
    let (_, mut diagnostics) = diagnostic_fixture(2);
    if let DiagnosticState::Present { after, .. } = &mut diagnostics {
        after.role = SourceRole::ReplayAfter;
    }
    let mut frame = serde_json::to_vec(&failed(diagnostics)).unwrap();
    frame.push(b'\n');
    assert!(decode_response(&frame).is_err());
}

fn module_record() -> ModuleProvenance {
    ModuleProvenance::Present {
        started_qpc: 10,
        finished_qpc: 11,
        diagnostic_only: true,
        acceptance_authority: false,
        import_matches_resolved: true,
        api_set_resolution: ApiSetResolution {
            contract: API_SET_CONTRACT.into(),
            symbol: API_SET_SYMBOL.into(),
            resolution_method: API_SET_METHOD.into(),
            observation: ApiSetObservation::Unavailable {
                stage: ApiSetStage::LoadContract,
                raw_error: Some(126),
                deadline: false,
            },
        },
        modules: [
            ModuleRole::ImportAddress,
            ModuleRole::Kernel32ExportTable,
            ModuleRole::ResolvedExport,
            ModuleRole::NtOpenEvent,
        ]
        .into_iter()
        .map(|role| ModuleLocation {
            role,
            base: 4096,
            address: if role == ModuleRole::Kernel32ExportTable {
                4096
            } else {
                4128
            },
            rva: if role == ModuleRole::Kernel32ExportTable {
                0
            } else {
                32
            },
            path_utf16: "C:\\Windows\\System32\\kernelbase.dll"
                .encode_utf16()
                .collect(),
        })
        .collect(),
    }
}

#[test]
fn passive_module_locations_require_canonical_roles_utf16_and_checked_rvas() {
    let original = module_record();
    original.validate().unwrap();
    let wire = serde_json::to_value(&original).unwrap();
    for (pointer, value) in [
        ("/modules/0/base", json!(0)),
        ("/modules/0/address", json!(1)),
        ("/modules/0/rva", json!(31)),
        ("/modules/0/path_utf16", json!([0])),
        ("/modules/0/path_utf16", json!([0xD800])),
        ("/modules/0/path_utf16", json!([])),
        ("/modules/1/role", json!("import-address-owner")),
        ("/diagnostic_only", json!(false)),
        ("/acceptance_authority", json!(true)),
        ("/import_matches_resolved", json!(false)),
        ("/finished_qpc", json!(9)),
        ("/api_set_resolution/contract", json!("kernelbase.dll")),
        ("/api_set_resolution/symbol", json!("OpenEventA")),
        ("/api_set_resolution/resolution_method", json!("IAT-read")),
    ] {
        let mut invalid = wire.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        let value: ModuleProvenance = serde_json::from_value(invalid).unwrap();
        assert!(value.validate().is_err(), "{pointer}");
    }
    let mut oversized = original.clone();
    if let ModuleProvenance::Present { modules, .. } = &mut oversized {
        modules[0].path_utf16 = vec![65; 32769];
    }
    assert!(oversized.validate().is_err());
    let mut duplicate = original;
    if let ModuleProvenance::Present { modules, .. } = &mut duplicate {
        modules.push(modules[0].clone());
    }
    assert!(duplicate.validate().is_err());
}

#[test]
fn module_frame_bound_preserves_original_error_and_native_handle_custody() {
    let mut response = failed(DiagnosticState::NotApplicable);
    let mut modules = module_record();
    if let ModuleProvenance::Present { modules, .. } = &mut modules {
        for module in modules {
            module.path_utf16 = vec![65; 10000];
        }
    }
    response.native_open = Some(NativeOpen {
        cell: Cell::Private,
        name_utf16: "alias\\self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        inherit: false,
        probe_desired_access: 0,
        namespace_held: true,
        probe: ZeroProbe::Held { handle: 19 },
        native_root: None,
        module_provenance: Some(modules),
    });
    let frame = encode_response(&response).unwrap();
    let decoded = decode_response(&frame).unwrap();
    assert_eq!(decoded.raw_error, response.raw_error);
    assert_eq!(
        decoded.native_open.as_ref().unwrap().probe,
        ZeroProbe::Held { handle: 19 }
    );
    assert!(matches!(
        decoded.native_open.unwrap().module_provenance,
        Some(ModuleProvenance::Unavailable { .. })
    ));
    response.native_open.as_mut().unwrap().module_provenance = Some(module_record());
    let mut old = serde_json::to_value(&response).unwrap();
    old["revision"] = json!(5);
    let mut bytes = serde_json::to_vec(&old).unwrap();
    bytes.push(b'\n');
    assert!(decode_response(&bytes).is_err());
    let mut missing = serde_json::to_value(&response).unwrap();
    missing["native_open"]
        .as_object_mut()
        .unwrap()
        .remove("module_provenance");
    let mut bytes = serde_json::to_vec(&missing).unwrap();
    bytes.push(b'\n');
    assert!(decode_response(&bytes).is_err());
}

#[test]
fn explicit_api_set_resolution_preserves_thunk_uncertainty_and_original_failure() {
    let mut record = module_record();
    if let ModuleProvenance::Present {
        modules,
        api_set_resolution,
        ..
    } = &mut record
    {
        modules.push(ModuleLocation {
            role: ModuleRole::ApiSetOpenEvent,
            base: 8192,
            address: 8224,
            rva: 32,
            path_utf16: "C:\\Windows\\System32\\host.dll".encode_utf16().collect(),
        });
        api_set_resolution.observation = ApiSetObservation::Resolved {
            same_as_original_thunk: false,
        };
    }
    record.validate().unwrap();
    let mut inconsistent = record.clone();
    if let ModuleProvenance::Present {
        api_set_resolution, ..
    } = &mut inconsistent
    {
        api_set_resolution.observation = ApiSetObservation::Resolved {
            same_as_original_thunk: true,
        };
    }
    assert!(inconsistent.validate().is_err());
    if let ModuleProvenance::Present {
        modules,
        api_set_resolution,
        ..
    } = &mut record
    {
        modules[4] = ModuleLocation {
            role: ModuleRole::ApiSetOpenEvent,
            ..modules[0].clone()
        };
        api_set_resolution.observation = ApiSetObservation::Resolved {
            same_as_original_thunk: true,
        };
    }
    record.validate().unwrap();
    let mut response = failed(DiagnosticState::NotApplicable);
    response.native_open = Some(NativeOpen {
        cell: Cell::Private,
        name_utf16: "alias\\self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        inherit: false,
        probe_desired_access: 0,
        namespace_held: true,
        probe: ZeroProbe::Failed { raw_error: 5 },
        native_root: None,
        module_provenance: Some(record),
    });
    for stage in [
        ApiSetStage::LoadContract,
        ApiSetStage::ResolveExport,
        ApiSetStage::ObserveOwner,
    ] {
        let mut unavailable = module_record();
        if let ModuleProvenance::Present {
            api_set_resolution, ..
        } = &mut unavailable
        {
            api_set_resolution.observation = ApiSetObservation::Unavailable {
                stage,
                raw_error: Some(126),
                deadline: true,
            };
        }
        response.native_open.as_mut().unwrap().module_provenance = Some(unavailable);
        let decoded = decode_response(&encode_response(&response).unwrap()).unwrap();
        assert_eq!(decoded.raw_error, Some(5));
        assert!(!decoded.success);
        assert_eq!(decoded.event_handle, None);
        assert_eq!(
            decoded.native_open.unwrap().module_provenance,
            response.native_open.as_ref().unwrap().module_provenance
        );
    }
}

#[test]
fn public_native_type_name_bounds_refuse_foreign_odd_and_overflow_extents() {
    assert!(root_bounds::native_type_name_extent(
        1000, 100, 1020, 18, 20
    ));
    for (pointer, length, maximum) in [
        (999, 18, 20),
        (1021, 18, 20),
        (1020, 19, 20),
        (1020, 22, 20),
        (1090, 18, 20),
        (1020, 0, 0),
    ] {
        assert!(!root_bounds::native_type_name_extent(
            1000, 100, pointer, length, maximum
        ));
    }
    assert!(!root_bounds::native_type_name_extent(
        usize::MAX - 2,
        100,
        usize::MAX - 1,
        4,
        4
    ));
}

#[test]
fn native_relative_event_probe_requires_observed_public_directory_facts() {
    let root = NativeRoot {
        root_handle: 7,
        type_status: Some(0),
        basic_status: Some(0),
        type_name: Some("Directory".into()),
        granted_access: Some(3),
        handle_attributes: Some(0),
        leaf_utf16: "self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        object_attributes: 0,
        open_status: Some(0),
        handle: Some(33),
        unavailable: None,
        reason: None,
        deadline: false,
        native_error: None,
    };
    let mut response = failed(DiagnosticState::NotApplicable);
    response.native_open = Some(NativeOpen {
        cell: Cell::Private,
        name_utf16: "alias\\self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        inherit: false,
        probe_desired_access: 0,
        namespace_held: true,
        probe: ZeroProbe::Failed { raw_error: 5 },
        native_root: Some(root),
        module_provenance: None,
    });
    let bytes = encode_response(&response).unwrap();
    assert_eq!(decode_response(&bytes).unwrap(), response);
    assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
    for (field, bad) in [
        ("type_name", json!("Event")),
        ("type_status", json!(-1)),
        ("basic_status", json!(-1)),
        ("object_attributes", json!(4096)),
        ("desired_access", json!(0)),
        ("handle", json!(0)),
        ("leaf_utf16", json!([92, 65])),
    ] {
        let mut wire = serde_json::to_value(&response).unwrap();
        wire["native_open"]["native_root"][field] = bad;
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        assert!(decode_response(&bytes).is_err(), "{field}");
    }
    for (name, status) in [(None, -1), (Some("Event"), 0), (Some("Directory"), 0)] {
        let root = response
            .native_open
            .as_mut()
            .unwrap()
            .native_root
            .as_mut()
            .unwrap();
        root.type_name = name.map(str::to_owned);
        root.type_status = Some(status);
        root.open_status = None;
        root.handle = None;
        root.unavailable = Some("query-or-open-unavailable".into());
        assert_eq!(
            decode_response(&encode_response(&response).unwrap()).unwrap(),
            response
        );
    }
}

#[test]
fn failed_native_open_probe_has_separate_custody_and_cannot_be_success() {
    let request = request();
    let call = NativeOpen {
        cell: Cell::Private,
        name_utf16: "alias\\self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        inherit: false,
        probe_desired_access: 0,
        namespace_held: true,
        probe: ZeroProbe::Held { handle: 19 },
        native_root: None,
        module_provenance: None,
    };
    for probe in [
        ZeroProbe::Held { handle: 19 },
        ZeroProbe::Failed { raw_error: 5 },
        ZeroProbe::Unavailable { deadline: true },
    ] {
        let mut response = failed(DiagnosticState::NotApplicable);
        response.native_open = Some(NativeOpen {
            probe,
            ..call.clone()
        });
        let bytes = encode_response(&response).unwrap();
        assert_eq!(decode_response(&bytes).unwrap(), response);
        let core = decode_failure_core(&bytes).unwrap();
        assert_eq!(core.raw_error, 5);
        assert_eq!(core.event_handle, None);
        assert!(!core.success);
    }
    let mut response = failed(DiagnosticState::NotApplicable);
    response.native_open = Some(call);
    for (key, value) in [
        ("success", json!(true)),
        ("phase", json!("Held")),
        ("event_handle", json!(7)),
        ("modify_denied", json!(true)),
    ] {
        let mut wire = serde_json::to_value(&response).unwrap();
        wire[key] = value;
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        assert!(decode_response(&bytes).is_err());
    }
    for (key, value) in [
        ("desired_access", json!(0)),
        ("inherit", json!(true)),
        ("name_utf16", json!([0])),
        ("namespace_held", json!(false)),
        ("probe", json!({"state":"held","handle":0})),
        ("name_utf16", json!(vec![65; 2 * NAME_UNITS_BOUND + 2])),
    ] {
        let mut wire = serde_json::to_value(&response).unwrap();
        wire["native_open"][key] = value;
        let mut bytes = serde_json::to_vec(&wire).unwrap();
        bytes.push(b'\n');
        assert!(decode_response(&bytes).is_err());
    }
    assert_ne!(
        encode_ack(&request.nonce).unwrap(),
        encode_probe_ack(&request.nonce).unwrap()
    );
    assert!(encode_probe_ack("wrong-nonce").is_err());
}

fn request() -> Request {
    let user = "S-1-5-21-1-2-3-1001".to_owned();
    Request {
        revision: REVISION,
        nonce: "a".repeat(32),
        cell: Cell::Private,
        alias: "owned-alias".into(),
        boundary: "owned-boundary".into(),
        event: "original-event".into(),
        user_sid: user.clone(),
        deadline_qpc: u64::MAX,
        qpc_frequency: 10_000_000,
        expected_default_acl_sha256: "a".repeat(size_of::<[u8; 32]>() * 2),
        expected_token: memcordon_core::WindowsCallerTokenEnvelopeV1 {
            user_sid: user,
            owner_sid: "S-1-5-32-544".into(),
            primary_group_sid: "S-1-5-21-1-2-3-513".into(),
            groups_sha256: "1".repeat(64),
            privileges_sha256: "2".repeat(64),
            restricted_sids_sha256: "3".repeat(64),
            integrity_level: "S-1-16-12288".into(),
            mandatory_policy: 1,
            session_id: 2,
            elevation_type: 2,
            elevated: true,
            virtualization_allowed: false,
            virtualization_enabled: false,
            ui_access: false,
            appcontainer: false,
            authentication_id: u64::MAX,
            token_type: 1,
            impersonation_level: 0,
        },
    }
}
fn frame(value: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&value).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn all_closed_cells_and_native_observations_roundtrip_without_narrowing() {
    for cell in [
        Cell::Local,
        Cell::Private,
        Cell::NamespaceDenied,
        Cell::EventDenied,
        Cell::WrongBoundary,
    ] {
        let mut value = request();
        value.cell = cell;
        let bytes = encode_request(&value).unwrap();
        assert!(bytes.len() <= FRAME_BOUND);
        assert_eq!(decode_request(&bytes).unwrap(), value);
    }
    for phase in [
        Phase::Primary,
        Phase::Namespace,
        Phase::Event,
        Phase::Held,
        Phase::Completed,
    ] {
        for success in [false, true] {
            if phase == Phase::Held && !success {
                continue;
            }
            let value = Response {
                revision: REVISION,
                nonce: request().nonce,
                phase,
                success,
                raw_error: (!success).then_some(5),
                event_handle: if success && phase == Phase::Held {
                    Some(u64::MAX)
                } else {
                    None
                },
                modify_denied: success.then_some(true),
                diagnostics: DiagnosticState::NotApplicable,
                native_open: None,
            };
            assert_eq!(
                decode_response(&encode_response(&value).unwrap()).unwrap(),
                value
            );
        }
    }
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&encode_ack(&request().nonce).unwrap())
            .unwrap(),
        json!({"revision":REVISION,"nonce":request().nonce})
    );
    assert!(encode_ack("foreign").is_err());
}

#[test]
fn request_admission_rejects_unbound_or_malformed_native_inputs() {
    let original = serde_json::to_value(request()).unwrap();
    for (field, bad) in [
        ("revision", json!(1)),
        ("nonce", json!("A".repeat(32))),
        ("nonce", json!("a".repeat(31))),
        ("cell", json!("Fallback")),
        ("deadline_qpc", json!(0)),
        ("qpc_frequency", json!(0)),
        ("unreviewed", json!(true)),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        assert!(decode_request(&frame(value)).is_err(), "{field}");
    }
    for field in ["alias", "boundary", "event"] {
        for bad in [
            "".to_owned(),
            ".".into(),
            "..".into(),
            "Local\\name".into(),
            "a/b".into(),
            "a\0b".into(),
            "a\nb".into(),
            "x".repeat(NAME_UNITS_BOUND + 1),
            "😀".repeat(NAME_UNITS_BOUND),
        ] {
            let mut value = original.clone();
            value[field] = json!(bad);
            assert!(decode_request(&frame(value)).is_err(), "{field}");
        }
    }
    for bad in [
        "S-1-5",
        "s-1-5-18",
        "S-2-5-18",
        "S-1-05-18",
        "S-1-5-018",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5-1\0",
        "S-1-5--1",
    ] {
        let mut value = original.clone();
        value["user_sid"] = json!(bad);
        assert!(decode_request(&frame(value)).is_err(), "{bad:?}");
    }
    let mut value = request();
    value.alias = "😀".repeat(NAME_UNITS_BOUND / 2);
    assert!(encode_request(&value).is_ok());
    value.alias.push('x');
    assert!(encode_request(&value).is_err());
    let mut mismatch = request();
    mismatch.expected_token.user_sid = "S-1-5-18".into();
    assert!(encode_request(&mismatch).is_err());
    for field in [
        "groups_sha256",
        "privileges_sha256",
        "restricted_sids_sha256",
        "owner_sid",
        "primary_group_sid",
        "integrity_level",
    ] {
        let mut value = original.clone();
        value["expected_token"][field] = json!("malformed");
        assert!(decode_request(&frame(value)).is_err());
    }
}

#[test]
fn frames_refuse_duplicate_unknown_multiple_truncated_and_oversized_data() {
    let encoded = encode_request(&request()).unwrap();
    assert!(decode_request(encoded.strip_suffix(b"\n").unwrap()).is_err());
    let mut multiple = encoded.clone();
    multiple.extend_from_slice(&encoded);
    assert!(decode_request(&multiple).is_err());
    let mut trailing = encoded.clone();
    trailing.push(b'\n');
    assert!(decode_request(&trailing).is_err());
    assert!(decode_request(&vec![b'x'; FRAME_BOUND + 1]).is_err());
    assert!(decode_request(b"{\"revision\":1,\"revision\":1}\n").is_err());
    assert!(decode_request(b"{\xff}\n").is_err());
    let response = Response {
        revision: REVISION,
        nonce: request().nonce,
        phase: Phase::Held,
        success: true,
        raw_error: None,
        event_handle: Some(9),
        modify_denied: Some(true),
        diagnostics: DiagnosticState::NotApplicable,
        native_open: None,
    };
    let original = serde_json::to_value(&response).unwrap();
    for (field, bad) in [
        ("event_handle", json!(0)),
        ("success", json!(false)),
        ("raw_error", json!(5)),
        ("phase", json!("Fallback")),
        ("extra", json!(true)),
        ("revision", json!(0)),
        ("nonce", json!("unbound")),
    ] {
        let mut value = original.clone();
        value[field] = bad;
        assert!(decode_response(&frame(value)).is_err(), "{field}");
    }
    assert!(decode_response(b"{\"success\":true,\"success\":false}\n").is_err());
    for field in [
        "revision",
        "nonce",
        "phase",
        "success",
        "raw_error",
        "event_handle",
        "modify_denied",
        "diagnostics",
    ] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(decode_response(&frame(value)).is_err(), "missing {field}");
    }
}

fn diagnostic_fixture(count: usize) -> (Request, DiagnosticState) {
    try_diagnostic_fixture(count).unwrap()
}
fn try_diagnostic_fixture(count: usize) -> Option<(Request, DiagnosticState)> {
    use memcordon_windows_launch_core::*;
    let mut request = request();
    let normal = vec![
        SidAttributesV1 {
            sid: "S-1-5-32-544".into(),
            attributes: 4
        };
        count
    ];
    let restricted = vec![SidAttributesV1 {
        sid: "S-1-5-12".into(),
        attributes: 4,
    }];
    let privileges = vec![PrivilegeAttributesV1 {
        luid_high: i32::MIN,
        luid_low: u32::MAX,
        attributes: u32::MAX,
    }];
    request.expected_token.groups_sha256 = sid_attributes_digest(&normal).unwrap();
    request.expected_token.restricted_sids_sha256 = sid_attributes_digest(&restricted).unwrap();
    request.expected_token.privileges_sha256 = privilege_attributes_digest(&privileges).unwrap();
    let stats = TokenStatisticsObservationV1 {
        token_id: u64::MAX,
        modified_id: u64::MAX - 1,
        expiration_time: i64::MIN,
        dynamic_charged: u32::MAX,
        dynamic_available: u32::MAX,
        group_count: count as u32,
        privilege_count: 1,
    };
    let token = TokenObservationV1::from_parts(
        request.expected_token.clone(),
        u32::MAX,
        stats,
        normal,
        restricted,
        privileges,
    )
    .ok()?;
    request.expected_default_acl_sha256 = acl_hash(&None);
    let before = SourceObservation {
        role: SourceRole::BeforeOpen,
        started_qpc: 10,
        finished_qpc: 20,
        token: token.clone(),
        default_acl_sha256: request.expected_default_acl_sha256.clone(),
        default_acl_bytes: None,
        no_thread_token_raw_error: 1008,
    };
    let after = SourceObservation {
        role: SourceRole::AfterFailedOpen,
        started_qpc: 30,
        finished_qpc: 40,
        token,
        default_acl_sha256: request.expected_default_acl_sha256.clone(),
        default_acl_bytes: None,
        no_thread_token_raw_error: 1008,
    };
    Some((
        request,
        DiagnosticState::Present {
            before: Box::new(before),
            after: Box::new(after),
        },
    ))
}
fn failed(diagnostics: DiagnosticState) -> Response {
    Response {
        revision: REVISION,
        nonce: request().nonce,
        phase: Phase::Event,
        success: false,
        raw_error: Some(5),
        event_handle: None,
        modify_denied: None,
        diagnostics,
        native_open: None,
    }
}
fn acl_hash(bytes: &Option<Vec<u8>>) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(serde_json::to_vec(bytes).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn complete_diagnostics_join_each_original_collection_to_expected_source_without_atomic_claim() {
    let (request, diagnostics) = diagnostic_fixture(2);
    diagnostics.validate_correspondence(&request).unwrap();
    let original = failed(diagnostics.clone());
    let wire = encode_response(&original).unwrap();
    let observed = decode_response(&wire).unwrap();
    assert_eq!(observed, original);
    observed
        .diagnostics
        .validate_correspondence(&request)
        .unwrap();
    for field in [
        "role",
        "started_qpc",
        "finished_qpc",
        "default_acl_sha256",
        "no_thread_token_raw_error",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["diagnostics"]["after"][field] = match field {
            "role" => json!("before-open"),
            "started_qpc" => json!(1),
            "finished_qpc" => json!(0),
            "default_acl_sha256" => json!("wrong"),
            _ => json!(5),
        };
        assert!(decode_response(&frame(value)).is_err(), "{field}");
    }
    let mut changed = request.clone();
    changed.deadline_qpc = 40;
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut changed = request.clone();
    changed.expected_token.session_id ^= 1;
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut changed = request.clone();
    changed.expected_default_acl_sha256 = "0".repeat(64);
    assert!(diagnostics.validate_correspondence(&changed).is_err());
    let mut malformed = serde_json::to_value(&original).unwrap();
    malformed["diagnostics"]["before"]["token"]["normal_groups"][0]["attributes"] = json!(16);
    let bytes = frame(malformed);
    assert!(decode_response(&bytes).is_err());
    let core = decode_failure_core(&bytes).unwrap();
    assert_eq!(core.raw_error, 5);
    assert_eq!(core.nonce, request.nonce);
    assert!(!core.success && !core.diagnostics_validated && !core.full_frame_canonical_validated);
    assert_eq!(core.frame_bytes, bytes.len());
}

#[test]
fn optional_diagnostic_refusal_preserves_failure_core_but_never_admits_success() {
    let (_, diagnostics) = diagnostic_fixture(1);
    let original = failed(diagnostics);
    let mut malformed = original.clone();
    if let DiagnosticState::Present { before, .. } = &mut malformed.diagnostics {
        before.token.user_attributes ^= 1;
        before.no_thread_token_raw_error = 5;
    }
    let fallback = decode_response(&encode_response(&malformed).unwrap()).unwrap();
    assert_eq!(fallback.raw_error, Some(5));
    assert_eq!(fallback.phase, Phase::Event);
    assert!(!fallback.success);
    assert!(matches!(
        fallback.diagnostics,
        DiagnosticState::Unavailable {
            reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
        }
    ));
    for diagnostic in [
        None,
        Some(json!({"state":"present","before":"broken","after":null})),
        Some(json!({"state":"not-applicable","unexpected":true})),
        Some(
            json!({"state":"unavailable","reason":{"kind":"encoding-bound-or-refused","unexpected":true}}),
        ),
        Some(
            json!({"state":"unavailable","reason":{"kind":"observation","role":"before-open","reason":"count-bound","unexpected":true}}),
        ),
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        if let Some(diagnostic) = diagnostic {
            value["diagnostics"] = diagnostic;
        } else {
            value.as_object_mut().unwrap().remove("diagnostics");
        }
        let bytes = frame(value);
        assert!(decode_response(&bytes).is_err());
        assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
    }
    let mut success = original.clone();
    success.phase = Phase::Held;
    success.success = true;
    success.raw_error = None;
    success.event_handle = Some(u64::MAX);
    success.diagnostics = DiagnosticState::NotApplicable;
    assert_eq!(
        decode_response(&encode_response(&success).unwrap()).unwrap(),
        success
    );
    let mut invalid = serde_json::to_value(&success).unwrap();
    invalid["diagnostics"] = json!({"state":"not-applicable","unexpected":true});
    let bytes = frame(invalid);
    assert!(decode_response(&bytes).is_err());
    assert!(decode_failure_core(&bytes).is_err());
    let mut invalid = serde_json::to_value(&success).unwrap();
    invalid["diagnostics"] = json!({"state":"present"});
    let bytes = frame(invalid);
    assert!(decode_response(&bytes).is_err());
    assert!(decode_failure_core(&bytes).is_err());
    success.diagnostics = original.diagnostics.clone();
    assert!(encode_response(&success).is_err());
    for (field, value) in [
        ("revision", json!(1)),
        ("nonce", json!("wrong")),
        ("success", json!(true)),
        ("raw_error", json!(null)),
        ("event_handle", json!(1)),
        ("modify_denied", json!(false)),
        ("phase", json!("Completed")),
        ("unknown", json!(true)),
    ] {
        let mut value_json = serde_json::to_value(&original).unwrap();
        value_json[field] = value;
        assert!(decode_failure_core(&frame(value_json)).is_err(), "{field}");
    }
}

#[test]
fn two_complete_observations_exceeding_original_frame_become_wholly_unavailable() {
    let (_, diagnostics) = (1..=memcordon_windows_launch_core::TOKEN_OBSERVATION_ENTRY_BOUND)
        .filter_map(try_diagnostic_fixture)
        .next_back()
        .unwrap();
    let mut original = failed(diagnostics);
    original.native_open = Some(NativeOpen {
        cell: Cell::Private,
        name_utf16: "alias\\self".encode_utf16().collect(),
        desired_access: 0x0010_0000,
        inherit: false,
        probe_desired_access: 0,
        namespace_held: true,
        probe: ZeroProbe::Held { handle: 19 },
        native_root: None,
        module_provenance: None,
    });
    let oversized = serde_json::to_vec(&original).unwrap();
    assert!(oversized.len() + b"\n".len() > FRAME_BOUND);
    let bytes = encode_response(&original).unwrap();
    assert!(bytes.len() <= FRAME_BOUND);
    let projected = decode_response(&bytes).unwrap();
    assert_eq!(projected.raw_error, original.raw_error);
    assert_eq!(projected.nonce, original.nonce);
    assert_eq!(projected.phase, original.phase);
    assert_eq!(projected.success, original.success);
    assert_eq!(
        projected.native_open, original.native_open,
        "fallback must preserve diagnostic handle custody"
    );
    assert!(matches!(
        projected.diagnostics,
        DiagnosticState::Unavailable {
            reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
        }
    ));
    assert!(
        matches!(original.diagnostics, DiagnosticState::Present { .. }),
        "source complete vectors must not be trimmed or mutated"
    );
    let mut oversized = oversized;
    oversized.push(b'\n');
    assert!(decode_response(&oversized).is_err());
    assert!(decode_failure_core(&oversized).is_err());
}

#[test]
fn default_acl_raw_preimage_is_required_lossless_and_not_a_semantic_acl_verdict() {
    let empty_acl = vec![2, 0, 8, 0, 0, 0, 0, 0];
    let mut allow_rc = vec![2, 0, 28, 0, 1, 0, 0, 0, 0, 0, 20, 0, 0, 0, 16, 0];
    allow_rc.extend([1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]);
    let mut digests = std::collections::BTreeSet::new();
    // Some(empty Vec) is a raw-preimage distinction, not an admitted native ACL.
    // Native collection supplies its own existing ACL extent admission.
    for bytes in [None, Some(vec![]), Some(empty_acl), Some(allow_rc)] {
        let (mut request, mut diagnostics) = diagnostic_fixture(1);
        let digest = acl_hash(&bytes);
        assert!(digests.insert(digest.clone()));
        request.expected_default_acl_sha256 = digest.clone();
        if let DiagnosticState::Present { before, after } = &mut diagnostics {
            for source in [before, after] {
                source.default_acl_bytes = bytes.clone();
                source.default_acl_sha256 = digest.clone();
            }
        }
        diagnostics.validate_correspondence(&request).unwrap();
        let original = failed(diagnostics);
        let encoded = encode_response(&original).unwrap();
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded, original);
        if let DiagnosticState::Present { before, after } = decoded.diagnostics {
            assert_eq!(before.default_acl_bytes, bytes);
            assert_eq!(after.default_acl_bytes, bytes);
        }
        for altered in [
            serde_json::json!("not-an-array"),
            serde_json::json!([256]),
            serde_json::json!([1, 2, 3]),
        ] {
            let mut wire = serde_json::to_value(&original).unwrap();
            wire["diagnostics"]["before"]["default_acl_bytes"] = altered;
            let bytes = frame(wire);
            assert!(decode_response(&bytes).is_err());
            assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
        }
        let mut missing = serde_json::to_value(&original).unwrap();
        missing["diagnostics"]["before"]
            .as_object_mut()
            .unwrap()
            .remove("default_acl_bytes");
        let bytes = frame(missing);
        assert!(decode_response(&bytes).is_err());
        assert_eq!(decode_failure_core(&bytes).unwrap().raw_error, 5);
    }
    for length in [64 * 1024, 64 * 1024 + 1] {
        let (_, mut diagnostics) = diagnostic_fixture(1);
        if let DiagnosticState::Present { before, after } = &mut diagnostics {
            for source in [before, after] {
                source.default_acl_bytes = Some(vec![0; length]);
                source.default_acl_sha256 = acl_hash(&source.default_acl_bytes);
            }
        }
        let encoded = encode_response(&failed(diagnostics)).unwrap();
        assert!(encoded.len() <= FRAME_BOUND);
        let decoded = decode_response(&encoded).unwrap();
        assert_eq!(decoded.raw_error, Some(5));
        assert!(matches!(
            decoded.diagnostics,
            DiagnosticState::Unavailable {
                reason: DiagnosticUnavailableReason::EncodingBoundOrRefused
            }
        ));
    }
}
