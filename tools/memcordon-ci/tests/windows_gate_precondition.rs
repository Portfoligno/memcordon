#[path = "../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/gate_precondition_input.rs"]
mod control;

use control::{Input, Observation, TokenObservation};
use memcordon_core::WindowsCallerTokenEnvelopeV1;

fn input() -> Input {
    Input {
        revision: 1,
        expected_token: TokenObservation {
            user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
            restricted: true,
            integrity_rid: 8192,
            elevated: false,
            restricting_sids: vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]],
        },
        work_cutoff_qpc: 123456,
        qpc_frequency: 1000,
    }
}

fn envelope() -> WindowsCallerTokenEnvelopeV1 {
    WindowsCallerTokenEnvelopeV1 {
        user_sid: "S-1-5-18".into(),
        owner_sid: "S-1-5-18".into(),
        primary_group_sid: "S-1-5-18".into(),
        groups_sha256: "a".repeat(64),
        privileges_sha256: "b".repeat(64),
        restricted_sids_sha256: "c".repeat(64),
        integrity_level: "S-1-16-8192".into(),
        mandatory_policy: 1,
        session_id: 2,
        elevation_type: 1,
        elevated: false,
        virtualization_allowed: false,
        virtualization_enabled: false,
        ui_access: false,
        appcontainer: false,
        authentication_id: 100,
        token_type: 1,
        impersonation_level: 0,
    }
}

fn observation(opened: bool) -> Observation {
    Observation {
        format: "memcordon.fixture-gate-precondition".into(),
        revision: 1,
        diagnostic_only: true,
        case: serde_json::json!("envelope"),
        challenge_sha256: "d".repeat(64),
        gate_name_utf16_sha256: "e".repeat(64),
        operation: "OpenEventW-pre-handoff-control".into(),
        desired_access: 0x0010_0000,
        attempted: true,
        opened,
        native_error: if opened { None } else { Some(5) },
        original_call_trace: None,
        token: input().expected_token,
        token_envelope: envelope(),
        same_original_event_identity_proved: false,
        acceptance_authority: false,
    }
}

fn validate(observation: &Observation) -> Result<(), String> {
    observation.validate(
        &input(),
        &serde_json::json!("envelope"),
        &"d".repeat(64),
        &"e".repeat(64),
        &envelope(),
    )
}

#[test]
fn compiler_authority_reduction_requires_actual_group_and_privilege_changes() {
    use control::{
        CompilerAuthoritySnapshot, CompilerGroup, CompilerPrivilege,
        validate_compiler_authority_reduction,
    };
    let mut token = input().expected_token;
    token.restricted = false;
    token.restricting_sids.clear();
    token.elevated = true;
    let traversal = CompilerPrivilege {
        luid: [23, 0],
        attributes: 3,
    };
    let administrative = CompilerPrivilege {
        luid: [32, 0],
        attributes: 0,
    };
    let source = CompilerAuthoritySnapshot {
        token,
        authentication_id: [12, 0],
        session_id: 3,
        primary: true,
        administrators_attributes: 7,
        groups: vec![CompilerGroup {
            sid: control::COMPILER_ADMINISTRATORS_SID.to_vec(),
            attributes: 7,
        }],
        privileges: vec![traversal.clone(), administrative.clone()],
        traversal_luid: traversal.luid,
    };
    let mut reduced = source.clone();
    reduced.administrators_attributes = 17;
    reduced.groups[0].attributes = 17;
    reduced.privileges.pop();
    assert!(validate_compiler_authority_reduction(&source, &reduced).is_ok());
    let mut owner_source = source.clone();
    owner_source.administrators_attributes |= 8;
    owner_source.groups[0].attributes |= 8;
    assert!(validate_compiler_authority_reduction(&owner_source, &reduced).is_ok());
    for attributes in [0, 16 | 2, 16 | 4] {
        let mut invalid_admin = reduced.clone();
        invalid_admin.administrators_attributes = attributes;
        invalid_admin.groups[0].attributes = attributes;
        assert!(validate_compiler_authority_reduction(&owner_source, &invalid_admin).is_err());
    }
    assert!(validate_compiler_authority_reduction(&source, &source).is_err());
    assert!(validate_compiler_authority_reduction(&reduced, &reduced).is_err());
    let mut missing_deletion = reduced.clone();
    missing_deletion.privileges.push(administrative);
    assert!(validate_compiler_authority_reduction(&source, &missing_deletion).is_err());
    let mut other_target = reduced.clone();
    other_target.authentication_id = [13, 0];
    assert!(validate_compiler_authority_reduction(&source, &other_target).is_err());
    other_target = reduced.clone();
    other_target.token.user_sid.push(7);
    assert!(validate_compiler_authority_reduction(&source, &other_target).is_err());
    other_target = reduced.clone();
    other_target.privileges.clear();
    assert!(validate_compiler_authority_reduction(&source, &other_target).is_err());

    let token_hash = control::sha256(&serde_json::to_vec(&reduced.token).unwrap());
    let challenge_hash = control::sha256(&[21; 32]);
    let proof = serde_json::json!({
        "effective_token_sha256": token_hash,
        "challenge_sha256": challenge_hash,
        "protected": {"volume_serial": 7, "file_index": 21},
        "protected_write_win32": 5,
        "output_write_verified": true,
        "authority":reduced,
    });
    let parsed: control::CompilerAuthorityProbes = serde_json::from_value(proof.clone()).unwrap();
    assert!(serde_json::to_vec(&parsed).unwrap().len() <= control::COMPILER_AUTHORITY_PROBE_BYTES);
    assert_eq!(serde_json::to_value(&parsed).unwrap(), proof);
    let mut changed = proof;
    changed["administrators_enabled"] = false.into();
    assert!(serde_json::from_value::<control::CompilerAuthorityProbes>(changed).is_err());
    let ordinary_bytes = serde_json::to_vec(&source.token).unwrap();
    let ordinary = serde_json::json!({
        "effective_token_sha256": control::sha256(&ordinary_bytes),
        "challenge_sha256": challenge_hash,
        "protected": {"volume_serial": 7, "file_index": 21},
        "protected_write_verified": true,
        "token": source.token,
        "authority": source,
    });
    let observed: control::CompilerAuthorityOrdinaryControl =
        serde_json::from_value(ordinary.clone()).unwrap();
    assert_eq!(serde_json::to_value(&observed).unwrap(), ordinary);
    assert_eq!(
        [
            control::REDUCED_COMPILER_SENTINEL,
            control::REDUCED_COMPILER_OUTPUT
        ],
        [
            "reduced-compiler-sentinel.bin",
            "reduced-compiler-output.bin"
        ]
    );
}

#[test]
fn reduced_compiler_qualification_preserves_bounded_failure_origin() {
    use control::{CompilerQualificationFailure as Failure, CompilerQualificationStage as Stage};
    for failure in [
        Failure {
            stage: Stage::CreateRestrictedToken,
            win32: Some(87),
            premise: None,
        },
        Failure {
            stage: Stage::EffectiveValidation,
            win32: None,
            premise: Some("reduced compiler target retains deleted privileges".into()),
        },
    ] {
        assert_eq!(
            Failure::parse(&serde_json::to_vec(&failure).unwrap()),
            Some(failure)
        );
    }
    assert!(Failure::parse(&[b' '; control::COMPILER_QUALIFICATION_FAILURE_BYTES + 1]).is_none());
    assert!(Failure::parse(br#"{"stage":"other","win32":7,"premise":null}"#).is_none());
    assert_eq!(
        Failure::held_child_status(b"reduced-compiler-child-exit=2\n", Some(2)),
        Some(2)
    );
    assert_eq!(
        Failure::held_child_status(b"reduced-compiler-child-exit=2\n", Some(3)),
        None
    );
}

#[test]
fn optional_native_trace_never_changes_original_result_or_grants_authority() {
    let mut actual = observation(false);
    actual.original_call_trace = Some(serde_json::json!({
        "context":"pre-handoff-control-child","diagnostic_only":true,
        "acceptance_authority":false,"target_identity_proved":false,
        "called":1,"outer_opened":0,"outer_error":5,"coverage_inconclusive":true
    }));
    validate(&actual).unwrap();
    let bytes = serde_json::to_vec(&actual).unwrap();
    validate(&Observation::parse(&bytes).unwrap()).unwrap();
    for (field, changed) in [
        ("acceptance_authority", serde_json::json!(true)),
        ("target_identity_proved", serde_json::json!(true)),
        ("outer_opened", serde_json::json!(1)),
        ("outer_error", serde_json::json!(0)),
        ("called", serde_json::json!(0)),
    ] {
        let mut bad = actual.clone();
        bad.original_call_trace.as_mut().unwrap()[field] = changed;
        assert!(validate(&bad).is_err());
    }
    actual.original_call_trace.as_mut().unwrap()["extra"] = "x".repeat(24 * 1024).into();
    assert!(validate(&actual).is_err());
}

#[test]
fn success_and_denial_are_distinct_bound_diagnostics_neither_is_authority() {
    assert_eq!(
        control::sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    for opened in [false, true] {
        let actual = observation(opened);
        let bytes = serde_json::to_vec(&actual).unwrap();
        let parsed = Observation::parse(&bytes).unwrap();
        validate(&parsed).unwrap();
        assert_eq!(parsed.opened, opened);
        assert_eq!(parsed.native_error, if opened { None } else { Some(5) });
        assert!(!parsed.same_original_event_identity_proved && !parsed.acceptance_authority);
    }
}

#[test]
fn foreign_bindings_token_changes_and_unsupported_access_cannot_form_a_comparison() {
    let original = serde_json::to_value(observation(false)).unwrap();
    for (pointer, value) in [
        ("/format", serde_json::json!("foreign")),
        ("/revision", serde_json::json!(2)),
        ("/diagnostic_only", serde_json::json!(false)),
        ("/case", serde_json::json!("foreign")),
        ("/challenge_sha256", serde_json::json!("f".repeat(64))),
        ("/gate_name_utf16_sha256", serde_json::json!("f".repeat(64))),
        ("/operation", serde_json::json!("OpenEventW-target")),
        ("/desired_access", serde_json::json!(0)),
        ("/attempted", serde_json::json!(false)),
        ("/opened", serde_json::json!(true)),
        ("/native_error", serde_json::json!(0)),
        ("/native_error", serde_json::json!(-1)),
        ("/native_error", serde_json::Value::Null),
        ("/token/restricted", serde_json::json!(false)),
        ("/token/restricting_sids", serde_json::json!([])),
        ("/token_envelope/session_id", serde_json::json!(3)),
        ("/token_envelope/authentication_id", serde_json::json!(101)),
        (
            "/same_original_event_identity_proved",
            serde_json::json!(true),
        ),
        ("/acceptance_authority", serde_json::json!(true)),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        let parsed = Observation::parse(&serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(validate(&parsed).is_err(), "accepted mutation {pointer}");
    }
}

#[test]
fn bounded_input_and_record_parsing_reject_missing_or_ambiguous_data() {
    let original = serde_json::to_value(input()).unwrap();
    for (pointer, value) in [
        ("/revision", serde_json::json!(0)),
        ("/work_cutoff_qpc", serde_json::json!(0)),
        ("/qpc_frequency", serde_json::json!(0)),
        ("/expected_token/restricted", serde_json::json!(false)),
        ("/expected_token/user_sid", serde_json::json!([])),
        ("/expected_token/user_sid", serde_json::json!(vec![1; 257])),
        ("/expected_token/restricting_sids", serde_json::json!([])),
        (
            "/expected_token/restricting_sids",
            serde_json::json!(vec![vec![1]; 65]),
        ),
        ("/expected_token/restricting_sids", serde_json::json!([[]])),
        (
            "/expected_token/restricting_sids",
            serde_json::json!([vec![1; 257]]),
        ),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            serde_json::from_value::<Input>(changed)
                .unwrap()
                .validate()
                .is_err(),
            "{pointer}"
        );
    }
    assert!(Observation::parse(&vec![b' '; control::RECORD_BYTES + 1]).is_err());
    assert!(Observation::parse(br#"{"revision":1,"revision":1}"#).is_err());
    let mut extra = serde_json::to_value(observation(false)).unwrap();
    extra["invented_authority"] = true.into();
    assert!(Observation::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
    extra.as_object_mut().unwrap().remove("invented_authority");
    extra.as_object_mut().unwrap().remove("attempted");
    assert!(Observation::parse(&serde_json::to_vec(&extra).unwrap()).is_err());
}
