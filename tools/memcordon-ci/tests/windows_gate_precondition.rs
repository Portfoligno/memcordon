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
