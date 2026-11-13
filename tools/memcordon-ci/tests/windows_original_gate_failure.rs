use memcordon_ci::{
    CiError,
    windows_original_gate_failure::{Expected, callback_failure},
};
use memcordon_testkit::ProcessTestError;
use serde_json::{Value, json};

const CHALLENGE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NAME: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn expected(case: &Value) -> Expected<'_> {
    Expected {
        case,
        challenge_sha256: CHALLENGE,
        gate_name_utf16_sha256: NAME,
        fixture: Some((123, 456)),
        guardian: Some((42, 777)),
        guardian_query_failed: true,
        pre_handoff_control: None,
    }
}
fn record() -> Value {
    json!({"format":"memcordon.original-gate-failure-before-control","revision":1,
        "diagnostic_only":true,"operation":"OpenEventW-controller-wait","desired_access":0x00100000,
        "original_raw_os_error":5,"original_kind":"PermissionDenied","control":"pending",
        "binding":{"case":"envelope","challenge_sha256":CHALLENGE,"gate_name_utf16_sha256":NAME,"next_transcript_sequence":2}})
}
fn line(value: &Value) -> Vec<u8> {
    let mut bytes = b"original-gate-failure-before-control ".to_vec();
    bytes.extend(serde_json::to_vec(value).unwrap());
    bytes.push(b'\n');
    bytes
}
fn query(stderr: Vec<u8>, complete: bool, cleanup: Result<(), String>) -> ProcessTestError {
    ProcessTestError::Callback {
        error: std::io::Error::other("original guardian process already signaled; query-status=1"),
        stdout: b"original stdout".to_vec(),
        stderr,
        capture_complete: complete,
        observed_status: None,
        termination: None,
        cleanup,
    }
}
fn original(error: &CiError) -> &ProcessTestError {
    match error {
        CiError::Context { source, .. } => original(source),
        CiError::LaneFailures { secondary, .. } => original(secondary),
        CiError::Process(error) => error,
        other => panic!("original typed process failure was lost: {other}"),
    }
}
fn assert_original(error: &CiError, bytes: &[u8]) {
    match original(error) {
        ProcessTestError::Callback {
            error,
            stdout,
            stderr,
            ..
        } => {
            assert!(
                error
                    .to_string()
                    .contains("original guardian process already signaled")
            );
            assert_eq!(stdout, b"original stdout");
            assert_eq!(stderr, bytes);
        }
        _ => panic!("original callback variant changed"),
    }
}

#[test]
fn preadmission_start_failure_surfaces_bounded_original_stderr_without_inventing_gate_cause() {
    let stderr=b"memcordon-test-fixture: terminal transport DuplicateHandle own-thread reference: OS Error 5\n".to_vec();
    let failure = callback_failure(query(stderr.clone(), true, Ok(())), None);
    assert_original(&failure, &stderr);
    let text = failure.to_string();
    assert!(text.contains("original fixture callback failure"));
    assert!(text.contains("DuplicateHandle own-thread reference"));
    assert!(!text.contains("original captured gate failure"));
    let mut large = stderr.clone();
    large.extend(vec![b'x'; 16 * 1024]);
    large.extend(b"original terminal tail\xff");
    let failure = callback_failure(
        query(
            large.clone(),
            false,
            Err("original cleanup unproved".into()),
        ),
        None,
    );
    assert_original(&failure, &large);
    let text = failure.to_string();
    assert!(text.contains("DuplicateHandle own-thread reference"));
    assert!(text.contains("original terminal tail"));
    assert!(text.contains("capture-complete=false"));
    assert!(text.contains("omitted-bytes="));
    assert!(text.len() < 4 * 1024 * 6 + 2048);
}

#[test]
fn complete_middle_trace_and_escaped_binary_excerpt_preserve_original_capture() {
    let mut stderr = vec![b'a'; 1024];
    stderr.extend_from_slice(b"original-startup-trace-middle");
    stderr.resize(2086, b'z');
    let failure = callback_failure(query(stderr.clone(), true, Ok(())), None);
    assert_original(&failure, &stderr);
    assert!(
        failure
            .to_string()
            .contains("original-startup-trace-middle")
    );
    assert!(!failure.to_string().contains("omitted-bytes="));
    for byte in [0x1b, 0xff] {
        let stderr = vec![byte; 32 * 1024];
        let failure = callback_failure(query(stderr.clone(), false, Ok(())), None);
        assert_original(&failure, &stderr);
        let text = failure.to_string();
        assert!(text.contains("original-stderr-bytes=32768"));
        assert!(text.contains("omitted-bytes=28672"));
        // Debug escaping needs at most six rendered bytes per retained raw byte.
        assert!(text.len() < 4 * 1024 * 6 + 2048);
    }
}

#[test]
fn bound_original_failure_leads_without_claiming_an_authenticated_target_association() {
    let case = json!("envelope");
    let expected = expected(&case);
    let bytes = line(&record());
    let error = callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected));
    assert_original(&error, &bytes);
    match &error {
        CiError::LaneFailures { primary, secondary } => {
            assert!(matches!(**primary, CiError::SettledCommandFailure(_)));
            let primary = primary.to_string();
            assert!(
                primary.contains("OpenEventW-controller-wait")
                    && primary.contains("raw-os-error=5")
            );
            assert!(primary.contains("controller-held-fixture-pid=123"));
            assert!(primary.contains("target-association=unavailable-after-failed-query"));
            assert!(
                secondary
                    .to_string()
                    .contains("controller-held-guardian=Some((42, 777))")
            );
        }
        _ => panic!("matching original failure was not leading context"),
    }
    assert!(!memcordon_ci::work_outcome::has_unresolved_owner(&error));
    let doubled = [bytes.as_slice(), bytes.as_slice()].concat();
    assert!(matches!(
        callback_failure(query(doubled, true, Ok(())), Some(&expected)),
        CiError::LaneFailures { .. }
    ));
}

#[test]
fn foreign_bindings_and_unsupported_operations_never_replace_the_query_failure() {
    let case = json!("envelope");
    let expected = expected(&case);
    for (pointer, wrong) in [
        ("/binding/challenge_sha256", json!(NAME)),
        ("/binding/gate_name_utf16_sha256", json!(CHALLENGE)),
        ("/binding/case", json!("other-case")),
        ("/desired_access", json!(0x1f0003)),
        ("/operation", json!("NtOpenEvent")),
        ("/revision", json!(2)),
        ("/diagnostic_only", json!(false)),
        ("/original_raw_os_error", Value::Null),
    ] {
        let mut value = record();
        *value.pointer_mut(pointer).unwrap() = wrong;
        let bytes = line(&value);
        let error = callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected));
        assert!(matches!(error, CiError::Context { .. }));
        assert_original(&error, &bytes);
        assert!(error.to_string().contains("diagnostic unavailable"));
    }
}

#[test]
fn malformed_truncated_duplicate_conflicting_and_oversized_records_are_inconclusive() {
    let case = json!("envelope");
    let expected = expected(&case);
    let valid = line(&record());
    let mut conflict = record();
    conflict["original_raw_os_error"] = 6.into();
    let wire = serde_json::to_string(&record()).unwrap();
    let duplicate = format!(
        "original-gate-failure-before-control {{\"revision\":1,{}\n",
        wire.strip_prefix('{').unwrap()
    )
    .into_bytes();
    let mut oversized = b"original-gate-failure-before-control ".to_vec();
    oversized.extend(vec![b'x'; 2049]);
    oversized.push(b'\n');
    for bytes in [
        b"ordinary query stderr\n".to_vec(),
        b"original-gate-failure-before-control {broken}\n".to_vec(),
        valid[..valid.len() - 1].to_vec(),
        duplicate,
        [valid.as_slice(), line(&conflict).as_slice()].concat(),
        oversized,
    ] {
        let error = callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected));
        assert!(matches!(error, CiError::Context { .. }));
        assert_original(&error, &bytes);
    }
}

#[test]
fn incomplete_cleanup_remains_unproved_but_missing_owner_is_explicit_diagnostic_context() {
    let case = json!("envelope");
    let mut expected = expected(&case);
    let bytes = line(&record());
    for error in [
        query(bytes.clone(), false, Ok(())),
        query(
            bytes.clone(),
            true,
            Err("original cleanup unresolved".into()),
        ),
    ] {
        let error = callback_failure(error, Some(&expected));
        assert_original(&error, &bytes);
        assert!(!matches!(error, CiError::LaneFailures { .. }));
        assert!(memcordon_ci::work_outcome::has_unresolved_owner(&error));
    }
    let error = callback_failure(query(bytes.clone(), true, Ok(())), None);
    assert_original(&error, &bytes);
    expected.guardian_query_failed = false;
    assert!(matches!(
        callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected)),
        CiError::LaneFailures { .. }
    ));
    expected.fixture = None;
    let unowned = callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected));
    assert_original(&unowned, &bytes);
    let text = unowned.to_string();
    assert!(text.contains("controller-held-target=unavailable"));
    assert!(text.contains("target-association=unavailable"));
    assert!(text.contains("acceptance-authority=false"));
    assert!(!text.contains("controller-held-fixture-pid="));
    expected.guardian_query_failed = true;
    expected.fixture = Some((0, 456));
    assert!(!matches!(
        callback_failure(query(bytes, true, Ok(())), Some(&expected)),
        CiError::LaneFailures { .. }
    ));
}

#[test]
fn retirement_owner_absence_live_observation_and_query_failure_stay_distinct_errors() {
    use memcordon_ci::windows_original_gate_failure::retired_family;
    let missing = retired_family(Vec::<std::io::Result<bool>>::new()).unwrap_err();
    assert!(missing.to_string().contains("ownership unavailable"));
    assert!(!missing.to_string().contains("remains live"));
    let live = retired_family([Ok(true), Ok(false)]).unwrap_err();
    assert!(live.to_string().contains("remains live; member-index=1"));
    let query = retired_family([Err(std::io::Error::from_raw_os_error(5))]).unwrap_err();
    assert!(query.to_string().contains("query failed"));
    assert_eq!(
        query
            .get_ref()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(5)
    );
    retired_family([Ok(true), Ok(true)]).unwrap();
}

fn control_pair(
    opened: bool,
) -> (
    Value,
    Value,
    memcordon_ci::windows_consumer_readiness::descriptor::gate_precondition::Input,
) {
    use memcordon_ci::windows_consumer_readiness::descriptor::gate_precondition::{
        Input, TokenObservation,
    };
    let token = TokenObservation {
        user_sid: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        restricted: true,
        integrity_rid: 8192,
        elevated: false,
        restricting_sids: vec![vec![1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]],
    };
    let envelope = json!({"user_sid":"S-1-5-18","owner_sid":"S-1-5-18","primary_group_sid":"S-1-5-18",
        "groups_sha256":"a".repeat(64),"privileges_sha256":"b".repeat(64),"restricted_sids_sha256":"c".repeat(64),
        "integrity_level":"S-1-16-8192","mandatory_policy":1,"session_id":2,"elevation_type":1,"elevated":false,
        "virtualization_allowed":false,"virtualization_enabled":false,"ui_access":false,"appcontainer":false,
        "authentication_id":100,"token_type":1,"impersonation_level":0});
    let controller = json!({"format":"memcordon.fixture-gate-precondition-controller","revision":1,"diagnostic_only":true,
        "case":"envelope","challenge_sha256":CHALLENGE,"gate_name_utf16_sha256":NAME,"expected_token_envelope":envelope,
        "child_pid":321,"child_exit_status":0,"child_settled":true,"same_retained_primary_token_input":true,
        "source_token_stable_identity_security_unchanged":true,"selected_token_stable_identity_security_unchanged":true,
        "same_original_event_identity_proved":false,"acceptance_authority":false});
    let child = json!({"format":"memcordon.fixture-gate-precondition","revision":1,"diagnostic_only":true,"case":"envelope",
        "challenge_sha256":CHALLENGE,"gate_name_utf16_sha256":NAME,"operation":"OpenEventW-pre-handoff-control",
        "desired_access":0x100000,"attempted":true,"opened":opened,"native_error":if opened {None}else{Some(5)},
        "token":token,"token_envelope":envelope,"same_original_event_identity_proved":false,"acceptance_authority":false});
    (
        controller,
        child,
        Input {
            revision: 1,
            expected_token: token,
            work_cutoff_qpc: 1000,
            qpc_frequency: 10,
        },
    )
}

#[test]
fn settled_same_input_control_is_context_not_target_ownership_or_success() {
    use memcordon_ci::windows_original_gate_failure::control_summary;
    let case = json!("envelope");
    for opened in [false, true] {
        let (controller, child, input) = control_pair(opened);
        let summary = control_summary(
            &serde_json::to_vec(&controller).unwrap(),
            &serde_json::to_vec(&child).unwrap(),
            &input,
            &case,
            CHALLENGE,
            NAME,
        )
        .unwrap();
        assert!(summary.contains("independent-control-child=321"));
        assert!(summary.contains("same-original-event-identity-proved=false"));
        assert!(summary.contains("acceptance-authority=false"));
        assert!(summary.contains(&format!("opened={opened}")));
        let mut expected = expected(&case);
        expected.fixture = None;
        expected.guardian_query_failed = false;
        expected.pre_handoff_control = Some(&summary);
        let bytes = line(&record());
        let failure = callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected));
        assert_original(&failure, &bytes);
        assert!(
            failure
                .to_string()
                .contains("controller-held-target=unavailable")
        );
        assert!(
            failure
                .to_string()
                .contains("independent-control-child=321")
        );
        assert!(matches!(failure, CiError::LaneFailures { .. }));
    }
    let oversized = "untrusted-control-summary".repeat(300);
    let mut expected = expected(&case);
    expected.fixture = None;
    expected.pre_handoff_control = Some(&oversized);
    let failure = callback_failure(query(line(&record()), true, Ok(())), Some(&expected));
    assert!(
        failure
            .to_string()
            .contains("control-summary-exceeds-bound")
    );
    assert!(!failure.to_string().contains(&oversized));
}

#[test]
fn control_context_rejects_foreign_binding_token_mismatch_and_unsettled_records() {
    use memcordon_ci::windows_original_gate_failure::control_summary;
    let (controller, child, input) = control_pair(false);
    let case = json!("envelope");
    let check = |controller: &Value, child: &Value| {
        control_summary(
            &serde_json::to_vec(controller).unwrap(),
            &serde_json::to_vec(child).unwrap(),
            &input,
            &case,
            CHALLENGE,
            NAME,
        )
    };
    for (pointer, value) in [
        ("/case", json!("other")),
        ("/challenge_sha256", json!(NAME)),
        ("/gate_name_utf16_sha256", json!(CHALLENGE)),
        ("/child_pid", json!(0)),
        ("/child_exit_status", json!(1)),
        ("/child_settled", json!(false)),
        ("/same_retained_primary_token_input", json!(false)),
        (
            "/source_token_stable_identity_security_unchanged",
            json!(false),
        ),
        (
            "/selected_token_stable_identity_security_unchanged",
            json!(false),
        ),
        ("/acceptance_authority", json!(true)),
        ("/same_original_event_identity_proved", json!(true)),
        ("/expected_token_envelope/session_id", json!(3)),
    ] {
        let mut changed = controller.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(check(&changed, &child).is_err(), "{pointer}");
    }
    for (pointer, value) in [
        ("/token/restricted", json!(false)),
        ("/token_envelope/groups_sha256", json!("d".repeat(64))),
        ("/challenge_sha256", json!(NAME)),
        ("/native_error", Value::Null),
    ] {
        let mut changed = child.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(check(&controller, &changed).is_err(), "{pointer}");
    }
    assert!(control_summary(&vec![b'x'; 65537], b"{}", &input, &case, CHALLENGE, NAME).is_err());
    let bytes = serde_json::to_string(&controller).unwrap();
    let duplicate = format!("{{\"revision\":1,{}", bytes.strip_prefix('{').unwrap());
    assert!(
        control_summary(
            duplicate.as_bytes(),
            &serde_json::to_vec(&child).unwrap(),
            &input,
            &case,
            CHALLENGE,
            NAME
        )
        .is_err()
    );
}
