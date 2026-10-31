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
        fixture_pid: 123,
        fixture_birth: 456,
        guardian: Some((42, 777)),
        guardian_query_failed: true,
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
fn incomplete_cleanup_missing_original_holder_or_query_observation_never_promotes_a_record() {
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
    assert!(!matches!(
        callback_failure(query(bytes.clone(), true, Ok(())), Some(&expected)),
        CiError::LaneFailures { .. }
    ));
    expected.guardian_query_failed = true;
    expected.fixture_pid = 0;
    assert!(!matches!(
        callback_failure(query(bytes, true, Ok(())), Some(&expected)),
        CiError::LaneFailures { .. }
    ));
}
