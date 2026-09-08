use super::*;

#[test]
fn authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token() {
    let attempt = "01".repeat(32);
    let request = "02".repeat(32);
    let token = "03".repeat(32);
    let identity = WindowsProcessIdentityV1 {
        process_id: 12,
        creation_time_100ns: 34,
    };
    let record = super::super::record::WindowsAttemptRecordV1::new(
        attempt.clone(),
        request.clone(),
        identity.clone(),
        token.clone(),
        "04".repeat(32),
    )
    .unwrap();
    let binding = || AuthenticatedAttemptBinding {
        attempt_id: attempt.clone(),
        nonce: "authenticated-request-nonce".to_owned(),
        request_sha256: request.clone(),
        process_identity: identity.clone(),
        token_sha256: token.clone(),
    };
    assert!(binding().matches_record(&record));
    let mut wrong = binding();
    wrong.attempt_id = "05".repeat(32);
    assert!(!wrong.matches_record(&record));
    let mut wrong = binding();
    wrong.request_sha256 = "06".repeat(32);
    assert!(!wrong.matches_record(&record));
    let mut wrong = binding();
    wrong.process_identity.process_id += 1;
    assert!(!wrong.matches_record(&record));
    let mut wrong = binding();
    wrong.process_identity.creation_time_100ns += 1;
    assert!(!wrong.matches_record(&record));
    let mut wrong = binding();
    wrong.token_sha256 = "07".repeat(32);
    assert!(!wrong.matches_record(&record));
    assert_eq!(
        record.record_revision, 0,
        "diagnostic binding checks cannot acknowledge or publish"
    );
    assert!(record.terminal_response_json.is_none());
}
