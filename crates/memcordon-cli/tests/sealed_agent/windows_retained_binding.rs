use super::*;

#[test]
fn observed_relay_error_never_revises_the_original_record_or_relaxes_credentials() {
    let caller = super::super::readiness_receipt::HeldNativeProcess::open(std::process::id());
    let attempt = "01".repeat(32);
    let request = "02".repeat(32);
    let token = "03".repeat(32);
    let nonce = "original-relay-nonce";
    let mut record = super::super::record::WindowsAttemptRecordV1::new(
        attempt.clone(),
        request.clone(),
        caller.identity.clone(),
        token.clone(),
        "04".repeat(32),
    )
    .unwrap();
    record.nonce = nonce.into();
    record.record_revision = 8;
    record.terminalization.sequence = 1;
    let error = super::super::record::bounded_terminalization_error(
        memcordon_core::WindowsTerminalizationErrorStageV1::LaunchRelay,
        "MCREPORT-WRITE",
        "support control site Publication: Access is denied",
        Some(5),
    );
    let project = |record: &super::super::record::WindowsAttemptRecordV1,
                   nonce: &str,
                   request: &str,
                   caller: &memcordon_core::WindowsProcessIdentityV1,
                   token: &str| {
        super::super::record::retained_relay_failure_from_snapshot(
            record,
            (&attempt, nonce, request),
            memcordon_core::WindowsRelayPhaseV1::Authorized,
            caller,
            token,
            &error,
        )
    };
    let before = serde_json::to_vec(&record).unwrap();
    let observed = project(&record, nonce, &request, &caller.identity, &token).unwrap();
    assert!(
        observed
            .primary_detail
            .contains("observed uncommitted relay failure")
    );
    assert!(observed.primary_detail.contains(&error.detail));
    assert_eq!(serde_json::to_vec(&record).unwrap(), before);
    assert_eq!(record.record_revision, 8);
    assert_eq!(record.terminalization.sequence, 1);
    assert_eq!(observed.causal_diagnostics, record.causal_diagnostics);
    assert!(!observed.terminal_replay_available);
    assert!(!observed.cleanup_complete);
    assert!(project(&record, "foreign", &request, &caller.identity, &token).is_err());
    assert!(project(&record, nonce, &"05".repeat(32), &caller.identity, &token).is_err());
    assert!(project(&record, nonce, &request, &caller.identity, &"05".repeat(32)).is_err());
    let mut foreign = caller.identity.clone();
    foreign.creation_time_100ns += 1;
    assert!(project(&record, nonce, &request, &foreign, &token).is_err());
}

#[test]
fn authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token() {
    let receipt = super::super::readiness_receipt::begin(
        "windows::control_service::retained_binding_tests::authenticated_retained_binding_rejects_other_attempt_request_process_creation_and_token",
    );
    let attempt = "01".repeat(32);
    let request = "02".repeat(32);
    let caller = super::super::readiness_receipt::HeldNativeProcess::open(std::process::id());
    let identity = caller.identity.clone();
    assert!(!caller.exited());
    // SAFETY: pseudo handle denotes this test's real current process.
    let token_handle = super::super::token::process_token(unsafe {
        windows_sys::Win32::System::Threading::GetCurrentProcess()
    })
    .unwrap();
    let envelope = super::super::token::envelope(token_handle.raw()).unwrap();
    let envelope_bytes = serde_json::to_vec(&envelope).unwrap();
    let token = super::super::record::digest(&envelope_bytes);
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
    if let Some(receipt) = receipt {
        let record_path =
            receipt.retain("binding.record.json", &serde_json::to_vec(&record).unwrap());
        let envelope_path = receipt.retain("binding.caller-envelope.json", &envelope_bytes);
        let original_binding = binding();
        let mut variants = Vec::new();
        for field in [
            "attempt-id",
            "request-sha256",
            "process-id",
            "process-birth",
            "token-sha256",
        ] {
            let mut wrong = binding();
            match field {
                "attempt-id" => wrong.attempt_id = "05".repeat(32),
                "request-sha256" => wrong.request_sha256 = "06".repeat(32),
                "process-id" => wrong.process_identity.process_id += 1,
                "process-birth" => wrong.process_identity.creation_time_100ns += 1,
                "token-sha256" => wrong.token_sha256 = "07".repeat(32),
                _ => unreachable!(),
            }
            assert!(!wrong.matches_record(&record));
            variants.push(
                serde_json::json!({"changed_field":field,"attempt_id":wrong.attempt_id,
                "nonce":wrong.nonce,"request_sha256":wrong.request_sha256,
                "process_identity":wrong.process_identity,"token_sha256":wrong.token_sha256,
                "accepted":false}),
            );
        }
        receipt.finish_payload(serde_json::json!({"kind":"binding", "record":record_path,
            "caller_envelope":envelope_path,"caller_identity":identity,"caller_held_live":!caller.exited(),
            "baseline":{"attempt_id":original_binding.attempt_id,"nonce":original_binding.nonce,
                "request_sha256":original_binding.request_sha256,"process_identity":original_binding.process_identity,
                "token_sha256":original_binding.token_sha256,"accepted":true},"variants":variants,
            "record_revision_after":record.record_revision,"terminal_published":false}));
    }
}
