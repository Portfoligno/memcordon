#![no_main]

use libfuzzer_sys::fuzz_target;
use memcordon_core::*;

fuzz_target!(|bytes: &[u8]| {
    let binding = PublicProviderBindingV1 {
        generation: BoundedText::new("fuzz-provider").unwrap(),
        source_commit: BoundedText::new("0123456789012345678901234567890123456789").unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    };
    let attempt = "02".repeat(32);
    let request = "03".repeat(32);
    let attempt_digest = DiagnosticSha256::from_bytes([2; 32]);
    let request_digest = DiagnosticSha256::from_bytes([3; 32]);
    let _ = windows_response_frame_limit(
        bytes
            .get(..bytes.len().min(WINDOWS_RESPONSE_PREFIX_BYTES))
            .unwrap(),
    );
    if bytes.len() <= WINDOWS_MAX_FRAME_BYTES {
        let _ = validate_record_json_structure(bytes);
    }
    let _ =
        ProviderFailureDiagnosticV1::parse_bound(bytes, &binding, &attempt_digest, &request_digest);
    if let Ok(journal) = WindowsCausalDiagnosticsV1::parse(bytes) {
        assert!(journal.is_consistent());
        let encoded = serde_json::to_vec(&journal).unwrap();
        assert_eq!(
            WindowsCausalDiagnosticsV1::parse(&encoded).unwrap(),
            journal
        );
    }

    // Structured generation reaches valid originals/unavailable states even
    // when byte mutation has not yet discovered the authenticated JSON shape.
    let mut journal = WindowsCausalDiagnosticsV1::default();
    if bytes.first().is_some_and(|byte| byte & 1 != 0) {
        journal.original = OriginalFailureV1::Unavailable {
            reason: OriginalUnavailableReasonV1::WorkerLostBeforeObservation,
        };
    }
    let original = journal.original.clone();
    for byte in bytes.iter().take(64) {
        let event = CausalEventV1 {
            sequence: 0,
            origin: DiagnosticOriginV1::RecordWriter,
            category: FailureCategoryV1::Persistence,
            operation: FailureOperationV1::StoreRecord,
            code: FailureCodeV1::RecordIo,
            native_code: Some(NativeFailureCodeV1::Win32(u32::from(*byte))),
            observed_phase: AttemptObservationPhaseV1::Terminalizing,
            safe_detail: SafeDiagnosticDetailV1::NoAdditionalDetail,
            detail_redacted: true,
            detail_truncated: false,
            terminalization_reference: None,
        };
        journal.observe_secondary(event).unwrap();
        assert_eq!(journal.original, original);
        assert!(journal.is_consistent());
    }
    let projection =
        ProviderFailureDiagnosticV1::from_journal(binding.clone(), &attempt, &request, &journal)
            .unwrap();
    let encoded = serde_json::to_vec(&projection).unwrap();
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &encoded,
            &binding,
            &attempt_digest,
            &request_digest
        )
        .is_ok()
    );
    let wrong_attempt = DiagnosticSha256::from_bytes([4; 32]);
    assert!(
        ProviderFailureDiagnosticV1::parse_bound(
            &encoded,
            &binding,
            &wrong_attempt,
            &request_digest
        )
        .is_err()
    );
});
