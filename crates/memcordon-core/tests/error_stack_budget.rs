use memcordon_core::{
    BoundarySetupPhase, Error, ErrorCategory, ProviderRejectionEvidence, RestartSafetyProof,
};

#[test]
fn error_indirects_large_rejections_without_losing_evidence() {
    // Windows debug builds propagate this type through several nested supervision
    // frames. Keep its fixed footprint bounded independently of rejection detail.
    assert!(std::mem::size_of::<Error>() <= 2 * 1024);

    let rejection = ProviderRejectionEvidence {
        provider_failure: None,
        schema_version: 1,
        code: "MCSEALED-TARGET-DESCRIPTORS-READBACK".to_owned(),
        phase: BoundarySetupPhase::ResourceVerification,
        detail: "permission denied".to_owned(),
        os_code: Some(13),
        loader_qualification: None,
        target_created: true,
        target_released: false,
        cleanup_attempted: true,
        restart_safety: RestartSafetyProof::default(),
    };
    let error = Error::new(
        ErrorCategory::Setup,
        "MCSEALED-PROVIDER-REJECTION",
        "rejected",
    )
    .with_provider_rejection(rejection.clone());
    assert_eq!(error.provider_rejection(), Some(&rejection));
}

#[test]
fn boxed_provider_failure_preserves_native_inputs_through_clone_and_report() {
    use memcordon_core::*;
    let stage = NativeInputStageV1::Observed {
        summary: NativeTokenSummaryV1 {
            digest_kind: NativeEnvelopeDigestKindV1::NativeEnvelopeJsonV1,
            envelope_sha256: [4; 32],
            derived_primary_projection_kind:
                NativePrimaryProjectionKindV1::PrimaryTypeAnonymousLevelV1,
            derived_primary_projection_sha256: [5; 32],
            groups_sha256: [6; 32],
            privileges_sha256: [7; 32],
            restricted_sids_sha256: [8; 32],
            token_type: 1,
            impersonation_level: 0,
            group_count: Some(14),
            privilege_count: Some(24),
        },
    };
    let mut inputs = WindowsNativeInputObservationV1::new(
        [2; 32],
        [3; 32],
        WindowsProcessIdentityV1 {
            process_id: 4,
            creation_time_100ns: 5,
        },
        NativeInputCaptureV1 {
            authenticated: stage.clone(),
            duplicated: stage.clone(),
            prepared: stage.clone(),
            frontend: stage.clone(),
        },
    );
    inputs.launcher_primary = stage.clone();
    inputs.suspended_target = stage;
    inputs.target_identity = Some(WindowsProcessIdentityV1 {
        process_id: 6,
        creation_time_100ns: 7,
    });
    let mut journal = WindowsCausalDiagnosticsV1::default();
    journal.set_native_inputs(inputs.clone()).unwrap();
    let provider = PublicProviderBindingV1 {
        generation: BoundedText::new("provider").unwrap(),
        source_commit: BoundedText::new(&"ab".repeat(20)).unwrap(),
        runtime_manifest_sha256: DiagnosticSha256::from_bytes([1; 32]),
    };
    let attempt = DiagnosticSha256::from_bytes([2; 32]);
    let request = DiagnosticSha256::from_bytes([3; 32]);
    let projection = ProviderFailureDiagnosticV1::from_journal(
        provider.clone(),
        &String::from(attempt.clone()),
        &String::from(request.clone()),
        &journal,
    )
    .unwrap();
    let wire = serde_json::to_vec(&projection).unwrap();
    let validated =
        ProviderFailureDiagnosticV1::parse_bound(&wire, &provider, &attempt, &request).unwrap();
    let original = Error::new(ErrorCategory::Setup, "MCSEALED-TEST", "fixture failure")
        .with_provider_failure(validated);
    let cloned = original.clone();
    assert_eq!(cloned.provider_failure.as_deref(), Some(&projection));
    assert_eq!(original.provider_failure.as_deref(), Some(&projection));
    let report = OperationalAttemptFailure::from_error(&cloned).unwrap();
    report.validate().unwrap();
    let retained = report.provider_failure.unwrap();
    assert_eq!(retained.native_inputs.as_ref(), Some(&inputs));
    assert_eq!(serde_json::to_vec(&retained).unwrap(), wire);
}
