use memcordon_core::{
    BoundarySetupPhase, Error, ErrorCategory, ProviderRejectionEvidence, RestartSafetyProof,
};

#[test]
fn error_indirects_large_rejections_without_losing_evidence() {
    // Windows debug builds propagate this type through several nested supervision
    // frames. Keep its fixed footprint bounded independently of rejection detail.
    assert!(std::mem::size_of::<Error>() <= 2 * 1024);

    let rejection = ProviderRejectionEvidence {
        workload_admission: None,
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
        terminal_ack_required: false,
        terminal_receipt: None,
    };
    let error = Error::new(
        ErrorCategory::Setup,
        "MCSEALED-PROVIDER-REJECTION",
        "rejected",
    )
    .with_provider_rejection(rejection.clone());
    assert_eq!(error.provider_rejection(), Some(&rejection));
}
