use memcordon_core::DiagnosticSha256;
use memcordon_core::private_public_report_v2::PublicCliReportEvidenceV2;
use memcordon_core::private_release_case_v1::PrivateReleaseAllocatedOutcomeV1;
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn present_report_requires_exact_bytes() {
    let bytes = b"public report";
    let evidence = PublicCliReportEvidenceV2::Present {
        size: bytes.len() as u64,
        sha256: hash_bytes(bytes),
    };
    evidence
        .validate_for_outcome(
            PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
            Some(bytes),
        )
        .unwrap();
    assert!(
        evidence
            .validate_for_outcome(PrivateReleaseAllocatedOutcomeV1::TargetCompleted, None)
            .is_err()
    );
    assert!(
        evidence
            .validate_for_outcome(
                PrivateReleaseAllocatedOutcomeV1::TargetCompleted,
                Some(b"altered report")
            )
            .is_err()
    );
}

#[test]
fn absent_report_requires_frontend_loss_and_replacement_evidence() {
    let evidence = PublicCliReportEvidenceV2::AbsentFrontendLoss {
        authenticated_terminal_sha256: DiagnosticSha256::from_bytes([1; 32]),
        supervised_transport_sha256: DiagnosticSha256::from_bytes([2; 32]),
        independent_recovery_sha256: DiagnosticSha256::from_bytes([3; 32]),
    };
    evidence
        .validate_for_outcome(PrivateReleaseAllocatedOutcomeV1::FrontendLost, None)
        .unwrap();
    assert!(
        evidence
            .validate_for_outcome(PrivateReleaseAllocatedOutcomeV1::GuardianLost, None)
            .is_err()
    );
    assert!(
        evidence
            .validate_for_outcome(PrivateReleaseAllocatedOutcomeV1::FrontendLost, Some(b""))
            .is_err()
    );
    let mut incomplete = evidence.clone();
    if let PublicCliReportEvidenceV2::AbsentFrontendLoss {
        independent_recovery_sha256,
        ..
    } = &mut incomplete
    {
        *independent_recovery_sha256 = DiagnosticSha256::from_bytes([0; 32]);
    }
    assert!(incomplete.validate_structure().is_err());
}

#[test]
fn report_evidence_decoder_rejects_duplicate_and_unknown_fields() {
    let digest = DiagnosticSha256::from_bytes([4; 32]);
    let evidence = PublicCliReportEvidenceV2::Present {
        size: 4,
        sha256: digest,
    };
    let bytes = serde_json::to_vec(&evidence).unwrap();
    assert_eq!(PublicCliReportEvidenceV2::parse(&bytes).unwrap(), evidence);
    let mut duplicate = bytes.clone();
    duplicate.pop();
    duplicate.extend_from_slice(b",\"size\":5}");
    assert!(PublicCliReportEvidenceV2::parse(&duplicate).is_err());
    let mut unknown = bytes;
    unknown.pop();
    unknown.extend_from_slice(b",\"trusted\":true}");
    assert!(PublicCliReportEvidenceV2::parse(&unknown).is_err());
}
