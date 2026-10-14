use memcordon_ci::mixed_collection_diagnostics::refused_carrier_detail;
use memcordon_core::result_v2::{
    MixedAdmissionRejectionV2, MixedAuthorizationKnowledgeV2, MixedRuntimeOutcomeV2,
    OutstandingMixedRetirementV2,
};
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

#[test]
fn indeterminate_summary_retains_first_and_last_exact_obligations() {
    let mut obligations = BoundedVec::default();
    for index in 0..32 {
        obligations
            .try_push(BoundedText::new(&format!("native-step-{index}: 界\nerrno=2")).unwrap())
            .unwrap();
    }
    let outcome = MixedRuntimeOutcomeV2::Indeterminate {
        attempt_id: BoundedText::new(&"02".repeat(32)).unwrap(),
        request_sha256: DiagnosticSha256::from_bytes([3; 32]),
        retained_obligations: OutstandingMixedRetirementV2 {
            authorization: MixedAuthorizationKnowledgeV2::Authorized,
            obligations,
        },
    };
    let detail = refused_carrier_detail(&outcome);
    assert!(detail.contains("outcome=indeterminate"));
    assert!(detail.contains("authorization=Authorized; obligations=32; omitted=26"));
    for index in [0, 1, 2, 3, 30, 31] {
        assert!(detail.contains(&format!("obligation[{index}]=\"native-step-{index}:")));
    }
    assert!(!detail.contains("obligation[4]="));
    assert!(!detail.contains('\n'));
    assert!(detail.len() < 8 * 1024);
}

#[test]
fn rejected_summary_does_not_dump_detail_or_request_evidence() {
    let outcome = MixedRuntimeOutcomeV2::RejectedIngress {
        request_bytes_sha256: DiagnosticSha256::from_bytes([4; 32]),
        reason: MixedAdmissionRejectionV2::UnsupportedRequest,
        detail: BoundedText::new("private request detail must stay outside summary").unwrap(),
        allocation: OutstandingMixedRetirementV2 {
            authorization: MixedAuthorizationKnowledgeV2::NeverAuthorized,
            obligations: BoundedVec::default(),
        },
    };
    let detail = refused_carrier_detail(&outcome);
    assert!(detail.contains("outcome=rejected-ingress; reason=UnsupportedRequest"));
    assert!(detail.contains("authorization=NeverAuthorized; obligations=0; omitted=0"));
    assert!(!detail.contains("private request detail"));
}
