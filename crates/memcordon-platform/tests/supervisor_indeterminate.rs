#![cfg(feature = "test-support")]

use memcordon_core::result_v2::{
    MixedAuthorizationKnowledgeV2, MixedRuntimeCarrierV2, MixedRuntimeOutcomeV2,
    OutstandingMixedRetirementV2,
};
use memcordon_core::{BoundedText, BoundedVec, DiagnosticSha256};

#[test]
fn authorization_refusal_retains_bounded_first_and_last_native_obligations() {
    let mut obligations = BoundedVec::default();
    for index in 0..32 {
        let text = format!("native-operation-{index}: {}", "é".repeat(110));
        obligations
            .try_push(BoundedText::new(&text).unwrap())
            .unwrap();
    }
    let carrier = MixedRuntimeCarrierV2 {
        kind: "linux-mixed-private".into(),
        carrier_revision: 2,
        provider_contract: 4,
        launch_wire: 4,
        outcome: MixedRuntimeOutcomeV2::Indeterminate {
            attempt_id: BoundedText::new(&"ab".repeat(16)).unwrap(),
            request_sha256: DiagnosticSha256::from_bytes([1; 32]),
            retained_obligations: OutstandingMixedRetirementV2 {
                authorization: MixedAuthorizationKnowledgeV2::Authorized,
                obligations,
            },
        },
    };
    assert!(carrier.validate().is_ok());
    let error = memcordon_platform::test_support::authorization_evidence_failure(Some(&carrier));
    assert_eq!(error.code, "MCRESTART-AUTHORIZATION-EVIDENCE");
    assert!(
        error
            .message
            .starts_with("backend release, target identity, and runtime evidence disagree")
    );
    assert!(error.message.contains("authorization=Authorized"));
    assert!(error.message.contains("obligations=32; omitted=26"));
    assert!(error.message.contains("native-operation-0:"));
    assert!(error.message.contains("native-operation-31:"));
    assert!(!error.message.contains("native-operation-4:"));
    assert!(error.message.len() < 2048);
    let plain = memcordon_platform::test_support::authorization_evidence_failure(None);
    assert_eq!(
        plain.message,
        "backend release, target identity, and runtime evidence disagree"
    );
    let mut malformed = carrier.clone();
    malformed.provider_contract = 0;
    let error = memcordon_platform::test_support::authorization_evidence_failure(Some(&malformed));
    assert_eq!(error.message, plain.message);
}
