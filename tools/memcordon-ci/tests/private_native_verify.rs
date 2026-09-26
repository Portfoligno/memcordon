use memcordon_ci::private_native_verify::{
    CaseEvidenceFamilyV1, RequiredDispositionV1, case_evidence_requirements_v1,
};
use memcordon_core::private_release_case_v1::REQUIRED_PRIVATE_RELEASE_SELECTORS_V1;

#[test]
fn every_required_selector_has_one_explicit_semantics_family() {
    assert_eq!(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1.len(), 25);
    for selector in REQUIRED_PRIVATE_RELEASE_SELECTORS_V1 {
        let requirements = case_evidence_requirements_v1(selector).unwrap();
        assert!(requirements.requires_kernel_interval, "{selector}");
        assert!(requirements.requires_live_barrier, "{selector}");
    }
    assert!(case_evidence_requirements_v1("private_tcp::invented_case").is_none());
    assert_eq!(
        case_evidence_requirements_v1("private_tcp::abi_alternate_entry_denied")
            .unwrap()
            .family,
        CaseEvidenceFamilyV1::AlternateAbi,
    );
    assert_eq!(
        case_evidence_requirements_v1("private_tcp::wrong_grant_profile_and_port_rejected")
            .unwrap()
            .disposition,
        RequiredDispositionV1::PolicyComposite,
    );
    assert_eq!(
        case_evidence_requirements_v1("private_tcp::dual_attempt_namespace_isolation")
            .unwrap()
            .disposition,
        RequiredDispositionV1::DualAllocatedAndRetired,
    );
}
