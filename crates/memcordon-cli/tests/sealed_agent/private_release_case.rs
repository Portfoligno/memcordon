#![cfg(target_os = "linux")]

use crate::linux::private_release_case::{
    REQUIRED_SELECTORS, RESULT_ROOT, ReleaseCaseRequestV1, ReleaseStageV1,
};
use std::ffi::OsStr;

fn request(stage: &str, selector: &str, challenge: &str) -> Result<ReleaseCaseRequestV1, String> {
    ReleaseCaseRequestV1::parse(
        OsStr::new(stage),
        OsStr::new(selector),
        OsStr::new(challenge),
    )
}

#[test]
fn native_release_selectors_match_the_ci_policy_exactly() {
    let catalogue: toml::Value =
        toml::from_str(include_str!("../../../../ci/private-native-v2.toml")).unwrap();
    let selectors = catalogue["tests"].as_array().unwrap();
    assert_eq!(selectors.len(), REQUIRED_SELECTORS.len());
    for (actual, expected) in selectors.iter().zip(REQUIRED_SELECTORS) {
        assert_eq!(actual.as_str(), Some(expected));
    }
}

#[test]
fn release_case_admission_is_closed_to_exact_stage_selector_and_challenge() {
    let challenge = "ab".repeat(32);
    let selector = REQUIRED_SELECTORS[0];
    let candidate = request("candidate-capability", selector, &challenge).unwrap();
    let final_public = request("final-public", selector, &challenge).unwrap();
    assert_eq!(candidate.stage, ReleaseStageV1::CandidateCapability);
    assert_eq!(final_public.stage, ReleaseStageV1::FinalPublic);
    assert_ne!(candidate.result_key(), final_public.result_key());
    assert_eq!(
        String::from(candidate.result_key()),
        "2fd68a0c106ed6322f1b3494812268015c9634b5bf1dabcab3e1b5d78ce41944"
    );
    assert_eq!(
        candidate.result_path().parent().unwrap().to_str(),
        Some(RESULT_ROOT)
    );
    assert_ne!(candidate.result_path(), final_public.result_path());
    assert!(request("candidate", selector, &challenge).is_err());
    assert!(request("final-public", "private_tcp::unknown", &challenge).is_err());
    assert!(request("final-public", selector, &"0".repeat(64)).is_err());
    assert!(request("final-public", selector, &"AB".repeat(32)).is_err());
    assert!(request("final-public", selector, "../selector").is_err());
}

#[test]
fn parsed_release_case_cannot_claim_completion_without_a_native_owner() {
    let case = request(
        "candidate-capability",
        REQUIRED_SELECTORS[16],
        &"ab".repeat(32),
    )
    .unwrap();
    let error = crate::linux::private_release_case::run(case).unwrap_err();
    assert!(error.contains("unavailable") || error.contains("root supervisor required"));
}

#[test]
fn candidate_target_fixtures_are_fixed_and_domain_separated() {
    let selector = "private_tcp::native_tcp_bind_listen_connect";
    let first =
        crate::linux::private_release_case::candidate_fixture_response(selector, &[0x5a; 32]);
    let second =
        crate::linux::private_release_case::candidate_fixture_response(selector, &[0x5b; 32]);
    assert_ne!(first, second);
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(selector)
            .is_ok()
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            "private_tcp::af_unix_socketpair_denied"
        )
        .is_ok()
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            "private_tcp::io_uring_and_pidfd_import_denied"
        )
        .is_ok()
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            "private_tcp::namespace_reentry_denied"
        )
        .is_ok()
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            "private_tcp::port_collision_same_namespace"
        )
        .is_ok()
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            "private_tcp::frontend_loss_retired"
        )
        .is_err()
    );
}

#[test]
fn uncertain_transport_selector_cannot_enter_success_fixture() {
    let selector = crate::linux::private_release_case::AUTHORIZATION_UNCERTAIN_SELECTOR;
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(selector));
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(selector));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(selector)
            .is_ok()
    );
    assert!(
        crate::linux::private_release_case::run_candidate_fixture(OsStr::new(selector)).is_err()
    );
}

#[test]
fn precreated_socket_probe_uses_separate_gated_result_route() {
    let selector = crate::linux::private_release_socket_launder::SELECTOR;
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(selector));
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(selector));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(selector)
            .is_ok()
    );
    assert!(crate::linux::private_release_case::candidate_executable_fixture_supported(selector));
}

#[test]
fn retirement_fault_executes_a_fixed_fixture_but_cannot_claim_target_completed() {
    let selector = crate::linux::private_release_case::RETIREMENT_FAULT_SELECTOR;
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(selector));
    assert!(crate::linux::private_release_case::candidate_executable_fixture_supported(selector));
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(selector));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(selector)
            .is_ok()
    );
}

#[test]
fn checkpoint_gate_requires_its_distinct_owner_and_detached_reader() {
    let selector = crate::linux::private_release_case::CHECKPOINT_GATE_SELECTOR;
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(selector));
    assert!(crate::linux::private_release_case::candidate_executable_fixture_supported(selector));
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(selector));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(selector)
            .is_ok()
    );
}
