#![cfg(target_os = "linux")]

#[test]
fn guardian_loss_armed_response_is_selector_bound_but_not_a_completed_case() {
    let challenge = [0x6d; 32];
    let selector = crate::linux::private_release_guardian_loss::SELECTOR;
    let response = crate::linux::private_release_guardian_loss::armed_response(&challenge);
    assert_eq!(response.len(), challenge.len());
    assert_eq!(
        response,
        crate::linux::private_release_case::candidate_fixture_response(selector, &challenge)
    );
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(selector));
}
