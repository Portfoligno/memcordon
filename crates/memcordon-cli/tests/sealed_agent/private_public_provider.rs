#![cfg(target_os = "linux")]

use crate::linux::private_public_provider::{
    decode_challenge_for_test, expected_launch_exchanges_for_test,
    expected_policy_launch_exchanges_for_test,
};
use memcordon_core::private_release_branch_v1::PolicyOperationBranchV1;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};

#[test]
fn registered_public_challenge_is_exact_lowercase_nonzero_and_stage_separated() {
    let challenge = "ab".repeat(32);
    let bytes = decode_challenge_for_test(&challenge).unwrap();
    assert_eq!(bytes, [0xab; 32]);
    for invalid in [
        "0".repeat(64),
        "AB".repeat(32),
        "ab".repeat(31),
        "ag".repeat(32),
    ] {
        assert!(decode_challenge_for_test(&invalid).is_err());
    }
    let selector = "private_tcp::native_tcp_bind_listen_connect";
    let final_key =
        private_release_case_key_v1(PrivateReleaseStageV1::FinalPublic, selector, &bytes).unwrap();
    let candidate_key =
        private_release_case_key_v1(PrivateReleaseStageV1::CandidateCapability, selector, &bytes)
            .unwrap();
    assert_ne!(final_key, candidate_key);
}

#[test]
fn provider_transcript_bounds_and_historical_epoch_remain_closed() {
    assert!(
        expected_launch_exchanges_for_test("private_tcp::wrong_grant_profile_and_port_rejected")
            .is_err()
    );
    for (branch, exchanges) in [
        (PolicyOperationBranchV1::AcceptedControl, 1),
        (PolicyOperationBranchV1::WrongGrant, 0),
        (PolicyOperationBranchV1::WrongProfile, 0),
        (PolicyOperationBranchV1::UnapprovedChangedPortPlan, 0),
        (PolicyOperationBranchV1::CommittedPortTamper, 1),
    ] {
        assert_eq!(
            expected_policy_launch_exchanges_for_test(branch).unwrap(),
            exchanges
        );
    }
    for selector in [
        "private_tcp::dual_attempt_namespace_isolation",
        "private_tcp::retirement_failure_blocks_reuse",
    ] {
        assert_eq!(expected_launch_exchanges_for_test(selector).unwrap(), 2);
    }
    assert_eq!(
        expected_launch_exchanges_for_test("private_tcp::native_tcp_bind_listen_connect").unwrap(),
        1
    );
    assert_eq!(
        expected_launch_exchanges_for_test("private_tcp::caller_identity_and_epoch_bound").unwrap(),
        1
    );
}
