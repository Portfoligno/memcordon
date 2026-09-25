use memcordon_core::private_release_case_v1::{
    PrivateReleaseStageV1, REQUIRED_PRIVATE_RELEASE_SELECTORS_V1, private_release_case_key_v1,
};

use crate::linux::private_public_release_case::{
    ExpectedFinalPublicOutcomeV1, FinalPublicCaseSpecV1, run_final_public_port_collision_fixture,
    run_final_public_tcp_fixture,
};
use crate::rejection::RejectionV1;

#[test]
fn final_public_catalogue_is_exact_and_stage_separated() {
    let challenge = [9; 32];
    for selector in REQUIRED_PRIVATE_RELEASE_SELECTORS_V1 {
        let case = FinalPublicCaseSpecV1::new(selector, challenge).expect("fixed selector");
        assert_eq!(case.selector(), selector);
        assert_ne!(
            case.result_key(),
            private_release_case_key_v1(
                PrivateReleaseStageV1::CandidateCapability,
                selector,
                &challenge,
            )
            .expect("candidate key"),
        );
    }
    assert!(FinalPublicCaseSpecV1::new("private_tcp::unreviewed", challenge).is_err());
    assert!(FinalPublicCaseSpecV1::new(REQUIRED_PRIVATE_RELEASE_SELECTORS_V1[0], [0; 32]).is_err());
}

#[test]
fn wrong_grant_requires_exact_public_rejection_not_q_unavailability() {
    let case = FinalPublicCaseSpecV1::new(
        "private_tcp::wrong_grant_profile_and_port_rejected",
        [8; 32],
    )
    .expect("fixed wrong-grant selector");
    assert_eq!(
        case.expected(),
        ExpectedFinalPublicOutcomeV1::PublicGrantRejected
    );
    assert!(!case.expected().requires_allocated_attempt());
    let unavailable = RejectionV1::request_error(
        "MCSEALED-PRIVATE-QUALIFICATION-UNAVAILABLE",
        "trusted Q absent",
    );
    assert!(case.validate_public_grant_rejection(&unavailable).is_err());
    let wrong_grant = RejectionV1::request_error(
        "MCSEALED-PRIVATE-PUBLIC-GRANT-REJECTED",
        "current V2 grant rejected",
    );
    case.validate_public_grant_rejection(&wrong_grant)
        .expect("exact V2 grant denial");
    let completed =
        FinalPublicCaseSpecV1::new("private_tcp::native_tcp_bind_listen_connect", [8; 32])
            .expect("fixed TCP selector");
    assert_eq!(
        completed.expected(),
        ExpectedFinalPublicOutcomeV1::TargetCompleted
    );
    assert!(completed.expected().requires_allocated_attempt());
    assert!(
        completed
            .validate_public_grant_rejection(&wrong_grant)
            .is_err()
    );
}

#[test]
fn final_public_tcp_fixture_performs_real_loopback_challenge_exchange() {
    let challenge = [0x6d; 32];
    let observation = run_final_public_tcp_fixture(challenge)
        .expect("loopback TCP fixture must exchange the challenge");
    assert_eq!(observation.schema_version, 1);
    assert_ne!(observation.network_namespace_inode, 0);
    assert_ne!(observation.listener_port, 0);
    assert_ne!(observation.client_port, 0);
    assert_ne!(observation.listener_port, observation.client_port);
    assert_eq!(
        observation.challenge_sha256,
        memcordon_core::workload_codec::hash_bytes(&challenge)
    );
    let mut expected = b"memcordon-final-public-tcp-fixture-v1\0".to_vec();
    expected.extend_from_slice(&challenge);
    expected.extend_from_slice(&observation.listener_port.to_be_bytes());
    assert_eq!(
        observation.response_sha256,
        memcordon_core::workload_codec::hash_bytes(&expected)
    );
    assert!(run_final_public_tcp_fixture([0; 32]).is_err());
}

#[test]
fn final_public_port_collision_fixture_observes_exact_kernel_denial() {
    let challenge = [0x79; 32];
    let observation = run_final_public_port_collision_fixture(challenge)
        .expect("a live listener must exclude the identical second bind");
    assert_eq!(observation.schema_version, 1);
    assert_ne!(observation.network_namespace_inode, 0);
    assert_ne!(observation.bound_port, 0);
    assert_eq!(observation.collision_os_code, libc::EADDRINUSE);
    assert_eq!(
        observation.challenge_sha256,
        memcordon_core::workload_codec::hash_bytes(&challenge)
    );
    assert!(run_final_public_port_collision_fixture([0; 32]).is_err());
}
