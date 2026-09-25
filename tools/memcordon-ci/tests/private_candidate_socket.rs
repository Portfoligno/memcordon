use memcordon_ci::private_protected_readback::validate_candidate_target_stdio;
use memcordon_core::workload_codec::hash_bytes;
use sha2::{Digest, Sha256};

#[test]
fn scm_target_stdio_requires_exact_selector_response_and_no_leaked_descriptors() {
    let selector = "private_tcp::scm_rights_and_precreated_socket_denied";
    let challenge = [0x31; 32];
    let mut response = Sha256::new();
    response.update(b"memcordon-private-release-candidate-fixture-v1\0");
    response.update(selector.as_bytes());
    response.update([0]);
    response.update(challenge);
    let mut response = response.finalize().to_vec();
    response.extend_from_slice(&[3, 1, 1, 1]);
    let mut stdio = challenge.to_vec();
    stdio.extend_from_slice(&response);
    assert_eq!(
        validate_candidate_target_stdio(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &stdio,
            None,
        )
        .unwrap(),
        hash_bytes(&response)
    );
    *stdio.last_mut().unwrap() = 0;
    assert!(
        validate_candidate_target_stdio(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &stdio,
            None,
        )
        .is_err()
    );
    stdio.pop();
    assert!(
        validate_candidate_target_stdio(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &stdio,
            None,
        )
        .is_err()
    );
}
