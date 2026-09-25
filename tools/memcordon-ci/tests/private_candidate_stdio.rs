use memcordon_ci::private_protected_readback::{
    validate_candidate_target_stdio, validate_candidate_target_stdio_with_agent_identity,
};
use sha2::{Digest, Sha256};

fn observed_fixture(selector: &str, challenge: [u8; 32], suffix: &[u8]) -> Vec<u8> {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    digest.update(selector.as_bytes());
    digest.update([0]);
    digest.update(challenge);
    let mut bytes = challenge.to_vec();
    bytes.extend_from_slice(&digest.finalize());
    bytes.extend_from_slice(suffix);
    bytes
}

#[test]
fn fixed_candidate_target_responses_reject_errno_capability_and_selector_substitutions() {
    let challenge = [0x5a; 32];
    let cases: [(&str, Vec<u8>); 9] = [
        ("private_tcp::native_tcp_bind_listen_connect", vec![]),
        (
            "private_tcp::af_unix_socketpair_denied",
            [97_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat(),
        ),
        (
            "private_tcp::io_uring_and_pidfd_import_denied",
            [1_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat(),
        ),
        (
            "private_tcp::namespace_reentry_denied",
            [1_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat(),
        ),
        (
            "private_tcp::port_collision_same_namespace",
            98_i32.to_le_bytes().to_vec(),
        ),
        (
            "private_tcp::target_credentials_and_capabilities_dropped",
            {
                let mut projection = vec![0; 33];
                projection[32] = 1;
                projection
            },
        ),
        (
            "private_tcp::native_filter_digest_and_abi_bound",
            vec![2, 1],
        ),
        (
            "private_tcp::descriptor_table_and_stdio_bound",
            vec![3, 1, 1, 1],
        ),
        (
            "private_tcp::host_namespace_and_sysctl_unchanged",
            [
                0_u16.to_le_bytes(),
                32768_u16.to_le_bytes(),
                60999_u16.to_le_bytes(),
            ]
            .concat()
            .into_iter()
            .chain([0])
            .collect(),
        ),
    ];
    for (selector, suffix) in cases {
        let valid = observed_fixture(selector, challenge, &suffix);
        validate_candidate_target_stdio(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &valid,
            None,
        )
        .unwrap();

        let mut changed = valid.clone();
        let last = changed.last_mut().unwrap();
        *last ^= 1;
        assert!(
            validate_candidate_target_stdio(
                selector,
                "x86_64-unknown-linux-gnu",
                challenge,
                &changed,
                None
            )
            .is_err()
        );
        assert!(
            validate_candidate_target_stdio(
                selector,
                "x86_64-unknown-linux-gnu",
                [0x5b; 32],
                &valid,
                None
            )
            .is_err()
        );
        assert!(
            validate_candidate_target_stdio(
                selector,
                "x86_64-unknown-linux-gnu",
                challenge,
                &valid[..valid.len() - 1],
                None
            )
            .is_err()
        );
    }
    let af_unix = observed_fixture(
        "private_tcp::af_unix_socketpair_denied",
        challenge,
        &[97_i32.to_le_bytes(), 1_i32.to_le_bytes()].concat(),
    );
    assert!(
        validate_candidate_target_stdio(
            "private_tcp::io_uring_and_pidfd_import_denied",
            "x86_64-unknown-linux-gnu",
            challenge,
            &af_unix,
            None,
        )
        .is_err()
    );
    assert!(
        validate_candidate_target_stdio(
            "private_tcp::unsupported_selector",
            "x86_64-unknown-linux-gnu",
            challenge,
            &af_unix,
            None,
        )
        .is_err()
    );
    let arm64 = observed_fixture(
        "private_tcp::native_filter_digest_and_abi_bound",
        challenge,
        &[2, 2],
    );
    validate_candidate_target_stdio(
        "private_tcp::native_filter_digest_and_abi_bound",
        "aarch64-unknown-linux-gnu",
        challenge,
        &arm64,
        None,
    )
    .unwrap();
    assert!(
        validate_candidate_target_stdio(
            "private_tcp::native_filter_digest_and_abi_bound",
            "x86_64-unknown-linux-gnu",
            challenge,
            &arm64,
            None,
        )
        .is_err()
    );
    let topology = observed_fixture(
        "private_tcp::private_namespace_topology_exact",
        challenge,
        &42_u64.to_le_bytes(),
    );
    validate_candidate_target_stdio(
        "private_tcp::private_namespace_topology_exact",
        "x86_64-unknown-linux-gnu",
        challenge,
        &topology,
        Some(42),
    )
    .unwrap();
    assert!(
        validate_candidate_target_stdio(
            "private_tcp::private_namespace_topology_exact",
            "x86_64-unknown-linux-gnu",
            challenge,
            &topology,
            Some(43),
        )
        .is_err()
    );
    assert!(
        validate_candidate_target_stdio(
            "private_tcp::private_namespace_topology_exact",
            "x86_64-unknown-linux-gnu",
            challenge,
            &topology,
            None,
        )
        .is_err()
    );
}

#[test]
fn post_exec_image_response_requires_independently_observed_installed_file_identity() {
    let selector = "private_tcp::target_exec_and_fd_leak_observed";
    let challenge = [0xa5; 32];
    let mut suffix = Vec::new();
    suffix.extend_from_slice(&1234_u64.to_le_bytes());
    suffix.extend_from_slice(&5678_u64.to_le_bytes());
    suffix.extend_from_slice(&[3, 1, 1, 1]);
    let observed = observed_fixture(selector, challenge, &suffix);
    validate_candidate_target_stdio_with_agent_identity(
        selector,
        "x86_64-unknown-linux-gnu",
        challenge,
        &observed,
        None,
        Some((1234, 5678)),
    )
    .unwrap();
    assert!(
        validate_candidate_target_stdio_with_agent_identity(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &observed,
            None,
            None,
        )
        .is_err()
    );
    assert!(
        validate_candidate_target_stdio_with_agent_identity(
            selector,
            "x86_64-unknown-linux-gnu",
            challenge,
            &observed,
            None,
            Some((1234, 5679)),
        )
        .is_err()
    );
}
