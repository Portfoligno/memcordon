#![cfg(target_os = "linux")]

use memcordon_core::DiagnosticSha256;

use crate::linux::private_public_reuse::validate_command_for_test;

#[test]
fn reuse_command_requires_exact_final_public_selector_challenge_and_key() {
    let selector = "private_tcp::retirement_failure_blocks_reuse";
    let challenge = DiagnosticSha256::from_bytes([0xab; 32]);
    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        challenge.bytes(),
    )
    .expect("fixed final-public selector");
    let challenge = String::from(challenge);
    let key = String::from(key);
    validate_command_for_test(selector, &challenge, &key).expect("exact dispatch binding");
    assert!(validate_command_for_test(selector, &challenge, &challenge).is_err());
    assert!(
        validate_command_for_test(
            "private_tcp::native_tcp_bind_listen_connect",
            &challenge,
            &key,
        )
        .is_err()
    );
    assert!(validate_command_for_test(selector, &"00".repeat(32), &key).is_err());
    assert!(validate_command_for_test(selector, &challenge.to_uppercase(), &key).is_err());
}
