use crate::linux::private_release_socket_gate::{ack_bytes_for_test, verify_ack_for_test};
use memcordon_core::DiagnosticSha256;

#[test]
fn socket_ack_is_bound_to_case_challenge_and_pre_release_gate() {
    let key = DiagnosticSha256::from_bytes([0x61; 32]);
    let gate = DiagnosticSha256::from_bytes([0x62; 32]);
    let challenge = [0x63; 32];
    let canonical = ack_bytes_for_test(&key, &challenge, &gate);
    assert!(verify_ack_for_test(&canonical, &key, &challenge, &gate).is_ok());
    assert!(verify_ack_for_test(&canonical, &key, &[0x64; 32], &gate).is_err());
    assert!(
        verify_ack_for_test(
            &canonical,
            &key,
            &challenge,
            &DiagnosticSha256::from_bytes([0x65; 32])
        )
        .is_err()
    );
    let duplicate = String::from_utf8(canonical).unwrap().replace(
        "\"schema_version\":1,",
        "\"schema_version\":1,\"schema_version\":1,",
    );
    assert!(verify_ack_for_test(duplicate.as_bytes(), &key, &challenge, &gate).is_err());
}
