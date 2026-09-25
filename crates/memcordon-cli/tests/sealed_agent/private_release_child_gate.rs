use crate::linux::private_release_child_gate::{ack_bytes_for_test, verify_ack_for_test};
use memcordon_core::DiagnosticSha256;

#[test]
fn child_live_ack_is_exactly_bound_to_case_challenge_and_gate() {
    let key = DiagnosticSha256::from_bytes([0x11; 32]);
    let gate = DiagnosticSha256::from_bytes([0x22; 32]);
    let challenge = [0x33; 32];
    let canonical = ack_bytes_for_test(&key, &challenge, &gate);
    assert!(verify_ack_for_test(&canonical, &key, &challenge, &gate).is_ok());
    assert!(verify_ack_for_test(&canonical, &key, &[0x34; 32], &gate).is_err());
    assert!(
        verify_ack_for_test(
            &canonical,
            &key,
            &challenge,
            &DiagnosticSha256::from_bytes([0x44; 32])
        )
        .is_err()
    );
    let duplicate = String::from_utf8(canonical.clone()).unwrap().replace(
        "\"schema_version\":1,",
        "\"schema_version\":1,\"schema_version\":1,",
    );
    assert!(verify_ack_for_test(duplicate.as_bytes(), &key, &challenge, &gate).is_err());
}
