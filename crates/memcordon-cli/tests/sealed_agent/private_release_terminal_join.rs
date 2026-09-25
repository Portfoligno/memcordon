use crate::linux::private_release_terminal_join::{LIVE_BYTES, SELECTOR, TerminalJoinLiveFrameV1};
use memcordon_core::DiagnosticSha256;
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn terminal_join_live_frame_rejects_wrong_target_and_challenge() {
    let challenge = [0x31; 32];
    let mut frame = Vec::with_capacity(LIVE_BYTES);
    frame.extend_from_slice(b"MCRJOIN1");
    frame.extend_from_slice(&77_u32.to_le_bytes());
    frame.extend_from_slice(hash_bytes(&challenge).bytes());
    assert_eq!(frame.len(), LIVE_BYTES);
    let decoded = TerminalJoinLiveFrameV1::decode(&frame, &challenge).unwrap();
    assert_eq!(decoded.target_pid, 77);
    assert_eq!(decoded.challenge_sha256, hash_bytes(&challenge));
    assert!(TerminalJoinLiveFrameV1::decode(&frame, &[0x32; 32]).is_err());
    frame[b"MCRJOIN1".len()..b"MCRJOIN1".len() + 4].fill(0);
    assert!(TerminalJoinLiveFrameV1::decode(&frame, &challenge).is_err());
    assert!(crate::linux::private_release_case::candidate_physical_selector_supported(SELECTOR));
    assert!(crate::linux::private_release_case::candidate_executable_fixture_supported(SELECTOR));
    assert!(!crate::linux::private_release_case::candidate_fixture_supported(SELECTOR));
}

#[test]
fn terminal_join_ack_requires_exact_gate_challenge_and_key() {
    use crate::linux::private_release_terminal_gate::{ack_bytes_for_test, verify_ack_for_test};

    let key = DiagnosticSha256::from_bytes([0x71; 32]);
    let gate = DiagnosticSha256::from_bytes([0x72; 32]);
    let challenge = [0x73; 32];
    let canonical = ack_bytes_for_test(&key, &challenge, &gate);
    assert!(verify_ack_for_test(&canonical, &key, &challenge, &gate).is_ok());
    assert!(verify_ack_for_test(&canonical, &key, &[0x74; 32], &gate).is_err());
    assert!(
        verify_ack_for_test(
            &canonical,
            &key,
            &challenge,
            &DiagnosticSha256::from_bytes([0x75; 32])
        )
        .is_err()
    );
    let duplicate = String::from_utf8(canonical).unwrap().replace(
        "\"schema_version\":1,",
        "\"schema_version\":1,\"schema_version\":1,",
    );
    assert!(verify_ack_for_test(duplicate.as_bytes(), &key, &challenge, &gate).is_err());
}
