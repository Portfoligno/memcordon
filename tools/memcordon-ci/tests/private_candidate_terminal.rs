use memcordon_ci::private_protected_readback::validate_terminal_target_stdio;
use memcordon_ci::private_terminal_live::TERMINAL_JOIN_SELECTOR;
use memcordon_core::workload_codec::hash_bytes;
use sha2::{Digest, Sha256};

#[test]
fn terminal_live_frame_and_final_response_are_exact() {
    let challenge = [0x62; 32];
    let namespace_pid = 17_u32;
    let mut frame = b"MCRJOIN1".to_vec();
    frame.extend_from_slice(&namespace_pid.to_le_bytes());
    frame.extend_from_slice(hash_bytes(&challenge).bytes());
    let mut final_digest = Sha256::new();
    final_digest.update(b"memcordon-private-release-candidate-fixture-v1\0");
    final_digest.update(TERMINAL_JOIN_SELECTOR.as_bytes());
    final_digest.update([0]);
    final_digest.update(challenge);
    let mut response = frame.clone();
    response.extend_from_slice(&final_digest.finalize());
    let mut stdio = challenge.to_vec();
    stdio.extend_from_slice(&response);
    assert_eq!(
        validate_terminal_target_stdio(challenge, namespace_pid, &stdio).unwrap(),
        (frame, hash_bytes(&response))
    );
    assert!(validate_terminal_target_stdio(challenge, 0, &stdio).is_err());
    let mut wrong = stdio.clone();
    wrong[challenge.len() + b"MCRJOIN1".len()] ^= 1;
    assert!(validate_terminal_target_stdio(challenge, namespace_pid, &wrong).is_err());
    let mut wrong = stdio.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(validate_terminal_target_stdio(challenge, namespace_pid, &wrong).is_err());
    let mut short = stdio;
    short.pop();
    assert!(validate_terminal_target_stdio(challenge, namespace_pid, &short).is_err());
}
