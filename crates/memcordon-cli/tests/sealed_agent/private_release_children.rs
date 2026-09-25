use memcordon_core::workload_codec::hash_bytes;

use crate::linux::private_release_children::{LIVE_BYTES, LIVE_PREFIX, TargetLiveChildrenV1};

fn live_frame(challenge: &[u8; 32], target: u32, child: u32, thread: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(LIVE_BYTES);
    bytes.extend_from_slice(LIVE_PREFIX);
    bytes.extend_from_slice(&target.to_le_bytes());
    bytes.extend_from_slice(&child.to_le_bytes());
    bytes.extend_from_slice(&thread.to_le_bytes());
    bytes.extend_from_slice(hash_bytes(challenge).bytes());
    bytes
}

#[test]
fn child_live_frame_binds_three_distinct_kernel_ids_and_challenge() {
    let challenge = [0xab; 32];
    let bytes = live_frame(&challenge, 101, 102, 103);
    let decoded = TargetLiveChildrenV1::decode(&bytes, &challenge).unwrap();
    assert_eq!(decoded.target_pid, 101);
    assert_eq!(decoded.child_pid, 102);
    assert_eq!(decoded.thread_tid, 103);
    assert_eq!(decoded.challenge_sha256, hash_bytes(&challenge));
    assert!(TargetLiveChildrenV1::decode(&bytes, &[0xcd; 32]).is_err());
    assert!(TargetLiveChildrenV1::decode(&bytes[..bytes.len() - 1], &challenge).is_err());
    assert!(
        TargetLiveChildrenV1::decode(&live_frame(&challenge, 101, 101, 103), &challenge).is_err()
    );
    assert!(
        TargetLiveChildrenV1::decode(&live_frame(&challenge, 101, 102, 102), &challenge).is_err()
    );
}

#[test]
fn child_runtime_selector_uses_distinct_owner_and_not_generic_success_fixture() {
    assert!(
        crate::linux::private_release_case::candidate_physical_selector_supported(
            crate::linux::private_release_children::SELECTOR
        )
    );
    assert!(
        !crate::linux::private_release_case::candidate_fixture_supported(
            crate::linux::private_release_children::SELECTOR
        )
    );
}
