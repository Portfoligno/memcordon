#![cfg(target_os = "linux")]

use crate::linux::private_release_case::{TOPOLOGY_SELECTOR, candidate_fixture_output_with_native};

#[test]
fn topology_response_requires_a_gated_kernel_inode() {
    assert!(crate::linux::private_release_case::candidate_fixture_supported(TOPOLOGY_SELECTOR));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(
            TOPOLOGY_SELECTOR
        )
        .is_ok()
    );
    let challenge = [0x48; 32];
    assert!(
        candidate_fixture_output_with_native(TOPOLOGY_SELECTOR, &challenge, 0, (0, 0)).is_err()
    );
    let first = candidate_fixture_output_with_native(TOPOLOGY_SELECTOR, &challenge, 9001, (0, 0))
        .expect("nonzero gated namespace inode");
    let second = candidate_fixture_output_with_native(TOPOLOGY_SELECTOR, &challenge, 9002, (0, 0))
        .expect("second gated namespace inode");
    assert_eq!(first.len(), challenge.len() + std::mem::size_of::<u64>());
    assert_eq!(&first[..challenge.len()], &second[..challenge.len()]);
    assert_ne!(first, second);
    assert_eq!(
        u64::from_le_bytes(first[challenge.len()..].try_into().unwrap()),
        9001
    );
}
