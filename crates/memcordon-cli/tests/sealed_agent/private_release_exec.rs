#![cfg(target_os = "linux")]

use crate::linux::private_release_case::{
    candidate_fixture_output_with_native, candidate_fixture_supported,
};
use crate::linux::private_release_exec::{SELECTOR, expected_projection};

#[test]
fn target_exec_case_requires_retained_pinned_image_identity() {
    assert!(candidate_fixture_supported(SELECTOR));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
    let challenge = [0x4c; 32];
    assert!(candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (0, 9)).is_err());
    assert!(candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (8, 0)).is_err());
    let first = candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (8, 9))
        .expect("pinned image identity");
    let second = candidate_fixture_output_with_native(SELECTOR, &challenge, 7, (8, 10))
        .expect("different pinned image inode");
    assert_eq!(
        first.len(),
        challenge.len() + expected_projection(8, 9).unwrap().len()
    );
    assert_eq!(
        &first[challenge.len()..],
        expected_projection(8, 9).unwrap()
    );
    assert_ne!(first, second);
}
