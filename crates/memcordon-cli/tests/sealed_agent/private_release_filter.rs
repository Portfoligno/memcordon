#![cfg(target_os = "linux")]

use crate::linux::private_release_case::candidate_fixture_output;
use crate::linux::private_release_filter::{SELECTOR, expected_projection};

#[test]
fn filter_mode_and_native_abi_target_projection_is_exact_and_selector_bound() {
    assert_eq!(SELECTOR, "private_tcp::native_filter_digest_and_abi_bound");
    let projection = expected_projection();
    assert_eq!(projection[0], 2);
    match crate::linux::runtime_manifest::target().unwrap() {
        "x86_64-unknown-linux-gnu" => assert_eq!(projection[1], 1),
        "aarch64-unknown-linux-gnu" => assert_eq!(projection[1], 2),
        _ => panic!("reviewed native target differs"),
    }
    let output = candidate_fixture_output(SELECTOR, &[0x47; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + projection.len());
    assert_eq!(&output[output.len() - projection.len()..], projection);
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
}
