#![cfg(target_os = "linux")]

use crate::linux::private_release_case::candidate_fixture_output;
use crate::linux::private_release_identity::{SELECTOR, expected_projection};

#[test]
fn target_identity_fixture_projection_is_exact_and_selector_bound() {
    assert_eq!(
        SELECTOR,
        "private_tcp::target_credentials_and_capabilities_dropped"
    );
    let projection = expected_projection();
    assert!(projection[..32].iter().all(|byte| *byte == 0));
    assert_eq!(projection[32], 1);
    let output = candidate_fixture_output(SELECTOR, &[0x46; 32]);
    assert_eq!(output.len(), [0_u8; 32].len() + projection.len());
    assert_eq!(&output[output.len() - projection.len()..], projection);
    assert_ne!(
        output,
        candidate_fixture_output("private_tcp::native_tcp_bind_listen_connect", &[0x46; 32])
    );
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
}
