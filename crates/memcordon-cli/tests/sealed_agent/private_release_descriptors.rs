#![cfg(target_os = "linux")]

use crate::linux::private_release_case::candidate_fixture_output;
use crate::linux::private_release_descriptors::{SELECTOR, expected_projection};

#[test]
fn post_exec_descriptor_case_is_fixed_and_selector_bound() {
    assert_eq!(SELECTOR, "private_tcp::descriptor_table_and_stdio_bound");
    assert!(crate::linux::private_release_case::candidate_fixture_supported(SELECTOR));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
    let challenge = [0x4a; 32];
    let output = candidate_fixture_output(SELECTOR, &challenge);
    assert_eq!(output.len(), challenge.len() + expected_projection().len());
    assert_eq!(&output[challenge.len()..], expected_projection());
    assert_ne!(
        output,
        candidate_fixture_output("private_tcp::native_tcp_bind_listen_connect", &challenge)
    );
}
