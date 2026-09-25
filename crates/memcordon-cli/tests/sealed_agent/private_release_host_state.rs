#![cfg(target_os = "linux")]

use crate::linux::private_release_case::candidate_fixture_output;
use crate::linux::private_release_host_state::{
    HostNetworkPreservationV1, HostNetworkStateV1, SELECTOR, expected_private_projection,
};

#[test]
fn host_preservation_case_has_a_distinct_target_policy_projection() {
    assert!(crate::linux::private_release_case::candidate_fixture_supported(SELECTOR));
    assert!(
        crate::linux::private_target::PrivateExecArguments::for_release_candidate_fixture(SELECTOR)
            .is_ok()
    );
    let challenge = [0x4b; 32];
    let output = candidate_fixture_output(SELECTOR, &challenge);
    assert_eq!(
        output.len(),
        challenge.len() + expected_private_projection().len()
    );
    assert_eq!(&output[challenge.len()..], expected_private_projection());
}

#[test]
fn host_preservation_record_rejects_changed_namespace_identity() {
    let state = HostNetworkStateV1::capture().expect("read local kernel host state");
    let proof = HostNetworkPreservationV1::complete(state.clone(), state)
        .expect("unchanged host observation");
    proof.verify_current().expect("same current host state");
    let mut value = serde_json::to_value(&proof).expect("typed host record");
    let original = value["after"]["namespace_inode"]
        .as_u64()
        .expect("kernel namespace inode");
    value["after"]["namespace_inode"] = serde_json::json!(original.wrapping_add(1));
    let changed: HostNetworkPreservationV1 =
        serde_json::from_value(value).expect("structural host record");
    assert!(changed.validate().is_err());
}
