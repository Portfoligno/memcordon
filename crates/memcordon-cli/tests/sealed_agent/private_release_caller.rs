#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use crate::linux::private_release_caller::{
    SELECTOR, spoof_challenge_for_test, validate_proc_identity_for_test,
    validate_spoof_rejection_for_test,
};
use crate::protocol::{Frame, MessageKind, write_network_frame};
use crate::rejection::RejectionV1;

#[test]
fn spoof_challenge_is_distinct_and_binds_original_challenge() {
    assert!(!crate::linux::private_release_case::candidate_physical_selector_supported(SELECTOR));
    let first = [0x21; 32];
    let second = [0x22; 32];
    assert_ne!(spoof_challenge_for_test(&first), first);
    assert_ne!(spoof_challenge_for_test(&first), [0; 32]);
    assert_ne!(
        spoof_challenge_for_test(&first),
        spoof_challenge_for_test(&second)
    );
}

#[test]
fn caller_proc_identity_rejects_root_capabilities_and_extra_groups() {
    let valid = "Name:\tcaller\nUid:\t601 601 601 601\nGid:\t602 602 602 602\nGroups:\t603\nCapEff:\t0000000000000000\nCapPrm:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    assert!(validate_proc_identity_for_test(valid, 601, 602, 603).is_ok());
    assert!(validate_proc_identity_for_test(valid, 0, 602, 603).is_err());
    assert!(validate_proc_identity_for_test(valid, 601, 602, 604).is_err());
    assert!(
        validate_proc_identity_for_test(&valid.replace("603\n", "603 604\n"), 601, 602, 603)
            .is_err()
    );
    assert!(
        validate_proc_identity_for_test(
            &valid.replace("0000000000000000", "0000000000000001"),
            601,
            602,
            603
        )
        .is_err()
    );
    assert!(
        validate_proc_identity_for_test(
            &valid.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
            601,
            602,
            603
        )
        .is_err()
    );
}

#[test]
fn spoof_denial_must_be_exact_preallocation_authorization_rejection() {
    let accepted = RejectionV1::request_error(
        "MCSEALED-PRIVATE-RELEASE-AUTHORIZATION",
        "root-only release case",
    );
    validate_spoof_rejection_for_test(&accepted).expect("exact root-only rejection");
    let unavailable = RejectionV1::request_error(
        "MCSEALED-PRIVATE-QUALIFICATION-UNAVAILABLE",
        "host Q absent",
    );
    assert!(validate_spoof_rejection_for_test(&unavailable).is_err());
    let mut allocated = accepted.clone();
    allocated.target_created = true;
    assert!(validate_spoof_rejection_for_test(&allocated).is_err());
}

#[test]
fn caller_handoff_transfers_the_connected_socket_not_response_bytes() {
    let (mut parent, child) = UnixStream::pair().expect("control socket pair");
    let (client, mut provider) = UnixStream::pair().expect("provider socket pair");
    let marker = Frame {
        kind: MessageKind::ReleaseCase,
        nonce: [3; 16],
        attempt_id: [4; 16],
        payload: b"connected-public-service-v1".to_vec(),
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &marker).expect("marker frame");
    crate::linux::transport::send(&child, &bytes, &[client.as_raw_fd()])
        .expect("transfer the provider socket");
    let (observed, mut descriptors) =
        crate::linux::transport::receive_network(&parent).expect("receive provider socket");
    assert_eq!(observed.kind, marker.kind);
    assert_eq!(observed.nonce, marker.nonce);
    assert_eq!(observed.attempt_id, marker.attempt_id);
    assert_eq!(observed.payload, marker.payload);
    assert_eq!(descriptors.len(), 1);
    let mut transferred: UnixStream = descriptors.pop().expect("one descriptor").into();
    provider
        .write_all(b"root-provider-rejection")
        .expect("provider writes");
    let mut response = [0_u8; 23];
    transferred
        .read_exact(&mut response)
        .expect("parent reads provider");
    assert_eq!(&response, b"root-provider-rejection");
    parent.write_all(b"go").expect("control remains separate");
    let mut control = [0_u8; 2];
    (&child)
        .read_exact(&mut control)
        .expect("child reads control");
    assert_eq!(&control, b"go");
}
