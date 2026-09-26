#![cfg(target_os = "linux")]

use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};

use crate::linux::private_public_abi_control::{auxiliary_key, validate_command_for_test};
use crate::protocol::{Frame, MessageKind, read_frame, write_frame};

#[test]
fn public_abi_auxiliary_key_binds_all_four_inputs_and_domain() {
    let h1 = DiagnosticSha256::from_bytes([1; 32]);
    let epoch = DiagnosticSha256::from_bytes([2; 32]);
    let dispatch = DiagnosticSha256::from_bytes([3; 32]);
    let challenge = DiagnosticSha256::from_bytes([4; 32]);
    let mut expected = b"memcordon-public-abi-outer-v1\0".to_vec();
    expected.extend_from_slice(h1.bytes());
    expected.extend_from_slice(epoch.bytes());
    expected.extend_from_slice(dispatch.bytes());
    expected.extend_from_slice(challenge.bytes());
    let key = auxiliary_key(&h1, &epoch, &dispatch, &challenge);
    assert_eq!(key, hash_bytes(&expected));
    assert_ne!(key, auxiliary_key(&h1, &epoch, &dispatch, &h1));
    assert_ne!(key, auxiliary_key(&h1, &epoch, &challenge, &challenge));
    assert_ne!(key, auxiliary_key(&h1, &challenge, &dispatch, &challenge));
    assert_ne!(
        key,
        auxiliary_key(&challenge, &epoch, &dispatch, &challenge)
    );
}

#[test]
fn public_abi_auxiliary_protocol_roundtrips_distinct_kinds() {
    for kind in [
        MessageKind::PublicAbiOuterControl,
        MessageKind::PublicAbiOuterRecorded,
    ] {
        let frame = Frame {
            kind,
            nonce: [7; 16],
            attempt_id: [8; 16],
            payload: vec![9; 64],
        };
        let mut bytes = Vec::new();
        write_frame(&mut bytes, &frame).expect("encode fixed frame");
        let observed = read_frame(&mut bytes.as_slice()).expect("decode fixed frame");
        assert_eq!(observed.kind, kind);
        assert_eq!(observed.nonce, frame.nonce);
        assert_eq!(observed.attempt_id, frame.attempt_id);
        assert_eq!(observed.payload, frame.payload);
    }
}

#[test]
fn public_abi_command_accepts_only_final_public_dispatch_binding() {
    let challenge = [0xab_u8; 32];
    let selector = "private_tcp::abi_alternate_entry_denied";
    let key = memcordon_core::private_release_case_v1::private_release_case_key_v1(
        memcordon_core::private_release_case_v1::PrivateReleaseStageV1::FinalPublic,
        selector,
        &challenge,
    )
    .expect("fixed final-public selector");
    let challenge_hex = String::from(DiagnosticSha256::from_bytes(challenge));
    let key_hex = String::from(key);
    validate_command_for_test(selector, &challenge_hex, &key_hex).expect("bound request");
    assert!(validate_command_for_test(selector, &challenge_hex, &challenge_hex).is_err());
    assert!(
        validate_command_for_test(
            "private_tcp::native_tcp_bind_listen_connect",
            &challenge_hex,
            &key_hex
        )
        .is_err()
    );
    assert!(validate_command_for_test(selector, &"00".repeat(32), &key_hex).is_err());
    assert!(validate_command_for_test(selector, &challenge_hex.to_uppercase(), &key_hex).is_err());
}
