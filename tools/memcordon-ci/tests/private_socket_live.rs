use memcordon_ci::private_socket_live::{SOCKET_SELECTOR, validate_socket_gate_bytes};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize)]
struct Identity {
    pid: u32,
    start_time: u64,
}

#[derive(Clone, Serialize)]
struct Witness {
    schema_version: u8,
    target: Identity,
    network_namespace_inode: u64,
    first_socket_device: u64,
    first_socket_inode: u64,
    second_socket_device: u64,
    second_socket_inode: u64,
    filter_sha256: DiagnosticSha256,
    sendmsg_errno: i32,
}

#[derive(Clone, Serialize)]
struct Gate {
    schema_version: u8,
    selector: String,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    attempt_id: String,
    witness: Witness,
}

fn fixture() -> (Gate, [u8; 32], DiagnosticSha256) {
    let challenge = [0xab; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        SOCKET_SELECTOR,
        &challenge,
    )
    .unwrap();
    let mut attempt = Sha256::new();
    attempt.update(b"memcordon-private-release-candidate-attempt-v1\0");
    attempt.update(key.bytes());
    let filter = DiagnosticSha256::from_bytes([0x42; 32]);
    (
        Gate {
            schema_version: 1,
            selector: SOCKET_SELECTOR.into(),
            result_key: key,
            challenge_sha256: hash_bytes(&challenge),
            attempt_id: hex::encode(&attempt.finalize()[..16]),
            witness: Witness {
                schema_version: 1,
                target: Identity {
                    pid: 1234,
                    start_time: 5678,
                },
                network_namespace_inode: 12,
                first_socket_device: 9,
                first_socket_inode: 100,
                second_socket_device: 9,
                second_socket_inode: 101,
                filter_sha256: filter.clone(),
                sendmsg_errno: libc::EPERM,
            },
        },
        challenge,
        filter,
    )
}

#[test]
fn socket_gate_structural_parser_rejects_identity_and_socket_substitutions() {
    let (gate, challenge, filter) = fixture();
    let bytes = serde_json::to_vec(&gate).unwrap();
    assert_eq!(
        validate_socket_gate_bytes(&bytes, &challenge, &filter).unwrap(),
        hash_bytes(&bytes)
    );
    assert!(validate_socket_gate_bytes(&bytes, &[0xcd; 32], &filter).is_err());
    assert!(
        validate_socket_gate_bytes(&bytes, &challenge, &DiagnosticSha256::from_bytes([3; 32]))
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.selector = "private_tcp::native_tcp_bind_listen_connect".into();
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.attempt_id = "00".repeat(16);
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.result_key = DiagnosticSha256::from_bytes([0x11; 32]);
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.witness.target.start_time = 0;
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.witness.network_namespace_inode = 0;
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.witness.first_socket_inode = 0;
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate.clone();
    wrong.witness.second_socket_inode = wrong.witness.first_socket_inode;
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&unknown).unwrap(), &challenge, &filter)
            .is_err()
    );
    let mut wrong = gate;
    wrong.witness.sendmsg_errno = libc::EACCES;
    assert!(
        validate_socket_gate_bytes(&serde_json::to_vec(&wrong).unwrap(), &challenge, &filter)
            .is_err()
    );
    assert!(
        validate_socket_gate_bytes(
            b"{\"schema_version\":1,\"schema_version\":1}",
            &challenge,
            &filter
        )
        .is_err()
    );
}
