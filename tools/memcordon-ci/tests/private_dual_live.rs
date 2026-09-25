use memcordon_ci::private_dual_live::{DUAL_SELECTOR, validate_dual_gate_bytes};
use memcordon_ci::private_protected_readback::{
    ProtectedCandidateReleaseRequestV1, ProtectedCoordinatorIdentityV1,
    StructuralTerminalMidflightV1,
};
use memcordon_core::DiagnosticSha256;
use memcordon_core::private_release_case_v1::{PrivateReleaseStageV1, private_release_case_key_v1};
use memcordon_core::workload_codec::hash_bytes;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Serialize)]
struct Branch {
    subattempt_key: DiagnosticSha256,
    attempt_id: String,
    target: ProtectedCoordinatorIdentityV1,
    network_namespace_inode: u64,
    listener_socket_inode: u64,
    checkpoint_sha256: DiagnosticSha256,
    execution_record_digest: DiagnosticSha256,
    midflight_bytes_sha256: DiagnosticSha256,
    filter_sha256: DiagnosticSha256,
}

#[derive(Clone, Serialize)]
struct Gate {
    schema_version: u8,
    selector: &'static str,
    result_key: DiagnosticSha256,
    challenge_sha256: DiagnosticSha256,
    port: u16,
    first: Branch,
    second: Branch,
}

fn subkey(parent: &DiagnosticSha256, tag: u8) -> DiagnosticSha256 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-dual-subattempt-v1\0");
    digest.update(parent.bytes());
    digest.update([tag]);
    DiagnosticSha256::from_bytes(digest.finalize().into())
}

fn fixed_port(challenge: &[u8; 32]) -> u16 {
    let mut digest = Sha256::new();
    digest.update(b"memcordon-private-release-dual-port-v1\0");
    digest.update(challenge);
    let bytes = digest.finalize();
    20_000 + u16::from_le_bytes([bytes[0], bytes[1]]) % 30_000
}

fn midpoint(pid: u32, seed: u8, filter: &DiagnosticSha256) -> StructuralTerminalMidflightV1 {
    StructuralTerminalMidflightV1 {
        attempt_id: hex::encode([seed; 16]),
        target: ProtectedCoordinatorIdentityV1 {
            pid,
            start_time: u64::from(pid) + 100,
        },
        checkpoint_sha256: DiagnosticSha256::from_bytes([seed; 32]),
        execution_record_digest: DiagnosticSha256::from_bytes([seed + 10; 32]),
        filter_sha256: filter.clone(),
        network_namespace_inode: u64::from(pid) + 200,
    }
}

fn branch(
    key: DiagnosticSha256,
    midpoint: &StructuralTerminalMidflightV1,
    bytes: &[u8],
    listener_inode: u64,
) -> Branch {
    Branch {
        subattempt_key: key,
        attempt_id: midpoint.attempt_id.clone(),
        target: midpoint.target.clone(),
        network_namespace_inode: midpoint.network_namespace_inode,
        listener_socket_inode: listener_inode,
        checkpoint_sha256: midpoint.checkpoint_sha256.clone(),
        execution_record_digest: midpoint.execution_record_digest.clone(),
        midflight_bytes_sha256: hash_bytes(bytes),
        filter_sha256: midpoint.filter_sha256.clone(),
    }
}

#[test]
fn dual_gate_requires_distinct_bound_live_branches() {
    let challenge = [0x4d; 32];
    let key = private_release_case_key_v1(
        PrivateReleaseStageV1::CandidateCapability,
        DUAL_SELECTOR,
        &challenge,
    )
    .unwrap();
    let filter = DiagnosticSha256::from_bytes([0x13; 32]);
    let request = ProtectedCandidateReleaseRequestV1 {
        schema_version: 1,
        stage: "candidate-capability".into(),
        selector: DUAL_SELECTOR.into(),
        challenge: hex::encode(challenge),
        result_key: key.clone(),
        installation_epoch: DiagnosticSha256::from_bytes([1; 32]),
        candidate_manifest_sha256: DiagnosticSha256::from_bytes([2; 32]),
        service_generation_sha256: DiagnosticSha256::from_bytes([3; 32]),
        coordinator: ProtectedCoordinatorIdentityV1 {
            pid: 900,
            start_time: 901,
        },
    };
    let first_midflight = b"first protected midpoint";
    let second_midflight = b"second protected midpoint";
    let first = midpoint(1001, 4, &filter);
    let second = midpoint(2002, 5, &filter);
    let gate = Gate {
        schema_version: 1,
        selector: DUAL_SELECTOR,
        result_key: key.clone(),
        challenge_sha256: hash_bytes(&challenge),
        port: fixed_port(&challenge),
        first: branch(subkey(&key, 1), &first, first_midflight, 3003),
        second: branch(subkey(&key, 2), &second, second_midflight, 4004),
    };
    let valid = serde_json::to_vec(&gate).unwrap();
    assert_eq!(
        validate_dual_gate_bytes(
            &valid,
            &request,
            challenge,
            &first,
            first_midflight,
            &second,
            second_midflight,
            &filter,
        )
        .unwrap(),
        hash_bytes(&valid)
    );
    let rejects = |mutated: Gate| {
        assert!(
            validate_dual_gate_bytes(
                &serde_json::to_vec(&mutated).unwrap(),
                &request,
                challenge,
                &first,
                first_midflight,
                &second,
                second_midflight,
                &filter,
            )
            .is_err()
        );
    };
    let mut wrong = gate.clone();
    wrong.second.target = wrong.first.target.clone();
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.second.network_namespace_inode = wrong.first.network_namespace_inode;
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.second.listener_socket_inode = wrong.first.listener_socket_inode;
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.port += 1;
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.first.subattempt_key = gate.second.subattempt_key.clone();
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.second.midflight_bytes_sha256 = hash_bytes(first_midflight);
    rejects(wrong);
    let mut wrong = gate.clone();
    wrong.first.filter_sha256 = DiagnosticSha256::from_bytes([9; 32]);
    rejects(wrong);
    let mut wrong = gate;
    wrong.challenge_sha256 = DiagnosticSha256::from_bytes([8; 32]);
    rejects(wrong);
}
