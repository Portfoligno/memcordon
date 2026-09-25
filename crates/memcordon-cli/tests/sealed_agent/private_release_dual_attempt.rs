#![cfg(target_os = "linux")]

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_attempt::MidflightTerminalJoinReadbackV1;
use crate::linux::private_release_attempt::candidate_attempt_bytes;
use crate::linux::private_release_dual_attempt::{
    DualAttemptRoleV1, child_leaf_for_test, fixed_port, ready_frame, subattempt_key, target_ack,
};
use crate::linux::private_release_dual_execution::parse_loopback_listener_inode;
use crate::linux::private_release_dual_gate::{
    DualLiveBranchV1, ack_bytes_for_test, branch_matches_for_test, verify_ack_for_test,
};
use crate::linux::private_release_dual_raw::{DualRawBranchV1, DualRawReportV1};
use memcordon_core::workload_codec::hash_bytes;

#[test]
fn dual_attempt_keys_are_distinct_from_parent_and_each_other() {
    let parent = hash_bytes(b"fixed protected release result key");
    let first = subattempt_key(&parent, DualAttemptRoleV1::First);
    let second = subattempt_key(&parent, DualAttemptRoleV1::Second);
    assert_ne!(parent, first);
    assert_ne!(parent, second);
    assert_ne!(first, second);
    assert_ne!(
        candidate_attempt_bytes(&parent),
        candidate_attempt_bytes(&first)
    );
    assert_ne!(
        candidate_attempt_bytes(&first),
        candidate_attempt_bytes(&second)
    );
    assert_eq!(child_leaf_for_test(DualAttemptRoleV1::First), "dual-first");
    assert_eq!(
        child_leaf_for_test(DualAttemptRoleV1::Second),
        "dual-second"
    );
}

#[test]
fn dual_target_frame_binds_common_port_challenge_and_distinct_netns() {
    let challenge = [0x91; 32];
    let port = fixed_port(&challenge);
    assert!((20_000..50_000).contains(&port));
    let first = ready_frame(&challenge, port, 1401);
    let second = ready_frame(&challenge, port, 1402);
    assert_eq!(&first[..34], &second[..34]);
    assert_ne!(&first[34..], &second[34..]);
    assert_ne!(ready_frame(&[0x92; 32], port, 1401), first);
    assert_eq!(target_ack(), [0xa7]);
}

#[test]
fn dual_listener_parser_requires_exact_loopback_port_state_and_inode() {
    let header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n";
    let row = "  0: 0100007F:6D60 00000000:0000 0A 0:0 00:0 0 1000 0 4567\n";
    let table = [header, row].concat();
    assert_eq!(parse_loopback_listener_inode(&table, 28_000).unwrap(), 4567);
    assert!(parse_loopback_listener_inode(&table, 28_001).is_err());
    assert!(parse_loopback_listener_inode(header, 28_000).is_err());
    let duplicate = [header, row, row].concat();
    assert!(parse_loopback_listener_inode(&duplicate, 28_000).is_err());
}

#[test]
fn dual_ci_ack_cannot_be_rebound_to_another_case_or_gate() {
    let key = hash_bytes(b"dual parent result key");
    let challenge = [0x31; 32];
    let gate = hash_bytes(b"two live target kernel observations");
    let ack = ack_bytes_for_test(&key, &challenge, &gate);
    assert!(verify_ack_for_test(&ack, &key, &challenge, &gate).is_ok());
    assert!(verify_ack_for_test(&ack, &hash_bytes(b"other key"), &challenge, &gate).is_err());
    assert!(verify_ack_for_test(&ack, &key, &[0x32; 32], &gate).is_err());
    assert!(verify_ack_for_test(&ack, &key, &challenge, &hash_bytes(b"other gate")).is_err());
    let mut duplicate = ack;
    duplicate.splice(1..1, b"\"schema_version\":1,".iter().copied());
    assert!(verify_ack_for_test(&duplicate, &key, &challenge, &gate).is_err());
}

#[test]
fn dual_gate_branch_rejects_a_swapped_namespace_or_midflight_digest() {
    let bytes = b"protected exec-observed journal";
    let target = ProcessIdentityV4 {
        pid: 301,
        start_time: 902,
    };
    let midflight = MidflightTerminalJoinReadbackV1 {
        attempt_id: "ab".repeat(16),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        execution_record_digest: hash_bytes(b"record"),
        target: target.clone(),
        network_namespace_inode: 801,
        filter_sha256: hash_bytes(b"filter"),
        execution_record_bytes: bytes.to_vec(),
    };
    let mut branch = DualLiveBranchV1 {
        subattempt_key: hash_bytes(b"subattempt"),
        attempt_id: midflight.attempt_id.clone(),
        target,
        network_namespace_inode: 801,
        listener_socket_inode: 603,
        checkpoint_sha256: midflight.checkpoint_digest.clone(),
        execution_record_digest: midflight.execution_record_digest.clone(),
        midflight_bytes_sha256: hash_bytes(bytes),
        filter_sha256: midflight.filter_sha256.clone(),
    };
    assert!(branch_matches_for_test(&branch, &midflight, bytes));
    branch.network_namespace_inode += 1;
    assert!(!branch_matches_for_test(&branch, &midflight, bytes));
    branch.network_namespace_inode -= 1;
    assert!(!branch_matches_for_test(
        &branch,
        &midflight,
        b"swapped journal"
    ));
}

#[test]
fn dual_raw_report_requires_both_distinct_branch_records() {
    let branch = |seed: u8, attempt_id: String| DualRawBranchV1 {
        subattempt_key: hash_bytes(&[seed, 1]),
        attempt_id,
        checkpoint_sha256: hash_bytes(&[seed, 2]),
        terminal_record_digest: hash_bytes(&[seed, 3]),
        terminal_sha256: hash_bytes(&[seed, 4]),
        settlement_sha256: hash_bytes(&[seed, 5]),
        network_namespace_inode: u64::from(seed) + 100,
        listener_socket_inode: u64::from(seed) + 200,
        candidate_exit_code: 0,
    };
    let report = DualRawReportV1 {
        schema_version: 1,
        selector: crate::linux::private_release_dual_attempt::SELECTOR.into(),
        result_key: hash_bytes(b"parent"),
        challenge_sha256: hash_bytes(b"challenge"),
        gate_sha256: hash_bytes(b"gate"),
        port: 28_000,
        first: branch(1, "ab".repeat(16)),
        second: branch(2, "cd".repeat(16)),
        installed_inspection_json: "{}".into(),
    };
    let bytes = serde_json::to_vec(&report).unwrap();
    assert_eq!(
        serde_json::from_slice::<DualRawReportV1>(&bytes).unwrap(),
        report
    );
    let mut missing: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    missing.as_object_mut().unwrap().remove("second");
    assert!(serde_json::from_value::<DualRawReportV1>(missing).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    unknown["first"]["synthetic_success"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DualRawReportV1>(unknown).is_err());
}
