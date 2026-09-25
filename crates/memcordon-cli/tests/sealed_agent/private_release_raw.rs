#![cfg(target_os = "linux")]

use crate::linux::private_release_attempt::{
    ReadbackBlockedCandidateAttemptV1, ReadbackRetiredCandidateAttemptV1,
};
use crate::linux::private_release_raw::{
    CandidateRawContextV1, persist_attachment_for_test, read_attachment_for_test,
    readback_blocked_retirement_worker_raw_for_test, readback_candidate_worker_raw_for_test,
    readback_frontend_loss_worker_raw_for_test, readback_guardian_loss_worker_raw_for_test,
    readback_uncertain_candidate_worker_raw_for_test,
};
use memcordon_core::private_release_case_v1::PrivateReleaseAttachmentRoleV1;
use memcordon_core::workload_codec::hash_bytes;
use std::fs::File;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn protected_raw_attachment_is_read_back_and_never_replaced() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let role = PrivateReleaseAttachmentRoleV1::Observer;
    persist_attachment_for_test(&directory, role, b"native kernel trace").unwrap();
    assert_eq!(
        read_attachment_for_test(&directory, role).unwrap(),
        b"native kernel trace"
    );
    assert!(persist_attachment_for_test(&directory, role, b"replacement").is_err());
    assert_eq!(
        read_attachment_for_test(&directory, role).unwrap(),
        b"native kernel trace"
    );
}

#[test]
fn protected_raw_attachment_rejects_symlink_and_unsafe_mode() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let role = PrivateReleaseAttachmentRoleV1::Cleanup;
    let external_leaf = external.path().join("outside");
    std::fs::write(&external_leaf, b"outside").unwrap();
    symlink(&external_leaf, root.path().join(role.leaf())).unwrap();
    assert!(persist_attachment_for_test(&directory, role, b"evidence").is_err());
    assert!(read_attachment_for_test(&directory, role).is_err());
    assert_eq!(std::fs::read(external_leaf).unwrap(), b"outside");

    let role = PrivateReleaseAttachmentRoleV1::Report;
    persist_attachment_for_test(&directory, role, b"native report").unwrap();
    std::fs::set_permissions(
        root.path().join(role.leaf()),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(read_attachment_for_test(&directory, role).is_err());
}

#[test]
fn detached_raw_reader_rejects_duplicate_report_keys() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let request_path = root.path().join("request.json");
    std::fs::write(&request_path, b"protected request").unwrap();
    std::fs::set_permissions(&request_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    let key = hash_bytes(b"candidate raw duplicate report");
    let challenge = [0x5a; 32];
    let response = [0xa5; 32];
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "example-attempt".into(),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        terminal_record_digest: hash_bytes(b"terminal"),
        terminal_bytes: b"retired journal".to_vec(),
    };
    let error = readback_candidate_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: "private_tcp::native_tcp_bind_listen_connect",
            result_key: &key,
            challenge: &challenge,
            expected_response: &response,
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &journal,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}

#[test]
fn uncertain_raw_reader_rejects_duplicate_report_keys_without_claiming_retirement() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let request = root.path().join("request.json");
    std::fs::write(&request, b"protected request").unwrap();
    std::fs::set_permissions(&request, std::fs::Permissions::from_mode(0o600)).unwrap();
    let attempt = root.path().join("attempt.json");
    std::fs::write(&attempt, b"retired uncertainty journal").unwrap();
    std::fs::set_permissions(&attempt, std::fs::Permissions::from_mode(0o600)).unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    let key = hash_bytes(b"uncertain raw duplicate report");
    let challenge = [0x5a; 32];
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "example-attempt".into(),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        terminal_record_digest: hash_bytes(b"terminal"),
        terminal_bytes: b"retired uncertainty journal".to_vec(),
    };
    let error = readback_uncertain_candidate_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: "private_tcp::authorization_uncertainty_retired",
            result_key: &key,
            challenge: &challenge,
            expected_response: b"",
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &journal,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}

#[test]
fn blocked_retirement_raw_reader_rejects_duplicate_report_keys() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    for (leaf, bytes) in [
        ("request.json", b"protected request".as_slice()),
        ("attempt.json", b"retiring journal".as_slice()),
        ("attempt.json.new", b"protected fault marker".as_slice()),
    ] {
        let path = root.path().join(leaf);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    let key = hash_bytes(b"blocked raw duplicate report");
    let challenge = [0x5a; 32];
    let blocked = ReadbackBlockedCandidateAttemptV1 {
        journal: ReadbackRetiredCandidateAttemptV1 {
            attempt_id: "example-attempt".into(),
            checkpoint_digest: hash_bytes(b"checkpoint"),
            terminal_record_digest: hash_bytes(b"terminal"),
            terminal_bytes: b"retiring journal".to_vec(),
        },
        fault_marker_bytes: b"protected fault marker".to_vec(),
        detached_reuse_error: "file exists".into(),
    };
    let error = readback_blocked_retirement_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: "private_tcp::retirement_failure_blocks_reuse",
            result_key: &key,
            challenge: &challenge,
            expected_response: b"response",
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &blocked,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}

#[test]
fn guardian_loss_raw_reader_rejects_duplicate_report_keys() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    for (leaf, bytes) in [
        ("request.json", b"protected request".as_slice()),
        ("attempt.json", b"retired guardian-loss journal".as_slice()),
    ] {
        let path = root.path().join(leaf);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    let key = hash_bytes(b"guardian-loss raw duplicate report");
    let challenge = [0x5a; 32];
    let response = crate::linux::private_release_guardian_loss::armed_response(&challenge);
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "example-attempt".into(),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        terminal_record_digest: hash_bytes(b"terminal"),
        terminal_bytes: b"retired guardian-loss journal".to_vec(),
    };
    let error = readback_guardian_loss_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: crate::linux::private_release_guardian_loss::SELECTOR,
            result_key: &key,
            challenge: &challenge,
            expected_response: &response,
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &journal,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}

#[test]
fn frontend_loss_raw_reader_rejects_duplicate_report_keys() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    for (leaf, bytes) in [
        ("request.json", b"protected request".as_slice()),
        ("attempt.json", b"retired frontend-loss journal".as_slice()),
    ] {
        let path = root.path().join(leaf);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        b"{\"schema_version\":1,\"schema_version\":1}",
    )
    .unwrap();
    let key = hash_bytes(b"frontend-loss raw duplicate report");
    let challenge = [0x5a; 32];
    let response = crate::linux::private_release_frontend_loss::armed_response(&challenge);
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "example-attempt".into(),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        terminal_record_digest: hash_bytes(b"terminal"),
        terminal_bytes: b"retired frontend-loss journal".to_vec(),
    };
    let error = readback_frontend_loss_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: crate::linux::private_release_frontend_loss::SELECTOR,
            result_key: &key,
            challenge: &challenge,
            expected_response: &response,
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &journal,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}

#[test]
fn detached_raw_reader_rejects_unbound_guardian_terminal() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let request_path = root.path().join("request.json");
    std::fs::write(&request_path, b"protected request").unwrap();
    std::fs::set_permissions(&request_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Request,
        b"protected request",
    )
    .unwrap();
    let key = hash_bytes(b"candidate raw invalid guardian");
    let challenge = [0x5a; 32];
    let response = [0xa5; 32];
    let journal = ReadbackRetiredCandidateAttemptV1 {
        attempt_id: "example-attempt".into(),
        checkpoint_digest: hash_bytes(b"checkpoint"),
        terminal_record_digest: hash_bytes(b"terminal"),
        terminal_bytes: b"retired journal".to_vec(),
    };
    let report = serde_json::json!({
        "schema_version": 1,
        "selector": "private_tcp::native_tcp_bind_listen_connect",
        "result_key": key,
        "attempt_id": journal.attempt_id,
        "checkpoint_sha256": journal.checkpoint_digest,
        "terminal_record_digest": journal.terminal_record_digest,
        "challenge_sha256": hash_bytes(&challenge),
        "response_sha256": hash_bytes(&response),
        "candidate_exit_code": 0,
        "installed_inspection_json": "{}",
    });
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Report,
        &serde_json::to_vec(&report).unwrap(),
    )
    .unwrap();
    let mut stdio = Vec::from(challenge);
    stdio.extend_from_slice(&response);
    persist_attachment_for_test(&directory, PrivateReleaseAttachmentRoleV1::Stdio, &stdio).unwrap();
    let observer = serde_json::json!({
        "schema_version": 1,
        "attempt_id": journal.attempt_id,
        "checkpoint_sha256": journal.checkpoint_digest,
        "terminal_record_digest": journal.terminal_record_digest,
        "settlement": {
            "schema_version": 1,
            "monitor_outcome": "Completed",
            "cgroup_empty_before_cleanup": true,
            "containment_removed": true,
            "target_pidfd_exited": true,
            "namespace_init_reaped": true,
            "guardian_terminal": vec![0_u8; 20],
            "candidate_exit_code": 0,
        },
    });
    persist_attachment_for_test(
        &directory,
        PrivateReleaseAttachmentRoleV1::Observer,
        &serde_json::to_vec(&observer).unwrap(),
    )
    .unwrap();
    let error = readback_candidate_worker_raw_for_test(
        CandidateRawContextV1 {
            directory: &directory,
            selector: "private_tcp::native_tcp_bind_listen_connect",
            result_key: &key,
            challenge: &challenge,
            expected_response: &response,
            installed_inspection_bytes: b"{}",
            agent_path_snapshot: None,
        },
        &journal,
    )
    .err()
    .unwrap();
    assert!(error.contains("guardian"));
}
