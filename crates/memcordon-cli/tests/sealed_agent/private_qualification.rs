#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::fs::symlink;

use crate::linux::private_qualification::{
    PreparedProbeRunV1, ProbeBaselineCompletionV1, ProbeFailedExecCompletionV1, ProbeFixtureKindV1,
    ProbeLossCompletionV1, ProbeLossKindV1, ProbeSuccessfulCompletionV1, decode_broker_request,
    pending_records, pinned_directory_entries, probe_attempt_id, probe_loss_attempt_id,
    verify_complete_run_inventory,
};
use crate::linux::qualification::HOST_PROBE_CATALOG_V1;
use crate::protocol::{Frame, MessageKind, read_network_frame, write_network_frame};

#[test]
fn detached_probe_completion_has_distinct_v4_wire_kind() {
    let frame = Frame {
        kind: MessageKind::PrivateProbeRunCompleted,
        nonce: [3; 16],
        attempt_id: [4; 16],
        payload: Vec::new(),
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &frame).unwrap();
    assert_eq!(read_network_frame(&mut bytes.as_slice()).unwrap(), frame);
    assert_ne!(MessageKind::PrivateProbeRunCompleted, MessageKind::Terminal);
    let finalizer = Frame {
        kind: MessageKind::FinalizePrivateHost,
        nonce: [5; 16],
        attempt_id: [6; 16],
        payload: [7_u8; 32].to_vec(),
    };
    let mut bytes = Vec::new();
    write_network_frame(&mut bytes, &finalizer).unwrap();
    assert_eq!(
        read_network_frame(&mut bytes.as_slice()).unwrap(),
        finalizer
    );
}

#[test]
fn fixed_catalogue_has_no_arbitrary_case_selector() {
    assert_eq!(HOST_PROBE_CATALOG_V1.len(), 8);
    for (index, (_, name)) in HOST_PROBE_CATALOG_V1.iter().enumerate() {
        assert_eq!(
            ProbeFixtureKindV1::named(OsStr::new(name)),
            ProbeFixtureKindV1::at(index)
        );
    }
    assert!(ProbeFixtureKindV1::at(HOST_PROBE_CATALOG_V1.len()).is_none());
    assert!(ProbeFixtureKindV1::named(OsStr::new("arbitrary-command")).is_none());
}

#[test]
fn probe_attempt_id_is_domain_bound_and_case_distinct() {
    let first = probe_attempt_id(&[3; 32], 0);
    assert_eq!(first, probe_attempt_id(&[3; 32], 0));
    assert_ne!(first, probe_attempt_id(&[3; 32], 1));
    assert_ne!(first, probe_attempt_id(&[4; 32], 0));
    assert_eq!(first.len(), [0_u8; 16].len() * 2);
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[test]
fn loss_subattempt_ids_are_distinct_from_each_other_and_catalogue_case() {
    let nonce = [7_u8; 32];
    let frontend = probe_loss_attempt_id(&nonce, ProbeLossKindV1::Frontend);
    let guardian = probe_loss_attempt_id(&nonce, ProbeLossKindV1::Guardian);
    assert_ne!(frontend, guardian);
    assert_ne!(frontend, probe_attempt_id(&nonce, 1));
    assert_ne!(guardian, probe_attempt_id(&nonce, 1));
    assert_ne!(
        frontend,
        probe_loss_attempt_id(&[8_u8; 32], ProbeLossKindV1::Frontend)
    );
}

#[test]
fn probe_recovery_rejects_symlink_and_unprotected_directory() {
    let temporary = tempfile::tempdir().unwrap();
    let missing = temporary.path().join("missing");
    assert!(pending_records(&missing).unwrap().is_empty());
    let link = temporary.path().join("link");
    symlink(temporary.path(), &link).unwrap();
    assert!(pending_records(&link).is_err());
    let ordinary = temporary.path().join("ordinary");
    std::fs::create_dir(&ordinary).unwrap();
    assert!(pending_records(&ordinary).is_err());
}

#[test]
fn pinned_probe_recovery_cannot_be_redirected_by_path_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("protected");
    let moved = temporary.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    let pinned = std::fs::File::open(&original).unwrap();
    std::fs::write(original.join("case-0.json"), b"blocking evidence").unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    assert_eq!(
        pinned_directory_entries(&pinned).unwrap(),
        vec!["private-qualification/case-0.json"]
    );
    assert!(std::fs::read_dir(&original).unwrap().next().is_none());
}

#[test]
fn probe_broker_request_rejects_duplicate_and_wrong_catalogue() {
    let temporary = tempfile::tempdir().unwrap();
    let prepared = PreparedProbeRunV1 {
        nonce: [7; 32],
        directory: std::fs::File::open(temporary.path()).unwrap(),
    };
    let encoded = prepared.encode_broker_request().unwrap();
    assert_eq!(decode_broker_request(&encoded).unwrap(), prepared.nonce);
    let text = std::str::from_utf8(&encoded).unwrap();
    let tail = text.strip_prefix('{').unwrap();
    let duplicate = format!("{{\"schema_version\":1,{tail}");
    assert!(decode_broker_request(duplicate.as_bytes()).is_err());
    let mut wrong: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    wrong["catalogue_version"] = serde_json::json!(2);
    assert!(decode_broker_request(&serde_json::to_vec(&wrong).unwrap()).is_err());
    wrong["catalogue_version"] = serde_json::json!(1);
    wrong["run_nonce"] = serde_json::to_value([0_u8; 32]).unwrap();
    assert!(decode_broker_request(&serde_json::to_vec(&wrong).unwrap()).is_err());
}

#[test]
fn completed_probe_inventory_rejects_missing_and_unexpected_entries() {
    let nonce = [9_u8; 32];
    let temporary = tempfile::tempdir().unwrap();
    let pinned = std::fs::File::open(temporary.path()).unwrap();
    assert!(verify_complete_run_inventory(&pinned, &nonce).is_err());
    for index in 0..HOST_PROBE_CATALOG_V1.len() {
        std::fs::write(
            temporary
                .path()
                .join(format!("case-{index}.completion.json")),
            b"candidate bytes",
        )
        .unwrap();
    }
    for index in [0, 2, 3, 4, 5, 6] {
        std::fs::write(
            temporary.path().join(format!("case-{index}.json")),
            b"record",
        )
        .unwrap();
    }
    for name in ["case-1-frontend.json", "case-1-guardian.json"] {
        std::fs::write(temporary.path().join(name), b"record").unwrap();
    }
    std::fs::write(
        temporary
            .path()
            .join(format!("{}.retired", probe_attempt_id(&nonce, 7))),
        b"record",
    )
    .unwrap();
    assert!(verify_complete_run_inventory(&pinned, &nonce).is_ok());
    std::fs::write(temporary.path().join("unexpected.json"), b"record").unwrap();
    assert!(verify_complete_run_inventory(&pinned, &nonce).is_err());
}

#[test]
fn protected_completion_parser_rejects_oversize_and_duplicate_keys() {
    let oversized = vec![b' '; 16 * 1024 + 1];
    assert!(ProbeSuccessfulCompletionV1::parse_verified(&oversized).is_err());
    assert!(ProbeFailedExecCompletionV1::parse_verified(&oversized).is_err());
    assert!(ProbeBaselineCompletionV1::parse_verified(&oversized).is_err());
    assert!(ProbeLossCompletionV1::parse_verified(&oversized).is_err());
    assert!(
        ProbeSuccessfulCompletionV1::parse_verified(b"{\"schema_version\":1,\"schema_version\":1}")
            .is_err()
    );
    assert!(
        ProbeFailedExecCompletionV1::parse_verified(b"{\"schema_version\":1,\"schema_version\":1}")
            .is_err()
    );
    assert!(
        ProbeBaselineCompletionV1::parse_verified(b"{\"schema_version\":1,\"schema_version\":1}")
            .is_err()
    );
    assert!(
        ProbeLossCompletionV1::parse_verified(b"{\"schema_version\":1,\"schema_version\":1}")
            .is_err()
    );
}
