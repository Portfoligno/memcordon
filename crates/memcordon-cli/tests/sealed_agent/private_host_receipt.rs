#![cfg(target_os = "linux")]

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_host_receipt::{
    parse_active_for_test, persist_receipt_for_test, publish_storage_for_test,
    require_coordinator_exited_for_test,
};
use memcordon_core::{DiagnosticSha256, workload_codec::hash_bytes};
use std::fs::File;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;

#[test]
fn detached_finalizer_refuses_a_live_recorded_coordinator() {
    let pid = std::process::id() as libc::pid_t;
    // SAFETY: pidfd_open observes only this test process and transfers one fd.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0);
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity = ProcessIdentityV4::observe(pid, pidfd.as_fd()).unwrap();
    assert!(require_coordinator_exited_for_test(&identity).is_err());
}

#[test]
fn active_host_reference_is_strict_and_never_accepts_caller_extras() {
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let value = serde_json::json!({
        "schema_version": 1,
        "run_nonce": "ab".repeat(32),
        "receipt_sha256": digest,
        "native_run_digest": digest,
        "host_prerequisites_digest": digest,
        "installation_epoch": digest,
        "release_qualification_sha256": digest,
    });
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(parse_active_for_test(&bytes).is_ok());
    let mut extra = value.clone();
    extra["caller_authority"] = serde_json::json!(true);
    assert!(parse_active_for_test(&serde_json::to_vec(&extra).unwrap()).is_err());
    let mut zero_run = value.clone();
    zero_run["run_nonce"] = serde_json::json!("0".repeat(64));
    assert!(parse_active_for_test(&serde_json::to_vec(&zero_run).unwrap()).is_err());
    let mut upper_run = value.clone();
    upper_run["run_nonce"] = serde_json::json!("AB".repeat(32));
    assert!(parse_active_for_test(&serde_json::to_vec(&upper_run).unwrap()).is_err());
    let text = std::str::from_utf8(&bytes).unwrap();
    let duplicate = format!("{},\"schema_version\":1}}", text.strip_suffix('}').unwrap());
    assert!(parse_active_for_test(duplicate.as_bytes()).is_err());
    assert!(parse_active_for_test(&vec![b' '; 1025]).is_err());
}

#[test]
fn receipt_is_durable_before_active_and_replay_requires_exact_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let root = File::open(directory.path()).unwrap();
    let nonce = "ab".repeat(32);
    let receipt = br#"{"candidate":"storage-order-only"}"#;
    let digest = DiagnosticSha256::from_bytes([7; 32]);
    let active = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "run_nonce": nonce,
        "receipt_sha256": hash_bytes(receipt),
        "native_run_digest": digest,
        "host_prerequisites_digest": digest,
        "installation_epoch": digest,
        "release_qualification_sha256": digest,
    }))
    .unwrap();
    persist_receipt_for_test(&root, &nonce, receipt).unwrap();
    assert_eq!(
        std::fs::read(directory.path().join(format!("receipt-{nonce}.json"))).unwrap(),
        receipt
    );
    assert!(!directory.path().join("active").exists());
    publish_storage_for_test(&root, &nonce, receipt, &active).unwrap();
    assert_eq!(
        std::fs::read(directory.path().join("active")).unwrap(),
        active
    );
    publish_storage_for_test(&root, &nonce, receipt, &active).unwrap();
    assert!(publish_storage_for_test(&root, &nonce, b"different", &active).is_err());
    assert_eq!(
        std::fs::read(directory.path().join("active")).unwrap(),
        active
    );
}

#[test]
fn incomplete_receipt_temp_cannot_advance_active() {
    let directory = tempfile::tempdir().unwrap();
    let root = File::open(directory.path()).unwrap();
    let nonce = "cd".repeat(32);
    let receipt = br#"{"candidate":"storage-order-only"}"#;
    let digest = DiagnosticSha256::from_bytes([8; 32]);
    let active = serde_json::to_vec(&serde_json::json!({
        "schema_version": 1,
        "run_nonce": nonce,
        "receipt_sha256": hash_bytes(receipt),
        "native_run_digest": digest,
        "host_prerequisites_digest": digest,
        "installation_epoch": digest,
        "release_qualification_sha256": digest,
    }))
    .unwrap();
    let temporary = directory.path().join(format!("receipt-{nonce}.json.new"));
    std::fs::write(&temporary, b"incomplete").unwrap();
    std::fs::set_permissions(&temporary, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(publish_storage_for_test(&root, &nonce, receipt, &active).is_err());
    assert!(!directory.path().join("active").exists());
}
