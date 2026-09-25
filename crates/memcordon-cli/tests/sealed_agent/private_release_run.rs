#![cfg(target_os = "linux")]

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_run::require_candidate_cgroup_leaf_absent_for_test;
use crate::linux::private_release_run::require_coordinator_exited_for_test;
use crate::linux::private_release_run::{create_case_directory_for_test, persist_request_for_test};
use crate::linux::private_release_run::{decode_broker_request, encode_control_request};
use memcordon_core::workload_codec::hash_bytes;
use std::fs::File;
use std::os::fd::{AsFd, FromRawFd, OwnedFd};
use std::os::unix::fs::symlink;

#[test]
fn protected_release_case_directory_is_never_reused() {
    let root = tempfile::tempdir().unwrap();
    let pinned = File::open(root.path()).unwrap();
    let key = hash_bytes(b"fixed native release test case");
    let directory = create_case_directory_for_test(&pinned, &key).unwrap();
    persist_request_for_test(&directory, b"protected request").unwrap();
    assert!(create_case_directory_for_test(&pinned, &key).is_err());
    assert!(persist_request_for_test(&directory, b"replacement").is_err());
    let name: String = key.into();
    assert_eq!(
        std::fs::read(root.path().join(name).join("request.json")).unwrap(),
        b"protected request"
    );
}

#[test]
fn release_case_directory_rejects_a_preexisting_symlink() {
    let root = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();
    let pinned = File::open(root.path()).unwrap();
    let key = hash_bytes(b"substituted native release test case");
    let name: String = key.clone().into();
    symlink(other.path(), root.path().join(name)).unwrap();
    assert!(create_case_directory_for_test(&pinned, &key).is_err());
    assert!(!other.path().join("request.json").exists());
}

#[test]
fn candidate_broker_selector_and_key_are_exactly_bound() {
    let request = crate::linux::private_release_case::ReleaseCaseRequestV1::parse(
        std::ffi::OsStr::new("candidate-capability"),
        std::ffi::OsStr::new("private_tcp::native_tcp_bind_listen_connect"),
        std::ffi::OsStr::new(&"ab".repeat(32)),
    )
    .unwrap();
    let bytes = encode_control_request(&request).unwrap();
    let decoded = decode_broker_request(&bytes).unwrap();
    assert_eq!(decoded.selector, request.selector);
    assert_eq!(decoded.challenge, request.challenge);
    assert_eq!(decoded.result_key(), request.result_key());

    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    tampered["result_key"] = serde_json::Value::String(String::from(hash_bytes(b"wrong")));
    assert!(decode_broker_request(&serde_json::to_vec(&tampered).unwrap()).is_err());
    assert!(decode_broker_request(b"{\"schema_version\":1,\"schema_version\":1}").is_err());
}

#[test]
fn detached_candidate_rejects_its_still_live_coordinator() {
    let pid = unsafe { libc::getpid() };
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    assert!(raw >= 0);
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
    let identity = ProcessIdentityV4::observe(pid, pidfd.as_fd()).unwrap();
    assert!(require_coordinator_exited_for_test(&identity).is_err());
    let prior_identity = ProcessIdentityV4 {
        pid: identity.pid,
        start_time: identity.start_time.checked_add(1).unwrap(),
    };
    assert!(require_coordinator_exited_for_test(&prior_identity).is_ok());
}

#[test]
fn detached_candidate_requires_its_exact_cgroup_leaf_absent() {
    let root = tempfile::tempdir().unwrap();
    let pinned = File::open(root.path()).unwrap();
    let identity = "ab".repeat(16);
    assert!(require_candidate_cgroup_leaf_absent_for_test(&pinned, &identity).is_ok());
    std::fs::create_dir(root.path().join(&identity)).unwrap();
    assert!(require_candidate_cgroup_leaf_absent_for_test(&pinned, &identity).is_err());
    assert!(require_candidate_cgroup_leaf_absent_for_test(&pinned, "../escape").is_err());
}

#[test]
fn detached_uncertainty_reader_rejects_a_normal_success_selector() {
    let request = crate::linux::private_release_case::ReleaseCaseRequestV1::parse(
        std::ffi::OsStr::new("candidate-capability"),
        std::ffi::OsStr::new("private_tcp::native_tcp_bind_listen_connect"),
        std::ffi::OsStr::new(&"ab".repeat(32)),
    )
    .unwrap();
    assert!(
        crate::linux::private_release_run::verify_detached_uncertain_candidate_case(&request)
            .is_err()
    );
}
