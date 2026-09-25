#![cfg(target_os = "linux")]

use crate::linux::private_attempt::ProcessIdentityV4;
use crate::linux::private_release_attempt::ReleaseCandidateReadbackExpectationV1;
use crate::linux::private_release_raw::{
    persist_checkpoint_gate_leaf_for_test, read_checkpoint_gate_leaf_for_test,
};
use memcordon_core::workload_codec::hash_bytes;
use std::fs::File;

#[test]
fn checkpoint_gate_leaf_is_exclusive_and_read_back_from_pinned_directory() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let bytes = b"protected pre-release checkpoint";
    persist_checkpoint_gate_leaf_for_test(&directory, bytes).unwrap();
    assert_eq!(
        read_checkpoint_gate_leaf_for_test(&directory).unwrap(),
        bytes
    );
    assert!(persist_checkpoint_gate_leaf_for_test(&directory, b"replacement").is_err());
    assert_eq!(
        read_checkpoint_gate_leaf_for_test(&directory).unwrap(),
        bytes
    );
}

#[test]
fn checkpoint_gate_parser_rejects_duplicate_authority_keys() {
    let key = hash_bytes(b"checkpoint gate test key");
    let epoch = hash_bytes(b"checkpoint gate test epoch");
    let manifest = hash_bytes(b"checkpoint gate test M0");
    let generation = hash_bytes(b"checkpoint gate test service");
    let challenge = [0x5a; 32];
    let coordinator = ProcessIdentityV4 {
        pid: 123,
        start_time: 456,
    };
    let expected = ReleaseCandidateReadbackExpectationV1 {
        result_key: &key,
        selector: crate::linux::private_release_case::CHECKPOINT_GATE_SELECTOR,
        challenge: &challenge,
        installation_epoch: &epoch,
        candidate_manifest_sha256: &manifest,
        service_generation_sha256: &generation,
        coordinator: &coordinator,
    };
    let error = crate::linux::private_release_gate::parse_witness_for_test(
        b"{\"schema_version\":1,\"schema_version\":1}",
        &expected,
    )
    .err()
    .unwrap();
    assert!(error.contains("duplicate"));
}
