#![cfg(unix)]
use memcordon_ci::{
    consumer_readiness_ledger::SourceIdentity,
    release::linux_recovery_harness::{
        HeldRecoveryHarness, RecoveryHarnessOwner, protected_directory,
    },
};
use memcordon_readiness_verifier::ProductKey;

#[test]
fn reconstruction_refuses_reassociation_and_missing_original_without_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let identity = SourceIdentity {
        run_id: "17".into(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        version: "0.5.8-dev".into(),
    };
    let cell = ProductKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
    };
    let owner = RecoveryHarnessOwner {
        format: "memcordon.original-native-recovery-harness-owner".into(),
        revision: 1,
        identity: identity.clone(),
        cell: cell.clone(),
        scope_id: "original-lease".into(),
        work_deadline_unix_millis: 10,
        cleanup_deadline_unix_millis: 20,
        owner_path: directory.path().join("owner.json"),
        executable: directory.path().join("native-test-harness"),
        sha256: "c".repeat(64),
        device: 1,
        inode: 2,
        length: 3,
        mode: 0o100555,
        compiler_output: directory.path().join("recovery-cargo-output.jsonl"),
        compiler_output_sha256: "d".repeat(64),
        compiler_errors: directory.path().join("recovery-cargo-stderr.bin"),
        compiler_errors_sha256: "e".repeat(64),
        acquisition_records: Vec::new(),
    };
    for changed in [
        "run", "commit", "tree", "version", "target", "channel", "scope", "work", "cleanup",
    ] {
        let mut identity = identity.clone();
        let mut cell = cell.clone();
        let mut scope = "original-lease";
        let (mut work, mut cleanup) = (10, 20);
        match changed {
            "run" => identity.run_id.push('1'),
            "commit" => identity.source_commit = "f".repeat(40),
            "tree" => identity.source_tree_sha256 = "f".repeat(64),
            "version" => identity.version.push('1'),
            "target" => cell.target = "aarch64-unknown-linux-gnu".into(),
            "channel" => cell.channel = "cargo".into(),
            "scope" => scope = "foreign-lease",
            "work" => work += 1,
            "cleanup" => cleanup += 1,
            _ => unreachable!(),
        }
        let error =
            HeldRecoveryHarness::reconstruct(&owner, &identity, &cell, scope, work, cleanup)
                .err()
                .unwrap();
        assert!(
            error.to_string().contains("original association differs"),
            "{changed}: {error}"
        );
    }
    assert!(
        HeldRecoveryHarness::reconstruct(&owner, &identity, &cell, "original-lease", 10, 20)
            .is_err()
    );
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[test]
fn protected_ancestry_requires_absolute_normalized_owned_directories() {
    assert!(
        !protected_directory(std::path::Path::new("/"))
            .unwrap()
            .is_empty()
    );
    assert!(protected_directory(std::path::Path::new("relative")).is_err());
    assert!(protected_directory(std::path::Path::new("/../")).is_err());
    assert!(protected_directory(std::path::Path::new("/tmp")).is_err());
}
