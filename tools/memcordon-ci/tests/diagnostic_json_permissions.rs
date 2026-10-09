#![cfg(unix)]

use memcordon_ci::release::source;
use serde_json::json;
use std::os::unix::fs::MetadataExt;

#[test]
fn diagnostic_publication_is_readable_without_changing_private_link_target() {
    let root = tempfile::tempdir().unwrap();
    let private = root.path().join("administrator-policy.json");
    source::write_json(&private, &json!({"private": "original authority"})).unwrap();
    let original = std::fs::read(&private).unwrap();
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o600);

    let diagnostic = root.path().join("source-check.json");
    std::os::unix::fs::symlink(&private, &diagnostic).unwrap();
    let observation = json!({"phase": "source-check", "state": "failed"});
    source::write_diagnostic_json(&diagnostic, &observation).unwrap();
    assert!(std::fs::symlink_metadata(&diagnostic).unwrap().is_file());
    let metadata = std::fs::metadata(&diagnostic).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o644);
    assert_eq!(metadata.uid(), std::fs::metadata(&private).unwrap().uid());
    let mut expected = serde_json::to_vec_pretty(&observation).unwrap();
    expected.push(b'\n');
    assert_eq!(std::fs::read(&diagnostic).unwrap(), expected);
    assert_eq!(std::fs::read(&private).unwrap(), original);
    assert_eq!(std::fs::metadata(&private).unwrap().mode() & 0o777, 0o600);
}

#[test]
fn oversized_diagnostic_does_not_replace_existing_observation() {
    let root = tempfile::tempdir().unwrap();
    let diagnostic = root.path().join("source-check.json");
    source::write_diagnostic_json(&diagnostic, &json!({"state": "original failure"})).unwrap();
    let original = std::fs::read(&diagnostic).unwrap();
    let oversized = "x".repeat(1024 * 1024);
    assert!(source::write_diagnostic_json(&diagnostic, &oversized).is_err());
    assert_eq!(std::fs::read(&diagnostic).unwrap(), original);
    assert_eq!(
        std::fs::metadata(&diagnostic).unwrap().mode() & 0o777,
        0o644
    );
}

#[test]
fn readable_native_failure_snapshot_retains_unresolved_owner_state() {
    use memcordon_ci::consumer_readiness_ledger::{CellEvidence, SourceIdentity};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("component-failure.json");
    let cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: SourceIdentity {
            run_id: "failed-native-run".into(),
            source_commit: "1".repeat(40),
            source_tree_sha256: "2".repeat(64),
            version: "0.5.8-dev".into(),
        },
        key: memcordon_readiness_verifier::ProductKey {
            target: "aarch64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: Vec::new(),
        artifacts: Vec::new(),
        cleanup_failures: vec!["original native recovery remains unresolved".into()],
        cache_quiescent: false,
    };
    source::write_diagnostic_json(&path, &cell).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
    let restored: CellEvidence = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert!(!restored.cache_quiescent);
    assert!(restored.product.is_none());
    assert_eq!(restored.cleanup_failures, cell.cleanup_failures);
    assert_eq!(restored.identity.source_commit, cell.identity.source_commit);
}
