use memcordon_ci::consumer_readiness_current::{CellEvidenceV2, ingest_resolved, initialize};
use memcordon_ci::readiness_identity::SourceIdentity;
use memcordon_readiness_verifier::CaseState;
use std::path::Path;

fn identity() -> SourceIdentity {
    SourceIdentity {
        run_id: "actual-run".into(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        version: "0.5.8-dev".into(),
    }
}

#[test]
fn current_ledger_rejects_unsupported_inventory() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let directory = tempfile::tempdir().unwrap();
    let unsupported = directory.path().join("unsupported.toml");
    std::fs::write(&unsupported, "format='unsupported'\nrevision=99\n").unwrap();
    assert!(initialize(&unsupported, identity()).is_err());
    let index = initialize(&root.join("ci/consumer-readiness-v2.toml"), identity()).unwrap();
    assert_eq!(index.revision, 2);
    assert_eq!(index.workflow_cells.len(), 16);
    assert!(
        index
            .records
            .iter()
            .all(|row| row.state == CaseState::NotRun)
    );
}

#[test]
fn foreign_run_cannot_replace_a_planned_current_row() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut index = initialize(&root.join("ci/consumer-readiness-v2.toml"), identity()).unwrap();
    let key = index.workflow_cells[0].clone();
    let mut foreign = identity();
    foreign.run_id = "different-run".into();
    let row = index
        .records
        .iter()
        .find(|row| row.key.target == key.target && row.key.channel.as_ref() == Some(&key.channel))
        .unwrap()
        .clone();
    let cell = CellEvidenceV2 {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 2,
        identity: foreign,
        key,
        product: None,
        component_build: None,
        records: vec![row],
        artifacts: Vec::new(),
        cleanup_failures: Vec::new(),
        cache_quiescent: true,
    };
    let mut touched = false;
    assert!(
        ingest_resolved(&mut index, cell, |_| {
            touched = true;
            Ok(())
        })
        .is_err()
    );
    assert!(!touched);
    assert!(
        index
            .records
            .iter()
            .all(|row| row.state == CaseState::NotRun)
    );
}

#[test]
fn current_storage_rejects_unsupported_producer_revision() {
    use memcordon_readiness_verifier::current::{ProducerManifestV2, storage::decode_producer};
    let mut producer = ProducerManifestV2 {
        format: "memcordon.consumer-readiness.producer".into(),
        revision: 2,
        job: "native-linux-arm64".into(),
        run_id: "1".into(),
        run_attempt: 1,
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        version: "0.5.8-dev".into(),
        manifest_sha256: "c".repeat(64),
        artifacts: Vec::new(),
        products: Vec::new(),
        component_builds: Vec::new(),
        records: Vec::new(),
    };
    let bytes = serde_json::to_vec(&producer).unwrap();
    decode_producer(&bytes).unwrap();
    producer.revision = 99;
    assert!(decode_producer(&serde_json::to_vec(&producer).unwrap()).is_err());
}
