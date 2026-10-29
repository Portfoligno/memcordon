use memcordon_ci::{
    consumer_readiness_current::{CellEvidenceV2 as CellEvidence, ingest_resolved, initialize},
    readiness_identity::SourceIdentity,
};
use memcordon_readiness_verifier::{CaseState, ProductKey};

fn identity() -> SourceIdentity {
    SourceIdentity {
        run_id: "ledger-test".into(),
        source_commit: "1".repeat(40),
        source_tree_sha256: "2".repeat(64),
        version: "0.5.8-dev".into(),
    }
}

#[test]
fn plan_keeps_all_channels_and_component_rows_without_claiming_observation() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ci/consumer-readiness-v2.toml");
    let index = initialize(&manifest, identity()).unwrap();
    assert_eq!(index.workflow_cells.len(), 16);
    assert!(index.products.is_empty());
    assert!(
        index
            .records
            .iter()
            .all(|r| r.state == CaseState::NotRun && r.evidence.is_none())
    );
    assert!(index.records.iter().any(|r| r.key.channel.is_none()));
    assert!(
        index
            .records
            .iter()
            .any(|r| r.key.channel.as_deref() == Some("public-cargo"))
    );
}

#[test]
fn full_manifest_evidence_uses_verifier_bound_and_refuses_oversize_before_creation() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ci/consumer-readiness-v2.toml");
    let mut index = initialize(&manifest, identity()).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let evidence = directory.path().join("evidence.json");
    memcordon_ci::consumer_readiness_current::persist(&index, &evidence).unwrap();
    let bytes = std::fs::read(&evidence).unwrap();
    assert!(bytes.len() > 1024 * 1024);
    let restored: memcordon_readiness_verifier::current::EvidenceIndexV2 =
        serde_json::from_slice(&bytes).unwrap();
    assert_eq!(restored.records.len(), index.records.len());
    assert!(
        restored
            .records
            .iter()
            .all(|row| row.state == CaseState::NotRun)
    );
    // Exercise the exact reader boundary, including the persisted newline.
    index.assessment_failures = vec![String::new(); 32];
    let base = serde_json::to_vec_pretty(&index).unwrap().len() + 1;
    let mut remaining = memcordon_readiness_verifier::MAX_INDEX_BYTES - base;
    for failure in &mut index.assessment_failures {
        let size = remaining.min(512 * 1024);
        *failure = "x".repeat(size);
        remaining -= size;
    }
    assert_eq!(remaining, 0);
    let boundary = directory.path().join("boundary.json");
    memcordon_ci::consumer_readiness_current::persist(&index, &boundary).unwrap();
    assert_eq!(
        std::fs::metadata(boundary).unwrap().len(),
        memcordon_readiness_verifier::MAX_INDEX_BYTES as u64
    );
    index.assessment_failures[0].push('x');
    let oversized = directory.path().join("oversized.json");
    assert_eq!(
        memcordon_ci::consumer_readiness_current::persist(&index, &oversized).unwrap_err(),
        "current index exceeds metadata bound"
    );
    assert!(!oversized.exists());
}

#[test]
fn wrong_source_and_channel_cannot_reassociate_existing_plan() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ci/consumer-readiness-v2.toml");
    let mut index = initialize(&manifest, identity()).unwrap();
    let mut other = identity();
    other.source_commit = "3".repeat(40);
    let cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 2,
        identity: other,
        key: ProductKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: vec![],
        artifacts: vec![],
        cleanup_failures: vec![],
        cache_quiescent: true,
    };
    assert!(ingest_resolved(&mut index, cell, |_| Ok(())).is_err());
    assert!(index.records.iter().all(|r| r.state == CaseState::NotRun));
}

#[test]
fn failed_cleanup_cannot_leave_a_producer_passed_row() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ci/consumer-readiness-v2.toml");
    let mut index = initialize(&manifest, identity()).unwrap();
    let key = ProductKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
    };
    let mut record = index
        .records
        .iter()
        .find(|row| {
            row.key.target == key.target && row.key.channel.as_deref() == Some(key.channel.as_str())
        })
        .unwrap()
        .clone();
    record.state = CaseState::Passed;
    record.reason = None;
    let record_key = record.key.clone();
    let cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 2,
        identity: identity(),
        key,
        product: None,
        component_build: None,
        records: vec![record],
        artifacts: vec![],
        cleanup_failures: vec!["native recovery uncertain".into()],
        cache_quiescent: false,
    };
    ingest_resolved(&mut index, cell, |_| Ok(())).unwrap();
    let row = index
        .records
        .iter()
        .find(|row| row.key == record_key)
        .unwrap();
    assert_eq!(row.state, CaseState::Failed);
    assert!(row.reason.as_ref().unwrap().contains("cleanup"));
    assert!(
        index
            .records
            .iter()
            .any(|row| row.state == CaseState::NotRun)
    );
}

#[test]
fn earlier_producer_run_is_preserved_when_current_assessment_merges_it() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../ci/consumer-readiness-v2.toml");
    let mut index = initialize(&manifest, identity()).unwrap();
    let mut original = identity();
    original.run_id = "original-candidate-run".into();
    let key = ProductKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
    };
    let mut record = index
        .records
        .iter()
        .find(|record| {
            record.key.target == key.target
                && record.key.channel.as_deref() == Some(key.channel.as_str())
        })
        .unwrap()
        .clone();
    record.run_id = original.run_id.clone();
    record.state = CaseState::Failed;
    record.reason = Some("actual original failure".into());
    let record_key = record.key.clone();
    let cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 2,
        identity: original.clone(),
        key,
        product: None,
        component_build: None,
        records: vec![record],
        artifacts: vec![],
        cleanup_failures: vec![],
        cache_quiescent: true,
    };
    assert!(ingest_resolved(&mut index, cell.clone(), |_| Ok(())).is_err());
    let origin = memcordon_readiness_verifier::ProducerOrigin {
        job: "candidate-linux-x64-native".into(),
        run_id: original.run_id,
        run_attempt: 1,
        artifact_id: "1".into(),
        artifact_sha256: "3".repeat(64),
        bundle_artifact: "original.bundle".into(),
        source_commit: original.source_commit,
        source_tree_sha256: original.source_tree_sha256,
        version: original.version,
        manifest_sha256: index.manifest_sha256.clone(),
        repository: None,
    };
    memcordon_ci::consumer_readiness_current::record_origin(&mut index, origin).unwrap();
    ingest_resolved(&mut index, cell, |_| Ok(())).unwrap();
    assert_eq!(index.run_id, "ledger-test");
    let merged = index
        .records
        .iter()
        .find(|row| row.key == record_key)
        .unwrap();
    assert_eq!(merged.run_id, "original-candidate-run");
    assert_eq!(merged.state, CaseState::Failed);
}

#[test]
fn job_operands_preserve_actual_non_success_and_reject_ambiguous_inputs() {
    use memcordon_ci::readiness_identity::parse_job_outcomes;
    use memcordon_readiness_verifier::JobResult;
    let rows = parse_job_outcomes(&[
        "candidate-linux-x64-native=failure".into(),
        "native-linux-x64=cancelled".into(),
        "public-linux-x64-cargo=skipped".into(),
    ])
    .unwrap();
    assert_eq!(rows[0].result, JobResult::Failure);
    assert_eq!(rows[1].result, JobResult::Cancelled);
    assert_eq!(rows[2].result, JobResult::Skipped);
    for arguments in [
        vec![
            "candidate-linux-x64-native=success".into(),
            "candidate-linux-x64-native=failure".into(),
        ],
        vec!["candidate-linux-x64-native=unknown".into()],
        vec!["unselected-job=success".into()],
        vec!["candidate-linux-x64-native=success=other".into()],
    ] {
        assert!(parse_job_outcomes(&arguments).is_err());
    }
}
