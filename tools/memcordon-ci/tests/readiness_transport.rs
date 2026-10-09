use memcordon_ci::{
    Result,
    consumer_readiness_ledger::{CellEvidence, SourceIdentity},
    release::{
        artifacts,
        http::{ReadBudget, Response, Transport},
        readiness_transport,
    },
};
use memcordon_readiness_verifier::{JobResult, ProducerManifest, ProductKey};
use std::{
    collections::BTreeMap,
    io::{Cursor, Write},
    path::Path,
    time::{Duration, Instant},
};
struct Replies {
    metadata: Vec<u8>,
    zip: Vec<u8>,
}
impl Transport for Replies {
    fn request(
        &self,
        _: &str,
        url: &url::Url,
        _: &[(String, String)],
        _: &[u8],
        _: Instant,
        _: u64,
    ) -> Result<Response> {
        Ok(Response {
            status: 200,
            headers: BTreeMap::new(),
            body: if url.path().ends_with("/zip") {
                self.zip.clone()
            } else {
                self.metadata.clone()
            },
        })
    }
}
fn budget() -> ReadBudget {
    ReadBudget::new(Instant::now() + Duration::from_secs(5))
}
#[test]
fn actual_job_attempts_and_missing_owners_cannot_be_relabelled() {
    let observed=Replies{metadata:serde_json::to_vec(&serde_json::json!({"jobs":[{"name":"candidate-linux-x64-native","run_id":12,"run_attempt":3,"conclusion":"success"}]})).unwrap(),zip:Vec::new()};
    let result = readiness_transport::job_outcomes(
        &observed,
        &budget(),
        &[],
        "owner/repository",
        12,
        3,
        &["candidate-linux-x64-native", "candidate-linux-x64-cargo"],
    )
    .unwrap();
    assert_eq!(result[0].result, JobResult::Success);
    assert_eq!(result[1].result, JobResult::Missing);
    assert!(
        readiness_transport::job_outcomes(
            &observed,
            &budget(),
            &[],
            "owner/repository",
            12,
            4,
            &["candidate-linux-x64-native"]
        )
        .is_err()
    );
    let duplicate=Replies{metadata:serde_json::to_vec(&serde_json::json!({"jobs":[{"name":"candidate-linux-x64-native","run_id":12,"run_attempt":3,"conclusion":"success"},{"name":"candidate-linux-x64-native","run_id":12,"run_attempt":3,"conclusion":"success"}]})).unwrap(),zip:Vec::new()};
    assert!(
        readiness_transport::job_outcomes(
            &duplicate,
            &budget(),
            &[],
            "owner/repository",
            12,
            3,
            &["candidate-linux-x64-native"]
        )
        .is_err()
    );
}
fn payload(original_attempt: u64, mismatched_cell: bool) -> (SourceIdentity, Replies) {
    let identity = SourceIdentity {
        run_id: "12".into(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        version: "0.5.8-dev".into(),
    };
    let mut cell = CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: identity.clone(),
        key: ProductKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: Vec::new(),
        artifacts: Vec::new(),
        cleanup_failures: Vec::new(),
        cache_quiescent: false,
    };
    if mismatched_cell {
        cell.identity.version = "0.5.7".into();
    }
    let manifest = ProducerManifest {
        format: "memcordon.consumer-readiness.producer".into(),
        revision: 1,
        job: "candidate-linux-x64-native".into(),
        run_id: identity.run_id.clone(),
        run_attempt: original_attempt,
        source_commit: identity.source_commit.clone(),
        source_tree_sha256: identity.source_tree_sha256.clone(),
        version: identity.version.clone(),
        manifest_sha256: "c".repeat(64),
        artifacts: Vec::new(),
        products: Vec::new(),
        component_builds: Vec::new(),
        records: Vec::new(),
    };
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer
        .start_file("producer-manifest.json", options)
        .unwrap();
    writer
        .write_all(&serde_json::to_vec(&manifest).unwrap())
        .unwrap();
    writer.start_file("cell.json", options).unwrap();
    writer
        .write_all(&serde_json::to_vec(&cell).unwrap())
        .unwrap();
    let zip = writer.finish().unwrap().into_inner();
    let metadata=serde_json::to_vec(&serde_json::json!({"id":42,"expired":false,"name":"readiness-candidate-linux-x64-native-12-3","workflow_run":{"id":12,"head_sha":identity.source_commit},"digest":format!("sha256:{}",artifacts::checksum(&zip)),"size_in_bytes":zip.len()})).unwrap();
    (identity, Replies { metadata, zip })
}
#[test]
fn immutable_original_bundle_transport_rejects_attempt_relabel_and_cell_substitution() {
    // This checks transport custody only; an empty cell cannot pass readiness.
    for (original_attempt, mismatched_cell, expected) in
        [(3, false, true), (4, false, false), (3, true, false)]
    {
        let (identity, replies) = payload(original_attempt, mismatched_cell);
        let temp = tempfile::tempdir().unwrap();
        let result = readiness_transport::download_producer(
            &replies,
            &budget(),
            &[],
            "owner/repository",
            12,
            3,
            42,
            "candidate-linux-x64-native",
            &identity,
            &"c".repeat(64),
            &temp.path().join("producer"),
        );
        assert_eq!(
            result.is_ok(),
            expected,
            "attempt={original_attempt}, mismatched_cell={mismatched_cell}"
        );
        if let Ok(producer) = result {
            assert_eq!(producer.origin.run_attempt, 3);
            assert!(
                producer
                    .directory
                    .join(Path::new(&producer.archive.path))
                    .is_file()
            );
            assert!(!producer.cell.cache_quiescent);
        }
    }
}
