use memcordon_ci::{
    Result,
    consumer_readiness_ledger::{CellEvidence, SourceIdentity},
    release::{
        artifacts,
        http::{ReadBudget, Response, StreamedResponse, StreamingTransport, Transport},
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
            body: {
                assert!(
                    !url.path().ends_with("/zip"),
                    "producer ZIP must use streaming transport"
                );
                self.metadata.clone()
            },
        })
    }
}
impl StreamingTransport for Replies {
    fn request_to(
        &self,
        url: &url::Url,
        _: &[(String, String)],
        _: Instant,
        maximum: u64,
        destination: &mut dyn Write,
    ) -> Result<StreamedResponse> {
        assert!(url.path().ends_with("/zip"));
        if self.zip.len() as u64 > maximum {
            return Err(memcordon_ci::CiError::Message(
                "fixture stream exceeds bound".into(),
            ));
        }
        destination.write_all(&self.zip)?;
        Ok(StreamedResponse {
            status: 200,
            headers: BTreeMap::new(),
            length: self.zip.len() as u64,
        })
    }
}
fn budget() -> ReadBudget {
    ReadBudget::new(Instant::now() + Duration::from_secs(5))
}
#[test]
fn producer_outcomes_require_exact_names_and_preserve_actual_conclusions() {
    let observed = Replies {
        metadata: serde_json::to_vec(&serde_json::json!({"jobs":[
            {"name":"native-linux-x64 (x86_64-unknown-linux-gnu, ubuntu-24.04)","run_id":12,"run_attempt":3,"conclusion":"success"},
            {"name":"candidate-linux-x64-native","run_id":12,"run_attempt":3,"conclusion":"success"},
            {"name":"candidate-linux-x64-cargo","run_id":12,"run_attempt":3,"conclusion":"cancelled"},
            {"name":"candidate-windows-x64-native","run_id":12,"run_attempt":3,"conclusion":"skipped"},
            {"name":"candidate-windows-x64-cargo","run_id":12,"run_attempt":3,"conclusion":"failure"}
        ]})).unwrap(),
        zip: Vec::new(),
    };
    let result = readiness_transport::job_outcomes(
        &observed,
        &budget(),
        &[],
        "owner/repository",
        12,
        3,
        &[
            "native-linux-x64",
            "candidate-linux-x64-native",
            "candidate-linux-x64-cargo",
            "candidate-windows-x64-native",
            "candidate-windows-x64-cargo",
        ],
    )
    .unwrap();
    assert_eq!(
        result
            .iter()
            .map(|outcome| outcome.result)
            .collect::<Vec<_>>(),
        [
            JobResult::Missing,
            JobResult::Success,
            JobResult::Cancelled,
            JobResult::Skipped,
            JobResult::Failure,
        ]
    );
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

fn packed_payload(omit_object: bool) -> (SourceIdentity, Replies) {
    use memcordon_readiness_verifier::{
        Artifact,
        storage::{ArtifactBinding, PackedProducerManifestV1, object_path},
    };
    use std::io::Read;
    let (identity, original) = payload(3, false);
    let mut original = zip::ZipArchive::new(Cursor::new(original.zip)).unwrap();
    let mut cell_bytes = Vec::new();
    original
        .by_name("cell.json")
        .unwrap()
        .read_to_end(&mut cell_bytes)
        .unwrap();
    let mut cell: CellEvidence = serde_json::from_slice(&cell_bytes).unwrap();
    let mut manifest_bytes = Vec::new();
    original
        .by_name("producer-manifest.json")
        .unwrap()
        .read_to_end(&mut manifest_bytes)
        .unwrap();
    let mut producer: ProducerManifest = serde_json::from_slice(&manifest_bytes).unwrap();
    producer.manifest_sha256 = artifacts::checksum(b"packed-fixture-manifest");
    let digest = artifacts::checksum(b"same");
    let objects = vec![Artifact {
        path: object_path(&digest).unwrap(),
        length: b"same".len() as u64,
        sha256: digest.clone(),
    }];
    cell.artifacts = ["first", "second"]
        .into_iter()
        .map(|name| Artifact {
            path: format!("x86_64-unknown-linux-gnu/candidate-native/{name}"),
            length: b"same".len() as u64,
            sha256: digest.clone(),
        })
        .collect();
    producer.artifacts = cell.artifacts.clone();
    let envelope = PackedProducerManifestV1 {
        format: "memcordon.consumer-readiness.packed-producer".into(),
        revision: 1,
        bindings: cell
            .artifacts
            .iter()
            .map(|logical| ArtifactBinding {
                logical_path: logical.path.clone(),
                object_path: objects[0].path.clone(),
            })
            .collect(),
        objects: objects.clone(),
        producer,
    };
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default();
    writer
        .start_file("producer-manifest.json", options)
        .unwrap();
    writer
        .write_all(&serde_json::to_vec(&envelope).unwrap())
        .unwrap();
    writer.start_file("cell.json", options).unwrap();
    writer
        .write_all(&serde_json::to_vec(&cell).unwrap())
        .unwrap();
    if !omit_object {
        writer.start_file(&objects[0].path, options).unwrap();
        writer.write_all(b"same").unwrap();
    }
    let zip = writer.finish().unwrap().into_inner();
    let metadata = serde_json::to_vec(&serde_json::json!({"id":42,"expired":false,"name":"readiness-candidate-linux-x64-native-12-3",
        "workflow_run":{"id":12,"head_sha":identity.source_commit},"digest":format!("sha256:{}",artifacts::checksum(&zip)),"size_in_bytes":zip.len()})).unwrap();
    (identity, Replies { metadata, zip })
}

#[test]
fn packed_transport_and_report_keep_logical_custody_and_every_original_archive() {
    use memcordon_ci::consumer_readiness_ledger::{self as ledger, PackedLedger};
    let root = if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    };
    let (identity, replies) = packed_payload(false);
    let manifest_digest = artifacts::checksum(b"packed-fixture-manifest");
    let producer = readiness_transport::download_producer(
        &replies,
        &budget(),
        &[],
        "owner/repository",
        12,
        3,
        42,
        "candidate-linux-x64-native",
        &identity,
        &manifest_digest,
        &root.path().join("producer"),
    )
    .unwrap();
    assert_eq!(producer.storage.physical_artifacts().count(), 1);
    assert_eq!(producer.cell.artifacts.len(), 2);
    for logical in &producer.cell.artifacts {
        assert!(!producer.directory.join(&logical.path).exists());
    }
    let output = root.path().join("report-artifacts");
    std::fs::create_dir(&output).unwrap();
    let mut index = ledger::initialize(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../ci/consumer-readiness-v1.toml")
            .as_path(),
        identity.clone(),
    )
    .unwrap();
    index.manifest_sha256 = manifest_digest.clone();
    let mut packed = PackedLedger::default();
    packed.check_archive(&index, &producer.archive).unwrap();
    readiness_transport::retain_downloaded_archive(
        &producer.directory,
        &producer.archive,
        &output.join(&producer.archive.path),
        budget().deadline(),
    )
    .unwrap();
    index.artifacts.push(producer.archive.clone());
    ledger::record_origin(&mut index, producer.origin).unwrap();
    packed
        .ingest(
            &mut index,
            producer.cell,
            &producer.directory,
            &output,
            &producer.storage,
        )
        .unwrap();
    let evidence = root.path().join("evidence.json");
    packed.persist(&index, &evidence, &output).unwrap();
    let bytes = std::fs::read(evidence).unwrap();
    let (logical, storage) =
        memcordon_readiness_verifier::storage::decode_evidence(&bytes).unwrap();
    assert_eq!(logical.artifacts.len(), 3);
    assert_eq!(logical.producer_origins.len(), 1);
    assert_eq!(storage.physical_artifacts().count(), 2);
    assert_eq!(
        std::fs::read(output.join(&producer.archive.path)).unwrap(),
        replies.zip
    );
    // This transport-only cell has no readiness rows; storage cannot invent a pass.
    assert!(logical.products.is_empty());
    let (_, missing) = packed_payload(true);
    assert!(
        readiness_transport::download_producer(
            &missing,
            &budget(),
            &[],
            "owner/repository",
            12,
            3,
            42,
            "candidate-linux-x64-native",
            &identity,
            &manifest_digest,
            &root.path().join("missing-own-object")
        )
        .is_err()
    );
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
            readiness_transport::check_evidence_budget(&[], &producer).unwrap();
            let existing = memcordon_readiness_verifier::Artifact {
                path: "prior-evidence".into(),
                length: memcordon_readiness_verifier::MAX_PRODUCER_BYTES,
                sha256: "d".repeat(64),
            };
            assert!(readiness_transport::check_evidence_budget(&[existing], &producer).is_err());
            let retained = temp.path().join("retained.zip");
            readiness_transport::retain_downloaded_archive(
                &producer.directory,
                &producer.archive,
                &retained,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
            assert_eq!(std::fs::read(retained).unwrap(), replies.zip);
        }
    }
}

#[test]
fn producer_stream_rejects_metadata_overrun_truncation_and_digest_without_admission() {
    for mutation in ["oversize", "truncated", "overrun", "digest"] {
        let (identity, mut replies) = payload(3, false);
        let mut metadata: serde_json::Value = serde_json::from_slice(&replies.metadata).unwrap();
        match mutation {
            "oversize" => {
                metadata["size_in_bytes"] =
                    (memcordon_readiness_verifier::MAX_PRODUCER_ARCHIVE_BYTES + 1).into()
            }
            "truncated" => metadata["size_in_bytes"] = (replies.zip.len() as u64 + 1).into(),
            "overrun" => metadata["size_in_bytes"] = (replies.zip.len() as u64 - 1).into(),
            "digest" => metadata["digest"] = format!("sha256:{}", "d".repeat(64)).into(),
            _ => unreachable!(),
        }
        replies.metadata = serde_json::to_vec(&metadata).unwrap();
        let owner = tempfile::tempdir().unwrap();
        let destination = owner.path().join("producer");
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
            &destination,
        );
        assert!(result.is_err(), "{mutation}");
        if destination.exists() {
            assert_eq!(
                std::fs::read_dir(&destination).unwrap().count(),
                0,
                "{mutation} must remove partial transfer"
            );
        }
    }
}

#[test]
fn failed_stream_removes_partial_file_before_returning_error() {
    struct Interrupted(Replies);
    impl Transport for Interrupted {
        fn request(
            &self,
            method: &str,
            url: &url::Url,
            headers: &[(String, String)],
            body: &[u8],
            deadline: Instant,
            maximum: u64,
        ) -> Result<Response> {
            self.0
                .request(method, url, headers, body, deadline, maximum)
        }
    }
    impl StreamingTransport for Interrupted {
        fn request_to(
            &self,
            _: &url::Url,
            _: &[(String, String)],
            _: Instant,
            _: u64,
            destination: &mut dyn Write,
        ) -> Result<StreamedResponse> {
            destination.write_all(b"partial")?;
            Err(memcordon_ci::CiError::Message(
                "fixture interrupted stream".into(),
            ))
        }
    }
    let (identity, replies) = payload(3, false);
    let owner = tempfile::tempdir().unwrap();
    let destination = owner.path().join("producer");
    let error = readiness_transport::download_producer(
        &Interrupted(replies),
        &budget(),
        &[],
        "owner/repository",
        12,
        3,
        42,
        "candidate-linux-x64-native",
        &identity,
        &"c".repeat(64),
        &destination,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("artifact=42"));
    assert_eq!(std::fs::read_dir(destination).unwrap().count(), 0);
}
