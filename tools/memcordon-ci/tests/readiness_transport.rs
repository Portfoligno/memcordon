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
