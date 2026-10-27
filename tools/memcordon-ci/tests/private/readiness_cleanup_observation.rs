use super::*;
#[path = "../../src/release/linux_export_failure.rs"]
mod original_capture;

fn producer_record() -> Vec<u8> {
    let attempt = "0123456789abcdef0123456789abcdef";
    let result = std::path::Path::new("/owned/export-symlink/launch/result.json");
    let request = result
        .parent()
        .unwrap()
        .join("observations")
        .join(std::path::Path::new(attempt).with_extension("provider-request.bin"));
    original_capture::binding(attempt, result, result, &request).unwrap();
    let capture = original_capture::capture(Ok(vec![
            0xab;
            producer_failure_forwarding::CAPTURE_PREFIX_BYTES
        ]));
    let fields = [
        "native_wait",
        "invocation",
        "stdout",
        "stderr",
        "provider_terminal",
        "report_delivery_failure",
    ];
    let metadata_budget = producer_failure_forwarding::RECORD_BOUND
        - fields.len() * producer_failure_forwarding::CAPTURE_PREFIX_BYTES * 2;
    let seed = "\0";
    let escaped_metadata = seed.repeat(metadata_budget / serde_json::to_vec(seed).unwrap().len());
    let mut value = serde_json::json!({"format":"memcordon.original-export-producer-failure","revision":1,"diagnostic_only":true,
        "attempt_id":attempt,"required_result":result,"escaped_metadata":escaped_metadata});
    for field in fields {
        value[field] = capture.clone();
    }
    let mut record = producer_failure_forwarding::MARKER.to_vec();
    record.extend_from_slice(&serde_json::to_vec(&value).unwrap());
    record.push(b'\n');
    record
}

#[test]
fn original_complete_producer_record_survives_outside_the_generic_excerpt() {
    let record = producer_record();
    assert!(record.len() > 64 * 1024 && record.len() <= producer_failure_forwarding::RECORD_BOUND);
    let mut observed = output(false).unwrap();
    observed.stderr = vec![b'h'; 80 * 1024];
    observed.stderr.push(b'\n');
    observed.stderr.extend_from_slice(&record);
    observed.stderr.extend_from_slice(&vec![b't'; 80 * 1024]);
    let mut forwarded = Vec::new();
    let selected = producer_failure_forwarding::inspect(Some(&observed.stderr));
    assert_eq!(selected.record, Some(record.as_slice()));
    selected.write_to(&mut forwarded).unwrap();
    assert!(forwarded.starts_with(&record));
    let summary: serde_json::Value = serde_json::from_slice(
        forwarded
            .split(|byte| *byte == b'\n')
            .find_map(|line| line.strip_prefix(b"export-producer-forwarding "))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(summary["forwarded_bytes"], record.len());
    assert_eq!(summary["forwarded_sha256"], {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(&record))
    });
    let generic = command_failure(&Ok(observed));
    assert!(generic.len() < 2 * 64 * 1024 + 1024);
    assert!(!generic.contains("export-original-producer-failure"));
}

#[test]
fn incomplete_oversized_invalid_multiple_and_missing_records_are_explicit() {
    let record = producer_record();
    let incomplete =
        producer_failure_forwarding::inspect(Some(&record[..record.len() - b"\n".len()]));
    assert_eq!(incomplete.counts.incomplete_records, 1);
    assert!(incomplete.record.is_none());
    let mut oversized = producer_failure_forwarding::MARKER.to_vec();
    oversized.extend(vec![b'x'; producer_failure_forwarding::RECORD_BOUND]);
    oversized.push(b'\n');
    let oversized = producer_failure_forwarding::inspect(Some(&oversized));
    assert_eq!(oversized.counts.oversized_records, 1);
    assert!(oversized.record.is_none());
    let invalid = b"export-original-producer-failure {\n";
    assert_eq!(
        producer_failure_forwarding::inspect(Some(invalid))
            .counts
            .invalid_records,
        1
    );
    let mut multiple = record.clone();
    multiple.extend_from_slice(&record);
    let selected = producer_failure_forwarding::inspect(Some(&multiple));
    assert_eq!(selected.record, Some(record.as_slice()));
    assert_eq!(selected.counts.matching_records, 2);
    assert_eq!(selected.counts.omitted_valid_records, 1);
    assert!(
        producer_failure_forwarding::inspect(Some(b"ordinary original failure\n"))
            .record
            .is_none()
    );
    assert!(
        !producer_failure_forwarding::inspect(None)
            .counts
            .capture_available
    );
}

#[test]
fn forwarding_sink_failure_cannot_change_the_original_command_failure() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let observed = output(false);
    let original = command_failure(&observed);
    let selected = producer_failure_forwarding::inspect(
        observed.as_ref().ok().map(|value| value.stderr.as_slice()),
    );
    assert!(selected.write_to(&mut Broken).is_err());
    assert_eq!(command_failure(&observed), original);
    struct Partial {
        bytes: Vec<u8>,
        remaining: usize,
    }
    impl std::io::Write for Partial {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let count = bytes.len().min(self.remaining);
            self.bytes.extend_from_slice(&bytes[..count]);
            self.remaining -= count;
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let record = producer_record();
    let mut partial = Partial {
        bytes: Vec::new(),
        remaining: record.len() / 2,
    };
    assert!(
        producer_failure_forwarding::inspect(Some(&record))
            .write_to(&mut partial)
            .is_err()
    );
    assert_eq!(partial.bytes, &record[..record.len() / 2]);
    let completion_marker = b"export-producer-forwarding ";
    assert!(
        !partial
            .bytes
            .windows(completion_marker.len())
            .any(|bytes| bytes == completion_marker)
    );
    assert_eq!(command_failure(&observed), original);
}

fn settled_cell() -> CellEvidence {
    CellEvidence {
        format: "memcordon.consumer-readiness.cell".into(),
        revision: 1,
        identity: SourceIdentity {
            run_id: "1".into(),
            source_commit: "a".repeat(40),
            source_tree_sha256: "b".repeat(64),
            version: "0.5.8-dev".into(),
        },
        key: memcordon_readiness_verifier::ProductKey {
            target: "x86_64-unknown-linux-gnu".into(),
            channel: "candidate-native".into(),
        },
        product: None,
        component_build: None,
        records: vec![],
        artifacts: vec![],
        cleanup_failures: vec![],
        cache_quiescent: true,
    }
}

fn output(success: bool) -> memcordon_ci::Result<memcordon_testkit::ObservedOutput> {
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 256 })
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(if success { 0 } else { 1 })
    };
    Ok(memcordon_testkit::ObservedOutput {
        status,
        stdout: vec![],
        stderr: b"retained inner recovery failure".to_vec(),
        elapsed: std::time::Duration::ZERO,
    })
}

#[test]
fn cleanup_requires_both_command_and_settled_cell_and_retains_each_failure() {
    assert!(cleanup_failures(&output(true), &Ok(settled_cell())).is_empty());
    let failed_command = cleanup_failures(&output(false), &Ok(settled_cell())).join("; ");
    assert!(failed_command.contains("retained inner recovery failure"));
    assert!(failed_command.contains("status="));

    let missing_cell =
        cleanup_failures(&output(true), &Err("cell access denied".into())).join("; ");
    assert!(missing_cell.contains("cell access denied"));
    let mut cell = settled_cell();
    cell.cleanup_failures.push("native owner still held".into());
    let unsettled = cleanup_failures(&output(true), &Ok(cell)).join("; ");
    assert!(unsettled.contains("native owner still held"));

    let failed_observation = Err(memcordon_ci::CiError::Message(
        "spawn observation unavailable".into(),
    ));
    let combined = cleanup_failures(&failed_observation, &Err("cell absent".into()));
    assert_eq!(combined.len(), 2);
    assert!(combined[0].contains("spawn observation unavailable"));
    assert!(combined[1].contains("cell absent"));
}
