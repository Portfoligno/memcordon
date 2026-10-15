use memcordon_ci::windows_component_query_evidence::{retain_invocation, retain_result};
use std::{process::Command, time::Duration};

#[test]
fn actual_nonzero_query_is_retained_before_any_output_decoding() {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new("rustc");
    command.arg("--definitely-invalid-live-query-evidence-option");
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(10),
        memcordon_core::WindowsGuardianAttemptObservation::MAX_FRAME_BYTES,
    )
    .unwrap();
    assert!(!output.status.success());
    assert!(!output.stderr.is_empty());
    let expected_stdout = output.stdout.clone();
    let expected_stderr = output.stderr.clone();
    let expected_status = format!("{:?}", output.status);
    let invocation = serde_json::to_vec(&serde_json::json!({
        "guardian":{"process_id":7,"creation_time_100ns":134364958304946298_u64},
        "argv":["--definitely-invalid-live-query-evidence-option"]
    }))
    .unwrap();
    retain_invocation(directory.path(), &invocation).unwrap();
    let result = Ok(output);
    retain_result(directory.path(), &result).unwrap();
    assert_eq!(
        std::fs::read(directory.path().join("live-association-query.stdout.bin")).unwrap(),
        expected_stdout
    );
    assert_eq!(
        std::fs::read(directory.path().join("live-association-query.stderr.bin")).unwrap(),
        expected_stderr
    );
    let evidence: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.path().join("live-association-query-result.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(evidence["observation"]["kind"], "completed");
    assert_eq!(evidence["observation"]["status"], expected_status);
    let invocation: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            directory
                .path()
                .join("live-association-query-invocation.json"),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        invocation["guardian"]["creation_time_100ns"].as_u64(),
        Some(134364958304946298)
    );
    assert!(retain_result(directory.path(), &result).is_err());
    assert_eq!(
        std::fs::read(directory.path().join("live-association-query.stderr.bin")).unwrap(),
        expected_stderr
    );
}

#[test]
fn actual_spawn_refusal_does_not_fabricate_streams_status_or_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let mut command = Command::new(directory.path().join("not-an-executable"));
    let result = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(10),
        1024,
    );
    assert!(matches!(
        result,
        Err(memcordon_testkit::ProcessTestError::Spawn(_))
    ));
    retain_result(directory.path(), &result).unwrap();
    let evidence: serde_json::Value = serde_json::from_slice(
        &std::fs::read(directory.path().join("live-association-query-result.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(evidence["streams_available"], false);
    assert_eq!(evidence["observation"]["kind"], "spawn");
    assert!(evidence["observation"].get("termination").is_none());
    assert!(evidence["observation"].get("cleanup").is_none());
    assert!(
        !directory
            .path()
            .join("live-association-query.stdout.bin")
            .exists()
    );
    assert!(
        !directory
            .path()
            .join("live-association-query.stderr.bin")
            .exists()
    );
}
