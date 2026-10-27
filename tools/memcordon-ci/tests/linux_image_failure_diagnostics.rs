#[path = "../src/release/linux_image_failure_diagnostics.rs"]
mod diagnostics;
use serde_json::{Value, json};

#[test]
fn original_pre_neighbor_failure_retains_exact_cause_and_binding() {
    let errors = vec!["select_startup_members: actual original failure".to_owned()];
    let binding = json!({"identity":{"source_commit":"retained-source"},"cell":{"target":"native-host"},"lease_id":"original-lease","work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    let bytes = diagnostics::encode(
        binding.clone(),
        "select-startup-members",
        None,
        &errors,
        false,
    )
    .unwrap();
    let record: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["binding"], binding);
    assert_eq!(record["failures"][0]["error"], errors[0]);
    assert_eq!(record["neighbor_observation_created"], false);
    assert_eq!(record["diagnostic_only"], true);
    assert_eq!(record["failures"][0]["truncated"], false);
    let original = diagnostics::primary(
        "select-startup-members",
        None,
        &errors,
        Some("retention refused"),
    )
    .unwrap();
    assert!(original.contains(&errors[0]));
    assert!(original.contains("retention refused"));
    assert_eq!(serde_json::from_slice::<Value>(&bytes).unwrap(), record);
    assert!(diagnostics::encode(json!({}), "selection", None, &[], false).is_err());
    assert!(diagnostics::primary("selection", None, &[], None).is_none());
    let expected = memcordon_readiness_verifier::Artifact {
        path: "selected-cell/image-cases/image-case-failures.json".into(),
        length: bytes.len() as u64,
        sha256: memcordon_ci::release::artifacts::checksum(&bytes),
    };
    diagnostics::validate_artifact(&expected, &expected).unwrap();
    let mut changed = expected.clone();
    changed.sha256 = memcordon_ci::release::artifacts::checksum(b"different bytes");
    assert!(diagnostics::validate_artifact(&expected, &changed).is_err());
    changed = expected.clone();
    changed.path = "../escaped.json".into();
    assert!(diagnostics::validate_artifact(&changed, &changed).is_err());
    changed = expected.clone();
    changed.length = diagnostics::RECORD_BOUND as u64 + 1;
    assert!(diagnostics::validate_artifact(&changed, &changed).is_err());
}

#[test]
fn original_text_truncation_and_later_failure_omissions_are_explicit_and_utf8_safe() {
    let error = "界😀\"\n".repeat(diagnostics::RECORD_BOUND);
    let errors = vec![error.clone(); 16];
    let bytes =
        diagnostics::encode(json!({}), "import", Some("neighbor-import"), &errors, false).unwrap();
    assert!(bytes.len() <= diagnostics::RECORD_BOUND);
    let record: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(record["failure_count"], errors.len());
    assert!(record["omitted_failure_count"].as_u64().unwrap() > 0);
    for entry in record["failures"].as_array().unwrap() {
        let retained = entry["error"].as_str().unwrap();
        assert!(error.starts_with(retained));
        assert_eq!(entry["original_bytes"], error.len());
        assert_eq!(entry["truncated"], true);
    }
    let primary = diagnostics::primary("import", Some("neighbor-import"), &errors, None).unwrap();
    assert!(primary.contains("[truncated; original_bytes="));
    assert!(primary.len() < diagnostics::RECORD_BOUND);
}

#[cfg(unix)]
#[test]
fn registered_image_failure_survives_normalization_but_rejects_replacement_hash_and_escape() {
    use memcordon_ci::{
        CiError,
        consumer_readiness_ledger::SourceIdentity,
        release::linux_lifecycle_diagnostics::{
            HeldCellPublication, capture_before_normalize, register_existing,
        },
    };
    use memcordon_readiness_verifier::{Artifact, ProductKey};
    use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt};
    let root = tempfile::tempdir().unwrap();
    let identity = SourceIdentity {
        run_id: "failure-retention".into(),
        source_commit: "0123456789012345678901234567890123456789".into(),
        source_tree_sha256: memcordon_ci::release::artifacts::checksum(b"selected source"),
        version: "0.5.8-dev".into(),
    };
    let cell = ProductKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
    };
    let anchor = HeldCellPublication::create(root.path(), &identity, &cell).unwrap();
    let bytes = diagnostics::encode(
        json!({"identity":identity,"cell":cell,"lease_id":"original-lease"}),
        "select-startup-members",
        None,
        &["exact original failure".into()],
        false,
    )
    .unwrap();
    let path = anchor.prefix().join("image-case-failures.json");
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o444)
        .open(&path)
        .unwrap();
    writer.write_all(&bytes).unwrap();
    writer.sync_all().unwrap();
    drop(writer);
    let original = OpenOptions::new().read(true).open(&path).unwrap();
    let expected = Artifact {
        path: path
            .strip_prefix(root.path())
            .unwrap()
            .to_str()
            .unwrap()
            .into(),
        length: bytes.len() as u64,
        sha256: memcordon_ci::release::artifacts::checksum(&bytes),
    };
    let mut artifacts = Vec::new();
    let (captured, normalized) = capture_before_normalize(
        &mut artifacts,
        |out| {
            let before = original.metadata()?;
            let mut actual = Vec::new();
            let held = register_existing(&anchor, &path, &mut actual)?;
            diagnostics::validate_registration(
                &expected,
                &actual[0],
                &before,
                &original.metadata()?,
                &held.metadata()?,
            )
            .map_err(CiError::Message)?;
            out.extend(actual);
            Ok(())
        },
        || {
            Err::<(), _>(CiError::Message(
                "image negatives lack actual neighboring import observation".into(),
            ))
        },
    );
    captured.unwrap();
    assert!(normalized.is_err());
    assert_eq!(artifacts.len(), 1);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let mut forged = expected.clone();
    forged.sha256 = memcordon_ci::release::artifacts::checksum(b"replacement");
    assert!(diagnostics::validate_artifact(&forged, &artifacts[0]).is_err());
    forged = expected.clone();
    forged.path = "../outside/image-case-failures.json".into();
    assert!(diagnostics::validate_artifact(&forged, &forged).is_err());
    let before = original.metadata().unwrap();
    std::fs::rename(&path, path.with_extension("original")).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    std::fs::set_permissions(&path, original.metadata().unwrap().permissions()).unwrap();
    let mut substituted = Vec::new();
    let held = register_existing(&anchor, &path, &mut substituted).unwrap();
    assert!(
        diagnostics::validate_registration(
            &expected,
            &substituted[0],
            &before,
            &original.metadata().unwrap(),
            &held.metadata().unwrap()
        )
        .is_err()
    );
    let other = tempfile::tempdir().unwrap();
    let outside = other.path().join("image-case-failures.json");
    std::fs::write(&outside, &bytes).unwrap();
    assert!(register_existing(&anchor, &outside, &mut Vec::new()).is_err());
}
