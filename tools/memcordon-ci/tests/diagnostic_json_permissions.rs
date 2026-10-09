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
