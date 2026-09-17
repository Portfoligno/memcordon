use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;

#[test]
fn audit_reports_added_removed_and_changed_inputs_without_contents() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("removed"), "old").unwrap();
    fs::write(root.path().join("changed"), "old").unwrap();
    let before = BuildInputSnapshot::capture(root.path()).unwrap();
    fs::remove_file(root.path().join("removed")).unwrap();
    fs::write(root.path().join("added"), "new private contents").unwrap();
    fs::write(root.path().join("changed"), "changed private contents").unwrap();
    let message = before.audit().unwrap_err().to_string();
    assert!(message.contains("added=1 removed=1 changed=1 samples=3 omitted=0"));
    assert!(message.contains("fields=digest"));
    assert!(!message.contains("private contents"));
    let native_path = root.path().canonicalize().unwrap().join("added");
    assert!(message.contains(&hex::encode(native_path.as_os_str().as_encoded_bytes())));
}

#[test]
fn audit_samples_are_bounded_and_deterministic_but_counts_are_complete() {
    let root = tempfile::tempdir().unwrap();
    let before = BuildInputSnapshot::capture(root.path()).unwrap();
    for ordinal in 0..24 {
        fs::write(root.path().join(format!("input-{ordinal:02}")), "data").unwrap();
    }
    let first = before.audit().unwrap_err().to_string();
    assert!(first.contains("added=24 removed=0 changed=0 samples=8 omitted=16"));
    assert_eq!(first.matches("path_hex=").count(), 8);
    assert_eq!(first, before.audit().unwrap_err().to_string());
    assert!(first.len() < 8192);
}
