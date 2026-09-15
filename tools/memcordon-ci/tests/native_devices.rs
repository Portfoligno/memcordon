use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;

#[test]
fn regular_file_named_null_remains_a_content_input() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("null");
    fs::write(&input, b"original input\n").unwrap();
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    fs::write(&input, b"changed input\n").unwrap();
    assert!(snapshot.audit().is_err());
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn masked_native_unit_records_null_device_and_detects_retargeting() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let unit = root.path().join("masked.service");
    symlink("/dev/null", &unit).unwrap();
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    assert_eq!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );

    let replacement = tempfile::NamedTempFile::new().unwrap();
    fs::write(replacement.path(), b"enabled unit\n").unwrap();
    fs::remove_file(&unit).unwrap();
    symlink(replacement.path(), &unit).unwrap();
    assert!(snapshot.audit().is_err());
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_null_device_and_required_dependency_remain_unsupported() {
    use std::os::unix::fs::symlink;
    use std::path::Path;

    let root = tempfile::tempdir().unwrap();
    let unit = root.path().join("masked.service");
    symlink("/dev/null", &unit).unwrap();
    assert!(BuildInputSnapshot::capture(root.path()).is_err());
    assert!(BuildInputSnapshot::capture(Path::new("/dev/null")).is_err());
    assert!(BuildInputSnapshot::capture_native_tree(Path::new("/dev/null")).is_err());
    assert!(BuildInputSnapshot::capture_native_tree(&unit).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn non_null_character_device_is_rejected_and_invalidates_null_snapshot() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let unit = root.path().join("masked.service");
    symlink("/dev/null", &unit).unwrap();
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    fs::remove_file(&unit).unwrap();
    symlink("/dev/zero", &unit).unwrap();
    assert!(snapshot.audit().is_err());
    let error = BuildInputSnapshot::capture_native_tree(root.path()).unwrap_err();
    assert!(error.to_string().contains("unsupported build input"));
}
