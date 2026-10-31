#[path = "../src/bin/memcordon-sealed-agent/windows/runtime_state_presence.rs"]
mod runtime_state_presence;

use runtime_state_presence::{RuntimeStatePresence, inspect};
use std::fs;

#[test]
fn absent_runtime_and_present_partial_runtime_have_distinct_dispositions() {
    let owner = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(owner.path()).unwrap();
    let runtime = parent.join("sealed");
    assert_eq!(
        inspect(&runtime, |_| Ok(())).unwrap(),
        RuntimeStatePresence::Absent
    );
    assert!(
        !runtime.exists(),
        "inspection must not bootstrap runtime state"
    );
    fs::create_dir(&runtime).unwrap();
    assert_eq!(
        inspect(&runtime, |_| Ok(())).unwrap(),
        RuntimeStatePresence::Present
    );
    // Missing runtime children require native completeness/security validation;
    // an incomplete tree must never be classified as absent and overwritten.
    fs::create_dir(runtime.join("attempts")).unwrap();
    fs::write(runtime.join("retained-state"), b"owned runtime bytes").unwrap();
    assert_eq!(
        inspect(&runtime, |_| Ok(())).unwrap(),
        RuntimeStatePresence::Present
    );
    assert_eq!(
        fs::read(runtime.join("retained-state")).unwrap(),
        b"owned runtime bytes"
    );
    owner.close().unwrap();
}

#[test]
fn component_authentication_errors_are_preserved_before_absence_classification() {
    let owner = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(owner.path()).unwrap();
    let absent = parent.join("sealed");
    let mut inspected = Vec::new();
    let error = inspect(&absent, |path| {
        inspected.push(path.to_path_buf());
        Err("original protected component inspection failure".into())
    })
    .unwrap_err();
    assert_eq!(inspected.as_slice(), std::slice::from_ref(&absent));
    assert_eq!(error, "original protected component inspection failure");
    assert!(!absent.exists());
    fs::create_dir(&absent).unwrap();
    assert_eq!(
        inspect(&absent, |_| Err("original native ACL rejection".into())).unwrap_err(),
        "original native ACL rejection"
    );
    assert!(absent.is_dir());
    owner.close().unwrap();
}

#[test]
fn regular_file_and_non_directory_ancestor_are_errors_not_restore_permission() {
    let owner = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(owner.path()).unwrap();
    let file = parent.join("sealed");
    fs::write(&file, b"unexpected retained inode").unwrap();
    for path in [&file, &file.join("child")] {
        let error = inspect(path, |_| Ok(())).unwrap_err();
        assert!(error.contains(&file.display().to_string()), "{error}");
        assert!(error.contains("non-directory-or-reparse"), "{error}");
    }
    assert_eq!(fs::read(&file).unwrap(), b"unexpected retained inode");
    owner.close().unwrap();
}

#[cfg(unix)]
#[test]
fn no_follow_inspection_rejects_directory_and_dangling_symlinks() {
    use std::os::unix::fs::symlink;

    let owner = tempfile::tempdir().unwrap();
    let parent = fs::canonicalize(owner.path()).unwrap();
    let actual = parent.join("actual");
    fs::create_dir(&actual).unwrap();
    let link = parent.join("sealed");
    symlink(&actual, &link).unwrap();
    for path in [&link, &link.join("child")] {
        let error = inspect(path, |_| Ok(())).unwrap_err();
        assert!(error.contains(&link.display().to_string()), "{error}");
        assert!(error.contains("non-directory-or-reparse"), "{error}");
    }
    fs::remove_file(&link).unwrap();
    let absent = parent.join("absent");
    symlink(&absent, &link).unwrap();
    for path in [&link, &link.join("child")] {
        let error = inspect(path, |_| Ok(())).unwrap_err();
        assert!(error.contains(&link.display().to_string()), "{error}");
        assert!(error.contains("non-directory-or-reparse"), "{error}");
    }
    assert!(!absent.exists());
    assert!(actual.is_dir());
    owner.close().unwrap();
}
