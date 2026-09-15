#![cfg(unix)]

use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

struct RestrictedDirectory(PathBuf);

impl RestrictedDirectory {
    fn new(path: &Path, mode: u32) -> Self {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        Self(path.to_owned())
    }

    fn make_readable(&self) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Drop for RestrictedDirectory {
    fn drop(&mut self) {
        self.make_readable();
    }
}

fn assert_enumeration_denied(path: &Path) {
    let error =
        fs::read_dir(path).expect_err("permission fixtures require an unprivileged test process");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[test]
fn required_tree_rejects_inaccessible_directory() {
    let root = tempfile::tempdir().unwrap();
    let denied = root.path().join("required-inputs");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("input"), b"required bytes\n").unwrap();
    let _permissions = RestrictedDirectory::new(&denied, 0);
    assert_enumeration_denied(&denied);

    assert!(BuildInputSnapshot::capture(root.path()).is_err());
    assert!(BuildInputSnapshot::capture(&denied).is_err());
}

#[test]
fn required_tree_rejects_unlisted_but_readable_child() {
    let root = tempfile::tempdir().unwrap();
    let searchable = root.path().join("searchable");
    fs::create_dir(&searchable).unwrap();
    let known = searchable.join("known-input");
    fs::write(&known, b"bytes still influence compilation\n").unwrap();
    let _permissions = RestrictedDirectory::new(&searchable, 0o100);
    assert_enumeration_denied(&searchable);
    assert_eq!(
        fs::read(&known).unwrap(),
        b"bytes still influence compilation\n"
    );

    assert!(BuildInputSnapshot::capture(root.path()).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_discovery_records_blocked_symlink_target_and_audits_access_changes() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let denied = external.path().join("private-inputs");
    fs::create_dir(&denied).unwrap();
    fs::write(denied.join("input"), b"not accessible to compilation\n").unwrap();
    symlink(&denied, root.path().join("discovered-alias")).unwrap();
    let permissions = RestrictedDirectory::new(&denied, 0);
    assert_enumeration_denied(&denied);
    assert_eq!(
        fs::read(denied.join("input")).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );

    assert!(BuildInputSnapshot::capture(root.path()).is_err());
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    assert_eq!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );

    permissions.make_readable();
    assert!(
        snapshot.audit().is_err(),
        "newly accessible inputs must invalidate the snapshot"
    );
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_discovery_root_remains_required() {
    let root = tempfile::tempdir().unwrap();
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("required-root-alias");
    std::os::unix::fs::symlink(root.path(), &alias).unwrap();
    let _permissions = RestrictedDirectory::new(root.path(), 0);
    assert_enumeration_denied(root.path());
    assert!(BuildInputSnapshot::capture_native_tree(root.path()).is_err());
    assert!(BuildInputSnapshot::capture_native_tree(&alias).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_discovery_audit_rejects_newly_blocked_inputs() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("previously-readable");
    fs::create_dir(&child).unwrap();
    fs::write(child.join("input"), b"measured bytes\n").unwrap();
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    let _permissions = RestrictedDirectory::new(&child, 0);
    assert_enumeration_denied(&child);

    assert!(
        snapshot.audit().is_err(),
        "losing access must invalidate measured content"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_discovery_rejects_execute_only_directory_with_readable_known_input() {
    let root = tempfile::tempdir().unwrap();
    let searchable = root.path().join("searchable");
    fs::create_dir(&searchable).unwrap();
    let known = searchable.join("known-input");
    fs::write(&known, b"must not disappear from the cache identity\n").unwrap();
    let _permissions = RestrictedDirectory::new(&searchable, 0o100);
    assert_enumeration_denied(&searchable);
    assert_eq!(
        fs::read(&known).unwrap(),
        b"must not disappear from the cache identity\n"
    );

    assert!(BuildInputSnapshot::capture_native_tree(root.path()).is_err());
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn native_discovery_audit_rejects_search_access_without_enumeration_access() {
    let root = tempfile::tempdir().unwrap();
    let child = root.path().join("private-inputs");
    fs::create_dir(&child).unwrap();
    let known = child.join("known-input");
    fs::write(&known, b"newly usable input\n").unwrap();
    let _permissions = RestrictedDirectory::new(&child, 0);
    assert_enumeration_denied(&child);
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();

    fs::set_permissions(&child, fs::Permissions::from_mode(0o100)).unwrap();
    assert_enumeration_denied(&child);
    assert_eq!(fs::read(&known).unwrap(), b"newly usable input\n");
    assert!(snapshot.audit().is_err());
    assert!(BuildInputSnapshot::capture_native_tree(root.path()).is_err());
}
