#![cfg(any(target_os = "linux", target_os = "macos"))]

use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

struct Blocked(PathBuf);

impl Blocked {
    fn new(path: &Path) -> Self {
        fs::set_permissions(path, fs::Permissions::from_mode(0o0)).unwrap();
        assert_eq!(
            fs::read_dir(path).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        Self(path.to_owned())
    }

    fn open(&self) {
        fs::set_permissions(&self.0, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

impl Drop for Blocked {
    fn drop(&mut self) {
        self.open();
    }
}

#[test]
fn inaccessible_link_target_is_auditable_and_access_transitions_invalidate_it() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let private = external.path().join("private");
    fs::create_dir(&private).unwrap();
    let target = private.join("input");
    fs::write(&target, b"native input\n").unwrap();
    let link = root.path().join("tool-alias");
    symlink(&target, &link).unwrap();
    let blocked = Blocked::new(&private);
    assert_eq!(
        link.canonicalize().unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );

    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    assert!(BuildInputSnapshot::capture(root.path()).is_err());
    assert!(BuildInputSnapshot::capture_native_tree(&link).is_err());

    blocked.open();
    assert!(snapshot.audit().is_err());
    let accessible = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    assert_ne!(snapshot.digest().unwrap(), accessible.digest().unwrap());
    let _blocked_again = Blocked::new(&private);
    assert!(accessible.audit().is_err());
}

#[test]
fn retargeting_within_the_same_blocked_ancestor_changes_identity() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let private = external.path().join("private");
    fs::create_dir(&private).unwrap();
    let link = root.path().join("tool-alias");
    symlink(private.join("first"), &link).unwrap();
    let _blocked = Blocked::new(&private);
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    fs::remove_file(&link).unwrap();
    symlink(private.join("second"), &link).unwrap();
    assert!(snapshot.audit().is_err());
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[test]
fn relative_link_through_an_intermediate_alias_preserves_route_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("discovery");
    let external = temporary.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&external).unwrap();
    let private = external.join("private");
    fs::create_dir(&private).unwrap();
    let route = external.join("route");
    symlink(&private, &route).unwrap();
    symlink(
        Path::new("..").join("outside").join("route").join("input"),
        root.join("tool-alias"),
    )
    .unwrap();
    let _blocked = Blocked::new(&private);
    let snapshot = BuildInputSnapshot::capture_native_tree(&root).unwrap();
    snapshot.audit().unwrap();
    fs::remove_file(&route).unwrap();
    symlink(Path::new(".").join("private"), &route).unwrap();
    assert!(snapshot.audit().is_err());
    assert_ne!(
        snapshot.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(&root)
            .unwrap()
            .digest()
            .unwrap()
    );
}

#[test]
fn searchable_parent_keeps_known_file_content_measured() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let private = external.path().join("private");
    fs::create_dir(&private).unwrap();
    let target = private.join("input");
    fs::write(&target, b"known accessible bytes\n").unwrap();
    symlink(&target, root.path().join("tool-alias")).unwrap();
    let blocked = Blocked::new(&private);
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o100)).unwrap();
    assert_eq!(
        fs::read_dir(&private).unwrap_err().kind(),
        io::ErrorKind::PermissionDenied
    );
    assert_eq!(fs::read(&target).unwrap(), b"known accessible bytes\n");
    assert!(snapshot.audit().is_err());
    let measured = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    blocked.open();
    fs::write(&target, b"changed bytes\n").unwrap();
    assert!(measured.audit().is_err());
}

#[test]
#[cfg(target_os = "linux")]
fn parent_components_follow_actual_resolution_and_audit_changes() {
    assert_parent_component_resolution_is_audited();
}

#[test]
#[cfg(target_os = "macos")]
fn successfully_resolved_parent_components_keep_target_bytes_measured() {
    assert_parent_component_resolution_is_audited();
}

fn assert_parent_component_resolution_is_audited() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let private = external.path().join("private");
    fs::create_dir(&private).unwrap();
    let visible = external.path().join("visible");
    fs::write(&visible, b"visible bytes\n").unwrap();
    let link = root.path().join("tool-alias");
    symlink(private.join("..").join("visible"), &link).unwrap();
    let blocked = Blocked::new(&private);
    let resolution = link.canonicalize();
    let snapshot = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    snapshot.audit().unwrap();
    match resolution {
        Ok(resolved) => {
            assert_eq!(resolved, visible.canonicalize().unwrap());
        }
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            assert!(BuildInputSnapshot::capture(root.path()).is_err());
            assert!(BuildInputSnapshot::capture_native_tree(&link).is_err());
            blocked.open();
            assert!(snapshot.audit().is_err());
            assert_ne!(
                snapshot.digest().unwrap(),
                BuildInputSnapshot::capture_native_tree(root.path())
                    .unwrap()
                    .digest()
                    .unwrap()
            );
        }
        Err(error) => panic!("unexpected parent-component canonicalization error: {error}"),
    }
    // In either case, once resolution succeeds the target is a content input.
    let measured = BuildInputSnapshot::capture_native_tree(root.path()).unwrap();
    measured.audit().unwrap();
    fs::write(&visible, b"changed visible bytes\n").unwrap();
    assert!(measured.audit().is_err());
    assert_ne!(
        measured.digest().unwrap(),
        BuildInputSnapshot::capture_native_tree(root.path())
            .unwrap()
            .digest()
            .unwrap()
    );
}
