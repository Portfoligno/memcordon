//! Direct tests of native inspection observations; inventory admission remains in CI.

#[test]
fn malformed_native_reply_count_cannot_expose_uninitialized_or_excess_bytes() {
    let buffer = [1, 2, 3, 4];
    for initialized in 0..=buffer.len() {
        assert_eq!(
            memcordon_native_inspect::initialized_reparse_bytes(&buffer, initialized).unwrap(),
            &buffer[..initialized]
        );
    }
    for malformed in [buffer.len() + 1, usize::MAX] {
        assert_eq!(
            memcordon_native_inspect::initialized_reparse_bytes(&buffer, malformed)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn searchable_directory_is_not_absence_evidence() {
    let root = tempfile::tempdir().unwrap();
    assert!(
        memcordon_native_inspect::unsearchable_directory(
            root.path(),
            &root.path().metadata().unwrap()
        )
        .unwrap()
        .is_none()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn missing_path_is_an_error_not_denied_search_evidence() {
    let root = tempfile::tempdir().unwrap();
    let metadata = root.path().metadata().unwrap();
    assert!(
        memcordon_native_inspect::unsearchable_directory(&root.path().join("missing"), &metadata)
            .is_err()
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn effective_search_permission_transition_is_observed() {
    use std::fs::{self, Permissions};
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("directory");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o0)).unwrap();
    let denied = memcordon_native_inspect::unsearchable_directory(&path, &path.metadata().unwrap());
    // Restore first, including on assertion failure, so cleanup retains access.
    fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    let denied = denied
        .unwrap()
        .expect("native permission test requires an unprivileged runner");
    assert_ne!(denied.effective_uid, 0);
    assert!(
        memcordon_native_inspect::unsearchable_directory(&path, &path.metadata().unwrap())
            .unwrap()
            .is_none()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn writable_mount_descriptor_is_rejected_after_path_replacement() {
    use std::fs::{self, File};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("input");
    fs::write(&path, b"original\n").unwrap();
    let descriptor = File::open(&path).unwrap();
    fs::rename(&path, root.path().join("retained")).unwrap();
    fs::write(&path, b"replacement\n").unwrap();
    assert!(memcordon_native_inspect::macos_read_only_descriptor_path(&descriptor).is_err());
    assert!(
        memcordon_native_inspect::macos_read_only_descriptor_path(&File::open(path).unwrap())
            .is_err()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn read_only_system_descriptor_resolves_its_actual_path() {
    let path = std::path::Path::new("/usr/bin/true");
    let descriptor = std::fs::File::open(path).unwrap();
    assert_eq!(
        memcordon_native_inspect::macos_read_only_descriptor_path(&descriptor).unwrap(),
        path.canonicalize().unwrap()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn socket_descriptor_cannot_be_system_file_evidence() {
    use std::os::fd::OwnedFd;
    let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    let descriptor = std::fs::File::from(OwnedFd::from(socket));
    assert!(memcordon_native_inspect::macos_read_only_descriptor_path(&descriptor).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn effective_search_honors_native_acl_even_with_search_mode_bits() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("acl-directory");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let installed = Command::new("/bin/chmod")
        .args(["+a", "everyone deny search"])
        .arg(&path)
        .status()
        .unwrap();
    assert!(installed.success(), "could not install native ACL fixture");
    let observed =
        memcordon_native_inspect::unsearchable_directory(&path, &path.metadata().unwrap());
    let removed = Command::new("/bin/chmod")
        .arg("-N")
        .arg(&path)
        .status()
        .unwrap();
    assert!(removed.success(), "could not remove native ACL fixture");
    assert!(
        observed.unwrap().is_some(),
        "ACL denial must not become searchable evidence"
    );
    assert!(
        memcordon_native_inspect::unsearchable_directory(&path, &path.metadata().unwrap())
            .unwrap()
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn hard_links_share_descriptor_identity_and_replacements_do_not() {
    use memcordon_native_inspect::windows_file_identity;
    use std::fs::{self, File};
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("input");
    let alias = root.path().join("alias");
    fs::write(&path, b"original\n").unwrap();
    fs::hard_link(&path, &alias).unwrap();
    let descriptor = File::open(&path).unwrap();
    let original = windows_file_identity(&descriptor).unwrap();
    assert_eq!(
        original,
        windows_file_identity(&File::open(&alias).unwrap()).unwrap()
    );
    fs::rename(&path, root.path().join("retained")).unwrap();
    fs::write(&path, b"replacement\n").unwrap();
    assert_eq!(original, windows_file_identity(&descriptor).unwrap());
    assert_ne!(
        original,
        windows_file_identity(&File::open(&path).unwrap()).unwrap()
    );
}

#[cfg(windows)]
#[test]
fn ordinary_file_is_not_reparse_evidence() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("ordinary");
    std::fs::write(&path, b"not a reparse point\n").unwrap();
    assert_eq!(
        memcordon_native_inspect::windows_reparse_data(&path)
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[cfg(windows)]
#[test]
fn missing_reparse_target_is_an_error() {
    let root = tempfile::tempdir().unwrap();
    assert!(memcordon_native_inspect::windows_reparse_data(&root.path().join("missing")).is_err());
}
