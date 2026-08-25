#![cfg(all(target_os = "linux", feature = "test-support"))]

use memcordon_sealed_agent::package::{
    open_metadata_artifact_for_test, open_readable_artifact_for_test,
    verify_metadata_artifact_for_test, verify_open_artifact_for_test,
    verify_readable_artifact_for_test,
};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::os::unix::net::UnixListener;

fn identity(path: &std::path::Path) -> (u32, u32) {
    let metadata = fs::symlink_metadata(path).unwrap();
    (metadata.uid(), metadata.gid())
}

fn set_mode(path: &std::path::Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn assert_package_rejection(error: &str) {
    assert!(
        error.starts_with("MCSEALED-PACKAGE-VERIFY:"),
        "unexpected verifier error: {error}"
    );
}

#[test]
fn metadata_only_descriptor_accepts_unreadable_regular_inode_and_rejects_unsafe_metadata() {
    let temporary = tempfile::tempdir().unwrap();
    let artifact = temporary.path().join("lease");
    fs::write(&artifact, b"opaque lease state").unwrap();
    set_mode(&artifact, 0o000);
    let (uid, gid) = identity(&artifact);

    if uid != 0 {
        assert!(
            fs::read(&artifact).is_err(),
            "mode-000 fixture unexpectedly remained readable"
        );
    }
    verify_metadata_artifact_for_test(&artifact, uid, gid, 0o000).unwrap();

    for error in [
        verify_metadata_artifact_for_test(&artifact, uid.wrapping_add(1), gid, 0o000).unwrap_err(),
        verify_metadata_artifact_for_test(&artifact, uid, gid.wrapping_add(1), 0o000).unwrap_err(),
        verify_metadata_artifact_for_test(&artifact, uid, gid, 0o600).unwrap_err(),
    ] {
        assert_package_rejection(&error);
    }

    set_mode(&artifact, 0o4600);
    let special_bits = verify_metadata_artifact_for_test(&artifact, uid, gid, 0o600).unwrap_err();
    assert_package_rejection(&special_bits);

    let symlink_path = temporary.path().join("lease-link");
    symlink(&artifact, &symlink_path).unwrap();
    let symlink_error =
        verify_metadata_artifact_for_test(&symlink_path, uid, gid, 0o600).unwrap_err();
    assert_package_rejection(&symlink_error);

    let directory = temporary.path().join("lease-directory");
    fs::create_dir(&directory).unwrap();
    let directory_error =
        verify_metadata_artifact_for_test(&directory, uid, gid, 0o700).unwrap_err();
    assert_package_rejection(&directory_error);

    let socket_path = temporary.path().join("lease-socket");
    let _listener = UnixListener::bind(&socket_path).unwrap();
    let socket_error =
        verify_metadata_artifact_for_test(&socket_path, uid, gid, 0o600).unwrap_err();
    assert_package_rejection(&socket_error);

    let missing = temporary.path().join("missing");
    assert_eq!(
        verify_metadata_artifact_for_test(&missing, uid, gid, 0o600).unwrap_err(),
        "MCSEALED-PACKAGE-VERIFY: installed package is incomplete"
    );
}

#[test]
fn metadata_validation_is_bound_to_the_opened_no_follow_descriptor() {
    let temporary = tempfile::tempdir().unwrap();
    let artifact = temporary.path().join("lease");
    let preserved = temporary.path().join("preserved-lease");
    let replacement = temporary.path().join("replacement");
    fs::write(&artifact, b"stable").unwrap();
    set_mode(&artifact, 0o600);
    let (uid, gid) = identity(&artifact);

    let mut descriptor = open_metadata_artifact_for_test(&artifact).unwrap();
    fs::rename(&artifact, &preserved).unwrap();
    fs::write(&replacement, b"replacement").unwrap();
    symlink(&replacement, &artifact).unwrap();

    verify_open_artifact_for_test(&mut descriptor, &artifact, uid, gid, 0o600, None).unwrap();
    let replaced = verify_metadata_artifact_for_test(&artifact, uid, gid, 0o600).unwrap_err();
    assert_package_rejection(&replaced);
}

#[test]
fn readable_descriptor_keeps_exact_content_checks_on_the_same_inode() {
    let temporary = tempfile::tempdir().unwrap();
    let artifact = temporary.path().join("unit");
    fs::write(&artifact, b"approved").unwrap();
    set_mode(&artifact, 0o600);
    let (uid, gid) = identity(&artifact);

    verify_readable_artifact_for_test(&artifact, uid, gid, 0o600, Some(b"approved")).unwrap();

    fs::write(&artifact, b"approved!").unwrap();
    let appended = verify_readable_artifact_for_test(&artifact, uid, gid, 0o600, Some(b"approved"))
        .unwrap_err();
    assert_package_rejection(&appended);

    fs::write(&artifact, b"original").unwrap();
    let mut descriptor = open_readable_artifact_for_test(&artifact).unwrap();
    let preserved = temporary.path().join("preserved-unit");
    fs::rename(&artifact, &preserved).unwrap();
    fs::write(&artifact, b"substitute").unwrap();
    set_mode(&artifact, 0o600);

    verify_open_artifact_for_test(
        &mut descriptor,
        &artifact,
        uid,
        gid,
        0o600,
        Some(b"original"),
    )
    .unwrap();
    let substituted =
        verify_readable_artifact_for_test(&artifact, uid, gid, 0o600, Some(b"original"))
            .unwrap_err();
    assert_package_rejection(&substituted);

    fs::remove_file(&artifact).unwrap();
    symlink(&preserved, &artifact).unwrap();
    let symlink_error =
        verify_readable_artifact_for_test(&artifact, uid, gid, 0o600, Some(b"original"))
            .unwrap_err();
    assert_package_rejection(&symlink_error);
}
