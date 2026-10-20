#![cfg(unix)]

#[path = "../src/release/linux_cleanup_publication.rs"]
mod publication;

use std::fs::{File, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn fixture() -> (tempfile::TempDir, File, u32) {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), Permissions::from_mode(0o700)).unwrap();
    let path = parent.path().join("lease-owner.json");
    std::fs::write(&path, b"original lease owner").unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o600)).unwrap();
    let owner = File::open(path).unwrap();
    let uid = owner.metadata().unwrap().uid();
    (parent, owner, uid)
}

#[test]
fn publication_is_held_retryable_and_separate_from_original_acquisition() {
    let (parent, owner, uid) = fixture();
    let first = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    first.verify().unwrap();
    let original = std::fs::metadata(first.path()).unwrap();
    std::fs::write(first.path().join("receipt.json"), b"retained receipt").unwrap();
    let retry = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    let retried = std::fs::metadata(retry.path()).unwrap();
    assert_eq!(
        (original.dev(), original.ino()),
        (retried.dev(), retried.ino())
    );
    assert_eq!(retried.mode() & 0o7777, 0o700);
    assert_eq!(
        std::fs::read(retry.path().join("receipt.json")).unwrap(),
        b"retained receipt"
    );
    assert!(!parent.path().join("mixed-cases").exists());
    first.verify().unwrap();
    retry.verify().unwrap();
}

#[test]
fn publication_rejects_foreign_owner_uid_and_unsafe_directory_modes() {
    let (parent, owner, uid) = fixture();
    assert!(publication::HeldPublication::open(parent.path(), &owner, uid ^ 1).is_err());
    let foreign = tempfile::tempfile().unwrap();
    assert!(publication::HeldPublication::open(parent.path(), &foreign, uid).is_err());
    std::fs::set_permissions(parent.path(), Permissions::from_mode(0o777)).unwrap();
    assert!(publication::HeldPublication::open(parent.path(), &owner, uid).is_err());
    std::fs::set_permissions(parent.path(), Permissions::from_mode(0o700)).unwrap();
    let held = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    std::fs::set_permissions(held.path(), Permissions::from_mode(0o755)).unwrap();
    assert!(held.verify().is_err());
    assert!(publication::HeldPublication::open(parent.path(), &owner, uid).is_err());
}

#[test]
fn publication_rejects_symlink_replacement_and_changed_original_owner() {
    let (parent, owner, uid) = fixture();
    let other = tempfile::tempdir().unwrap();
    let leaf = parent.path().join("interrupted-resource-retirement");
    symlink(other.path(), &leaf).unwrap();
    assert!(publication::HeldPublication::open(parent.path(), &owner, uid).is_err());
    std::fs::remove_file(&leaf).unwrap();
    let held = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    std::fs::rename(held.path(), parent.path().join("original-publication")).unwrap();
    std::fs::create_dir(&leaf).unwrap();
    std::fs::set_permissions(&leaf, Permissions::from_mode(0o700)).unwrap();
    assert!(held.verify().is_err());

    let (parent, owner, uid) = fixture();
    let held = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    std::fs::write(
        parent.path().join("lease-owner.json"),
        b"changed original owner bytes",
    )
    .unwrap();
    assert!(held.verify().is_err());

    let (parent, owner, uid) = fixture();
    let held = publication::HeldPublication::open(parent.path(), &owner, uid).unwrap();
    let owner_path = parent.path().join("lease-owner.json");
    std::fs::rename(&owner_path, parent.path().join("original-owner.json")).unwrap();
    symlink(parent.path().join("original-owner.json"), &owner_path).unwrap();
    assert!(held.verify().is_err());
}
