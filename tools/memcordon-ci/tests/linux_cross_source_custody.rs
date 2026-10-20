#![cfg(unix)]

#[path = "../src/release/linux_cross_source_custody.rs"]
mod custody;

use std::fs::{File, Metadata, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

fn stamp(metadata: &Metadata) -> (u64, u64, u32, u32, u32) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
    )
}

#[test]
fn actual_held_directory_requires_original_identity_and_selected_caller() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frontend");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    let held = File::open(&path).unwrap();
    let original = held.metadata().unwrap();
    let named = std::fs::symlink_metadata(&path).unwrap();
    let expected = stamp(&original);
    custody::require_caller_boundary(&named, &original, expected, original.uid(), original.gid())
        .unwrap();
    assert!(
        custody::require_caller_boundary(
            &named,
            &original,
            expected,
            original.uid() ^ 1,
            original.gid()
        )
        .is_err()
    );
    assert!(
        custody::require_caller_boundary(
            &named,
            &original,
            expected,
            original.uid(),
            original.gid() ^ 1
        )
        .is_err()
    );
    for foreign in [
        (
            expected.0 ^ 1,
            expected.1,
            expected.2,
            expected.3,
            expected.4,
        ),
        (
            expected.0,
            expected.1 ^ 1,
            expected.2,
            expected.3,
            expected.4,
        ),
        (
            expected.0,
            expected.1,
            expected.2 ^ 1,
            expected.3,
            expected.4,
        ),
        (
            expected.0,
            expected.1,
            expected.2,
            expected.3 ^ 1,
            expected.4,
        ),
        (
            expected.0,
            expected.1,
            expected.2,
            expected.3,
            expected.4 ^ 1,
        ),
    ] {
        assert!(
            custody::require_caller_boundary(
                &named,
                &original,
                foreign,
                original.uid(),
                original.gid()
            )
            .is_err()
        );
    }
}

#[test]
fn actual_sibling_replacement_and_symlink_cannot_substitute_for_held_directory() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frontend");
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    let held = File::open(&path).unwrap();
    let original = held.metadata().unwrap();
    let expected = stamp(&original);
    let old = root.path().join("retained-original");
    std::fs::rename(&path, &old).unwrap();
    std::fs::create_dir(&path).unwrap();
    std::fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    let replacement = std::fs::symlink_metadata(&path).unwrap();
    assert!(
        custody::require_caller_boundary(
            &replacement,
            &held.metadata().unwrap(),
            expected,
            original.uid(),
            original.gid()
        )
        .is_err()
    );
    let alias = root.path().join("alias");
    symlink(&old, &alias).unwrap();
    assert!(
        custody::require_caller_boundary(
            &std::fs::symlink_metadata(&alias).unwrap(),
            &original,
            expected,
            original.uid(),
            original.gid()
        )
        .is_err()
    );
    let file = root.path().join("regular-file");
    std::fs::write(&file, b"not a directory").unwrap();
    let regular = File::open(&file).unwrap().metadata().unwrap();
    assert!(
        custody::require_caller_boundary(
            &regular,
            &regular,
            stamp(&regular),
            regular.uid(),
            regular.gid()
        )
        .is_err()
    );
    custody::require_caller_boundary(
        &std::fs::symlink_metadata(&old).unwrap(),
        &held.metadata().unwrap(),
        expected,
        original.uid(),
        original.gid(),
    )
    .unwrap();
}

#[test]
fn actual_directory_permissions_remain_exact_even_with_matching_current_stamp() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("frontend");
    std::fs::create_dir(&path).unwrap();
    let held = File::open(&path).unwrap();
    for mode in [0o755, 0o770, 0o1700] {
        std::fs::set_permissions(&path, Permissions::from_mode(mode)).unwrap();
        let current = held.metadata().unwrap();
        assert!(
            custody::require_caller_boundary(
                &std::fs::symlink_metadata(&path).unwrap(),
                &current,
                stamp(&current),
                current.uid(),
                current.gid()
            )
            .is_err()
        );
    }
    std::fs::set_permissions(&path, Permissions::from_mode(0o700)).unwrap();
    let current = held.metadata().unwrap();
    custody::require_caller_boundary(
        &std::fs::symlink_metadata(&path).unwrap(),
        &current,
        stamp(&current),
        current.uid(),
        current.gid(),
    )
    .unwrap();
}
