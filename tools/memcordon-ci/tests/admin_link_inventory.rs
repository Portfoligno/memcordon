#![cfg(unix)]
#[path = "../src/release/admin_link_inventory.rs"]
mod admin_link_inventory;

use admin_link_inventory::Inventory;
use std::{fs, os::unix::fs::MetadataExt};

#[test]
fn accounts_actual_owned_hardlinks_through_last_unlink() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("metadata.rmeta");
    let second = root.path().join("retained.rmeta");
    fs::write(&first, b"actual compiler metadata").unwrap();
    fs::hard_link(&first, &second).unwrap();
    let held = fs::File::open(&first).unwrap();
    let mut inventory = Inventory::default();
    inventory
        .directory(root.path(), &fs::metadata(root.path()).unwrap(), true)
        .unwrap();
    for path in [&first, &second] {
        let metadata = fs::symlink_metadata(path).unwrap();
        inventory.observe(path, &metadata).unwrap();
    }
    inventory.verify_complete().unwrap();
    inventory
        .directory(root.path(), &fs::metadata(root.path()).unwrap(), false)
        .unwrap();
    for path in [&first, &second] {
        let before = held.metadata().unwrap();
        inventory.before_unlink(path, &before).unwrap();
        fs::remove_file(path).unwrap();
        let after = held.metadata().unwrap();
        inventory.after_unlink(path, &after).unwrap();
    }
    inventory.verify_retired().unwrap();
    assert_eq!(held.metadata().unwrap().nlink(), 0);
}

#[test]
fn refuses_outside_alias_and_alias_added_after_census() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let first = root.path().join("metadata.rmeta");
    let alias = outside.path().join("outside.rmeta");
    fs::write(&first, b"retained original").unwrap();
    fs::hard_link(&first, &alias).unwrap();
    let mut inventory = Inventory::default();
    let metadata = fs::metadata(&first).unwrap();
    inventory.observe(&first, &metadata).unwrap();
    assert!(inventory.verify_complete().is_err());
    assert_eq!(fs::read(&alias).unwrap(), b"retained original");
    fs::remove_file(&alias).unwrap();
    let mut inventory = Inventory::default();
    let metadata = fs::metadata(&first).unwrap();
    inventory.observe(&first, &metadata).unwrap();
    inventory.verify_complete().unwrap();
    fs::hard_link(&first, &alias).unwrap();
    let changed = fs::metadata(&first).unwrap();
    assert!(inventory.before_unlink(&first, &changed).is_err());
    assert!(first.exists());
    assert!(alias.exists());
    assert!(inventory.verify_retired().is_err());
}

#[test]
fn refuses_original_name_or_directory_substitution_with_unchanged_link_count() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("metadata.rmeta");
    let renamed = root.path().join("renamed.rmeta");
    fs::write(&original, b"original").unwrap();
    let metadata = fs::metadata(&original).unwrap();
    let mut inventory = Inventory::default();
    inventory.observe(&original, &metadata).unwrap();
    inventory.verify_complete().unwrap();
    fs::rename(&original, &renamed).unwrap();
    assert!(
        inventory
            .before_unlink(&renamed, &fs::metadata(&renamed).unwrap())
            .is_err()
    );
    fs::write(&original, b"different").unwrap();
    assert!(
        inventory
            .before_unlink(&original, &fs::metadata(&original).unwrap())
            .is_err()
    );
    let directory = root.path().join("directory");
    fs::create_dir(&directory).unwrap();
    inventory
        .directory(&directory, &fs::metadata(&directory).unwrap(), true)
        .unwrap();
    fs::rename(&directory, root.path().join("old-directory")).unwrap();
    fs::create_dir(&directory).unwrap();
    assert!(
        inventory
            .directory(&directory, &fs::metadata(&directory).unwrap(), false)
            .is_err()
    );
}
