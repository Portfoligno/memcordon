#![cfg(windows)]
use std::fs;
use std::io::Write;

use memcordon_ci::inventory_progress::InventoryProgress;
use memcordon_ci::inventory_reader::{BUFFER_SIZE, NativeFilePhase, digest_native_file};

#[test]
fn enumerated_stamp_is_not_refreshed_to_hide_a_preopen_change() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input");
    fs::write(&path, b"original").unwrap();
    let expected = fs::symlink_metadata(&path).unwrap();
    let progress = InventoryProgress::new(&path);
    let error = digest_native_file(
        &path,
        &expected,
        &mut vec![0; BUFFER_SIZE],
        &progress,
        |phase| {
            if phase == NativeFilePhase::BeforeOpen {
                fs::write(&path, b"different length")?;
            }
            Ok(())
        },
    )
    .err()
    .expect("changed input must fail");
    assert!(error.to_string().contains("changed before read"));
}

#[test]
fn exact_read_growth_and_truncation_remain_errors() {
    for grow in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"original bytes").unwrap();
        let expected = fs::symlink_metadata(&path).unwrap();
        let progress = InventoryProgress::new(&path);
        let error = digest_native_file(
            &path,
            &expected,
            &mut vec![0; BUFFER_SIZE],
            &progress,
            |phase| {
                if phase == NativeFilePhase::Prechecked {
                    if grow {
                        fs::OpenOptions::new()
                            .append(true)
                            .open(&path)?
                            .write_all(b"growth")?;
                    } else {
                        fs::OpenOptions::new().write(true).open(&path)?.set_len(1)?;
                    }
                }
                Ok(())
            },
        )
        .err()
        .expect("during-read size drift must fail");
        if grow {
            assert!(error.to_string().contains("changed during read"));
        } else {
            assert!(
                error
                    .to_string()
                    .contains("ended before its verified length")
            );
        }
    }
}

#[test]
fn replacing_the_current_path_after_read_is_not_accepted() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input");
    let old = directory.path().join("old-input");
    fs::write(&path, b"original").unwrap();
    let expected = fs::symlink_metadata(&path).unwrap();
    let progress = InventoryProgress::new(&path);
    let error = digest_native_file(
        &path,
        &expected,
        &mut vec![0; BUFFER_SIZE],
        &progress,
        |phase| {
            if phase == NativeFilePhase::BeforeReopen {
                fs::rename(&path, &old)?;
                fs::write(&path, b"replaced with different content")?;
            }
            Ok(())
        },
    )
    .err()
    .expect("path replacement must fail");
    assert!(error.to_string().contains("changed during read"));
}

#[test]
fn cancellation_after_open_never_produces_a_validated_digest() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("empty-input");
    fs::write(&path, b"").unwrap();
    let expected = fs::symlink_metadata(&path).unwrap();
    let progress = InventoryProgress::new(&path);
    let cancellation = progress.cancellation();
    assert!(
        digest_native_file(
            &path,
            &expected,
            &mut vec![0; BUFFER_SIZE],
            &progress,
            |phase| {
                if phase == NativeFilePhase::Prechecked {
                    cancellation.cancel();
                }
                Ok(())
            }
        )
        .is_err()
    );
}

#[test]
fn same_size_persistent_mutation_with_a_changed_stamp_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("input");
    fs::write(&path, b"original").unwrap();
    let expected = fs::symlink_metadata(&path).unwrap();
    let progress = InventoryProgress::new(&path);
    let error = digest_native_file(
        &path,
        &expected,
        &mut vec![0; BUFFER_SIZE],
        &progress,
        |phase| {
            if phase == NativeFilePhase::ReadComplete {
                fs::write(&path, b"modified")?;
                let file = fs::OpenOptions::new().write(true).open(&path)?;
                file.set_times(
                    fs::FileTimes::new().set_modified(std::time::SystemTime::UNIX_EPOCH),
                )?;
            }
            Ok(())
        },
    )
    .err()
    .expect("persistent same-size drift must fail");
    assert!(error.to_string().contains("changed during read"));
}
