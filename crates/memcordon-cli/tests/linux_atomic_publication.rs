#![cfg(target_os = "linux")]

#[path = "../src/bin/linux_atomic_publication.rs"]
mod publication;

use publication::{Phase, publish, publish_observed};
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::unix::fs::MetadataExt;

const OBSERVATION: &[u8] =
    br#"{"format":"memcordon.installed-native-owner-loss","retirement_observed":true}"#;

#[test]
fn canonical_appearance_contains_only_the_complete_synced_observation() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let path = root.path().join("observation.json");
    let mut seen = Vec::new();
    publish_observed(
        &directory,
        OsStr::new("observation.json"),
        OBSERVATION,
        0o600,
        OBSERVATION.len(),
        |phase| {
            seen.push(phase);
            if phase != Phase::Published {
                assert!(!path.try_exists()?);
                assert_eq!(std::fs::read_dir(root.path())?.count(), 0);
            } else {
                assert_eq!(std::fs::read(&path)?, OBSERVATION);
            }
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(seen, [Phase::Created, Phase::Synced, Phase::Published]);
    let metadata = std::fs::metadata(path).unwrap();
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.mode() & 0o777, 0o600);
}

#[test]
fn collision_preserves_the_original_bytes_and_inode() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    let path = root.path().join("attempt");
    std::fs::write(&path, b"original custody").unwrap();
    let before = std::fs::metadata(&path).unwrap();
    let error = publish(
        &directory,
        OsStr::new("attempt"),
        OBSERVATION,
        0o600,
        OBSERVATION.len(),
    )
    .unwrap_err();
    assert!(!error.committed);
    assert_eq!(error.source.kind(), io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"original custody");
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn interrupted_unpublished_inode_disappears_and_committed_custody_survives_errors() {
    for failure in [Phase::Created, Phase::Synced, Phase::Published] {
        let root = tempfile::tempdir().unwrap();
        let directory = File::open(root.path()).unwrap();
        let error = publish_observed(
            &directory,
            OsStr::new("attempt"),
            OBSERVATION,
            0o600,
            OBSERVATION.len(),
            |phase| {
                if phase == failure {
                    Err(io::Error::other("injected publication checkpoint"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert_eq!(error.committed, failure == Phase::Published);
        if error.committed {
            assert_eq!(
                std::fs::read(root.path().join("attempt")).unwrap(),
                OBSERVATION
            );
        } else {
            assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        }
    }
}

#[test]
fn invalid_names_and_oversized_bytes_never_publish() {
    let root = tempfile::tempdir().unwrap();
    let directory = File::open(root.path()).unwrap();
    for name in [".", "..", "nested/attempt", "/attempt", "nul\0name"] {
        assert!(
            !publish(
                &directory,
                OsStr::new(name),
                OBSERVATION,
                0o600,
                OBSERVATION.len()
            )
            .unwrap_err()
            .committed
        );
    }
    assert!(
        !publish(
            &directory,
            OsStr::new("attempt"),
            OBSERVATION,
            0o600,
            OBSERVATION.len() - 1
        )
        .unwrap_err()
        .committed
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}
