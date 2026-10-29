#![cfg(unix)]
use memcordon_ci::readiness_identity::SourceIdentity;
use memcordon_ci::release::linux_lifecycle_diagnostics::{
    HeldCellPublication, publish, register_existing,
};
use memcordon_readiness_verifier::ProductKey;

fn identity() -> SourceIdentity {
    SourceIdentity {
        run_id: "original-run".into(),
        source_commit: "1".repeat(40),
        source_tree_sha256: "2".repeat(64),
        version: "0.5.6".into(),
    }
}
fn cell() -> ProductKey {
    ProductKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: "candidate-native".into(),
    }
}
fn original() -> (tempfile::TempDir, HeldCellPublication) {
    let root = tempfile::tempdir().unwrap();
    let held = HeldCellPublication::create(root.path(), &identity(), &cell()).unwrap();
    (root, held)
}

#[test]
fn later_normalization_error_does_not_erase_published_failure_evidence() {
    use memcordon_ci::{CiError, release::linux_lifecycle_diagnostics::capture_before_normalize};
    let (_root, anchor) = original();
    let path = anchor.prefix().join("phase-journal.bin");
    let mut artifacts = Vec::new();
    let (capture, normalized) = capture_before_normalize(
        &mut artifacts,
        |retained| {
            let _held = publish(&anchor, &path, b"actual retained journal", retained)?;
            Ok(())
        },
        || {
            Err::<(), _>(CiError::Message(
                "later independent normalizer failed".into(),
            ))
        },
    );
    capture.unwrap();
    assert!(
        normalized
            .unwrap_err()
            .to_string()
            .contains("later independent normalizer failed")
    );
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        artifacts[0].path,
        "x86_64-unknown-linux-gnu/candidate-native/phase-journal.bin"
    );
    assert_eq!(std::fs::read(path).unwrap(), b"actual retained journal");
}

#[test]
fn original_journal_survives_later_failure_and_is_exportable() {
    let (_root, anchor) = original();
    let path = anchor.prefix().join("phase-journal.bin");
    let journal = b"authenticated original journal\0actual obsolete checkpoint state";
    let mut artifacts = Vec::new();
    let held = publish(&anchor, &path, journal, &mut artifacts).unwrap();
    // A later diagnostic publication fails without replacing the original
    // registered bytes or requiring successful case normalization.
    assert!(publish(&anchor, &path, b"replacement", &mut artifacts).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), journal);
    assert_eq!(held.metadata().unwrap().len(), journal.len() as u64);
    assert_eq!(artifacts.len(), 1);
    assert_eq!(
        artifacts[0].path,
        "x86_64-unknown-linux-gnu/candidate-native/phase-journal.bin"
    );
    assert_eq!(artifacts[0].length, journal.len() as u64);
    assert_eq!(
        artifacts[0].sha256,
        memcordon_ci::release::artifacts::checksum(journal)
    );
}

#[test]
fn publication_rejects_escape_alias_and_writable_parent() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let (_root, anchor) = original();
    let other = tempfile::tempdir().unwrap();
    let mut artifacts = Vec::new();
    assert!(publish(&anchor, &other.path().join("outside"), b"x", &mut artifacts).is_err());
    let path = anchor.prefix().join("phase-journal.bin");
    symlink(other.path().join("target"), &path).unwrap();
    assert!(publish(&anchor, &path, b"x", &mut artifacts).is_err());
    assert!(!other.path().join("target").exists());
    symlink(other.path(), anchor.prefix().join("alias")).unwrap();
    assert!(
        publish(
            &anchor,
            &anchor.prefix().join("alias/escaped"),
            b"x",
            &mut artifacts
        )
        .is_err()
    );
    assert!(!other.path().join("escaped").exists());
    let writable = anchor.prefix().join("writable");
    std::fs::create_dir(&writable).unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o777)).unwrap();
    let error = publish(&anchor, &writable.join("journal"), b"x", &mut artifacts)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("controller descendant")
            && error.contains("observed_uid=")
            && error.contains("mode=")
    );
    assert!(artifacts.is_empty());
}

#[test]
fn namespace_mapping_selection_and_shared_target_are_pinned() {
    let (root, anchor) = original();
    let mut artifacts = Vec::new();
    let mut changed = identity();
    changed.run_id = "unrelated".into();
    assert!(
        anchor
            .verify_selection(
                &changed,
                &cell(),
                "original-run-x86_64-unknown-linux-gnu-candidate-native"
            )
            .is_err()
    );
    assert!(
        anchor
            .verify_selection(&identity(), &cell(), "unrelated-lease")
            .is_err()
    );
    let mut second = cell();
    second.channel = "candidate-cargo".into();
    let other = HeldCellPublication::create(root.path(), &identity(), &second).unwrap();
    assert!(
        publish(
            &anchor,
            &other.prefix().join("wrong-prefix"),
            b"x",
            &mut artifacts
        )
        .is_err()
    );
    assert!(HeldCellPublication::create(root.path(), &identity(), &cell()).is_err());
    let renamed = anchor.prefix().with_extension("original");
    std::fs::rename(anchor.prefix(), &renamed).unwrap();
    std::fs::create_dir(anchor.prefix()).unwrap();
    assert!(
        publish(
            &anchor,
            &anchor.prefix().join("substitution"),
            b"x",
            &mut artifacts
        )
        .is_err()
    );
    assert!(!anchor.prefix().join("substitution").exists());
    assert!(artifacts.is_empty());
    std::fs::remove_dir(anchor.prefix()).unwrap();
    std::fs::rename(renamed, anchor.prefix()).unwrap();
}

#[test]
fn existing_context_is_independent_of_new_witness_failure() {
    use std::os::unix::fs::symlink;
    let (_root, anchor) = original();
    let existing = anchor.prefix().join("frontend-preinput.json");
    std::fs::write(&existing, b"original context").unwrap();
    let mut artifacts = Vec::new();
    let _held = register_existing(&anchor, &existing, &mut artifacts).unwrap();
    let forbidden = anchor.prefix().join("barrier-observation.json");
    symlink("frontend-preinput.json", &forbidden).unwrap();
    assert!(publish(&anchor, &forbidden, b"new witness", &mut artifacts).is_err());
    assert_eq!(artifacts.len(), 1);
    assert_eq!(std::fs::read(existing).unwrap(), b"original context");
}
