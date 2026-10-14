#![cfg(target_os = "linux")]

#[path = "../src/caller_observation.rs"]
mod publisher;

use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[test]
fn caller_observation_final_is_absent_until_complete_publication() {
    let directory = tempfile::tempdir().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let final_path = directory.path().join("attempt.observer-ack.json");
    let bytes = b"complete caller acknowledgment\n";
    let staged = publisher::StagedCallerObservation::stage(&final_path, bytes, uid).unwrap();
    assert!(!final_path.exists());
    let pending = directory.path().join("attempt.observer-ack.json.pending");
    let metadata = std::fs::symlink_metadata(&pending).unwrap();
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.mode() & 0o7777, 0o600);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(std::fs::read(&pending).unwrap(), bytes);
    staged.publish().unwrap();
    assert!(!pending.exists());
    assert_eq!(std::fs::read(&final_path).unwrap(), bytes);
    let final_metadata = std::fs::symlink_metadata(&final_path).unwrap();
    assert_eq!(
        (metadata.dev(), metadata.ino()),
        (final_metadata.dev(), final_metadata.ino())
    );
    assert_eq!(final_metadata.mode() & 0o7777, 0o600);
}

#[test]
fn caller_observation_refuses_collisions_and_unprotected_parent_without_removal() {
    let directory = tempfile::tempdir().unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let final_path = directory.path().join("ack.json");
    std::fs::write(&final_path, b"original").unwrap();
    assert!(publisher::publish(&final_path, b"replacement", uid).is_err());
    assert_eq!(std::fs::read(&final_path).unwrap(), b"original");
    assert_eq!(
        std::fs::read(directory.path().join("ack.json.pending")).unwrap(),
        b"replacement"
    );
    assert!(publisher::publish(&final_path, b"another", uid).is_err());
    let linked = directory.path().join("symlink.json");
    std::os::unix::fs::symlink(&final_path, &linked).unwrap();
    assert!(publisher::publish(&linked, b"replacement", uid).is_err());
    assert!(std::fs::symlink_metadata(&linked).unwrap().is_symlink());
    assert_eq!(std::fs::read(&final_path).unwrap(), b"original");
    let bad_owner = directory.path().join("wrong-owner.json");
    assert!(publisher::publish(&bad_owner, b"no", uid.checked_add(1).unwrap()).is_err());
    assert!(
        !bad_owner
            .with_file_name("wrong-owner.json.pending")
            .exists()
    );
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o722)).unwrap();
    let unprotected = directory.path().join("unprotected.json");
    assert!(publisher::publish(&unprotected, b"no", uid).is_err());
    assert!(!unprotected.exists());
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn caller_observation_rejects_named_parent_substitution_before_publish() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("caller");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let staged = publisher::StagedCallerObservation::stage(
        &parent.join("ack.json"),
        b"complete",
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    let retained = directory.path().join("retained");
    std::fs::rename(&parent, &retained).unwrap();
    std::fs::create_dir(&parent).unwrap();
    assert!(staged.publish().is_err());
    assert!(!parent.join("ack.json").exists());
    assert_eq!(
        std::fs::read(retained.join("ack.json.pending")).unwrap(),
        b"complete"
    );
}

#[test]
fn caller_observation_refuses_fifo_substitution_without_waiting_for_a_writer() {
    let directory = tempfile::tempdir().unwrap();
    let final_path = directory.path().join("ack.json");
    let pending = directory.path().join("ack.json.pending");
    let staged = publisher::StagedCallerObservation::stage(
        &final_path,
        b"complete",
        rustix::process::geteuid().as_raw(),
    )
    .unwrap();
    let retained = directory.path().join("held-original");
    std::fs::rename(&pending, &retained).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &pending,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    let before = std::time::Instant::now();
    assert!(
        staged
            .publish()
            .unwrap_err()
            .contains("file custody differs")
    );
    assert!(before.elapsed() < std::time::Duration::from_secs(1));
    assert!(!final_path.exists());
    assert_eq!(std::fs::read(&retained).unwrap(), b"complete");
    use std::os::unix::fs::FileTypeExt;
    assert!(
        std::fs::symlink_metadata(&pending)
            .unwrap()
            .file_type()
            .is_fifo()
    );
}

#[test]
fn caller_observation_refuses_symlink_ancestors_and_parent_traversal() {
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let parent = real.join("caller");
    std::fs::create_dir(&parent).unwrap();
    std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    assert!(publisher::publish(&alias.join("caller").join("ack.json"), b"no", uid).is_err());
    assert!(
        publisher::publish(
            &parent.join("..").join("caller").join("ack.json"),
            b"no",
            uid
        )
        .is_err()
    );
    assert!(!parent.join("ack.json.pending").exists());
    assert!(!parent.join("ack.json").exists());
}
