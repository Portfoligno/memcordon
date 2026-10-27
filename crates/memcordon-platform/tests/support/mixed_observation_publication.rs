//! Deterministic publication boundaries using actual held native files.
use super::*;
use std::os::unix::fs::PermissionsExt;

fn observer_directory() -> (tempfile::TempDir, File) {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let held = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(root.path())
        .unwrap();
    (root, held)
}

#[test]
fn final_name_means_complete_single_link_immutable_observation() {
    let (root, held) = observer_directory();
    let bytes = b"complete original retirement observation";
    let pending = PendingObservation::prepare(&held, "retirement-prepared.json", bytes).unwrap();
    assert!(
        !root
            .path()
            .join("retirement-prepared.json")
            .try_exists()
            .unwrap()
    );
    assert!(root.path().join(&pending.staging).try_exists().unwrap());
    let before = pending.file.metadata().unwrap();
    assert_eq!(before.nlink(), 1);
    pending.publish(&held, bytes).unwrap();
    let complete = member(&held, "retirement-prepared.json", false).unwrap();
    let published = complete.metadata().unwrap();
    assert_eq!(
        (before.dev(), before.ino()),
        (published.dev(), published.ino())
    );
    assert_eq!(published.nlink(), 1);
    assert_eq!(
        read_retirement_member(&held, "retirement-prepared.json").unwrap(),
        bytes
    );
    verify_observation(
        &held,
        "retirement-prepared.json",
        &complete,
        &published,
        bytes,
    )
    .unwrap();
    assert_eq!(
        observation_stamp(&published),
        observation_stamp(&complete.metadata().unwrap())
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 1);
}

#[test]
fn final_collision_never_overwrites_and_preserves_exact_private_evidence() {
    let (root, held) = observer_directory();
    publish_observation(&held, "prepared.json", b"original final evidence").unwrap();
    let first = std::fs::metadata(root.path().join("prepared.json")).unwrap();
    let pending =
        PendingObservation::prepare(&held, "prepared.json", b"competing observation").unwrap();
    let staging = pending.staging.clone();
    assert_eq!(
        pending
            .publish(&held, b"competing observation")
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(
        std::fs::read(root.path().join("prepared.json")).unwrap(),
        b"original final evidence"
    );
    let retained = std::fs::metadata(root.path().join("prepared.json")).unwrap();
    assert_eq!(observation_stamp(&first), observation_stamp(&retained));
    assert_eq!(
        std::fs::read(root.path().join(staging)).unwrap(),
        b"competing observation"
    );
    assert_eq!(retained.nlink(), 1);
}

#[test]
fn staging_custody_or_content_changes_cannot_publish_a_ready_name() {
    for mutation in ["bytes", "mode", "hardlink", "replacement"] {
        let (root, held) = observer_directory();
        let bytes = b"original complete observation";
        let pending =
            PendingObservation::prepare(&held, "retirement-enrolled.json", bytes).unwrap();
        let staging = root.path().join(&pending.staging);
        match mutation {
            "bytes" => std::fs::write(&staging, b"changed").unwrap(),
            "mode" => {
                std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o644)).unwrap()
            }
            "hardlink" => std::fs::hard_link(&staging, root.path().join("extra-link")).unwrap(),
            "replacement" => {
                let foreign = root.path().join("foreign");
                std::fs::write(&foreign, bytes).unwrap();
                std::fs::set_permissions(&foreign, std::fs::Permissions::from_mode(0o600)).unwrap();
                std::fs::rename(foreign, &staging).unwrap();
            }
            _ => unreachable!(),
        }
        assert!(
            pending.publish(&held, bytes).is_err(),
            "published changed {mutation}"
        );
        assert!(
            !root
                .path()
                .join("retirement-enrolled.json")
                .try_exists()
                .unwrap()
        );
        assert!(staging.try_exists().unwrap());
    }
}
