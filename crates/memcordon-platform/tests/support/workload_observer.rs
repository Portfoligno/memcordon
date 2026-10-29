use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

fn directory() -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    temporary
}

#[test]
fn prepared_publication_stays_beneath_held_directory_after_path_replacement() {
    let temporary = directory();
    let path = temporary.path().join("observer");
    std::fs::create_dir(&path).unwrap();
    let held = open(&path).unwrap();
    let moved = temporary.path().join("original");
    std::fs::rename(&path, &moved).unwrap();
    std::fs::create_dir(&path).unwrap();
    let payload = br#"{"native":"actual held prepared bytes"}"#;
    publish_observation(&held, "attempt.prepared.json", payload).unwrap();
    assert_eq!(
        std::fs::read(moved.join("attempt.prepared.json")).unwrap(),
        payload
    );
    assert!(!path.join("attempt.prepared.json").exists());
    assert!(publish_observation(&held, "attempt.prepared.json", b"replacement").is_err());
    assert_eq!(
        std::fs::read(moved.join("attempt.prepared.json")).unwrap(),
        payload
    );
}

#[test]
fn acknowledgement_requires_exact_json_binding_and_private_named_inode() {
    let temporary = directory();
    let held = open(temporary.path()).unwrap();
    let path = temporary.path().join("attempt.prepared-ack.json");
    let expected = br#"{"association":{"attempt":"original"},"prepared_sha256":"actual digest"}"#;
    assert!(!acknowledgment(&held, "attempt.prepared-ack.json", expected).unwrap());
    std::fs::write(
        &path,
        b"{\n\"association\":{\"attempt\":\"original\"},\"prepared_sha256\":\"actual digest\"}\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(acknowledgment(&held, "attempt.prepared-ack.json", expected).unwrap());
    std::fs::write(
        &path,
        br#"{"association":{"attempt":"other"},"prepared_sha256":"actual digest"}"#,
    )
    .unwrap();
    assert!(acknowledgment(&held, "attempt.prepared-ack.json", expected).is_err());
    std::fs::write(&path,br#"{"association":{"attempt":"original"},"prepared_sha256":"actual digest","prepared_sha256":"actual digest"}"#).unwrap();
    assert!(acknowledgment(&held, "attempt.prepared-ack.json", expected).is_err());
    std::fs::remove_file(&path).unwrap();
    let elsewhere = temporary.path().join("unrelated");
    std::fs::write(&elsewhere, expected).unwrap();
    symlink(&elsewhere, &path).unwrap();
    assert!(acknowledgment(&held, "attempt.prepared-ack.json", expected).is_err());
    assert_eq!(std::fs::read(elsewhere).unwrap(), expected);
}
