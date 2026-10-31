#[path = "../src/bin/fixture_identity_snapshot.rs"]
mod snapshot;

use std::fs;
use std::io::Write;

#[test]
fn cumulative_replacement_retains_every_complete_identity() {
    let owner = tempfile::tempdir().unwrap();
    let path = owner.path().join("children.pid");
    let mut identities = Vec::new();
    let mut expected = String::new();
    for index in 1..=9 {
        let pid = 100 + index;
        let birth = u128::MAX - u128::from(index);
        identities.push((pid, birth));
        expected.push_str(&format!("{pid} {birth}\n"));
        snapshot::publish_snapshot(&path, &identities).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), expected);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
    owner.close().unwrap();
}

#[test]
fn partial_and_complete_unpublished_staging_leave_public_snapshot_intact() {
    let owner = tempfile::tempdir().unwrap();
    let path = owner.path().join("children.pid");
    snapshot::publish_snapshot(&path, &[(101, 9001)]).unwrap();
    let mut partial = tempfile::NamedTempFile::new_in(owner.path()).unwrap();
    partial.write_all(b"101 9001\n102 ").unwrap();
    partial.flush().unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "101 9001\n");

    let staged = snapshot::stage_snapshot(&path, &[(101, 9001), (102, 9002)]).unwrap();
    assert_eq!(staged.path().parent(), path.parent());
    assert_eq!(fs::read_to_string(&path).unwrap(), "101 9001\n");
    staged.persist(&path).unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), "101 9001\n102 9002\n");
    drop(partial);
    owner.close().unwrap();
}

#[test]
fn surviving_case_owner_removes_abandoned_staging_siblings() {
    let owner = tempfile::tempdir().unwrap();
    let directory = owner.path().to_path_buf();
    let path = directory.join("children.pid");
    snapshot::publish_snapshot(&path, &[(101, 9001)]).unwrap();
    let staged = snapshot::stage_snapshot(&path, &[(101, 9001), (102, 9002)]).unwrap();
    let (_, abandoned) = staged.keep().unwrap();
    assert!(abandoned.exists());
    assert_eq!(fs::read_to_string(&path).unwrap(), "101 9001\n");
    owner.close().unwrap();
    assert!(!directory.exists());
    assert!(!abandoned.exists());
}
