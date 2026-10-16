// Mounted privately by preparation.rs to exercise the actual promotion seam.
use super::{promote_auxiliary, validate_auxiliary_directory};
use std::fs;

#[test]
fn promotion_changes_only_the_owned_tool_and_retires_backups() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let bin = root.join("bin");
    fs::create_dir(&bin).unwrap();
    let audit = bin.join("cargo-audit");
    let deny = bin.join("cargo-deny");
    fs::write(&audit, "old\n").unwrap();
    fs::write(&deny, "peer\n").unwrap();
    let staged = root.join("staged");
    fs::write(&staged, "new\n").unwrap();
    promote_auxiliary(&staged, &audit).unwrap();
    assert_eq!(fs::read(&audit).unwrap(), b"new\n");
    assert_eq!(fs::read(&deny).unwrap(), b"peer\n");
    assert_eq!(fs::read_dir(bin).unwrap().count(), 2);
}

#[test]
fn directory_and_symlink_destination_fail_before_sibling_mutation() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().canonicalize().unwrap();
    let staged = root.join("staged");
    fs::write(&staged, "new\n").unwrap();
    let destination = root.join("bin/tool");
    fs::create_dir_all(&destination).unwrap();
    assert!(promote_auxiliary(&staged, &destination).is_err());
    assert!(destination.is_dir());
    #[cfg(unix)]
    {
        let alias = root.join("alias");
        std::os::unix::fs::symlink(&destination, &alias).unwrap();
        assert!(promote_auxiliary(&staged, &alias).is_err());
        assert!(validate_auxiliary_directory(&alias.join("child")).is_err());
        assert!(!destination.join("child").exists());
    }
}
