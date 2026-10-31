use super::*;

#[test]
fn byte_inventory_detects_changed_members_and_refuses_symlinks_and_size_growth() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("image.json"), b"first").unwrap();
    let paths = [PathBuf::from("image.json")];
    let initial = records(temp.path(), &paths).unwrap();
    std::fs::write(temp.path().join("image.json"), b"other").unwrap();
    assert_ne!(initial, records(temp.path(), &paths).unwrap());
    assert!(read(temp.path(), Path::new("image.json"), 2).is_err());
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(temp.path().join("image.json"), temp.path().join("linked"))
            .unwrap();
        assert!(read(temp.path(), Path::new("linked"), 100).is_err());
    }
}

#[test]
fn private_member_inventory_requires_exact_executable_fixture_without_changing_private_driver() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::write(temp.path().join("image.json"), b"driver image").unwrap();
    let upstream = vec![PathBuf::from("image.json")];
    assert_eq!(
        private_members(Kind::PrivateDriver, upstream.clone()),
        upstream
    );
    let paths = private_members(Kind::Private, upstream.clone());
    assert_eq!(paths.len(), upstream.len() + 1);
    assert_eq!(
        paths.last().unwrap(),
        Path::new("target/ci/native/release/memcordon-linux-readiness-fixture")
    );
    assert!(records(temp.path(), &paths).is_err());
    let fixture = temp.path().join(paths.last().unwrap());
    std::fs::create_dir_all(fixture.parent().unwrap()).unwrap();
    std::fs::write(&fixture, b"actual fixture bytes").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let original = records(temp.path(), &paths).unwrap();
    assert!(original.last().unwrap().executable);
    std::fs::write(&fixture, b"changed fixture bytes").unwrap();
    assert_ne!(original, records(temp.path(), &paths).unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fixture, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(records(temp.path(), &paths).is_err());
    }
    assert!(records(temp.path(), &upstream).is_ok());
}
