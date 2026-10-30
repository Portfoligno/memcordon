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
