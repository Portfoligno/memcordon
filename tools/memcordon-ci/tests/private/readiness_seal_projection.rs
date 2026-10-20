use super::acquisition_failed;

#[test]
fn stale_projection_cannot_hide_either_wrapper_failure() {
    assert!(!acquisition_failed(None).unwrap());
    for marker in ["acquisition-failure.json", "always-cleanup-failure.json"] {
        let owned = tempfile::tempdir().unwrap();
        assert!(!acquisition_failed(Some(owned.path())).unwrap());
        std::fs::write(owned.path().join(marker), b"retained failure").unwrap();
        assert!(acquisition_failed(Some(owned.path())).unwrap());
    }
    let owned = tempfile::tempdir().unwrap();
    let not_directory = owned.path().join("not-directory");
    std::fs::write(&not_directory, b"invalid acquisition root").unwrap();
    assert!(acquisition_failed(Some(&not_directory)).is_err());
    assert!(acquisition_failed(Some(&owned.path().join("missing"))).is_err());
    #[cfg(unix)]
    {
        let linked = owned.path().join("linked-root");
        std::os::unix::fs::symlink(owned.path(), &linked).unwrap();
        assert!(acquisition_failed(Some(&linked)).is_err());
    }
}
