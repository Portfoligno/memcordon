use memcordon_ci::release::packages::publish_install_lineage_file;

#[test]
fn published_lineage_is_exact_immutable_custody_and_cannot_replace_a_record() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("registry-graph.json");
    let bytes = br#"{"format":"lineage","packages":[]}"#;
    publish_install_lineage_file(&path, bytes).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    #[cfg(windows)]
    {
        let held =
            memcordon_ci::windows_readiness_adapter::hold_artifact(&path, None, 1024).unwrap();
        assert_eq!(held.bytes, bytes);
    }
    assert!(publish_install_lineage_file(&path, b"replacement").is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let crates = directory.path().join("crates");
    std::fs::create_dir(&crates).unwrap();
    let archive = crates.join("dependency.crate");
    publish_install_lineage_file(&archive, b"exact archive").unwrap();
    assert_eq!(std::fs::read(archive).unwrap(), b"exact archive");
}
