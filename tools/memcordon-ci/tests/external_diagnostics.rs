use memcordon_ci::external_consumer::retain_diagnostics;

#[test]
fn partial_raw_observations_are_retained_and_unexpected_or_oversized_entries_rejected() {
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let raw = temporary.path().join("raw");
    let retained = temporary.path().join("retained");
    std::fs::create_dir(&raw).unwrap();
    std::fs::create_dir(&retained).unwrap();
    for name in [
        "result.json",
        "stdout.bin",
        "stderr.bin",
        "requested-contract.json",
        "assessment.json",
    ] {
        std::fs::write(raw.join(name), b"partial\n").unwrap();
    }
    retain_diagnostics(&raw, &retained).unwrap();
    for entry in std::fs::read_dir(&raw).unwrap() {
        let entry = entry.unwrap();
        assert_eq!(
            std::fs::read(entry.path()).unwrap(),
            std::fs::read(retained.join(entry.file_name())).unwrap()
        );
    }
    let unexpected = raw.join("unexpected.json");
    std::fs::write(&unexpected, b"unbounded\n").unwrap();
    assert!(retain_diagnostics(&raw, &retained).is_err());
    std::fs::remove_file(&unexpected).unwrap();
    for (name, maximum) in [
        (
            "result.json",
            memcordon_core::result_v1::RESULT_MAX_BYTES as u64,
        ),
        ("assessment.json", 1024 * 1024),
        ("requested-contract.json", 1024 * 1024),
        ("stdout.bin", 16 * 1024 * 1024),
        ("stderr.bin", 16 * 1024 * 1024),
    ] {
        let path = raw.join(name);
        std::fs::File::create(&path)
            .unwrap()
            .set_len(maximum + 1)
            .unwrap();
        assert!(retain_diagnostics(&raw, &retained).is_err(), "{name}");
        std::fs::write(path, b"partial\n").unwrap();
    }
    std::fs::remove_file(raw.join("result.json")).unwrap();
    retain_diagnostics(&raw, &retained).unwrap();
    std::fs::remove_file(raw.join("stdout.bin")).unwrap();
    std::fs::create_dir(raw.join("stdout.bin")).unwrap();
    assert!(retain_diagnostics(&raw, &retained).is_err());
}

#[cfg(unix)]
#[test]
fn raw_diagnostics_do_not_follow_symlinks() {
    let temporary = tempfile::tempdir_in("/tmp").unwrap();
    let raw = temporary.path().join("raw");
    let retained = temporary.path().join("retained");
    std::fs::create_dir(&raw).unwrap();
    std::fs::create_dir(&retained).unwrap();
    let outside = temporary.path().join("outside");
    std::fs::write(&outside, b"outside\n").unwrap();
    std::os::unix::fs::symlink(&outside, raw.join("stdout.bin")).unwrap();
    assert!(retain_diagnostics(&raw, &retained).is_err());
    assert!(!retained.join("stdout.bin").exists());
}
