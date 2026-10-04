use memcordon_ci::native_channel::NativeChannelRequirement;

#[test]
fn required_release_archive_cannot_downgrade_to_development_source() {
    let temporary = tempfile::tempdir().unwrap();
    let input = temporary.path().join("downloaded archive");
    assert!(
        NativeChannelRequirement::RequiredDownloadedArchive
            .validate_input(&input)
            .is_err()
    );
    assert!(
        NativeChannelRequirement::DevelopmentSourceAllowed
            .validate_input(&input)
            .is_ok()
    );
    std::fs::write(&input, "not a directory\n").unwrap();
    assert!(
        NativeChannelRequirement::RequiredDownloadedArchive
            .validate_input(&input)
            .is_err()
    );
    std::fs::remove_file(&input).unwrap();
    std::fs::create_dir(&input).unwrap();
    assert!(
        NativeChannelRequirement::RequiredDownloadedArchive
            .validate_input(&input)
            .is_ok()
    );
}

#[test]
fn obsolete_channel_override_is_rejected_before_ordinary_suite_execution() {
    for suite in [
        "native",
        "miri-first",
        "fuzz-quarter-one",
        "stress-packages",
        "backend-linux-private",
        "backend-windows-job",
    ] {
        let result = std::process::Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
            .args([
                "suite",
                suite,
                "--native-channel",
                "required-downloaded-archive",
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert_eq!(result.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("unexpected argument '--native-channel'")
        );
    }
}
