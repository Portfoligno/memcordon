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
fn strict_channel_option_is_rejected_outside_windows_phase_suites() {
    for suite in [
        "native",
        "miri-first",
        "fuzz-quarter-one",
        "stress-packages",
        "backend-linux-private-v4",
        "backend-windows-sealed-v2",
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
        assert!(String::from_utf8_lossy(&result.stderr).contains("--native-channel applies only"));
    }
}
