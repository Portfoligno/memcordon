use clap::ValueEnum;
use memcordon_ci::bootstrap_profile::BootstrapProfile;

#[allow(dead_code)]
#[path = "../../ci-native-fingerprint.rs"]
mod launcher;

#[test]
fn dependency_free_launcher_and_controller_profile_inventory_agree() {
    let controller: Vec<_> = BootstrapProfile::value_variants()
        .iter()
        .map(|profile| profile.to_possible_value().unwrap().get_name().to_owned())
        .collect();
    assert_eq!(controller, launcher::PREPARATION_PROFILES);
    for profile in BootstrapProfile::value_variants() {
        assert!(profile.satisfies(BootstrapProfile::Stable));
        assert!(profile.satisfies(*profile));
    }
    assert!(BootstrapProfile::ReleasePreflight.satisfies(BootstrapProfile::Msrv));
    assert!(BootstrapProfile::ReleasePreflight.satisfies(BootstrapProfile::SupplyChain));
    assert!(!BootstrapProfile::Miri.satisfies(BootstrapProfile::Fuzz));
    assert!(!BootstrapProfile::Fuzz.satisfies(BootstrapProfile::Miri));
    assert!(!BootstrapProfile::Stable.satisfies(BootstrapProfile::Msrv));
}

#[test]
fn launcher_rejects_missing_duplicate_unknown_and_extra_options() {
    let args = |values: &[&str]| {
        values
            .iter()
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
    };
    for values in [
        vec![],
        vec!["--output", "context"],
        vec!["--profile", "unknown", "--output", "context"],
        vec!["--profile", "stable", "--profile", "miri"],
        vec!["--profile", "stable", "--output", "--profile"],
        vec!["--profile", "stable", "--output", "context", "--extra", "x"],
        vec![
            "--profile",
            "stable",
            "--output",
            "context",
            "--trace-inventory",
            "1",
        ],
    ] {
        assert!(
            launcher::parse_preparation_arguments(&args(&values)).is_err(),
            "{values:?}"
        );
    }
    for profile in launcher::PREPARATION_PROFILES {
        let values = args(&[
            "--profile",
            profile,
            "--output",
            "path with spaces",
            "--trace-inventory",
            "false",
        ]);
        let (selected, output, tracing) = launcher::parse_preparation_arguments(&values).unwrap();
        assert_eq!(selected, *profile);
        assert_eq!(output, std::path::Path::new("path with spaces"));
        assert!(!tracing);
    }
    if !cfg!(windows) {
        assert!(
            launcher::parse_preparation_arguments(&args(&[
                "--profile",
                "stable",
                "--output",
                "context",
                "--trace-inventory",
                "true"
            ]))
            .is_err()
        );
    }
}

#[test]
fn controller_requires_exact_profile_and_rejects_private_options_on_new_suites() {
    let executable = env!("CARGO_BIN_EXE_memcordon-ci");
    for arguments in [
        vec!["build-context", "--output", "unused"],
        vec![
            "build-context",
            "--profile",
            "unknown",
            "--output",
            "unused",
        ],
        vec![
            "build-context",
            "--profile",
            "stable",
            "--profile",
            "fuzz",
            "--output",
            "unused",
        ],
    ] {
        let result = std::process::Command::new(executable)
            .args(arguments)
            .output()
            .unwrap();
        assert!(!result.status.success());
    }
    for suite in [
        "miri-first",
        "miri-second",
        "fuzz-quarter-one",
        "fuzz-quarter-four",
        "stress-packages",
        "stress-lifecycle",
    ] {
        let result = std::process::Command::new(executable)
            .args(["suite", suite, "--stage", "candidate-capability"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("private native suite options"));
    }
}

#[test]
fn staged_tool_promotion_is_content_checked_and_failure_cannot_publish_context() {
    let temporary = tempfile::tempdir().unwrap();
    let staging = temporary.path().join("staged-tool");
    let destination = temporary.path().join("bin/tool");
    std::fs::write(&staging, b"prepared executable\n").unwrap();
    assert!(launcher::promote_tool(&staging, &destination, "wrong digest").is_err());
    assert!(!destination.exists());
    use sha2::Digest;
    let digest = hex::encode(sha2::Sha256::digest(std::fs::read(&staging).unwrap()));
    launcher::promote_tool(&staging, &destination, &digest).unwrap();
    assert_eq!(
        std::fs::read(&destination).unwrap(),
        std::fs::read(&staging).unwrap()
    );
    std::fs::write(&staging, b"changed staged executable\n").unwrap();
    assert!(launcher::promote_tool(&staging, &destination, &digest).is_err());
    assert!(!temporary.path().join("native-inputs.bin").exists());
}
