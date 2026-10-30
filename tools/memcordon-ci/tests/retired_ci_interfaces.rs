use std::process::Command;

#[test]
fn retired_evidence_commands_are_not_compatibility_routes() {
    for arguments in [
        vec!["consumer-readiness-cell", "--help"],
        vec!["consumer-readiness-cleanup", "--help"],
        vec!["consumer-readiness-native-components", "--help"],
        vec!["consumer-readiness-loader-diagnostic", "--help"],
        vec!["release", "consumer-readiness-report", "--help"],
        vec!["release", "prepare-readiness-tools", "--help"],
        vec!["release", "native-coverage-plan", "--help"],
        vec!["release", "native-coverage-shard", "--help"],
        vec!["release", "build-target", "--consumer-readiness"],
        vec!["suite", "release-readiness"],
        vec!["ci", "aggregate-macos"],
    ] {
        let root = tempfile::tempdir().unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
            .current_dir(root.path())
            .args(&arguments)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "accepted retired route {arguments:?}: {:?}",
            output
        );
        assert!(std::fs::read_dir(root.path()).unwrap().next().is_none());
    }
}
