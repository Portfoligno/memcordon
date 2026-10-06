use std::fs;
use std::process::Command;
use std::time::Duration;

fn directory() -> tempfile::TempDir {
    #[cfg(unix)]
    let root = tempfile::tempdir_in("/tmp").unwrap();
    #[cfg(not(unix))]
    let root = tempfile::tempdir().unwrap();
    assert!(
        root.path()
            .ancestors()
            .all(|parent| { !(parent.join("Cargo.toml").is_file() && parent.join("ci").is_dir()) })
    );
    root
}

#[test]
fn artifact_only_rehearsal_reaches_explicit_input_validation_without_a_workspace() {
    let root = directory();
    let input = root.path().join("input");
    fs::create_dir(&input).unwrap();
    let fixture = root.path().join("fixture-must-not-be-read.json");
    let result = root.path().join("result-must-not-exist.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
    command
        .current_dir(root.path())
        .args(["release", "rehearsal-transaction", "--input"])
        .arg(&input)
        .arg("--fixture")
        .arg(&fixture)
        .arg("--result")
        .arg(&result);
    memcordon_ci::rehearsal_support::coordinator::sanitize_child(&mut command);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(30),
        16 * 1024,
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "memcordon-ci: exactly one rehearsal envelope required\n"
    );
    assert!(!fixture.exists());
    assert!(!result.exists());
    assert_eq!(fs::read_dir(&input).unwrap().count(), 0);
}

#[test]
fn ordinary_ci_suite_still_requires_a_workspace() {
    let root = directory();
    let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
    command.current_dir(root.path()).args(["suite", "policy"]);
    memcordon_ci::rehearsal_support::coordinator::sanitize_child(&mut command);
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(30),
        16 * 1024,
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "memcordon-ci: could not locate the MemCordon workspace\n"
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}
