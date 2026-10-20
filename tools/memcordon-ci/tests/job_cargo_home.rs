use std::{fs, path::Path, process::Command, time::Duration};

fn context(root: &Path) -> memcordon_testkit::ObservedOutput {
    let mut child = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
    child
        .current_dir(root)
        .args(["ci", "driver-context"])
        .env("CARGO_HOME", root.join("target/ci-cargo-home"));
    memcordon_testkit::run_with_deadline_output_limit(
        &mut child,
        Duration::from_secs(60),
        128 * 1024,
    )
    .unwrap()
}

fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("ci")).unwrap();
    fs::write(
        root.path().join("Cargo.toml"),
        "[workspace]\nmembers=[]\nresolver='2'\n",
    )
    .unwrap();
    fs::write(root.path().join("Cargo.lock"), "version=4\n").unwrap();
    fs::write(
        root.path().join("ci/toolchains.toml"),
        include_str!("../../../ci/toolchains.toml"),
    )
    .unwrap();
    fs::write(
        root.path().join("ci/driver-bootstrap.toml"),
        include_str!("../../../ci/driver-bootstrap.toml"),
    )
    .unwrap();
    root
}

#[test]
fn bootstrap_context_initializes_absent_owned_cargo_home_before_optional_discovery() {
    let fixture = fixture();
    let root = fixture.path().canonicalize().unwrap();
    assert!(!root.join("target/ci-cargo-home").exists());
    let _result = context(&root); // This intentionally incomplete repository can miss optional identity.
    assert!(root.join("target/ci-cargo-home").is_dir());
}

#[cfg(unix)]
#[test]
fn redirected_cargo_home_is_rejected_before_outside_mutation() {
    let fixture = fixture();
    let root = fixture.path().canonicalize().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(root.join("target")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.join("target/ci-cargo-home")).unwrap();
    let result = context(&root);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cache"));
    assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
}

#[test]
#[ignore = "native acceptance requires a clean checkout and modeled runner/compiler/SDK identity"]
fn offline_exact_image_miss_preserves_independent_compilation_requests() {
    let fixture = tempfile::tempdir().unwrap();
    let home = fixture
        .path()
        .canonicalize()
        .unwrap()
        .join("empty-cargo-home");
    fs::create_dir(&home).unwrap();
    let outputs = fixture.path().join("outputs");
    fs::write(&outputs, "").unwrap();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
    child
        .current_dir(&root)
        .args(["ci", "driver-context"])
        .env("CARGO_HOME", &home)
        .env("GITHUB_OUTPUT", &outputs);
    let result = memcordon_testkit::run_with_deadline_output_limit(
        &mut child,
        Duration::from_secs(120),
        256 * 1024,
    )
    .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let outputs = fs::read_to_string(outputs).unwrap();
    if !outputs
        .lines()
        .any(|line| line == "compiled-complete-restore=true")
    {
        let mut diagnostic = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"));
        diagnostic
            .current_dir(&root)
            .args(["ci", "cache-context", "--purpose", "ci-driver-build"])
            .env("CARGO_HOME", &home);
        let diagnostic = memcordon_testkit::run_with_deadline_output_limit(
            &mut diagnostic,
            Duration::from_secs(120),
            256 * 1024,
        )
        .unwrap();
        panic!(
            "native compilation identity unavailable; actual context: {}\n{}",
            String::from_utf8_lossy(&diagnostic.stdout),
            String::from_utf8_lossy(&diagnostic.stderr)
        );
    }
    assert!(outputs.lines().any(|line| line == "image-restore=false"));
    assert!(
        outputs
            .lines()
            .any(|line| line == "compiled-complete-restore=true"),
        "{outputs}\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        outputs
            .lines()
            .any(|line| line == "compiled-partial-restore=true"),
        "{outputs}\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
