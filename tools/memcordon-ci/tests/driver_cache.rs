use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

fn fixture() -> tempfile::TempDir {
    let fixture = tempfile::tempdir().unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::create_dir_all(fixture.path().join("ci")).unwrap();
    for name in ["driver-bootstrap.toml", "toolchains.toml"] {
        fs::copy(
            repository.join("ci").join(name),
            fixture.path().join("ci").join(name),
        )
        .unwrap();
    }
    fs::write(
        fixture.path().join("Cargo.toml"),
        "[workspace]\nmembers=[]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(fixture.path().join("Cargo.lock"), "version = 4\n").unwrap();
    fixture
}

fn executable() -> &'static str {
    if cfg!(windows) {
        "memcordon-ci.exe"
    } else {
        "memcordon-ci"
    }
}

fn cold_image(root: &Path) -> PathBuf {
    let cold = root.join("target/ci-driver-cold/release");
    fs::create_dir_all(&cold).unwrap();
    let binary = cold.join(executable());
    fs::copy(env!("CARGO_BIN_EXE_memcordon-ci"), &binary).unwrap();
    // Native debug tests still exercise the real driver, but its unrelated
    // Linux debug sections are not part of the bounded release image fixture.
    // Strip only the disposable copy, never Cargo's original executable.
    #[cfg(target_os = "linux")]
    {
        let mut strip = Command::new("strip");
        strip.arg("--strip-debug").arg(&binary);
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut strip,
            Duration::from_secs(30),
            1024 * 1024,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    binary
}

fn invoke(
    root: &Path,
    binary: &Path,
    command: &str,
    event: &str,
) -> (memcordon_testkit::ObservedOutput, String) {
    let outputs = root.join("outputs");
    fs::write(&outputs, "").unwrap();
    let mut child = Command::new(binary);
    child
        .current_dir(root)
        .args(["ci", command])
        .env("GITHUB_OUTPUT", &outputs)
        .env("GITHUB_EVENT_NAME", event)
        .env("GITHUB_REF", "refs/heads/test")
        .env(
            "CARGO_HOME",
            root.canonicalize().unwrap().join("cargo-home"),
        );
    let output = memcordon_testkit::run_with_deadline_output_limit(
        &mut child,
        Duration::from_secs(120),
        2 * 1024 * 1024,
    )
    .unwrap();
    (output, fs::read_to_string(outputs).unwrap())
}

#[test]
fn real_cold_image_is_adopted_as_bootstrap_then_activated_without_old_job_logic() {
    let fixture = fixture();
    let root = fixture.path();
    let binary = cold_image(root);
    let (output, outputs) = invoke(root, &binary, "driver-adopt-cold", "push");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(outputs.contains("current-ready=true\n"));
    assert!(outputs.contains("driver-origin=built-cold\n"));
    assert!(outputs.contains("bootstrap-save=true\n"));
    assert!(!outputs.contains("image-save=true\n"));
    assert!(!outputs.contains("compiled-complete-save=true\n"));
    let candidate = root.join("target/ci-bootstrap-in");
    fs::create_dir_all(&candidate).unwrap();
    for entry in fs::read_dir(root.join("target/ci-transfer/out/driver-bootstrap")).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), candidate.join(entry.file_name())).unwrap();
    }
    let (output, outputs) = invoke(
        root,
        &candidate.join(executable()),
        "driver-bootstrap",
        "pull_request",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(outputs.contains("bootstrap-ready=true\n"));
    assert!(!outputs.contains("current-ready=true\n"));
    assert!(
        root.join("target/ci-runtime/bootstrap")
            .join(executable())
            .is_file()
    );
}

#[test]
fn cold_adoption_never_uses_untrusted_events_to_publish_an_executable() {
    let fixture = fixture();
    let root = fixture.path();
    let binary = cold_image(root);
    let (output, outputs) = invoke(root, &binary, "driver-adopt-cold", "pull_request");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(outputs.contains("current-ready=true\n"));
    assert!(!outputs.contains("bootstrap-save=true\n"));
    assert!(
        !root
            .join("target/ci-transfer/out/driver-bootstrap")
            .exists()
    );
}

#[test]
fn failed_managed_source_build_retains_sources_when_driver_reuse_is_unavailable() {
    let fixture = fixture();
    let root = fixture.path();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname=\"memcordon-ci\"\nversion=\"0.1.0\"\nedition=\"2021\"\n[workspace]\nmembers=[]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "version=4\n[[package]]\nname=\"memcordon-ci\"\nversion=\"0.1.0\"\n",
    )
    .unwrap();
    fs::write(
        root.join("src/main.rs"),
        "fn main() { let _: u8 = true; }\n",
    )
    .unwrap();
    let archive =
        root.join("cargo-home/registry/cache/index.crates.io-1949cf8c6b5b557f/settled-0.1.0.crate");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    let encoder = flate2::write::GzEncoder::new(
        fs::File::create(&archive).unwrap(),
        flate2::Compression::default(),
    );
    let mut tar = tar::Builder::new(encoder);
    let manifest = b"[package]\nname=\"settled\"\nversion=\"0.1.0\"\n";
    let mut header = tar::Header::new_gnu();
    header.set_size(manifest.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "settled-0.1.0/Cargo.toml", &manifest[..])
        .unwrap();
    tar.into_inner().unwrap().finish().unwrap();
    for arguments in [
        vec!["init", "--quiet"],
        vec!["add", "--", "Cargo.toml", "Cargo.lock", "src", "ci"],
    ] {
        let mut git = Command::new("git");
        git.current_dir(root).args(arguments);
        let output = memcordon_testkit::run_with_deadline_output_limit(
            &mut git,
            Duration::from_secs(30),
            1024 * 1024,
        )
        .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let (output, outputs) = invoke(
        root,
        Path::new(env!("CARGO_BIN_EXE_memcordon-ci")),
        "driver-build",
        "push",
    );
    assert!(
        !output.status.success(),
        "actual compiler failure was hidden"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("mismatched types"),
        "failure did not reach the intended actual compiler error: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        outputs.contains("archives-partial-save=true\n"),
        "{}\n{}",
        outputs,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!outputs.contains("current-ready=true\n"));
    assert!(!outputs.contains("image-save=true\n"));
    assert!(!outputs.contains("compiled-complete-save=true\n"));
    let staged = outputs
        .lines()
        .find_map(|line| line.strip_prefix("archives-partial-path="))
        .unwrap();
    let files: Vec<_> = walkdir::WalkDir::new(staged)
        .into_iter()
        .map(|entry| entry.unwrap())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "crate")
        })
        .collect();
    assert_eq!(files.len(), 1);
    assert_eq!(
        fs::read(files[0].path()).unwrap(),
        fs::read(archive).unwrap()
    );
}
