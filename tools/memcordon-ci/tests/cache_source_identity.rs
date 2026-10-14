use memcordon_ci::{
    cache_inputs,
    cache_restore::{self, RestoreMode},
    command::CommandSpec,
    release::git::Git,
};
use std::{fs, path::Path, time::Duration};

fn cargo(root: &Path, arguments: &[&str]) {
    CommandSpec::cargo("rustup", root, "1.97.1", Duration::from_secs(90))
        .args(arguments.iter().copied())
        .run()
        .unwrap();
}

fn reported_commit(root: &Path) -> String {
    let binary = root.join("target/ci/native/debug").join(if cfg!(windows) {
        "identity-fixture.exe"
    } else {
        "identity-fixture"
    });
    String::from_utf8(
        CommandSpec::new(binary, root, Duration::from_secs(10))
            .run()
            .unwrap(),
    )
    .unwrap()
    .trim()
    .to_owned()
}

fn packaged_commit(root: &Path) -> String {
    cargo(
        root,
        &[
            "package",
            "--locked",
            "--no-verify",
            "--target-dir",
            "target/ci/native",
            "-p",
            "identity-fixture",
        ],
    );
    let bytes =
        fs::read(root.join("target/ci/native/package/identity-fixture-0.1.0.crate")).unwrap();
    let mut archive = tar::Archive::new(flate2::read::GzDecoder::new(bytes.as_slice()));
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if entry
            .path()
            .unwrap()
            .file_name()
            .is_some_and(|name| name == ".cargo_vcs_info.json")
        {
            return serde_json::from_reader::<_, serde_json::Value>(&mut entry).unwrap()["git"]["sha1"]
                .as_str().unwrap().to_owned();
        }
    }
    panic!("real Cargo package omitted current VCS metadata");
}

#[test]
fn exact_and_compatible_restores_rebuild_commit_bearing_binary_and_package_metadata() {
    let directory = tempfile::Builder::new()
        .prefix("memcordon-cache-identity-")
        .tempdir()
        .unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("ci")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[\".\"]\nresolver=\"2\"\n[package]\nname=\"identity-fixture\"\nversion=\"0.1.0\"\nedition=\"2024\"\n").unwrap();
    fs::write(
        root.join("src/main.rs"),
        "fn main() { println!(\"{}\", env!(\"FIXTURE_COMMIT\")); }\n",
    )
    .unwrap();
    fs::write(
        root.join("build.rs"),
        r#"fn main() {
    let output = std::process::Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();
    assert!(output.status.success());
    println!("cargo:rustc-env=FIXTURE_COMMIT={}", String::from_utf8(output.stdout).unwrap().trim());
    println!("cargo:rerun-if-changed=build.rs");
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("ci/toolchains.toml"),
        include_str!("../../../ci/toolchains.toml"),
    )
    .unwrap();
    fs::write(root.join(".gitignore"), "/target/\n").unwrap();
    cargo(root, &["generate-lockfile"]);
    let git = Git::new(root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Identity fixture"])
        .unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    git.text(["add", "."]).unwrap();
    git.text(["commit", "--no-gpg-sign", "-m", "fixture source"])
        .unwrap();
    let initial = git.text(["rev-parse", "HEAD"]).unwrap().trim().to_owned();
    let inputs = cache_inputs::local_files(root, "native-debug").unwrap();
    cargo(
        root,
        &["build", "--locked", "--target-dir", "target/ci/native"],
    );
    assert_eq!(reported_commit(root), initial);
    assert_eq!(packaged_commit(root), initial);
    for mode in [RestoreMode::Exact, RestoreMode::Compatible] {
        git.text([
            "commit",
            "--allow-empty",
            "--no-gpg-sign",
            "-m",
            "same tree, new identity",
        ])
        .unwrap();
        let current = git.text(["rev-parse", "HEAD"]).unwrap().trim().to_owned();
        assert_ne!(current, initial);
        assert_eq!(
            inputs,
            cache_inputs::local_files(root, "native-debug").unwrap()
        );
        // The reused target really contains stale output before sanitation.
        assert_ne!(reported_commit(root), current);
        cache_restore::prepare(root, "native-debug", "complete", mode).unwrap();
        cargo(
            root,
            &["build", "--locked", "--target-dir", "target/ci/native"],
        );
        assert_eq!(reported_commit(root), current);
        assert_eq!(packaged_commit(root), current);
    }
}
