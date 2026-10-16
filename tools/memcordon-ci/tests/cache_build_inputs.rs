use memcordon_ci::{
    cache_inputs::{self, KeyInputs},
    cache_restore,
    release::git::Git,
};
use std::{collections::BTreeMap, fs, path::Path};

#[test]
fn scoped_inputs_track_includes_modes_paths_without_commit_or_runtime_state() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("crates/example")).unwrap();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    fs::write(root.join("Cargo.lock"), "version=4\n").unwrap();
    fs::write(root.join("crates/example/lib.rs"), "pub fn current() {}\n").unwrap();
    fs::write(
        root.join(".github/workflows/release.yml"),
        "name: included\n",
    )
    .unwrap();
    fs::write(root.join("README.md"), "Root documentation\n").unwrap();
    let git = Git::new(root).unwrap();
    for arguments in [
        vec!["init", "--quiet"],
        vec!["config", "user.name", "Fixture"],
        vec!["config", "user.email", "fixture@example.invalid"],
        vec!["add", "."],
        vec!["commit", "--no-gpg-sign", "-m", "inputs"],
    ] {
        git.text(arguments).unwrap();
    }
    let initial = cache_inputs::local_files(root, "native-debug").unwrap();
    git.text([
        "commit",
        "--allow-empty",
        "--no-gpg-sign",
        "-m",
        "new identity",
    ])
    .unwrap();
    assert_eq!(
        initial,
        cache_inputs::local_files(root, "native-debug").unwrap()
    );
    for name in [
        "README.md",
        ".release/prepared/sentinel",
        "target/ci/reports/execution/sentinel",
        "target/ci/installed/sentinel",
    ] {
        let path = root.join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "Excluded runtime or root documentation\n").unwrap();
    }
    assert_eq!(
        initial,
        cache_inputs::local_files(root, "native-debug").unwrap()
    );
    fs::write(
        root.join(".github/workflows/release.yml"),
        "name: changed include\n",
    )
    .unwrap();
    assert_ne!(
        initial,
        cache_inputs::local_files(root, "native-debug").unwrap()
    );
    fs::write(
        root.join(".github/workflows/release.yml"),
        "name: included\n",
    )
    .unwrap();
    git.text(["mv", "crates/example/lib.rs", "crates/example/main.rs"])
        .unwrap();
    assert_ne!(
        initial,
        cache_inputs::local_files(root, "native-debug").unwrap()
    );
    git.text(["mv", "crates/example/main.rs", "crates/example/lib.rs"])
        .unwrap();
    git.text(["update-index", "--chmod=+x", "crates/example/lib.rs"])
        .unwrap();
    assert_ne!(
        initial,
        cache_inputs::local_files(root, "native-debug").unwrap()
    );
}

#[test]
fn key_renderer_separates_content_from_full_compatibility() {
    let mut inputs = KeyInputs {
        family: "workspace".into(),
        layout_revision: 4,
        compatibility: BTreeMap::from([("compiler".into(), "stable-x64-debug".into())]),
        content: BTreeMap::from([("source".into(), "first".into())]),
    };
    let first = cache_inputs::keys(&inputs).unwrap();
    inputs.content.insert("source".into(), "second".into());
    let second = cache_inputs::keys(&inputs).unwrap();
    assert_ne!(first.0, second.0);
    assert_eq!(first.1, second.1);
    inputs
        .compatibility
        .insert("compiler".into(), "stable-arm-release".into());
    assert_ne!(second.1, cache_inputs::keys(&inputs).unwrap().1);
    inputs.family = "arbitrary".into();
    assert!(cache_inputs::keys(&inputs).is_err());
}

#[test]
fn finite_paths_exclude_runtime_capture_staging_tools_and_sibling_shards() {
    let excluded = [
        ".release/prepared/sentinel",
        ".release/native-readiness/sentinel",
        "target/ci/reports/execution/sentinel",
        "target/ci/deadline-evidence/sentinel",
        "target/ci/installed/sentinel",
        "target/ci-build/package-staging/sentinel",
        "target/ci-consumers/install-capture/sentinel",
        "target/ci-tools/bin/unselected",
        ".cargo/credentials",
    ];
    for (purpose, shard) in [
        ("native-debug", "complete"),
        ("native-release", "complete"),
        ("quality", "complete"),
        ("miri", "first"),
    ] {
        for root in cache_restore::roots(purpose, shard).unwrap() {
            for sentinel in excluded {
                assert!(
                    !Path::new(sentinel).starts_with(&root),
                    "{root:?} captures {sentinel}"
                );
            }
            if purpose == "miri" {
                assert!(!Path::new("target/ci/miri-second").starts_with(&root));
            }
        }
    }
    assert!(cache_restore::roots("consumer-readiness", "public").is_err());
    assert_eq!(
        cache_restore::roots("private", "complete").unwrap().len(),
        3
    );
    assert!(cache_restore::roots("native", "complete").is_err());
}

#[test]
fn discard_refuses_links_and_unknown_roots_and_retains_reports() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir_all(directory.path().join("target/ci/quality")).unwrap();
    fs::create_dir_all(directory.path().join("target/ci/reports")).unwrap();
    fs::write(
        directory.path().join("target/ci/reports/sentinel"),
        "retain\n",
    )
    .unwrap();
    cache_restore::prepare(
        directory.path(),
        "quality",
        "complete",
        cache_restore::RestoreMode::Discard,
    )
    .unwrap();
    assert!(!directory.path().join("target/ci/quality").exists());
    assert!(directory.path().join("target/ci/reports/sentinel").exists());
    assert!(
        cache_restore::prepare(
            directory.path(),
            "../",
            "complete",
            cache_restore::RestoreMode::Discard
        )
        .is_err()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(
            directory.path().join("target/ci/reports"),
            directory.path().join("target/ci/quality"),
        )
        .unwrap();
        assert!(
            cache_restore::prepare(
                directory.path(),
                "quality",
                "complete",
                cache_restore::RestoreMode::Discard
            )
            .is_err()
        );
    }
}

#[test]
fn isolated_home_seeds_third_party_archives_without_credentials_or_public_images() {
    let directory = tempfile::tempdir().unwrap();
    let shared = directory.path().join("shared");
    let fresh = directory.path().join("fresh");
    fs::create_dir_all(shared.join("registry/cache/source")).unwrap();
    fs::create_dir_all(&fresh).unwrap();
    fs::write(
        shared.join("registry/cache/source/third-party-1.0.crate"),
        "download",
    )
    .unwrap();
    fs::write(
        shared.join("registry/cache/source/memcordon-1.0.crate"),
        "selected public image",
    )
    .unwrap();
    fs::write(shared.join("config.toml"), "secret").unwrap();
    fs::write(shared.join("credentials.toml"), "secret").unwrap();
    cache_inputs::seed_isolated_downloads(&shared, &fresh, true).unwrap();
    assert!(
        fresh
            .join("registry/cache/source/third-party-1.0.crate")
            .exists()
    );
    assert!(
        !fresh
            .join("registry/cache/source/memcordon-1.0.crate")
            .exists()
    );
    assert!(!fresh.join("config.toml").exists());
    assert!(!fresh.join("credentials.toml").exists());
    assert!(!fresh.join("registry/src").exists());
    let missing = directory.path().join("missing-shared");
    let cold = directory.path().join("cold");
    fs::create_dir(&cold).unwrap();
    cache_inputs::seed_isolated_downloads(&missing, &cold, true).unwrap();
    #[cfg(unix)]
    {
        let unsafe_home = directory.path().join("unsafe-home");
        let outside = directory.path().join("outside");
        fs::create_dir(&unsafe_home).unwrap();
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, unsafe_home.join("registry")).unwrap();
        assert!(cache_inputs::seed_isolated_downloads(&shared, &unsafe_home, true).is_err());
        assert!(!outside.join("cache").exists());
    }
}

#[test]
fn tracked_fixture_targets_are_hashed_without_accepting_untracked_or_external_sources() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("checkout");
    let manifest = root.join("tests/fixtures/example/Cargo.toml");
    let source = root.join("tests/fixtures/example/src/main.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    fs::write(
        &manifest,
        "[package]\nname=\"fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[workspace]\n[[bin]]\nname=\"fixture\"\npath=\"src/main.rs\"\n",
    )
    .unwrap();
    fs::write(&source, "fn main() {}\n").unwrap();
    let git = Git::new(&root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["add", "Cargo.toml", "tests"]).unwrap();
    let initial = cache_inputs::local_files(&root, "native-readiness").unwrap();
    assert!(initial.contains_key("tests/fixtures/example/src/main.rs"));
    fs::write(&source, "fn main() { println!(\"changed\"); }\n").unwrap();
    assert_ne!(
        initial,
        cache_inputs::local_files(&root, "native-readiness").unwrap()
    );
    fs::write(
        source.parent().unwrap().join("untracked.rs"),
        "fn main() {}\n",
    )
    .unwrap();
    fs::write(
        &manifest,
        "[package]\nname=\"fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[workspace]\n[[bin]]\nname=\"fixture\"\npath=\"src/untracked.rs\"\n",
    )
    .unwrap();
    assert!(cache_inputs::local_files(&root, "native-readiness").is_err());
    fs::write(fixture.path().join("outside.rs"), "fn main() {}\n").unwrap();
    fs::write(
        &manifest,
        "[package]\nname=\"fixture\"\nversion=\"0.0.0\"\nedition=\"2021\"\n[workspace]\n[[bin]]\nname=\"fixture\"\npath=\"../../../../outside.rs\"\n",
    )
    .unwrap();
    assert!(cache_inputs::local_files(&root, "native-readiness").is_err());
}

#[test]
fn checkout_native_readiness_projection_models_all_tracked_manifest_inputs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    cache_inputs::local_files(root, "native-readiness").unwrap();
}

#[test]
fn external_or_untracked_local_dependencies_disable_workspace_projection() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("checkout");
    let outside = fixture.path().join("outside");
    fs::create_dir_all(&root).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("Cargo.toml"),
        "[package]\nname=\"outside\"\nversion=\"0.0.0\"\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
    let git = Git::new(&root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["add", "Cargo.toml"]).unwrap();
    assert!(cache_inputs::local_files(&root, "native-debug").is_ok());
    fs::write(
        root.join("Cargo.toml"),
        "[workspace.dependencies]\noutside={path=\"../outside\"}\n",
    )
    .unwrap();
    assert!(cache_inputs::local_files(&root, "native-debug").is_err());
    fs::create_dir(root.join("unmodeled")).unwrap();
    fs::write(
        root.join("unmodeled/Cargo.toml"),
        "[package]\nname=\"unmodeled\"\nversion=\"0.0.0\"\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace.dependencies]\nunmodeled={path=\"unmodeled\"}\n",
    )
    .unwrap();
    assert!(cache_inputs::local_files(&root, "native-debug").is_err());
}
