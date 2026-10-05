use memcordon_ci::{
    cache, native_test_plan,
    release::{distribution::Distribution, git::Git},
};
use serde_yaml::Value;
use std::{
    fs,
    path::{Path, PathBuf},
};

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn compilation_keys_cover_tracked_recipes_and_checkout_policy_without_runtime_state() {
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-cache-inputs-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-cache-inputs-")
        .tempdir()
        .unwrap();
    let root = directory.path();
    fs::create_dir_all(root.join("ci")).unwrap();
    fs::create_dir_all(root.join(".github/workflows")).unwrap();
    for file in ["toolchains.toml", "distribution.toml"] {
        fs::copy(
            repository().join("ci").join(file),
            root.join("ci").join(file),
        )
        .unwrap();
    }
    fs::write(root.join("Cargo.lock"), "# Fixture lockfile\nversion = 4\n").unwrap();
    fs::write(root.join(".gitattributes"), "*.rs text eol=lf\n").unwrap();
    fs::write(
        root.join(".github/workflows/release.yml"),
        "name: Fixture\n",
    )
    .unwrap();
    let git = Git::new(root).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Cache fixture"]).unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    git.text(["add", "."]).unwrap();
    git.text(["commit", "--no-gpg-sign", "-m", "Fixture inputs"])
        .unwrap();
    let initial = cache::context(root, "native-debug", "complete", &[]).unwrap();
    let release = cache::context(root, "native-release", "complete", &[]).unwrap();
    let legacy = cache::context(root, "native", "complete", &[]).unwrap();
    assert_eq!(legacy.revision, 1);
    assert!(!legacy.inputs.contains_key("native-test-arguments"));
    for (context, optimized, profile) in [
        (&initial, false, "source-tests:dev"),
        (&release, true, "source-tests:release;product:release"),
    ] {
        assert_eq!(context.revision, 2);
        assert_eq!(context.inputs["profile"], profile);
        let actual: Vec<Vec<String>> =
            serde_json::from_str(&context.inputs["native-test-arguments"]).unwrap();
        let expected: Vec<_> = native_test_plan::commands(optimized)
            .into_iter()
            .map(|command| command.arguments)
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(actual.len(), 2);
        assert!(actual[0].iter().any(|argument| argument == "--no-run"));
        assert!(
            actual[1]
                .iter()
                .any(|argument| argument == "--no-fail-fast")
        );
        for command in actual {
            assert_eq!(
                command.iter().any(|argument| argument == "--release"),
                optimized
            );
        }
    }
    for partition in ["source", "product", "consumer"] {
        assert_ne!(initial.partitions[partition], release.partitions[partition]);
        assert_ne!(initial.partitions[partition], legacy.partitions[partition]);
        assert_ne!(release.partitions[partition], legacy.partitions[partition]);
    }
    assert_eq!(initial.inputs["commit"], release.inputs["commit"]);
    assert_eq!(initial.inputs["target"], release.inputs["target"]);
    assert!(!initial.inputs.contains_key("product-distribution"));
    assert_eq!(release.inputs["product-package"], "memcordon");
    assert_eq!(release.inputs["product-profile"], "release");
    let selected = Distribution::read(root).unwrap();
    assert_eq!(
        release.inputs["product-distribution"],
        serde_json::to_string(selected.native().unwrap()).unwrap()
    );
    for path in [
        ".release/prepared/sentinel",
        "target/ci/reports/execution/sentinel",
        "target/ci/installed/sentinel",
    ] {
        let path = root.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "Runtime state is excluded\n").unwrap();
    }
    let runtime = cache::context(root, "native-debug", "complete", &[]).unwrap();
    assert_eq!(initial.partitions, runtime.partitions);
    let mut previous = initial.partitions;
    for (file, bytes) in [
        (
            ".github/workflows/release.yml",
            "name: Changed setup recipe\n",
        ),
        (".gitattributes", "*.rs text eol=lf\n*.yml text eol=lf\n"),
    ] {
        fs::write(root.join(file), bytes).unwrap();
        let dirty = cache::context(root, "native-debug", "complete", &[]).unwrap();
        assert!(
            !dirty.usable,
            "dirty tracked inputs cannot restore compiled output"
        );
        git.text(["add", file]).unwrap();
        git.text(["commit", "--no-gpg-sign", "-m", "Changed build input"])
            .unwrap();
        let changed = cache::context(root, "native-debug", "complete", &[]).unwrap();
        for partition in ["source", "product", "consumer"] {
            assert_ne!(previous[partition], changed.partitions[partition]);
        }
        previous = changed.partitions;
    }
    fs::write(root.join("ci/distribution.toml"), "invalid distribution\n").unwrap();
    git.text(["add", "ci/distribution.toml"]).unwrap();
    git.text(["commit", "--no-gpg-sign", "-m", "Unknown product selection"])
        .unwrap();
    let unknown = cache::context(root, "native-release", "complete", &[]).unwrap();
    assert!(!unknown.usable);
    assert_eq!(unknown.inputs["product-distribution"], "unknown-selection");
}

#[test]
fn actual_native_owner_cache_paths_do_not_capture_staging_or_report_sentinels() {
    #[cfg(unix)]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-native-cache-paths-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let directory = tempfile::Builder::new()
        .prefix("memcordon-native-cache-paths-")
        .tempdir()
        .unwrap();
    let sentinels = [
        ".release/prepared/sentinel",
        "target/ci/reports/execution/sentinel",
        "target/ci/deadline-evidence/sentinel",
        "target/ci/installed/sentinel",
        ".cargo/credentials/sentinel",
    ];
    for sentinel in sentinels {
        let path = directory.path().join(sentinel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, "Excluded state\n").unwrap();
    }
    for source in [
        include_str!("../../../.github/workflows/ci.yml"),
        include_str!("../../../.github/workflows/release.yml"),
    ] {
        let workflow: Value = serde_yaml::from_str(source).unwrap();
        for job in workflow["jobs"].as_mapping().unwrap().values() {
            for step in job["steps"].as_sequence().unwrap() {
                if !step["uses"]
                    .as_str()
                    .is_some_and(|action| action.starts_with("actions/cache/"))
                {
                    continue;
                }
                for cached in step["with"]["path"]
                    .as_str()
                    .unwrap()
                    .lines()
                    .map(str::trim)
                    .filter(|path| !path.is_empty())
                {
                    let prefix = cached
                        .split_once('*')
                        .map_or(cached, |(prefix, _)| prefix)
                        .trim_end_matches('/');
                    let prefix = prefix.strip_prefix("~/").unwrap_or(prefix);
                    let cached = directory.path().join(prefix);
                    for sentinel in sentinels {
                        assert!(
                            !directory.path().join(sentinel).starts_with(&cached),
                            "cache path captures excluded sentinel: {prefix}"
                        );
                    }
                }
            }
        }
    }
}
