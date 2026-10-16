use memcordon_ci::{
    cache::OptionalCache,
    download_cache::{self, DownloadFamily},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn fixture() -> tempfile::TempDir {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    fs::create_dir(root.join("ci")).unwrap();
    fs::create_dir(root.join("fuzz")).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for file in ["toolchains.toml", "tools.toml"] {
        fs::copy(repository.join("ci").join(file), root.join("ci").join(file)).unwrap();
    }
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers=[]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.lock"), "version = 4\n").unwrap();
    fs::write(
        root.join("fuzz/Cargo.toml"),
        "[workspace]\nmembers=[]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(root.join("fuzz/Cargo.lock"), "version = 4\n").unwrap();
    fixture
}

fn available(root: &Path, family: DownloadFamily) -> memcordon_ci::cache::CacheEntry {
    match download_cache::context(root, family) {
        OptionalCache::Available { entry } => entry,
        other => panic!("fixture acquisition must be identified: {other:?}"),
    }
}

#[test]
fn tool_pin_content_and_recipe_prefixes_are_independent_of_workspace_lock_and_image() {
    let fixture = fixture();
    let root = fixture.path();
    let workspace = available(root, DownloadFamily::Workspace);
    let audit = available(root, DownloadFamily::ToolCargoAudit);
    let deny = available(root, DownloadFamily::ToolCargoDeny);
    let fuzz = available(root, DownloadFamily::ToolCargoFuzz);
    for entry in [&audit, &deny, &fuzz] {
        assert_ne!(workspace.restore_prefix, entry.restore_prefix);
    }
    assert_ne!(audit.restore_prefix, deny.restore_prefix);
    assert_ne!(deny.restore_prefix, fuzz.restore_prefix);
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n# Different workspace resolution\n",
    )
    .unwrap();
    assert_ne!(
        workspace.exact_key,
        available(root, DownloadFamily::Workspace).exact_key
    );
    assert_eq!(
        audit.exact_key,
        available(root, DownloadFamily::ToolCargoAudit).exact_key
    );
    let tools = fs::read_to_string(root.join("ci/tools.toml")).unwrap();
    fs::write(
        root.join("ci/tools.toml"),
        tools.replace("0.22.2", "0.22.3"),
    )
    .unwrap();
    let changed = available(root, DownloadFamily::ToolCargoAudit);
    assert_ne!(audit.exact_key, changed.exact_key);
    assert_eq!(audit.restore_prefix, changed.restore_prefix);
    assert_eq!(
        deny.exact_key,
        available(root, DownloadFamily::ToolCargoDeny).exact_key
    );
    assert!(audit.paths.iter().all(|path| path.is_absolute()));
    assert!(audit.paths[0].ends_with(PathBuf::from("registry").join("cache")));
    assert!(audit.paths[1].ends_with(PathBuf::from("git").join("db")));
}

#[test]
fn relative_cargo_home_is_resolved_at_actual_operation_cwd_and_fetch_emits_current_fact() {
    let fixture = fixture();
    let root = fixture.path();
    let output_file = root.join("outputs");
    let expected_cache = root.join("relative-home").join("registry").join("cache");
    assert!(!expected_cache.exists());
    fs::write(&output_file, "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .current_dir(root)
        .args(["ci", "download-cache-context", "--family", "workspace"])
        .env("CARGO_HOME", "relative-home")
        .env("GITHUB_OUTPUT", &output_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let context: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let emitted_cache = PathBuf::from(context["entry"]["paths"][0].as_str().unwrap());
    assert!(emitted_cache.is_absolute());
    fs::create_dir_all(&expected_cache).unwrap();
    // Windows short names and extended canonical prefixes may spell the same
    // directory differently. Compare existing native paths without changing
    // the lossless context emitted for a cold Cargo home.
    assert_eq!(
        emitted_cache.canonicalize().unwrap(),
        expected_cache.canonicalize().unwrap()
    );
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .current_dir(root)
        .args(["ci", "fetch-downloads", "--family", "workspace"])
        .env("CARGO_HOME", "relative-home")
        .env("GITHUB_OUTPUT", &output_file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outputs = fs::read_to_string(&output_file).unwrap();
    assert!(outputs.contains("workspace-downloads-populated=true\n"));
    assert!(outputs.contains("cache-quiescent=true\n"));
    assert!(!outputs.contains("download-cargo-audit-populated=true"));
    // Failed real acquisition must not produce a successful current fact.
    fs::write(root.join("Cargo.lock"), "invalid lock syntax").unwrap();
    fs::write(&output_file, "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
        .current_dir(root)
        .args(["ci", "fetch-downloads", "--family", "workspace"])
        .env("CARGO_HOME", "relative-home")
        .env("GITHUB_OUTPUT", &output_file)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !fs::read_to_string(&output_file)
            .unwrap()
            .contains("workspace-downloads-populated=true")
    );
}

#[test]
fn unknown_target_policy_suppresses_complete_context_without_failing_builds() {
    let fixture = fixture();
    fs::create_dir(fixture.path().join(".cargo")).unwrap();
    fs::write(
        fixture.path().join(".cargo/config.toml"),
        "[build]\ntarget=\"aarch64-unknown-linux-gnu\"\n",
    )
    .unwrap();
    assert!(matches!(
        download_cache::context(fixture.path(), DownloadFamily::Workspace),
        OptionalCache::Unavailable { .. }
    ));
}
