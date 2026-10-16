use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, SystemTime},
};

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    home: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        fs::create_dir(root.join("ci")).unwrap();
        fs::write(root.join("Cargo.toml"), "[workspace]\nmembers=[]\n").unwrap();
        let home = root.join("cargo-home");
        fs::create_dir(&home).unwrap();
        Self {
            _directory: directory,
            root,
            home,
        }
    }
    fn archive(&self, name: &str) -> PathBuf {
        self.home
            .join("registry/cache/index.crates.io-1949cf8c6b5b557f")
            .join(name)
    }
    fn stage(&self) -> PathBuf {
        self.root.join("target/ci-cache-export/registry-archives")
    }
    fn run(&self, command: &str) -> Output {
        fs::write(self.root.join("outputs"), b"").unwrap();
        Command::new(env!("CARGO_BIN_EXE_memcordon-ci"))
            .args(["ci", command, "--kind", "registry-archives"])
            .current_dir(&self.root)
            .env("CARGO_HOME", &self.home)
            .env("GITHUB_OUTPUT", self.root.join("outputs"))
            .output()
            .unwrap()
    }
    fn snapshot(&self) {
        let result = self.run("cache-snapshot");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            fs::read_to_string(self.root.join("outputs"))
                .unwrap()
                .contains("snapshot-ready=true")
        );
    }
}

fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn registry_snapshot_round_trip_keeps_bytes_and_original_transport_time_without_aliases() {
    let fixture = Fixture::new();
    let archive = fixture.archive("fixture-1.0.0.crate");
    write(&archive, b"actual immutable archive bytes");
    let modified = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    fs::OpenOptions::new()
        .write(true)
        .open(&archive)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    write(&fixture.home.join("credentials.toml"), b"never copied");
    write(
        &fixture
            .home
            .join("registry/cache/private-source/private.crate"),
        b"never copied",
    );
    fixture.snapshot();
    let staged = fixture
        .stage()
        .join("payload/0/index.crates.io-1949cf8c6b5b557f/fixture-1.0.0.crate");
    fs::write(&archive, b"later mutation").unwrap();
    assert_eq!(
        fs::read(&staged).unwrap(),
        b"actual immutable archive bytes"
    );
    assert!(!fixture.stage().join("payload/0/private-source").exists());
    fs::remove_file(&archive).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&staged)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(SystemTime::now()))
        .unwrap();
    let result = fixture.run("import-cache-snapshot");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(&archive).unwrap(),
        b"actual immutable archive bytes"
    );
    assert_eq!(
        fs::metadata(&archive).unwrap().modified().unwrap(),
        modified
    );
    assert!(!fixture.stage().exists());
    fixture.snapshot();
}

#[test]
fn conflicting_archive_and_corrupt_index_are_optional_without_overwriting_live_bytes() {
    let fixture = Fixture::new();
    let archive = fixture.archive("fixture-1.0.0.crate");
    write(&archive, b"seed");
    fixture.snapshot();
    fs::write(&archive, b"live").unwrap();
    assert!(fixture.run("import-cache-snapshot").status.success());
    assert_eq!(fs::read(&archive).unwrap(), b"live");
    assert!(!fixture.stage().exists());
    fixture.snapshot();
    fs::write(fixture.stage().join("index.json"), b"{malformed").unwrap();
    assert!(fixture.run("import-cache-snapshot").status.success());
    assert_eq!(fs::read(&archive).unwrap(), b"live");
}

#[test]
fn effective_config_prefers_extensionless_and_nearest_scalar_over_home() {
    let fixture = Fixture::new();
    write(
        &fixture.home.join("config.toml"),
        b"registries.crates-io.protocol='git'\n",
    );
    write(
        &fixture.root.join(".cargo/config"),
        b"registries.crates-io.protocol='sparse'\n",
    );
    write(
        &fixture.root.join(".cargo/config.toml"),
        b"registry.token='ignored-secret'\n",
    );
    let context = || {
        let result = fixture.run("seed-context");
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        fs::read_to_string(fixture.root.join("outputs"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("seed-compatibility="))
            .unwrap()
            .to_owned()
    };
    let initial = context();
    write(
        &fixture.home.join("config.toml"),
        b"registries.crates-io.protocol='sparse'\n",
    );
    assert_eq!(initial, context());
    write(
        &fixture.root.join(".cargo/config"),
        b"# rustflags token @ include\nregistries.crates-io.protocol='sparse'\nbuild.jobs=4\n",
    );
    assert_eq!(initial, context());
    write(
        &fixture.root.join(".cargo/config"),
        b"registries.crates-io.protocol='git'\n",
    );
    assert_ne!(initial, context());
}

#[test]
fn archive_seed_imports_into_another_owned_cargo_home_without_producer_paths() {
    let producer = Fixture::new();
    write(
        &producer.archive("fixture-1.0.0.crate"),
        b"portable source bytes",
    );
    producer.snapshot();
    let recipient = Fixture::new();
    fs::create_dir_all(recipient.stage().parent().unwrap()).unwrap();
    fs::rename(producer.stage(), recipient.stage()).unwrap();
    let result = recipient.run("import-cache-snapshot");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(recipient.archive("fixture-1.0.0.crate")).unwrap(),
        b"portable source bytes"
    );
}

#[test]
fn traversal_duplicate_and_windows_stream_members_are_rejected_before_live_mutation() {
    for member in [
        "0/../../outside.crate",
        "0/index.crates.io-1949cf8c6b5b557f/fixture.crate:stream",
        "0/index.crates.io-1949cf8c6b5b557f/CON.crate",
    ] {
        let fixture = Fixture::new();
        let archive = fixture.archive("fixture-1.0.0.crate");
        write(&archive, b"seed");
        fixture.snapshot();
        let path = fixture.stage().join("index.json");
        let mut index: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        index["files"][0]["path"] = serde_json::Value::String(member.into());
        fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
        assert!(fixture.run("import-cache-snapshot").status.success());
        assert_eq!(fs::read(&archive).unwrap(), b"seed");
        assert!(!fixture.root.join("outside.crate").exists());
    }
    let fixture = Fixture::new();
    let archive = fixture.archive("fixture-1.0.0.crate");
    write(&archive, b"seed");
    fixture.snapshot();
    let path = fixture.stage().join("index.json");
    let mut index: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let duplicate = index["files"][0].clone();
    index["files"].as_array_mut().unwrap().push(duplicate);
    fs::write(path, serde_json::to_vec(&index).unwrap()).unwrap();
    assert!(fixture.run("import-cache-snapshot").status.success());
    assert_eq!(fs::read(&archive).unwrap(), b"seed");
}

#[test]
fn unknown_registry_scope_emits_empty_lookup_and_keeps_cold_operations_available() {
    let fixture = Fixture::new();
    write(&fixture.root.join(".cargo/config.toml"), b"source.crates-io.replace-with='private'\nsource.private.registry='https://example.invalid/index'\n");
    let result = fixture.run("seed-context");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let outputs = fs::read_to_string(fixture.root.join("outputs")).unwrap();
    assert!(outputs.lines().any(|line| line == "seed-lookup-key="));
    assert!(outputs.lines().any(|line| line == "seed-import-path="));
    assert!(!fixture.stage().exists());
}

#[test]
fn source_seed_ignores_compiler_only_configuration_but_complete_fetch_stays_strict() {
    let fixture = Fixture::new();
    write(&fixture.root.join(".cargo/config.toml"), b"build.rustflags=['--cfg','custom']\nbuild.rustc-wrapper='custom-wrapper'\n[target.x86_64-unknown-linux-gnu]\nlinker='custom-linker'\n[profile.custom]\ninherits='release'\n");
    assert!(memcordon_ci::cache_inputs::download_configs(&fixture.root, false).is_err());
    let result = fixture.run("seed-context");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let outputs = fs::read_to_string(fixture.root.join("outputs")).unwrap();
    assert!(outputs.lines().any(|line| {
        line.strip_prefix("seed-lookup-key=")
            .is_some_and(|value| !value.is_empty())
    }));
}

#[test]
#[cfg(unix)]
fn oversized_sparse_archive_is_refused_before_copy_without_allocating_payload() {
    let fixture = Fixture::new();
    let archive = fixture.archive("oversized-1.0.0.crate");
    fs::create_dir_all(archive.parent().unwrap()).unwrap();
    fs::File::create(&archive)
        .unwrap()
        .set_len(4 * 1024 * 1024 * 1024 + 1)
        .unwrap();
    let result = fixture.run("cache-snapshot");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        fs::read_to_string(fixture.root.join("outputs"))
            .unwrap()
            .lines()
            .any(|line| line == "snapshot-ready=false")
    );
    assert!(!fixture.stage().exists());
    assert_eq!(
        fs::metadata(archive).unwrap().len(),
        4 * 1024 * 1024 * 1024 + 1
    );
}

#[cfg(unix)]
#[test]
fn active_source_lock_and_redirected_stage_are_blocking() {
    let fixture = Fixture::new();
    write(&fixture.archive("fixture-1.0.0.crate"), b"seed");
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(fixture.home.join(".package-cache"))
        .unwrap();
    rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).unwrap();
    assert!(!fixture.run("cache-snapshot").status.success());
    drop(lock);
    let outside = fixture.root.join("outside");
    fs::create_dir(&outside).unwrap();
    fs::create_dir_all(fixture.stage().parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&outside, fixture.stage()).unwrap();
    assert!(!fixture.run("import-cache-snapshot").status.success());
    assert!(outside.exists());
}
