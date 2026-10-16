//! Real offline Cargo installation from checksum-valid authored registry data.
use memcordon_ci::{
    download_cache::{self, DownloadFamily},
    release::artifacts,
};
use std::{fs, path::Path, process::Command, time::Duration};

const NAMESPACE: &str = "index.crates.io-1949cf8c6b5b557f";

fn package(
    home: &Path,
    name: &str,
    files: &[(&str, String)],
    dependencies: serde_json::Value,
) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o644);
        header.set_size(contents.len() as u64);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                Path::new(&format!("{name}-0.0.1")).join(path),
                contents.as_bytes(),
            )
            .unwrap();
    }
    let bytes = archive.into_inner().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut gzip, &bytes).unwrap();
    let bytes = gzip.finish().unwrap();
    let index = home.join("registry/index").join(NAMESPACE);
    fs::create_dir_all(&index).unwrap();
    fs::write(
        index.join("config.json"),
        "{\"dl\":\"https://static.crates.io/crates\",\"api\":\"https://crates.io\"}\n",
    )
    .unwrap();
    let metadata = serde_json::json!({"name": name, "vers":"0.0.1", "deps":dependencies, "cksum": artifacts::checksum(&bytes), "features":{}, "yanked":false});
    // Cargo's sparse-cache framing for the pinned reader. This is fixture data,
    // not a resolver: Cargo selects and checksum-validates the real archives.
    let mut record = vec![3, 2, 0, 0, 0];
    record.extend_from_slice(b"etag: \"fixture\"\0");
    record.extend_from_slice(b"0.0.1\0");
    record.extend_from_slice(serde_json::to_string(&metadata).unwrap().as_bytes());
    record.push(0);
    let mut chars = name.chars();
    let first = chars.by_ref().take(2).collect::<String>();
    let second = chars.take(2).collect::<String>();
    let entry = index.join(".cache").join(first).join(second).join(name);
    fs::create_dir_all(entry.parent().unwrap()).unwrap();
    fs::write(entry, record).unwrap();
    bytes
}

fn child(root: &Path, home: &Path, output: &Path) -> String {
    let result = Command::new(std::env::current_exe().unwrap())
        .current_dir(root)
        .args([
            "--ignored",
            "--exact",
            "actual_install_child",
            "--nocapture",
        ])
        .env("CARGO_HOME", home)
        .env("CARGO_NET_OFFLINE", "true")
        .env("GITHUB_OUTPUT", output)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stderr).into_owned()
}

#[test]
fn partial_first_snapshot_cannot_freeze_real_tool_archive_roundtrip() {
    let fixture = tempfile::tempdir().unwrap();
    let canonical = fixture.path().canonicalize().unwrap();
    let root = canonical.as_path();
    let home = root.join("cargo-home");
    fs::create_dir_all(root.join("ci")).unwrap();
    fs::create_dir_all(&home).unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::copy(
        repository.join("ci/toolchains.toml"),
        root.join("ci/toolchains.toml"),
    )
    .unwrap();
    fs::write(
        root.join("ci/tools.toml"),
        "cargo_audit=\"0.0.1\"\ncargo_deny=\"0.0.1\"\ncargo_fuzz=\"0.0.1\"\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[workspace]\nmembers=[]\nresolver=\"2\"\n",
    )
    .unwrap();
    fs::write(root.join("Cargo.lock"), "version=4\n").unwrap();
    fs::write(home.join("config.toml"), "").unwrap();
    let dependency = package(&home, "cache-fixture-dependency", &[("Cargo.toml", "[package]\nname=\"cache-fixture-dependency\"\nversion=\"0.0.1\"\nedition=\"2021\"\n".into()), ("src/lib.rs", "pub fn version() -> &'static str { \"0.0.1\" }\n".into())], serde_json::json!([]));
    let cache = home.join("registry/cache").join(NAMESPACE);
    fs::create_dir_all(&cache).unwrap();
    fs::write(
        cache.join("cache-fixture-dependency-0.0.1.crate"),
        &dependency,
    )
    .unwrap();
    let mut partial = tar::Builder::new(Vec::new());
    partial
        .append_dir_all("registry/cache", home.join("registry/cache"))
        .unwrap();
    let partial = partial.into_inner().unwrap();
    let lock = format!(
        "version=4\n[[package]]\nname=\"cargo-audit\"\nversion=\"0.0.1\"\ndependencies=[\"cache-fixture-dependency\"]\n[[package]]\nname=\"cache-fixture-dependency\"\nversion=\"0.0.1\"\nsource=\"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum=\"{}\"\n",
        artifacts::checksum(&dependency)
    );
    let tool = package(&home, "cargo-audit", &[("Cargo.toml", "[package]\nname=\"cargo-audit\"\nversion=\"0.0.1\"\nedition=\"2021\"\n[dependencies]\ncache-fixture-dependency=\"=0.0.1\"\n".into()), ("Cargo.lock", lock), ("src/main.rs", "fn main() { if std::env::args().any(|arg| arg == \"audit\") { std::fs::write(\"audit-scanned\", b\"scanned\\n\").unwrap(); } println!(\"cargo-audit {}\", cache_fixture_dependency::version()); }\n".into())], serde_json::json!([{"name":"cache-fixture-dependency","req":"=0.0.1","features":[],"optional":false,"default_features":true,"target":null,"kind":"normal"}]));
    // The explicitly partial first producer lacks this registry package. The
    // acquisition fixture supplies it; real Cargo must verify and install it.
    fs::write(cache.join("cargo-audit-0.0.1.crate"), &tool).unwrap();
    let output = root.join("outputs");
    fs::write(&output, "").unwrap();
    let diagnostics = child(root, &home, &output);
    let first = fs::read_to_string(&output).unwrap();
    assert!(
        first.contains("download-cargo-audit-populated=true\n"),
        "{diagnostics}"
    );
    assert!(!first.contains("download-cargo-deny-populated=true"));
    let mut complete = tar::Builder::new(Vec::new());
    complete
        .append_dir_all("registry/cache", home.join("registry/cache"))
        .unwrap();
    let complete = complete.into_inner().unwrap();
    fs::remove_dir_all(root.join("target")).unwrap();
    fs::remove_dir_all(home.join("registry/src")).unwrap();
    fs::remove_dir_all(home.join("registry/cache")).unwrap();
    tar::Archive::new(partial.as_slice()).unpack(&home).unwrap();
    assert!(!cache.join("cargo-audit-0.0.1.crate").exists());
    tar::Archive::new(complete.as_slice())
        .unpack(&home)
        .unwrap();
    assert_eq!(
        fs::read(cache.join("cargo-audit-0.0.1.crate")).unwrap(),
        tool
    );
    fs::write(&output, "").unwrap();
    child(root, &home, &output);
    assert!(
        fs::read_to_string(output)
            .unwrap()
            .contains("download-cargo-audit-populated=true\n")
    );
    let deny = package(&home, "cargo-deny", &[
        ("Cargo.toml", "[package]\nname=\"cargo-deny\"\nversion=\"0.0.1\"\nedition=\"2021\"\n".into()),
        ("Cargo.lock", "version=4\n[[package]]\nname=\"cargo-deny\"\nversion=\"0.0.1\"\n".into()),
        ("src/main.rs", "fn main() { println!(\"cargo-deny 0.0.1\"); }\n".into()),
        ("build.rs", "fn main() { let here = std::env::current_dir().unwrap(); let root = here.ancestors().find(|p| p.join(\"ci/toolchains.toml\").exists()).unwrap(); std::fs::write(root.join(\"deny-build-waiting\"), b\"waiting\\n\").unwrap(); let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10); while !root.join(\"audit-scanned\").exists() { assert!(std::time::Instant::now() < deadline, \"warm audit did not scan during cold deny acquisition\"); std::thread::yield_now(); } std::fs::write(root.join(\"deny-built-after-scan\"), b\"built\\n\").unwrap(); }\n".into()),
    ], serde_json::json!([]));
    fs::write(cache.join("cargo-deny-0.0.1.crate"), deny).unwrap();
    let pipeline = Command::new(std::env::current_exe().unwrap())
        .current_dir(root)
        .args([
            "--ignored",
            "--exact",
            "actual_pipeline_child",
            "--nocapture",
        ])
        .env("CARGO_HOME", &home)
        .env("CARGO_NET_OFFLINE", "true")
        .output()
        .unwrap();
    assert!(
        pipeline.status.success(),
        "{} {}",
        String::from_utf8_lossy(&pipeline.stdout),
        String::from_utf8_lossy(&pipeline.stderr)
    );
    assert!(root.join("deny-built-after-scan").is_file());
}

#[test]
#[ignore = "owned actual warm/cold tool pipeline acceptance child"]
fn actual_pipeline_child() {
    use memcordon_ci::{failure_mode::FailureMode, performance_plan::Layout, preparation};
    let root = std::env::current_dir().unwrap();
    let stable = memcordon_ci::config::toolchains(&root).unwrap().stable;
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let [audit, deny] = memcordon_ci::command::supply_chain_commands(&root, &stable);
    preparation::with_operation(FailureMode::CollectAll, deadline, || {
        preparation::complete_lanes_with_allocation(
            Layout::Parallel,
            FailureMode::CollectAll,
            [1, 1],
            || {
                preparation::ensure_one_auxiliary_until(
                    &root,
                    "cargo-audit",
                    "0.0.1",
                    &stable,
                    deadline,
                    std::num::NonZeroUsize::new(1).unwrap(),
                )?;
                while !root.join("deny-build-waiting").exists() {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "cold deny did not start"
                    );
                    std::thread::yield_now();
                }
                let duplicate = preparation::ensure_one_auxiliary_until(
                    &root,
                    "cargo-deny",
                    "0.0.1",
                    &stable,
                    deadline,
                    std::num::NonZeroUsize::new(1).unwrap(),
                )
                .unwrap_err();
                assert!(
                    duplicate
                        .to_string()
                        .contains("duplicate concurrent auxiliary acquisition")
                );
                audit.run().map(|_| ())
            },
            || {
                preparation::ensure_one_auxiliary_until(
                    &root,
                    "cargo-deny",
                    "0.0.1",
                    &stable,
                    deadline,
                    std::num::NonZeroUsize::new(1).unwrap(),
                )?;
                deny.run().map(|_| ())
            },
        )
    })
    .unwrap();
    let audit_bytes = fs::read(preparation::auxiliary_tool(&root, "cargo-audit").unwrap()).unwrap();
    let deny_bytes = fs::read(preparation::auxiliary_tool(&root, "cargo-deny").unwrap()).unwrap();
    assert!(!audit_bytes.is_empty() && !deny_bytes.is_empty());
    // Both cold slots acquire independently without replacing the shared bin.
    fs::remove_file(preparation::auxiliary_tool(&root, "cargo-audit").unwrap()).unwrap();
    fs::remove_file(preparation::auxiliary_tool(&root, "cargo-deny").unwrap()).unwrap();
    preparation::with_operation(FailureMode::CollectAll, deadline, || {
        preparation::complete_lanes_with_allocation(
            Layout::Parallel,
            FailureMode::CollectAll,
            [1, 1],
            || {
                preparation::ensure_one_auxiliary_until(
                    &root,
                    "cargo-audit",
                    "0.0.1",
                    &stable,
                    deadline,
                    std::num::NonZeroUsize::new(1).unwrap(),
                )
                .map(|_| ())
            },
            || {
                preparation::ensure_one_auxiliary_until(
                    &root,
                    "cargo-deny",
                    "0.0.1",
                    &stable,
                    deadline,
                    std::num::NonZeroUsize::new(1).unwrap(),
                )
                .map(|_| ())
            },
        )
    })
    .unwrap();
    assert_eq!(
        fs::read(preparation::auxiliary_tool(&root, "cargo-audit").unwrap()).unwrap(),
        audit_bytes
    );
    assert_eq!(
        fs::read(preparation::auxiliary_tool(&root, "cargo-deny").unwrap()).unwrap(),
        deny_bytes
    );
}

#[test]
#[ignore = "owned child of the offline archive roundtrip"]
fn actual_install_child() {
    let root = std::env::current_dir().unwrap();
    let stable = memcordon_ci::config::toolchains(&root).unwrap().stable;
    let family = DownloadFamily::ToolCargoAudit;
    let before = download_cache::context(&root, family);
    memcordon_ci::preparation::ensure_one_auxiliary_until(
        &root,
        "cargo-audit",
        "0.0.1",
        &stable,
        std::time::Instant::now() + Duration::from_secs(120),
        std::num::NonZeroUsize::new(2).unwrap(),
    )
    .unwrap();
    let executable = memcordon_ci::preparation::auxiliary_tool(&root, "cargo-audit").unwrap();
    let version =
        memcordon_ci::command::CommandSpec::new(executable, &root, Duration::from_secs(30))
            .arg("--version")
            .output_quiet()
            .unwrap();
    assert!(version.status.success());
    assert!(
        String::from_utf8(version.stdout)
            .unwrap()
            .split_whitespace()
            .any(|part| part == "0.0.1")
    );
    assert!(download_cache::packaged_lock_present(&root, "cargo-audit", "0.0.1").unwrap());
    download_cache::record(family, &before, &download_cache::context(&root, family));
    memcordon_ci::workflow_output::quiescent(Ok(())).unwrap();
}
