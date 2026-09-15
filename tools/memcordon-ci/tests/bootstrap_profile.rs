use memcordon_ci::build_context::BuildInputSnapshot;
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[test]
fn optimized_bootstrap_profile_retains_runtime_checks_and_cache_identity() {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest: toml::Value =
        toml::from_str(&fs::read_to_string(repository.join("Cargo.toml")).unwrap()).unwrap();
    let profile = manifest["profile"]["ci-bootstrap"].clone();
    assert_eq!(profile["inherits"].as_str(), Some("dev"));
    assert_eq!(profile["opt-level"].as_integer(), Some(2));
    assert_eq!(profile["debug-assertions"].as_bool(), Some(true));
    assert_eq!(profile["overflow-checks"].as_bool(), Some(true));
    assert_eq!(profile["lto"].as_bool(), Some(false));
    assert!(
        profile.get("package").is_none(),
        "runtime dependencies must share the optimized profile"
    );

    let source = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("src")).unwrap();
    fs::create_dir(source.path().join("tests")).unwrap();
    fs::write(source.path().join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    fs::write(
        source.path().join("tests/runtime.rs"),
        r#"#[test]
fn optimized_profile_keeps_runtime_guards() {
    assert!(cfg!(debug_assertions));
    let overflow = std::panic::catch_unwind(|| {
        let maximum = std::hint::black_box(u8::MAX);
        std::hint::black_box(maximum + 1)
    });
    assert!(overflow.is_err(), "integer overflow checks were disabled");
}
"#,
    )
    .unwrap();
    let mut fixture: toml::Value = toml::from_str("[package]\nname = \"bootstrap-profile-fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n").unwrap();
    let mut profiles = toml::Table::new();
    profiles.insert("ci-bootstrap".into(), profile);
    fixture
        .as_table_mut()
        .unwrap()
        .insert("profile".into(), toml::Value::Table(profiles));
    let fixture_manifest = source.path().join("Cargo.toml");
    fs::write(&fixture_manifest, toml::to_string(&fixture).unwrap()).unwrap();
    let mut command = Command::new("rustup");
    command
        .args([
            "run",
            "1.97.1",
            "cargo",
            "test",
            "--offline",
            "--profile",
            "ci-bootstrap",
            "--manifest-path",
        ])
        .arg(&fixture_manifest)
        .arg("--target-dir")
        .arg(target.path());
    let result = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(30),
        65536,
    )
    .unwrap();
    assert!(
        result.status.success(),
        "profile fixture failed: stdout={:?} stderr={:?}",
        result.stdout,
        result.stderr
    );
    assert!(
        String::from_utf8(result.stdout)
            .unwrap()
            .contains("1 passed;")
    );

    let snapshot = BuildInputSnapshot::capture(source.path()).unwrap();
    fixture["profile"]["ci-bootstrap"]["opt-level"] = toml::Value::Integer(1);
    fs::write(&fixture_manifest, toml::to_string(&fixture).unwrap()).unwrap();
    assert!(
        snapshot.audit().is_err(),
        "profile mutation must invalidate measured source identity"
    );
}
