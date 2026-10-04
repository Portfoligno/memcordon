use memcordon_ci::release::packages::{prepare_consumer_lock, verify_external_lock};
use std::path::Path;

const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";
const CHECKSUM: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn directory() -> tempfile::TempDir {
    if cfg!(unix) {
        tempfile::tempdir_in("/tmp").unwrap()
    } else {
        tempfile::tempdir().unwrap()
    }
}

fn package(name: &str, version: &str, source: Option<&str>) -> toml::Value {
    let mut package = toml::Table::from_iter([
        ("name".into(), toml::Value::String(name.into())),
        ("version".into(), toml::Value::String(version.into())),
    ]);
    if let Some(source) = source {
        package.insert("source".into(), toml::Value::String(source.into()));
        package.insert("checksum".into(), toml::Value::String(CHECKSUM.into()));
    }
    toml::Value::Table(package)
}

fn lock(packages: Vec<toml::Value>) -> String {
    toml::to_string(&toml::Table::from_iter([
        ("version".into(), toml::Value::Integer(4)),
        ("package".into(), toml::Value::Array(packages)),
    ]))
    .unwrap()
}

#[test]
fn consumer_lock_keeps_selected_external_identity_checksum_and_duplicate_guards() {
    let owner = directory();
    let selected = owner.path().join("selected.lock");
    let consumer = owner.path().join("consumer.lock");
    let dependency = package("selected-dependency", "1.0.0", Some(REGISTRY));
    let unused = package("unused-dependency", "2.0.0", Some(REGISTRY));
    std::fs::write(&selected, lock(vec![dependency.clone(), unused])).unwrap();
    std::fs::write(
        &consumer,
        lock(vec![
            package("generated-consumer", "0.0.0", None),
            dependency.clone(),
        ]),
    )
    .unwrap();
    verify_external_lock(&selected, &consumer).unwrap();

    for (field, replacement) in [
        ("name", "different-dependency"),
        ("version", "1.0.1"),
        ("source", "registry+https://example.invalid/index"),
        ("checksum", "different-checksum"),
    ] {
        let mut changed = dependency.clone();
        changed[field] = toml::Value::String(replacement.into());
        std::fs::write(&consumer, lock(vec![changed])).unwrap();
        assert!(verify_external_lock(&selected, &consumer).is_err());
    }
    let mut missing_checksum = dependency.clone();
    missing_checksum.as_table_mut().unwrap().remove("checksum");
    std::fs::write(&consumer, lock(vec![missing_checksum])).unwrap();
    assert!(verify_external_lock(&selected, &consumer).is_err());
    std::fs::write(
        &consumer,
        lock(vec![dependency.clone(), dependency.clone()]),
    )
    .unwrap();
    assert!(verify_external_lock(&selected, &consumer).is_err());
    std::fs::write(
        &selected,
        lock(vec![dependency.clone(), dependency.clone()]),
    )
    .unwrap();
    std::fs::write(&consumer, lock(vec![dependency])).unwrap();
    assert!(verify_external_lock(&selected, &consumer).is_err());
}

#[test]
fn selected_lock_reconciles_a_new_offline_local_workspace_without_mutating_source() {
    let owner = directory();
    let selected = owner.path().join("Cargo.lock");
    let selected_bytes = lock(vec![
        package("selected-workspace", "0.0.0", None),
        package("local-public", "0.9.0", None),
        package("unused-selected-external", "1.0.0", Some(REGISTRY)),
    ]);
    std::fs::write(&selected, &selected_bytes).unwrap();
    let public = owner.path().join("local-public");
    std::fs::create_dir(&public).unwrap();
    std::fs::create_dir(public.join("src")).unwrap();
    std::fs::write(
        public.join("Cargo.toml"),
        "[package]\nname = \"local-public\"\nversion = \"1.0.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    std::fs::write(public.join("src/lib.rs"), "pub fn value() -> u8 { 7 }\n").unwrap();
    let consumer = owner.path().join("consumer");
    std::fs::create_dir(&consumer).unwrap();
    std::fs::create_dir(consumer.join("src")).unwrap();
    let manifest = consumer.join("Cargo.toml");
    std::fs::write(
        &manifest,
        "[package]\nname = \"generated-consumer\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n[dependencies]\nlocal-public = { path = \"../local-public\" }\n",
    )
    .unwrap();
    std::fs::write(consumer.join("src/main.rs"), "fn main() {}\n").unwrap();
    let config = owner.path().join("offline.toml");
    std::fs::write(&config, "[net]\noffline = true\n").unwrap();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let toolchain = memcordon_ci::config::toolchains(repository).unwrap().stable;
    prepare_consumer_lock(owner.path(), &toolchain, &manifest, &config).unwrap();
    assert_eq!(std::fs::read_to_string(&selected).unwrap(), selected_bytes);
    let reconciled: toml::Value =
        toml::from_str(&std::fs::read_to_string(consumer.join("Cargo.lock")).unwrap()).unwrap();
    let packages = reconciled["package"].as_array().unwrap();
    assert!(packages.iter().any(|package| {
        package["name"].as_str() == Some("generated-consumer")
            && package["version"].as_str() == Some("0.0.0")
    }));
    assert!(packages.iter().any(|package| {
        package["name"].as_str() == Some("local-public")
            && package["version"].as_str() == Some("1.0.0")
            && package.get("source").is_none()
    }));
    verify_external_lock(&selected, &consumer.join("Cargo.lock")).unwrap();
}
