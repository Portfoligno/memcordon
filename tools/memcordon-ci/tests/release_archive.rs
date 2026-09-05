use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};

use flate2::Compression;
use flate2::write::GzEncoder;
use memcordon_ci::config;
use memcordon_ci::release_archive::{
    NATIVE_ARCHIVE_STATIC_PATHS, REVIEWED_CARGO_BINARIES, cargo_install_inventory,
    configured_default_cargo_binaries, validate_markdown_documents,
    validate_memcordon_crate_distribution,
};
use tar::Builder;
use tar::Header;
use tempfile::TempDir;

const EXPECTED_STATIC_PATHS: &[&str] = &[
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/linux-sealed-certification.md",
    "docs/reference.md",
    "docs/sealed-provider.md",
    "docs/sealed-supervision.md",
    "docs/assets/banner.png",
    "docs/assets/key-guarantees.png",
    "spec/sealed-linux-v2.md",
    "spec/sealed-provider-protocol-v2.md",
    "spec/sealed-windows-provider-v1.md",
    "spec/sealed-windows-v2.md",
];

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

fn archive_documents() -> BTreeMap<PathBuf, Vec<u8>> {
    let root = repository_root();
    NATIVE_ARCHIVE_STATIC_PATHS
        .iter()
        .map(|relative| {
            let relative = PathBuf::from(*relative);
            let bytes = fs::read(root.join(&relative)).unwrap_or_else(|error| {
                panic!("archive member {relative:?} should be readable: {error}")
            });
            (relative, bytes)
        })
        .collect()
}

fn canonical_release() -> config::Release {
    toml::from_str(include_str!("../../../ci/release.toml"))
        .expect("canonical release configuration should parse")
}

fn reviewed_manifest(test_fixture_features: &str) -> String {
    let mut manifest = String::from("[package]\nname = \"memcordon\"\nautobins = false\n");
    for binary in REVIEWED_CARGO_BINARIES {
        manifest.push_str("\n[[bin]]\n");
        manifest.push_str(&format!("name = \"{}\"\n", binary.name));
        manifest.push_str(&format!("path = \"{}\"\n", binary.path));
        if let Some(doc) = binary.doc {
            manifest.push_str(&format!("doc = {doc}\n"));
        }
        if let Some(features) = binary.required_features {
            if binary.name == "memcordon-test-fixture" {
                manifest.push_str(&format!("required-features = {test_fixture_features}\n"));
            } else {
                manifest.push_str(&format!("required-features = {features:?}\n"));
            }
        }
    }
    manifest
}

fn write_crate_fixture(manifest: &str, path: &Path) {
    let file = File::create(path).expect("crate fixture should be writable");
    let mut members: Vec<(&str, Vec<u8>)> = Vec::from([
        ("Cargo.toml.orig", manifest.as_bytes().to_vec()),
        ("Cargo.lock", Vec::new()),
        ("src/lib.rs", Vec::new()),
        ("src/main.rs", Vec::new()),
        ("src/bin/memcordon-sealed-agent/main.rs", Vec::new()),
        ("src/bin/memcordon-sealed-agent/package.rs", Vec::new()),
        ("src/bin/memcordon-sealed-agent/protocol.rs", Vec::new()),
        ("src/bin/memcordon-sealed-agent/linux/mod.rs", Vec::new()),
        ("src/bin/memcordon-sealed-agent/windows/mod.rs", Vec::new()),
        (
            "src/bin/memcordon-sealed-agent/windows/control_service.rs",
            Vec::new(),
        ),
        (
            "src/bin/memcordon-sealed-agent/windows/launcher_service.rs",
            Vec::new(),
        ),
        (
            "src/bin/memcordon-sealed-agent/windows/package.rs",
            Vec::new(),
        ),
        (
            "src/bin/memcordon-sealed-agent/windows/qualification.rs",
            Vec::new(),
        ),
        ("src/bin/memcordon-target-desktop-bootstrap.rs", Vec::new()),
        ("src/bin/memcordon-session-broker.rs", Vec::new()),
        ("src/bin/memcordon-test-fixture.rs", Vec::new()),
        ("src/bin/memcordon-sealed-test-fixture.rs", Vec::new()),
        ("src/bin/memcordon-embedding-fixture.rs", Vec::new()),
    ]);
    members.push(("Cargo.toml", manifest.as_bytes().to_vec()));
    let mut archive = Builder::new(GzEncoder::new(&file, Compression::default()));
    for (member, bytes) in members {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                format!("memcordon-0.0.0/{member}"),
                bytes.as_slice(),
            )
            .expect("crate fixture member should be writable");
    }
    archive
        .into_inner()
        .expect("crate fixture tar should finalize")
        .finish()
        .expect("crate fixture gzip stream should finalize");
}

fn assert_missing_document_link(
    omitted: &Path,
    source: &Path,
    target_file_name: &str,
    expectation: &str,
) {
    let mut documents = archive_documents();
    assert!(
        documents.remove(omitted).is_some(),
        "archive fixture should contain omitted document {omitted:?}"
    );
    let error = validate_markdown_documents(&documents).expect_err(expectation);
    let target = source.with_file_name(target_file_name);
    assert_eq!(
        error.to_string(),
        format!("Markdown link target is absent from package or archive: {source:?} -> {target:?}")
    );
}

#[test]
fn native_archive_markdown_links_resolve_within_member_set() {
    assert_eq!(NATIVE_ARCHIVE_STATIC_PATHS, EXPECTED_STATIC_PATHS);
    let documents = archive_documents();
    validate_markdown_documents(&documents)
        .expect("native archive Markdown links should resolve within the member set");
}

#[test]
fn native_archive_markdown_links_reject_each_missing_sealed_document() {
    assert_missing_document_link(
        Path::new("docs/sealed-supervision.md"),
        Path::new("docs/reference.md"),
        "sealed-supervision.md",
        "reference link to missing sealed supervision document must fail",
    );
    assert_missing_document_link(
        Path::new("docs/sealed-provider.md"),
        Path::new("docs/linux-sealed-certification.md"),
        "sealed-provider.md",
        "certification link to missing sealed provider document must fail",
    );
}

#[test]
fn memcordon_crate_distribution_accepts_the_reviewed_inventory() {
    let defaults = configured_default_cargo_binaries(&canonical_release())
        .expect("canonical release defaults should validate");
    let temporary = TempDir::new().expect("crate fixture directory should be created");
    let archive = temporary.path().join("memcordon-0.0.0.crate");
    write_crate_fixture(&reviewed_manifest(r#"["test-fixtures"]"#), &archive);

    validate_memcordon_crate_distribution(&archive, &defaults)
        .expect("reviewed crate inventory should validate");
}

#[test]
fn memcordon_crate_distribution_rejects_the_stale_two_default_inventory() {
    let stale_manifest = concat!(
        "[package]\n",
        "name = \"memcordon\"\n",
        "autobins = false\n",
        "\n[[bin]]\n",
        "name = \"memcordon\"\n",
        "path = \"src/main.rs\"\n",
        "\n[[bin]]\n",
        "name = \"memcordon-sealed-agent\"\n",
        "path = \"src/bin/memcordon-sealed-agent/main.rs\"\n",
        "doc = false\n",
        "\n[[bin]]\n",
        "name = \"memcordon-test-fixture\"\n",
        "path = \"src/bin/memcordon-test-fixture.rs\"\n",
        "required-features = [\"test-fixtures\"]\n",
        "\n[[bin]]\n",
        "name = \"memcordon-sealed-test-fixture\"\n",
        "path = \"src/bin/memcordon-sealed-test-fixture.rs\"\n",
        "required-features = [\"test-support\"]\n",
        "\n[[bin]]\n",
        "name = \"memcordon-embedding-fixture\"\n",
        "path = \"src/bin/memcordon-embedding-fixture.rs\"\n",
        "required-features = [\"test-fixtures\"]\n",
    );
    let defaults = configured_default_cargo_binaries(&canonical_release())
        .expect("canonical release defaults should validate");
    let temporary = TempDir::new().expect("crate fixture directory should be created");
    let archive = temporary.path().join("memcordon-0.0.0.crate");
    write_crate_fixture(stale_manifest, &archive);

    let error = validate_memcordon_crate_distribution(&archive, &defaults)
        .expect_err("stale two-default crate inventory should fail");
    assert_eq!(
        error.to_string(),
        "memcordon crate binary inventory differs from the exact reviewed set"
    );
}

#[test]
fn memcordon_crate_distribution_rejects_malformed_feature_gating() {
    let defaults = configured_default_cargo_binaries(&canonical_release())
        .expect("canonical release defaults should validate");
    let temporary = TempDir::new().expect("crate fixture directory should be created");
    let archive = temporary.path().join("memcordon-0.0.0.crate");
    write_crate_fixture(&reviewed_manifest(r#""test-fixtures""#), &archive);

    let error = validate_memcordon_crate_distribution(&archive, &defaults)
        .expect_err("malformed binary feature gating should fail");
    assert_eq!(
        error.to_string(),
        "binary required-features must be an array"
    );
}

#[test]
fn reviewed_cargo_inventory_matches_the_workspace_manifest() {
    let root = repository_root();
    let manifest_text =
        fs::read_to_string(root.join("crates").join("memcordon-cli").join("Cargo.toml"))
            .expect("workspace memcordon manifest should be readable");
    let manifest: toml::Value =
        toml::from_str(&manifest_text).expect("workspace memcordon manifest should parse");
    assert_eq!(
        manifest
            .get("package")
            .and_then(|value| value.get("autobins"))
            .and_then(toml::Value::as_bool),
        Some(false)
    );
    let bins = manifest
        .get("bin")
        .and_then(toml::Value::as_array)
        .expect("workspace memcordon manifest should have explicit binaries");
    let actual = bins
        .iter()
        .map(|bin| {
            (
                bin.get("name").and_then(toml::Value::as_str),
                bin.get("path").and_then(toml::Value::as_str),
                bin.get("doc").and_then(toml::Value::as_bool),
                bin.get("required-features")
                    .and_then(toml::Value::as_array)
                    .and_then(|features| {
                        features
                            .iter()
                            .map(toml::Value::as_str)
                            .collect::<Option<Vec<_>>>()
                    }),
            )
        })
        .collect::<Vec<_>>();
    let expected = REVIEWED_CARGO_BINARIES
        .iter()
        .map(|binary| {
            (
                Some(binary.name),
                Some(binary.path),
                binary.doc,
                binary.required_features.map(|features| features.to_vec()),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn default_cargo_inventory_requires_structured_target_configuration() {
    let mut release = canonical_release();
    let linux_index = release
        .assets
        .target
        .iter()
        .position(|target| target.id == "linux-x64")
        .expect("linux target should exist");
    let windows_index = release
        .assets
        .target
        .iter()
        .position(|target| target.id == "windows-x64")
        .expect("windows target should exist");
    let union_before = release
        .assets
        .target
        .iter()
        .flat_map(|target| target.executable.iter())
        .map(|executable| executable.binary.clone())
        .collect::<BTreeSet<_>>();
    let mut moved = Vec::new();
    for name in [
        "memcordon-target-desktop-bootstrap",
        "memcordon-session-broker",
    ] {
        let windows = &mut release.assets.target[windows_index];
        let index = windows
            .executable
            .iter()
            .position(|executable| executable.binary == name)
            .expect("reviewed executable should be configured");
        moved.push(windows.executable.remove(index));
    }
    release.assets.target[linux_index]
        .executable
        .append(&mut moved);
    let union_after = release
        .assets
        .target
        .iter()
        .flat_map(|target| target.executable.iter())
        .map(|executable| executable.binary.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(union_after, union_before);

    let error = configured_default_cargo_binaries(&release)
        .expect_err("contradictory per-target inventory should fail");
    assert_eq!(
        error.to_string(),
        "release configuration identity is invalid"
    );
}

#[test]
fn packaged_and_public_cargo_installs_expect_the_four_default_binaries() {
    let defaults = configured_default_cargo_binaries(&canonical_release())
        .expect("canonical release defaults should validate");
    let expected_names = BTreeSet::from([
        "memcordon".to_owned(),
        "memcordon-sealed-agent".to_owned(),
        "memcordon-target-desktop-bootstrap".to_owned(),
        "memcordon-session-broker".to_owned(),
    ]);
    assert_eq!(defaults, expected_names);
    let expected = expected_names
        .iter()
        .map(|name| {
            let mut binary = OsString::from(name);
            if cfg!(windows) {
                binary.push(".exe");
            }
            binary
        })
        .collect::<BTreeSet<_>>();
    let packaged = cargo_install_inventory(&defaults);
    let public = cargo_install_inventory(&defaults);
    assert_eq!(packaged, expected);
    assert_eq!(public, expected);
}

#[test]
fn markdown_validation_accepts_packaged_relative_targets_and_anchors() {
    let documents = BTreeMap::from([
        (
            PathBuf::from("README.md"),
            b"# Package\n\n[Top](#package)\n[Details](docs/reference.md#exact-contract)\n".to_vec(),
        ),
        (
            PathBuf::from("docs/reference.md"),
            b"# Reference\n\n## Exact contract\n".to_vec(),
        ),
    ]);
    validate_markdown_documents(&documents)
        .expect("packaged relative target and anchor should validate");
}

#[test]
fn markdown_validation_rejects_missing_packaged_target_or_anchor() {
    let missing_target = BTreeMap::from([(
        PathBuf::from("README.md"),
        b"# Package\n\n[Missing](docs/missing.md)\n".to_vec(),
    )]);
    assert!(validate_markdown_documents(&missing_target).is_err());

    let missing_anchor = BTreeMap::from([
        (
            PathBuf::from("README.md"),
            b"# Package\n\n[Missing](reference.md#missing)\n".to_vec(),
        ),
        (PathBuf::from("reference.md"), b"# Reference\n".to_vec()),
    ]);
    assert!(validate_markdown_documents(&missing_anchor).is_err());
}
