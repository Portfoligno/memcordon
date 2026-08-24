use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use memcordon_ci::release_archive::{NATIVE_ARCHIVE_STATIC_PATHS, validate_markdown_documents};

const EXPECTED_STATIC_PATHS: &[&str] = &[
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "docs/reference.md",
    "docs/sealed-provider.md",
    "docs/sealed-supervision.md",
    "docs/assets/banner.png",
    "docs/assets/key-guarantees.png",
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
        Path::new("docs/sealed-supervision.md"),
        "sealed-provider.md",
        "transitive link to missing sealed provider document must fail",
    );
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
