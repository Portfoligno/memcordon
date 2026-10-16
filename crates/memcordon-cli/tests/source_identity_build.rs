#[path = "../build_support/source_identity.rs"]
mod source_identity;

use std::fs;
use tempfile::tempdir;

const CACHE_TAG: &str = "Signature: 8a477f597d28d172789f06886806bc55\n";

#[test]
fn optional_metadata_watches_preserve_creation_without_observing_outputs() {
    let fixture = tempdir().unwrap();
    let source = fixture.path().join("source");
    let target = fixture.path().join("target");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&target).unwrap();
    let target = target.canonicalize().unwrap();
    let missing = source.join("nested").join("metadata.json");
    assert_eq!(
        source_identity::watch_path(&missing, Some(&target)),
        source.canonicalize().unwrap()
    );
    assert_eq!(source_identity::watch_path(&missing, None), missing);
    assert_eq!(
        source_identity::watch_path(&missing, Some(&source)),
        missing
    );
    let nested_output = source.join("target");
    fs::create_dir_all(&nested_output).unwrap();
    assert_eq!(
        source_identity::watch_path(&missing, Some(&nested_output)),
        missing
    );
    let generated = target.join("generated.json");
    assert_eq!(
        source_identity::watch_path(&generated, Some(&target)),
        generated
    );
    let existing = source.join("metadata.json");
    fs::write(&existing, b"actual metadata").unwrap();
    assert_eq!(
        source_identity::watch_path(&existing, Some(&target)),
        existing
    );
}

#[test]
fn output_boundary_requires_a_genuine_tag_and_uses_outermost_tag() {
    let fixture = tempdir().unwrap();
    let target = fixture.path().join("target");
    let inner = target.join("nested");
    let output = inner
        .join("release")
        .join("build")
        .join("package")
        .join("out");
    fs::create_dir_all(&output).unwrap();
    assert_eq!(source_identity::output_root(&output), None);
    fs::write(target.join("CACHEDIR.TAG"), b"unrelated marker\n").unwrap();
    assert_eq!(source_identity::output_root(&output), None);
    fs::remove_file(target.join("CACHEDIR.TAG")).unwrap();
    fs::write(inner.join("CACHEDIR.TAG"), CACHE_TAG).unwrap();
    assert_eq!(
        source_identity::output_root(&output),
        Some(inner.canonicalize().unwrap())
    );
    fs::write(target.join("CACHEDIR.TAG"), CACHE_TAG).unwrap();
    assert_eq!(
        source_identity::output_root(&output),
        Some(target.canonicalize().unwrap())
    );
}

#[cfg(unix)]
#[test]
fn symlinked_watch_trees_keep_the_conservative_missing_file_watch() {
    let fixture = tempdir().unwrap();
    let source = fixture.path().join("source");
    let target = fixture.path().join("target");
    fs::create_dir_all(&source).unwrap();
    fs::create_dir_all(&target).unwrap();
    std::os::unix::fs::symlink(&target, source.join("generated-alias")).unwrap();
    let missing = source.join("metadata.json");
    assert_eq!(
        source_identity::watch_path(&missing, Some(&target)),
        missing
    );
}
