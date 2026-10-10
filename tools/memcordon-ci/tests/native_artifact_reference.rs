#[path = "../src/release/native_artifact_reference.rs"]
mod native_artifact_reference;

use std::path::Path;

#[test]
fn resolves_actual_boundary_artifact_reference_under_original_case() {
    let root = std::env::temp_dir().join("original-native-case");
    let prefix = "aarch64-unknown-linux-gnu/candidate-native/components/account-retirement";
    let reference = "aarch64-unknown-linux-gnu/candidate-native/components/account-retirement/boundary-journal.bin";
    assert_eq!(
        native_artifact_reference::resolve_case_reference(
            &root,
            prefix,
            reference,
            "boundary-journal.bin"
        )
        .unwrap(),
        root.join("boundary-journal.bin")
    );
}

#[test]
fn refuses_foreign_prefix_leaf_and_traversal_in_original_reference() {
    let root = std::env::temp_dir().join("original-native-case");
    for (prefix, reference, leaf) in [
        (
            "case",
            "foreign/boundary-journal.bin",
            "boundary-journal.bin",
        ),
        (
            "case",
            "case/boundary-reference.json",
            "boundary-journal.bin",
        ),
        ("case", "/case/boundary-journal.bin", "boundary-journal.bin"),
        (
            "case/..",
            "case/../boundary-journal.bin",
            "boundary-journal.bin",
        ),
        (
            "case",
            "case/../boundary-journal.bin",
            "boundary-journal.bin",
        ),
        (
            "case\\foreign",
            "case\\foreign/boundary-journal.bin",
            "boundary-journal.bin",
        ),
        ("case", "case/../foreign", "../foreign"),
    ] {
        assert!(
            native_artifact_reference::resolve_case_reference(&root, prefix, reference, leaf)
                .is_err()
        );
    }
    assert!(
        native_artifact_reference::resolve_case_reference(
            Path::new("relative"),
            "case",
            "case/boundary-journal.bin",
            "boundary-journal.bin"
        )
        .is_err()
    );
}
