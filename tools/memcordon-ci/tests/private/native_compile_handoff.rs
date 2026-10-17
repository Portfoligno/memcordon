use super::*;

#[test]
fn later_phase_requires_exact_selected_product_bytes_and_distribution() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let selected = BuildSourceIdentity::Working {
        version: semver::Version::new(0, 1, 0),
        commit: "abcdef".into(),
    };
    let distribution = TargetDistribution {
        target: "x86_64-apple-darwin".into(),
        features: vec![],
        binaries: vec!["memcordon".into()],
        units: vec![],
    };
    let product = root.join("target/ci-build/product/x86_64-apple-darwin/release/memcordon");
    fs::create_dir_all(product.parent().unwrap()).unwrap();
    // A modeled header exercises byte/path handoff validation, not native execution.
    let image = [0xcf, 0xfa, 0xed, 0xfe, 7, 0, 0, 1];
    fs::write(&product, image).unwrap();
    fs::create_dir_all(root.join("target/ci-session")).unwrap();
    assert!(verify_product_inputs(root, &selected, &distribution).is_err());
    retain_product_inputs(root, &selected, &distribution).unwrap();
    verify_product_inputs(root, &selected, &distribution).unwrap();
    let mut changed = distribution.clone();
    changed.features.push("changed".into());
    assert!(verify_product_inputs(root, &selected, &changed).is_err());
    let mut altered = image.to_vec();
    altered.push(0);
    fs::write(&product, altered).unwrap();
    assert!(verify_product_inputs(root, &selected, &distribution).is_err());
    fs::remove_file(&product).unwrap();
    assert!(verify_product_inputs(root, &selected, &distribution).is_err());
}

#[test]
fn original_deadline_begin_and_resume_require_both_uncached_records() {
    use crate::release::native_component_harness::{begin_original_deadline, original_deadline};
    let root = tempfile::tempdir().unwrap();
    let selected = BuildSourceIdentity::Working {
        version: semver::Version::new(0, 1, 0),
        commit: "abcdef".into(),
    };
    assert!(original_deadline(root.path(), &selected, "host").is_err());
    begin_original_deadline(root.path(), &selected, "host").unwrap();
    original_deadline(root.path(), &selected, "host").unwrap();
    assert!(original_deadline(root.path(), &selected, "other-host").is_err());
    fs::remove_file(root.path().join(".release/native-operation-deadline.json")).unwrap();
    assert!(original_deadline(root.path(), &selected, "host").is_err());
    assert!(
        !root
            .path()
            .join(".release/native-operation-deadline.json")
            .exists()
    );
}
