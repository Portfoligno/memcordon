#[path = "../src/stress_artifact_inventory.rs"]
mod inventory;
use std::collections::BTreeSet;

fn names(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|name| (*name).into()).collect()
}

#[test]
fn strict_coverage_reports_sorted_expected_actual_missing_and_unexpected() {
    let expected = names(&["stress-packages-linux-x64", "stress-lifecycle-macos-arm64"]);
    let actual = names(&["stress-unexpected", "stress-packages-linux-x64"]);
    assert!(inventory::difference(&expected, &expected, 5).is_none());
    let error = inventory::difference(&expected, &actual, 5).unwrap();
    assert!(error.starts_with("stress artifact inventory differs from selected phases"));
    assert!(error.contains("expected=[count=2; names(prefix,omitted_bytes)=[(\"stress-lifecycle-macos-arm64\", 0), (\"stress-packages-linux-x64\", 0)]"));
    assert!(error.contains("actual=[count=2; names(prefix,omitted_bytes)=[(\"stress-packages-linux-x64\", 0), (\"stress-unexpected\", 0)]"));
    assert!(error.contains(
        "missing=[count=1; names(prefix,omitted_bytes)=[(\"stress-lifecycle-macos-arm64\", 0)]"
    ));
    assert!(
        error.contains(
            "unexpected=[count=1; names(prefix,omitted_bytes)=[(\"stress-unexpected\", 0)]"
        )
    );
    assert_eq!(inventory::difference(&expected, &actual, 5), Some(error));
}

#[test]
fn arbitrary_names_are_bounded_without_hiding_exact_mismatch_counts() {
    let seed = "界\n";
    let long = seed.repeat(4096 / seed.len() + 1);
    let actual = (0..100)
        .map(|ordinal| format!("{ordinal:03}-{long}"))
        .collect();
    let error = inventory::difference(&BTreeSet::new(), &actual, 5).unwrap();
    assert!(error.contains("actual=[count=100;"));
    assert!(error.contains("unexpected=[count=100;"));
    assert!(error.contains("omitted_names=85"));
    assert!(error.len() < 16 * 1024);
    assert!(
        inventory::difference(&BTreeSet::new(), &actual, 0)
            .unwrap()
            .contains("omitted_names=100")
    );
}
