use std::collections::BTreeMap;

use memcordon_ci::{config::WorkspacePolicy, policy};
use semver::Version;

fn version(value: &str) -> Version {
    Version::parse(value).expect("version fixture should parse")
}

fn workspace_policy() -> WorkspacePolicy {
    WorkspacePolicy {
        production_packages: vec!["production".to_owned()],
        ci_packages: vec!["tool".to_owned()],
        ci_package_rust_versions: BTreeMap::from([("tool".to_owned(), version("1.88.0"))]),
        publish_packages: vec!["production".to_owned()],
        non_publish_packages: vec!["tool".to_owned()],
    }
}

#[test]
fn package_rust_versions_match_the_split_msrv_policy() {
    let actual = BTreeMap::from([
        ("production".to_owned(), version("1.85.0")),
        ("tool".to_owned(), version("1.88.0")),
    ]);
    policy::validate_package_rust_versions(&actual, &workspace_policy(), &version("1.85.0"))
        .expect("split package Rust versions should pass");
}

#[test]
fn package_rust_version_drift_is_rejected() {
    let actual = BTreeMap::from([
        ("production".to_owned(), version("1.85.0")),
        ("tool".to_owned(), version("1.87.0")),
    ]);
    let error =
        policy::validate_package_rust_versions(&actual, &workspace_policy(), &version("1.85.0"))
            .expect_err("CI tool Rust-version drift must fail");
    assert!(
        error
            .to_string()
            .contains("CI package rust-version differs"),
        "unexpected policy error: {error}"
    );
}
