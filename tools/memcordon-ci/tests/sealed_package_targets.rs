const PACKAGE_SELECTORS: &str =
    include_str!("../../../crates/memcordon-sealed-agent/tests/linux_package.rs");

#[test]
fn installed_provider_package_selectors_use_provider_visible_targets() {
    for forbidden in [
        "CARGO_BIN_EXE",
        "CARGO_MANIFEST_DIR",
        "target/ci/",
        "target/debug/",
        "StagedFixture",
        "support::fixture",
    ] {
        assert!(
            !PACKAGE_SELECTORS.contains(forbidden),
            "installed-provider package selectors must not use workspace target {forbidden}"
        );
    }
    assert!(PACKAGE_SELECTORS.contains("memcordon_core::CommandSpec::new(\"/usr/bin/true\")"));
}
