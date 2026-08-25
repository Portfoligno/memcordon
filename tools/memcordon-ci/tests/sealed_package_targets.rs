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
    for required in [
        "assert_active_capability_caller_rejected(&execution)",
        "MCSEALED-PROVIDER-REJECTION",
        "MCSEALED-CALLER-ENVELOPE-CAPTURE",
        "MCSEALED-CREDENTIAL-TRANSITION-POLICY: callers with active capability sets are unsupported",
        "BoundarySetupPhase::RequestValidation",
        "assert!(!rejection.target_created)",
        "assert!(!rejection.target_released)",
        "assert!(!rejection.cleanup_attempted)",
    ] {
        assert!(
            PACKAGE_SELECTORS.contains(required),
            "privileged package selector omitted active-capability rejection proof {required}"
        );
    }
}
