use std::path::Path;

#[test]
fn retired_hosted_worker_is_not_exported_or_available() {
    let retired_source = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/release_hosted_worker.rs");
    assert!(
        !retired_source.exists(),
        "the V1 hosted worker must not remain an accepted CI module"
    );
    assert!(
        !include_str!("../src/lib.rs").contains("mod release_hosted_worker"),
        "the V1 hosted worker must not be exported"
    );
}

#[test]
fn retired_release_signing_helpers_are_not_exported_or_available() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = include_str!("../src/lib.rs");
    for module in ["release_hosted_publication", "release_hosted_reservation"] {
        assert!(
            !root.join(format!("src/{module}.rs")).exists(),
            "retired V3 signing helper {module} must not remain available"
        );
        assert!(
            !library.contains(&format!("mod {module}")),
            "retired V3 signing helper {module} must not be exported"
        );
    }
}

#[test]
fn retired_candidate_preflight_cycle_is_not_exported_or_available() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let library = include_str!("../src/lib.rs");
    for module in [
        "release_hosted_candidate_decision",
        "release_hosted_archive_preflight",
        "release_hosted_config",
    ] {
        assert!(
            !root.join(format!("src/{module}.rs")).exists(),
            "retired candidate/preflight module {module} must not remain available"
        );
        assert!(
            !library.contains(&format!("mod {module}")),
            "retired candidate/preflight module {module} must not be exported"
        );
    }
}
