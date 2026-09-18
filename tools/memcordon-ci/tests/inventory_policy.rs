use memcordon_ci::policy::validate_rust_policy_bytes;
use std::path::Path;

#[test]
fn inventory_subprocess_and_environment_boundaries_follow_repository_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for relative in [
        "tools/ci-bootstrap-windows.rs",
        "tools/ci-bounded-command.rs",
        "tools/ci-content-sha256.rs",
        "tools/ci-process-usage.rs",
        "tools/ci-inventory-trace.rs",
        "tools/ci-inventory-trace-windows.rs",
        "tools/ci-trace-volume.rs",
        "tools/memcordon-ci/tests/bootstrap_trace.rs",
        "tools/memcordon-ci/tests/bootstrap_usage.rs",
        "tools/memcordon-ci/src/inventory_benchmark.rs",
        "tools/memcordon-ci/src/inventory_profile.rs",
        "tools/memcordon-ci/src/inventory_observation.rs",
        "tools/memcordon-ci/src/inventory_report.rs",
        "tools/memcordon-ci/src/inventory_pipeline.rs",
        "tools/memcordon-ci/src/inventory_native.rs",
        "tools/memcordon-ci/src/native_profile.rs",
        "tools/memcordon-ci/src/native_profile",
        "crates/memcordon-platform/src/test_support/windows_trace_volume.rs",
    ] {
        for entry in walkdir::WalkDir::new(root.join(relative)) {
            let entry = entry.unwrap();
            if entry.file_type().is_file() {
                let path = entry.path().strip_prefix(&root).unwrap();
                validate_rust_policy_bytes(path, &std::fs::read(entry.path()).unwrap())
                    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            }
        }
    }
}
