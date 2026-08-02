#![no_main]

use std::path::Path;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("fuzz crate is inside repository root");
    let policy = memcordon_ci::config::parse_policy(include_bytes!("../../ci/policy.toml"))
        .expect("checked-in policy is valid");
    let _ = memcordon_ci::policy::validate_workflow_bytes(
        root,
        Path::new(".github/workflows/ci.yml"),
        data,
        &policy,
    );
});
