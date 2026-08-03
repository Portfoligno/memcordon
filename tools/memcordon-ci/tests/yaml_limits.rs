use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn workflow_yaml_size_limit_is_enforced_before_deserialization() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let oversized = vec![b' '; policy::MAXIMUM_YAML_BYTES.saturating_add(1)];
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        &oversized,
        &repository_policy,
    )
    .expect_err("oversized workflow YAML must be rejected");
    assert!(
        error
            .to_string()
            .contains("YAML input exceeds configured size policy"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn workflow_yaml_depth_limit_is_enforced_after_deserialization() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let nested_depth = policy::MAXIMUM_YAML_DEPTH.saturating_add(1);
    let nested = format!(
        "{}null{}\n",
        "[".repeat(nested_depth),
        "]".repeat(nested_depth)
    );
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        nested.as_bytes(),
        &repository_policy,
    )
    .expect_err("deeply nested workflow YAML must be rejected");
    assert!(
        error
            .to_string()
            .contains("YAML nesting exceeds configured depth policy"),
        "unexpected policy error: {error}"
    );
}
