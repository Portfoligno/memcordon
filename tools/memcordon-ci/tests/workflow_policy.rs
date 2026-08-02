use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn action_input_boolean_value_selection_is_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let explicit = r#"      - name: Check out pushed tag
        if: github.event_name == 'push'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ github.ref }}
          fetch-depth: 0
          persist-credentials: false
      - name: Check out dispatched tag
        if: github.event_name == 'workflow_dispatch'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ inputs.tag }}
          fetch-depth: 0
          persist-credentials: false
"#;
    let coalesced = r#"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          ref: ${{ inputs.tag || github.ref }}
          fetch-depth: 0
          persist-credentials: false
"#;
    let invalid = exact.replacen(explicit, coalesced, 1);
    assert_ne!(invalid, exact, "checkout fixture mutation must apply");

    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("Boolean value selection in an action input must be rejected");
    assert!(
        error
            .to_string()
            .contains("workflow action input may not select values with Boolean operators"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn named_github_environments_are_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/release.yml").replace("\r\n", "\n");
    let invalid = exact.replacen(
        "    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n",
        "    runs-on: ubuntu-24.04\n    environment: release\n    timeout-minutes: 60\n",
        1,
    );
    assert_ne!(invalid, exact, "environment fixture mutation must apply");

    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("named GitHub environments must be rejected");
    assert!(
        error
            .to_string()
            .contains("named GitHub environments are forbidden"),
        "unexpected policy error: {error}"
    );
}
