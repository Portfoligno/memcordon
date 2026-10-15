use memcordon_ci::{config, policy};
use std::path::Path;

#[test]
fn real_workflows_reject_mixed_family_population_home_and_order_mutations() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    for file in [
        "ci.yml",
        "release.yml",
        "deep-ci.yml",
        "backend-certification.yml",
    ] {
        let relative = Path::new(".github/workflows").join(file);
        let source = std::fs::read_to_string(root.join(&relative)).unwrap();
        policy::validate_workflow_bytes(&root, &relative, source.as_bytes(), &configuration)
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        for (from, to) in [
            (
                "steps.workspace-fetch.outputs.workspace-downloads-populated == 'true'",
                "steps.workspace-downloads.outputs.cache-hit == 'true'",
            ),
            (
                "steps.workspace-download-save-context.outputs.source-key == steps.workspace-fetch.outputs.workspace-downloads-key",
                "steps.workspace-download-save-context.outputs.source-key == steps.workspace-download-context.outputs.source-key",
            ),
            (
                "steps.workspace-download-context.outputs.bootstrap-home-matches == 'true'",
                "true",
            ),
            (
                "id: workspace-download-context",
                "id: misplaced-download-context",
            ),
            ("source-restore-prefix", "product-restore-prefix"),
        ] {
            assert!(source.contains(from), "{file} fixture lacks {from}");
            let changed = source.replacen(from, to, 1);
            assert!(
                policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    changed.as_bytes(),
                    &configuration
                )
                .is_err(),
                "{file} accepted {from} -> {to}"
            );
        }
        if file == "ci.yml" {
            let changed = source.replace(
                "cargo clean --locked --offline --package memcordon-ci --target-dir target",
                "cargo clean --locked --offline --target-dir target",
            );
            assert!(
                policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    changed.as_bytes(),
                    &configuration
                )
                .is_err()
            );
        }
    }
}
