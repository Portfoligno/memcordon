use memcordon_ci::{config, policy};
use std::path::Path;

#[test]
fn bootstrap_only_selection_requires_one_preceding_workspace_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    let relative = Path::new(".github/workflows/release.yml");
    let source = std::fs::read_to_string(root.join(relative)).unwrap();
    let document: serde_yaml::Value = serde_yaml::from_str(&source).unwrap();
    let steps = document["jobs"]["select"]["steps"].as_sequence().unwrap();
    let context = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("workspace-download-context"))
        .unwrap();
    let restore = steps
        .iter()
        .position(|step| step["id"].as_str() == Some("deps"))
        .unwrap();
    assert!(
        restore < context,
        "bootstrap restore must precede driver context"
    );
    assert!(
        steps.iter().all(|step| {
            step["id"].as_str() != Some("workspace-downloads")
                && !step["run"]
                    .as_str()
                    .is_some_and(|run| run.contains(" ci fetch-downloads "))
        }),
        "selection must remain independent of full workspace acquisition"
    );
    policy::validate_workflow_bytes(&root, relative, source.as_bytes(), &configuration).unwrap();

    for mutation in [
        "missing",
        "renamed",
        "after-save",
        "unrelated-command",
        "wrong-family",
        "duplicate-before-save",
        "duplicate-after-save",
    ] {
        let mut changed = document.clone();
        let steps = changed["jobs"]["select"]["steps"]
            .as_sequence_mut()
            .unwrap();
        match mutation {
            "missing" => {
                steps.remove(context);
            }
            "renamed" => steps[context]["id"] = "misplaced-download-context".into(),
            "after-save" => {
                let producer = steps.remove(context);
                steps.push(producer);
            }
            "unrelated-command" => {
                steps[context]["run"] =
                    "./target/ci/release/memcordon-ci release select-preparation".into();
            }
            "wrong-family" => {
                steps[context]["run"] =
                    "./target/ci/release/memcordon-ci ci download-cache-context --family fuzz"
                        .into();
            }
            "duplicate-before-save" => steps.insert(context, steps[context].clone()),
            "duplicate-after-save" => steps.push(steps[context].clone()),
            _ => unreachable!(),
        }
        let bytes = serde_yaml::to_string(&changed).unwrap();
        assert!(
            policy::validate_workflow_bytes(&root, relative, bytes.as_bytes(), &configuration)
                .is_err(),
            "bootstrap-only selection accepted {mutation} context ownership"
        );
    }
}

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
            let initializer = "cargo clean --locked --package memcordon-ci --target-dir target";
            assert!(source.contains(initializer));
            let changed = source.replace(initializer, "cargo clean --locked --target-dir target");
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
