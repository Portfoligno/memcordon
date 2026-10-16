use memcordon_ci::{config, policy};
use std::path::Path;

#[test]
fn index_snapshots_are_independent_of_complete_archive_hits() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut selected = 0;
    for file in ["ci.yml", "deep-ci.yml", "release.yml"] {
        let value: serde_yaml::Value = serde_yaml::from_str(
            &std::fs::read_to_string(root.join(".github/workflows").join(file)).unwrap(),
        )
        .unwrap();
        for job in value["jobs"].as_mapping().unwrap().values() {
            let Some(steps) = job["steps"].as_sequence() else {
                continue;
            };
            for step in steps {
                if step["id"].as_str() == Some("index-snapshot-restore") {
                    assert_eq!(
                        step["if"].as_str(),
                        Some("steps.index-snapshot-context.outputs.seed-lookup-key != ''")
                    );
                    selected += 1;
                }
                if step["id"].as_str() == Some("archive-seed-restore") {
                    assert_eq!(
                        step["if"].as_str(),
                        Some(
                            "steps.archive-seed-context.outputs.seed-lookup-key != '' && steps.workspace-downloads.outputs.cache-hit != 'true'"
                        )
                    );
                }
            }
        }
    }
    assert_eq!(selected, 7);
}

#[test]
fn checkpoint_and_sysroot_workflows_require_real_work_settlement_and_content_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    for (file, mutations) in [
        (
            "ci.yml",
            vec![
                ("suite native-compile", "suite native"),
                ("suite native-execute", "suite native"),
                (
                    "steps.native-compile.outputs.cache-quiescent == 'true'",
                    "steps.native-run.outputs.cache-quiescent == 'true'",
                ),
                (
                    "steps.native-build-snapshot.outputs.input-key == steps.compiled-context.outputs.product-key",
                    "true",
                ),
                ("lookup-only: true", "lookup-only: false"),
            ],
        ),
        (
            "deep-ci.yml",
            vec![
                ("ci prepare-miri-sysroot", "ci prepare-miri-components"),
                (
                    "steps.miri-sysroot-save-context.outputs.sysroot-key == steps.miri-sysroot-context.outputs.sysroot-key",
                    "true",
                ),
                ("suite fuzz-compile-quarter-one", "suite fuzz-quarter-one"),
                ("suite fuzz-execute-quarter-one", "suite fuzz-quarter-one"),
                (
                    "(steps.fuzz-one-compile.outputs.cache-quiescent || steps.fuzz-one-compile-diagnostic.outputs.cache-quiescent) == 'true'",
                    "true",
                ),
            ],
        ),
    ] {
        let relative = Path::new(".github/workflows").join(file);
        let source = std::fs::read_to_string(root.join(&relative)).unwrap();
        policy::validate_workflow_bytes(&root, &relative, source.as_bytes(), &configuration)
            .unwrap_or_else(|error| panic!("{file}: {error}"));
        for (from, to) in mutations {
            assert!(
                source.contains(from),
                "missing mutation input {file}: {from}"
            );
            let changed = source.replacen(from, to, 1);
            assert!(
                policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    changed.as_bytes(),
                    &configuration
                )
                .is_err(),
                "accepted mutation {file}: {from}"
            );
        }
    }
}
