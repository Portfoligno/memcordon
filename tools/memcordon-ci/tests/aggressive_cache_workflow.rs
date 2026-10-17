use memcordon_ci::{config, policy, workflow_definitions};
use std::path::Path;

#[test]
fn index_snapshots_are_independent_of_complete_archive_hits() {
    let mut indexes = 0;
    let mut fetches = 0;
    for file in workflow_definitions::FILES {
        let document = workflow_definitions::definition(file).unwrap();
        for job in document["jobs"].as_mapping().unwrap().values() {
            for step in job["steps"].as_sequence().unwrap() {
                let run = step["run"].as_str().unwrap_or("");
                if run.ends_with(" ci segment workspace-fetch")
                    || run.ends_with(" ci segment fuzz-fetch")
                {
                    fetches += 1;
                }
                if step["id"]
                    .as_str()
                    .is_some_and(|id| id.ends_with("-index-partial-restore"))
                {
                    let guard = step["if"].as_str().unwrap();
                    assert!(guard.contains(".outputs.index-partial-restore == 'true'"));
                    assert!(!guard.contains("cache-hit"));
                    indexes += 1;
                }
            }
        }
    }
    assert!(fetches > 10);
    assert!(indexes >= fetches);
}

#[test]
fn checkpoint_and_sysroot_workflows_require_real_work_settlement_and_content_identity() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    for (file, mutations) in [
        (
            "ci.yml",
            vec![
                ("ci segment native-compile", "ci segment native"),
                ("ci segment native-execute", "ci segment native"),
                ("lookup-only: true", "lookup-only: false"),
            ],
        ),
        (
            "deep-ci.yml",
            vec![
                (
                    "ci segment miri-setup",
                    "ci segment prepare-miri-components",
                ),
                (
                    "ci segment fuzz-compile-quarter-one",
                    "ci segment fuzz-quarter-one",
                ),
                (
                    "ci segment fuzz-execute-quarter-one",
                    "ci segment fuzz-quarter-one",
                ),
                ("outputs.sysroot-key", "outputs.image-key"),
            ],
        ),
    ] {
        let relative = Path::new(".github/workflows").join(file);
        let source = std::fs::read_to_string(root.join(&relative)).unwrap();
        policy::validate_workflow_bytes(&root, &relative, source.as_bytes(), &configuration)
            .unwrap();
        for (from, to) in mutations {
            assert!(
                source.contains(from),
                "missing mutation target {file}: {from}"
            );
            assert!(
                policy::validate_workflow_bytes(
                    &root,
                    &relative,
                    source.replacen(from, to, 1).as_bytes(),
                    &configuration
                )
                .is_err(),
                "accepted mutation {file}: {from}"
            );
        }
    }
}
