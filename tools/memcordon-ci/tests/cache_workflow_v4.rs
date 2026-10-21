//! Historical v4 workflow tests now exercise the typed producer contract.
use memcordon_ci::{config, policy, workflow_definitions};
use std::path::Path;

fn public_source_save(job: &serde_yaml::Value, step: &serde_yaml::Value) -> bool {
    job.as_str() == Some("source-seed") && step["id"].as_str() == Some("public-source-seed-save")
}

#[test]
fn actual_workflows_use_typed_ready_output_transfers() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let configuration = config::policy(&root).unwrap();
    let mut saves = 0;
    let mut source_saves = 0;
    for file in workflow_definitions::FILES {
        let bytes = std::fs::read(root.join(".github/workflows").join(file)).unwrap();
        let document: serde_yaml::Value = serde_yaml::from_slice(&bytes).unwrap();
        workflow_definitions::validate_semantics(&document).unwrap();
        policy::validate_workflow_bytes(
            &root,
            &Path::new(".github/workflows").join(file),
            &bytes,
            &configuration,
        )
        .unwrap();
        for (name, job) in document["jobs"].as_mapping().unwrap() {
            let steps = job["steps"].as_sequence().unwrap();
            for (index, step) in steps.iter().enumerate() {
                if step["uses"]
                    .as_str()
                    .is_some_and(|u| u.starts_with("actions/cache/save@"))
                {
                    if public_source_save(name, step) {
                        let restore = steps[..index]
                            .iter()
                            .find(|candidate| {
                                candidate["id"].as_str() == Some("public-source-seed-restore")
                            })
                            .expect("source save must follow its restore");
                        assert_eq!(step["with"]["path"], restore["with"]["path"]);
                        assert_eq!(
                            step["with"]["key"].as_str(),
                            Some(
                                "${{ steps.public-source-seed-restore.outputs.cache-primary-key }}"
                            )
                        );
                        assert_eq!(step["continue-on-error"].as_bool(), Some(true));
                        source_saves += 1;
                        continue;
                    }
                    assert!(
                        step["if"]
                            .as_str()
                            .unwrap()
                            .starts_with("always() && steps.")
                    );
                    assert!(step["with"]["key"].as_str().unwrap().ends_with("-key }}"));
                    assert!(step["with"]["path"].as_str().unwrap().ends_with("-path }}"));
                    assert_eq!(step["continue-on-error"].as_bool(), Some(true));
                    saves += 1;
                }
            }
        }
    }
    assert_eq!(source_saves, workflow_definitions::FILES.len());
    assert!(saves > 50);
}

#[test]
fn transfer_identity_path_and_failure_guards_are_independently_enforced() {
    for file in workflow_definitions::FILES {
        let document = workflow_definitions::definition(file).unwrap();
        let (name, index) = document["jobs"]
            .as_mapping()
            .unwrap()
            .iter()
            .find_map(|(name, job)| {
                job["steps"]
                    .as_sequence()?
                    .iter()
                    .position(|s| {
                        s["uses"]
                            .as_str()
                            .is_some_and(|u| u.starts_with("actions/cache/save@"))
                            && !public_source_save(name, s)
                    })
                    .map(|i| (name.as_str().unwrap().to_owned(), i))
            })
            .unwrap();
        for mutation in [
            "path",
            "sentinel",
            "partial-key",
            "missing-always",
            "cache-hit",
        ] {
            let mut changed = document.clone();
            let step = &mut changed["jobs"][&name]["steps"][index];
            match mutation {
                "path" => step["with"]["path"] = "target".into(),
                "sentinel" => step["with"]["key"] = "sentinel-success".into(),
                "partial-key" => {
                    step["with"]["key"] = "${{ steps.absent.outputs.compiled-partial-key }}".into()
                }
                "missing-always" => {
                    step["if"] = step["if"]
                        .as_str()
                        .unwrap()
                        .strip_prefix("always() && ")
                        .unwrap()
                        .into()
                }
                "cache-hit" => step["if"] = "steps.service.outputs.cache-hit == 'true'".into(),
                _ => unreachable!(),
            }
            assert!(
                workflow_definitions::validate_semantics(&changed).is_err(),
                "{file}: {mutation}"
            );
        }
        let source_steps = document["jobs"]["source-seed"]["steps"]
            .as_sequence()
            .unwrap();
        let source_save = source_steps
            .iter()
            .position(|step| step["id"].as_str() == Some("public-source-seed-save"))
            .unwrap();
        for field in ["path", "key"] {
            let mut changed = document.clone();
            changed["jobs"]["source-seed"]["steps"][source_save]["with"][field] = "target".into();
            let error = workflow_definitions::validate_semantics(&changed).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("source acquisition must be independent with finite event ownership"),
                "{file}: source {field}: {error}"
            );
        }
    }
}
