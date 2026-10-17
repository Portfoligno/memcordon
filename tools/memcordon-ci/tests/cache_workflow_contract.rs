use memcordon_ci::{config, policy, workflow_definitions};
use std::path::Path;

#[test]
fn publication_source_producer_really_compiles_before_adoption() {
    let document = workflow_definitions::definition("release.yml").unwrap();
    let steps = document["jobs"]["select"]["steps"].as_sequence().unwrap();
    let compile = steps
        .iter()
        .position(|s| {
            s["run"].as_str().is_some_and(|r| {
                r.contains("cargo build --locked --release ")
                    && r.contains("--target-dir target/ci-driver-cold")
                    && r.ends_with("--bin memcordon-ci")
            })
        })
        .unwrap();
    let adoption = steps
        .iter()
        .position(|s| {
            s["run"]
                .as_str()
                .is_some_and(|r| r.ends_with(" ci driver-adopt-cold"))
        })
        .unwrap();
    assert!(compile < adoption);
    assert!(!steps.iter().any(|s| {
        s["run"]
            .as_str()
            .is_some_and(|r| r.ends_with(" ci driver-select"))
    }));
    let mut changed = document.clone();
    changed["jobs"]["select"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .remove(compile);
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    assert!(
        policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/release.yml"),
            serde_yaml::to_string(&changed).unwrap().as_bytes(),
            &config::policy(&root).unwrap()
        )
        .is_err()
    );
}

#[test]
fn source_and_compiler_transfer_classes_cannot_be_substituted() {
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
                            && s["with"]["key"]
                                .as_str()
                                .is_some_and(|k| k.contains(".outputs.source-complete-key"))
                    })
                    .map(|i| (name.as_str().unwrap().to_owned(), i))
            })
            .unwrap();
        for mutation in ["owner", "class", "broad-path", "population"] {
            let mut changed = document.clone();
            let step = &mut changed["jobs"][&name]["steps"][index];
            match mutation {
                "owner" => {
                    step["with"]["key"] = step["with"]["key"]
                        .as_str()
                        .unwrap()
                        .replace("steps.", "steps.absent-")
                        .into()
                }
                "class" => {
                    step["with"]["key"] = step["with"]["key"]
                        .as_str()
                        .unwrap()
                        .replace("source-complete-key", "compiled-complete-key")
                        .into()
                }
                "broad-path" => step["with"]["path"] = "~/.cargo".into(),
                "population" => {
                    step["if"] =
                        "always() && steps.workspace-fetch.outputs.cache-populated == 'true'".into()
                }
                _ => unreachable!(),
            }
            assert!(
                workflow_definitions::validate_semantics(&changed).is_err(),
                "{file}: {mutation}"
            );
        }
    }
}
