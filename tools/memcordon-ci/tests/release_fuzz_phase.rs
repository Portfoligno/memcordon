use memcordon_ci::workflow_definitions;
use serde_yaml::Value;

#[test]
fn release_fuzz_requires_exact_selected_setup_before_every_unchanged_shard() {
    let workflow = workflow_definitions::definition("release.yml").unwrap();
    assert_eq!(
        workflow["jobs"]["fuzz"]["strategy"]["matrix"]["shard"]
            .as_sequence()
            .unwrap()
            .len(),
        4
    );
    let steps = workflow["jobs"]["fuzz"]["steps"].as_sequence().unwrap();
    assert!(!steps.iter().any(|step| {
        step["run"]
            .as_str()
            .is_some_and(|run| run.ends_with(" ci segment prepare-fuzz"))
    }));
    for mutation in [
        "missing-setup",
        "wrong-source",
        "wrong-artifact",
        "optional-check",
        "missing-admission",
    ] {
        let mut altered = workflow.clone();
        match mutation {
            "missing-setup" => {
                altered["jobs"]
                    .as_mapping_mut()
                    .unwrap()
                    .remove(Value::String("fuzz-setup".into()));
            }
            "wrong-source" => {
                altered["jobs"]["fuzz"]["steps"][1]["with"]["ref"] =
                    Value::String("${{ github.sha }}".into())
            }
            "wrong-artifact" | "optional-check" => {
                let id = if mutation == "wrong-artifact" {
                    "fuzz-setup-download"
                } else {
                    "fuzz-setup-check"
                };
                let step = altered["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|step| step["id"].as_str() == Some(id))
                    .unwrap();
                if mutation == "wrong-artifact" {
                    step["with"]["artifact-ids"] = Value::String("latest".into());
                } else {
                    step["continue-on-error"] = Value::Bool(true);
                }
            }
            "missing-admission" => {
                altered["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .remove(0);
            }
            _ => unreachable!(),
        }
        assert!(
            workflow_definitions::validate_semantics(&altered).is_err(),
            "{mutation}"
        );
    }
}
