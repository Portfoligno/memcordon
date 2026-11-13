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
        assert_ne!(altered, workflow, "{mutation} must change the graph");
        assert!(
            workflow_definitions::validate_semantics(&altered).is_err(),
            "{mutation}"
        );
    }
}

fn command_index(job: &Value, command: &str) -> usize {
    let matches = job["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .enumerate()
        .filter(|(_, step)| step["run"].as_str() == Some(command))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    assert_eq!(
        matches.len(),
        1,
        "required operation must be unique: {command}"
    );
    matches[0]
}

#[test]
fn selected_fuzz_inputs_precede_each_required_unchanged_quarter() {
    let baseline = workflow_definitions::definition("release.yml").unwrap();
    let fuzz = &baseline["jobs"]["fuzz"];
    let check = command_index(
        fuzz,
        "./.release/tool/memcordon-ci ci preparation-tools check --kind release-fuzz",
    );
    let extract = command_index(
        fuzz,
        "tar -xzf target/ci/release-fuzz-download/release-fuzz-setup.tar.gz -C .",
    );
    for quarter in ["one", "two", "three", "four"] {
        let compile = command_index(
            fuzz,
            &format!("./.release/tool/memcordon-ci ci segment fuzz-compile-quarter-{quarter}"),
        );
        let execute = command_index(
            fuzz,
            &format!("./.release/tool/memcordon-ci ci segment fuzz-execute-quarter-{quarter}"),
        );
        assert!(check < compile && compile < execute);
        assert_eq!(
            fuzz["steps"][compile]["if"],
            format!("matrix.shard == 'quarter-{quarter}'")
        );
        assert_eq!(
            fuzz["steps"][execute]["if"],
            format!("matrix.shard == 'quarter-{quarter}'")
        );
        for mutation in 0..4 {
            let mut changed = baseline.clone();
            let steps = changed["jobs"]["fuzz"]["steps"].as_sequence_mut().unwrap();
            match mutation {
                0 => {
                    steps.remove(compile);
                }
                1 => steps[compile]["if"] = "always()".into(),
                2 => steps.swap(check, compile),
                _ => steps[execute]["continue-on-error"] = true.into(),
            }
            assert_ne!(changed, baseline);
            assert!(
                workflow_definitions::validate_semantics(&changed).is_err(),
                "quarter {quarter} mutation {mutation}"
            );
        }
    }
    let setup = &baseline["jobs"]["fuzz-setup"];
    let prepare = command_index(
        setup,
        "./.release/tool/memcordon-ci ci segment prepare-fuzz",
    );
    let package = command_index(
        setup,
        "./.release/tool/memcordon-ci ci preparation-tools package --kind release-fuzz",
    );
    let checkout = setup["steps"]
        .as_sequence()
        .unwrap()
        .iter()
        .position(|step| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/checkout@"))
        })
        .unwrap();
    for mutation in 0..6 {
        let mut changed = baseline.clone();
        match mutation {
            0 => {
                changed["jobs"]["fuzz-setup"]["steps"][checkout]["with"]["ref"] =
                    "${{ github.sha }}".into()
            }
            1 => {
                changed["jobs"]["fuzz-setup"]["outputs"]["artifact-id"] =
                    "${{ steps.unrelated.outputs.artifact-id }}".into()
            }
            2 => changed["jobs"]["fuzz-setup"]["steps"]
                .as_sequence_mut()
                .unwrap()
                .swap(prepare, package),
            3 => {
                changed["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .remove(extract);
            }
            4 => {
                let duplicate = changed["jobs"]["fuzz"]["steps"][check].clone();
                changed["jobs"]["fuzz"]["steps"]
                    .as_sequence_mut()
                    .unwrap()
                    .push(duplicate);
            }
            _ => changed["jobs"]["fuzz"]["steps"][0]["continue-on-error"] = true.into(),
        }
        assert_ne!(changed, baseline);
        assert!(
            workflow_definitions::validate_semantics(&changed).is_err(),
            "selected input mutation {mutation}"
        );
    }
}
