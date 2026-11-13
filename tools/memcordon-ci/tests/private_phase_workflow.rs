use memcordon_ci::workflow_definitions;
use serde_yaml::Value;

fn rejects(workflow: &Value, boundary: &str, mutation: impl FnOnce(&mut Value)) {
    let mut changed = workflow.clone();
    mutation(&mut changed);
    assert_ne!(&changed, workflow, "mutation must change {boundary}");
    assert!(
        workflow_definitions::validate_semantics(&changed).is_err(),
        "semantic validation accepted changed {boundary}"
    );
}

fn step_index(job: &Value, command: &str) -> usize {
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
        "actual operation must be unique: {command}"
    );
    matches[0]
}

#[test]
fn private_payloads_and_runtime_are_required_exact_host_artifact_phases() {
    let workflow = workflow_definitions::definition("backend-certification.yml").unwrap();
    for (prepare, runtime, artifact) in [
        (
            "private-linux-prepare-x64",
            "private-linux",
            "private-prepared-linux-x64",
        ),
        (
            "private-linux-prepare-arm64",
            "private-linux-arm64",
            "private-prepared-linux-arm64",
        ),
    ] {
        let producer = &workflow["jobs"][prepare];
        let consumer = &workflow["jobs"][runtime];
        assert_eq!(consumer["needs"].as_str(), Some(prepare));
        assert_eq!(
            producer["strategy"]["matrix"],
            consumer["strategy"]["matrix"]
        );
        let steps = producer["steps"].as_sequence().unwrap();
        assert!(steps.iter().any(|step| step["run"].as_str()
            == Some(
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-prepare"
            )));
        assert!(steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains(" ci segment workspace-fetch"))
        }));
        let upload = steps
            .iter()
            .find(|step| step["id"].as_str() == Some("private-prepared-upload"))
            .unwrap();
        assert_eq!(upload["with"]["name"].as_str(), Some(artifact));
        assert!(upload["continue-on-error"].is_null());
        let steps = consumer["steps"].as_sequence().unwrap();
        let download = steps
            .iter()
            .find(|step| step["with"]["artifact-ids"].is_string())
            .unwrap();
        assert_eq!(
            download["with"]["artifact-ids"].as_str(),
            Some(format!("${{{{ needs.{prepare}.outputs.artifact-id }}}}").as_str())
        );
        assert_eq!(download["with"]["digest-mismatch"].as_str(), Some("error"));
        assert!(steps.iter().any(|step| step["run"].as_str()
            == Some("./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch")));
        assert!(steps.iter().any(|step| step["run"].as_str()
            == Some(
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-runtime"
            )));
        assert!(!steps.iter().any(|step| {
            step["run"].as_str().is_some_and(|run| {
                run.contains(" ci driver-build")
                    || run.contains("--target-dir target/ci-driver-cold")
            })
        }));
        for step in producer["steps"].as_sequence().unwrap().iter().chain(steps) {
            if let Some(run) = step["run"].as_str() {
                assert!(!run.contains("target/ci-session"));
            }
        }
        let mut missing = workflow.clone();
        missing["jobs"][runtime]
            .as_mapping_mut()
            .unwrap()
            .remove(serde_yaml::Value::String("needs".into()));
        assert_ne!(missing, workflow);
        assert!(workflow_definitions::validate_semantics(&missing).is_err());
        let mut optional = workflow.clone();
        for step in optional["jobs"][runtime]["steps"]
            .as_sequence_mut()
            .unwrap()
        {
            if step["run"].as_str()
                == Some(
                    "./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind private",
                )
            {
                step["continue-on-error"] = serde_yaml::Value::Bool(true);
            }
        }
        assert_ne!(optional, workflow);
        assert!(workflow_definitions::validate_semantics(&optional).is_err());
    }
}

#[test]
fn private_phase_inputs_hosts_and_required_execution_order_are_independent_invariants() {
    let workflow = workflow_definitions::definition("backend-certification.yml").unwrap();
    for (tools, prepare, runtime, wrong_tools, wrong_prepare) in [
        (
            "private-linux-tools-x64",
            "private-linux-prepare-x64",
            "private-linux",
            "private-linux-tools-arm64",
            "private-linux-prepare-arm64",
        ),
        (
            "private-linux-tools-arm64",
            "private-linux-prepare-arm64",
            "private-linux-arm64",
            "private-linux-tools-x64",
            "private-linux-prepare-x64",
        ),
    ] {
        for (owner, predecessor, wrong_predecessor, kind, extraction, segment) in [
            (
                prepare,
                tools,
                wrong_tools,
                "private-driver",
                "tar -xf target/ci/private-driver-transfer/private-driver.tar",
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-prepare",
            ),
            (
                runtime,
                prepare,
                wrong_prepare,
                "private",
                "tar -xf target/ci/private-transfer/private-prepared.tar",
                "./target/ci-runtime/current/memcordon-ci ci segment backend-linux-private-runtime",
            ),
        ] {
            let job = &workflow["jobs"][owner];
            let command = format!(
                "./target/ci-runtime/current/memcordon-ci ci preparation-tools check --kind {kind}"
            );
            let check = step_index(job, &command);
            let extract = step_index(job, extraction);
            let execute = step_index(job, segment);
            let fetch = step_index(
                job,
                "./target/ci-runtime/current/memcordon-ci ci segment workspace-fetch",
            );
            let download = job["steps"]
                .as_sequence()
                .unwrap()
                .iter()
                .position(|step| step["with"]["artifact-ids"].is_string())
                .unwrap();
            assert_eq!(job["needs"], predecessor);
            assert!(download < extract && extract < check && check < fetch && fetch < execute);
            assert_eq!(job["steps"][execute]["if"], "runner.os != 'Windows'");
            for mutation in 0..18 {
                rejects(&workflow, owner, |changed| {
                    let job = &mut changed["jobs"][owner];
                    match mutation {
                        0 => {
                            job.as_mapping_mut()
                                .unwrap()
                                .remove(Value::String("needs".into()));
                        }
                        1 => job["needs"] = wrong_predecessor.into(),
                        2 => job["strategy"]["matrix"]["include"][0]["id"] = "wrong-host".into(),
                        3 => {
                            job["steps"][download]["with"]["artifact-ids"] =
                                format!("${{{{ needs.{wrong_predecessor}.outputs.artifact-id }}}}")
                                    .into()
                        }
                        4 => job["steps"][download]["with"]["digest-mismatch"] = "ignore".into(),
                        5 => {
                            job["steps"][download]["with"]["path"] =
                                "target/wrong-private-input".into()
                        }
                        6 => job["steps"][check]["continue-on-error"] = true.into(),
                        7 => job["steps"][check]["if"] = "always()".into(),
                        8 => {
                            let duplicate = job["steps"][check].clone();
                            job["steps"]
                                .as_sequence_mut()
                                .unwrap()
                                .insert(check, duplicate);
                        }
                        9 => job["steps"].as_sequence_mut().unwrap().swap(extract, check),
                        10 => job["steps"].as_sequence_mut().unwrap().swap(check, fetch),
                        11 => job["steps"][execute]["if"] = "always()".into(),
                        12 => job["steps"][execute]["continue-on-error"] = true.into(),
                        13 => {
                            job["steps"].as_sequence_mut().unwrap().remove(check);
                        }
                        14 => {
                            job["steps"].as_sequence_mut().unwrap().remove(execute);
                        }
                        15 => job["runs-on"] = "ubuntu-24.04".into(),
                        16 => job["steps"][check]["continue-on-error"] = "${{ always() }}".into(),
                        _ => {
                            job["strategy"]["matrix"]["include"][0]["runner"] =
                                "wrong-runner".into()
                        }
                    }
                });
            }
        }
        for (owner, upload_id, package, archive) in [
            (
                tools,
                "private-driver-upload",
                "./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind private-driver",
                "tar -cf target/ci/private-driver.tar target/ci-runtime/current target/ci-preparation/private-driver.json",
            ),
            (
                prepare,
                "private-prepared-upload",
                "./target/ci-runtime/current/memcordon-ci ci preparation-tools package --kind private",
                "tar -cf target/ci/private-prepared.tar target/ci/private-prepared target/ci-runtime/current target/ci-preparation/private.json target/ci/native/release/memcordon-linux-readiness-fixture",
            ),
        ] {
            let job = &workflow["jobs"][owner];
            let package = step_index(job, package);
            let archive = step_index(job, archive);
            let upload = job["steps"]
                .as_sequence()
                .unwrap()
                .iter()
                .position(|step| step["id"] == upload_id)
                .unwrap();
            assert!(package < archive && archive < upload);
            if owner == prepare {
                rejects(
                    &workflow,
                    "private readiness executable transport",
                    |changed| {
                        let step = &mut changed["jobs"][owner]["steps"][archive];
                        step["run"] = step["run"]
                            .as_str()
                            .unwrap()
                            .strip_suffix(
                                " target/ci/native/release/memcordon-linux-readiness-fixture",
                            )
                            .expect("private preparation transports its required native fixture")
                            .into();
                    },
                );
            }
            for mutation in 0..5 {
                rejects(&workflow, owner, |changed| {
                    let job = &mut changed["jobs"][owner];
                    match mutation {
                        0 => {
                            job["outputs"]["artifact-id"] =
                                "${{ steps.unrelated.outputs.artifact-id }}".into()
                        }
                        1 => job["steps"][upload]["continue-on-error"] = true.into(),
                        2 => {
                            job["steps"][upload]["with"]["path"] =
                                "target/wrong-private-output.tar".into()
                        }
                        3 => job["steps"][upload]["with"]["if-no-files-found"] = "warn".into(),
                        _ => job["steps"]
                            .as_sequence_mut()
                            .unwrap()
                            .swap(package, archive),
                    }
                });
            }
        }
    }
}
