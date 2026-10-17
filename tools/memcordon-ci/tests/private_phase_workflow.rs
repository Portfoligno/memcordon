use memcordon_ci::workflow_definitions;

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
        assert!(!steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains(" ci segment workspace-fetch"))
        }));
        assert!(!steps.iter().any(|step| {
            step["id"].as_str().is_some_and(|id| {
                id.starts_with("private-run-private-native-tests-")
                    || id.starts_with("private-run-request-private-native-tests-")
            })
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
        assert!(!steps.iter().any(|step| {
            step["id"].as_str().is_some_and(|id| {
                id.starts_with("private-run-product-")
                    || id.starts_with("private-run-native-tests-")
                    || id.starts_with("private-run-request-product-")
                    || id.starts_with("private-run-request-native-tests-")
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
        assert!(workflow_definitions::validate_semantics(&optional).is_err());
    }
}
