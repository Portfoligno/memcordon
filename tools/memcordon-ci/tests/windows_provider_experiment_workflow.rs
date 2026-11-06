use memcordon_ci::workflow_definitions::definition;

#[test]
fn provider_experiments_are_payload_ready_siblings_of_unchanged_mandatory_consumers() {
    let workflow = definition("backend-certification.yml").unwrap();
    for architecture in ["x64", "arm64"] {
        let name = format!("windows-provider-input-experiment-{architecture}");
        let job = &workflow["jobs"][&name];
        let needs = serde_yaml::to_string(&job["needs"]).unwrap();
        assert!(needs.contains(&format!("windows-payload-{architecture}")));
        assert!(!needs.contains("windows-installed"));
        let matrix = job["strategy"]["matrix"]["include"].as_sequence().unwrap();
        assert_eq!(matrix.len(), 1);
        assert_eq!(matrix[0]["channel"], "native");
        let steps = job["steps"].as_sequence().unwrap();
        let command = steps
            .iter()
            .find(|step| step["id"] == "provider-input-experiment")
            .unwrap();
        assert!(command["run"].as_str().unwrap().contains("release working-windows-provider-experiment --destination target/ci/provider-input-experiment"));
        assert!(command["continue-on-error"].is_null());
        assert_eq!(command["timeout-minutes"].as_u64(), Some(135));
        let retained = steps
            .iter()
            .find_map(|step| {
                step["with"]["path"]
                    .as_str()
                    .filter(|path| path.contains("provider-input-experiment.json"))
            })
            .unwrap();
        assert_eq!(retained.lines().count(), 4);
        assert!(!retained.contains("**"));
        let original_name = format!("windows-installed-{architecture}");
        let originals = workflow["jobs"][&original_name]["steps"]
            .as_sequence()
            .unwrap();
        for channel in ["native", "cargo"] {
            let original = originals.iter().find(|step| step["id"] == channel).unwrap();
            assert!(
                original["run"]
                    .as_str()
                    .unwrap()
                    .contains(&format!("working-windows-consumer --channel {channel}"))
            );
            assert_eq!(original["timeout-minutes"].as_u64(), Some(135));
            assert!(original["continue-on-error"].is_null());
        }
    }
}
