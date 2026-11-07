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
        assert_eq!(retained.lines().count(), 14);
        for leaf in [
            "result.stdout.bin",
            "result.stderr.bin",
            "result.guardian-query.stdout.bin",
            "result.guardian-query.stderr.bin",
        ] {
            assert!(retained.lines().any(|path| path == format!("target/ci/provider-input-experiment/cases/provider-input-experiment/*/facts/{leaf}")));
        }
        for leaf in [
            "package-uninstall.stdout.bin",
            "package-uninstall.stderr.bin",
            "package-uninstall.capture.json",
            "package-uninstall.invocation.json",
            "recovery.stdout.bin",
            "recovery.stderr.bin",
        ] {
            assert!(retained.lines().any(|path|path == format!("target/ci/provider-input-experiment/cases/{leaf}")));
        }
        assert!(!retained.contains("**"));
        // Independent job/command gives the FILE layout a fresh installation
        // and original cutoff; it is never a fallback after directory failure.
        let alternate =
            &workflow["jobs"][format!("windows-provider-file-input-experiment-{architecture}")];
        assert_eq!(alternate["needs"], job["needs"]);
        assert_eq!(alternate["strategy"], job["strategy"]);
        let alternate_steps = alternate["steps"].as_sequence().unwrap();
        let alternate_command = alternate_steps
            .iter()
            .find(|step| step["id"] == "provider-input-experiment")
            .unwrap();
        assert_eq!(
            alternate_command["run"],
            "./target/ci-runtime/current/memcordon-ci.exe release working-windows-provider-experiment --destination target/ci/provider-file-input-experiment --dot-local-file"
        );
        assert_eq!(
            alternate_command["timeout-minutes"],
            command["timeout-minutes"]
        );
        assert!(alternate_command["continue-on-error"].is_null());
        let artifact = alternate_steps
            .iter()
            .find(|step| {
                step["with"]["name"]
                    .as_str()
                    .is_some_and(|name| name.starts_with("provider-file-input-experiment-"))
            })
            .unwrap();
        let alternate_paths = artifact["with"]["path"].as_str().unwrap();
        assert_eq!(alternate_paths.lines().count(), retained.lines().count());
        assert!(
            alternate_paths
                .lines()
                .all(|path| path.starts_with("target/ci/provider-file-input-experiment/cases/"))
        );
        assert!(!alternate_paths.contains("**"));
        assert!(
            !command["run"]
                .as_str()
                .unwrap()
                .contains("--dot-local-file")
        );
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
