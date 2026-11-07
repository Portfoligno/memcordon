use memcordon_ci::workflow_definitions::definition;

#[test]
fn matched_measurements_are_independent_native_payload_consumers() {
    let workflow = definition("backend-certification.yml").unwrap();
    for architecture in ["x64", "arm64"] {
        let job = &workflow["jobs"][format!("windows-matched-owned-{architecture}")];
        let original = &workflow["jobs"][format!("windows-installed-{architecture}")];
        assert_eq!(job["needs"], format!("windows-payload-{architecture}"));
        assert_eq!(job["runs-on"], original["runs-on"]);
        assert_eq!(job["timeout-minutes"], original["timeout-minutes"]);
        let matrix = job["strategy"]["matrix"]["include"].as_sequence().unwrap();
        assert_eq!(matrix.len(), 1);
        assert_eq!(matrix[0]["channel"], "native");
        assert_eq!(
            job["strategy"]["fail-fast"],
            original["strategy"]["fail-fast"]
        );
        let steps = job["steps"].as_sequence().unwrap();
        let command = steps
            .iter()
            .find(|step| step["id"] == "matched-owned")
            .unwrap();
        assert_eq!(
            command["run"],
            "./target/ci-runtime/current/memcordon-ci.exe release working-windows-matched-owned --destination target/ci/matched-owned"
        );
        assert_eq!(command["timeout-minutes"].as_u64(), Some(135));
        assert!(command["continue-on-error"].is_null());
        assert!(!steps.iter().any(|step| {
            step["run"]
                .as_str()
                .is_some_and(|run| run.contains("working-windows-consumer"))
        }));
        let original_steps = original["steps"].as_sequence().unwrap();
        for step in original_steps {
            let consumer = step["run"]
                .as_str()
                .is_some_and(|run| run.contains("working-windows-consumer"));
            let upload = step["with"]["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("windows-installed"));
            if !consumer && !upload {
                assert!(steps.contains(step), "preparation/cache step changed");
            }
        }
        for channel in ["native", "cargo"] {
            assert!(original_steps.iter().any(|step| {
                step["id"] == channel
                    && step["run"]
                        .as_str()
                        .unwrap()
                        .contains(&format!("working-windows-consumer --channel {channel}"))
            }));
        }
        let artifact = steps
            .iter()
            .find(|step| step["with"]["name"] == "matched-owned-${{ matrix.id }}")
            .unwrap();
        assert_eq!(artifact["if"], "!cancelled()");
        assert_eq!(artifact["uses"], "./.github/actions/upload-artifact");
        let paths: Vec<_> = artifact["with"]["path"].as_str().unwrap().lines().collect();
        assert_eq!(paths.len(), 44);
        assert!(
            paths
                .iter()
                .all(|path| path.starts_with("target/ci/matched-owned/cases/")
                    && !path.contains("**")
                    && !path.ends_with('*')
                    && !path.contains("payload")
                    && !path.ends_with(".zip"))
        );
        for leaf in [
            "broker.json",
            "plan.direct-input.json",
            "installed-input.json",
        ] {
            assert!(
                paths.contains(
                    &format!("target/ci/matched-owned/cases/matched-owned-controls/*/*/{leaf}")
                        .as_str()
                )
            );
        }
        for leaf in [
            "native-exit.json",
            "native-retirement.json",
            "result.failed-frontend.json",
            "result.guardian-query.json",
        ] {
            assert!(paths.contains(&format!("target/ci/matched-owned/cases/matched-owned-controls/*/*/W-MATCHED-OWNED/*/{leaf}").as_str()));
        }
        assert!(paths.contains(&"target/ci/matched-owned/cases/candidate-outputs/*/*/installed/frontend-result.terminal-observation.json"));
        for leaf in [
            "package-uninstall.capture.json",
            "package-uninstall.invocation.json",
            "recovery.stderr.bin",
        ] {
            assert!(paths.contains(&format!("target/ci/matched-owned/cases/{leaf}").as_str()));
        }
    }
}
