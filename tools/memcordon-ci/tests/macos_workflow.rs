use serde_yaml::Value;

#[test]
fn selected_macos_forms_require_both_architectures_and_actual_phase_collection() {
    let workflow: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for (job, condition, suite, phase) in [
        (
            "macos-combined",
            "needs.macos-performance-plan.outputs.split == 'false'",
            "backend-macos-watchdog",
            "combined",
        ),
        (
            "macos-native",
            "needs.macos-performance-plan.outputs.split == 'true'",
            "release-macos-native",
            "native",
        ),
        (
            "macos-acceptance",
            "needs.macos-performance-plan.outputs.split == 'true'",
            "release-macos-acceptance",
            "acceptance",
        ),
    ] {
        let selected = &workflow["jobs"][job];
        assert_eq!(selected["needs"].as_str(), Some("macos-performance-plan"));
        assert_eq!(selected["if"].as_str(), Some(condition));
        let matrix = selected["strategy"]["matrix"]["include"]
            .as_sequence()
            .unwrap();
        assert_eq!(matrix.len(), 2);
        assert!(
            matrix
                .iter()
                .any(|entry| entry["id"] == "macos-x64" && entry["runner"] == "macos-15-intel")
        );
        assert!(
            matrix
                .iter()
                .any(|entry| entry["id"] == "macos-arm64" && entry["runner"] == "macos-15")
        );
        let steps = selected["steps"].as_sequence().unwrap();
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["run"]
                    .as_str()
                    .is_some_and(|run| run.split_whitespace().last() == Some(suite)))
                .count(),
            1
        );
        assert!(steps.iter().any(|step| {
            step["id"] == "context"
                && step["run"]
                    .as_str()
                    .is_some_and(|run| run.split_whitespace().last() == Some(phase))
        }));
        assert!(
            steps
                .iter()
                .filter(|step| step["uses"]
                    .as_str()
                    .is_some_and(|uses| uses.contains("cache/save"))
                    && step["with"]["path"] == "target/ci/backend-macos")
                .all(|step| step["if"]
                    .as_str()
                    .unwrap()
                    .contains("steps.native.outputs.cache-quiescent == 'true'"))
        );
    }
    let assessment = &workflow["jobs"]["macos-assessment"];
    assert_eq!(assessment["if"], "always()");
    assert_eq!(assessment["needs"].as_sequence().unwrap().len(), 4);
    assert!(
        assessment["steps"]
            .as_sequence()
            .unwrap()
            .iter()
            .any(|step| step["run"] == "./target/ci/release/memcordon-ci ci aggregate-macos")
    );
}
