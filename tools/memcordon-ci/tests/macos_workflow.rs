use serde_yaml::Value;

#[test]
fn selected_macos_forms_require_both_architectures_and_actual_phase_collection() {
    let workflow: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for (job, condition, suite) in [
        (
            "macos-combined",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'false'",
            "backend-macos-watchdog",
        ),
        (
            "macos-native",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'",
            "release-macos-native",
        ),
        (
            "macos-acceptance",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'",
            "release-macos-acceptance",
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
                .filter(|step| step["run"].as_str()
                    == Some(&format!(
                        "./target/ci-runtime/current/memcordon-ci ci segment {suite}"
                    )))
                .count(),
            1
        );
        let work = steps
            .iter()
            .find(|step| {
                step["run"].as_str()
                    == Some(&format!(
                        "./target/ci-runtime/current/memcordon-ci ci segment {suite}"
                    ))
            })
            .unwrap();
        assert_ne!(work["continue-on-error"].as_bool(), Some(true));
        assert_eq!(work["if"].as_str(), Some("runner.os != 'Windows'"));
    }
    assert!(workflow["jobs"]["macos-assessment"].is_null());
}
