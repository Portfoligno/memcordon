use serde_yaml::Value;

const OWNER_SETTLED: &str = "steps.native.outputs.compiled-complete-save == 'true'";

fn compiled_save(selected: &Value) -> Result<usize, &'static str> {
    let steps = selected["steps"].as_sequence().ok_or("steps absent")?;
    let restores: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step["id"] == "native-request-compiled-complete-restore")
        .collect();
    if restores.len() != 1 {
        return Err("exactly one compiled restore is required");
    }
    let (restore_index, restore) = restores[0];
    if !restore["uses"]
        .as_str()
        .is_some_and(|uses| uses.starts_with("actions/cache/restore@"))
        || restore["with"]["key"] != "${{ steps.native-request.outputs.compiled-complete-key }}"
        || restore["with"]["path"] != "${{ steps.native-request.outputs.compiled-complete-inbox }}"
        || restore["with"]["restore-keys"]
            != "${{ steps.native-request.outputs.compiled-complete-prefix }}"
    {
        return Err("compiled restore must use its selected context");
    }
    let saves: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step["uses"]
                .as_str()
                .is_some_and(|uses| uses.starts_with("actions/cache/save@"))
                && step["with"]["key"] == "${{ steps.native.outputs.compiled-complete-key }}"
        })
        .collect();
    if saves.len() != 1 {
        return Err("exactly one original-key compiled save is required");
    }
    let (save_index, save) = saves[0];
    if save_index <= restore_index
        || save["with"]["path"] != "${{ steps.native.outputs.compiled-complete-path }}"
        || !save["if"]
            .as_str()
            .is_some_and(|condition| {
                condition == "always() && steps.native.outputs.compiled-complete-save == 'true' && steps.native-compiled-complete-probe.outputs.cache-hit != 'true'"
            })
    {
        return Err("compiled save must retain selected paths and settled owner");
    }
    Ok(save_index)
}

#[test]
fn selected_macos_forms_require_both_architectures_and_actual_phase_collection() {
    let workflow: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for (job, condition, suite, phase) in [
        (
            "macos-combined",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'false'",
            "backend-macos-watchdog",
            "combined",
        ),
        (
            "macos-native",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'",
            "release-macos-native",
            "native",
        ),
        (
            "macos-acceptance",
            "needs.macos-performance-plan.outputs.standalone-common == 'true' && needs.macos-performance-plan.outputs.split == 'true'",
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
        assert_eq!(
            steps
                .iter()
                .filter(|step| step["run"].as_str()
                    == Some(&format!(
                        "./target/ci-runtime/current/memcordon-ci ci cleanup-transfers {suite}"
                    )))
                .count(),
            1
        );
        assert_eq!(
            steps
                .iter()
                .filter(|step| {
                    step["run"].as_str()
                        == Some(&format!(
                            "./target/ci-runtime/current/memcordon-ci ci cache-requests {suite}"
                        ))
                })
                .count(),
            1
        );
        let roots = memcordon_ci::cache_restore::roots("macos", phase).unwrap();
        let expected: &[&str] = if phase == "acceptance" {
            &["target/ci/backend-macos"]
        } else {
            &[
                "target/ci/backend-macos",
                "target/ci/deadline-build",
                "target/ci/deadline-oracle-build",
            ]
        };
        assert_eq!(
            roots,
            expected
                .iter()
                .map(std::path::PathBuf::from)
                .collect::<Vec<_>>()
        );
        let save = compiled_save(selected).unwrap();
        for mutation in ["owner", "missing", "duplicate", "path", "primary-key"] {
            let mut changed = selected.clone();
            let changed_steps = changed["steps"].as_sequence_mut().unwrap();
            match mutation {
                "owner" => {
                    let condition = changed_steps[save]["if"].as_str().unwrap();
                    assert!(condition.contains(OWNER_SETTLED));
                    changed_steps[save]["if"] = condition.replace(OWNER_SETTLED, "true").into();
                }
                "missing" => {
                    changed_steps.remove(save);
                }
                "duplicate" => changed_steps.push(changed_steps[save].clone()),
                "path" => changed_steps[save]["with"]["path"] = "target/ci/backend-macos".into(),
                "primary-key" => {
                    changed_steps[save]["with"]["key"] =
                        "${{ steps.compiled.outputs.cache-matched-key }}".into()
                }
                _ => unreachable!(),
            }
            assert_ne!(&changed, selected, "{job} {mutation} mutation was empty");
            assert!(
                compiled_save(&changed).is_err(),
                "{job} accepted {mutation}"
            );
        }
    }
    let assessment = &workflow["jobs"]["macos-assessment"];
    assert_eq!(
        assessment["if"],
        "always() && github.event.deleted != true && needs.macos-performance-plan.result == 'success' && needs.macos-performance-plan.outputs.standalone-common == 'true'"
    );
    assert_eq!(assessment["needs"].as_sequence().unwrap().len(), 4);
    assert!(
        assessment["steps"].as_sequence().unwrap().iter().any(
            |step| step["run"] == "./target/ci-runtime/current/memcordon-ci ci aggregate-macos"
        )
    );
}
