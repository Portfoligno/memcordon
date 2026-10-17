use memcordon_ci::workflow_definitions::budget::{
    BudgetNode as N, JobDefinition, PLATFORM_LIMIT_MINUTES,
};

fn step(name: &str, minutes: u64) -> N {
    N::minutes(name, minutes).unwrap()
}

#[test]
fn actual_sequential_actions_exclusive_driver_paths_and_shared_clock_have_a_retained_breakdown() {
    let definition = JobDefinition {
        steps: vec![
            N::Alternatives {
                name: "driver".into(),
                branches: vec![
                    N::Sequence {
                        name: "cold".into(),
                        steps: vec![step("cold build", 30), step("adopt", 15)],
                    },
                    N::Sequence {
                        name: "managed".into(),
                        steps: vec![step("bootstrap", 2), step("context", 5), step("build", 50)],
                    },
                ],
            },
            N::SharedOperation {
                name: "original native work".into(),
                seconds: 140 * 60,
                steps: vec![step("compile", 115), step("validate/package", 100)],
            },
            N::Alternatives {
                name: "one native compiler class".into(),
                branches: vec![step("complete save", 6), step("partial save", 6)],
            },
            step("independent product save", 6),
            step("required cleanup", 15),
        ],
    };
    assert_eq!(definition.timeout_minutes().unwrap(), 229);
    let breakdown = definition.breakdown().unwrap();
    assert_eq!(breakdown.children[0].selected_branch, Some(1));
    assert_eq!(breakdown.children[1].seconds, 140 * 60);
    assert_eq!(breakdown.children.last().unwrap().seconds, 5 * 60);
    assert_eq!(breakdown.children[1].children.len(), 2);
}

#[test]
fn overflow_missing_bounds_and_beyond_platform_limit_fail_instead_of_clamping() {
    assert!(N::minutes("overflow", u64::MAX).is_err());
    let overflow = JobDefinition {
        steps: vec![
            N::Step {
                name: "one".into(),
                seconds: u64::MAX,
            },
            N::Step {
                name: "two".into(),
                seconds: 1,
            },
        ],
    };
    assert!(overflow.timeout_minutes().is_err());
    assert!(
        JobDefinition {
            steps: vec![step("work", PLATFORM_LIMIT_MINUTES)]
        }
        .timeout_minutes()
        .is_err()
    );
    assert_eq!(
        JobDefinition {
            steps: vec![step("work", PLATFORM_LIMIT_MINUTES - 5)]
        }
        .timeout_minutes()
        .unwrap(),
        PLATFORM_LIMIT_MINUTES
    );
    for yaml in [
        "steps: [{run: checked}]",
        "steps: [{uses: pinned, timeout-minutes: 0}]",
        "steps: [{run: checked, timeout-minutes: -1}]",
    ] {
        assert!(JobDefinition::from_job(&serde_yaml::from_str(yaml).unwrap()).is_err());
    }
    assert!(
        JobDefinition {
            steps: vec![N::Alternatives {
                name: "unreviewed".into(),
                branches: vec![]
            }]
        }
        .timeout_minutes()
        .is_err()
    );
}

#[test]
fn every_run_and_action_is_counted_and_seconds_round_up_after_slack() {
    let job=serde_yaml::from_str("steps:\n- id: checkout\n  uses: pinned\n  timeout-minutes: 2\n- run: actual\n  timeout-minutes: 3\n- uses: cache-save\n  timeout-minutes: 6\n").unwrap();
    assert_eq!(
        JobDefinition::from_job(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        16
    );
    assert_eq!(
        JobDefinition {
            steps: vec![N::Step {
                name: "one second".into(),
                seconds: 1
            }]
        }
        .timeout_minutes()
        .unwrap(),
        6
    );
}

#[test]
fn all_actual_emitted_jobs_have_finite_reviewed_steps_and_retained_maximum_paths() {
    use memcordon_ci::workflow_definitions;
    let mut failures = Vec::new();
    for file in workflow_definitions::FILES {
        let workflow = match workflow_definitions::definition(file) {
            Ok(workflow) => workflow,
            Err(error) => {
                failures.push(format!("{file}: {error}"));
                continue;
            }
        };
        for (_, job) in workflow["jobs"].as_mapping().unwrap() {
            if job["steps"].is_sequence() {
                JobDefinition::from_job(job).unwrap();
                for step in job["steps"].as_sequence().unwrap() {
                    let run = step["run"].as_str().unwrap_or("");
                    let expected = if run.ends_with(" ci segment macos-deadline") {
                        Some(75)
                    } else if [
                        "backend-macos-watchdog",
                        "release-macos-native",
                        "release-macos-acceptance",
                    ]
                    .iter()
                    .any(|recipe| run.ends_with(&format!(" ci segment {recipe}")))
                    {
                        Some(120)
                    } else if run.ends_with(" ci segment backend-linux-private") {
                        Some(195)
                    } else if run.ends_with(" ci segment backend-linux-private-prepare") {
                        Some(190)
                    } else if run.ends_with(" ci segment backend-linux-private-runtime") {
                        Some(195)
                    } else if run.ends_with(" release working-windows-prepare") {
                        Some(150)
                    } else if run.contains(" release working-windows-consumer ") {
                        Some(135)
                    } else {
                        None
                    };
                    if let Some(expected) = expected {
                        assert_eq!(
                            step["timeout-minutes"].as_u64(),
                            Some(expected),
                            "explicit Actions outer planning guard: {run}"
                        );
                    }
                }
            }
        }
        for (name, budget) in workflow_definitions::budget::workflow_breakdown(file).unwrap() {
            let paths = &budget.children[0];
            let selected = &paths.children[paths.selected_branch.unwrap()];
            eprintln!(
                "{file}/{name}: {} minutes, {}",
                budget.seconds.div_ceil(60),
                selected.name
            );
            for contribution in &selected.children {
                eprintln!("  {}: {} seconds", contribution.name, contribution.seconds);
            }
            assert!(budget.seconds.div_ceil(60) <= PLATFORM_LIMIT_MINUTES);
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
