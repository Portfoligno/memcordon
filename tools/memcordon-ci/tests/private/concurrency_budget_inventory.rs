use super::*;

#[test]
fn native_step_budgets_include_platform_execution_and_optional_retention() {
    for (command, minutes) in [
        (
            "./target/ci-runtime/current/memcordon-ci ci segment native-compile",
            35,
        ),
        (
            "./target/ci-runtime/current/memcordon-ci.exe ci segment native-compile",
            35,
        ),
        (
            "./target/ci-runtime/current/memcordon-ci ci segment native-execute",
            40,
        ),
        (
            "./target/ci-runtime/current/memcordon-ci.exe ci segment native-execute",
            40,
        ),
        (
            "./target/ci-runtime/current/memcordon-ci ci segment native",
            65,
        ),
        (
            "./target/ci-runtime/current/memcordon-ci.exe ci segment native",
            65,
        ),
    ] {
        let mut step = Value::Mapping(Default::default());
        step["run"] = command.into();
        assert_eq!(reviewed_step_minutes(&step), Some(minutes), "{command}");
        if !command.contains("memcordon-ci.exe") {
            for platform in [
                crate::native_test_plan::NativePlatform::MacOs,
                crate::native_test_plan::NativePlatform::Other,
            ] {
                let plan = crate::native_test_plan::commands_for_platform(
                    false,
                    crate::failure_mode::FailureMode::StopAfterFailure,
                    platform,
                );
                let modeled = if command.ends_with("native-compile") {
                    plan[0].deadline
                } else if command.ends_with("native-execute") {
                    plan[1].deadline
                } else {
                    plan[0].deadline + plan[1].deadline
                };
                assert!(
                    std::time::Duration::from_secs(minutes * 60)
                        >= modeled + std::time::Duration::from_secs(10 * 60),
                    "{command}: {platform:?}"
                );
            }
        }
        step["timeout-minutes"] = minutes.into();
        let mut job = Value::Mapping(Default::default());
        job["runs-on"] = if command.contains("memcordon-ci.exe") {
            "windows-2025"
        } else {
            "ubuntu-24.04"
        }
        .into();
        job["steps"] = Value::Sequence(vec![step]);
        assert_eq!(
            job_budget_definition(&job)
                .unwrap()
                .timeout_minutes()
                .unwrap(),
            minutes + 5,
            "{command}"
        );
    }
}

#[test]
fn statically_skipped_producer_outputs_exclude_only_impossible_descendants() {
    let job: Value = serde_yaml::from_str("runs-on: windows-2025\nstrategy:\n  matrix:\n    include:\n    - quarter: one\nsteps:\n- id: other\n  run: other\n  if: runner.os == 'Linux' || matrix.quarter == 'two'\n  timeout-minutes: 50\n- id: request\n  run: request\n  if: steps.other.outputs.ready == 'true'\n  timeout-minutes: 20\n- run: impossible-save\n  if: steps.request.outputs.ready == 'true'\n  timeout-minutes: 10\n- run: missing-producer\n  if: steps.absent.outputs.ready == 'true'\n  timeout-minutes: 3\n- run: unknown-status\n  if: steps.other.outcome == 'failure' || steps.live.outcome == 'failure'\n  timeout-minutes: 2\n").unwrap();
    assert_eq!(
        job_budget_definition(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        10
    );
}

#[test]
fn only_complete_static_matrix_rows_make_missing_properties_empty() {
    let static_job: Value = serde_yaml::from_str("runs-on: macos-15\nstrategy:\n  matrix:\n    include:\n    - channel: native\nsteps:\n- run: producer\n  if: matrix.producer-job != ''\n  timeout-minutes: 150\n- run: normal\n  if: matrix.producer-job == ''\n  timeout-minutes: 20\n").unwrap();
    assert_eq!(
        job_budget_definition(&static_job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        25
    );
    let mut dynamic_job = static_job.clone();
    dynamic_job["strategy"]["matrix"] =
        Value::String("${{ fromJSON(needs.select.outputs.matrix) }}".into());
    assert_eq!(
        job_budget_definition(&dynamic_job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        175
    );
}

#[test]
fn driver_routes_are_exclusive_by_source_host_without_inventing_success() {
    let job: Value = serde_yaml::from_str("runs-on: windows-2025\nsteps:\n- id: driver-selection\n  run: current ci driver-select\n  if: runner.os != 'Windows'\n  timeout-minutes: 1\n- id: driver-selection-windows\n  run: current.exe ci driver-select\n  if: runner.os == 'Windows'\n  timeout-minutes: 1\n- id: driver-managed-build\n  run: build-linux\n  if: steps.driver-selection.outputs.build-required == 'true'\n  timeout-minutes: 50\n- id: driver-managed-build-windows\n  run: build-windows\n  if: steps.driver-selection-windows.outputs.build-required == 'true'\n  timeout-minutes: 50\n- run: unknown-failure\n  if: steps.driver-managed-build-windows.outcome == 'failure'\n  timeout-minutes: 2\n").unwrap();
    assert_eq!(
        job_budget_definition(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        58
    );
}

#[test]
fn installed_readiness_native_paths_share_the_actual_acquisition_clock() {
    for executable in ["consumer-readiness", "consumer-readiness.exe"] {
        let job: Value = serde_yaml::from_str(&format!("runs-on: windows-2025\nsteps:\n- run: ./target/{executable} acquire --identity selected\n  timeout-minutes: 160\n- run: ./target/{executable} cleanup --identity selected\n  timeout-minutes: 20\n")).unwrap();
        assert_eq!(
            job_budget_definition(&job)
                .unwrap()
                .timeout_minutes()
                .unwrap(),
            165
        );
    }
}

#[test]
fn matrix_or_guards_and_unrecognized_conditions_never_omit_a_possible_step() {
    let job:Value=serde_yaml::from_str("runs-on: ubuntu-24.04\nstrategy:\n  matrix:\n    channel: [native, cargo]\nsteps:\n- run: native\n  if: matrix.channel == 'native'\n  timeout-minutes: 10\n- run: cargo\n  if: matrix.channel == 'cargo'\n  timeout-minutes: 30\n- run: either\n  if: matrix.channel == 'native' || matrix.channel == 'cargo'\n  timeout-minutes: 5\n- run: unknown\n  if: startsWith(github.ref, 'refs/heads/')\n  timeout-minutes: 1\n").unwrap();
    assert_eq!(
        job_budget_definition(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        41
    );
}

#[test]
fn exact_producer_complete_probe_save_and_partial_save_are_one_alternative() {
    let job:Value=serde_yaml::from_str(&format!("runs-on: ubuntu-24.04\nsteps:\n- uses: {RESTORE}\n  timeout-minutes: 1\n  with:\n    lookup-only: true\n    key: '${{{{ steps.work.outputs.compiled-complete-key }}}}'\n- uses: {SAVE}\n  timeout-minutes: 2\n  with:\n    key: '${{{{ steps.work.outputs.compiled-complete-key }}}}'\n- uses: {SAVE}\n  timeout-minutes: 2\n  with:\n    key: '${{{{ steps.work.outputs.compiled-partial-key }}}}'\n- uses: {SAVE}\n  timeout-minutes: 2\n  with:\n    key: '${{{{ steps.other.outputs.compiled-partial-key }}}}'\n")).unwrap();
    assert_eq!(
        job_budget_definition(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        10
    );
}

#[test]
fn source_analysis_keeps_false_string_truthiness_and_unknown_statuses() {
    let unknown = |_: &str| None;
    for condition in ["'false'", "steps.work.outputs.value == 'true'", "always()"] {
        let expression = crate::policy::cache_guard::parse(condition).unwrap();
        assert!(!budget_guard_value(&expression, &unknown).is_some_and(|value| !value.truthy()));
    }
    let expression = crate::policy::cache_guard::parse("false").unwrap();
    assert!(budget_guard_value(&expression, &unknown).is_some_and(|value| !value.truthy()));
}

#[test]
fn native_shared_clock_is_only_selected_for_real_split_and_actions_remain_additional() {
    let job:Value=serde_yaml::from_str("runs-on: ubuntu-24.04\nsteps:\n- run: ./current release compile-target --build-source selected\n  timeout-minutes: 115\n- run: ./current release validate-package --build-source selected\n  timeout-minutes: 100\n- run: ./current consumer-readiness-native-components --identity selected\n  timeout-minutes: 155\n- uses: pinned-cache-save\n  timeout-minutes: 2\n").unwrap();
    assert_eq!(
        job_budget_definition(&job)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        172
    );
    let mut no_split = job.clone();
    no_split["steps"].as_sequence_mut().unwrap().remove(0);
    assert_eq!(
        job_budget_definition(&no_split)
            .unwrap()
            .timeout_minutes()
            .unwrap(),
        262
    );
}
