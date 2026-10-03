use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy};
use serde_yaml::Value;

#[path = "support/text_fixture.rs"]
mod text_fixture;

const CI_WORKFLOW_PATH: &str = ".github/workflows/ci.yml";

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

#[test]
fn workflow_mutation_fixture_is_checkout_eol_independent() {
    let lf = text_fixture::canonical_lf_utf8(
        include_bytes!("../../../.github/workflows/ci.yml"),
        CI_WORKFLOW_PATH,
    )
    .unwrap();
    let crlf = text_fixture::crlf_from_lf(&lf);
    for source in [lf.as_bytes(), crlf.as_bytes()] {
        assert_eq!(
            text_fixture::canonical_lf_utf8(source, CI_WORKFLOW_PATH).unwrap(),
            lf
        );
    }
}

#[test]
fn text_fixture_preserves_utf8_with_mixed_line_endings() {
    assert_eq!(
        text_fixture::canonical_lf_utf8("first\r\n日本語\nlast\r\n".as_bytes(), "fixture").unwrap(),
        "first\n日本語\nlast\n"
    );
}

#[test]
fn text_fixture_rejects_bare_cr_missing_newline_and_invalid_utf8() {
    for source in [
        b"first\rsecond\n".as_slice(),
        b"first\r",
        b"first",
        b"\xff\n",
    ] {
        assert!(text_fixture::canonical_lf_utf8(source, "fixture").is_err());
    }
}

#[test]
fn native_workspace_suite_retains_all_targets_and_features() {
    let suites_source = include_str!("../src/suites.rs");
    assert!(suites_source.contains("Suite::Native => native(root, &toolchains.stable, false)"));
    assert!(
        suites_source
            .contains("for command in memcordon_ci::native_test_plan::commands(release_mode)")
    );
    for release_mode in [false, true] {
        let commands = memcordon_ci::native_test_plan::commands(release_mode);
        assert!(!commands.is_empty(), "native test plan must run Cargo");
        for command in commands {
            for required in ["--workspace", "--all-targets", "--all-features"] {
                assert!(
                    command.arguments.contains(&required),
                    "native suite dropped {required} in release_mode={release_mode}"
                );
            }
        }
    }
}

#[test]
fn macos_deadline_rejects_missing_failure_evidence() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy");
    let fixture = include_str!("../../../.github/workflows/ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("complete independent deadline lane");
    {
        let missing = "target/ci/deadline-evidence";
        let invalid = fixture.replace(missing, "missing-deadline-proof");
        assert!(
            policy::validate_workflow_bytes(
                &root,
                Path::new(".github/workflows/ci.yml"),
                invalid.as_bytes(),
                &repository_policy
            )
            .is_err(),
            "missing required evidence was accepted: {missing}"
        );
    }
}

fn workflow_with_job_timeout(fixture: &str, job_id: &str, timeout_minutes: u64) -> Vec<u8> {
    let mut document: Value =
        serde_yaml::from_str(fixture).expect("workflow fixture should deserialize");
    let jobs_key = Value::String(String::from("jobs"));
    let timeout_key = Value::String(String::from("timeout-minutes"));
    let job_key = Value::String(job_id.to_owned());
    let jobs = document
        .as_mapping_mut()
        .and_then(|workflow| workflow.get_mut(&jobs_key))
        .and_then(Value::as_mapping_mut)
        .expect("workflow fixture should contain jobs");
    let job = jobs
        .get_mut(&job_key)
        .and_then(Value::as_mapping_mut)
        .expect("workflow fixture should contain the selected job");
    job.insert(timeout_key, Value::Number(timeout_minutes.into()));
    serde_yaml::to_string(&document)
        .expect("workflow fixture should serialize")
        .into_bytes()
}

#[test]
fn deep_ci_fuzz_timeout_covers_the_complete_target_set() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let fixture = include_str!("../../../.github/workflows/deep-ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/deep-ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("the exact deep CI workflow should pass");

    for timeout_minutes in [30, 45, 59, 61] {
        let invalid = workflow_with_job_timeout(fixture, "fuzz", timeout_minutes);
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/deep-ci.yml"),
            &invalid,
            &repository_policy,
        )
        .expect_err("a changed fuzz shard deadline must fail");
        assert!(
            error
                .to_string()
                .contains("deep CI fuzz timeout differs from workload deadline"),
            "unexpected workflow policy error: {error}"
        );
    }
}

#[test]
fn deep_ci_miri_job_bound_includes_audit_and_cleanup_headroom() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let fixture = include_str!("../../../.github/workflows/deep-ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/deep-ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("the exact deep CI workflow should pass");

    for timeout_minutes in [45, 59, 61] {
        let invalid = workflow_with_job_timeout(fixture, "miri", timeout_minutes);
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/deep-ci.yml"),
            &invalid,
            &repository_policy,
        )
        .expect_err("a changed Miri job bound must fail");
        assert!(
            error
                .to_string()
                .contains("deep shard runner or execution bounds differ"),
            "unexpected workflow policy error: {error}"
        );
    }
}

#[test]
fn deep_ci_stress_job_bound_covers_cold_packages_lifecycle_and_audit() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let fixture = include_str!("../../../.github/workflows/deep-ci.yml");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/deep-ci.yml"),
        fixture.as_bytes(),
        &repository_policy,
    )
    .expect("the bounded deep CI workflow should pass");

    for timeout_minutes in [89, 91, 120] {
        let invalid = workflow_with_job_timeout(fixture, "stress", timeout_minutes);
        let error = policy::validate_workflow_bytes(
            &root,
            Path::new(".github/workflows/deep-ci.yml"),
            &invalid,
            &repository_policy,
        )
        .expect_err("a changed stress job bound must fail");
        assert!(
            error
                .to_string()
                .contains("deep CI stress timeout does not cover the complete cold workload"),
            "unexpected workflow policy error: {error}"
        );
    }
}

#[test]
fn dependabot_requires_each_independent_dependency_surface() {
    let exact = include_str!("../../../.github/dependabot.yml").replace("\r\n", "\n");
    policy::validate_dependabot_bytes(exact.as_bytes())
        .expect("the exact Dependabot dependency matrix should pass");

    let fuzz_update = r#"  - package-ecosystem: cargo
    directory: /fuzz
    schedule:
      interval: weekly
    open-pull-requests-limit: 3
"#;
    let cases = [
        (fuzz_update, ""),
        ("    directory: /fuzz\n", "    directory: /\n"),
        (
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n",
            "    directory: /fuzz\n    schedule:\n      interval: daily\n",
        ),
        (
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 3\n",
            "    directory: /fuzz\n    schedule:\n      interval: weekly\n    open-pull-requests-limit: 4\n",
        ),
    ];

    for (expected, replacement) in cases {
        let invalid = exact.replacen(expected, replacement, 1);
        assert_ne!(invalid, exact, "Dependabot fixture mutation must apply");
        policy::validate_dependabot_bytes(invalid.as_bytes())
            .expect_err("a Dependabot dependency-surface regression must be rejected");
    }
}

#[test]
fn fuzz_dependency_cache_keys_require_the_fuzz_lockfile() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let relative = ".github/workflows/deep-ci.yml";
    let exact = std::fs::read_to_string(root.join(relative))
        .expect("workflow fixture should be readable")
        .replace("\r\n", "\n");
    let invalid = exact.replacen("'fuzz/Cargo.lock', ", "", 1);
    assert_ne!(invalid, exact, "fuzz lockfile mutation must apply");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(relative),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("a fuzz dependency cache key without its lockfile must fail");
    assert!(
        error
            .to_string()
            .contains("fuzz manifest must include its lockfile"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn windows_arm_native_matrix_entries_are_structurally_required() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    for (relative, job, fixture) in [(
        ".github/workflows/ci.yml",
        "CI native",
        include_str!("../../../.github/workflows/ci.yml"),
    )] {
        let exact = fixture.replace("\r\n", "\n");
        let windows_rows = "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-11-arm\n";
        for replacement in [
            "          - id: windows-x64\n            runner: windows-2025\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-arm64\n            runner: windows-2025\n",
            "          - id: windows-arm64\n            runner: windows-11-arm\n",
            "          - id: windows-x64\n            runner: windows-11-arm\n          - id: windows-arm64\n            runner: windows-2025\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-x64\n            runner: windows-11-arm\n",
            "          - id: windows-x64\n            runner: windows-2025\n          - id: windows-other\n            runner: windows-11-arm\n",
        ] {
            let invalid = exact.replacen(windows_rows, replacement, 1);
            assert_ne!(invalid, exact, "{job} mutation must apply");
            let error = policy::validate_workflow_bytes(
                &root,
                Path::new(relative),
                invalid.as_bytes(),
                &repository_policy,
            )
            .expect_err("Windows ARM matrix regression must be rejected");
            assert!(
                error
                    .to_string()
                    .contains(&format!("{job} matrix entries differ")),
                "unexpected {job} policy error: {error}"
            );
        }
        let planted = exact
            .replacen(
                windows_rows,
                "          - id: windows-x64\n            runner: windows-2025\n",
                1,
            )
            .replacen("    name: ", "    name: windows-arm64 / ", 1);
        let planted_error = policy::validate_workflow_bytes(
            &root,
            Path::new(relative),
            planted.as_bytes(),
            &repository_policy,
        )
        .expect_err("Windows ARM text outside the matrix must not satisfy policy");
        assert!(
            planted_error
                .to_string()
                .contains(&format!("{job} matrix entries differ")),
            "unexpected planted {job} policy error: {planted_error}"
        );
        let direct_runner = exact.replacen(
            "    runs-on: ${{ matrix.runner }}\n",
            "    runs-on: windows-11-arm\n",
            1,
        );
        let runner_error = policy::validate_workflow_bytes(
            &root,
            Path::new(relative),
            direct_runner.as_bytes(),
            &repository_policy,
        )
        .expect_err("matrix jobs must select the typed runner field");
        assert!(
            runner_error
                .to_string()
                .contains(&format!("{job} runner selection differs")),
            "unexpected {job} runner policy error: {runner_error}"
        );
    }
    // The typed planner supplies the complete stress matrix. Verify
    // both layouts together retain the independent native Windows runners.
    use memcordon_ci::performance_plan::{Layout, PerformancePlan};
    let plan = PerformancePlan::read(&root).unwrap();
    let mut cells = plan.stress_cells(Layout::Serial).unwrap();
    cells.extend(plan.stress_cells(Layout::Parallel).unwrap());
    let windows = cells
        .iter()
        .filter(|cell| {
            cell["id"]
                .as_str()
                .is_some_and(|id| id.starts_with("windows-"))
        })
        .map(|cell| {
            (
                cell["id"].as_str().unwrap(),
                cell["runner"].as_str().unwrap(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert_eq!(
        windows,
        std::collections::BTreeMap::from([
            ("windows-x64", "windows-2025"),
            ("windows-arm64", "windows-11-arm"),
        ])
    );
    let mut missing = plan.clone();
    missing
        .stress
        .retain(|entry| entry.platform != "windows-arm64");
    assert!(missing.validate().is_err());
    let mut duplicate = plan.clone();
    let arm = duplicate
        .stress
        .iter_mut()
        .find(|entry| entry.platform == "windows-arm64")
        .unwrap();
    arm.platform = "windows-x64".into();
    assert!(duplicate.validate().is_err());
    let deep: serde_yaml::Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for (job, output) in [
        ("stress", "combined"),
        ("stress-packages", "split"),
        ("stress-lifecycle", "split"),
    ] {
        assert_eq!(
            deep["jobs"][job]["strategy"]["matrix"]["include"].as_str(),
            Some(format!("${{{{ fromJSON(needs.performance-plan.outputs.{output}) }}}}").as_str())
        );
    }
}

#[test]
fn action_input_boolean_value_selection_is_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/ci.yml").replace("\r\n", "\n");
    let invalid = exact.replacen(
        "          persist-credentials: false\n",
        "          ref: ${{ inputs.tag || github.ref }}\n          persist-credentials: false\n",
        1,
    );
    assert_ne!(invalid, exact, "checkout fixture mutation must apply");
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(CI_WORKFLOW_PATH),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("Boolean value selection in an action input must be rejected");
    assert!(
        error
            .to_string()
            .contains("workflow action input may not select values with Boolean operators"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn named_github_environments_are_rejected() {
    let root = repository_root();
    let exact = include_str!("../../../.github/workflows/ci.yml").replace("\r\n", "\n");
    let invalid = exact.replacen(
        "    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n",
        "    runs-on: ubuntu-24.04\n    environment: release\n    timeout-minutes: 30\n",
        1,
    );
    assert_ne!(invalid, exact, "environment fixture mutation must apply");
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let error = policy::validate_workflow_bytes(
        &root,
        Path::new(CI_WORKFLOW_PATH),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("named GitHub environments must be rejected");
    assert!(
        error
            .to_string()
            .contains("named GitHub environments are forbidden"),
        "unexpected policy error: {error}"
    );
}

#[test]
fn certification_runner_regressions_are_rejected_structurally() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let path = Path::new(".github/workflows/backend-certification.yml");
    let backend: serde_yaml::Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    let cases = [
        (
            "standard-linux",
            "[self-hosted, memcordon, linux, x64, cgroup-v2, ephemeral]",
        ),
        (
            "standard-windows",
            "[self-hosted, memcordon, windows, x64, job-object, ephemeral]",
        ),
        ("standard-linux", "ubuntu-latest"),
        ("standard-windows", "windows-latest"),
    ];
    for (job, replacement) in cases {
        let mut invalid = backend.clone();
        invalid["jobs"][job]["runs-on"] = serde_yaml::from_str(replacement).unwrap();
        assert_ne!(invalid, backend, "native runner mutation must apply: {job}");
        policy::validate_workflow_bytes(
            &root,
            path,
            serde_yaml::to_string(&invalid).unwrap().as_bytes(),
            &repository_policy,
        )
        .expect_err("noncanonical certification runner must be rejected");
    }
}

#[test]
fn windows_working_source_jobs_disable_eol_conversion_before_checkout() {
    let root = repository_root();
    let repository_policy = config::policy(&root).unwrap();
    let path = Path::new(".github/workflows/backend-certification.yml");
    let bytes = include_bytes!("../../../.github/workflows/backend-certification.yml");
    policy::validate_workflow_bytes(&root, path, bytes, &repository_policy).unwrap();
    let workflow: serde_yaml::Value = serde_yaml::from_slice(bytes).unwrap();
    for job in [
        "windows-payload-x64",
        "windows-payload-arm64",
        "windows-installed-x64",
        "windows-installed-arm64",
    ] {
        let steps = workflow["jobs"][job]["steps"].as_sequence().unwrap();
        assert_eq!(
            steps.first().unwrap()["run"].as_str(),
            Some("git config --global core.autocrlf false"),
            "{job} must configure checkout before source materialization",
        );
        assert!(
            steps[1]["uses"]
                .as_str()
                .unwrap()
                .starts_with("actions/checkout@")
        );
    }
}

#[test]
fn stress_uploads_retain_hidden_failure_diagnostics() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let path = Path::new(".github/workflows/deep-ci.yml");
    let fixture = include_str!("../../../.github/workflows/deep-ci.yml");
    let normalized = text_fixture::canonical_lf_utf8(fixture.as_bytes(), "workflow fixture")
        .expect("workflow fixture must be UTF-8 text with a trailing newline");
    let invalid = normalized.replacen("          include-hidden-files: true\n", "", 1);
    assert_ne!(
        invalid, normalized,
        "hidden-diagnostic fixture mutation must apply"
    );
    policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
        .expect_err("actual stress job must upload hidden failure diagnostics");
}

#[test]
fn deep_and_backend_workflows_require_unfiltered_push_and_manual_dispatch() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let expected_trigger = "on:\n  push:\n  workflow_dispatch:\n";
    let branch_filtered_push = "on:\n  push:\n    branches:\n      - main\n  workflow_dispatch:\n";
    let tag_filtered_push = "on:\n  push:\n    tags:\n      - release\n  workflow_dispatch:\n";
    let path_filtered_push = "on:\n  push:\n    paths:\n      - crates/**\n  workflow_dispatch:\n";
    let ignored_path_push =
        "on:\n  push:\n    paths-ignore:\n      - docs/**\n  workflow_dispatch:\n";
    let missing_dispatch = "on:\n  push:\n";
    let dispatch_inputs =
        "on:\n  push:\n  workflow_dispatch:\n    inputs:\n      reason:\n        required: false\n";
    let cases = [
        (
            Path::new(".github/workflows/deep-ci.yml"),
            include_str!("../../../.github/workflows/deep-ci.yml"),
            "on:\n  schedule:\n    - cron: \"17 3 * * 1\"\n  workflow_dispatch:\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            include_str!("../../../.github/workflows/backend-certification.yml"),
            "on:\n  schedule:\n    - cron: \"43 4 * * 3\"\n  workflow_dispatch:\n",
        ),
    ];

    for (path, fixture, scheduled_trigger) in cases {
        let exact = fixture.replace("\r\n", "\n");
        policy::validate_workflow_bytes(&root, path, exact.as_bytes(), &repository_policy)
            .expect("exact push and manual workflow triggers should pass");
        for replacement in [
            scheduled_trigger,
            branch_filtered_push,
            tag_filtered_push,
            path_filtered_push,
            ignored_path_push,
            missing_dispatch,
            dispatch_inputs,
        ] {
            let invalid = exact.replacen(expected_trigger, replacement, 1);
            assert_ne!(
                invalid, exact,
                "workflow trigger fixture mutation must apply: {path:?}"
            );
            policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
                .expect_err("workflow trigger regression must be rejected");
        }
    }

    let deep = include_str!("../../../.github/workflows/deep-ci.yml").replace("\r\n", "\n");
    let backend =
        include_str!("../../../.github/workflows/backend-certification.yml").replace("\r\n", "\n");
    let concurrency_cases = [
        (
            Path::new(".github/workflows/deep-ci.yml"),
            deep.as_str(),
            "  group: deep-ci-${{ github.ref }}\n",
            "  group: deep-ci-all\n",
        ),
        (
            Path::new(".github/workflows/deep-ci.yml"),
            deep.as_str(),
            "  cancel-in-progress: true\n",
            "  cancel-in-progress: false\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "  group: backend-certification-${{ github.ref }}\n",
            "  group: backend-certification-all\n",
        ),
        (
            Path::new(".github/workflows/backend-certification.yml"),
            backend.as_str(),
            "  cancel-in-progress: false\n",
            "  cancel-in-progress: true\n",
        ),
    ];
    for (path, fixture, exact, replacement) in concurrency_cases {
        let invalid = fixture.replacen(exact, replacement, 1);
        assert_ne!(
            invalid, fixture,
            "workflow concurrency fixture mutation must apply: {path:?}"
        );
        policy::validate_workflow_bytes(&root, path, invalid.as_bytes(), &repository_policy)
            .expect_err("workflow concurrency regression must be rejected");
    }
}

#[test]
fn ci_concurrency_separates_trigger_methods() {
    let root = repository_root();
    let repository_policy = config::policy(&root).expect("repository policy should parse");
    let exact = include_str!("../../../.github/workflows/ci.yml").replace("\r\n", "\n");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        exact.as_bytes(),
        &repository_policy,
    )
    .expect("CI concurrency should separate trigger methods");

    let invalid = exact.replacen("-${{ github.event_name }}", "", 1);
    assert_ne!(invalid, exact, "CI concurrency fixture mutation must apply");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/ci.yml"),
        invalid.as_bytes(),
        &repository_policy,
    )
    .expect_err("CI concurrency without the trigger method must be rejected");
}

#[test]
fn artifact_upload_action_retries_exactly_and_fails_closed() {
    let exact =
        include_str!("../../../.github/actions/upload-artifact/action.yml").replace("\r\n", "\n");
    policy::validate_upload_artifact_action_bytes(exact.as_bytes())
        .expect("the bounded artifact upload action should pass");

    let retry_two = exact
        .find("    - id: retry-two\n")
        .expect("final retry fixture must be present");
    let missing_final = &exact[..retry_two];
    policy::validate_upload_artifact_action_bytes(missing_final.as_bytes())
        .expect_err("a missing final retry must be rejected");

    for (name, source, replacement) in [
        (
            "pin",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/upload-artifact@0000000000000000000000000000000000000000",
        ),
        (
            "retry condition",
            "steps.initial.outcome == 'failure'",
            "steps.initial.conclusion == 'failure'",
        ),
        (
            "retry overwrite",
            "        overwrite: true\n",
            "        overwrite: false\n",
        ),
        (
            "input forwarding",
            "        path: ${{ inputs.path }}\n",
            "        path: ${{ inputs.name }}\n",
        ),
        (
            "final failure",
            "    - id: retry-two\n      if:",
            "    - id: retry-two\n      continue-on-error: true\n      if:",
        ),
    ] {
        let invalid = exact.replacen(source, replacement, 1);
        assert_ne!(invalid, exact, "{name} mutation must apply");
        policy::validate_upload_artifact_action_bytes(invalid.as_bytes())
            .expect_err("artifact upload retry mutation must be rejected");
    }
}

#[test]
fn every_workflow_upload_uses_the_bounded_action() {
    let workflows = [
        include_str!("../../../.github/workflows/ci.yml"),
        include_str!("../../../.github/workflows/deep-ci.yml"),
        include_str!("../../../.github/workflows/backend-certification.yml"),
    ];
    let local = "uses: ./.github/actions/upload-artifact";
    let direct = "uses: actions/upload-artifact@";
    let count: usize = workflows
        .iter()
        .map(|workflow| {
            assert!(
                !workflow.contains(direct),
                "workflow bypasses the bounded artifact upload action"
            );
            workflow.matches(local).count()
        })
        .sum();
    assert!(
        count >= 4,
        "ordinary workflow artifact upload coverage regressed"
    );
}
