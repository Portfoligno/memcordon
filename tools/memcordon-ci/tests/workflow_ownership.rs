use std::path::{Path, PathBuf};

use memcordon_ci::{config, policy, workflow_scope};
use serde_yaml::Value;

const CI: &str = ".github/workflows/ci.yml";
const DEEP: &str = ".github/workflows/deep-ci.yml";
const BACKEND: &str = ".github/workflows/backend-certification.yml";
const RELEASE: &str = ".github/workflows/release.yml";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn validate(path: &str, document: &Value) -> memcordon_ci::Result<()> {
    let root = root();
    policy::validate_workflow_bytes(
        &root,
        Path::new(path),
        serde_yaml::to_string(document).unwrap().as_bytes(),
        &config::policy(&root).unwrap(),
    )
}

fn fixture(path: &str) -> Value {
    let document = serde_yaml::from_slice(&std::fs::read(root().join(path)).unwrap()).unwrap();
    validate(path, &document).unwrap_or_else(|error| panic!("actual workflow {path}: {error}"));
    document
}

fn set_condition(document: &mut Value, job: &str, condition: &str) {
    document["jobs"][job]["if"] = Value::String(condition.into());
}

#[test]
fn rehearsal_helper_rejects_missing_assembly_and_candidate_output() {
    let mut missing_job = fixture(RELEASE);
    missing_job["jobs"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("assemble".into()));
    assert!(missing_job["jobs"]["assemble"].is_null());
    assert!(
        validate(RELEASE, &missing_job).is_err(),
        "missing required assembly must be rejected before any legacy projection"
    );

    let mut missing_output = fixture(RELEASE);
    missing_output["jobs"]["assemble"]["outputs"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("candidate-artifact-id".into()));
    assert!(missing_output["jobs"]["assemble"]["outputs"]["candidate-artifact-id"].is_null());
    assert!(
        validate(RELEASE, &missing_output).is_err(),
        "missing candidate artifact route must be rejected"
    );
}

#[test]
fn real_release_trigger_matches_scope_and_keeps_all_branch_preparation() {
    let exact = fixture(RELEASE);
    assert_eq!(
        exact["on"]["push"]["tags"][0],
        workflow_scope::RELEASE_TAG_FILTER
    );
    for field in ["branches", "tags"] {
        let mut changed = exact.clone();
        changed["on"]["push"]
            .as_mapping_mut()
            .unwrap()
            .remove(Value::String(field.into()));
        assert!(validate(RELEASE, &changed).is_err(), "removed {field}");
    }
    for (field, value) in [
        ("branches", "[main]"),
        ("tags", "['v*']"),
        ("paths", "['src/**']"),
        ("branches-ignore", "[develop]"),
    ] {
        let mut changed = exact.clone();
        changed["on"]["push"][field] = serde_yaml::from_str(value).unwrap();
        assert!(validate(RELEASE, &changed).is_err(), "changed {field}");
    }
    for (job, suite) in [
        ("source-checks", "release-quality-compiler"),
        ("source-docs", "quality-documentation"),
        ("msrv", "msrv"),
        ("supply-chain-audit", "supply-audit"),
        ("supply-chain-deny", "supply-deny"),
    ] {
        let mut changed = exact.clone();
        let command = ["./.release/tool/memcordon-ci ci segment", suite].join(" ");
        let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let index = steps
            .iter()
            .position(|step| step["run"].as_str() == Some(command.as_str()))
            .unwrap();
        steps.remove(index);
        assert!(
            validate(RELEASE, &changed).is_err(),
            "removed executing owner {suite}"
        );
    }
    let mut changed = exact.clone();
    changed["jobs"]["select"]["steps"]
        .as_sequence_mut()
        .unwrap()
        .retain(|step| {
            !step["run"]
                .as_str()
                .is_some_and(|run| run.contains("release check-selected-inputs"))
        });
    assert!(
        validate(RELEASE, &changed).is_err(),
        "removed selected source/notes owner"
    );
    for family in ["miri", "fuzz"] {
        let mut changed = exact.clone();
        changed["jobs"][family]["strategy"]["matrix"]["shard"][1] = Value::String("first".into());
        assert!(
            validate(RELEASE, &changed).is_err(),
            "invalid {family} quarter"
        );
        let mut changed = exact.clone();
        let steps = changed["jobs"][family]["steps"].as_sequence_mut().unwrap();
        steps.retain(|step| {
            !step["run"]
                .as_str()
                .is_some_and(|run| run.contains(" ci segment ") && run.contains("quarter-two"))
        });
        assert!(
            validate(RELEASE, &changed).is_err(),
            "removed {family} quarter-two execution"
        );
    }
    for missing in [
        "native-macos-x64",
        "native-macos-arm64",
        "candidate-windows-x64-cargo",
        "assemble",
    ] {
        let mut changed = exact.clone();
        changed["jobs"]
            .as_mapping_mut()
            .unwrap()
            .remove(Value::String(missing.into()));
        assert!(validate(RELEASE, &changed).is_err(), "removed {missing}");
    }
}

#[test]
fn ci_keeps_debug_matrix_and_real_pr_merge_and_dispatch_work() {
    let exact = fixture(CI);
    for job in [
        "policy",
        "quality",
        "msrv",
        "supply-chain",
        "macos-deadline",
    ] {
        for condition in [
            "false",
            "github.event_name == 'workflow_dispatch'",
            "github.ref == 'refs/heads/main'",
        ] {
            let mut changed = exact.clone();
            set_condition(&mut changed, job, condition);
            assert!(validate(CI, &changed).is_err(), "{job}: {condition}");
        }
    }
    let mut changed = exact.clone();
    changed["jobs"]["native"]["strategy"]["matrix"]["include"]
        .as_sequence_mut()
        .unwrap()
        .pop();
    assert!(validate(CI, &changed).is_err());
    for mutation in ["release-suite", "head-checkout", "skip-native"] {
        let mut changed = exact.clone();
        let native = &mut changed["jobs"]["native"];
        if mutation == "skip-native" {
            native["if"] = Value::String("github.event_name != 'push'".into());
        } else {
            let steps = native["steps"].as_sequence_mut().unwrap();
            let step = match mutation {
                "release-suite" => steps
                    .iter_mut()
                    .find(|step| {
                        step["run"]
                            == "./target/ci-runtime/current/memcordon-ci ci segment native-execute"
                    })
                    .unwrap(),
                "head-checkout" => steps
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                    })
                    .unwrap(),
                _ => unreachable!(),
            };
            match mutation {
                "release-suite" => {
                    step["run"] = Value::String(
                        "./target/ci/release/memcordon-ci suite backend-macos-watchdog".into(),
                    )
                }
                "head-checkout" => {
                    step["with"]["ref"] =
                        Value::String("${{ github.event.pull_request.head.sha }}".into())
                }
                _ => unreachable!(),
            }
        }
        assert!(validate(CI, &changed).is_err(), "{mutation}");
    }
}

#[test]
fn standalone_routing_cannot_suppress_stress_optional_work_or_failure_assessment() {
    for (path, planner, feedback) in [
        (DEEP, "performance-plan", " --feedback deep-plan"),
        (
            BACKEND,
            "macos-performance-plan",
            " --feedback backend-plan",
        ),
    ] {
        let exact = fixture(path);
        let mut changed = exact.clone();
        changed["jobs"][planner]["outputs"]["standalone-common"] = Value::String("false".into());
        assert!(validate(path, &changed).is_err());
        let mut changed = exact.clone();
        for step in changed["jobs"][planner]["steps"].as_sequence_mut().unwrap() {
            if let Some(command) = step["run"]
                .as_str()
                .and_then(|command| command.strip_suffix(feedback))
                .map(str::to_owned)
            {
                step["run"] = Value::String(command);
            }
        }
        assert_ne!(
            changed, exact,
            "scope feedback mutation must change {planner}"
        );
        assert!(validate(path, &changed).is_err());
    }
    let deep = fixture(DEEP);
    for job in ["miri", "fuzz"] {
        let mut changed = deep.clone();
        set_condition(&mut changed, job, "github.event_name != 'push'");
        assert!(
            validate(DEEP, &changed).is_err(),
            "uncovered tags lose {job}"
        );
    }
    for job in ["stress", "stress-packages", "stress-lifecycle"] {
        let mut changed = deep.clone();
        set_condition(
            &mut changed,
            job,
            "needs.performance-plan.outputs.standalone-common == 'true'",
        );
        assert!(validate(DEEP, &changed).is_err(), "stress gated by scope");
    }
    let backend = fixture(BACKEND);
    for job in [
        "windows-payload-x64",
        "windows-payload-arm64",
        "windows-installed-x64",
        "windows-installed-arm64",
        "private-linux",
    ] {
        let mut changed = backend.clone();
        set_condition(
            &mut changed,
            job,
            "needs.macos-performance-plan.outputs.standalone-common == 'true'",
        );
        assert!(
            validate(BACKEND, &changed).is_err(),
            "optional {job} gated by common scope"
        );
        let mut changed = backend.clone();
        changed["jobs"][job]["needs"] = Value::String("macos-performance-plan".into());
        assert!(
            validate(BACKEND, &changed).is_err(),
            "optional {job} waits for common planner"
        );
    }
    for job in [
        "standard-linux",
        "standard-windows",
        "standard-windows-arm64",
    ] {
        let mut changed = backend.clone();
        set_condition(&mut changed, job, "github.event_name != 'push'");
        assert!(validate(BACKEND, &changed).is_err());
    }
}

#[test]
fn release_native_phase_and_diagnostic_retention_cannot_fall_back_to_old_wrapper() {
    let exact = fixture(RELEASE);
    for mutation in ["missing-phase", "missing-raw", "ignore-owner-failure"] {
        let mut changed = exact.clone();
        let steps = changed["jobs"]["native-macos-arm64"]["steps"]
            .as_sequence_mut()
            .unwrap();
        match mutation {
            "ignore-owner-failure" => {
                steps.iter_mut().find(|step| step["id"] == "build").unwrap()["continue-on-error"] =
                    Value::Bool(true)
            }
            _ => {
                let diagnostic = steps
                    .iter_mut()
                    .find(|step| step["name"] == "Retain bounded preparation diagnostics")
                    .unwrap();
                let omitted = if mutation == "missing-phase" {
                    "target/ci/reports/release-macos-native.json"
                } else {
                    "target/ci/reports/memcordon-macos-acceptance-*"
                };
                diagnostic["with"]["path"] = Value::String(
                    diagnostic["with"]["path"]
                        .as_str()
                        .unwrap()
                        .lines()
                        .filter(|path| *path != omitted)
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        }
        assert!(validate(RELEASE, &changed).is_err(), "{mutation}");
    }
}

#[test]
fn actual_release_native_owner_still_executes_optimized_tests_and_complete_backend() {
    let source = include_str!("../src/release/target.rs");
    assert!(source.contains("crate::native_test_plan::commands_with_failure(true, failure_mode)"));
    assert!(source.contains(".bounded_until(operation_deadline)"));
    assert!(source.contains("crate::preparation::complete_owned_pair("));
    assert!(
        source
            .contains("compile_native_pair(root, selected, distribution, prepared).into_result()?")
    );
    assert!(source.contains(
        "for phase in crate::native_test_plan::commands_with_failure(true, failure_mode)"
    ));
    for backend in [
        "backend-linux-cgroup",
        "backend-windows-job",
        "backend-macos-watchdog",
    ] {
        assert!(source.contains(backend));
    }
    assert!(source.contains(".args([\"suite\", backend])"));
    let suites = include_str!("../src/suites.rs");
    assert!(suites.contains("Suite::Native => native("));
    assert!(
        suites.contains("Suite::BackendMacosWatchdog => release_macos(root, &toolchains.stable)")
    );
    let native = suites
        .split_once("pub fn release_macos_native(")
        .unwrap()
        .1
        .split_once("pub fn release_macos_acceptance(")
        .unwrap()
        .0;
    assert!(native.contains("macos_deadline(root, stable)?"));
}
