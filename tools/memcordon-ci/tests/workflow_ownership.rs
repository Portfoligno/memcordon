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
    let error = validate(RELEASE, &missing_job).unwrap_err();
    assert!(error.to_string().contains("assembly absent"), "{error}");

    let mut missing_output = fixture(RELEASE);
    missing_output["jobs"]["assemble"]["outputs"]
        .as_mapping_mut()
        .unwrap()
        .remove(Value::String("candidate-artifact-id".into()));
    let error = validate(RELEASE, &missing_output).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("assembly must expose the existing candidate artifact ID"),
        "{error}"
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
    for suite in ["policy", "quality", "msrv", "supply-chain"] {
        let mut changed = exact.clone();
        let command = ["./target/ci/release/memcordon-ci suite", suite].join(" ");
        let steps = changed["jobs"]["source-checks"]["steps"]
            .as_sequence_mut()
            .unwrap();
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
    for family in ["miri", "fuzz"] {
        let mut changed = exact.clone();
        changed["jobs"][family]["strategy"]["matrix"]["shard"][1] = Value::String("first".into());
        assert!(
            validate(RELEASE, &changed).is_err(),
            "duplicate {family} half"
        );
        let mut changed = exact.clone();
        let steps = changed["jobs"][family]["steps"].as_sequence_mut().unwrap();
        steps.retain(|step| step["id"].as_str() != Some("second"));
        assert!(
            validate(RELEASE, &changed).is_err(),
            "removed {family} second execution"
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
    for mutation in [
        "release-suite",
        "head-checkout",
        "generic-cache",
        "skip-native",
    ] {
        let mut changed = exact.clone();
        let native = &mut changed["jobs"]["native"];
        if mutation == "skip-native" {
            native["if"] = Value::String("github.event_name != 'push'".into());
        } else {
            let steps = native["steps"].as_sequence_mut().unwrap();
            let step = match mutation {
                "release-suite" => steps
                    .iter_mut()
                    .find(|step| step["run"] == "./target/ci/release/memcordon-ci suite native")
                    .unwrap(),
                "head-checkout" => steps
                    .iter_mut()
                    .find(|step| {
                        step["uses"]
                            .as_str()
                            .is_some_and(|uses| uses.starts_with("actions/checkout@"))
                    })
                    .unwrap(),
                "generic-cache" => steps
                    .iter_mut()
                    .find(|step| step["id"] == "compiled-context")
                    .unwrap(),
                _ => unreachable!(),
            };
            match mutation {
                "release-suite" => step["run"] = Value::String("./target/ci/release/memcordon-ci suite backend-macos-watchdog".into()),
                "head-checkout" => step["with"]["ref"] = Value::String("${{ github.event.pull_request.head.sha }}".into()),
                "generic-cache" => step["run"] = Value::String("./target/ci/release/memcordon-ci ci cache-context --purpose native --shard complete".into()),
                _ => unreachable!(),
            }
        }
        assert!(validate(CI, &changed).is_err(), "{mutation}");
    }
}

#[test]
fn standalone_routing_cannot_suppress_stress_optional_work_or_failure_assessment() {
    for (path, planner) in [
        (DEEP, "performance-plan"),
        (BACKEND, "macos-performance-plan"),
    ] {
        let exact = fixture(path);
        let mut changed = exact.clone();
        changed["jobs"][planner]["outputs"]["standalone-common"] = Value::String("false".into());
        assert!(validate(path, &changed).is_err());
        let mut changed = exact.clone();
        changed["jobs"][planner]["steps"]
            .as_sequence_mut()
            .unwrap()
            .retain(|step| step["id"] != "scope");
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
    for condition in [
        "always()",
        "success()",
        "needs.macos-combined.result == 'success'",
    ] {
        let mut changed = backend.clone();
        set_condition(&mut changed, "macos-assessment", condition);
        assert!(
            validate(BACKEND, &changed).is_err(),
            "assessment {condition}"
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
fn release_native_cache_and_phase_retention_cannot_fall_back_to_old_wrapper() {
    let exact = fixture(RELEASE);
    for mutation in [
        "generic-cache",
        "missing-phase",
        "missing-raw",
        "ignore-owner-failure",
    ] {
        let mut changed = exact.clone();
        let steps = changed["jobs"]["native-macos-arm64"]["steps"]
            .as_sequence_mut()
            .unwrap();
        match mutation {
            "generic-cache" => steps.iter_mut().find(|step| step["id"] == "cache").unwrap()["run"] = Value::String("./target/ci/release/memcordon-ci ci cache-context --purpose native --shard complete".into()),
            "ignore-owner-failure" => steps.iter_mut().find(|step| step["id"] == "build").unwrap()["continue-on-error"] = Value::Bool(true),
            _ => {
                let diagnostic = steps.iter_mut().find(|step| step["name"] == "Retain bounded preparation diagnostics").unwrap();
                let omitted = if mutation == "missing-phase" { "target/ci/reports/release-macos-native.json" } else { "target/ci/reports/memcordon-macos-acceptance-*" };
                diagnostic["with"]["path"] = Value::String(diagnostic["with"]["path"].as_str().unwrap().lines().filter(|path| *path != omitted).collect::<Vec<_>>().join("\n"));
            }
        }
        assert!(validate(RELEASE, &changed).is_err(), "{mutation}");
    }
}

#[test]
fn actual_release_native_owner_still_executes_optimized_tests_and_complete_backend() {
    let source = include_str!("../src/release/target.rs");
    assert!(source.contains("for phase in crate::native_test_plan::commands(true)"));
    for backend in [
        "backend-linux-cgroup",
        "backend-windows-job",
        "backend-macos-watchdog",
    ] {
        assert!(source.contains(backend));
    }
    assert!(source.contains(".args([\"suite\", backend])"));
    let suites = include_str!("../src/suites.rs");
    assert!(suites.contains("Suite::Native => native(root, &toolchains.stable, false)"));
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

#[test]
fn optional_private_linux_preserves_installed_channels_and_extra_native_cases() {
    let source = include_str!("../src/release/linux_installed_consumer.rs");
    let working = source
        .split_once("pub fn run_working(")
        .unwrap()
        .1
        .split_once("fn compile_native_cases(")
        .unwrap()
        .0;
    for required in [
        "features: vec![\"sealed-runtime\".into(), \"private-tcp\".into()]",
        "binaries: vec![\"memcordon\".into(), \"memcordon-sealed-agent\".into()]",
        "memcordon-sealed-agent.service",
        "memcordon-sealed-agent.socket",
        "memcordon-sealed-launcher.service",
        "memcordon-sealed-launcher.socket",
        "memcordon-sealed-network-launcher.service",
        "memcordon-sealed-network-launcher.socket",
        "memcordon.conf",
        "target::build_selected(root, &source, &distribution, &target_directory)?",
        "super::installed_consumer::run(",
        "run_native_observer_cases(root, &destination.join(\"native-observer\"))?",
    ] {
        assert!(
            working.contains(required),
            "retained private selection/call: {required}"
        );
    }
    assert!(source.contains(
        "installed_owner_loss_cases(payload, work.path(), output, group, &current_contracts)?"
    ));
    let native = source
        .split_once("fn run_native_observer_cases(")
        .unwrap()
        .1;
    for required in [
        "native_private_frontend_loss_retires_exact_guarded_cgroup",
        "native_private_worker_loss_retires_exact_guarded_cgroup",
        "native_private_guardian_loss_never_fabricates_cgroup_retirement",
        ".args([\"--exact\", test, \"--ignored\", \"--test-threads=1\"])",
        "require_exact_standard_test_success(&observed.stdout, test)?",
    ] {
        assert!(
            native.contains(required),
            "retained native case: {required}"
        );
    }
    let installed = include_str!("../src/release/installed_consumer.rs");
    for channel in [
        "InstalledChannel::NativeBundle",
        "InstalledChannel::CargoPackage",
    ] {
        assert!(installed.contains(channel));
    }
}
