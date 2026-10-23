use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::Path;

fn check(file: &str, value: &Value) -> memcordon_ci::Result<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    policy::validate_workflow_bytes(
        &root,
        Path::new(file),
        serde_yaml::to_string(value).unwrap().as_bytes(),
        &config::policy(&root).unwrap(),
    )
}

#[test]
fn exact_non_release_workflows_and_shard_mutations() {
    for (file, source) in [
        (
            ".github/workflows/ci.yml",
            include_str!("../../../.github/workflows/ci.yml"),
        ),
        (
            ".github/workflows/deep-ci.yml",
            include_str!("../../../.github/workflows/deep-ci.yml"),
        ),
        (
            ".github/workflows/backend-certification.yml",
            include_str!("../../../.github/workflows/backend-certification.yml"),
        ),
    ] {
        let exact: Value = serde_yaml::from_str(source).unwrap();
        check(file, &exact).unwrap_or_else(|error| panic!("{file}: {error}"));
    }
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for family in ["miri", "fuzz"] {
        let mut missing = exact.clone();
        missing["jobs"][family]["strategy"]["matrix"]["shard"]
            .as_sequence_mut()
            .unwrap()
            .pop();
        assert!(check(".github/workflows/deep-ci.yml", &missing).is_err());
        let mut duplicate = exact.clone();
        let shards = duplicate["jobs"][family]["strategy"]["matrix"]["shard"]
            .as_sequence_mut()
            .unwrap();
        shards[1] = shards[0].clone();
        assert!(check(".github/workflows/deep-ci.yml", &duplicate).is_err());
        let mut wrong = exact.clone();
        let driver_owner = if family == "fuzz" {
            "fuzz-setup"
        } else {
            family
        };
        let steps = wrong["jobs"][driver_owner]["steps"]
            .as_sequence_mut()
            .unwrap();
        let prepare = steps
            .iter_mut()
            .find(|step| step["id"] == "driver-cold-build")
            .unwrap();
        prepare["run"] = Value::String(
            "rustup run 1.97.1 cargo build --locked --release --target-dir target/ci -p memcordon-core"
                .into(),
        );
        assert!(check(".github/workflows/deep-ci.yml", &wrong).is_err());
        let mut substitution = exact.clone();
        let steps = substitution["jobs"][family]["steps"]
            .as_sequence_mut()
            .unwrap();
        let suite = steps
            .iter_mut()
            .find(|step| {
                step["id"]
                    == if family == "miri" {
                        "miri-quarter-one"
                    } else {
                        "fuzz-one"
                    }
            })
            .unwrap();
        suite["run"] = Value::String("./target/ci/release/memcordon-ci suite native".into());
        assert!(check(".github/workflows/deep-ci.yml", &substitution).is_err());
    }
}

#[test]
fn windows_native_architecture_runner_and_environment_boundaries_are_exact() {
    let exact: Value = serde_yaml::from_str(include_str!(
        "../../../.github/workflows/backend-certification.yml"
    ))
    .unwrap();
    for (job, wrong_runner) in [
        ("standard-windows", "windows-11-arm"),
        ("standard-windows-arm64", "windows-2025"),
    ] {
        let mut wrong = exact.clone();
        wrong["jobs"][job]["runs-on"] = Value::String(wrong_runner.into());
        assert!(check(".github/workflows/backend-certification.yml", &wrong).is_err());
        let mut changed = exact.clone();
        let steps = changed["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let suite = steps
            .iter_mut()
            .find(|step| step["id"] == "backend-run")
            .unwrap();
        suite["env"] = serde_yaml::from_str("CARGO_TARGET_DIR: target/ci/incorrect").unwrap();
        assert!(check(".github/workflows/backend-certification.yml", &changed).is_err());
    }
}

#[test]
fn duplicate_ordinary_build_controls_cannot_be_weakened() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for (job, id) in [
        ("fuzz", "fuzz-current-probe"),
        ("fuzz-setup", "driver-cold-build"),
    ] {
        let mut duplicate = exact.clone();
        let steps = duplicate["jobs"][job]["steps"].as_sequence_mut().unwrap();
        let ordinal = steps.iter().position(|step| step["id"] == id).unwrap();
        steps.insert(ordinal + 1, steps[ordinal].clone());
        assert!(
            check(".github/workflows/deep-ci.yml", &duplicate).is_err(),
            "duplicate {job}/{id}"
        );
    }
}
#[test]
fn stress_phase_evidence_cannot_disappear_or_claim_success_only() {
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for mutation in [
        "missing",
        "duplicate",
        "success-only",
        "missing-seed",
        "missing-active",
        "missing-child",
        "missing-phase",
    ] {
        let mut changed = exact.clone();
        let steps = changed["jobs"]["stress"]["steps"]
            .as_sequence_mut()
            .unwrap();
        let ordinal = steps
            .iter()
            .position(|step| step["with"]["name"] == "stress-combined-${{ matrix.id }}")
            .unwrap();
        match mutation {
            "missing" => {
                steps.remove(ordinal);
            }
            "duplicate" => {
                steps.insert(ordinal + 1, steps[ordinal].clone());
            }
            "success-only" => {
                steps[ordinal]["if"] = Value::String("success()".into());
            }
            other => {
                let omitted = match other {
                    "missing-seed" => "target/ci/reports/stress-seed.txt",
                    "missing-active" => "target/ci/reports/stress-active-target.txt",
                    "missing-child" => "target/ci/reports/stress-deep_short_child_iterations.json",
                    "missing-phase" => "target/ci/reports/stress",
                    _ => unreachable!(),
                };
                steps[ordinal]["with"]["path"] = Value::String(
                    steps[ordinal]["with"]["path"]
                        .as_str()
                        .unwrap()
                        .lines()
                        .filter(|path| *path != omitted)
                        .collect::<Vec<_>>()
                        .join("\n")
                        + "\n",
                );
            }
        }
        assert!(
            check(".github/workflows/deep-ci.yml", &changed).is_err(),
            "{mutation}"
        );
    }
}

#[test]
fn selected_stress_phases_cannot_serialize_or_omit_aggregation() {
    let file = ".github/workflows/deep-ci.yml";
    let exact: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/deep-ci.yml")).unwrap();
    for family in ["stress", "stress-packages", "stress-lifecycle"] {
        for mutation in ["serial-edge", "static-matrix", "conditional-run"] {
            let mut changed = exact.clone();
            let job = &mut changed["jobs"][family];
            match mutation {
                "serial-edge" => {
                    job["needs"] = Value::Sequence(vec![
                        Value::String("performance-plan".into()),
                        Value::String("stress-packages".into()),
                    ]);
                }
                "static-matrix" => {
                    job["strategy"]["matrix"]["include"] = Value::Sequence(vec![]);
                }
                "conditional-run" => {
                    let steps = job["steps"].as_sequence_mut().unwrap();
                    let step = steps
                        .iter_mut()
                        .find(|step| step["id"] == "stress-run")
                        .unwrap();
                    step["if"] = Value::String("success()".into());
                }
                _ => unreachable!(),
            }
            assert!(check(file, &changed).is_err(), "{family}: {mutation}");
        }
    }
    for mutation in ["missing-aggregate", "success-only", "missing-phase"] {
        let mut changed = exact.clone();
        match mutation {
            "missing-aggregate" => {
                changed["jobs"]
                    .as_mapping_mut()
                    .unwrap()
                    .remove(Value::String("stress-assessment".into()));
            }
            "success-only" => {
                changed["jobs"]["stress-assessment"]["if"] = Value::String("success()".into())
            }
            "missing-phase" => {
                changed["jobs"]["stress-assessment"]["needs"]
                    .as_sequence_mut()
                    .unwrap()
                    .retain(|need| need.as_str() != Some("stress-lifecycle"));
            }
            _ => unreachable!(),
        }
        assert!(check(file, &changed).is_err(), "{mutation}");
    }
}
